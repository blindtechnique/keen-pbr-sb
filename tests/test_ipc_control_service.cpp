#include <doctest/doctest.h>

#include "../src/ipc/control_protocol.hpp"
#include "../src/ipc/ipc_control_service.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

using namespace keen_pbr3::ipc;

namespace {

class TempControlSocket {
public:
    TempControlSocket() {
        static std::atomic<unsigned long> serial{0};
        directory_ =
            "/tmp/keen-pbr-ipc-service-" +
            std::to_string(::getpid()) + "-" +
            std::to_string(++serial);
        path_ = directory_ + "/control.sock";
    }

    ~TempControlSocket() {
        std::error_code error;
        std::filesystem::remove_all(directory_, error);
    }

    const std::string& directory() const { return directory_; }
    const std::string& path() const { return path_; }

private:
    std::string directory_;
    std::string path_;
};

int connect_control_socket(const std::string& path) {
    const int fd =
        ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    timeval timeout{2, 0};
    if (::setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)) != 0 ||
        ::setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &timeout,
            sizeof(timeout)) != 0) {
        ::close(fd);
        return -1;
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(
        address.sun_path, path.c_str(), path.size() + 1);
    if (::connect(
            fd,
            reinterpret_cast<const sockaddr*>(&address),
            sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool send_all_bytes(int fd, const char* data, std::size_t size) {
    std::size_t written = 0;
    while (written < size) {
        const ssize_t count = ::send(
            fd, data + written, size - written, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<std::size_t>(count);
    }
    return true;
}

bool receive_control_response(int fd, nlohmann::json& response) {
    std::uint32_t network_size = 0;
    if (::recv(
            fd,
            &network_size,
            sizeof(network_size),
            MSG_WAITALL) != sizeof(network_size)) {
        return false;
    }
    const auto payload_size =
        static_cast<std::size_t>(ntohl(network_size));
    std::string frame(sizeof(network_size) + payload_size, '\0');
    std::memcpy(
        frame.data(), &network_size, sizeof(network_size));
    if (::recv(
            fd,
            frame.data() + sizeof(network_size),
            payload_size,
            MSG_WAITALL) != static_cast<ssize_t>(payload_size)) {
        return false;
    }
    response = decode_message(frame);
    return true;
}

bool wait_for_wake(
    std::mutex& mutex,
    std::condition_variable& condition,
    const std::size_t& wakes,
    std::size_t expected) {
    std::unique_lock<std::mutex> lock(mutex);
    return condition.wait_for(
        lock,
        std::chrono::seconds{2},
        [&] { return wakes >= expected; });
}

void start_test_service(
    IpcControlService& service,
    const std::string& path,
    IpcControlService::WakeControlLoop wake_control_loop) {
    IpcControlServiceTestHooks hooks;
    hooks.allow_current_process_owner = true;
    service.start(path, std::move(wake_control_loop), hooks);
}

} // namespace

TEST_CASE("IPC control service owns ingress and transfers one request") {
    TempControlSocket socket;
    IpcControlService service;
    std::mutex wake_mutex;
    std::condition_variable wake_condition;
    std::size_t wakes = 0;
    start_test_service(service, socket.path(), [&] {
        {
            std::lock_guard<std::mutex> lock(wake_mutex);
            ++wakes;
        }
        wake_condition.notify_all();
    });

    REQUIRE(service.active());
    REQUIRE(std::filesystem::is_socket(socket.path()));
    struct stat directory_metadata {};
    struct stat socket_metadata {};
    REQUIRE(::lstat(socket.directory().c_str(), &directory_metadata) == 0);
    REQUIRE(::lstat(socket.path().c_str(), &socket_metadata) == 0);
    CHECK(directory_metadata.st_uid == ::geteuid());
    CHECK(directory_metadata.st_gid == ::getegid());
    CHECK((directory_metadata.st_mode & 07777) == 0750);
    CHECK(socket_metadata.st_uid == ::geteuid());
    CHECK(socket_metadata.st_gid == ::getegid());
    CHECK((socket_metadata.st_mode & 07777) == 0600);

    const int client = connect_control_socket(socket.path());
    REQUIRE(client >= 0);
    const nlohmann::json request{
        {"protocol_version", kControlProtocolVersion},
        {"request_id", "service-1"},
        {"operation", "status"},
    };
    const auto frame = encode_message(request);
    REQUIRE(send_all_bytes(client, frame.data(), frame.size()));
    REQUIRE(wait_for_wake(
        wake_mutex, wake_condition, wakes, 1U));

    auto accepted = service.try_take_request();
    REQUIRE(accepted.has_value());
    CHECK(accepted->request == request);
    CHECK(accepted->peer_pid == ::getpid());
    CHECK(accepted->peer_uid == ::getuid());
    CHECK(accepted->peer_gid == ::getgid());
    CHECK_FALSE(service.try_take_request().has_value());

    IpcControlService::send_response_and_close(
        accepted->fd,
        {{"protocol_version", kControlProtocolVersion},
         {"request_id", "service-1"},
         {"ok", true},
         {"result", {{"state", "active"}}}});
    nlohmann::json response;
    REQUIRE(receive_control_response(client, response));
    CHECK(response.at("result").at("state") == "active");
    ::close(client);

    service.stop();
    CHECK_FALSE(service.active());
    CHECK_FALSE(std::filesystem::exists(socket.path()));
    CHECK_NOTHROW(service.stop());
}

TEST_CASE("IPC control service keeps an enqueued request when wake fails") {
    TempControlSocket socket;
    IpcControlService service;
    std::mutex wake_mutex;
    std::condition_variable wake_condition;
    std::size_t wakes = 0;
    start_test_service(service, socket.path(), [&] {
        {
            std::lock_guard<std::mutex> lock(wake_mutex);
            ++wakes;
        }
        wake_condition.notify_all();
        throw std::runtime_error("synthetic wake failure");
    });

    const int client = connect_control_socket(socket.path());
    REQUIRE(client >= 0);
    const auto frame = encode_message(
        {{"protocol_version", kControlProtocolVersion},
         {"request_id", "service-wake-failure"},
         {"operation", "status"}});
    REQUIRE(send_all_bytes(client, frame.data(), frame.size()));
    REQUIRE(wait_for_wake(
        wake_mutex, wake_condition, wakes, 1U));

    auto accepted = service.try_take_request();
    REQUIRE(accepted.has_value());
    CHECK(
        accepted->request.at("request_id") ==
        "service-wake-failure");
    IpcControlService::send_response_and_close(
        accepted->fd,
        {{"protocol_version", kControlProtocolVersion},
         {"request_id", "service-wake-failure"},
         {"ok", true},
         {"result", nlohmann::json::object()}});
    nlohmann::json response;
    CHECK(receive_control_response(client, response));
    ::close(client);
    service.stop();
}

TEST_CASE("IPC control service stop closes queued clients and unlinks socket") {
    TempControlSocket socket;
    IpcControlService service;
    std::mutex wake_mutex;
    std::condition_variable wake_condition;
    std::size_t wakes = 0;
    start_test_service(service, socket.path(), [&] {
        {
            std::lock_guard<std::mutex> lock(wake_mutex);
            ++wakes;
        }
        wake_condition.notify_all();
    });

    const int client = connect_control_socket(socket.path());
    REQUIRE(client >= 0);
    const auto frame = encode_message(
        {{"protocol_version", kControlProtocolVersion},
         {"request_id", "service-stop"},
         {"operation", "status"}});
    REQUIRE(send_all_bytes(client, frame.data(), frame.size()));
    REQUIRE(wait_for_wake(
        wake_mutex, wake_condition, wakes, 1U));

    service.stop();
    char byte = 0;
    CHECK(::recv(client, &byte, 1, 0) == 0);
    CHECK_FALSE(std::filesystem::exists(socket.path()));
    ::close(client);
}

TEST_CASE("IPC control service rejects oversized frames before dispatch") {
    TempControlSocket socket;
    IpcControlService service;
    std::atomic<std::size_t> wakes{0};
    start_test_service(service, socket.path(), [&] { ++wakes; });

    const int client = connect_control_socket(socket.path());
    REQUIRE(client >= 0);
    const std::uint32_t oversized = htonl(4097U);
    REQUIRE(send_all_bytes(
        client,
        reinterpret_cast<const char*>(&oversized),
        sizeof(oversized)));

    nlohmann::json response;
    REQUIRE(receive_control_response(client, response));
    CHECK_FALSE(response.at("ok").get<bool>());
    CHECK(response.at("error").at("code") == "protocol_error");
    CHECK(wakes.load() == 0U);
    CHECK_FALSE(service.try_take_request().has_value());
    ::close(client);
    service.stop();
}

TEST_CASE("IPC control service does not replace a regular path") {
    TempControlSocket socket;
    std::filesystem::create_directories(socket.directory());
    {
        const int fd = ::open(
            socket.path().c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            0600);
        REQUIRE(fd >= 0);
        ::close(fd);
    }

    IpcControlService service;
    CHECK_THROWS_WITH(
        start_test_service(service, socket.path(), [] {}),
        "unsafe stale control socket path");
    CHECK_FALSE(service.active());
    CHECK(std::filesystem::is_regular_file(socket.path()));
    CHECK_NOTHROW(service.stop());
}
