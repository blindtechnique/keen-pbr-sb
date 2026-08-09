#include <doctest/doctest.h>

#include "../src/ipc/control_client.hpp"
#include "../src/ipc/control_protocol.hpp"
#include "../src/ipc/bounded_socket_writer.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <thread>
#include <vector>

using namespace keen_pbr3::ipc;

namespace {

int listen_unix(const std::string& path, int backlog = 8) {
    (void)::unlink(path.c_str());
    const int listener =
        ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return -1;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(
        address.sun_path, path.c_str(), path.size() + 1);
    if (::bind(listener,
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) != 0 ||
        ::listen(listener, backlog) != 0) {
        ::close(listener);
        return -1;
    }
    return listener;
}

bool receive_request(int client, nlohmann::json& request) {
    std::uint32_t length = 0;
    if (::recv(client,
               &length,
               sizeof(length),
               MSG_WAITALL) != sizeof(length)) {
        return false;
    }
    const auto payload_size =
        static_cast<std::size_t>(ntohl(length));
    std::string frame(sizeof(length) + payload_size, '\0');
    std::memcpy(frame.data(), &length, sizeof(length));
    if (::recv(client,
               frame.data() + sizeof(length),
               payload_size,
               MSG_WAITALL) !=
        static_cast<ssize_t>(payload_size)) {
        return false;
    }
    request = decode_message(frame);
    return true;
}

std::size_t open_fd_count() {
    std::error_code error;
    std::size_t count = 0;
    for (const auto& entry :
         std::filesystem::directory_iterator("/proc/self/fd", error)) {
        (void)entry;
        ++count;
    }
    return error ? 0 : count;
}

} // namespace

TEST_CASE("control protocol round-trips a versioned request") {
    const nlohmann::json request{
        {"protocol_version", kControlProtocolVersion},
        {"request_id", "request-1"},
        {"operation", "status"},
    };

    const auto decoded = decode_message(encode_message(request));
    CHECK(decoded == request);
    CHECK_NOTHROW(validate_request_envelope(decoded));
}

TEST_CASE("control protocol rejects malformed envelopes") {
    CHECK_THROWS_AS(
        decode_message(std::string("\0\0\0", 3)),
        ControlProtocolError);
    CHECK_THROWS_AS(
        validate_request_envelope(
            {{"protocol_version", 999},
             {"request_id", "request-1"},
             {"operation", "status"}}),
        ControlProtocolError);
}

TEST_CASE("control protocol error preserves request correlation") {
    const auto response = make_error_response(
        {{"request_id", "request-1"}},
        "version_mismatch",
        "unsupported");
    CHECK(response["request_id"] == "request-1");
    CHECK_FALSE(response["ok"]);
    CHECK(response["error"]["code"] == "version_mismatch");
}

TEST_CASE("control client closes successful request sockets") {
    const auto path =
        "/tmp/keen-pbr-control-client-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path);
    REQUIRE(listener >= 0);

    constexpr int kRequests = 8;
    std::thread server([&] {
        for (int index = 0; index < kRequests; ++index) {
            const int client =
                ::accept4(
                    listener, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) return;
            nlohmann::json request;
            if (!receive_request(client, request)) {
                ::close(client);
                return;
            }
            const auto response = encode_message(
                {{"protocol_version", kControlProtocolVersion},
                 {"request_id", request.at("request_id")},
                 {"ok", true},
                 {"result", {{"value", "active"}}}});
            (void)::send(client,
                         response.data(),
                         response.size(),
                         MSG_NOSIGNAL);
            ::close(client);
        }
    });

    const std::size_t before = open_fd_count();
    REQUIRE(before > 0);
    for (int index = 0; index < kRequests; ++index) {
        const auto response = request_control(
            path,
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", "client-" + std::to_string(index)},
             {"operation", "status"}},
            1000);
        CHECK(response.at("result").at("value") == "active");
    }
    server.join();
    const std::size_t after = open_fd_count();
    CHECK(after <= before + 1);

    ::close(listener);
    (void)::unlink(path.c_str());
}

std::vector<int> fill_unix_listener_backlog(
    const std::string& path,
    bool& saturated) {
    std::vector<int> clients;
    saturated = false;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(
        address.sun_path, path.c_str(), path.size() + 1);

    for (int attempt = 0; attempt < 64; ++attempt) {
        const int client =
            ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (client < 0) {
            break;
        }
        if (::connect(client,
                      reinterpret_cast<const sockaddr*>(&address),
                      sizeof(address)) == 0 ||
            errno == EINPROGRESS) {
            clients.push_back(client);
            continue;
        }
        const int error = errno;
        ::close(client);
        if (error == EAGAIN || error == EWOULDBLOCK) {
            saturated = true;
            break;
        }
        for (const int fd : clients) {
            ::close(fd);
        }
        clients.clear();
        break;
    }
    return clients;
}

TEST_CASE("control client gives a routed request a separate response deadline") {
    const auto path =
        "/tmp/keen-pbr-control-deferred-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path);
    REQUIRE(listener >= 0);

    std::thread server([&] {
        const int client =
            ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) return;
        nlohmann::json request;
        if (!receive_request(client, request)) {
            ::close(client);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto response = encode_message(
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", request.at("request_id")},
             {"ok", true},
             {"result", {{"value", "ready"}}}});
        (void)::send(client,
                     response.data(),
                     response.size(),
                     MSG_NOSIGNAL);
        ::close(client);
    });

    nlohmann::json response;
    CHECK_NOTHROW(response = request_control(
        path,
        {{"protocol_version", kControlProtocolVersion},
         {"request_id", "deferred-1"},
         {"operation", "test-routing"}},
        25,
        500));
    server.join();
    CHECK(response.at("result").at("value") == "ready");

    ::close(listener);
    (void)::unlink(path.c_str());
}

TEST_CASE("control connect timeout is bounded when the Unix backlog is full") {
    const auto path =
        "/tmp/keen-pbr-control-connect-timeout-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path, 0);
    REQUIRE(listener >= 0);

    bool saturated = false;
    auto queued_clients =
        fill_unix_listener_backlog(path, saturated);
    REQUIRE_FALSE(queued_clients.empty());
    REQUIRE(saturated);

    const auto started = std::chrono::steady_clock::now();
    CHECK_THROWS_AS(
        request_control(
            path,
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", "connect-timeout-1"},
             {"operation", "status"}},
            60,
            500),
        ControlTimeoutError);
    const auto elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    CHECK(elapsed >= std::chrono::milliseconds(40));
    CHECK(elapsed < std::chrono::milliseconds(250));

    for (const int client : queued_clients) {
        ::close(client);
    }
    ::close(listener);
    (void)::unlink(path.c_str());
}

TEST_CASE("control response timeout is absolute across partial frames") {
    const auto path =
        "/tmp/keen-pbr-control-trickle-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path);
    REQUIRE(listener >= 0);

    std::thread server([&] {
        const int client =
            ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) return;
        nlohmann::json request;
        if (!receive_request(client, request)) {
            ::close(client);
            return;
        }
        const auto response = encode_message(
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", request.at("request_id")},
             {"ok", true},
             {"result", nlohmann::json::object()}});
        for (std::size_t index = 0;
             index < sizeof(std::uint32_t);
             ++index) {
            if (::send(client,
                       response.data() + index,
                       1,
                       MSG_NOSIGNAL) != 1) {
                break;
            }
            std::this_thread::sleep_for(
                std::chrono::milliseconds(35));
        }
        ::close(client);
    });

    const auto started = std::chrono::steady_clock::now();
    CHECK_THROWS_AS(
        request_control(
            path,
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", "trickle-1"},
             {"operation", "test-routing"}},
            500,
            60),
        ControlTimeoutError);
    const auto elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    CHECK(elapsed < std::chrono::milliseconds(250));
    server.join();

    ::close(listener);
    (void)::unlink(path.c_str());
}

TEST_CASE("control request write is bounded when the peer stops reading") {
    const auto path =
        "/tmp/keen-pbr-control-write-stall-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path);
    REQUIRE(listener >= 0);

    std::thread server([&] {
        const int client =
            ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        ::close(client);
    });

    const std::string padding(900U * 1024U, 'x');
    CHECK_THROWS_AS(
        request_control(
            path,
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", "write-stall-1"},
             {"operation", "test-routing"},
             {"padding", padding}},
            40,
            500),
        ControlTimeoutError);
    server.join();

    ::close(listener);
    (void)::unlink(path.c_str());
}

TEST_CASE("routing-test response writer cannot be held by a non-reading client") {
    int sockets[2] = {-1, -1};
    REQUIRE(::socketpair(
                AF_UNIX,
                SOCK_STREAM | SOCK_CLOEXEC,
                0,
                sockets) == 0);
    const int send_buffer_bytes = 4096;
    REQUIRE(::setsockopt(
                sockets[0],
                SOL_SOCKET,
                SO_SNDBUF,
                &send_buffer_bytes,
                sizeof(send_buffer_bytes)) == 0);

    const std::string response(1024U * 1024U, 'r');
    const auto started = std::chrono::steady_clock::now();
    CHECK_THROWS_WITH_AS(
        send_all_bounded_nonblocking(
            sockets[0],
            response.data(),
            response.size(),
            std::chrono::milliseconds{60}),
        "control socket response timeout",
        ControlProtocolError);
    const auto elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    CHECK(elapsed >= std::chrono::milliseconds(40));
    CHECK(elapsed < std::chrono::milliseconds(250));
    const int flags = ::fcntl(sockets[0], F_GETFL, 0);
    REQUIRE(flags >= 0);
    CHECK((flags & O_NONBLOCK) != 0);

    ::close(sockets[0]);
    ::close(sockets[1]);
}

TEST_CASE("control client streams bounded resolver chunks") {
    const auto path =
        "/tmp/keen-pbr-control-stream-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path);
    REQUIRE(listener >= 0);

    std::thread server([&] {
        const int client =
            ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) return;
        nlohmann::json request;
        if (!receive_request(client, request)) {
            ::close(client);
            return;
        }
        const auto header = encode_message(
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", request.at("request_id")},
             {"ok", true},
             {"stream", true}});
        (void)::send(
            client, header.data(), header.size(), MSG_NOSIGNAL);
        for (const std::string& chunk :
             {std::string("alpha-"), std::string("beta")}) {
            const std::uint32_t size =
                htonl(static_cast<std::uint32_t>(chunk.size()));
            (void)::send(
                client, &size, sizeof(size), MSG_NOSIGNAL);
            (void)::send(client,
                         chunk.data(),
                         chunk.size(),
                         MSG_NOSIGNAL);
        }
        const std::uint32_t end = 0;
        (void)::send(
            client, &end, sizeof(end), MSG_NOSIGNAL);
        ::close(client);
    });

    std::ostringstream output;
    CHECK_NOTHROW(stream_control(
        path,
        {{"protocol_version", kControlProtocolVersion},
         {"request_id", "stream-1"},
         {"operation", "generate-resolver-config"}},
        output,
        1000));
    server.join();
    CHECK(output.str() == "alpha-beta");

    ::close(listener);
    (void)::unlink(path.c_str());
}

TEST_CASE("control client marks truncated active streams") {
    const auto path =
        "/tmp/keen-pbr-control-truncated-" +
        std::to_string(::getpid()) + ".sock";
    const int listener = listen_unix(path);
    REQUIRE(listener >= 0);

    std::thread server([&] {
        const int client =
            ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) return;
        nlohmann::json request;
        if (!receive_request(client, request)) {
            ::close(client);
            return;
        }
        const auto header = encode_message(
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", request.at("request_id")},
             {"ok", true},
             {"stream", true}});
        (void)::send(
            client, header.data(), header.size(), MSG_NOSIGNAL);
        const std::string chunk = "active";
        const std::uint32_t size =
            htonl(static_cast<std::uint32_t>(chunk.size()));
        (void)::send(client, &size, sizeof(size), MSG_NOSIGNAL);
        (void)::send(client,
                     chunk.data(),
                     chunk.size(),
                     MSG_NOSIGNAL);
        ::close(client);
    });

    std::ostringstream output;
    try {
        stream_control(
            path,
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", "stream-2"},
             {"operation", "generate-resolver-config"}},
            output,
            1000);
        FAIL("expected stream failure");
    } catch (const ControlStreamError& error) {
        CHECK(error.active_bytes_streamed());
    }
    server.join();
    CHECK(output.str() == "active");

    ::close(listener);
    (void)::unlink(path.c_str());
}
