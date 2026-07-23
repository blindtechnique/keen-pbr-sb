#include <doctest/doctest.h>

#include "../src/ipc/control_client.hpp"
#include "../src/ipc/control_protocol.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <thread>

using namespace keen_pbr3::ipc;

namespace {

int listen_unix(const std::string& path) {
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
        ::listen(listener, 8) != 0) {
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
        for (const std::string chunk :
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
