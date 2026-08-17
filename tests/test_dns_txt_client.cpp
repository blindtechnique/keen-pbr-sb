#include <doctest/doctest.h>

#include "../src/dns/dns_txt_client.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace keen_pbr3;

namespace {

std::vector<uint8_t> encode_qname(const std::string& domain) {
    std::vector<uint8_t> encoded;
    size_t start = 0;
    while (start < domain.size()) {
        const size_t dot = domain.find('.', start);
        const size_t end = (dot == std::string::npos) ? domain.size() : dot;
        const size_t len = end - start;
        encoded.push_back(static_cast<uint8_t>(len));
        encoded.insert(encoded.end(), domain.begin() + static_cast<std::ptrdiff_t>(start),
                       domain.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    encoded.push_back(0x00);
    return encoded;
}

void push_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void push_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::vector<uint8_t> build_txt_response(uint16_t id,
                                        const std::string& domain,
                                        const std::vector<std::string>& txt_answers) {
    std::vector<uint8_t> packet;
    packet.reserve(512);

    push_u16(packet, id);
    push_u16(packet, 0x8180);
    push_u16(packet, 0x0001);
    push_u16(packet, static_cast<uint16_t>(txt_answers.size()));
    push_u16(packet, 0x0000);
    push_u16(packet, 0x0000);

    const auto qname = encode_qname(domain);
    packet.insert(packet.end(), qname.begin(), qname.end());
    push_u16(packet, 0x0010);
    push_u16(packet, 0x0001);

    for (const auto& txt : txt_answers) {
        push_u16(packet, 0xC00C);
        push_u16(packet, 0x0010);
        push_u16(packet, 0x0001);
        push_u32(packet, 0);
        push_u16(packet, static_cast<uint16_t>(txt.size() + 1));
        packet.push_back(static_cast<uint8_t>(txt.size()));
        packet.insert(packet.end(), txt.begin(), txt.end());
    }

    return packet;
}

class SingleResponseDnsServer {
public:
    explicit SingleResponseDnsServer(std::vector<std::string> txt_answers)
        : txt_answers_(std::move(txt_answers)) {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("socket() failed");
        }

        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(socket_fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(socket_fd_);
            throw std::runtime_error("bind() failed");
        }

        socklen_t len = sizeof(addr);
        if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            close(socket_fd_);
            throw std::runtime_error("getsockname() failed");
        }
        port_ = ntohs(addr.sin_port);

        server_thread_ = std::thread([this]() { serve_once(); });
    }

    ~SingleResponseDnsServer() {
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    std::string address() const {
        return "127.0.0.1:" + std::to_string(port_);
    }

private:
    void serve_once() {
        std::array<uint8_t, 512> buffer {};
        sockaddr_in client_addr {};
        socklen_t client_len = sizeof(client_addr);
        const ssize_t received = recvfrom(socket_fd_,
                                          buffer.data(),
                                          buffer.size(),
                                          0,
                                          reinterpret_cast<sockaddr*>(&client_addr),
                                          &client_len);
        if (received < 2) {
            return;
        }

        const uint16_t id = static_cast<uint16_t>((buffer[0] << 8) | buffer[1]);
        auto response = build_txt_response(id, "config-hash.keen.pbr", txt_answers_);
        (void)sendto(socket_fd_,
                     response.data(),
                     response.size(),
                     0,
                     reinterpret_cast<const sockaddr*>(&client_addr),
                     client_len);
    }

    int socket_fd_{-1};
    uint16_t port_{0};
    std::vector<std::string> txt_answers_;
    std::thread server_thread_;
};

class TruncatedThenTcpDnsServer {
public:
    enum class TcpReply {
        VALID,
        OVERSIZE,
        CLOSE_EARLY,
    };

    TruncatedThenTcpDnsServer(TcpReply reply, std::vector<std::string> txt_answers)
        : reply_(reply), txt_answers_(std::move(txt_answers)) {
        tcp_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_fd_ < 0) {
            throw std::runtime_error("TCP socket() failed");
        }

        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(tcp_fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(tcp_fd_, 1) != 0) {
            close(tcp_fd_);
            throw std::runtime_error("TCP bind/listen failed");
        }

        socklen_t len = sizeof(addr);
        if (getsockname(tcp_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            close(tcp_fd_);
            throw std::runtime_error("TCP getsockname() failed");
        }
        port_ = ntohs(addr.sin_port);

        udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd_ < 0) {
            close(tcp_fd_);
            throw std::runtime_error("UDP socket() failed");
        }
        addr.sin_port = htons(port_);
        if (bind(udp_fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(udp_fd_);
            close(tcp_fd_);
            throw std::runtime_error("UDP bind() failed");
        }

        server_thread_ = std::thread([this]() { serve(); });
    }

    ~TruncatedThenTcpDnsServer() {
        if (udp_fd_ >= 0) {
            close(udp_fd_);
            udp_fd_ = -1;
        }
        if (tcp_fd_ >= 0) {
            close(tcp_fd_);
            tcp_fd_ = -1;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    std::string address() const {
        return "127.0.0.1:" + std::to_string(port_);
    }

    bool tcp_query_matches_udp_query() const {
        return tcp_query_matches_udp_query_.load();
    }

private:
    static bool receive_exact(int fd, uint8_t* data, size_t size) {
        size_t received_total = 0;
        while (received_total < size) {
            const ssize_t received =
                recv(fd, data + received_total, size - received_total, 0);
            if (received <= 0) {
                return false;
            }
            received_total += static_cast<size_t>(received);
        }
        return true;
    }

    static bool send_exact(int fd, const uint8_t* data, size_t size) {
        size_t sent_total = 0;
        while (sent_total < size) {
            const ssize_t sent =
                send(fd, data + sent_total, size - sent_total, MSG_NOSIGNAL);
            if (sent <= 0) {
                return false;
            }
            sent_total += static_cast<size_t>(sent);
        }
        return true;
    }

    void serve() {
        std::array<uint8_t, 512> udp_query_buffer {};
        sockaddr_in client_addr {};
        socklen_t client_len = sizeof(client_addr);
        const ssize_t udp_query_size =
            recvfrom(udp_fd_,
                     udp_query_buffer.data(),
                     udp_query_buffer.size(),
                     0,
                     reinterpret_cast<sockaddr*>(&client_addr),
                     &client_len);
        if (udp_query_size < 2) {
            return;
        }

        const std::vector<uint8_t> udp_query(
            udp_query_buffer.begin(),
            udp_query_buffer.begin() + static_cast<std::ptrdiff_t>(udp_query_size));
        const uint16_t id =
            static_cast<uint16_t>((udp_query_buffer[0] << 8U) | udp_query_buffer[1]);
        auto truncated =
            build_txt_response(id, "config-hash.keen.pbr", {});
        truncated[2] |= 0x02U;
        (void)sendto(udp_fd_,
                     truncated.data(),
                     truncated.size(),
                     0,
                     reinterpret_cast<const sockaddr*>(&client_addr),
                     client_len);

        const int client_fd = accept(tcp_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            return;
        }

        std::array<uint8_t, 2> query_prefix {};
        if (!receive_exact(client_fd, query_prefix.data(), query_prefix.size())) {
            close(client_fd);
            return;
        }
        const size_t tcp_query_size =
            (static_cast<size_t>(query_prefix[0]) << 8U) | query_prefix[1];
        std::vector<uint8_t> tcp_query(tcp_query_size);
        if (!receive_exact(client_fd, tcp_query.data(), tcp_query.size())) {
            close(client_fd);
            return;
        }
        tcp_query_matches_udp_query_.store(tcp_query == udp_query);

        if (reply_ == TcpReply::CLOSE_EARLY) {
            close(client_fd);
            return;
        }
        if (reply_ == TcpReply::OVERSIZE) {
            constexpr uint16_t oversized_frame = 16U * 1024U + 1U;
            const std::array<uint8_t, 2> prefix {
                static_cast<uint8_t>((oversized_frame >> 8U) & 0xffU),
                static_cast<uint8_t>(oversized_frame & 0xffU),
            };
            (void)send_exact(client_fd, prefix.data(), prefix.size());
            close(client_fd);
            return;
        }

        auto response =
            build_txt_response(id, "config-hash.keen.pbr", txt_answers_);
        const uint16_t response_size = static_cast<uint16_t>(response.size());
        const std::array<uint8_t, 2> response_prefix {
            static_cast<uint8_t>((response_size >> 8U) & 0xffU),
            static_cast<uint8_t>(response_size & 0xffU),
        };

        // Deliberately split both the frame prefix and payload. The client must
        // not assume that one recv() corresponds to one DNS/TCP frame.
        (void)send_exact(client_fd, response_prefix.data(), 1);
        (void)send_exact(client_fd, response_prefix.data() + 1, 1);
        const size_t split = response.size() / 2;
        (void)send_exact(client_fd, response.data(), split);
        (void)send_exact(client_fd, response.data() + split, response.size() - split);
        close(client_fd);
    }

    int tcp_fd_{-1};
    int udp_fd_{-1};
    uint16_t port_{0};
    TcpReply reply_;
    std::vector<std::string> txt_answers_;
    std::atomic<bool> tcp_query_matches_udp_query_{false};
    std::thread server_thread_;
};

} // namespace

TEST_CASE("DNS truncation flag parsing supports unaligned packet buffers") {
    constexpr std::size_t dns_header_size = 12;
    std::array<unsigned char, dns_header_size + 1> storage {};
    unsigned char* packet = storage.data() + 1;
    packet[2] = 0x02;
    CHECK(keen_pbr3::detail::dns_response_is_truncated(packet, dns_header_size));
    packet[2] = 0;
    CHECK_FALSE(keen_pbr3::detail::dns_response_is_truncated(packet, dns_header_size));
}

TEST_CASE("DNS response validation checks transaction and question") {
    constexpr std::uint16_t id = 0x1234;
    const auto response = build_txt_response(
        id, "config-hash.keen.pbr", {"0123456789abcdef0123456789abcdef"});
    CHECK(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), id, "config-hash.keen.pbr"));
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), 0xabcd, "config-hash.keen.pbr"));
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), id, "other.example"));
}

TEST_CASE("DNS TXT query retries a truncated UDP response over framed TCP") {
    TruncatedThenTcpDnsServer server(
        TruncatedThenTcpDnsServer::TcpReply::VALID,
        {"1744060803|cccccccccccccccccccccccccccccccc"});
    std::string error;

    const auto result = query_dns_txt_record(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000),
        &error);

    REQUIRE(result.has_value());
    CHECK(*result == "1744060803|cccccccccccccccccccccccccccccccc");
    CHECK(error.empty());
    CHECK(server.tcp_query_matches_udp_query());
}

TEST_CASE("DNS TCP fallback rejects an oversized length prefix") {
    TruncatedThenTcpDnsServer server(
        TruncatedThenTcpDnsServer::TcpReply::OVERSIZE, {});
    std::string error;

    const auto result = query_dns_txt_record(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000),
        &error);

    CHECK_FALSE(result.has_value());
    CHECK(error == "DNS TCP response exceeds the size limit");
    CHECK(server.tcp_query_matches_udp_query());
}

TEST_CASE("DNS TCP fallback reports a response closed before its frame") {
    TruncatedThenTcpDnsServer server(
        TruncatedThenTcpDnsServer::TcpReply::CLOSE_EARLY, {});
    std::string error;

    const auto result = query_dns_txt_record(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000),
        &error);

    CHECK_FALSE(result.has_value());
    CHECK(error == "DNS TCP connection closed before the complete response");
    CHECK(server.tcp_query_matches_udp_query());
}

TEST_CASE("parse_resolver_config_hash_txt parses ts/hash payload") {
    const auto parsed = parse_resolver_config_hash_txt("1744060800|0123456789abcdef0123456789abcdef");
    REQUIRE(parsed.ts.has_value());
    CHECK(*parsed.ts == 1744060800);
    CHECK(parsed.hash == "0123456789abcdef0123456789abcdef");
}

TEST_CASE("parse_resolver_config_hash_txt parses quoted ts/hash payload") {
    const auto parsed = parse_resolver_config_hash_txt("\"1744060800|0123456789abcdef0123456789abcdef\"");
    REQUIRE(parsed.ts.has_value());
    CHECK(*parsed.ts == 1744060800);
    CHECK(parsed.hash == "0123456789abcdef0123456789abcdef");
}

TEST_CASE("parse_resolver_config_hash_txt parses md5-prefixed hash payload") {
    const auto parsed = parse_resolver_config_hash_txt("md5=0123456789ABCDEF0123456789ABCDEF");
    CHECK_FALSE(parsed.ts.has_value());
    CHECK(parsed.hash == "0123456789abcdef0123456789abcdef");
}

TEST_CASE("parse_resolver_state_txt distinguishes active and fallback modes") {
    const auto active =
        parse_resolver_state_txt("1744060800|active|runtime_active");
    CHECK(active.ts == std::optional<std::int64_t>{1744060800});
    CHECK(active.mode == ResolverRuntimeMode::ACTIVE);
    CHECK(active.reason == "runtime_active");

    const auto fallback = parse_resolver_state_txt(
        "\"1744060801|fallback|socket_unavailable\"");
    CHECK(fallback.ts == std::optional<std::int64_t>{1744060801});
    CHECK(fallback.mode == ResolverRuntimeMode::FALLBACK);
    CHECK(fallback.reason == "socket_unavailable");

    const auto unknown = parse_resolver_state_txt("legacy");
    CHECK_FALSE(unknown.ts.has_value());
    CHECK(unknown.mode == ResolverRuntimeMode::UNKNOWN);
    CHECK(unknown.reason.empty());
}

TEST_CASE("query_resolver_config_hash_txt selects TXT answer with latest timestamp") {
    SingleResponseDnsServer server({
        "1744060800|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1744060802|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    });

    const auto result = query_resolver_config_hash_txt(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::SUCCESS);
    REQUIRE(result.raw_txt.has_value());
    CHECK(*result.raw_txt == "1744060802|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    CHECK(result.parsed_value.ts == std::optional<std::int64_t>{1744060802});
    CHECK(result.parsed_value.hash == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}

TEST_CASE("query_resolver_config_hash_txt reports missing TXT as no usable TXT") {
    SingleResponseDnsServer server({});

    const auto result = query_resolver_config_hash_txt(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::NO_USABLE_TXT);
    CHECK_FALSE(result.raw_txt.has_value());
}

TEST_CASE("query_resolver_config_hash_txt reports invalid payload") {
    SingleResponseDnsServer server({"not-a-md5"});

    const auto result = query_resolver_config_hash_txt(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::INVALID_TXT);
    REQUIRE(result.raw_txt.has_value());
    CHECK(*result.raw_txt == "not-a-md5");
}

TEST_CASE("query_resolver_config_hash_txt reports query failure for invalid resolver address") {
    const auto result = query_resolver_config_hash_txt(
        "not-an-address",
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::QUERY_FAILED);
    CHECK_FALSE(result.error.empty());
}
