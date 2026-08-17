#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/cmd/test_routing.hpp"
#include "../src/daemon/config_store.hpp"
#include "../src/util/blocking_executor.hpp"
#include "../src/util/bounded_operation_admission.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace keen_pbr3;

namespace {

std::filesystem::path make_temp_dir() {
    char path_template[] = "/tmp/keen-pbr-test-routing-XXXXXX";
    const char* created = mkdtemp(path_template);
    if (created == nullptr) {
        throw std::runtime_error("mkdtemp failed");
    }
    return std::filesystem::path(created);
}

bool udp_socket_available() {
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
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

size_t find_question_end(const uint8_t* packet, size_t packet_len) {
    size_t offset = 12;
    while (offset < packet_len) {
        const uint8_t len = packet[offset++];
        if (len == 0) {
            break;
        }
        offset += len;
    }
    if (offset + 4 > packet_len) {
        throw std::runtime_error("truncated DNS question");
    }
    return offset + 4;
}

uint16_t read_qtype(const uint8_t* packet, size_t packet_len) {
    const size_t end = find_question_end(packet, packet_len);
    return static_cast<uint16_t>((packet[end - 4] << 8) | packet[end - 3]);
}

std::vector<uint8_t> build_dns_response(const uint8_t* request,
                                        size_t request_len,
                                        const std::vector<std::string>& ipv4_answers,
                                        const std::vector<std::string>& ipv6_answers) {
    std::vector<uint8_t> packet;
    packet.reserve(512);

    const size_t question_end = find_question_end(request, request_len);
    const uint16_t qtype = read_qtype(request, request_len);
    const uint16_t answer_count =
        static_cast<uint16_t>((qtype == 1 ? ipv4_answers.size() : 0) +
                              (qtype == 28 ? ipv6_answers.size() : 0));

    push_u16(packet, static_cast<uint16_t>((request[0] << 8) | request[1]));
    push_u16(packet, 0x8180);
    push_u16(packet, 0x0001);
    push_u16(packet, answer_count);
    push_u16(packet, 0x0000);
    push_u16(packet, 0x0000);
    packet.insert(packet.end(), request + 12, request + question_end);

    const auto append_answer = [&packet](uint16_t type, const std::string& ip) {
        push_u16(packet, 0xC00C);
        push_u16(packet, type);
        push_u16(packet, 0x0001);
        push_u32(packet, 0);

        if (type == 1) {
            in_addr addr {};
            if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
                throw std::runtime_error("invalid IPv4 answer");
            }
            push_u16(packet, 4);
            const auto* bytes = reinterpret_cast<const uint8_t*>(&addr);
            packet.insert(packet.end(), bytes, bytes + 4);
        } else {
            in6_addr addr {};
            if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) {
                throw std::runtime_error("invalid IPv6 answer");
            }
            push_u16(packet, 16);
            const auto* bytes = reinterpret_cast<const uint8_t*>(&addr);
            packet.insert(packet.end(), bytes, bytes + 16);
        }
    };

    if (qtype == 1) {
        for (const auto& ip : ipv4_answers) {
            append_answer(1, ip);
        }
    } else if (qtype == 28) {
        for (const auto& ip : ipv6_answers) {
            append_answer(28, ip);
        }
    }

    return packet;
}

class TestDnsServer {
public:
    TestDnsServer(std::vector<std::string> ipv4_answers,
                  std::vector<std::string> ipv6_answers)
        : ipv4_answers_(std::move(ipv4_answers))
        , ipv6_answers_(std::move(ipv6_answers)) {
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

        server_thread_ = std::thread([this]() { serve(); });
    }

    ~TestDnsServer() {
        stop_ = true;
        if (socket_fd_ >= 0) {
            sockaddr_in addr {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port_);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            (void)sendto(socket_fd_, "", 0, 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    std::string address() const {
        return "127.0.0.1:" + std::to_string(port_);
    }

private:
    void serve() {
        while (!stop_) {
            uint8_t buffer[512] = {};
            sockaddr_in client_addr {};
            socklen_t client_len = sizeof(client_addr);
            const ssize_t received = recvfrom(socket_fd_,
                                              buffer,
                                              sizeof(buffer),
                                              0,
                                              reinterpret_cast<sockaddr*>(&client_addr),
                                              &client_len);
            if (received <= 0) {
                continue;
            }
            if (stop_) {
                break;
            }

            auto response = build_dns_response(buffer,
                                               static_cast<size_t>(received),
                                               ipv4_answers_,
                                               ipv6_answers_);
            (void)sendto(socket_fd_,
                         response.data(),
                         response.size(),
                         0,
                         reinterpret_cast<const sockaddr*>(&client_addr),
                         client_len);
        }
    }

    int socket_fd_{-1};
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::vector<std::string> ipv4_answers_;
    std::vector<std::string> ipv6_answers_;
    std::thread server_thread_;
};

Config build_test_config() {
    Config config;
    config.lists = std::map<std::string, ListConfig>{};
    config.dns = DnsConfig{};
    return config;
}

class RoutingSequenceHttpTransport final : public HttpTransport {
public:
    void enqueue(std::string body) {
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = std::move(body);
        responses_.push_back(std::move(response));
    }

    HttpTransportResponse perform(
        const HttpTransportRequest&) override {
        if (responses_.empty()) {
            throw std::runtime_error(
                "no queued routing HTTP response");
        }
        auto response = std::move(responses_.front());
        responses_.pop_front();
        return response;
    }

private:
    std::deque<HttpTransportResponse> responses_;
};

bool process_has_open_path(const std::filesystem::path& expected) {
    std::error_code error;
    for (const auto& entry :
         std::filesystem::directory_iterator("/proc/self/fd", error)) {
        std::error_code link_error;
        const auto target =
            std::filesystem::read_symlink(entry.path(), link_error);
        if (!link_error && target == expected) {
            return true;
        }
    }
    return false;
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

class ScopedPathOverride {
public:
    explicit ScopedPathOverride(const std::string& value) {
        if (const char* current = std::getenv("PATH")) {
            previous_ = current;
        }
        (void)setenv("PATH", value.c_str(), 1);
    }

    ~ScopedPathOverride() {
        if (previous_.has_value()) {
            (void)setenv("PATH", previous_->c_str(), 1);
        } else {
            (void)unsetenv("PATH");
        }
    }

private:
    std::optional<std::string> previous_;
};

void write_executable(const std::filesystem::path& path,
                      const std::string& contents) {
    {
        std::ofstream output(path);
        output << contents;
    }
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_exec |
            std::filesystem::perms::group_exec |
            std::filesystem::perms::others_exec,
        std::filesystem::perm_options::add);
}

bool contains_condition(const std::vector<std::string>& conditions,
                        const std::string& condition) {
    return std::find(
               conditions.begin(), conditions.end(), condition) !=
           conditions.end();
}

} // namespace

TEST_CASE("compute_test_routing resolves domain through configured system resolver") {
    if (!udp_socket_available()) {
        DOCTEST_INFO("UDP sockets unavailable in current environment");
        return;
    }

    const auto temp_dir = make_temp_dir();
    CacheManager cache(temp_dir);
    cache.ensure_dir();

    TestDnsServer server({"10.0.0.53"}, {"2001:db8::53"});

    Config config = build_test_config();
    api::SystemResolver system_resolver;
    system_resolver.address = server.address();
    config.dns->system_resolver = system_resolver;

    const auto ip_list_path = temp_dir / "resolved-ip-list.txt";
    const auto domain_list_path = temp_dir / "domain-list.txt";
    {
        std::ofstream list(ip_list_path);
        list << "10.0.0.53/32\n";
    }
    {
        std::ofstream list(domain_list_path);
        list << "www.example.com\n";
    }
    ListConfig ip_list;
    ip_list.file = ip_list_path.string();
    ListConfig domain_list;
    domain_list.file = domain_list_path.string();
    config.lists = std::map<std::string, ListConfig>{
        {"resolved_ips", ip_list},
        {"domains", domain_list},
    };
    RouteRule ip_rule;
    ip_rule.outbound = "vpn";
    ip_rule.list = std::vector<std::string>{"resolved_ips"};
    RouteRule domain_rule;
    domain_rule.outbound = "vpn";
    domain_rule.list = std::vector<std::string>{"domains"};
    RouteConfig route;
    route.rules = std::vector<RouteRule>{ip_rule, domain_rule};
    config.route = route;

    const auto result = compute_test_routing(config, cache, "www.example.com");

    CHECK(result.is_domain);
    CHECK(result.resolved_ips == std::vector<std::string>{"10.0.0.53", "2001:db8::53"});
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].ip == "10.0.0.53");
    CHECK(result.entries[1].ip == "2001:db8::53");
    CHECK_FALSE(result.dns_error.has_value());
    REQUIRE(result.rule_diagnostics.size() == 2);
    const auto& ip_diagnostic = result.rule_diagnostics[0];
    CHECK_FALSE(ip_diagnostic.target_in_lists);
    REQUIRE(ip_diagnostic.ip_rows.size() == 2);
    CHECK(ip_diagnostic.ip_rows[0].in_lists);
    REQUIRE(ip_diagnostic.ip_rows[0].list_match.has_value());
    CHECK(ip_diagnostic.ip_rows[0].list_match->list_name ==
          "resolved_ips");
    CHECK(ip_diagnostic.ip_rows[0].list_match->via == "10.0.0.53");
    CHECK_FALSE(ip_diagnostic.ip_rows[1].in_lists);

    const auto& domain_diagnostic = result.rule_diagnostics[1];
    CHECK(domain_diagnostic.target_in_lists);
    REQUIRE(domain_diagnostic.ip_rows.size() == 2);
    for (const auto& row : domain_diagnostic.ip_rows) {
        CHECK(row.in_lists);
        REQUIRE(row.list_match.has_value());
        CHECK(row.list_match->list_name == "domains");
        CHECK(row.list_match->via == "www.example.com");
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("second routing worker creation failure joins the first and releases admission") {
    if (!udp_socket_available()) {
        DOCTEST_INFO("UDP sockets unavailable in current environment");
        return;
    }

    const auto temp_dir = make_temp_dir();
    CacheManager cache(temp_dir);
    cache.ensure_dir();
    TestDnsServer server(
        {"192.0.2.10", "192.0.2.11"}, {});
    Config config = build_test_config();
    api::SystemResolver system_resolver;
    system_resolver.address = server.address();
    config.dns->system_resolver = system_resolver;

    BoundedOperationAdmission admission(1);
    BlockingExecutor executor(1, 1);
    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());
    auto completion = std::make_shared<std::promise<bool>>();
    auto completed = completion->get_future();
    inject_test_routing_worker_creation_failure(1);
    REQUIRE(executor.try_post(
        "routing-worker-creation-fault",
        [&config,
         &cache,
         completion,
         lease = std::move(*lease)]() mutable {
            (void)lease;
            try {
                (void)compute_test_routing(
                    config,
                    cache,
                    "worker-fault.example",
                    nullptr,
                    std::nullopt,
                    FirewallBackend::iptables);
                completion->set_value(false);
            } catch (const std::runtime_error& error) {
                completion->set_value(
                    std::string(error.what()).find(
                        "worker creation failure") !=
                    std::string::npos);
            } catch (...) {
                completion->set_exception(
                    std::current_exception());
            }
        }));

    REQUIRE(completed.wait_for(std::chrono::seconds{2}) ==
            std::future_status::ready);
    CHECK(completed.get());
    executor.submit("routing-worker-creation-barrier", [] {}).get();
    CHECK(admission.active() == 0);
    auto replacement = admission.try_acquire();
    REQUIRE(replacement.has_value());
    replacement->reset();

    const auto retry = compute_test_routing(
        config,
        cache,
        "worker-fault.example",
        nullptr,
        std::nullopt,
        FirewallBackend::iptables);
    CHECK(retry.resolved_ips ==
          std::vector<std::string>{"192.0.2.10", "192.0.2.11"});
    CHECK(retry.entries.size() == 2);

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("compute_test_routing falls back to resolv.conf when system resolver is absent") {
    const auto temp_dir = make_temp_dir();
    CacheManager cache(temp_dir);
    cache.ensure_dir();

    Config config = build_test_config();

    const auto result = compute_test_routing(config, cache, "example.invalid");

    CHECK(result.is_domain);
    CHECK(result.resolved_ips.empty());
    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries.front().ip == "(no IPs resolved)");

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("routing test system resolver refuses to outlive its operation deadline") {
    const auto temp_dir = make_temp_dir();
    CacheManager cache(temp_dir);
    cache.ensure_dir();

    Config config = build_test_config();
    const auto started = std::chrono::steady_clock::now();
    CHECK_THROWS_AS(
        compute_test_routing(
            config,
            cache,
            "example.invalid",
            nullptr,
            started + std::chrono::milliseconds{500}),
        RoutingTestTimeoutError);
    const auto elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    CHECK(elapsed < std::chrono::milliseconds{250});

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("custom DNS socket closes on repeated post-open deadline faults") {
    if (!udp_socket_available()) {
        DOCTEST_INFO("UDP sockets unavailable in current environment");
        return;
    }

    const auto temp_dir = make_temp_dir();
    CacheManager cache(temp_dir);
    cache.ensure_dir();
    Config config = build_test_config();
    api::SystemResolver system_resolver;
    system_resolver.address = "127.0.0.1:9";
    config.dns->system_resolver = system_resolver;

    const std::size_t before = open_fd_count();
    REQUIRE(before > 0);
    for (int attempt = 0; attempt < 32; ++attempt) {
        inject_test_routing_dns_socket_failure();
        CHECK_THROWS_AS(
            compute_test_routing(
                config,
                cache,
                "socket-fault.example",
                nullptr,
                std::chrono::steady_clock::now() +
                    std::chrono::seconds{2},
                FirewallBackend::iptables),
            RoutingTestTimeoutError);
    }
    const std::size_t after = open_fd_count();
    REQUIRE(after > 0);
    CHECK(after <= before + 1);

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("compute_test_routing includes route rule conditions in diagnostics") {
    const auto temp_dir = make_temp_dir();
    CacheManager cache(temp_dir);
    cache.ensure_dir();

    Config config = build_test_config();
    RouteRule rule;
    rule.outbound = "vpn";
    rule.list = std::vector<std::string>{"work", "media"};
    rule.proto = "tcp";
    rule.src_addr = "192.168.1.0/24";
    rule.dest_addr = "10.0.0.0/8";
    rule.src_port = "1024-65535";
    rule.dest_port = "443";

    RouteConfig route;
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;

    const auto result = compute_test_routing(config, cache, "8.8.8.8");

    REQUIRE(result.rule_diagnostics.size() == 1);
    const auto& diagnostic_rule = result.rule_diagnostics.front().rule;
    CHECK(diagnostic_rule.outbound == "vpn");
    REQUIRE(diagnostic_rule.list.has_value());
    CHECK(*diagnostic_rule.list == std::vector<std::string>{"work", "media"});
    CHECK(diagnostic_rule.proto == "tcp");
    CHECK(diagnostic_rule.src_addr == "192.168.1.0/24");
    CHECK(diagnostic_rule.dest_addr == "10.0.0.0/8");
    CHECK(diagnostic_rule.src_port == "1024-65535");
    CHECK(diagnostic_rule.dest_port == "443");

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("compute_test_routing uses captured iptables backend and realized A-B names") {
    const auto temp_dir = make_temp_dir();
    const auto bin_dir = temp_dir / "bin";
    const auto invocation_log = temp_dir / "ipset-invocations.txt";
    const auto wrong_backend_log = temp_dir / "nft-invocations.txt";
    std::filesystem::create_directories(bin_dir);

    write_executable(bin_dir / "iptables", "#!/bin/sh\nexit 0\n");
    write_executable(
        bin_dir / "nft",
        "#!/bin/sh\n"
        "echo \"$@\" >> " + wrong_backend_log.string() + "\n"
        "exit 1\n");
    write_executable(
        bin_dir / "ipset",
        "#!/bin/sh\n"
        "echo \"$@\" >> " + invocation_log.string() + "\n"
        "if [ \"$1\" = test ] && [ \"$2\" = kpbr4S_remote_B ] && "
        "[ \"$3\" = 203.0.113.10 ]; then exit 0; fi\n"
        "exit 1\n");
    ScopedPathOverride path_override(
        bin_dir.string() + ":/usr/bin:/bin");

    const auto list_path = temp_dir / "remote.txt";
    {
        std::ofstream list(list_path);
        list << "203.0.113.10/32\n";
    }
    CacheManager cache(temp_dir / "cache");
    cache.ensure_dir();
    Config config = build_test_config();
    ListConfig list;
    list.file = list_path.string();
    config.lists =
        std::map<std::string, ListConfig>{{"remote", list}};
    DaemonConfig daemon;
    daemon.firewall_backend =
        api::DaemonConfigFirewallBackend::AUTO;
    config.daemon = daemon;
    Outbound outbound;
    outbound.tag = "vpn";
    outbound.type = OutboundType::TABLE;
    outbound.table = 100;
    config.outbounds = std::vector<Outbound>{outbound};
    RouteRule rule;
    rule.outbound = "vpn";
    rule.list = std::vector<std::string>{"remote"};
    RouteConfig route;
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;

    RuleState realized;
    realized.rule_index = 0;
    realized.list_names = {"remote"};
    realized.set_names = {"kpbr4S_remote_B"};
    realized.outbound_tag = "vpn";
    realized.action_type = RuleActionType::Mark;
    const std::vector<RuleState> realized_rules{realized};

    const auto result = compute_test_routing(
        config,
        cache,
        "203.0.113.10",
        &realized_rules,
        std::nullopt,
        FirewallBackend::iptables);

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries.front().expected_outbound == "vpn");
    CHECK(result.entries.front().actual_outbound == "vpn");
    CHECK(result.entries.front().ok);
    REQUIRE(result.rule_diagnostics.size() == 1);
    REQUIRE(result.rule_diagnostics.front().ip_rows.size() == 1);
    const auto& row = result.rule_diagnostics.front().ip_rows.front();
    CHECK(row.in_lists);
    REQUIRE(row.in_ipset.has_value());
    CHECK(*row.in_ipset);

    std::ifstream invocations(invocation_log);
    const std::string invocation_contents{
        std::istreambuf_iterator<char>(invocations),
        std::istreambuf_iterator<char>()};
    CHECK(invocation_contents.find("test kpbr4S_remote_B 203.0.113.10") !=
          std::string::npos);
    CHECK_FALSE(std::filesystem::exists(wrong_backend_log));
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("test-routing list lookups stay on one cache generation") {
    const auto temp_dir = make_temp_dir();
    const auto slow_file = temp_dir / "slow-local-list.txt";
    {
        std::ofstream output(slow_file);
        for (std::size_t line = 0; line < 1000000U; ++line) {
            output << "# filler\n";
        }
    }

    auto transport =
        std::make_shared<RoutingSequenceHttpTransport>();
    CacheManager cache(
        temp_dir / "cache", 16U * 1024U * 1024U, transport);
    cache.ensure_dir();
    constexpr const char* target_url =
        "https://example.test/routing-target.txt";
    transport->enqueue("203.0.113.77/32\n");
    REQUIRE(cache.download("z_target", target_url).updated());

    Config config = build_test_config();
    ListConfig slow_list;
    slow_list.file = slow_file.string();
    ListConfig target_list;
    target_list.url = target_url;
    config.lists = std::map<std::string, ListConfig>{
        {"a_slow", slow_list},
        {"z_target", target_list},
    };
    Outbound outbound;
    outbound.tag = "vpn";
    outbound.type = OutboundType::TABLE;
    outbound.table = 100;
    config.outbounds = std::vector<Outbound>{outbound};
    RouteRule slow_rule;
    slow_rule.outbound = "vpn";
    slow_rule.list = std::vector<std::string>{"a_slow"};
    RouteRule target_rule;
    target_rule.outbound = "vpn";
    target_rule.list = std::vector<std::string>{"z_target"};
    RouteConfig route;
    route.rules =
        std::vector<RouteRule>{slow_rule, target_rule};
    config.route = route;

    std::optional<TestRoutingResult> routing_result;
    std::exception_ptr routing_error;
    std::thread diagnostic([&]() {
        try {
            routing_result = compute_test_routing(
                config, cache, "203.0.113.77");
        } catch (...) {
            routing_error = std::current_exception();
        }
    });

    const auto open_deadline =
        std::chrono::steady_clock::now() +
        std::chrono::seconds{3};
    bool observed_first_list = false;
    while (std::chrono::steady_clock::now() < open_deadline) {
        if (process_has_open_path(slow_file)) {
            observed_first_list = true;
            break;
        }
        std::this_thread::sleep_for(
            std::chrono::milliseconds{1});
    }

    bool refresh_updated = false;
    std::exception_ptr refresh_error;
    if (observed_first_list) {
        // Commit a new target-list generation while the first referenced list
        // is still being streamed. The diagnostic must retain the old target
        // generation captured for the whole lookup transaction.
        try {
            transport->enqueue("198.51.100.99/32\n");
            refresh_updated =
                cache.download("z_target", target_url).updated();
        } catch (...) {
            refresh_error = std::current_exception();
        }
    }
    diagnostic.join();
    REQUIRE(observed_first_list);
    if (refresh_error) {
        std::rethrow_exception(refresh_error);
    }
    REQUIRE(refresh_updated);
    if (routing_error) {
        std::rethrow_exception(routing_error);
    }
    REQUIRE(routing_result.has_value());
    REQUIRE(routing_result->rule_diagnostics.size() == 2);
    REQUIRE(
        routing_result->rule_diagnostics[1].ip_rows.size() == 1);
    CHECK(
        routing_result->rule_diagnostics[1].ip_rows[0].in_lists);
    REQUIRE(
        routing_result->rule_diagnostics[1].ip_rows[0]
            .list_match.has_value());
    CHECK(
        routing_result->rule_diagnostics[1].ip_rows[0]
            .list_match->list_name == "z_target");

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("routing test deadline kills a slow kernel check and releases admission") {
    const auto temp_dir = make_temp_dir();
    const auto bin_dir = temp_dir / "bin";
    const auto started_marker = temp_dir / "ipset-started";
    std::filesystem::create_directories(bin_dir);
    write_executable(bin_dir / "iptables", "#!/bin/sh\nexit 0\n");
    write_executable(
        bin_dir / "ipset",
        "#!/bin/sh\n"
        "echo started > " + started_marker.string() + "\n"
        "sleep 10\n"
        "exit 1\n");
    ScopedPathOverride path_override(
        bin_dir.string() + ":/usr/bin:/bin");

    const auto list_path = temp_dir / "remote.txt";
    {
        std::ofstream list(list_path);
        list << "203.0.113.88/32\n";
    }
    CacheManager cache(temp_dir / "cache");
    cache.ensure_dir();
    Config config = build_test_config();
    ListConfig list;
    list.file = list_path.string();
    config.lists =
        std::map<std::string, ListConfig>{{"remote", list}};
    DaemonConfig daemon;
    daemon.firewall_backend =
        api::DaemonConfigFirewallBackend::IPTABLES;
    config.daemon = daemon;
    Outbound outbound;
    outbound.tag = "vpn";
    outbound.type = OutboundType::TABLE;
    outbound.table = 100;
    config.outbounds = std::vector<Outbound>{outbound};
    RouteRule rule;
    rule.outbound = "vpn";
    rule.list = std::vector<std::string>{"remote"};
    RouteConfig route;
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;
    RuleState realized;
    realized.rule_index = 0;
    realized.list_names = {"remote"};
    realized.set_names = {"kpbr4S_remote_B"};
    realized.outbound_tag = "vpn";
    realized.action_type = RuleActionType::Mark;
    const std::vector<RuleState> realized_rules{realized};

    BoundedOperationAdmission admission(1);
    BlockingExecutor executor(1, 1);
    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());
    auto completion =
        std::make_shared<std::promise<bool>>();
    auto completed = completion->get_future();
    const auto started = std::chrono::steady_clock::now();
    const RoutingTestDeadline deadline =
        started + std::chrono::milliseconds{200};
    REQUIRE(executor.try_post(
        "slow-kernel-routing-test",
        [&config,
         &cache,
         &realized_rules,
         deadline,
         completion,
         lease = std::move(*lease)]() mutable {
            (void)lease;
            try {
                (void)compute_test_routing(
                    config,
                    cache,
                    "203.0.113.88",
                    &realized_rules,
                    deadline);
                completion->set_value(false);
            } catch (const RoutingTestTimeoutError&) {
                completion->set_value(true);
            } catch (...) {
                completion->set_exception(
                    std::current_exception());
            }
        }));

    // A caller may abandon its response wait before the server's absolute
    // operation deadline. That must not leave the admitted worker occupied by
    // the slow kernel subprocess indefinitely.
    CHECK(completed.wait_for(std::chrono::milliseconds{50}) ==
          std::future_status::timeout);
    const auto completion_status =
        completed.wait_for(std::chrono::seconds{2});
    CHECK(completion_status == std::future_status::ready);
    if (completion_status == std::future_status::ready) {
        CHECK(completed.get());
    }
    executor.submit("slow-kernel-routing-barrier", [] {}).get();
    const auto elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    CHECK(std::filesystem::exists(started_marker));
    CHECK(elapsed < std::chrono::milliseconds{1500});
    CHECK(admission.active() == 0);
    auto replacement = admission.try_acquire();
    CHECK(replacement.has_value());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("compute_test_routing uses captured nft backend and realized names by rule index") {
    const auto temp_dir = make_temp_dir();
    const auto bin_dir = temp_dir / "bin";
    const auto invocation_log = temp_dir / "nft-invocations.txt";
    const auto wrong_backend_log = temp_dir / "ipset-invocations.txt";
    std::filesystem::create_directories(bin_dir);

    write_executable(bin_dir / "iptables", "#!/bin/sh\nexit 0\n");
    write_executable(
        bin_dir / "ipset",
        "#!/bin/sh\n"
        "echo \"$@\" >> " + wrong_backend_log.string() + "\n"
        "exit 1\n");
    write_executable(
        bin_dir / "nft",
        "#!/bin/sh\n"
        "echo \"$@\" >> " + invocation_log.string() + "\n"
        "if [ \"$1\" = get ] && [ \"$5\" = kpbr4_remote_live_B ] && "
        "[ \"$7\" = 198.51.100.8 ]; then exit 0; fi\n"
        "exit 1\n");
    ScopedPathOverride path_override(
        bin_dir.string() + ":/usr/bin:/bin");

    const auto list_path = temp_dir / "remote.txt";
    {
        std::ofstream list(list_path);
        list << "198.51.100.8/32\n";
    }
    CacheManager cache(temp_dir / "cache");
    cache.ensure_dir();
    Config config = build_test_config();
    ListConfig list;
    list.file = list_path.string();
    config.lists =
        std::map<std::string, ListConfig>{{"remote", list}};
    DaemonConfig daemon;
    daemon.firewall_backend =
        api::DaemonConfigFirewallBackend::AUTO;
    config.daemon = daemon;
    Outbound outbound;
    outbound.tag = "vpn";
    outbound.type = OutboundType::TABLE;
    outbound.table = 100;
    config.outbounds = std::vector<Outbound>{outbound};
    RouteRule first;
    first.enabled = false;
    first.outbound = "vpn";
    first.list = std::vector<std::string>{"remote"};
    RouteRule second;
    second.outbound = "vpn";
    second.list = std::vector<std::string>{"remote"};
    RouteConfig route;
    route.rules = std::vector<RouteRule>{first, second};
    config.route = route;

    RuleState realized_second;
    realized_second.rule_index = 1;
    realized_second.list_names = {"remote"};
    realized_second.set_names = {"kpbr4_remote_live_B"};
    realized_second.outbound_tag = "vpn";
    realized_second.action_type = RuleActionType::Mark;
    RuleState realized_first;
    realized_first.rule_index = 0;
    realized_first.action_type = RuleActionType::Skip;
    const std::vector<RuleState> realized_rules{
        realized_second, realized_first};

    const auto result = compute_test_routing(
        config,
        cache,
        "198.51.100.8",
        &realized_rules,
        std::nullopt,
        FirewallBackend::nftables);

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries.front().actual_outbound == "vpn");
    CHECK(result.entries.front().ok);
    REQUIRE(result.rule_diagnostics.size() == 2);
    REQUIRE(result.rule_diagnostics[1].ip_rows.size() == 1);
    REQUIRE(result.rule_diagnostics[1].ip_rows[0].in_ipset.has_value());
    CHECK(*result.rule_diagnostics[1].ip_rows[0].in_ipset);

    std::ifstream invocations(invocation_log);
    const std::string invocation_contents{
        std::istreambuf_iterator<char>(invocations),
        std::istreambuf_iterator<char>()};
    CHECK(invocation_contents.find(
              "get element inet KeenPbrTable kpbr4_remote_live_B { 198.51.100.8 }") !=
          std::string::npos);
    CHECK_FALSE(std::filesystem::exists(wrong_backend_log));
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("test-routing reports packet selectors as insufficient context") {
    const auto temp_dir = make_temp_dir();
    const auto bin_dir = temp_dir / "bin";
    std::filesystem::create_directories(bin_dir);
    write_executable(bin_dir / "iptables", "#!/bin/sh\nexit 0\n");
    ScopedPathOverride path_override(
        bin_dir.string() + ":/usr/bin:/bin");

    CacheManager cache(temp_dir / "cache");
    cache.ensure_dir();
    Config config = build_test_config();
    DaemonConfig daemon;
    daemon.firewall_backend =
        api::DaemonConfigFirewallBackend::IPTABLES;
    config.daemon = daemon;
    Outbound outbound;
    outbound.tag = "vpn";
    outbound.type = OutboundType::TABLE;
    outbound.table = 100;
    config.outbounds = std::vector<Outbound>{outbound};
    RouteRule rule;
    rule.outbound = "vpn";
    rule.src_addr = "192.0.2.0/24";
    rule.proto = "tcp";
    rule.src_port = "1024-65535";
    rule.dest_port = "443";
    rule.dscp = 10;
    RouteConfig route;
    route.inbound_interfaces = std::vector<std::string>{"br0"};
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;

    RuleState realized;
    realized.rule_index = 0;
    realized.outbound_tag = "vpn";
    realized.action_type = RuleActionType::Mark;
    const std::vector<RuleState> realized_rules{realized};
    const auto result = compute_test_routing(
        config, cache, "203.0.113.20", &realized_rules);

    REQUIRE(result.entries.size() == 1);
    const auto& entry = result.entries.front();
    CHECK(entry.expected_outbound == "(unknown)");
    CHECK(entry.actual_outbound == "(unknown)");
    CHECK_FALSE(entry.ok);
    CHECK(entry.evaluation ==
          RoutingMatchEvaluation::InsufficientContext);
    for (const auto& condition :
         {"inbound_interface",
          "source_address",
          "protocol",
          "source_port",
          "destination_port",
          "dscp"}) {
        CHECK(contains_condition(
            entry.unknown_conditions, condition));
    }
    REQUIRE(result.rule_diagnostics.size() == 1);
    REQUIRE(result.rule_diagnostics[0].ip_rows.size() == 1);
    CHECK(result.rule_diagnostics[0].ip_rows[0].evaluation ==
          RoutingMatchEvaluation::InsufficientContext);
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("test-routing evaluates destination address with the target IP") {
    const auto temp_dir = make_temp_dir();
    const auto bin_dir = temp_dir / "bin";
    std::filesystem::create_directories(bin_dir);
    write_executable(bin_dir / "iptables", "#!/bin/sh\nexit 0\n");
    ScopedPathOverride path_override(
        bin_dir.string() + ":/usr/bin:/bin");

    CacheManager cache(temp_dir / "cache");
    cache.ensure_dir();
    Config config = build_test_config();
    DaemonConfig daemon;
    daemon.firewall_backend =
        api::DaemonConfigFirewallBackend::IPTABLES;
    config.daemon = daemon;
    Outbound outbound;
    outbound.tag = "vpn";
    outbound.type = OutboundType::TABLE;
    outbound.table = 100;
    config.outbounds = std::vector<Outbound>{outbound};
    RouteRule rule;
    rule.outbound = "vpn";
    rule.dest_addr = "203.0.113.0/24";
    RouteConfig route;
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;
    RuleState realized;
    realized.rule_index = 0;
    realized.outbound_tag = "vpn";
    realized.action_type = RuleActionType::Mark;
    const std::vector<RuleState> realized_rules{realized};

    const auto result = compute_test_routing(
        config, cache, "203.0.113.20", &realized_rules);
    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries.front().expected_outbound == "vpn");
    CHECK(result.entries.front().actual_outbound == "vpn");
    CHECK(result.entries.front().evaluation ==
          RoutingMatchEvaluation::Matched);
    CHECK(result.entries.front().ok);
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("test-routing keeps active config aligned with live rule state when a draft exists") {
    const auto temp_dir = make_temp_dir();
    const auto bin_dir = temp_dir / "bin";
    std::filesystem::create_directories(bin_dir);
    write_executable(bin_dir / "iptables", "#!/bin/sh\nexit 0\n");
    ScopedPathOverride path_override(
        bin_dir.string() + ":/usr/bin:/bin");

    auto make_config = [](const std::string& outbound_tag) {
        Config config = build_test_config();
        DaemonConfig daemon;
        daemon.firewall_backend =
            api::DaemonConfigFirewallBackend::IPTABLES;
        config.daemon = daemon;
        Outbound outbound;
        outbound.tag = outbound_tag;
        outbound.type = OutboundType::TABLE;
        outbound.table = outbound_tag == "active-vpn" ? 100 : 200;
        config.outbounds = std::vector<Outbound>{outbound};
        RouteRule rule;
        rule.outbound = outbound_tag;
        rule.dest_addr = "203.0.113.0/24";
        RouteConfig route;
        route.rules = std::vector<RouteRule>{rule};
        config.route = route;
        return config;
    };

    ConfigStore store(make_config("active-vpn"));
    store.stage_config(
        make_config("draft-vpn"), "{\"draft\":true}");
    REQUIRE(store.config_is_draft());
    const auto active = store.active_snapshot();

    RuleState realized;
    realized.rule_index = 0;
    realized.outbound_tag = "active-vpn";
    realized.action_type = RuleActionType::Mark;
    const std::vector<RuleState> realized_rules{realized};
    CacheManager cache(temp_dir / "cache");
    cache.ensure_dir();
    const auto result = compute_test_routing(
        active.config,
        cache,
        "203.0.113.20",
        &realized_rules);

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries.front().expected_outbound == "active-vpn");
    CHECK(result.entries.front().actual_outbound == "active-vpn");
    CHECK(result.entries.front().expected_outbound != "draft-vpn");
    CHECK(result.entries.front().ok);
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("daemon test-routing response is rendered as a human-readable table") {
    const nlohmann::json response = {
        {"ok", true},
        {"result",
         {{"target", "example.com"},
          {"config_scope", "active"},
          {"unapplied_draft", false},
          {"resolved_ips", {"203.0.113.10"}},
          {"warnings", nlohmann::json::array()},
          {"dns_error", nullptr},
          {"entries",
           {{{"ip", "203.0.113.10"},
             {"expected_outbound", "vpn"},
             {"actual_outbound", "vpn"},
             {"ok", true},
             {"evaluation", "matched"},
             {"unknown_conditions", nlohmann::json::array()},
             {"list_match",
              {{"list", "domains"},
               {"via", "example.com"}}}}}}}}};

    std::ostringstream stdout_capture;
    std::ostringstream stderr_capture;
    auto* previous_stdout = std::cout.rdbuf(
        stdout_capture.rdbuf());
    auto* previous_stderr = std::cerr.rdbuf(
        stderr_capture.rdbuf());
    const int exit_code = run_test_routing_command(response);
    std::cout.rdbuf(previous_stdout);
    std::cerr.rdbuf(previous_stderr);

    CHECK(exit_code == 0);
    CHECK(stderr_capture.str().empty());
    CHECK(stdout_capture.str().find("Target: example.com") !=
          std::string::npos);
    CHECK(stdout_capture.str().find("Expected Outbound") !=
          std::string::npos);
    CHECK(stdout_capture.str().find(
              "domains (via example.com)") != std::string::npos);
    CHECK(stdout_capture.str().find("{\"") == std::string::npos);
}
