#include "test_routing.hpp"

#include "../config/routing_state.hpp"
#include "../dns/dns_server.hpp"
#include "../dns/legacy_resolver_lock.hpp"
#include "../lists/ipset.hpp"
#include "../lists/kernel_set_tester.hpp"
#include "../lists/list_entry_visitor.hpp"
#include "../lists/list_streamer.hpp"
#include "../util/format_compat.hpp"
#include "../util/string_compat.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

namespace {

#ifdef KEEN_PBR3_TESTING
std::atomic<std::ptrdiff_t> injected_worker_creation_failure{-1};
std::atomic<bool> injected_dns_socket_failure{false};
#endif

class UniqueSocketFd {
public:
    explicit UniqueSocketFd(int fd = -1) noexcept : fd_(fd) {}
    ~UniqueSocketFd() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    UniqueSocketFd(const UniqueSocketFd&) = delete;
    UniqueSocketFd& operator=(const UniqueSocketFd&) = delete;

    int get() const noexcept { return fd_; }

private:
    int fd_{-1};
};

class ThreadJoinGuard {
public:
    explicit ThreadJoinGuard(std::vector<std::thread>& workers) noexcept
        : workers_(workers) {}

    ~ThreadJoinGuard() noexcept { join_all(); }

    void join_all() noexcept {
        if (joined_) {
            return;
        }
        joined_ = true;
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                // This guard is only destroyed by the thread that created
                // the workers, so the documented join error cases (not
                // joinable or self-join) are excluded by construction.
                worker.join();
            }
        }
    }

private:
    std::vector<std::thread>& workers_;
    bool joined_{false};
};

void enforce_routing_test_deadline(
    const std::optional<RoutingTestDeadline>& deadline) {
    if (deadline.has_value() &&
        std::chrono::steady_clock::now() >= *deadline) {
        throw RoutingTestTimeoutError(
            "routing test operation deadline exceeded");
    }
}

std::chrono::milliseconds routing_test_remaining(
    const std::optional<RoutingTestDeadline>& deadline,
    std::chrono::milliseconds fallback) {
    if (!deadline.has_value()) {
        return fallback;
    }
    const auto remaining =
        std::chrono::ceil<std::chrono::milliseconds>(
            *deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) {
        throw RoutingTestTimeoutError(
            "routing test operation deadline exceeded");
    }
    return remaining;
}

bool is_ipv4_address(const std::string& s) {
    struct in_addr addr;
    return inet_pton(AF_INET, s.c_str(), &addr) == 1;
}

bool is_ipv6_address(const std::string& s) {
    struct in6_addr addr;
    return inet_pton(AF_INET6, s.c_str(), &addr) == 1;
}

bool is_ip_address(const std::string& s) {
    return is_ipv4_address(s) || is_ipv6_address(s);
}

// "www.google.com" → ["www.google.com", "google.com", "com"]
std::vector<std::string> domain_candidates(const std::string& domain) {
    std::vector<std::string> candidates;
    std::string d = domain;
    while (true) {
        candidates.push_back(d);
        auto dot = d.find('.');
        if (dot == std::string::npos) break;
        d = d.substr(dot + 1);
    }
    return candidates;
}

std::string lowercase_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

struct ListLookupData {
    IpSet ip_set;
    std::set<std::string> domain_set; // normalized lowercase, wildcard prefix stripped
};

class ListLookupBuilder : public ListEntryVisitor {
public:
    explicit ListLookupBuilder(
        std::optional<RoutingTestDeadline> deadline)
        : deadline_(deadline) {}

    ListLookupData data;

    void on_entry(EntryType type, std::string_view entry) override {
        if ((++entry_count_ & 0xFFU) == 0U) {
            enforce_routing_test_deadline(deadline_);
        }
        switch (type) {
            case EntryType::Ip:
                data.ip_set.add_address(std::string(entry));
                break;
            case EntryType::Cidr:
                data.ip_set.add_cidr(std::string(entry));
                break;
            case EntryType::Domain: {
                std::string d(entry);
                if (has_prefix(d, "*.")) d = d.substr(2);
                std::transform(d.begin(), d.end(), d.begin(), ::tolower);
                data.domain_set.insert(std::move(d));
                break;
            }
        }
    }

private:
    std::optional<RoutingTestDeadline> deadline_;
    std::size_t entry_count_{0};
};

// Pre-build lookup data for all lists referenced in route rules.
std::map<std::string, ListLookupData> build_all_lookups(
    const Config& config,
    const CacheManager& cache,
    std::optional<RoutingTestDeadline> deadline) {
    enforce_routing_test_deadline(deadline);
    std::map<std::string, ListLookupData> result;
    const auto& route_rules =
        config.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{});
    const auto& lists_map =
        config.lists.value_or(std::map<std::string, ListConfig>{});
    std::set<std::string> referenced;
    for (const auto& rule : route_rules) {
        if (!route_rule_enabled(rule)) {
            continue;
        }
        for (const auto& list_name : route_rule_lists(rule)) {
            referenced.insert(list_name);
        }
    }

    const std::vector<std::string> referenced_names(
        referenced.begin(), referenced.end());
    const auto cache_snapshot =
        cache.capture_generation(referenced_names);
    ListStreamer streamer(cache, cache_snapshot);

    for (const auto& list_name : referenced) {
        enforce_routing_test_deadline(deadline);
        auto it = lists_map.find(list_name);
        if (it == lists_map.end()) continue;
        ListLookupBuilder builder(deadline);
        streamer.stream_list(list_name, it->second, builder);
        enforce_routing_test_deadline(deadline);
        result.emplace(list_name, std::move(builder.data));
    }
    return result;
}

bool append_unique_ip(std::vector<std::string>& ips, const std::string& ip) {
    if (ip.empty() || std::find(ips.begin(), ips.end(), ip) != ips.end()) {
        return false;
    }
    ips.push_back(ip);
    return true;
}

bool extract_ips_from_dns_answer(const unsigned char* answer,
                                 int answer_len,
                                 int expected_type,
                                 std::vector<std::string>& ips,
                                 std::string* error_out) {
    ns_msg handle {};
    if (ns_initparse(answer, answer_len, &handle) < 0) {
        if (error_out) {
            *error_out = "Failed to parse DNS response";
        }
        return false;
    }

    const int answer_count = ns_msg_count(handle, ns_s_an);
    bool found = false;
    for (int i = 0; i < answer_count; ++i) {
        ns_rr rr {};
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            continue;
        }
        if (ns_rr_class(rr) != ns_c_in || ns_rr_type(rr) != expected_type) {
            continue;
        }

        char buf[INET6_ADDRSTRLEN] = {};
        if (expected_type == ns_t_a && ns_rr_rdlen(rr) == 4) {
            if (inet_ntop(AF_INET, ns_rr_rdata(rr), buf, sizeof(buf)) != nullptr) {
                found = append_unique_ip(ips, buf) || found;
            }
        } else if (expected_type == ns_t_aaaa && ns_rr_rdlen(rr) == 16) {
            if (inet_ntop(AF_INET6, ns_rr_rdata(rr), buf, sizeof(buf)) != nullptr) {
                found = append_unique_ip(ips, buf) || found;
            }
        }
    }

    return found;
}

std::optional<std::string> query_dns_record_with_resolver(
    const std::optional<DnsServerConfig>& server,
    const std::string& domain,
    int record_type,
    std::vector<std::string>& ips,
    std::optional<RoutingTestDeadline> deadline) {
    enforce_routing_test_deadline(deadline);
    std::array<unsigned char, NS_PACKETSZ * 8> answer {};
    int response_len = -1;
    int resolver_error = 0;

    if (!server.has_value()) {
        // Keep the diagnostic on its absolute operation deadline even when
        // resolv.conf points at an unresponsive server. A private resolver
        // state avoids mutating the process-global _res used by runtime DNS.
        struct __res_state resolver_state {};
        if (res_ninit(&resolver_state) != 0) {
            return "Failed to initialize the system resolver";
        }
        struct ResolverStateGuard {
            struct __res_state* state;
            ~ResolverStateGuard() { res_nclose(state); }
        } resolver_guard{&resolver_state};

        if (deadline.has_value()) {
            const auto remaining = routing_test_remaining(
                deadline, std::chrono::seconds{2});
            const auto nameserver_count = std::max(
                1, resolver_state.nscount);
            constexpr auto scheduling_guard =
                std::chrono::milliseconds{250};
            const auto minimum_budget =
                std::chrono::seconds{nameserver_count} +
                scheduling_guard;
            if (remaining <= minimum_budget) {
                throw RoutingTestTimeoutError(
                    "routing test DNS deadline exceeded");
            }
            const auto per_nameserver_seconds =
                std::chrono::duration_cast<std::chrono::seconds>(
                    (remaining - scheduling_guard) /
                    nameserver_count)
                    .count();
            resolver_state.retrans = static_cast<int>(
                std::clamp<std::int64_t>(
                    per_nameserver_seconds, 1, 2));
            resolver_state.retry = 1;
        }

        response_len = res_nquery(&resolver_state,
                                  domain.c_str(),
                                  ns_c_in,
                                  record_type,
                                  answer.data(),
                                  static_cast<int>(answer.size()));
        resolver_error = resolver_state.res_h_errno;
    } else {
        sockaddr_storage resolver_addr {};
        socklen_t resolver_addr_len = 0;
        int address_family = AF_UNSPEC;

        if (is_ipv6_address(server->resolved_ip)) {
            auto* addr6 = reinterpret_cast<sockaddr_in6*>(&resolver_addr);
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(server->port);
            if (inet_pton(AF_INET6, server->resolved_ip.c_str(), &addr6->sin6_addr) != 1) {
                return keen_pbr3::format("Resolver '{}' has invalid IPv6 address", server->address);
            }
            address_family = AF_INET6;
            resolver_addr_len = sizeof(sockaddr_in6);
        } else {
            auto* addr4 = reinterpret_cast<sockaddr_in*>(&resolver_addr);
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(server->port);
            if (inet_pton(AF_INET, server->resolved_ip.c_str(), &addr4->sin_addr) != 1) {
                return keen_pbr3::format("Resolver '{}' has invalid IPv4 address", server->address);
            }
            address_family = AF_INET;
            resolver_addr_len = sizeof(sockaddr_in);
        }

        std::array<unsigned char, NS_PACKETSZ * 2> query {};
        int query_len = -1;
        {
            // res_mkquery() builds the packet using the global _res.
            std::lock_guard<std::mutex> resolver_lock(legacy_resolver_mutex());
            query_len = res_mkquery(ns_o_query,
                                    domain.c_str(),
                                    ns_c_in,
                                    record_type,
                                    nullptr,
                                    0,
                                    nullptr,
                                    query.data(),
                                    static_cast<int>(query.size()));
        }
        if (query_len < 0) {
            return keen_pbr3::format("Failed to build DNS {} query",
                                     record_type == ns_t_a ? "A" : "AAAA");
        }

        UniqueSocketFd socket_fd(
            socket(address_family, SOCK_DGRAM, 0));
        if (socket_fd.get() < 0) {
            return keen_pbr3::format("Failed to create DNS socket: {}", std::strerror(errno));
        }

#ifdef KEEN_PBR3_TESTING
        if (injected_dns_socket_failure.exchange(
                false, std::memory_order_acq_rel)) {
            throw RoutingTestTimeoutError(
                "synthetic routing test DNS deadline after socket open");
        }
#endif

        const auto socket_timeout_ms = std::min(
            routing_test_remaining(
                deadline, std::chrono::seconds{2}),
            std::chrono::milliseconds{2000});
        timeval socket_timeout {};
        socket_timeout.tv_sec =
            static_cast<time_t>(socket_timeout_ms.count() / 1000);
        socket_timeout.tv_usec = static_cast<suseconds_t>(
            (socket_timeout_ms.count() % 1000) * 1000);
        if (setsockopt(socket_fd.get(),
                       SOL_SOCKET,
                       SO_SNDTIMEO,
                       &socket_timeout,
                       sizeof(socket_timeout)) != 0 ||
            setsockopt(socket_fd.get(),
                       SOL_SOCKET,
                       SO_RCVTIMEO,
                       &socket_timeout,
                       sizeof(socket_timeout)) != 0) {
            const std::string error = std::strerror(errno);
            return keen_pbr3::format("Failed to configure DNS socket timeout: {}", error);
        }

        const ssize_t sent = sendto(socket_fd.get(),
                                    query.data(),
                                    static_cast<size_t>(query_len),
                                    0,
                                    reinterpret_cast<const sockaddr*>(&resolver_addr),
                                    resolver_addr_len);
        if (sent != static_cast<ssize_t>(query_len)) {
            const std::string error = std::strerror(errno);
            return keen_pbr3::format("Failed to send DNS {} query via '{}': {}",
                                     record_type == ns_t_a ? "A" : "AAAA",
                                     server->address,
                                     error);
        }

        const ssize_t received = recvfrom(socket_fd.get(),
                                          answer.data(),
                                          answer.size(),
                                          0,
                                          nullptr,
                                          nullptr);
        if (received <= 0) {
            const std::string error = std::strerror(errno);
            return keen_pbr3::format("DNS {} query via '{}' failed: {}",
                                     record_type == ns_t_a ? "A" : "AAAA",
                                     server->address,
                                     error);
        }
        response_len = static_cast<int>(received);
    }

    enforce_routing_test_deadline(deadline);

    if (response_len < 0) {
        const char* reason = hstrerror(resolver_error);
        return keen_pbr3::format("DNS {} query via '{}' failed: {}",
                                 record_type == ns_t_a ? "A" : "AAAA",
                                 server.has_value() ? server->address : "resolv.conf",
                                 reason != nullptr ? reason : "unknown resolver error");
    }

    std::string parse_error;
    if (!extract_ips_from_dns_answer(answer.data(), response_len, record_type, ips, &parse_error) &&
        !parse_error.empty()) {
        return keen_pbr3::format("DNS {} query via '{}' failed: {}",
                                 record_type == ns_t_a ? "A" : "AAAA",
                                 server.has_value() ? server->address : "resolv.conf",
                                 parse_error);
    }

    return std::nullopt;
}

std::vector<std::string> resolve_domain_with_system_resolver(const Config& config,
                                                             const std::string& domain,
                                                             std::vector<std::string>& warnings,
                                                             std::optional<RoutingTestDeadline> deadline) {
    enforce_routing_test_deadline(deadline);
    std::vector<std::string> ips;

    const DnsConfig dns_config = config.dns.value_or(DnsConfig{});
    std::optional<DnsServerConfig> resolver;
    if (dns_config.system_resolver.has_value() &&
        !dns_config.system_resolver->address.empty()) {
        try {
            resolver = parse_dns_server("system_resolver",
                                        dns_config.system_resolver->address,
                                        std::nullopt);
        } catch (const std::exception& e) {
            warnings.push_back(keen_pbr3::format("DNS system resolver '{}' is invalid: {}",
                                                 dns_config.system_resolver->address,
                                                 e.what()));
            return ips;
        }
    }

    std::optional<std::string> a_error =
        query_dns_record_with_resolver(
            resolver, domain, ns_t_a, ips, deadline);
    enforce_routing_test_deadline(deadline);
    std::optional<std::string> aaaa_error =
        query_dns_record_with_resolver(
            resolver, domain, ns_t_aaaa, ips, deadline);
    enforce_routing_test_deadline(deadline);

    if (ips.empty() && a_error.has_value() && aaaa_error.has_value()) {
        warnings.push_back(keen_pbr3::format("DNS resolution failed for '{}' via system resolver '{}': {}; {}",
                                             domain,
                                             resolver.has_value() ? resolver->address : "resolv.conf",
                                             *a_error,
                                             *aaaa_error));
    }

    return ips;
}

std::optional<ListMatchInfo> find_rule_match(const RouteRule& rule,
                                             const std::map<std::string, ListLookupData>& lookups,
                                             const std::string& ip,
                                             const std::vector<std::string>& domain_cands) {
    if (!route_rule_enabled(rule)) {
        return std::nullopt;
    }

    for (const auto& list_name : route_rule_lists(rule)) {
        auto it = lookups.find(list_name);
        if (it == lookups.end()) continue;
        const auto& lookup = it->second;

        if (!ip.empty() && lookup.ip_set.contains(ip)) {
            return ListMatchInfo{list_name, ip};
        }

        for (const auto& candidate : domain_cands) {
            std::string lower = candidate;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (contains(lookup.domain_set, lower)) {
                return ListMatchInfo{list_name, candidate};
            }
        }
    }
    return std::nullopt;
}

void append_unknown_condition(std::vector<std::string>& conditions,
                              const std::string& condition) {
    if (std::find(conditions.begin(), conditions.end(), condition) ==
        conditions.end()) {
        conditions.push_back(condition);
    }
}

std::vector<std::string> packet_context_conditions(const RouteRule& rule,
                                                   bool inbound_is_restricted) {
    std::vector<std::string> conditions;
    if (inbound_is_restricted) {
        conditions.push_back("inbound_interface");
    }
    if (rule.src_addr.has_value()) {
        conditions.push_back("source_address");
    }
    if (rule.proto.has_value()) {
        conditions.push_back("protocol");
    }
    if (rule.src_port.has_value()) {
        conditions.push_back("source_port");
    }
    if (rule.dest_port.has_value()) {
        conditions.push_back("destination_port");
    }
    if (rule.dscp.has_value()) {
        conditions.push_back("dscp");
    }
    return conditions;
}

std::optional<bool> destination_address_matches(const RouteRule& rule,
                                                const std::string& ip) {
    if (!rule.dest_addr.has_value()) {
        return true;
    }
    if (ip.empty() || !is_ip_address(ip)) {
        return std::nullopt;
    }

    const FirewallRuleCriteria criteria = build_firewall_rule_criteria(rule);
    IpSet destinations;
    for (const auto& address : criteria.dst_addr) {
        if (address.find('/') == std::string::npos) {
            destinations.add_address(address);
        } else {
            destinations.add_cidr(address);
        }
    }
    const bool matched = destinations.contains(ip);
    return criteria.negate_dst_addr ? !matched : matched;
}

struct RuleTargetEvaluation {
    RoutingMatchEvaluation evaluation{RoutingMatchEvaluation::NotMatched};
    std::optional<ListMatchInfo> list_match;
    std::vector<std::string> unknown_conditions;
};

RuleTargetEvaluation evaluate_rule_from_config(
    const RouteRule& rule,
    const std::map<std::string, ListLookupData>& lookups,
    const std::string& ip,
    const std::vector<std::string>& domain_cands,
    bool inbound_is_restricted) {
    RuleTargetEvaluation result;
    if (!route_rule_enabled(rule)) {
        return result;
    }

    result.list_match = find_rule_match(rule, lookups, ip, domain_cands);
    if (!route_rule_lists(rule).empty() && !result.list_match.has_value()) {
        return result;
    }

    const auto destination_match = destination_address_matches(rule, ip);
    if (destination_match.has_value() && !*destination_match) {
        return result;
    }

    result.unknown_conditions =
        packet_context_conditions(rule, inbound_is_restricted);
    if (!destination_match.has_value()) {
        append_unknown_condition(
            result.unknown_conditions, "destination_address");
    }
    if (!result.unknown_conditions.empty()) {
        result.evaluation = RoutingMatchEvaluation::InsufficientContext;
        return result;
    }

    result.evaluation = RoutingMatchEvaluation::Matched;
    return result;
}

struct OutboundEvaluation {
    std::string outbound{"(default)"};
    std::optional<ListMatchInfo> list_match;
    RoutingMatchEvaluation evaluation{RoutingMatchEvaluation::NotMatched};
    std::vector<std::string> unknown_conditions;
};

OutboundEvaluation find_expected_outbound(
    const std::vector<RouteRule>& route_rules,
    const std::map<std::string, ListLookupData>& lookups,
    const std::string& ip,
    const std::vector<std::string>& domain_cands,
    bool inbound_is_restricted,
    const std::optional<RoutingTestDeadline>& deadline) {
    for (const auto& rule : route_rules) {
        enforce_routing_test_deadline(deadline);
        auto evaluation = evaluate_rule_from_config(
            rule, lookups, ip, domain_cands, inbound_is_restricted);
        if (evaluation.evaluation == RoutingMatchEvaluation::NotMatched) {
            continue;
        }
        if (evaluation.evaluation ==
            RoutingMatchEvaluation::InsufficientContext) {
            return OutboundEvaluation{
                "(unknown)",
                std::move(evaluation.list_match),
                evaluation.evaluation,
                std::move(evaluation.unknown_conditions),
            };
        }
        return OutboundEvaluation{
            rule.outbound,
            std::move(evaluation.list_match),
            RoutingMatchEvaluation::Matched,
            {},
        };
    }
    return {};
}

std::string outbound_interface_name(const Config& config, const std::string& outbound_tag) {
    const auto& outbounds = config.outbounds.value_or(std::vector<Outbound>{});
    for (const auto& outbound : outbounds) {
        if (outbound.tag != outbound_tag) continue;
        return outbound.interface.value_or("-");
    }
    return "-";
}

bool executable_exists_in_path(
    const std::string& executable,
    const std::optional<RoutingTestDeadline>& deadline) {
    const char* path_value = std::getenv("PATH");
    if (path_value == nullptr) {
        return false;
    }
    const std::string path(path_value);
    std::size_t start = 0;
    while (start <= path.size()) {
        enforce_routing_test_deadline(deadline);
        const auto separator = path.find(':', start);
        const auto length = separator == std::string::npos
            ? path.size() - start
            : separator - start;
        const std::string directory = length == 0
            ? "."
            : path.substr(start, length);
        if (::access(
                (directory + "/" + executable).c_str(), X_OK) == 0) {
            return true;
        }
        if (separator == std::string::npos) {
            break;
        }
        start = separator + 1;
    }
    return false;
}

FirewallBackend resolve_routing_test_firewall_backend(
    FirewallBackendPreference preference,
    const std::optional<RoutingTestDeadline>& deadline) {
    enforce_routing_test_deadline(deadline);
    if (preference == FirewallBackendPreference::iptables) {
        return FirewallBackend::iptables;
    }
    if (preference == FirewallBackendPreference::nftables) {
        return FirewallBackend::nftables;
    }
    if (executable_exists_in_path("nft", deadline)) {
        return FirewallBackend::nftables;
    }
    if (executable_exists_in_path("iptables", deadline)) {
        return FirewallBackend::iptables;
    }
    throw FirewallError(
        "No supported firewall backend found (need nft or iptables)");
}

std::optional<bool> test_rule_ipset_membership(const KernelSetTester& set_tester,
                                               const RuleState& rule_state,
                                               const std::string& ip,
                                               bool is_v4,
                                               const std::optional<RoutingTestDeadline>& deadline) {
    bool any_answer = false;

    for (const auto& set_name : rule_state.set_names) {
        const bool v4_set = has_prefix(set_name, "kpbr4_") ||
                            has_prefix(set_name, "kpbr4s_") ||
                            has_prefix(set_name, "kpbr4S_") ||
                            has_prefix(set_name, "kpbr4d_");
        const bool v6_set = has_prefix(set_name, "kpbr6_") ||
                            has_prefix(set_name, "kpbr6s_") ||
                            has_prefix(set_name, "kpbr6S_") ||
                            has_prefix(set_name, "kpbr6d_");
        if (is_v4 && !v4_set) continue;
        if (!is_v4 && !v6_set) continue;

        enforce_routing_test_deadline(deadline);
        std::optional<bool> result;
        if (deadline.has_value()) {
            const auto bounded = set_tester.contains_until(
                set_name, ip, *deadline);
            if (bounded.timed_out) {
                throw RoutingTestTimeoutError(
                    "routing test kernel check deadline exceeded");
            }
            result = bounded.membership;
        } else {
            result = set_tester.contains(set_name, ip);
        }
        if (!result.has_value()) {
            continue;
        }
        any_answer = true;
        if (*result) return true;
    }

    if (!any_answer) return std::nullopt;
    return false;
}

RuleTargetEvaluation evaluate_rule_from_live_state(
    const RouteRule& rule,
    const RuleState* rule_state,
    const RuleIpDiagnostic& ip_diagnostic,
    const std::string& ip,
    bool inbound_is_restricted) {
    RuleTargetEvaluation result;
    if (!route_rule_enabled(rule) ||
        (rule_state != nullptr &&
         rule_state->action_type == RuleActionType::Skip)) {
        return result;
    }
    if (rule_state == nullptr) {
        result.evaluation = RoutingMatchEvaluation::InsufficientContext;
        result.unknown_conditions.push_back("firewall_state");
        return result;
    }

    if (!route_rule_lists(rule).empty()) {
        if (ip_diagnostic.in_ipset.has_value() &&
            !*ip_diagnostic.in_ipset) {
            return result;
        }
        if (!ip_diagnostic.in_ipset.has_value()) {
            append_unknown_condition(
                result.unknown_conditions, "firewall_set");
        }
    }

    const auto destination_match = destination_address_matches(rule, ip);
    if (destination_match.has_value() && !*destination_match) {
        return result;
    }

    for (const auto& condition :
         packet_context_conditions(rule, inbound_is_restricted)) {
        append_unknown_condition(result.unknown_conditions, condition);
    }
    if (!destination_match.has_value()) {
        append_unknown_condition(
            result.unknown_conditions, "destination_address");
    }
    if (!result.unknown_conditions.empty()) {
        result.evaluation = RoutingMatchEvaluation::InsufficientContext;
        return result;
    }

    result.evaluation = RoutingMatchEvaluation::Matched;
    return result;
}

OutboundEvaluation find_actual_outbound(
    const std::vector<RouteRule>& route_rules,
    const std::vector<const RuleState*>& rule_states_by_index,
    const std::vector<RuleIpDiagnostic>& rule_ip_diagnostics,
    const std::string& ip,
    bool inbound_is_restricted,
    const std::optional<RoutingTestDeadline>& deadline) {
    const std::size_t count = std::min(
        route_rules.size(), rule_ip_diagnostics.size());
    for (std::size_t idx = 0; idx < count; ++idx) {
        enforce_routing_test_deadline(deadline);
        const RuleState* state =
            idx < rule_states_by_index.size()
                ? rule_states_by_index[idx]
                : nullptr;
        auto evaluation = evaluate_rule_from_live_state(
            route_rules[idx],
            state,
            rule_ip_diagnostics[idx],
            ip,
            inbound_is_restricted);
        if (evaluation.evaluation == RoutingMatchEvaluation::NotMatched) {
            continue;
        }
        if (evaluation.evaluation ==
            RoutingMatchEvaluation::InsufficientContext) {
            return OutboundEvaluation{
                "(unknown)",
                std::nullopt,
                evaluation.evaluation,
                std::move(evaluation.unknown_conditions),
            };
        }
        return OutboundEvaluation{
            state != nullptr ? state->outbound_tag : "(unknown)",
            std::nullopt,
            RoutingMatchEvaluation::Matched,
            {},
        };
    }
    return {};
}

// Every membership check may spawn an nft/ipset subprocess. Keep the inner
// fan-out at two because the daemon admits two whole routing tests globally.
constexpr std::size_t kTestRoutingMaxConcurrentIps = 2;

struct PerIpRoutingResult {
    TestRoutingEntry entry;
    std::vector<RuleIpDiagnostic> rule_ip_diagnostics;
};

} // namespace

#ifdef KEEN_PBR3_TESTING
void inject_test_routing_worker_creation_failure(
    std::size_t worker_index) {
    injected_worker_creation_failure.store(
        static_cast<std::ptrdiff_t>(worker_index),
        std::memory_order_release);
}

void inject_test_routing_dns_socket_failure() {
    injected_dns_socket_failure.store(
        true, std::memory_order_release);
}
#endif

const char* routing_match_evaluation_code(
    RoutingMatchEvaluation evaluation) noexcept {
    switch (evaluation) {
        case RoutingMatchEvaluation::Matched:
            return "matched";
        case RoutingMatchEvaluation::NotMatched:
            return "not_matched";
        case RoutingMatchEvaluation::InsufficientContext:
            return "insufficient_context";
    }
    return "insufficient_context";
}

TestRoutingResult compute_test_routing(const Config& config,
                                        const CacheManager& cache,
                                        const std::string& target,
                                        const std::vector<RuleState>* realized_rule_states,
                                        std::optional<RoutingTestDeadline> deadline,
                                        std::optional<FirewallBackend> realized_firewall_backend) {
    enforce_routing_test_deadline(deadline);
    TestRoutingResult result;
    result.target = target;
    result.is_domain = !is_ip_address(target);

    const auto lookups = build_all_lookups(
        config, cache, deadline);
    enforce_routing_test_deadline(deadline);

    std::vector<std::string> ips;
    std::vector<std::string> domain_cands;

    if (result.is_domain) {
        domain_cands = domain_candidates(lowercase_copy(target));
        ips = resolve_domain_with_system_resolver(
            config, target, result.warnings, deadline);
        if (ips.empty() && !result.warnings.empty()) {
            result.dns_error = result.warnings.front();
        }
        result.resolved_ips = ips;
    } else {
        ips.push_back(target);
    }

    enforce_routing_test_deadline(deadline);
    const auto marks = allocate_outbound_marks(
        config.fwmark.value_or(FwmarkConfig{}),
        config.outbounds.value_or(std::vector<Outbound>{}));
    const auto configured_rule_states = build_fw_rule_states(config, marks);
    const auto& rule_states = realized_rule_states != nullptr
        ? *realized_rule_states
        : configured_rule_states;
    const auto& route_rules =
        config.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{});
    const auto route_config = config.route.value_or(RouteConfig{});
    const bool inbound_is_restricted =
        route_config.inbound_interfaces.has_value() &&
        !route_config.inbound_interfaces->empty();

    std::vector<const RuleState*> rule_states_by_index(
        route_rules.size(), nullptr);
    for (const auto& rule_state : rule_states) {
        if (rule_state.rule_index < rule_states_by_index.size() &&
            rule_states_by_index[rule_state.rule_index] == nullptr) {
            rule_states_by_index[rule_state.rule_index] = &rule_state;
        }
    }

    std::optional<KernelSetTester> set_tester;
    try {
        const FirewallBackend backend =
            realized_firewall_backend.has_value()
                ? *realized_firewall_backend
                : resolve_routing_test_firewall_backend(
                      firewall_backend_preference(config), deadline);
        set_tester.emplace(backend);
    } catch (const std::exception& e) {
        result.warnings.push_back(
            keen_pbr3::format("Cannot check actual outbound (firewall tool unavailable): {}", e.what()));
    }

    // If DNS failed we still want to show a domain-only match row
    if (ips.empty() && result.is_domain) {
        TestRoutingEntry entry;
        entry.ip = "(no IPs resolved)";
        auto expected = find_expected_outbound(
            route_rules,
            lookups,
            "",
            domain_cands,
            inbound_is_restricted,
            deadline);
        entry.expected_outbound = expected.outbound;
        entry.list_match = std::move(expected.list_match);
        entry.actual_outbound = "(unknown)";
        entry.ok = false;
        entry.evaluation = RoutingMatchEvaluation::InsufficientContext;
        entry.unknown_conditions = std::move(expected.unknown_conditions);
        append_unknown_condition(entry.unknown_conditions, "resolved_ip");
        result.entries.push_back(std::move(entry));
    }

    for (size_t idx = 0; idx < route_rules.size(); ++idx) {
        enforce_routing_test_deadline(deadline);
        RuleDiagnostic diag;
        diag.rule_index = static_cast<int>(idx);
        diag.rule = route_rules[idx];
        diag.outbound = route_rules[idx].outbound;
        diag.interface_name = outbound_interface_name(config, diag.outbound);
        diag.target_match = find_rule_match(route_rules[idx], lookups,
                                            result.is_domain ? "" : target, domain_cands);
        diag.target_in_lists = diag.target_match.has_value();
        result.rule_diagnostics.push_back(std::move(diag));
    }

    std::vector<PerIpRoutingResult> per_ip_results(ips.size());
    const auto check_ip = [&](size_t ip_index) {
        enforce_routing_test_deadline(deadline);
        const auto& ip = ips[ip_index];
        auto& per_ip = per_ip_results[ip_index];

        per_ip.entry.ip = ip;
        auto expected = find_expected_outbound(
            route_rules,
            lookups,
            ip,
            domain_cands,
            inbound_is_restricted,
            deadline);
        per_ip.entry.expected_outbound = expected.outbound;
        per_ip.entry.list_match = std::move(expected.list_match);
        per_ip.entry.evaluation = expected.evaluation;
        per_ip.entry.unknown_conditions = expected.unknown_conditions;

        per_ip.rule_ip_diagnostics.reserve(result.rule_diagnostics.size());
        for (size_t idx = 0; idx < result.rule_diagnostics.size(); ++idx) {
            enforce_routing_test_deadline(deadline);
            RuleIpDiagnostic ip_diag;
            ip_diag.ip = ip;
            auto configured_evaluation = evaluate_rule_from_config(
                route_rules[idx],
                lookups,
                ip,
                domain_cands,
                inbound_is_restricted);
            ip_diag.list_match =
                std::move(configured_evaluation.list_match);
            ip_diag.in_lists = ip_diag.list_match.has_value();
            ip_diag.evaluation = configured_evaluation.evaluation;
            ip_diag.unknown_conditions =
                std::move(configured_evaluation.unknown_conditions);
            const RuleState* state =
                idx < rule_states_by_index.size()
                    ? rule_states_by_index[idx]
                    : nullptr;
            if (set_tester.has_value() && state != nullptr) {
                ip_diag.in_ipset = test_rule_ipset_membership(
                    *set_tester,
                    *state,
                    ip,
                    is_ipv4_address(ip),
                    deadline);
            }
            per_ip.rule_ip_diagnostics.push_back(std::move(ip_diag));
        }

        if (set_tester.has_value()) {
            auto actual = find_actual_outbound(
                route_rules,
                rule_states_by_index,
                per_ip.rule_ip_diagnostics,
                ip,
                inbound_is_restricted,
                deadline);
            per_ip.entry.actual_outbound = actual.outbound;
            if (actual.evaluation ==
                RoutingMatchEvaluation::InsufficientContext) {
                per_ip.entry.evaluation =
                    RoutingMatchEvaluation::InsufficientContext;
                for (const auto& condition : actual.unknown_conditions) {
                    append_unknown_condition(
                        per_ip.entry.unknown_conditions, condition);
                }
            }
        } else {
            per_ip.entry.actual_outbound = "(unknown)";
            per_ip.entry.evaluation =
                RoutingMatchEvaluation::InsufficientContext;
            append_unknown_condition(
                per_ip.entry.unknown_conditions, "firewall_tool");
        }
        per_ip.entry.ok =
            per_ip.entry.expected_outbound != "(unknown)" &&
            per_ip.entry.actual_outbound != "(unknown)" &&
            per_ip.entry.expected_outbound ==
                per_ip.entry.actual_outbound;
    };

    const size_t worker_count = std::min(kTestRoutingMaxConcurrentIps, ips.size());
    if (worker_count > 1) {
        std::atomic_size_t next_ip{0};
        std::atomic<bool> worker_failed{false};
        std::mutex worker_error_mutex;
        std::exception_ptr worker_error;
        std::vector<std::thread> workers;
        workers.reserve(worker_count);
        ThreadJoinGuard join_guard(workers);
        for (size_t worker = 0; worker < worker_count; ++worker) {
#ifdef KEEN_PBR3_TESTING
            auto expected_failure =
                static_cast<std::ptrdiff_t>(worker);
            if (injected_worker_creation_failure.compare_exchange_strong(
                    expected_failure,
                    -1,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                throw std::runtime_error(
                    "synthetic routing test worker creation failure");
            }
#endif
            workers.emplace_back([&]() {
                try {
                    while (!worker_failed.load(
                        std::memory_order_acquire)) {
                        const size_t ip_index = next_ip.fetch_add(1);
                        if (ip_index >= ips.size()) {
                            return;
                        }
                        check_ip(ip_index);
                    }
                } catch (...) {
                    if (!worker_failed.exchange(
                            true, std::memory_order_acq_rel)) {
                        std::lock_guard<std::mutex> lock(
                            worker_error_mutex);
                        worker_error = std::current_exception();
                    }
                }
            });
        }
        join_guard.join_all();
        if (worker_error) {
            std::rethrow_exception(worker_error);
        }
    } else if (worker_count == 1) {
        check_ip(0);
    }

    enforce_routing_test_deadline(deadline);

    for (auto& per_ip : per_ip_results) {
        result.entries.push_back(std::move(per_ip.entry));
        for (size_t idx = 0; idx < result.rule_diagnostics.size(); ++idx) {
            result.rule_diagnostics[idx].ip_rows.push_back(
                std::move(per_ip.rule_ip_diagnostics[idx]));
        }
    }

    result.no_matching_rule = std::none_of(
        result.entries.begin(), result.entries.end(), [](const TestRoutingEntry& entry) {
            return entry.expected_outbound != "(default)";
        });

    return result;
}

namespace {
int render_test_routing_result(const TestRoutingResult& result) {
    for (const auto& w : result.warnings) {
        std::cerr << "Warning: " << w << "\n";
    }
    if (result.dns_error.has_value()) {
        std::cerr << "DNS error: " << *result.dns_error << "\n";
    }

    std::cout << "Target: " << result.target << "\n";
    if (!result.resolved_ips.empty()) {
        std::cout << "Resolved IPs: ";
        for (size_t i = 0; i < result.resolved_ips.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << result.resolved_ips[i];
        }
        std::cout << "\n";
    }
    std::cout << "\n";

    constexpr int ip_w        = 25;
    constexpr int list_w      = 35;
    constexpr int outbound_w  = 18;

    std::cout << keen_pbr3::format("{:<{}} | {:<{}} | {:<{}} | {:<{}} | {}\n",
                             "IP", ip_w,
                             "List Match", list_w,
                             "Expected Outbound", outbound_w,
                             "Actual Outbound", outbound_w,
                             "Status");
    std::cout << std::string(ip_w + 3 + list_w + 3 + outbound_w + 3 + outbound_w + 3 + 6, '-')
              << "\n";

    bool all_ok = !result.dns_error.has_value();
    for (const auto& entry : result.entries) {
        std::string list_str = "-";
        if (entry.list_match) {
            list_str = entry.list_match->list_name;
            if (!entry.list_match->via.empty() && entry.list_match->via != entry.ip) {
                list_str += " (via " + entry.list_match->via + ")";
            }
        }

        const std::string status =
            entry.evaluation ==
                    RoutingMatchEvaluation::InsufficientContext
                ? "UNKNOWN"
                : (entry.ok ? "OK" : "NOK");
        if (!entry.ok) all_ok = false;

        std::cout << keen_pbr3::format("{:<{}} | {:<{}} | {:<{}} | {:<{}} | {}\n",
                                 entry.ip, ip_w,
                                 list_str, list_w,
                                 entry.expected_outbound, outbound_w,
                                 entry.actual_outbound, outbound_w,
                                 status);
    }

    return all_ok ? 0 : 1;
}
} // namespace

int run_test_routing_command(const Config& config,
                              const CacheManager& cache,
                              const std::string& target) {
    return render_test_routing_result(
        compute_test_routing(config, cache, target));
}

int run_test_routing_command(const nlohmann::json& response) {
    const auto& payload = response.at("result");
    TestRoutingResult result;
    result.target = payload.value("target", "");
    result.resolved_ips =
        payload.value("resolved_ips", std::vector<std::string>{});
    result.warnings =
        payload.value("warnings", std::vector<std::string>{});
    result.unapplied_draft = payload.value("unapplied_draft", false);
    if (payload.contains("dns_error") &&
        !payload.at("dns_error").is_null()) {
        result.dns_error = payload.at("dns_error").get<std::string>();
    }

    for (const auto& item :
         payload.value("entries", nlohmann::json::array())) {
        TestRoutingEntry entry;
        entry.ip = item.value("ip", "");
        entry.expected_outbound =
            item.value("expected_outbound", "(unknown)");
        entry.actual_outbound =
            item.value("actual_outbound", "(unknown)");
        entry.ok = item.value("ok", false);
        const std::string evaluation =
            item.value("evaluation", "insufficient_context");
        if (evaluation == "matched") {
            entry.evaluation = RoutingMatchEvaluation::Matched;
        } else if (evaluation == "not_matched") {
            entry.evaluation = RoutingMatchEvaluation::NotMatched;
        } else {
            entry.evaluation =
                RoutingMatchEvaluation::InsufficientContext;
        }
        entry.unknown_conditions = item.value(
            "unknown_conditions", std::vector<std::string>{});
        if (item.contains("list_match") &&
            item.at("list_match").is_object()) {
            const auto& match = item.at("list_match");
            entry.list_match = ListMatchInfo{
                match.value("list", match.value("list_name", "")),
                match.value("via", ""),
            };
        }
        result.entries.push_back(std::move(entry));
    }
    return render_test_routing_result(result);
}

} // namespace keen_pbr3
