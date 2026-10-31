#pragma once

#include "../config/config.hpp"
#include "dns_balancer.hpp"
#include "dns_server.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <arpa/inet.h>

namespace keen_pbr3 {

inline constexpr const char* kDohListenIp = "127.0.0.89";
inline constexpr std::uint16_t kDohFirstPort = 5355;

class DohPlanError : public DnsError {
public:
    DohPlanError(std::string message, std::string code, std::string path)
        : DnsError(std::move(message), std::move(code)), path_(std::move(path)) {}
    const std::string& path() const noexcept { return path_; }
private:
    std::string path_;
};

inline bool doh_numeric_host(const std::string& host) {
    if (host.find('\0') != std::string::npos) return false;
    in6_addr v6{};
    in_addr v4{};
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

// Strict configuration parser; never resolves a host or contacts a server.
inline std::string doh_url_host(const std::string& url) {
    const auto invalid = []() -> std::string {
        throw DnsError("Use an HTTPS DNS URL without credentials or a fragment",
                       "config.dns.doh_url");
    };
    if (url.rfind("https://", 0) != 0 || url.size() > 2048 ||
        std::any_of(url.begin(), url.end(), [](unsigned char c) { return c <= 32 || c == 127; }) ||
        url.find_first_of(" \t\r\n\\#") != std::string::npos) return invalid();
    const auto end = url.find_first_of("/?", 8);
    const auto authority = url.substr(8, end == std::string::npos ? end : end - 8);
    if (authority.empty() || authority.find('@') != std::string::npos) return invalid();
    std::string host, port;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string::npos) return invalid();
        host = authority.substr(1, close - 1);
        try { (void)parse_dns_address_str("[" + host + "]"); }
        catch (const DnsError&) { return invalid(); }
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return invalid();
            port = authority.substr(close + 2);
            if (port.empty()) return invalid();
        }
    } else {
        const auto colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != std::string::npos) {
            port = authority.substr(colon + 1);
            if (port.empty()) return invalid();
        }
        if (host.empty() || host.size() > 253) return invalid();
        std::size_t label = 0;
        for (unsigned char c : host) {
            if (c == '.') { if (!label || label > 63) return invalid(); label = 0; }
            else {
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-')) return invalid();
                ++label;
            }
        }
        if (label > 63) return invalid();
    }
    if (!port.empty()) {
        try { (void)parse_dns_address_str("127.0.0.1:" + port); }
        catch (const DnsError&) { return invalid(); }
    }
    return host;
}

struct DohPlan {
    std::map<std::string, std::uint16_t> ports;
    std::vector<DnsBalancerGroup> groups;
    std::vector<DnsBalancerUpstream> bootstrap;
};

inline DohPlan make_doh_plan(const DnsConfig& dns) {
    DohPlan plan;
    std::map<std::string, DnsServer> servers;
    for (const auto& server : dns.servers.value_or(std::vector<DnsServer>{}))
        servers.emplace(server.tag, server);
    const auto tags = dns.bootstrap.value_or(std::vector<std::string>{});
    if (tags.size() > 8)
        throw DohPlanError("At most eight bootstrap servers are supported", "config.dns.bootstrap", "dns.bootstrap");
    for (const auto& tag : tags) {
        const auto found = servers.find(tag);
        if (found == servers.end() ||
            found->second.type.value_or(api::DnsServerType::STATIC) != api::DnsServerType::STATIC ||
            !found->second.address)
            throw DohPlanError("Bootstrap must reference an installed static DNS server: " + tag,
                               "config.dns.bootstrap", "dns.bootstrap");
        ParsedDnsAddress parsed;
        try { parsed = parse_dns_address_str(*found->second.address); }
        catch (const DnsError& error) {
            throw DohPlanError(error.what(), "config.dns.bootstrap", "dns.bootstrap");
        }
        if (parsed.ip.rfind("127.", 0) == 0 || parsed.ip == "::1" ||
            parsed.ip == "0.0.0.0" || parsed.ip == "::")
            throw DohPlanError("Bootstrap cannot use a local resolver: " + tag,
                               "config.dns.bootstrap", "dns.bootstrap");
        auto upstream = DnsBalancerUpstream::plain(parsed.ip, parsed.port);
        upstream.name = tag;
        plan.bootstrap.push_back(std::move(upstream));
    }
    // Stable under reordering the UI table. No listeners for existing plain DNS.
    for (const auto& [tag, server] : servers) {
        if (server.type.value_or(api::DnsServerType::STATIC) != api::DnsServerType::DOH) continue;
        const auto path = "dns.servers." + tag;
        std::string host;
        try { host = doh_url_host(server.address.value_or("")); }
        catch (const DnsError& error) {
            throw DohPlanError(error.what(), error.code(), path + ".address");
        }
        const auto ips = server.ips.value_or(std::vector<std::string>{});
        if (ips.size() > 16)
            throw DohPlanError("At most sixteen fixed DoH addresses are supported", "config.dns.doh_ips", path + ".ips");
        for (const auto& ip : ips) {
            if (!doh_numeric_host(ip))
                throw DohPlanError("DoH fixed addresses must be numeric IPs without a port",
                                   "config.dns.doh_ips", path + ".ips");
        }
        if (ips.empty() && !doh_numeric_host(host) && plan.bootstrap.empty())
            throw DohPlanError("Choose bootstrap DNS servers or provide fixed IPs for DoH server " + tag,
                               "config.dns.bootstrap", "dns.bootstrap");
        if (plan.groups.size() >= kDnsBalancerMaxGroups)
            throw DohPlanError("At most 32 DoH servers are supported", "config.dns.doh_limit", "dns.servers");
        const auto port = static_cast<std::uint16_t>(kDohFirstPort + plan.groups.size());
        auto upstream = DnsBalancerUpstream::doh(*server.address, server.detour.value_or(""), ips);
        upstream.name = tag;
        plan.ports.emplace(tag, port);
        plan.groups.push_back({port, {std::move(upstream)}});
    }
    return plan;
}

} // namespace keen_pbr3
