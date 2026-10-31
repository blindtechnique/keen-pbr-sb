#pragma once

#include "interception_scope.hpp"
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

inline constexpr const char* kInterceptDnsChain = "KeenPbrDnsTap";
inline constexpr const char* kInterceptL7Chain = "KeenPbrL7Tap";

// Only user chains: never flush a built-in chain or change packet/ct marks.
inline std::string interception_iptables_script(const InterceptionHooks& hooks, bool ipv6) {
    std::string script = std::string("*mangle\n:") + kInterceptDnsChain + " - [0:0]\n:" +
                         kInterceptL7Chain + " - [0:0]\n-F " + kInterceptDnsChain +
                         "\n-F " + kInterceptL7Chain + "\n";
    const auto selector = [](const InterceptionClientSelector& s, bool dns) {
        return std::string(dns ? " -o " : " -i ") + s.interface +
            (s.cidr.empty() ? "" : std::string(dns ? " -d " : " -s ") + s.cidr);
    };
    for (const auto& s : hooks.client_scope.exclude) {
        if (s.family != (ipv6 ? 6 : 4)) continue;
        if (hooks.dns) script += std::string("-A ") + kInterceptDnsChain + selector(s, true) + " -j RETURN\n";
        if (hooks.l7) script += std::string("-A ") + kInterceptL7Chain + selector(s, false) + " -j RETURN\n";
    }
    for (const auto& s : hooks.client_scope.include) {
        if (s.family != (ipv6 ? 6 : 4)) continue;
        for (const bool dns : {true, false}) {
            if (!(dns ? hooks.dns : hooks.l7)) continue;
            const auto base = std::string("-A ") + (dns ? kInterceptDnsChain : kInterceptL7Chain) + selector(s, dns);
            for (const auto* proto : {"udp", "tcp"}) {
                const auto packet = base + " -p " + proto + (dns
                    ? " --sport 53 -m conntrack --ctstate ESTABLISHED --ctdir REPLY"
                    : std::string(proto) == "tcp" ? " -m multiport --dports 80,443 -m conntrack --ctdir ORIGINAL"
                                                 : " --dport 443 -m conntrack --ctdir ORIGINAL");
                script += packet + (dns ? " -j NFQUEUE --queue-num " + std::to_string(InterceptionHooks::queue) + " --queue-bypass\n"
                    : " -m limit --limit 200/second --limit-burst 400 -j NFLOG --nflog-group " + std::to_string(InterceptionHooks::group) + "\n");
            }
            // Prevent duplicate capture with overlapping client pools, also
            // after NFQUEUE reinjection or when NFLOG's rate limit is reached.
            script += base + " -j RETURN\n";
        }
    }
    return script + "COMMIT\n";
}

inline nlohmann::json interception_nft_commands(const InterceptionHooks& hooks, bool ipv6) {
    using J = nlohmann::json;
    auto commands = J::array();
    const auto chain = [&](const char* name, const char* hook) {
        commands.push_back({{"add", {{"chain", {{"family", "inet"}, {"table", "KeenPbrTable"},
            {"name", name}, {"type", "filter"}, {"hook", hook}, {"prio", -149}, {"policy", "accept"}}}}}});
    };
    const auto match = [](J left, J right) { return J{{"match", {{"op", "=="}, {"left", left}, {"right", right}}}}; };
    const auto emit = [&](bool dns, J expr) {
        commands.push_back({{"add", {{"rule", {{"family", "inet"}, {"table", "KeenPbrTable"},
            {"chain", dns ? kInterceptDnsChain : kInterceptL7Chain}, {"expr", expr}}}}}});
    };
    if (hooks.client_scope.include.empty()) return commands;
    if (hooks.dns) chain(kInterceptDnsChain, "postrouting");
    if (hooks.l7) chain(kInterceptL7Chain, "prerouting");
    const auto address = [&](const InterceptionClientSelector& s, bool dns) {
        auto expr = J::array({match({{"meta", {{"key", "nfproto"}}}}, s.family == 4 ? "ipv4" : "ipv6"),
            match({{"meta", {{"key", dns ? "oifname" : "iifname"}}}}, s.interface)});
        if (!s.cidr.empty()) {
            const auto slash = s.cidr.find('/');
            expr.push_back(match({{"payload", {{"protocol", s.family == 4 ? "ip" : "ip6"}, {"field", dns ? "daddr" : "saddr"}}}},
                {{"prefix", {{"addr", s.cidr.substr(0, slash)}, {"len", std::stoi(s.cidr.substr(slash + 1))}}}}));
        }
        return expr;
    };
    for (const auto& s : hooks.client_scope.exclude) {
        if (s.family == 6 && !ipv6) continue;
        for (const bool dns : {true, false}) if (dns ? hooks.dns : hooks.l7) {
            auto expr = address(s, dns);
            expr.push_back({{"return", nullptr}});
            emit(dns, std::move(expr));
        }
    }
    for (const auto& s : hooks.client_scope.include) {
        if (s.family == 6 && !ipv6) continue;
        for (const bool dns : {true, false}) if (dns ? hooks.dns : hooks.l7) {
            for (const auto* proto : {"tcp", "udp"}) {
                auto expr = address(s, dns);
                expr.push_back(match({{"meta", {{"key", "l4proto"}}}}, proto));
                expr.push_back(match({{"ct", {{"key", "direction"}}}}, dns ? "reply" : "original"));
                if (dns) {
                    expr.push_back(match({{"ct", {{"key", "state"}}}}, "established"));
                    expr.push_back(match({{"payload", {{"protocol", proto}, {"field", "sport"}}}}, 53));
                    expr.push_back({{"queue", {{"num", InterceptionHooks::queue}, {"flags", J::array({"bypass"})}}}});
                } else {
                    expr.push_back(match({{"payload", {{"protocol", proto}, {"field", "dport"}}}},
                        std::string(proto) == "tcp" ? J{{"set", J::array({80, 443})}} : J(443)));
                    expr.push_back({{"limit", {{"rate", 200}, {"per", "second"}, {"burst", 400}}}});
                    expr.push_back({{"log", {{"group", InterceptionHooks::group}, {"snaplen", 65535}, {"queue-threshold", 1}}}});
                }
                emit(dns, std::move(expr));
            }
            auto done = address(s, dns);
            done.push_back({{"return", nullptr}});
            emit(dns, std::move(done));
        }
    }
    return commands;
}

} // namespace keen_pbr3
