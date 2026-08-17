#pragma once

#include "../config/config.hpp"

namespace keen_pbr3 {

struct Ipv6SupportDecision {
    bool enabled{true};
    enum class Reason {
        Enabled,
        DisabledByConfig,
        UnsupportedBySystem
    } reason{Reason::Enabled};
};

// Resolver output distinguishes effective runtime capability from an explicit
// user request. A transiently unavailable IPv6 backend must omit IPv6 set
// targets without silently turning the managed DNS resolver into IPv4-only.
struct ResolverIpv6Policy {
    bool targets_enabled{true};
    bool suppress_aaaa{false};

    static constexpr ResolverIpv6Policy supported() {
        return {true, false};
    }

    static constexpr ResolverIpv6Policy unsupported() {
        return {false, false};
    }

    static constexpr ResolverIpv6Policy explicitly_disabled() {
        return {false, true};
    }
};

constexpr ResolverIpv6Policy resolver_ipv6_policy(
    const Ipv6SupportDecision& decision) {
    if (decision.reason == Ipv6SupportDecision::Reason::DisabledByConfig) {
        return ResolverIpv6Policy::explicitly_disabled();
    }
    return decision.enabled
        ? ResolverIpv6Policy::supported()
        : ResolverIpv6Policy::unsupported();
}

bool system_ipv6_supported();
bool iptables_ipv6_supported();
Ipv6SupportDecision resolve_ipv6_support(const Config& config);
void log_ipv6_support_decision_once(const Ipv6SupportDecision& decision);

} // namespace keen_pbr3
