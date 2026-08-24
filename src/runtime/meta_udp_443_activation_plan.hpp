#pragma once

#include "conntrack_manager.hpp"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Immutable exact-cleanup authority prepared before a Meta UDP/443 firewall
// publication. The daemon schedules and publishes it, but the data contract
// itself belongs to the worker-safe runtime boundary.
struct MetaUdp443ActivationPlan {
    std::uint32_t expected_fwmark{0U};
    std::uint32_t owned_mask{0U};
    // The current authoritative mark plus, during an in-process route-mark
    // transition, the one previously committed messages-first mark. No other
    // owned mark is eligible for destructive cleanup.
    std::set<std::uint32_t> cleanup_owned_marks;
    std::vector<std::string> destination_selectors;
    bool ipv6_enabled{false};
    bool allow_unmarked_cleanup{false};
    std::vector<ConntrackExactForwardedFlow> exact_flows;
};

} // namespace keen_pbr3
