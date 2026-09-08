#pragma once

#include "firewall_verifier.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct FirewallClassifierQuery {
    std::size_t rule_index{0};
    int family{0};
};

enum class FirewallCounterStatus { Observed, Unavailable, NotApplicable, Ambiguous };

struct FirewallClassifierCounter {
    int family{0};
    std::string table, chain;
    std::size_t position{0}; // One-based physical rule position, not a config index.
    std::string action, set_name;
    std::optional<std::uint32_t> fwmark, fwmask;
    std::uint64_t packets{0}, bytes{0};
};

struct FirewallClassifierEvidence {
    FirewallCounterStatus status{FirewallCounterStatus::NotApplicable};
    std::int64_t snapshot_at{0};
    std::size_t total{0};
    bool truncated{false};
    std::vector<FirewallClassifierCounter> rules;
};

// PREROUTING classifier counters for the captured realized rules. Absolute
// totals describe each whole physical rule, NOT this destination or a flow.
// The read is optional, bounded and request-local; no firewall writer is used.
std::vector<FirewallClassifierEvidence> collect_firewall_counter_evidence(
    FirewallBackend backend, RawPreroutingMode raw_prerouting,
    const std::vector<RuleState>& realized_rules,
    const std::vector<FirewallClassifierQuery>& queries,
    std::uint32_t fwmark_mask,
    std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt,
    CommandRunner runner = {});

} // namespace keen_pbr3
