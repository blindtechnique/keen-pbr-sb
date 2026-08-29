#pragma once

#include "firewall.hpp"

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

struct FirewallOwnedCleanupProbeView final {
    std::string_view source;
    bool complete{false};
    std::string_view output;
};

enum class FirewallOwnedMarkerObservation : std::uint8_t {
    absent,
    present,
    invalid,
};

inline bool nft_owned_table_absence_proven(
    int exit_code,
    bool timed_out,
    bool truncated,
    bool termination_uncertain,
    std::string_view output) noexcept {
    // nft uses exit 1 when the requested table is absent. Exit 127 is the
    // execvp failure used by safe_exec_capture and must never be confused
    // with proof merely because its diagnostic contains "not found".
    if (exit_code != 1 || timed_out || truncated ||
        termination_uncertain) {
        return false;
    }
    return output.find("No such file or directory") !=
               std::string_view::npos ||
           output.find("does not exist") != std::string_view::npos ||
           (output.find("KeenPbrTable") != std::string_view::npos &&
            output.find("not found") != std::string_view::npos);
}

inline bool iptables_owned_table_probe_complete(
    int exit_code,
    bool timed_out,
    bool truncated,
    bool termination_uncertain,
    bool table_explicitly_unavailable) noexcept {
    if (timed_out || truncated || termination_uncertain) {
        return false;
    }
    if (exit_code == 0) {
        return true;
    }
    // A missing executable is not evidence that a previously published
    // kernel table disappeared. Only an exact table/family unsupported
    // diagnostic from a real xtables process can close this probe.
    return exit_code != 127 && table_explicitly_unavailable;
}

inline bool is_firewall_owned_ipset_name(std::string_view name) noexcept {
    constexpr std::array<std::string_view, 10U> prefixes{
        "kpbr4_", "kpbr6_",
        "kpbr4s_", "kpbr6s_",
        "kpbr4S_", "kpbr6S_",
        "kpbr4d_", "kpbr6d_",
        "kpbr4m_", "kpbr6m_",
    };
    for (const auto prefix : prefixes) {
        if (name.size() >= prefix.size() &&
            name.compare(0U, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

inline std::vector<std::string>
firewall_owned_ipset_names(std::string_view names_only_inventory) {
    std::vector<std::string> owned;
    std::size_t cursor = 0U;
    while (cursor < names_only_inventory.size()) {
        const auto end = names_only_inventory.find('\n', cursor);
        const auto line_end = end == std::string_view::npos
            ? names_only_inventory.size()
            : end;
        auto line = names_only_inventory.substr(cursor, line_end - cursor);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1U);
        }
        if (is_firewall_owned_ipset_name(line)) {
            owned.emplace_back(line);
        }
        if (end == std::string_view::npos) {
            break;
        }
        cursor = end + 1U;
    }
    return owned;
}

// Final classifier for strict iptables STOP cleanup. A caller supplies fresh,
// complete post-cleanup snapshots of every relevant table plus the names-only
// ipset inventory. No mutation result is accepted as absence evidence.
inline FirewallOwnedCleanupInspection
inspect_iptables_owned_cleanup_absence(
    const std::vector<FirewallOwnedCleanupProbeView>& table_probes,
    const FirewallOwnedCleanupProbeView& ipset_names_probe,
    FirewallOwnedMarkerObservation ppe_marker) {
    for (const auto& probe : table_probes) {
        if (!probe.complete) {
            return {
                FirewallOwnedCleanupState::observation_failed,
                std::string{"could not inspect "} +
                    std::string{probe.source},
            };
        }
    }
    if (!ipset_names_probe.complete) {
        return {
            FirewallOwnedCleanupState::observation_failed,
            std::string{"could not inspect "} +
                std::string{ipset_names_probe.source},
        };
    }
    if (ppe_marker == FirewallOwnedMarkerObservation::invalid) {
        return {
            FirewallOwnedCleanupState::observation_failed,
            "could not verify the PPE ownership marker",
        };
    }

    constexpr std::array<std::string_view, 4U> owned_rule_markers{
        "KeenPbr",
        "KpPpeV",
        "keen-pbr-sb:ttl-bypass",
        "keen-pbr-sb:ppe:",
    };
    for (const auto& probe : table_probes) {
        for (const auto marker : owned_rule_markers) {
            if (probe.output.find(marker) != std::string_view::npos) {
                return {
                    FirewallOwnedCleanupState::owned_artifacts_present,
                    std::string{"owned firewall state remains in "} +
                        std::string{probe.source},
                };
            }
        }
    }

    const auto owned_ipsets =
        firewall_owned_ipset_names(ipset_names_probe.output);
    if (!owned_ipsets.empty()) {
        return {
            FirewallOwnedCleanupState::owned_artifacts_present,
            std::string{"owned ipset remains: "} + owned_ipsets.front(),
        };
    }
    if (ppe_marker == FirewallOwnedMarkerObservation::present) {
        return {
            FirewallOwnedCleanupState::owned_artifacts_present,
            "the PPE ownership marker remains",
        };
    }
    return {FirewallOwnedCleanupState::verified_absent, {}};
}

} // namespace keen_pbr3
