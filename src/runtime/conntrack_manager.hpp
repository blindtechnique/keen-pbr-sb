#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Conntrack handling is consumed by firewall backends, but its policy has a
// separate lifecycle and must be observable independently of generated rules.
struct ConntrackPolicy {
    bool bypass_established_or_dnat{false};

    bool operator==(const ConntrackPolicy& other) const {
        return bypass_established_or_dnat == other.bypass_established_or_dnat;
    }
    bool operator!=(const ConntrackPolicy& other) const {
        return !(*this == other);
    }
};

enum class ConntrackCleanupResult {
    Succeeded,
    CommandUnavailable,
    Failed,
};

struct ConntrackCleanupSummary {
    std::size_t failed{0};
    std::size_t skipped{0};
    bool command_unavailable{false};
    bool budget_exhausted{false};
    // Exact, deduplicated selectors which were not completely retired. The
    // order is retry-friendly: unattempted marks precede marks which failed,
    // so one broken selector cannot starve the rest of a bounded batch.
    std::vector<std::uint32_t> remaining_marks;
};

struct ConntrackCleanupOptions {
    bool ipv6_enabled{true};
    std::chrono::milliseconds budget{std::chrono::seconds{4}};
    std::size_t max_marks{std::numeric_limits<std::size_t>::max()};
};

struct ConntrackSourceCleanupSummary {
    std::size_t failed{0};
    std::size_t skipped{0};
    bool command_unavailable{false};
    bool budget_exhausted{false};
    // Exact, deduplicated IPv4 source selectors which were not completely
    // retired. Unattempted selectors precede failed selectors so bounded
    // retries cannot be starved by one persistent failure.
    std::vector<std::string> remaining_source_cidrs;
};

struct ConntrackSourceCleanupOptions {
    std::chrono::milliseconds budget{std::chrono::seconds{4}};
    std::size_t max_source_cidrs{
        std::numeric_limits<std::size_t>::max()};
};

class ConntrackManager {
public:
    struct CommandResult {
        int exit_code{-1};
        std::string output;
    };

    using CommandRunner =
        std::function<CommandResult(const std::vector<std::string>&)>;

    explicit ConntrackManager(CommandRunner runner = {});

    // Records the policy successfully handed to the firewall backend.
    // The backend owns the kernel representation; this class owns the
    // reconciler-visible desired/actual policy snapshot.
    bool reconcile(ConntrackPolicy desired);
    ConntrackPolicy inspect() const;

    // Restore or save only keen-pbr-owned bits. Callers must apply restore only
    // to original-direction packets; reply traffic must not be classified again.
    static uint32_t restore_original_mark(uint32_t nfmark,
                                          uint32_t ctmark,
                                          uint32_t owned_mask);
    static uint32_t save_selected_mark(uint32_t ctmark,
                                       uint32_t nfmark,
                                       uint32_t owned_mask);

    // Best-effort targeted removal for one owned mark. It never flushes the
    // global conntrack table and invokes each address family separately.
    ConntrackCleanupResult delete_mark(uint32_t mark,
                                       uint32_t owned_mask) const;

    // Delete a deduplicated set of keen-pbr-owned marks. Stop immediately when
    // conntrack is unavailable instead of spawning one failing command per
    // outbound.
    ConntrackCleanupSummary delete_marks(
        const std::set<uint32_t>& marks,
        uint32_t owned_mask,
        ConntrackCleanupOptions options = {}) const;

    // Ordered variant used by runtime recovery: marks from active forwarding
    // and DNS rules are retired before background probe/download marks.
    ConntrackCleanupSummary delete_marks_ordered(
        const std::vector<uint32_t>& marks,
        uint32_t owned_mask,
        ConntrackCleanupOptions options = {}) const;

    // Best-effort retirement of IPv4 flows whose original source belongs to
    // one of the authoritative CIDRs. Selectors are validated, canonicalized
    // and deduplicated before invoking `conntrack -D -f ipv4 -s <CIDR>`.
    // A zero-prefix selector is rejected so this API can never become a
    // disguised global conntrack flush.
    ConntrackSourceCleanupSummary delete_ipv4_source_cidrs(
        const std::vector<std::string>& source_cidrs,
        ConntrackSourceCleanupOptions options = {}) const;

private:
    ConntrackPolicy active_;
    CommandRunner runner_;
};

} // namespace keen_pbr3
