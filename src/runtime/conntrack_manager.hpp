#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
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

struct ConntrackForwardedFlowPair {
    std::string source;
    std::string destination;
    bool ipv6{false};

    bool operator==(const ConntrackForwardedFlowPair& other) const {
        return source == other.source &&
               destination == other.destination &&
               ipv6 == other.ipv6;
    }
};

struct ConntrackForwardedFlowCleanupSummary {
    std::size_t matched{0};
    std::size_t attempted{0};
    std::size_t failed{0};
    std::size_t skipped{0};
    bool command_unavailable{false};
    bool budget_exhausted{false};
    bool invalid_owned_mask{false};
    bool destination_input_truncated{false};
    bool snapshot_unavailable{false};
    bool snapshot_truncated{false};
    bool local_address_scope_missing{false};
    std::vector<ConntrackForwardedFlowPair> remaining_flows;
};

struct ConntrackForwardedFlowCleanupOptions {
    bool ipv6_enabled{true};
    std::chrono::milliseconds budget{std::chrono::seconds{2}};
    std::size_t max_flows{256};
    std::size_t max_destination_input_cidrs{1024};
    std::size_t max_snapshot_bytes{2U * 1024U * 1024U};
    std::size_t max_snapshot_lines{8192};
};

class ConntrackManager {
public:
    struct CommandResult {
        int exit_code{-1};
        std::string output;
    };

    struct Snapshot {
        std::string content;
        bool truncated{false};
    };

    using CommandRunner =
        std::function<CommandResult(const std::vector<std::string>&)>;
    using SnapshotReader =
        std::function<std::optional<Snapshot>(std::size_t)>;

    explicit ConntrackManager(CommandRunner runner = {},
                              SnapshotReader snapshot_reader = {});

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

    // Reconnect only currently observed forwarded flows which are still fully
    // unmarked after a successful broad destination-policy change. The
    // snapshot parser keeps the original source/destination pair, rejects
    // missing marks, excludes every live local address, and deletes exact host
    // pairs with a full-width zero mark. It never expands a CIDR into a broad
    // conntrack delete and never touches router-originated or foreign-marked
    // flows. Empty/invalid local-address authority fails closed.
    ConntrackForwardedFlowCleanupSummary
    delete_unmarked_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        uint32_t owned_mask,
        ConntrackForwardedFlowCleanupOptions options = {}) const;

private:
    ConntrackPolicy active_;
    CommandRunner runner_;
    SnapshotReader snapshot_reader_;
};

} // namespace keen_pbr3
