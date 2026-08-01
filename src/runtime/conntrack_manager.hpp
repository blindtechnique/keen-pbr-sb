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
    std::uint32_t mark{0};

    bool operator==(const ConntrackForwardedFlowPair& other) const {
        return source == other.source &&
               destination == other.destination &&
               ipv6 == other.ipv6 &&
               mark == other.mark;
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

enum class ConntrackFlowFamily {
    Ipv4,
    Ipv6,
};

enum class ConntrackFlowProtocol {
    Tcp,
    Udp,
};

enum class ConntrackTcpState {
    None,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Listen,
    SynSent2,
    Retrans,
    Unack,
};

struct ConntrackFlowCounters {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};

    bool operator==(const ConntrackFlowCounters& other) const {
        return packets == other.packets && bytes == other.bytes;
    }
};

// One exact original-direction forwarded flow. The tuple is normalized and
// complete; counters are kept separately for the original and reply
// directions so a higher-level observer can detect one-way progress without
// rereading or reparsing conntrack text.
struct ConntrackExactForwardedFlow {
    ConntrackFlowFamily family{ConntrackFlowFamily::Ipv4};
    ConntrackFlowProtocol protocol{ConntrackFlowProtocol::Tcp};
    std::string source;
    std::string destination;
    std::uint16_t source_port{0};
    std::uint16_t destination_port{0};
    std::uint32_t mark{0};
    ConntrackFlowCounters original;
    ConntrackFlowCounters reply;
    std::optional<ConntrackTcpState> tcp_state;
    bool assured{false};
    bool seen_reply{false};
    bool fastnat{false};

    bool operator==(const ConntrackExactForwardedFlow& other) const {
        return family == other.family &&
               protocol == other.protocol &&
               source == other.source &&
               destination == other.destination &&
               source_port == other.source_port &&
               destination_port == other.destination_port &&
               mark == other.mark &&
               original == other.original &&
               reply == other.reply &&
               tcp_state == other.tcp_state &&
               assured == other.assured &&
               seen_reply == other.seen_reply &&
               fastnat == other.fastnat;
    }
};

struct ConntrackFlowObservationOptions {
    bool ipv6_enabled{true};
    std::size_t max_flows{256};
    std::size_t max_destination_input_cidrs{1024};
    std::size_t max_snapshot_bytes{2U * 1024U * 1024U};
    std::size_t max_snapshot_lines{8192};
    // Call-affinity media views may retain unrelated mark bits owned by QoS
    // or another service. The ordinary destination-flow view remains strict.
    bool allow_foreign_mark_bits_for_media{false};
};

struct ConntrackFlowObservation {
    std::vector<ConntrackExactForwardedFlow> flows;
    // Destination-selected subset belonging specifically to the caller's
    // trusted media-seed coverage. Keeping this separate prevents an outbound
    // mark shared by unrelated lists from being mistaken for a call seed.
    std::vector<ConntrackExactForwardedFlow> media_seed_flows;
    // Read-only, source-scoped UDP media guard. These flows may target an
    // arbitrary peer outside destination_cidrs and are never deletion
    // candidates; callers use them only to protect a same-source signalling
    // flow while a P2P call is active.
    std::vector<ConntrackExactForwardedFlow> source_wide_udp_flows;
    std::size_t invalid_destination_selectors{0};
    std::size_t invalid_media_seed_destination_selectors{0};
    std::size_t invalid_media_guard_sources{0};
    std::size_t skipped_destination_selectors{0};
    bool invalid_owned_mask{false};
    bool destination_input_truncated{false};
    bool media_seed_destination_input_truncated{false};
    bool snapshot_unavailable{false};
    bool snapshot_truncated{false};
    bool line_limit_reached{false};
    bool flow_limit_reached{false};
    bool local_address_scope_missing{false};
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

    // Reconnect currently observed forwarded flows after a successfully
    // committed destination-policy change. Fully unmarked flows are eligible
    // for normal_destination_cidrs and aggressive_destination_cidrs. Flows
    // carrying at least one keen-pbr-owned mark bit are additionally eligible
    // for aggressive_destination_cidrs; foreign-only marks are never selected.
    // The snapshot is read once and all matches share the same time/flow
    // budget. Every deletion uses the exact original host pair and the full
    // observed mark, so this API cannot become a global or masked-mark flush.
    ConntrackForwardedFlowCleanupSummary delete_forwarded_destination_flows(
        const std::vector<std::string>& normal_destination_cidrs,
        const std::vector<std::string>& aggressive_destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        uint32_t owned_mask,
        ConntrackForwardedFlowCleanupOptions options = {}) const;

    // Reconnect only currently observed forwarded flows which are still fully
    // unmarked after a successful broad destination-policy change. The
    // snapshot parser keeps the original source/destination pair, rejects
    // missing marks, excludes every live local address, and deletes exact host
    // pairs with a full-width zero mark. It never expands a CIDR into a broad
    // conntrack delete and never touches router-originated or foreign-marked
    // flows. Empty/invalid local-address authority fails closed. This legacy
    // entry point delegates to delete_forwarded_destination_flows with no
    // aggressive coverage.
    ConntrackForwardedFlowCleanupSummary
    delete_unmarked_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        uint32_t owned_mask,
        ConntrackForwardedFlowCleanupOptions options = {}) const;

    // Observe only exact forwarded TCP/UDP flows whose destination belongs to
    // one of the validated, non-/0 selectors. The ordinary `flows` view keeps
    // only zero or entirely owned marks. A caller may opt the separate media
    // seed/source views into retaining foreign mark bits; this never broadens
    // the ordinary deletion-candidate view. Local-address inventory is
    // authoritative and any missing/invalid entry fails closed before reading
    // conntrack.
    ConntrackFlowObservation observe_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        uint32_t owned_mask,
        ConntrackFlowObservationOptions options = {},
        const std::vector<std::string>& media_guard_source_addresses = {},
        const std::vector<std::string>& media_seed_destination_cidrs = {},
        const std::set<uint32_t>& media_seed_owned_marks = {})
        const;

    // Delete one previously observed flow by its full original 5-tuple and
    // full-width mark. By default marks with foreign bits are rejected. A
    // caller that supplies expected_owned_mark may delete a tuple whose owned
    // component is either zero or exactly that mark while preserving the full
    // live mark in the conntrack selector. This method never issues a CIDR
    // selector or global flush.
    ConntrackCleanupResult delete_exact_forwarded_flow(
        const ConntrackExactForwardedFlow& flow,
        uint32_t owned_mask,
        std::optional<std::uint32_t> expected_owned_mark = std::nullopt) const;

private:
    ConntrackPolicy active_;
    CommandRunner runner_;
    SnapshotReader snapshot_reader_;
};

} // namespace keen_pbr3
