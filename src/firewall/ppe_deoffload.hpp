#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

inline constexpr const char* kPpeDeoffloadChain = "KeenPbrPpe4";
inline constexpr const char* kPpeDeoffloadPreroutingTag =
    "keen-pbr-sb:ppe:prerouting";
inline constexpr const char* kPpeDeoffloadForwardTag =
    "keen-pbr-sb:ppe:forward";
inline constexpr const char* kPpeDeoffloadTcpTagPrefix =
    "keen-pbr-sb:ppe:tcp:";
inline constexpr const char* kPpeDeoffloadQuicTag =
    "keen-pbr-sb:ppe:quic";
inline constexpr const char* kPpeDeoffloadReturnTag =
    "keen-pbr-sb:ppe:return";
inline constexpr const char* kPpeDeoffloadOwnerMarker =
    "/opt/var/run/keen-pbr.ppe-backend";
inline constexpr std::uint32_t kPpeDeoffloadConnskipWindow = 30U;
inline constexpr std::size_t kPpeDeoffloadMultiportLimit = 15U;
inline constexpr std::size_t kPpeDeoffloadMaxTcpChunks = 16U;

enum class PpeDeoffloadMode : std::uint8_t {
    off,
    automatic,
};

enum class PpeCapabilityState : std::uint8_t {
    unknown,
    unavailable,
    available,
};

// Public desired state supplied by the runtime observer. It contains only
// validated active-runtime facts; the firewall performs its own kernel and
// userspace capability checks immediately before publication.
struct PpeDeoffloadDesired {
    PpeDeoffloadMode mode{PpeDeoffloadMode::off};
    bool nfqueue_active{false};
    bool strategy_ports_available{false};
    // Queue identity is not rendered into the PPE graph, but is part of the
    // active-runtime contract. A live queue renumber therefore triggers the
    // existing full firewall refresh instead of being mistaken for a stable
    // desired state merely because its port selectors stayed equal.
    int nfqueue_number{-1};
    // Operator-facing refusal detail from the stable active-runtime observer
    // (PID identity, config/argv equality, and queue binding). It never
    // changes the stable state enum.
    std::string runtime_contract_detail;
    // Each string is a typed port selector accepted by PortSpec (single,
    // range, or comma-separated list). The graph canonicalizer sorts,
    // deduplicates and chunks these to the xt_multiport limit.
    std::vector<std::string> tcp_ports;
    // QUIC is deliberately narrower than the TCP input. v1 can emit only
    // UDP/443, and only when both the user switch and the active strategy say
    // that traffic is currently inspected.
    bool quic_enabled{false};
    bool quic_443_active{false};
};

enum class PpeDeoffloadState : std::uint8_t {
    disabled,
    admissible,
    active,
    unknown,
    ppe_target_missing,
    connskip_match_missing,
    backend_incompatible,
    nfqueue_inactive,
    strategy_ports_unavailable,
    conntrack_accounting_unknown,
    conntrack_accounting_disabled,
    ppe_state_unknown,
    ppe_already_disabled,
    userspace_incompatible,
    graph_conflict,
    reconcile_failed,
};

struct PpeDeoffloadInputs {
    PpeDeoffloadDesired desired;
    bool backend_compatible{true};
    PpeCapabilityState ppe_target{PpeCapabilityState::unknown};
    PpeCapabilityState connskip_match{PpeCapabilityState::unknown};
    // /proc/sys/net/netfilter/nf_conntrack_acct, read only.
    PpeCapabilityState conntrack_accounting{PpeCapabilityState::unknown};
    // /proc/sys/net/hwnat/ppe_enabled, read only.
    PpeCapabilityState ppe_enabled{PpeCapabilityState::unknown};
    // Exact iptables-restore acceptance of the graph syntax.
    PpeCapabilityState userspace{PpeCapabilityState::unknown};
};

struct PpeDeoffloadAssessment {
    PpeDeoffloadState state{PpeDeoffloadState::unknown};
    std::string detail;
    bool supported{false};
    bool degraded{false};
    bool tcp_eligible{false};
    bool quic_eligible{false};
};

struct PpeDeoffloadCounters {
    bool available{false};
    // Parent-hook totals and protocol totals are intentionally distinct. A
    // packet can traverse both PREROUTING and FORWARD, while the shared chain
    // cannot attribute its TCP/QUIC rule counter back to one parent hook.
    std::uint64_t prerouting_packets{0};
    std::uint64_t prerouting_bytes{0};
    std::uint64_t forward_packets{0};
    std::uint64_t forward_bytes{0};
    std::uint64_t tcp_packets{0};
    std::uint64_t tcp_bytes{0};
    std::uint64_t quic_packets{0};
    std::uint64_t quic_bytes{0};
    std::uint64_t observed_at_unix_seconds{0};
};

struct PpeDeoffloadSnapshot {
    PpeDeoffloadMode mode{PpeDeoffloadMode::off};
    PpeDeoffloadState state{PpeDeoffloadState::disabled};
    std::string detail{"disabled by configuration"};
    bool supported{false};
    bool active{false};
    bool degraded{false};
    std::vector<std::string> desired_tcp_ports;
    std::vector<std::string> applied_tcp_ports;
    bool desired_quic{false};
    bool applied_quic{false};
    std::uint32_t connskip_window{kPpeDeoffloadConnskipWindow};
    std::uint64_t last_reconcile_unix_seconds{0};
    PpeDeoffloadCounters counters;
};

struct PpeDeoffloadGraphSpec {
    // Canonical comma-separated chunks. Each chunk has at most fifteen
    // single/range entries, the xt_multiport ABI limit.
    std::vector<std::string> tcp_chunks;
    bool quic{false};

    bool empty() const { return tcp_chunks.empty() && !quic; }
    bool operator==(const PpeDeoffloadGraphSpec& other) const {
        return tcp_chunks == other.tcp_chunks && quic == other.quic;
    }
    bool operator!=(const PpeDeoffloadGraphSpec& other) const {
        return !(*this == other);
    }
};

enum class PpeGraphState : std::uint8_t {
    absent,
    exact,
    owned_drift,
    ambiguous,
};

enum class PpeObservationRefreshResult : std::uint8_t {
    inactive,
    refreshed,
    semantic_drift,
    unavailable,
};

// Pure decision used by the serialized observation owner. A published graph
// without its durable marker is repairable drift even when every rule is
// still exact; an ambiguous graph remains fail-closed/unavailable.
PpeObservationRefreshResult classify_ppe_deoffload_observation(
    PpeGraphState graph_state,
    bool owner_marker_valid,
    bool stored_snapshot_active) noexcept;

struct PpeGraphInspection {
    PpeGraphState state{PpeGraphState::absent};
    std::string detail;
    bool chain_exists{false};
    std::size_t prerouting_hook_count{0};
    std::size_t forward_hook_count{0};
    std::vector<std::size_t> prerouting_hook_positions;
    std::vector<std::size_t> forward_hook_positions;
    // Exact normalized `iptables -S` rule text for every semantically owned
    // rule observed in the chain. Transaction builders replay these as `-D`
    // so a post-inspection mutation cannot be hidden by a chain flush.
    std::vector<std::string> owned_chain_rules;
    PpeDeoffloadGraphSpec observed;
};

PpeDeoffloadAssessment evaluate_ppe_deoffload(
    const PpeDeoffloadInputs& inputs);

// Diagnostics are intentionally excluded so wording changes cannot cause a
// periodic full-refresh loop. Queue identity is included because it is part
// of the validated active NFQUEUE runtime contract.
bool ppe_deoffload_desired_semantically_equal(
    const PpeDeoffloadDesired& lhs,
    const PpeDeoffloadDesired& rhs) noexcept;

// Canonicalize the typed strategy input and enforce the multiport ABI bound.
// Throws std::invalid_argument for a malformed port selector.
PpeDeoffloadGraphSpec build_ppe_deoffload_graph_spec(
    const PpeDeoffloadDesired& desired);

// Parse a complete `iptables -t mangle -S` snapshot. Only the public tags and
// exact rule semantics above establish ownership. A foreign reference or an
// untagged rule in the named chain is ambiguous and is never mutated.
PpeGraphInspection inspect_ppe_deoffload_graph(
    const std::string& iptables_s,
    const PpeDeoffloadGraphSpec* expected = nullptr,
    bool owner_marker_present = false);

// Transaction builders consume an already inspected owned/absent graph.
// They never guess how many parent hooks exist.
std::string build_ppe_deoffload_apply_script(
    const PpeGraphInspection& before,
    const PpeDeoffloadGraphSpec& desired);
std::string build_ppe_deoffload_cleanup_script(
    const PpeGraphInspection& before);
std::string build_ppe_deoffload_validation_script(
    const PpeDeoffloadGraphSpec& desired,
    const std::string& validation_chain = "KeenPbrPpeV4");
// Remove only the exact rules rendered into the unique legacy-preflight
// chain. A concurrent foreign append is deliberately left behind so `-X`
// fails the atomic restore transaction instead of erasing foreign state.
std::string build_ppe_deoffload_validation_cleanup_script(
    const PpeDeoffloadGraphSpec& expected,
    const std::string& validation_chain,
    bool complete_graph);

// Validate the complete `iptables -S <unique-chain>` output used by the
// legacy userspace preflight. Exact tags alone are insufficient ownership
// proof: every match, option and target must still equal the rendered graph.
bool ppe_deoffload_validation_chain_is_exact(
    const std::string& chain_rules,
    const PpeDeoffloadGraphSpec& expected,
    const std::string& validation_chain);

// Passive parser for `iptables-save -c -t mangle`. Counters are returned only
// when the graph still semantically matches `expected`.
PpeDeoffloadCounters parse_ppe_deoffload_counters(
    const std::string& iptables_save,
    const PpeDeoffloadGraphSpec& expected,
    std::uint64_t observed_at_unix_seconds);

const char* ppe_deoffload_mode_name(PpeDeoffloadMode mode) noexcept;
const char* ppe_deoffload_state_name(PpeDeoffloadState state) noexcept;
const char* ppe_graph_state_name(PpeGraphState state) noexcept;

} // namespace keen_pbr3
