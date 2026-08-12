#pragma once

#include "firewall.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

// Whether hardware PPE offload may be selectively bypassed for the traffic
// nfqws2 needs to inspect.
//
// Deliberately a judgement, not an action. The roadmap orders visibility and
// counters BEFORE any rule and before any threshold change, because the pinned
// z2k production build already tried the aggressive setting and reverted it:
// retrans=1 caused false rotations on Instagram and YouTube. Measuring first
// is not caution for its own sake - it is the lesson somebody already paid for.
enum class PpeDeoffloadState {
    // Every precondition holds. Note this still authorises nothing: the next
    // slice decides what to do with the permission.
    admissible,
    // The kernel has no PPE target, so there is nothing to de-offload.
    ppe_target_missing,
    // Without connskip there is no way to exempt selected flows, and a blanket
    // de-offload is not on the table.
    connskip_match_missing,
    // Only the iptables backend has the target and match; nftables has neither
    // here, and pretending otherwise would emit rules that never load.
    backend_incompatible,
    // Nothing is enqueued, so no flow needs inspecting and de-offloading would
    // cost throughput for nobody.
    nfqueue_inactive,
    // No validated strategy to take ports from. Ports must be derived from the
    // active strategy rather than duplicated, or the two drift and packets are
    // de-offloaded for ports nfqws2 stopped watching.
    strategy_ports_unavailable,
    // PPE is already off system-wide. Selective de-offload is meaningless, and
    // this code must never be the thing that turns the sysctl back on.
    ppe_already_disabled,
};

struct PpeDeoffloadInputs {
    bool ppe_target_available{false};
    bool connskip_match_available{false};
    FirewallBackend backend{FirewallBackend::iptables};
    bool nfqueue_active{false};
    // Ports taken from the validated active nfqws2 strategy. Empty means we
    // could not read them, which is not the same as "no ports".
    std::vector<std::string> tcp_ports;
    std::vector<std::string> quic_ports;
    // Read, never written. The roadmap is explicit that net.hwnat.ppe_enabled
    // stays enabled; this value only decides whether the work is meaningful.
    bool ppe_sysctl_enabled{false};
};

struct PpeDeoffloadAssessment {
    PpeDeoffloadState state{PpeDeoffloadState::ppe_target_missing};
    std::string detail;
    // TCP and QUIC are assessed separately because the roadmap enables them
    // separately: one may have usable ports while the other does not.
    bool tcp_eligible{false};
    bool quic_eligible{false};
};

// Pure. Reads nothing, writes nothing, and in particular never touches the PPE
// sysctl - it only reports whether selective de-offload would be admissible.
PpeDeoffloadAssessment evaluate_ppe_deoffload(const PpeDeoffloadInputs& inputs);

const char* ppe_deoffload_state_name(PpeDeoffloadState state) noexcept;

} // namespace keen_pbr3
