#include "ppe_deoffload.hpp"

namespace keen_pbr3 {

const char* ppe_deoffload_state_name(PpeDeoffloadState state) noexcept {
    switch (state) {
        case PpeDeoffloadState::admissible:
            return "admissible";
        case PpeDeoffloadState::ppe_target_missing:
            return "ppe_target_missing";
        case PpeDeoffloadState::connskip_match_missing:
            return "connskip_match_missing";
        case PpeDeoffloadState::backend_incompatible:
            return "backend_incompatible";
        case PpeDeoffloadState::nfqueue_inactive:
            return "nfqueue_inactive";
        case PpeDeoffloadState::strategy_ports_unavailable:
            return "strategy_ports_unavailable";
        case PpeDeoffloadState::ppe_already_disabled:
            return "ppe_already_disabled";
    }
    return "unknown";
}

PpeDeoffloadAssessment evaluate_ppe_deoffload(
    const PpeDeoffloadInputs& inputs) {
    PpeDeoffloadAssessment assessment;

    // Order matters only for which reason is reported first. Every check below
    // is a hard requirement: the roadmap asks for all of them simultaneously,
    // and a partial match is a reason to do nothing, not to do part of it.

    if (inputs.backend != FirewallBackend::iptables) {
        // The PPE target and connskip match live in xtables. Emitting nft
        // equivalents would produce rules that never load.
        assessment.state = PpeDeoffloadState::backend_incompatible;
        assessment.detail = "PPE de-offload requires the iptables backend";
        return assessment;
    }

    if (!inputs.ppe_target_available) {
        assessment.state = PpeDeoffloadState::ppe_target_missing;
        assessment.detail = "kernel target 'PPE' is not registered";
        return assessment;
    }

    if (!inputs.connskip_match_available) {
        // Without connskip the only way to spare a flow from offload would be
        // to disable offload wholesale, which trades everyone's throughput for
        // one feature and is explicitly not on the table.
        assessment.state = PpeDeoffloadState::connskip_match_missing;
        assessment.detail = "kernel match 'connskip' is not registered";
        return assessment;
    }

    if (!inputs.ppe_sysctl_enabled) {
        // Selective de-offload of something already off is meaningless. Note
        // what this branch does NOT do: it never enables the sysctl. Turning
        // hardware acceleration back on to make our own feature applicable
        // would be a system-wide change nobody asked for.
        assessment.state = PpeDeoffloadState::ppe_already_disabled;
        assessment.detail = "hardware PPE is already disabled system-wide";
        return assessment;
    }

    if (!inputs.nfqueue_active) {
        // Nothing is being inspected, so de-offloading would cost throughput
        // on behalf of no one.
        assessment.state = PpeDeoffloadState::nfqueue_inactive;
        assessment.detail = "no active NFQUEUE rules to inspect traffic";
        return assessment;
    }

    // Ports come from the validated active strategy. Duplicating them here
    // would let the two drift, and a de-offload for ports nfqws2 no longer
    // watches is pure throughput loss with no benefit.
    assessment.tcp_eligible = !inputs.tcp_ports.empty();
    assessment.quic_eligible = !inputs.quic_ports.empty();

    if (!assessment.tcp_eligible && !assessment.quic_eligible) {
        assessment.state = PpeDeoffloadState::strategy_ports_unavailable;
        assessment.detail =
            "the active nfqws2 strategy exposed no TCP or QUIC ports";
        return assessment;
    }

    // TCP and QUIC stay independent: one having usable ports must not enable
    // the other, and the roadmap turns them on separately for exactly that
    // reason.
    assessment.state = PpeDeoffloadState::admissible;
    return assessment;
}

} // namespace keen_pbr3
