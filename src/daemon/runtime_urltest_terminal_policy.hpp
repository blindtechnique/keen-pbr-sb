#pragma once

#include "runtime_firewall_lifecycle_completion.hpp"

#include <cstdint>

namespace keen_pbr3 {

// Pure terminal boundary for one asynchronously owned URLTEST selection.
// The manager and Daemon cursors remain on the previous child until this
// policy admits a verified candidate. Any terminal after route mutation or
// entry into firewall COMMIT requires the separately prepared rollback.
enum class UrltestCandidateAction : std::uint8_t {
    publish_candidate,
    reject_runtime_unchanged,
    begin_exact_rollback,
    recovery_required,
};

struct UrltestCandidateEvidence final {
    bool exact_lease_owned{false};
    bool runtime_generation_current{false};
    bool manager_generation_current{false};
    bool exact_rollback_available{false};
    RuntimeFirewallLifecycleTerminal terminal;
};

inline UrltestCandidateAction plan_urltest_candidate_terminal(
    const UrltestCandidateEvidence& evidence) noexcept {
    if (!evidence.exact_lease_owned ||
        !evidence.runtime_generation_current ||
        evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::shutdown) {
        return UrltestCandidateAction::recovery_required;
    }

    if (evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        evidence.manager_generation_current &&
        evidence.terminal.committed &&
        !evidence.terminal.commit_ambiguous) {
        return UrltestCandidateAction::publish_candidate;
    }

    if (evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::not_verified &&
        evidence.terminal.previous_generation_certainly_retained &&
        !evidence.terminal.committed &&
        !evidence.terminal.commit_ambiguous) {
        return UrltestCandidateAction::reject_runtime_unchanged;
    }

    return evidence.exact_rollback_available
        ? UrltestCandidateAction::begin_exact_rollback
        : UrltestCandidateAction::recovery_required;
}

enum class UrltestRollbackAction : std::uint8_t {
    accept_verified_rollback,
    recovery_required,
};

struct UrltestRollbackEvidence final {
    bool exact_lease_owned{false};
    bool runtime_generation_current{false};
    RuntimeFirewallLifecycleTerminal terminal;
};

inline UrltestRollbackAction plan_urltest_rollback_terminal(
    const UrltestRollbackEvidence& evidence) noexcept {
    return evidence.exact_lease_owned &&
           evidence.runtime_generation_current &&
           evidence.terminal.outcome ==
               RuntimeFirewallLifecycleOutcome::verified_success &&
           evidence.terminal.committed &&
           !evidence.terminal.commit_ambiguous
        ? UrltestRollbackAction::accept_verified_rollback
        : UrltestRollbackAction::recovery_required;
}

} // namespace keen_pbr3
