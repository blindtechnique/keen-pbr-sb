#pragma once

#include "runtime_config_operation_identity.hpp"
#include "runtime_firewall_lifecycle_completion.hpp"

#include <cstdint>

namespace keen_pbr3 {

// Pure decision boundary between an asynchronous candidate-firewall owner and
// the config/WAL publisher. It deliberately carries evidence rather than an
// executable callback: the caller may act only after the exact mutation lease
// and the generation identity have both been checked.
enum class ConfigCandidateAction : std::uint8_t {
    publish_candidate,
    reject_runtime_unchanged,
    begin_exact_rollback,
    recovery_required,
};

struct ConfigCandidateEvidence {
    ConfigTerminalOperationIdentity expected_identity;
    bool exact_lease_owned{false};
    bool published_generation_current{false};
    RuntimeFirewallLifecycleTerminal terminal;
    bool exact_rollback_available{false};
};

inline ConfigCandidateAction plan_config_candidate_terminal(
    const ConfigCandidateEvidence& evidence) noexcept {
    if (!evidence.terminal.observed_config_identity ||
        !config_terminal_identity_matches(
            evidence.expected_identity,
            *evidence.terminal.observed_config_identity,
            ConfigTerminalOperationKind::candidate) ||
        !evidence.exact_lease_owned ||
        !evidence.published_generation_current ||
        evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::shutdown) {
        return ConfigCandidateAction::recovery_required;
    }

    // An uncommitted verified_success is not enough by itself: a preapply or
    // incomplete candidate could otherwise be mistaken for a candidate no-op.
    if (evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        !evidence.terminal.commit_ambiguous &&
        (evidence.terminal.committed ||
         evidence.terminal.candidate_noop_verified)) {
        return ConfigCandidateAction::publish_candidate;
    }

    // This is the only terminal which proves that the old runtime remained
    // intact. Every post-COMMIT or internally inconsistent terminal must use
    // the separately prepared old-generation transaction instead.
    if (evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::not_verified &&
        evidence.terminal.previous_generation_certainly_retained &&
        !evidence.terminal.committed &&
        !evidence.terminal.commit_ambiguous) {
        return ConfigCandidateAction::reject_runtime_unchanged;
    }

    return evidence.exact_rollback_available
        ? ConfigCandidateAction::begin_exact_rollback
        : ConfigCandidateAction::recovery_required;
}

enum class ConfigRollbackAction : std::uint8_t {
    accept_verified_rollback,
    recovery_required,
};

struct ConfigRollbackEvidence {
    ConfigTerminalOperationIdentity expected_identity;
    bool exact_lease_owned{false};
    bool published_generation_current{false};
    RuntimeFirewallLifecycleTerminal terminal;
};

inline ConfigRollbackAction plan_config_rollback_terminal(
    const ConfigRollbackEvidence& evidence) noexcept {
    return evidence.terminal.observed_config_identity &&
           config_terminal_identity_matches(
               evidence.expected_identity,
               *evidence.terminal.observed_config_identity,
               ConfigTerminalOperationKind::rollback) &&
           evidence.exact_lease_owned &&
           evidence.published_generation_current &&
           evidence.terminal.outcome ==
               RuntimeFirewallLifecycleOutcome::verified_success &&
           !evidence.terminal.commit_ambiguous &&
           (evidence.terminal.committed ||
            evidence.terminal.candidate_noop_verified)
        ? ConfigRollbackAction::accept_verified_rollback
        : ConfigRollbackAction::recovery_required;
}

enum class ConfigRuntimeTerminalAction : std::uint8_t {
    keep_active,
    fail_closed,
    shutdown,
};

// The user-visible/runtime-active cursor may remain healthy only after one of
// three exact proofs: the candidate was published, rollback was verified, or
// the worker proved that the base generation was never mutated. Any other
// terminal is an unknown kernel/routes/resolver state and must fail closed
// before the mutation lease is returned.
inline ConfigRuntimeTerminalAction plan_config_runtime_terminal(
    bool candidate_published,
    const RuntimeFirewallLifecycleTerminal& terminal) noexcept {
    if (terminal.outcome ==
        RuntimeFirewallLifecycleOutcome::shutdown) {
        return ConfigRuntimeTerminalAction::shutdown;
    }
    const bool exact_candidate_published =
        candidate_published &&
        terminal.observed_config_identity &&
        terminal.observed_config_identity->kind ==
            ConfigTerminalOperationKind::candidate &&
        terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        terminal.committed && !terminal.commit_ambiguous;
    const bool exact_rollback_verified =
        terminal.observed_config_identity &&
        terminal.observed_config_identity->kind ==
            ConfigTerminalOperationKind::rollback &&
        terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        (terminal.committed || terminal.candidate_noop_verified) &&
        !terminal.commit_ambiguous;
    const bool exact_base_unchanged =
        terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::not_verified &&
        terminal.previous_generation_certainly_retained &&
        !terminal.committed && !terminal.commit_ambiguous;
    return exact_candidate_published || exact_rollback_verified ||
            exact_base_unchanged
        ? ConfigRuntimeTerminalAction::keep_active
        : ConfigRuntimeTerminalAction::fail_closed;
}

} // namespace keen_pbr3
