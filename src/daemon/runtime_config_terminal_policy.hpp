#pragma once

#include "runtime_firewall_lifecycle_completion.hpp"

#include <cstdint>

namespace keen_pbr3 {

enum class ConfigTerminalOperationKind : std::uint8_t {
    config_preapply,
    candidate,
    rollback,
};

struct ConfigTerminalOperationIdentity {
    ConfigTerminalOperationKind kind{
        ConfigTerminalOperationKind::config_preapply};
    std::uint64_t operation_serial{0U};
    std::uint64_t base_runtime_generation{0U};
    std::uint64_t target_runtime_generation{0U};

    constexpr bool valid() const noexcept {
        return operation_serial != 0U &&
               base_runtime_generation != 0U &&
               target_runtime_generation != 0U;
    }

    constexpr bool operator==(
        const ConfigTerminalOperationIdentity& other) const noexcept {
        return kind == other.kind &&
               operation_serial == other.operation_serial &&
               base_runtime_generation == other.base_runtime_generation &&
               target_runtime_generation == other.target_runtime_generation;
    }
};

inline bool config_terminal_identity_matches(
    const ConfigTerminalOperationIdentity& expected,
    const ConfigTerminalOperationIdentity& observed,
    ConfigTerminalOperationKind required_kind) noexcept {
    return expected.valid() && observed.valid() &&
           expected.kind == required_kind &&
           observed.kind == required_kind && expected == observed;
}

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
    ConfigTerminalOperationIdentity observed_terminal_identity;
    bool exact_lease_owned{false};
    bool base_generation_current{false};
    RuntimeFirewallLifecycleOutcome outcome{
        RuntimeFirewallLifecycleOutcome::not_verified};
    bool committed{false};
    bool commit_ambiguous{true};
    bool candidate_noop_verified{false};
    bool previous_generation_certainly_retained{false};
    bool exact_rollback_available{false};
};

inline ConfigCandidateAction plan_config_candidate_terminal(
    const ConfigCandidateEvidence& evidence) noexcept {
    if (!config_terminal_identity_matches(
            evidence.expected_identity,
            evidence.observed_terminal_identity,
            ConfigTerminalOperationKind::candidate) ||
        !evidence.exact_lease_owned ||
        !evidence.base_generation_current ||
        evidence.outcome == RuntimeFirewallLifecycleOutcome::shutdown) {
        return ConfigCandidateAction::recovery_required;
    }

    // An uncommitted verified_success is not enough by itself: a preapply or
    // incomplete candidate could otherwise be mistaken for a candidate no-op.
    if (evidence.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        !evidence.commit_ambiguous &&
        (evidence.committed || evidence.candidate_noop_verified)) {
        return ConfigCandidateAction::publish_candidate;
    }

    // This is the only terminal which proves that the old runtime remained
    // intact. Every post-COMMIT or internally inconsistent terminal must use
    // the separately prepared old-generation transaction instead.
    if (evidence.outcome ==
            RuntimeFirewallLifecycleOutcome::not_verified &&
        evidence.previous_generation_certainly_retained &&
        !evidence.committed && !evidence.commit_ambiguous) {
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
    ConfigTerminalOperationIdentity observed_terminal_identity;
    bool exact_lease_owned{false};
    bool base_generation_current{false};
    RuntimeFirewallLifecycleOutcome outcome{
        RuntimeFirewallLifecycleOutcome::not_verified};
    bool commit_ambiguous{true};
};

inline ConfigRollbackAction plan_config_rollback_terminal(
    const ConfigRollbackEvidence& evidence) noexcept {
    return config_terminal_identity_matches(
               evidence.expected_identity,
               evidence.observed_terminal_identity,
               ConfigTerminalOperationKind::rollback) &&
                   evidence.exact_lease_owned &&
                   evidence.base_generation_current &&
                   evidence.outcome ==
                       RuntimeFirewallLifecycleOutcome::verified_success &&
                   !evidence.commit_ambiguous
        ? ConfigRollbackAction::accept_verified_rollback
        : ConfigRollbackAction::recovery_required;
}

} // namespace keen_pbr3
