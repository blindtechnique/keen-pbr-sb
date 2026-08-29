#pragma once

#include "runtime_firewall_lifecycle_completion.hpp"

#include <cstdint>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

enum class KeeneticDnsCandidateTerminalAction : std::uint8_t {
    publish_candidate,
    finish_clean_precommit,
    start_exact_rollback,
    request_fresh_recovery,
};

struct KeeneticDnsCandidateTerminalEvidence {
    RuntimeFirewallLifecycleOutcome outcome{
        RuntimeFirewallLifecycleOutcome::not_verified};
    bool committed{false};
    bool commit_ambiguous{false};
    bool previous_generation_certainly_retained{false};
    bool exact_lease_owned{false};
    bool runtime_generation_current{false};
    bool candidate_firewall_preimage_is_base{false};
    bool candidate_core_available{false};
    bool candidate_publication_succeeded{false};
    // True when the exact route checkpoint proves that this physical token
    // may restore the published route/firewall generation. This is distinct
    // from a committed candidate core: route mutation can precede a
    // non-ambiguous firewall pre-COMMIT failure.
    bool exact_rollback_available{false};
};

constexpr KeeneticDnsCandidateTerminalAction
plan_keenetic_dns_candidate_terminal(
    const KeeneticDnsCandidateTerminalEvidence& evidence) noexcept {
    const bool verified_terminal =
        evidence.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        evidence.committed &&
        !evidence.commit_ambiguous &&
        evidence.exact_lease_owned &&
        evidence.runtime_generation_current;
    if (verified_terminal) {
        // A failed CAS/publication after verified external COMMIT is not
        // authority to replay either private body.
        return evidence.candidate_publication_succeeded
            ? KeeneticDnsCandidateTerminalAction::publish_candidate
            : KeeneticDnsCandidateTerminalAction::request_fresh_recovery;
    }

    if (evidence.previous_generation_certainly_retained &&
        evidence.candidate_firewall_preimage_is_base &&
        !evidence.committed &&
        !evidence.commit_ambiguous) {
        return KeeneticDnsCandidateTerminalAction::
            finish_clean_precommit;
    }

    if (evidence.outcome ==
            RuntimeFirewallLifecycleOutcome::not_verified &&
        evidence.exact_lease_owned &&
        evidence.runtime_generation_current &&
        !evidence.commit_ambiguous &&
        evidence.exact_rollback_available &&
        (!evidence.committed || evidence.candidate_core_available)) {
        return KeeneticDnsCandidateTerminalAction::start_exact_rollback;
    }
    return KeeneticDnsCandidateTerminalAction::request_fresh_recovery;
}

enum class KeeneticDnsRollbackTerminalAction : std::uint8_t {
    finish_verified_rollback,
    request_fresh_recovery,
};

constexpr KeeneticDnsRollbackTerminalAction
plan_keenetic_dns_rollback_terminal(
    const RuntimeFirewallLifecycleTerminal& terminal,
    bool exact_lease_owned,
    bool runtime_generation_current,
    bool rollback_publication_succeeded) noexcept {
    return terminal.outcome ==
               RuntimeFirewallLifecycleOutcome::verified_success &&
           terminal.committed && !terminal.commit_ambiguous &&
           exact_lease_owned && runtime_generation_current &&
           rollback_publication_succeeded
        ? KeeneticDnsRollbackTerminalAction::finish_verified_rollback
        : KeeneticDnsRollbackTerminalAction::request_fresh_recovery;
}

// Recovery is a fresh observation, never another transaction-body attempt.
// It may be dispatched only after the exact writer token has left the DNS
// lifecycle.
constexpr bool keenetic_dns_fresh_recovery_dispatch_allowed(
    bool recovery_required,
    bool exact_lease_still_owned) noexcept {
    return recovery_required && !exact_lease_still_owned;
}

enum class KeeneticDnsFirewallTerminalPhase : std::uint8_t {
    idle,
    candidate,
    rollback,
    finished,
};

// Production terminal owner for one private DNS generation. It rejects
// duplicate/out-of-order callbacks and verifies that candidate and rollback
// are completed with the same physical admission token.
class KeeneticDnsFirewallTerminalOrchestrator final {
public:
    bool begin(std::uint64_t mutation_lease_token) noexcept {
        if (phase_ != KeeneticDnsFirewallTerminalPhase::idle ||
            mutation_lease_token == 0U) {
            return false;
        }
        mutation_lease_token_ = mutation_lease_token;
        phase_ = KeeneticDnsFirewallTerminalPhase::candidate;
        return true;
    }

    // The daemon calls this from the worker terminal drain before it may
    // enter ResolverStreamCoordinator. Re-entry for the same asynchronous
    // stream is idempotent; a stream can never be admitted before exact
    // route/firewall COMMIT proof or under a different physical token.
    bool admit_resolver_stream_after_firewall(
        bool route_firewall_commit_proven,
        std::uint64_t observed_lease_token) noexcept {
        if ((phase_ != KeeneticDnsFirewallTerminalPhase::candidate &&
             phase_ != KeeneticDnsFirewallTerminalPhase::rollback) ||
            observed_lease_token == 0U ||
            observed_lease_token != mutation_lease_token_ ||
            !route_firewall_commit_proven) {
            return false;
        }
        resolver_stream_started_ = true;
        return true;
    }

    bool observe_resolver_stream_terminal(
        bool verified,
        std::uint64_t observed_lease_token) noexcept {
        if ((phase_ != KeeneticDnsFirewallTerminalPhase::candidate &&
             phase_ != KeeneticDnsFirewallTerminalPhase::rollback) ||
            observed_lease_token == 0U ||
            observed_lease_token != mutation_lease_token_ ||
            !resolver_stream_started_ || resolver_terminal_observed_) {
            return false;
        }
        resolver_terminal_observed_ = true;
        resolver_verified_ = verified;
        return true;
    }

    bool resolver_stream_verified(
        std::uint64_t observed_lease_token) const noexcept {
        return observed_lease_token != 0U &&
            observed_lease_token == mutation_lease_token_ &&
            resolver_stream_started_ && resolver_terminal_observed_ &&
            resolver_verified_;
    }

    KeeneticDnsCandidateTerminalAction complete_candidate(
        KeeneticDnsCandidateTerminalEvidence evidence,
        std::uint64_t observed_lease_token) noexcept {
        if (phase_ != KeeneticDnsFirewallTerminalPhase::candidate ||
            observed_lease_token == 0U ||
            observed_lease_token != mutation_lease_token_) {
            phase_ = KeeneticDnsFirewallTerminalPhase::finished;
            return KeeneticDnsCandidateTerminalAction::
                request_fresh_recovery;
        }
        if (evidence.outcome ==
                RuntimeFirewallLifecycleOutcome::verified_success &&
            !resolver_stream_verified(observed_lease_token)) {
            evidence.outcome =
                RuntimeFirewallLifecycleOutcome::not_verified;
        }
        const auto action =
            plan_keenetic_dns_candidate_terminal(evidence);
        if (action ==
            KeeneticDnsCandidateTerminalAction::start_exact_rollback) {
            phase_ = KeeneticDnsFirewallTerminalPhase::rollback;
            resolver_stream_started_ = false;
            resolver_terminal_observed_ = false;
            resolver_verified_ = false;
        } else {
            phase_ = KeeneticDnsFirewallTerminalPhase::finished;
        }
        return action;
    }

    KeeneticDnsRollbackTerminalAction complete_rollback(
        const RuntimeFirewallLifecycleTerminal& terminal,
        bool exact_lease_owned,
        bool runtime_generation_current,
        bool rollback_publication_succeeded,
        std::uint64_t observed_lease_token) noexcept {
        if (phase_ != KeeneticDnsFirewallTerminalPhase::rollback ||
            observed_lease_token == 0U ||
            observed_lease_token != mutation_lease_token_) {
            phase_ = KeeneticDnsFirewallTerminalPhase::finished;
            return KeeneticDnsRollbackTerminalAction::
                request_fresh_recovery;
        }
        if (!resolver_stream_verified(observed_lease_token)) {
            rollback_publication_succeeded = false;
        }
        phase_ = KeeneticDnsFirewallTerminalPhase::finished;
        return plan_keenetic_dns_rollback_terminal(
            terminal,
            exact_lease_owned,
            runtime_generation_current,
            rollback_publication_succeeded);
    }

    bool fresh_recovery_dispatch_allowed(
        bool recovery_required,
        bool exact_lease_still_owned) const noexcept {
        return phase_ == KeeneticDnsFirewallTerminalPhase::finished &&
            keenetic_dns_fresh_recovery_dispatch_allowed(
                recovery_required, exact_lease_still_owned);
    }

    KeeneticDnsFirewallTerminalPhase phase() const noexcept {
        return phase_;
    }

private:
    std::uint64_t mutation_lease_token_{0U};
    bool resolver_stream_started_{false};
    bool resolver_terminal_observed_{false};
    bool resolver_verified_{false};
    KeeneticDnsFirewallTerminalPhase phase_{
        KeeneticDnsFirewallTerminalPhase::idle};
};

// The production publication seam makes the CAS boundary explicit. When the
// cursor predicate fails, the no-throw commit callback is never invoked and
// all published cursors remain unchanged. Once admitted, the callback is
// restricted to swaps/scalars/move-restores and therefore cannot expose a
// half-published DNS/firewall/resolver tuple.
template <typename CurrentFn, typename CommitFn>
bool publish_keenetic_dns_generation_if_current(
    CurrentFn&& current,
    CommitFn&& commit) noexcept {
    static_assert(
        std::is_nothrow_invocable_r_v<bool, CurrentFn&>,
        "Keenetic DNS publication CAS must be noexcept");
    static_assert(
        std::is_nothrow_invocable_r_v<void, CommitFn&>,
        "Keenetic DNS publication commit must be noexcept");
    if (!current()) {
        return false;
    }
    commit();
    return true;
}

} // namespace keen_pbr3
