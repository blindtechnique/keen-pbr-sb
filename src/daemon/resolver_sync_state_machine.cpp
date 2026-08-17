#include "resolver_sync_state_machine.hpp"

#include <utility>

namespace keen_pbr3 {

namespace {

bool within_converging_window(std::optional<std::int64_t> apply_started_ts,
                              std::int64_t now_ts) {
    return apply_started_ts.has_value() &&
           (now_ts - *apply_started_ts) <=
               ResolverSyncStateMachine::kConvergingWindowSeconds;
}

} // namespace

api::ResolverConfigProbeStatus resolver_probe_status_from_hash_probe_status(
    ResolverConfigHashProbeStatus status) {
    switch (status) {
    case ResolverConfigHashProbeStatus::SUCCESS:
        return api::ResolverConfigProbeStatus::SUCCESS;
    case ResolverConfigHashProbeStatus::NO_USABLE_TXT:
        return api::ResolverConfigProbeStatus::MISSING_TXT;
    case ResolverConfigHashProbeStatus::INVALID_TXT:
        return api::ResolverConfigProbeStatus::INVALID_TXT;
    case ResolverConfigHashProbeStatus::QUERY_FAILED:
        return api::ResolverConfigProbeStatus::QUERY_FAILED;
    }
    return api::ResolverConfigProbeStatus::UNKNOWN;
}

bool resolver_sync_semantically_equal(const ResolverSyncSnapshot& lhs,
                                      const ResolverSyncSnapshot& rhs) {
    return lhs.expected_hash == rhs.expected_hash &&
           lhs.actual_hash == rhs.actual_hash &&
           lhs.actual_ts == rhs.actual_ts &&
           lhs.apply_started_ts == rhs.apply_started_ts &&
           lhs.sync_state == rhs.sync_state &&
           lhs.probe_status == rhs.probe_status &&
           lhs.live_status == rhs.live_status;
}

std::chrono::seconds resolver_convergence_retry_delay(std::uint32_t attempt) {
    constexpr std::uint32_t kMaximumPowerOfTwoAttempt = 5;
    if (attempt > kMaximumPowerOfTwoAttempt) {
        return std::chrono::seconds{60};
    }
    return std::chrono::seconds{1U << attempt};
}

ResolverProbeCommitPlan plan_resolver_probe_commit(
    const ResolverSyncSnapshot& previous,
    const ResolverSyncSnapshot& current,
    std::uint32_t retry_attempt) {
    ResolverProbeCommitPlan plan;
    plan.publish_runtime_state =
        !resolver_sync_semantically_equal(previous, current);
    plan.next_retry_attempt = retry_attempt;

    // CONVERGING covers the initial apply window. A successful hash mismatch
    // remains actionable after that window becomes STALE: treating it as a
    // steady refresh reset the attempt counter and could turn a persistent
    // mismatch into a tight sequence of first-attempt retries.
    const bool successful_hash_mismatch =
        current.probe_status == api::ResolverConfigProbeStatus::SUCCESS &&
        !current.expected_hash.empty() &&
        current.actual_hash != current.expected_hash;
    plan.report_stale_txt_observation =
        plan.publish_runtime_state &&
        successful_hash_mismatch &&
        current.actual_ts.has_value() &&
        current.apply_started_ts.has_value() &&
        *current.actual_ts < *current.apply_started_ts;
    plan.schedule_convergence_retry =
        current.sync_state == api::ResolverConfigSyncState::CONVERGING ||
        successful_hash_mismatch;

    if (plan.schedule_convergence_retry) {
        plan.convergence_retry_delay =
            resolver_convergence_retry_delay(retry_attempt);
        constexpr std::uint32_t kMaximumRetryAttempt = 6;
        plan.next_retry_attempt = retry_attempt >= kMaximumRetryAttempt
            ? kMaximumRetryAttempt
            : retry_attempt + 1;
    } else if (current.sync_state ==
                   api::ResolverConfigSyncState::CONVERGED ||
               current.probe_status ==
                   api::ResolverConfigProbeStatus::NOT_CONFIGURED) {
        // A transient unavailable/stale observation outside the initial apply
        // window uses the existing steady 60-second refresh, but it is not
        // evidence that convergence happened. Preserve the accumulated retry
        // attempt so a later successful mismatch cannot jump back to 1s.
        plan.next_retry_attempt = 0;
    }
    return plan;
}

void ResolverSyncStateMachine::runtime_stopped() {
    runtime_active_ = false;
    resolver_configured_ = false;
    actual_hash_.clear();
    actual_ts_.reset();
    last_probe_ts_.reset();
    probe_status_ = api::ResolverConfigProbeStatus::NOT_CONFIGURED;
    consecutive_probe_failures_ = 0;
}

void ResolverSyncStateMachine::resolver_not_configured() {
    runtime_active_ = true;
    resolver_configured_ = false;
    actual_hash_.clear();
    actual_ts_.reset();
    last_probe_ts_.reset();
    probe_status_ = api::ResolverConfigProbeStatus::NOT_CONFIGURED;
    consecutive_probe_failures_ = 0;
}

void ResolverSyncStateMachine::expected_hash_updated(std::string expected_hash) {
    runtime_active_ = true;
    resolver_configured_ = true;
    expected_hash_ = std::move(expected_hash);
}

void ResolverSyncStateMachine::apply_started(std::int64_t ts, std::string expected_hash) {
    runtime_active_ = true;
    resolver_configured_ = true;
    apply_started_ts_ = ts;
    expected_hash_ = std::move(expected_hash);
    // A fresh apply starts a new observation window: failures from before it
    // say nothing about the configuration that is being installed now.
    consecutive_probe_failures_ = 0;
}

void ResolverSyncStateMachine::probe_succeeded(std::string actual_hash,
                                               std::optional<std::int64_t> actual_ts,
                                               std::optional<std::int64_t> probe_ts) {
    runtime_active_ = true;
    resolver_configured_ = true;
    actual_hash_ = std::move(actual_hash);
    actual_ts_ = actual_ts;
    last_probe_ts_ = probe_ts;
    probe_status_ = api::ResolverConfigProbeStatus::SUCCESS;
    consecutive_probe_failures_ = 0;
}

void ResolverSyncStateMachine::probe_failed(ResolverConfigHashProbeStatus status,
                                            std::optional<std::int64_t> probe_ts) {
    runtime_active_ = true;
    resolver_configured_ = true;
    ++consecutive_probe_failures_;
    // A missing TXT during a dnsmasq reload is indistinguishable from a stale
    // resolver, so both wait for the failure to repeat before we act on it.
    if (status != ResolverConfigHashProbeStatus::QUERY_FAILED &&
        consecutive_probe_failures_ >= kFailuresBeforeClearing) {
        actual_hash_.clear();
        actual_ts_.reset();
    }
    last_probe_ts_ = probe_ts;
    probe_status_ = resolver_probe_status_from_hash_probe_status(status);
}

ResolverSyncSnapshot ResolverSyncStateMachine::snapshot(std::int64_t now_ts) const {
    ResolverSyncSnapshot result;
    result.expected_hash = expected_hash_;
    result.actual_hash = actual_hash_;
    result.actual_ts = actual_ts_;
    result.last_probe_ts = last_probe_ts_;
    result.apply_started_ts = apply_started_ts_;
    result.probe_status = probe_status_;

    if (!runtime_active_ || !resolver_configured_) {
        result.probe_status = api::ResolverConfigProbeStatus::NOT_CONFIGURED;
        result.live_status = api::ResolverLiveStatus::UNKNOWN;
        return result;
    }

    if (expected_hash_.empty()) {
        result.live_status = api::ResolverLiveStatus::UNKNOWN;
        return result;
    }

    const bool converging = within_converging_window(apply_started_ts_, now_ts) &&
        (probe_status_ == api::ResolverConfigProbeStatus::UNKNOWN ||
         probe_status_ == api::ResolverConfigProbeStatus::QUERY_FAILED ||
         probe_status_ == api::ResolverConfigProbeStatus::MISSING_TXT ||
         probe_status_ == api::ResolverConfigProbeStatus::INVALID_TXT ||
         (expected_hash_ != actual_hash_ && actual_ts_.has_value() && apply_started_ts_.has_value() &&
          *actual_ts_ < *apply_started_ts_));

    if (converging) {
        result.sync_state = api::ResolverConfigSyncState::CONVERGING;
        result.live_status = probe_status_ == api::ResolverConfigProbeStatus::QUERY_FAILED
            ? api::ResolverLiveStatus::UNAVAILABLE
            : api::ResolverLiveStatus::HEALTHY;
        return result;
    }

    if (probe_status_ == api::ResolverConfigProbeStatus::QUERY_FAILED) {
        result.live_status = api::ResolverLiveStatus::UNAVAILABLE;
        return result;
    }

    if (probe_status_ == api::ResolverConfigProbeStatus::SUCCESS) {
        // A non-DNS apply deliberately leaves dnsmasq untouched. An older TXT
        // timestamp is therefore valid when its hash already matches.
        result.sync_state = expected_hash_ == actual_hash_
            ? api::ResolverConfigSyncState::CONVERGED
            : api::ResolverConfigSyncState::STALE;
        result.live_status = api::ResolverLiveStatus::HEALTHY;
        return result;
    }

    if (probe_status_ == api::ResolverConfigProbeStatus::MISSING_TXT ||
        probe_status_ == api::ResolverConfigProbeStatus::INVALID_TXT) {
        result.sync_state = api::ResolverConfigSyncState::STALE;
        result.live_status = api::ResolverLiveStatus::DEGRADED;
        return result;
    }

    result.live_status = api::ResolverLiveStatus::UNKNOWN;
    return result;
}

ResolverSyncCheckpoint ResolverSyncStateMachine::checkpoint() const {
    ResolverSyncCheckpoint result;
    result.expected_hash = expected_hash_;
    result.actual_hash = actual_hash_;
    result.actual_ts = actual_ts_;
    result.last_probe_ts = last_probe_ts_;
    result.apply_started_ts = apply_started_ts_;
    result.probe_status = probe_status_;
    result.consecutive_probe_failures = consecutive_probe_failures_;
    result.runtime_active = runtime_active_;
    result.resolver_configured = resolver_configured_;
    return result;
}

void ResolverSyncStateMachine::restore(
    const ResolverSyncCheckpoint& checkpoint) {
    expected_hash_ = checkpoint.expected_hash;
    actual_hash_ = checkpoint.actual_hash;
    actual_ts_ = checkpoint.actual_ts;
    last_probe_ts_ = checkpoint.last_probe_ts;
    apply_started_ts_ = checkpoint.apply_started_ts;
    probe_status_ = checkpoint.probe_status;
    consecutive_probe_failures_ = checkpoint.consecutive_probe_failures;
    runtime_active_ = checkpoint.runtime_active;
    resolver_configured_ = checkpoint.resolver_configured;
}

void ResolverSyncStateMachine::restore(
    ResolverSyncCheckpoint&& checkpoint) noexcept {
    expected_hash_ = std::move(checkpoint.expected_hash);
    actual_hash_ = std::move(checkpoint.actual_hash);
    actual_ts_ = std::move(checkpoint.actual_ts);
    last_probe_ts_ = std::move(checkpoint.last_probe_ts);
    apply_started_ts_ = std::move(checkpoint.apply_started_ts);
    probe_status_ = checkpoint.probe_status;
    consecutive_probe_failures_ = checkpoint.consecutive_probe_failures;
    runtime_active_ = checkpoint.runtime_active;
    resolver_configured_ = checkpoint.resolver_configured;
}

} // namespace keen_pbr3
