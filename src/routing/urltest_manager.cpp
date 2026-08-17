#include "urltest_manager.hpp"

#include "../daemon/scheduler.hpp"
#include "../log/logger.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

struct TestCandidate {
    std::string child_tag;
    std::string url;
    uint32_t fwmark{0};
    uint32_t timeout_ms{0};
    RetryConfig retry;
};

struct ProbeBatch {
    explicit ProbeBatch(std::size_t worker_count)
        : workers_remaining(worker_count) {}

    std::mutex mutex;
    std::map<std::string, URLTestResult> results;
    std::size_t workers_remaining{0};
    bool aborted{false};
};

template <typename Fn>
class ScopeExit final {
public:
    explicit ScopeExit(Fn fn)
        : fn_(std::move(fn)) {}

    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;

    ~ScopeExit() noexcept {
        if (!active_) {
            return;
        }
        try {
            fn_();
        } catch (...) {
            // Cleanup callbacks used here are noexcept already. Keep this
            // final fence so an unexpected logging/locking exception cannot
            // escape a worker during stack unwinding.
        }
    }

    void dismiss() noexcept { active_ = false; }

private:
    Fn fn_;
    bool active_{true};
};

template <typename Fn>
ScopeExit<std::decay_t<Fn>> make_scope_exit(Fn&& fn) {
    return ScopeExit<std::decay_t<Fn>>(std::forward<Fn>(fn));
}

constexpr std::size_t kMaxConcurrentUrltestCandidates = 2;
constexpr auto kExternalHealthRetryInterval =
    std::chrono::milliseconds{500};
constexpr std::uint8_t kExternalHealthMaxFailures = 4;

std::uint64_t next_nonzero_serial(std::uint64_t current) noexcept {
    return current == std::numeric_limits<std::uint64_t>::max()
               ? 1
               : current + 1;
}

std::chrono::seconds normalize_interval_seconds(const Outbound& outbound) {
    auto interval = std::chrono::seconds(outbound.interval_ms.value_or(180000) / 1000);
    if (interval.count() < 1) {
        interval = std::chrono::seconds(1);
    }
    return interval;
}

} // namespace

UrltestManager::UrltestManager(URLTester& tester,
                               const OutboundMarkMap& marks,
                               RepeatingTaskScheduler& scheduler,
                               BlockingExecutor& blocking_executor,
                               UrltestChangeCallback on_change,
                               UrltestCommitCallback on_commit)
    : tester_(tester)
    , marks_(marks)
    , scheduler_(scheduler)
    , blocking_executor_(blocking_executor)
    , on_change_(std::move(on_change))
    , on_commit_(std::move(on_commit)) {}

UrltestManager::~UrltestManager() {
    try {
        clear();
    } catch (const std::exception& e) {
        Logger::instance().error("UrltestManager cleanup failed during destruction: {}",
                                 e.what());
    } catch (...) {
        Logger::instance().error(
            "UrltestManager cleanup failed during destruction: unknown error");
    }
}

void UrltestManager::register_urltest(
    const Outbound& ut,
    std::string initial_selected_outbound) {
    {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);

        UrltestState state;
        state.config = ut;

        for (const auto& group : ut.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
            for (const auto& child_tag : group.outbounds) {
                state.circuit_breakers.emplace(
                    child_tag,
                    CircuitBreaker(ut.circuit_breaker.value_or(CircuitBreakerConfig{})));
            }
        }
        if (!initial_selected_outbound.empty() &&
            state.circuit_breakers.find(initial_selected_outbound) ==
                state.circuit_breakers.end()) {
            Logger::instance().warn(
                "Ignoring retained urltest selection '{}' for '{}': child is "
                "not part of the selector",
                initial_selected_outbound,
                ut.tag);
            initial_selected_outbound.clear();
        }
        state.selected_outbound = std::move(initial_selected_outbound);

        const std::string tag = ut.tag;
        state.scheduler_task_id = scheduler_.schedule_repeating(
            normalize_interval_seconds(ut),
            [this, tag]() {
                run_tests(tag);
            },
            "urltest:" + tag);

        states_.emplace(ut.tag, std::move(state));
    }

    Logger::instance().trace("urltest_register", "tag={}", ut.tag);
    queue_probe_unlocked(ut.tag, "initial");
}

void UrltestManager::trigger_immediate_test(const std::string& urltest_tag) {
    queue_probe_unlocked(urltest_tag, "manual");
}

void UrltestManager::trigger_external_health_test(
    const std::string& urltest_tag) noexcept {
    try {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        const auto it = states_.find(urltest_tag);
        if (it == states_.end()) {
            return;
        }

        auto& state = it->second;
        if (state.external_health_request_serial ==
            std::numeric_limits<std::uint64_t>::max()) {
            // A fully completed counter can be rebased without changing the
            // outstanding-request relation. With an outstanding UINT64_MAX
            // request, further transitions are already coalesced into it.
            if (state.external_health_completed_serial ==
                state.external_health_request_serial) {
                state.external_health_request_serial = 0;
                state.external_health_completed_serial = 0;
            }
        }
        if (state.external_health_request_serial !=
            std::numeric_limits<std::uint64_t>::max()) {
            ++state.external_health_request_serial;
        }
        // A new reachability edge earns a fresh bounded retry budget even if
        // it arrived while an older external request was still unresolved.
        state.external_health_failures = 0;
    } catch (...) {
        return;
    }

    try_start_external_health_probe(urltest_tag);
}

bool UrltestManager::commit_probe_results(const std::string& urltest_tag,
                                          std::uint64_t generation,
                                          std::map<std::string, URLTestResult> results) {
    std::string new_selected;
    std::string previous_selected;
    std::optional<UrltestSelectionChange> selection_change;
    bool selection_changed = false;
    ExternalHealthResolution external_health_resolution;

    try {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        auto it = states_.find(urltest_tag);
        if (it == states_.end()) {
            Logger::instance().trace("urltest_commit_skip",
                                     "tag={} generation={} reason=missing_state",
                                     urltest_tag,
                                     generation);
            return false;
        }

        auto& state = it->second;
        if (generation != state.generation || !state.probe_inflight) {
            Logger::instance().trace(
                "urltest_commit_skip",
                "tag={} generation={} current_generation={} inflight={} reason=stale",
                urltest_tag,
                generation,
                state.generation,
                state.probe_inflight ? "true" : "false");
            return false;
        }

        // Prepare every allocation and every potentially throwing breaker/map
        // mutation on a private copy. The live generation retains ownership
        // of all begun requests until the no-throw swaps below publish the
        // complete candidate state.
        UrltestState candidate_state = state;
        for (const auto& [child_tag, result] : results) {
            auto cb_it = candidate_state.circuit_breakers.find(child_tag);
            if (cb_it == candidate_state.circuit_breakers.end()) {
                continue;
            }

            cb_it->second.end_request(child_tag);
            if (result.success) {
                cb_it->second.record_success(child_tag);
            } else {
                cb_it->second.record_failure(child_tag);
            }
            candidate_state.last_results[child_tag] = result;
        }

        previous_selected = candidate_state.selected_outbound;
        new_selected = select_outbound_from_state(candidate_state);
        if (new_selected != previous_selected) {
            UrltestSelectionChangeReason reason =
                UrltestSelectionChangeReason::initial;
            if (!previous_selected.empty()) {
                const auto previous_result =
                    candidate_state.last_results.find(previous_selected);
                const auto previous_breaker =
                    candidate_state.circuit_breakers.find(previous_selected);
                const bool previous_healthy =
                    previous_result != candidate_state.last_results.end() &&
                    previous_result->second.success &&
                    previous_breaker !=
                        candidate_state.circuit_breakers.end() &&
                    previous_breaker->second.state(previous_selected) ==
                        CircuitState::closed;
                reason =
                    previous_healthy
                        ? UrltestSelectionChangeReason::healthy_rebalance
                        : UrltestSelectionChangeReason::previous_unhealthy;
            }

            candidate_state.selected_outbound = new_selected;
            selection_changed = true;
            selection_change = UrltestSelectionChange{
                .urltest_tag = urltest_tag,
                .probe_generation = generation,
                .previous_child_tag = previous_selected,
                .new_child_tag = new_selected,
                .reason = reason,
            };
        }

#ifdef KEEN_PBR3_TESTING
        if (fail_next_commit_after_prepare_) {
            fail_next_commit_after_prepare_ = false;
            throw std::runtime_error(
                "injected urltest commit failure after candidate prepare");
        }
#endif

        // std::allocator-backed map/string swap is noexcept. Only the fields
        // changed by a probe are replaced; config, scheduler id and generation
        // remain the exact live objects validated above.
        state.last_results.swap(candidate_state.last_results);
        state.circuit_breakers.swap(candidate_state.circuit_breakers);
        state.selected_outbound.swap(candidate_state.selected_outbound);
        // A changed selection remains single-flight until the controller
        // accepts the ordered transition below. This prevents another probe
        // from observing the candidate cursor during the callback and makes a
        // rejected/throwing handoff safely retryable.
        if (!selection_changed) {
            state.probe_inflight = false;
            external_health_resolution =
                finish_external_health_probe_locked(
                    state, /*controller_admitted=*/true);
        }
    } catch (...) {
        // The worker handed ownership to this controller callback. If prepare
        // failed before publication, release the exact still-live generation;
        // if publication already completed, probe_inflight=false makes this a
        // no-op and prevents double end_request.
        abandon_probe_results(urltest_tag, generation, results);
        throw;
    }

    bool transition_admitted = !selection_changed;
    if (selection_change.has_value()) {
        try {
            transition_admitted =
                on_change_ && on_change_(*selection_change);
        } catch (...) {
            // Admission exceptions are equivalent to a rejected handoff. The
            // exact live generation is restored below; no queued transition
            // owns it.
            transition_admitted = false;
        }

        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        const auto it = states_.find(urltest_tag);
        if (it != states_.end() &&
            it->second.generation == generation &&
            it->second.probe_inflight) {
            if (!transition_admitted) {
                // The old cursor was copied before candidate publication, so
                // this rollback is allocation-free and cannot strand a
                // half-published selection under memory pressure.
                it->second.selected_outbound.swap(previous_selected);
            }
            it->second.probe_inflight = false;
            external_health_resolution =
                finish_external_health_probe_locked(
                    it->second, transition_admitted);
        }
    }

    try {
        Logger::instance().trace(
            "urltest_commit",
            "tag={} generation={} changed={} admitted={} selected={}",
            urltest_tag,
            generation,
            selection_changed && transition_admitted ? "true" : "false",
            transition_admitted ? "true" : "false",
            new_selected);
    } catch (...) {
    }

    if (external_health_resolution.retry_task_to_cancel >= 0) {
        cancel_scheduler_task(
            external_health_resolution.retry_task_to_cancel);
    }
    if (external_health_resolution.launch_trailing) {
        try_start_external_health_probe(urltest_tag);
    } else if (external_health_resolution.ensure_retry) {
        ensure_external_health_retry(urltest_tag);
    }

    return selection_changed && transition_admitted;
}

#ifdef KEEN_PBR3_TESTING
void UrltestManager::fail_next_commit_after_prepare_for_testing() {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    fail_next_commit_after_prepare_ = true;
}
#endif

std::string UrltestManager::get_selected(const std::string& urltest_tag) const {
    KPBR_SHARED_LOCK(lock, mutex_);
    const auto it = states_.find(urltest_tag);
    if (it == states_.end()) {
        return "";
    }
    return it->second.selected_outbound;
}

std::optional<UrltestState> UrltestManager::get_state(const std::string& urltest_tag) const {
    KPBR_SHARED_LOCK(lock, mutex_);
    const auto it = states_.find(urltest_tag);
    if (it == states_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void UrltestManager::ensure_external_health_retry(
    const std::string& tag) noexcept {
    int registration_task_id = -1;
    std::uint64_t retry_epoch = 0;
    try {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        const auto it = states_.find(tag);
        if (it == states_.end()) {
            return;
        }
        auto& state = it->second;
        const bool pending =
            state.external_health_request_serial !=
            state.external_health_completed_serial;
        if (!pending ||
            state.external_health_failures >=
                kExternalHealthMaxFailures ||
            state.external_health_retry_task_id >= 0 ||
            state.external_health_retry_scheduling) {
            return;
        }
        state.external_health_retry_scheduling = true;
        state.external_health_retry_epoch =
            next_nonzero_serial(state.external_health_retry_epoch);
        registration_task_id = state.scheduler_task_id;
        retry_epoch = state.external_health_retry_epoch;
    } catch (...) {
        return;
    }

    int scheduled_task_id = -1;
    try {
        scheduled_task_id = scheduler_.schedule_repeating(
            kExternalHealthRetryInterval,
            [this, tag, registration_task_id, retry_epoch]() {
                run_external_health_retry(
                    tag, registration_task_id, retry_epoch);
            },
            "urltest-external-health-retry:" + tag);
    } catch (const std::exception& error) {
        try {
            Logger::instance().trace(
                "urltest_external_health_retry_schedule_failed",
                "tag={} error={}",
                tag,
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }

    bool published = false;
    try {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        const auto it = states_.find(tag);
        if (it != states_.end() &&
            it->second.scheduler_task_id == registration_task_id &&
            it->second.external_health_retry_scheduling &&
            it->second.external_health_retry_epoch == retry_epoch) {
            auto& state = it->second;
            state.external_health_retry_scheduling = false;
            const bool pending =
                state.external_health_request_serial !=
                state.external_health_completed_serial;
            if (scheduled_task_id >= 0 && pending &&
                state.external_health_failures <
                    kExternalHealthMaxFailures &&
                state.external_health_retry_task_id < 0) {
                state.external_health_retry_task_id = scheduled_task_id;
                published = true;
            }
        }
    } catch (...) {
    }

    if (scheduled_task_id >= 0 && !published) {
        cancel_scheduler_task(scheduled_task_id);
    }
}

void UrltestManager::run_external_health_retry(
    const std::string& tag,
    int registration_task_id,
    std::uint64_t retry_epoch) noexcept {
    int retry_task_to_cancel = -1;
    bool should_attempt = false;
    bool exhausted = false;
    try {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        const auto it = states_.find(tag);
        if (it == states_.end()) {
            return;
        }
        auto& state = it->second;
        if (state.scheduler_task_id != registration_task_id ||
            state.external_health_retry_task_id < 0 ||
            state.external_health_retry_epoch != retry_epoch) {
            return;
        }
        const bool pending =
            state.external_health_request_serial !=
            state.external_health_completed_serial;
        if (!pending ||
            state.external_health_failures >=
                kExternalHealthMaxFailures) {
            exhausted = pending;
            retry_task_to_cancel =
                state.external_health_retry_task_id;
            state.external_health_retry_task_id = -1;
            state.external_health_retry_epoch = next_nonzero_serial(
                state.external_health_retry_epoch);
        } else if (!state.probe_inflight) {
            should_attempt = true;
        }
    } catch (...) {
        return;
    }

    if (retry_task_to_cancel >= 0) {
        cancel_scheduler_task(retry_task_to_cancel);
    }
    if (exhausted) {
        try {
            Logger::instance().info(
                "Urltest '{}' external-health retry budget was exhausted; "
                "the next scheduled or health-triggered probe may retry",
                tag);
        } catch (...) {
        }
    }
    if (should_attempt) {
        try_start_external_health_probe(tag);
    }
}

void UrltestManager::try_start_external_health_probe(
    const std::string& tag) noexcept {
    ensure_external_health_retry(tag);

    std::uint8_t expected_failures = 0;
    try {
        KPBR_SHARED_LOCK(lock, mutex_);
        const auto it = states_.find(tag);
        if (it == states_.end()) {
            return;
        }
        const auto& state = it->second;
        if (state.external_health_request_serial ==
                state.external_health_completed_serial ||
            state.probe_inflight ||
            state.external_health_failures >=
                kExternalHealthMaxFailures) {
            return;
        }
        expected_failures = state.external_health_failures;
    } catch (...) {
        return;
    }

    bool queued = false;
    try {
        queued = queue_probe_unlocked(tag, "external-health");
    } catch (const std::exception& error) {
        try {
            Logger::instance().trace(
                "urltest_external_health_admission_failed",
                "tag={} error={}",
                tag,
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
    if (!queued) {
        record_external_health_start_failure(tag, expected_failures);
        ensure_external_health_retry(tag);
    }
}

void UrltestManager::record_external_health_start_failure(
    const std::string& tag,
    std::uint8_t expected_failures) noexcept {
    try {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        const auto it = states_.find(tag);
        if (it == states_.end()) {
            return;
        }
        auto& state = it->second;
        if (state.external_health_request_serial ==
                state.external_health_completed_serial ||
            state.probe_inflight ||
            state.external_health_failures != expected_failures) {
            return;
        }
        if (state.external_health_failures <
            kExternalHealthMaxFailures) {
            ++state.external_health_failures;
        }
    } catch (...) {
    }
}

void UrltestManager::record_claimed_external_health_failure_locked(
    UrltestState& state) noexcept {
    if (state.probe_external_health_serial == 0) {
        return;
    }
    state.probe_external_health_serial = 0;
    if (state.external_health_request_serial !=
            state.external_health_completed_serial &&
        state.external_health_failures <
            kExternalHealthMaxFailures) {
        ++state.external_health_failures;
    }
}

UrltestManager::ExternalHealthResolution
UrltestManager::finish_external_health_probe_locked(
    UrltestState& state,
    bool controller_admitted) noexcept {
    ExternalHealthResolution resolution;
    const auto claimed_serial =
        state.probe_external_health_serial;
    state.probe_external_health_serial = 0;

    if (claimed_serial != 0) {
        if (controller_admitted) {
            state.external_health_completed_serial = claimed_serial;
            state.external_health_failures = 0;
        } else if (state.external_health_failures <
                   kExternalHealthMaxFailures) {
            ++state.external_health_failures;
        }
    }

    const bool pending =
        state.external_health_request_serial !=
        state.external_health_completed_serial;
    if (!pending) {
        resolution.retry_task_to_cancel =
            state.external_health_retry_task_id;
        state.external_health_retry_task_id = -1;
        // A timer may still be between reservation and scheduler publication.
        // Invalidate that reservation as well; its publisher will observe the
        // epoch/flag mismatch and cancel the now-unneeded task.
        state.external_health_retry_scheduling = false;
        state.external_health_retry_epoch = next_nonzero_serial(
            state.external_health_retry_epoch);
        state.external_health_failures = 0;
    } else {
        resolution.ensure_retry =
            state.external_health_failures <
            kExternalHealthMaxFailures;
        if ((claimed_serial == 0 || controller_admitted) &&
            resolution.ensure_retry) {
            // An unclaimed probe predates the health edge. A successfully
            // completed claimed probe can also have a newer edge waiting
            // behind its serial. Both cases need exactly one immediate
            // trailing round.
            resolution.launch_trailing = true;
        }
    }
    return resolution;
}

void UrltestManager::cancel_scheduler_task(int task_id) noexcept {
    if (task_id < 0) {
        return;
    }
    try {
        scheduler_.cancel(task_id);
    } catch (...) {
    }
}

bool UrltestManager::synchronize_selected(
    const std::string& urltest_tag,
    const std::string& selected_outbound) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    const auto it = states_.find(urltest_tag);
    if (it == states_.end()) {
        return false;
    }
    if (!selected_outbound.empty() &&
        it->second.circuit_breakers.find(selected_outbound) ==
            it->second.circuit_breakers.end()) {
        return false;
    }
    it->second.selected_outbound = selected_outbound;
    return true;
}

bool UrltestManager::synchronize_selected_if_generation(
    const std::string& urltest_tag,
    std::uint64_t expected_generation,
    const std::string& selected_outbound) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    const auto it = states_.find(urltest_tag);
    if (it == states_.end() ||
        it->second.generation != expected_generation) {
        return false;
    }
    if (!selected_outbound.empty() &&
        it->second.circuit_breakers.find(selected_outbound) ==
            it->second.circuit_breakers.end()) {
        return false;
    }
    it->second.selected_outbound = selected_outbound;
    return true;
}

void UrltestManager::clear() {
    std::map<std::string, UrltestState> retired_states;
    {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        states_.swap(retired_states);
        ++generation_;
    }

    // Scheduler cancellation may synchronously rendezvous with the control
    // loop. Never hold the manager mutex across it: a timer callback already
    // dispatched on that loop may itself be waiting to inspect manager state.
    for (auto& [tag, state] : retired_states) {
        (void)tag;
        if (state.scheduler_task_id >= 0) {
            cancel_scheduler_task(state.scheduler_task_id);
        }
        if (state.external_health_retry_task_id >= 0) {
            cancel_scheduler_task(
                state.external_health_retry_task_id);
        }
    }
}

void UrltestManager::run_tests(const std::string& tag) {
    queue_probe_unlocked(tag, "scheduled");
}

bool UrltestManager::is_probe_current(const std::string& tag,
                                      std::uint64_t generation) const {
    const auto it = states_.find(tag);
    return it != states_.end() && it->second.generation == generation;
}

void UrltestManager::abandon_probe(
    const std::string& tag,
    std::uint64_t generation,
    const std::vector<std::string>& candidate_tags) noexcept {
    bool external_retry_needed = false;
    try {
        {
            KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
            const auto it = states_.find(tag);
            if (it == states_.end() ||
                it->second.generation != generation ||
                !it->second.probe_inflight) {
                return;
            }

            auto& state = it->second;
            state.probe_inflight = false;
            record_claimed_external_health_failure_locked(state);
            external_retry_needed =
                state.external_health_request_serial !=
                    state.external_health_completed_serial &&
                state.external_health_failures <
                    kExternalHealthMaxFailures;
            state.generation = generation_++;
            for (const auto& child_tag : candidate_tags) {
                const auto breaker = state.circuit_breakers.find(child_tag);
                if (breaker != state.circuit_breakers.end()) {
                    breaker->second.end_request(child_tag);
                }
            }
        }
    } catch (...) {
        // This path runs from noexcept worker finalizers. Every normal
        // implementation of the operations above is allocation-free for an
        // existing generation; never let cleanup terminate the executor.
    }
    if (external_retry_needed) {
        ensure_external_health_retry(tag);
    }
}

void UrltestManager::abandon_probe_results(
    const std::string& tag,
    std::uint64_t generation,
    const std::map<std::string, URLTestResult>& results) noexcept {
    bool external_retry_needed = false;
    try {
        {
            KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
            const auto it = states_.find(tag);
            if (it == states_.end() ||
                it->second.generation != generation ||
                !it->second.probe_inflight) {
                return;
            }

            auto& state = it->second;
            state.probe_inflight = false;
            record_claimed_external_health_failure_locked(state);
            external_retry_needed =
                state.external_health_request_serial !=
                    state.external_health_completed_serial &&
                state.external_health_failures <
                    kExternalHealthMaxFailures;
            state.generation = generation_++;
            for (const auto& [child_tag, result] : results) {
                (void)result;
                const auto breaker = state.circuit_breakers.find(child_tag);
                if (breaker != state.circuit_breakers.end()) {
                    breaker->second.end_request(child_tag);
                }
            }
        }
    } catch (...) {
    }
    if (external_retry_needed) {
        ensure_external_health_retry(tag);
    }
}

bool UrltestManager::queue_probe_unlocked(const std::string& tag,
                                          const std::string& reason) {
    std::shared_ptr<const std::vector<TestCandidate>> candidates_for_probe;
    std::shared_ptr<const std::vector<std::string>> candidate_tags;
    std::shared_ptr<ProbeBatch> batch;
    std::uint64_t probe_generation = 0;
    std::size_t worker_count = 0;
    const TraceId trace_id = ensure_trace_id();

    {
        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        auto it = states_.find(tag);
        if (it == states_.end()) {
            Logger::instance().trace("urltest_probe_skip",
                                     "tag={} reason=missing_state trigger={}",
                                     tag,
                                     reason);
            return false;
        }

        auto& state = it->second;
        if (state.probe_inflight) {
            Logger::instance().trace("urltest_probe_skip",
                                     "tag={} reason=inflight trigger={}",
                                     tag,
                                     reason);
            return false;
        }

        std::vector<TestCandidate> candidates;

        for (const auto& group : state.config.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
            for (const auto& child_tag : group.outbounds) {
                const auto mark_it = marks_.find(child_tag);
                if (mark_it == marks_.end()) {
                    continue;
                }

                auto cb_it = state.circuit_breakers.find(child_tag);
                if (cb_it == state.circuit_breakers.end()) {
                    continue;
                }

                if (!cb_it->second.is_allowed(child_tag)) {
                    continue;
                }

                candidates.push_back(TestCandidate{
                    .child_tag = child_tag,
                    .url = state.config.url.value_or(""),
                    .fwmark = mark_it->second,
                    .timeout_ms = static_cast<uint32_t>(
                        state.config.probe_timeout_ms.value_or(kDefaultUrltestProbeTimeoutMs)),
                    .retry = state.config.retry.value_or(RetryConfig{}),
                });
            }
        }

        std::vector<std::string> tags;
        tags.reserve(candidates.size());
        for (const auto& candidate : candidates) {
            tags.push_back(candidate.child_tag);
        }

        worker_count = std::max<std::size_t>(
            1,
            std::min(kMaxConcurrentUrltestCandidates, candidates.size()));
        candidates_for_probe =
            std::make_shared<const std::vector<TestCandidate>>(
                std::move(candidates));
        candidate_tags =
            std::make_shared<const std::vector<std::string>>(
                std::move(tags));
        batch = std::make_shared<ProbeBatch>(worker_count);

        // All allocations which can fail before worker ownership transfer are
        // complete. From here every begun request is covered by the exact
        // generation cleanup guard below.
        state.probe_inflight = true;
        state.probe_external_health_serial = 0;
        state.generation = generation_++;
        probe_generation = state.generation;
        try {
            for (const auto& candidate : *candidates_for_probe) {
                auto cb_it =
                    state.circuit_breakers.find(candidate.child_tag);
                if (cb_it != state.circuit_breakers.end()) {
                    cb_it->second.begin_request(candidate.child_tag);
                }
            }
            if (state.external_health_request_serial !=
                state.external_health_completed_serial) {
                state.probe_external_health_serial =
                    state.external_health_request_serial;
            }
        } catch (...) {
            state.probe_inflight = false;
            state.probe_external_health_serial = 0;
            state.generation = generation_++;
            for (const auto& candidate : *candidates_for_probe) {
                auto cb_it =
                    state.circuit_breakers.find(candidate.child_tag);
                if (cb_it != state.circuit_breakers.end()) {
                    cb_it->second.end_request(candidate.child_tag);
                }
            }
            throw;
        }
    }

    // Until every worker is admitted, the producer owns the exact generation.
    // A partial enqueue is deliberately invalidated: already queued workers
    // will observe the newer generation and cannot commit partial results.
    auto admission_guard = make_scope_exit([this,
                                            &tag,
                                            probe_generation,
                                            &candidate_tags]() noexcept {
        abandon_probe(tag, probe_generation, *candidate_tags);
    });

    Logger::instance().trace("urltest_probe_queued",
                             "tag={} generation={} trigger={} candidates={}",
                             tag,
                             probe_generation,
                             reason,
                             candidates_for_probe->size());

    for (std::size_t worker_index = 0; worker_index < worker_count; ++worker_index) {
        bool enqueued = false;
        try {
            enqueued = blocking_executor_.try_post(
                "urltest:" + tag,
                [this,
                 tag,
                 probe_generation,
                 reason,
                 candidates_for_probe,
                 candidate_tags,
                 batch,
                 worker_index,
                 worker_count,
                 trace_id]() mutable {
                    ScopedTraceContext trace_scope(trace_id);
                    // The guard is created before any operation which may
                    // throw. Only a completely normal worker marks itself
                    // successful; every other exit aborts the shared batch.
                    bool worker_aborted = true;
                    auto completion_guard = make_scope_exit(
                        [this,
                         &tag,
                         probe_generation,
                         &candidate_tags,
                         &batch,
                         &worker_aborted,
                         trace_id]() noexcept {
                            bool abandon_results = false;
                            std::map<std::string, URLTestResult>
                                completed_results;

                            try {
                                {
                                    std::lock_guard<std::mutex> batch_lock(
                                        batch->mutex);
                                    batch->aborted =
                                        batch->aborted || worker_aborted;
                                    if (batch->workers_remaining == 0) {
                                        return;
                                    }
                                    --batch->workers_remaining;
                                    if (batch->workers_remaining != 0) {
                                        return;
                                    }
                                    abandon_results = batch->aborted;
                                    if (!abandon_results) {
                                        completed_results =
                                            std::move(batch->results);
                                    }
                                }

                                if (abandon_results) {
                                    abandon_probe(
                                        tag,
                                        probe_generation,
                                        *candidate_tags);
                                    return;
                                }

                                bool admitted = false;
                                try {
                                    admitted = on_commit_ && on_commit_(
                                        tag,
                                        probe_generation,
                                        std::move(completed_results),
                                        trace_id);
                                } catch (const std::exception& error) {
                                    try {
                                        Logger::instance().trace(
                                            "urltest_commit_skip",
                                            "tag={} generation={} reason=commit_admission_exception error={}",
                                            tag,
                                            probe_generation,
                                            error.what());
                                    } catch (...) {
                                    }
                                } catch (...) {
                                    try {
                                        Logger::instance().trace(
                                            "urltest_commit_skip",
                                            "tag={} generation={} reason=commit_admission_exception error=unknown",
                                            tag,
                                            probe_generation);
                                    } catch (...) {
                                    }
                                }

                                if (!admitted) {
                                    abandon_probe(
                                        tag,
                                        probe_generation,
                                        *candidate_tags);
                                }
                            } catch (...) {
                                abandon_probe(tag,
                                              probe_generation,
                                              *candidate_tags);
                            }
                        });

                    for (std::size_t index = worker_index;
                         index < candidates_for_probe->size();
                         index += worker_count) {
                        const auto& candidate =
                            candidates_for_probe->at(index);
                        {
                            KPBR_SHARED_LOCK(lock, mutex_);
                            if (!is_probe_current(tag, probe_generation)) {
                                Logger::instance().trace(
                                    "urltest_probe_abort",
                                    "tag={} generation={} child={} trigger={} reason=stale_probe",
                                    tag,
                                    probe_generation,
                                    candidate.child_tag,
                                    reason);
                                return;
                            }
                        }

                        const auto started_at =
                            std::chrono::steady_clock::now();
                        Logger::instance().trace(
                            "urltest_candidate_start",
                            "tag={} generation={} child={} fwmark={} trigger={}",
                            tag,
                            probe_generation,
                            candidate.child_tag,
                            candidate.fwmark,
                            reason);

                        auto result = tester_.test(candidate.url,
                                                   candidate.fwmark,
                                                   candidate.timeout_ms,
                                                   candidate.retry);

                        const auto duration_ms =
                            std::chrono::duration_cast<
                                std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() -
                                started_at)
                                .count();
                        Logger::instance().trace(
                            "urltest_candidate_end",
                            "tag={} generation={} child={} success={} latency_ms={} duration_ms={} error={}",
                            tag,
                            probe_generation,
                            candidate.child_tag,
                            result.success ? "true" : "false",
                            result.latency_ms,
                            duration_ms,
                            result.error.empty() ? std::string("-")
                                                 : result.error);

                        std::lock_guard<std::mutex> batch_lock(batch->mutex);
                        batch->results.emplace(candidate.child_tag,
                                               std::move(result));
                    }

                    {
                        KPBR_SHARED_LOCK(lock, mutex_);
                        if (!is_probe_current(tag, probe_generation)) {
                            return;
                        }
                    }
                    worker_aborted = false;
                },
                trace_id);
        } catch (...) {
            try {
                std::lock_guard<std::mutex> batch_lock(batch->mutex);
                batch->aborted = true;
            } catch (...) {
            }
            throw;
        }

        if (enqueued) {
            continue;
        }

        {
            std::lock_guard<std::mutex> batch_lock(batch->mutex);
            batch->aborted = true;
        }

        Logger::instance().trace(
            "urltest_probe_skip",
            "tag={} generation={} trigger={} reason=executor_unavailable",
            tag,
            probe_generation,
            reason);
        return false;
    }

    admission_guard.dismiss();
    return true;
}

std::string UrltestManager::select_outbound(const std::string& tag) {
    const auto it = states_.find(tag);
    if (it == states_.end()) {
        return "";
    }

    return select_outbound_from_state(it->second);
}

std::string UrltestManager::select_outbound_from_state(
    const UrltestState& state) {
    const auto& ut = state.config;
    if (!ut.outbound_groups.has_value()) {
        return "";
    }

    struct GroupRef {
        size_t index;
        uint32_t weight;
    };

    const auto& groups = *ut.outbound_groups;
    std::vector<GroupRef> sorted_groups;
    sorted_groups.reserve(groups.size());
    for (size_t i = 0; i < groups.size(); ++i) {
        sorted_groups.push_back(GroupRef{
            .index = i,
            .weight = static_cast<uint32_t>(groups[i].weight.value_or(1)),
        });
    }
    std::stable_sort(sorted_groups.begin(),
                     sorted_groups.end(),
                     [](const GroupRef& lhs, const GroupRef& rhs) {
                         return lhs.weight < rhs.weight;
                     });

    const auto healthy_result = [&state](const std::string& child_tag)
        -> const URLTestResult* {
        const auto cb_it = state.circuit_breakers.find(child_tag);
        // HALF_OPEN is probe-only. Routing user traffic through it before the
        // configured success threshold would bypass the circuit breaker's
        // recovery contract and make priority mode flap back too early.
        if (cb_it == state.circuit_breakers.end() ||
            cb_it->second.state(child_tag) != CircuitState::closed) {
            return nullptr;
        }

        const auto result_it = state.last_results.find(child_tag);
        if (result_it == state.last_results.end() || !result_it->second.success) {
            return nullptr;
        }

        return &result_it->second;
    };

    const bool prefer_declared_priority =
        ut.selection_mode.value_or(UrltestSelectionMode::LATENCY) ==
        UrltestSelectionMode::PRIORITY;

    for (const auto& group_ref : sorted_groups) {
        const auto& group = groups[group_ref.index];

        if (prefer_declared_priority) {
            for (const auto& child_tag : group.outbounds) {
                if (healthy_result(child_tag) != nullptr) {
                    return child_tag;
                }
            }
            continue;
        }

        uint32_t min_latency = std::numeric_limits<uint32_t>::max();

        for (const auto& child_tag : group.outbounds) {
            const auto* result = healthy_result(child_tag);
            if (result == nullptr) {
                continue;
            }
            min_latency = std::min(min_latency, result->latency_ms);
        }

        if (min_latency == std::numeric_limits<uint32_t>::max()) {
            continue;
        }

        const uint32_t tolerance = static_cast<uint32_t>(ut.tolerance_ms.value_or(100));

        if (!state.selected_outbound.empty()) {
            const auto existing_it = std::find(group.outbounds.begin(),
                                               group.outbounds.end(),
                                               state.selected_outbound);
            if (existing_it != group.outbounds.end()) {
                const auto* result = healthy_result(state.selected_outbound);
                if (result != nullptr &&
                    result->latency_ms <= min_latency + tolerance) {
                    return state.selected_outbound;
                }
            }
        }

        for (const auto& child_tag : group.outbounds) {
            const auto* result = healthy_result(child_tag);
            if (result == nullptr) {
                continue;
            }
            if (result->latency_ms <= min_latency + tolerance) {
                return child_tag;
            }
        }
    }

    return "";
}

} // namespace keen_pbr3
