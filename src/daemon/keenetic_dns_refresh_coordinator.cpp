#include "keenetic_dns_refresh_coordinator.hpp"

#include "../runtime/periodic_task_metrics.hpp"
#include "../util/blocking_executor.hpp"

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <string>
#include <utility>

namespace keen_pbr3 {

namespace {

std::string refresh_failure_message(
    const KeeneticDnsRefreshResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.status ==
        KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE) {
        return "Keenetic DNS refresh failed; cached value retained";
    }
    return "Keenetic DNS refresh failed with no cached value";
}

void finish_refresh_metrics(
    PeriodicTaskRunToken& token,
    const KeeneticDnsRefreshResult& result) {
    switch (result.status) {
    case KeeneticDnsRefreshStatus::UPDATED:
        (void)token.success();
        break;
    case KeeneticDnsRefreshStatus::UNCHANGED:
        (void)token.noop();
        break;
    case KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE:
    case KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE:
        (void)token.failure(refresh_failure_message(result));
        break;
    }
}

} // namespace

struct KeeneticDnsRefreshCoordinator::State final
    : std::enable_shared_from_this<State> {
    enum class ClaimPhase : std::uint8_t {
        idle,
        worker,
        posting,
        control,
    };

    State(BlockingExecutor& executor_value,
          PeriodicTaskMetricsRegistry& metrics_value,
          RefreshFn refresh_value,
          PostControlFn post_control_value,
          CommitFn commit_value,
          CommitWithLeaseFn commit_with_lease_value = {})
        : executor(executor_value),
          metrics(metrics_value),
          refresh(std::move(refresh_value)),
          post_control(std::move(post_control_value)),
          commit(std::move(commit_value)),
          commit_with_lease(std::move(commit_with_lease_value)) {}

    RequestResult request(std::uint64_t runtime_generation,
                          RuntimeMutationLeaseHandoff mutation_lease) noexcept {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (stopping) {
            return RequestResult::rejected;
        }

        latest_generation =
            std::max(latest_generation, runtime_generation);

        if (in_flight) {
            pending = true;
            if (mutation_lease.state() !=
                RuntimeMutationLeaseHandoffState::Empty) {
                latest_mutation_lease = std::move(mutation_lease);
            }
            return RequestResult::coalesced;
        }

        in_flight = true;
        active_mutation_lease = std::move(mutation_lease);
        active_claim_id = next_claim_id_locked();
        claim_phase = ClaimPhase::worker;
        if (!enqueue_claimed_locked(latest_generation, active_claim_id)) {
            active_mutation_lease = {};
            in_flight = false;
            active_claim_id = 0;
            claim_phase = ClaimPhase::idle;
            return RequestResult::rejected;
        }
        return RequestResult::started;
    }

    void stop() noexcept {
        std::unique_lock<std::mutex> lock(state_mutex);
        stopping = true;
        pending = false;
        phase_changed.notify_all();
        callbacks_finished.wait(lock, [this]() {
            return active_callbacks == 0;
        });
        latest_mutation_lease = {};
        active_mutation_lease = {};
    }

private:
    struct CallbackLease {
        State* owner{nullptr};
        ~CallbackLease() noexcept {
            if (owner) {
                owner->end_callback();
            }
        }
    };

    struct ClaimLease {
        State* owner{nullptr};
        std::uint64_t claim_id{0};
        ~ClaimLease() noexcept {
            if (owner) {
                owner->complete_claim(claim_id);
            }
        }
        void transfer_to_control() noexcept {
            owner = nullptr;
        }
    };

    // state_mutex is held by the caller. BlockingExecutor::try_post is a
    // bounded non-blocking enqueue, so keeping the claim and enqueue in one
    // critical section closes the stop/handoff race without doing I/O here.
    bool enqueue_claimed_locked(std::uint64_t generation,
                                std::uint64_t claim_id) noexcept {
        std::shared_ptr<PeriodicTaskRunToken> task_metrics;
        try {
            task_metrics = std::make_shared<PeriodicTaskRunToken>(
                metrics.begin(KeeneticDnsRefreshCoordinator::metric_label()));
        } catch (const std::exception&) {
            return false;
        } catch (...) {
            return false;
        }

        bool enqueued = false;
        try {
            const auto self = shared_from_this();
            enqueued = executor.try_post(
                "keenetic-dns-refresh",
                [self, generation, claim_id, task_metrics]() {
                    self->run_worker(generation, claim_id, task_metrics);
                });
        } catch (const std::exception& error) {
            (void)task_metrics->skipped(error.what());
            return false;
        } catch (...) {
            (void)task_metrics->skipped(
                "blocking executor threw while queuing Keenetic DNS refresh");
            return false;
        }
        if (!enqueued) {
            (void)task_metrics->skipped(
                "blocking executor rejected Keenetic DNS refresh");
            return false;
        }
        return true;
    }

    bool begin_worker_callback(std::uint64_t claim_id) noexcept {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (stopping || !in_flight || active_claim_id != claim_id ||
            claim_phase != ClaimPhase::worker) {
            return false;
        }
        ++active_callbacks;
        return true;
    }

    bool begin_control_callback(std::uint64_t claim_id) noexcept {
        std::unique_lock<std::mutex> lock(state_mutex);
        phase_changed.wait(lock, [this, claim_id]() {
            return stopping || !in_flight ||
                   active_claim_id != claim_id ||
                   claim_phase != ClaimPhase::posting;
        });
        if (stopping || !in_flight || active_claim_id != claim_id ||
            claim_phase != ClaimPhase::control) {
            return false;
        }
        ++active_callbacks;
        return true;
    }

    bool begin_posting(std::uint64_t claim_id) noexcept {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (stopping || !in_flight || active_claim_id != claim_id ||
            claim_phase != ClaimPhase::worker) {
            return false;
        }
        claim_phase = ClaimPhase::posting;
        return true;
    }

    bool finish_posting(std::uint64_t claim_id, bool posted) noexcept {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (!in_flight || active_claim_id != claim_id ||
            claim_phase != ClaimPhase::posting) {
            phase_changed.notify_all();
            return false;
        }

        if (!posted || stopping) {
            claim_phase = ClaimPhase::worker;
            phase_changed.notify_all();
            return false;
        }

        claim_phase = ClaimPhase::control;
        phase_changed.notify_all();
        return true;
    }

    void end_callback() noexcept {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (active_callbacks > 0) {
            --active_callbacks;
        }
        if (active_callbacks == 0) {
            callbacks_finished.notify_all();
        }
    }

    void run_worker(
        std::uint64_t generation,
        std::uint64_t claim_id,
        const std::shared_ptr<PeriodicTaskRunToken>& task_metrics) {
        ClaimLease claim_lease{this, claim_id};
        if (!begin_worker_callback(claim_id)) {
            (void)task_metrics->abandon("coordinator stopped");
            return;
        }
        CallbackLease callback_lease{this};

        KeeneticDnsRefreshResult result;
        try {
            result = refresh();
        } catch (const std::exception& error) {
            result.status =
                KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE;
            result.error = error.what();
        } catch (...) {
            result.status =
                KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE;
            result.error = "Keenetic DNS refresh threw an unknown exception";
        }

        if (!begin_posting(claim_id)) {
            (void)task_metrics->abandon("coordinator stopped");
            return;
        }

        bool posted = false;
        try {
            {
                const auto self = shared_from_this();
                posted = post_control(
                    [self,
                     generation,
                     claim_id,
                     result = std::move(result),
                     task_metrics]() mutable {
                        self->commit_on_control(
                            generation, claim_id, result, task_metrics);
                    });
            }
        } catch (const std::exception& error) {
            (void)finish_posting(claim_id, false);
            (void)task_metrics->failure(error.what());
            return;
        } catch (...) {
            (void)finish_posting(claim_id, false);
            (void)task_metrics->failure(
                "posting Keenetic DNS refresh result threw an unknown exception");
            return;
        }

        if (!finish_posting(claim_id, posted)) {
            (void)task_metrics->abandon(
                posted ? "coordinator stopped"
                       : "control queue rejected Keenetic DNS refresh result");
            return;
        }
        claim_lease.transfer_to_control();
    }

    void commit_on_control(
        std::uint64_t generation,
        std::uint64_t claim_id,
        const KeeneticDnsRefreshResult& result,
        const std::shared_ptr<PeriodicTaskRunToken>& task_metrics) {
        ClaimLease claim_lease{this, claim_id};
        if (!begin_control_callback(claim_id)) {
            // Before the posting phase is committed the worker still owns the
            // shared token. Do not race its failure/abandon path here. After a
            // successful handoff this callback is the last owner, so the token
            // destructor records abandonment if shutdown rejects the commit.
            return;
        }
        CallbackLease callback_lease{this};

        try {
            const bool committed = commit_with_lease
                ? commit_with_lease(
                      generation, result, active_mutation_lease)
                : commit(generation, result);
            if (!committed) {
                (void)task_metrics->abandon("stale runtime generation");
            } else {
                finish_refresh_metrics(*task_metrics, result);
            }
        } catch (const std::exception& error) {
            (void)task_metrics->failure(error.what());
        } catch (...) {
            (void)task_metrics->failure(
                "committing Keenetic DNS refresh threw an unknown exception");
        }
    }

    void complete_claim(std::uint64_t claim_id) noexcept {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (!in_flight || active_claim_id != claim_id) {
            return;
        }
        if (stopping) {
            pending = false;
            latest_mutation_lease = {};
            active_mutation_lease = {};
            in_flight = false;
            active_claim_id = 0;
            claim_phase = ClaimPhase::idle;
            phase_changed.notify_all();
            return;
        }

        if (!pending) {
            active_mutation_lease = {};
            in_flight = false;
            active_claim_id = 0;
            claim_phase = ClaimPhase::idle;
            phase_changed.notify_all();
            return;
        }

        pending = false;
        active_mutation_lease = std::move(latest_mutation_lease);
        active_claim_id = next_claim_id_locked();
        claim_phase = ClaimPhase::worker;
        if (!enqueue_claimed_locked(latest_generation, active_claim_id)) {
            active_mutation_lease = {};
            in_flight = false;
            active_claim_id = 0;
            claim_phase = ClaimPhase::idle;
            phase_changed.notify_all();
        }
    }

    std::uint64_t next_claim_id_locked() noexcept {
        ++last_claim_id;
        if (last_claim_id == 0) {
            ++last_claim_id;
        }
        return last_claim_id;
    }

    BlockingExecutor& executor;
    PeriodicTaskMetricsRegistry& metrics;
    RefreshFn refresh;
    PostControlFn post_control;
    CommitFn commit;
    CommitWithLeaseFn commit_with_lease;

    std::mutex state_mutex;
    std::condition_variable callbacks_finished;
    std::condition_variable phase_changed;
    std::uint64_t latest_generation{0};
    std::uint64_t last_claim_id{0};
    std::uint64_t active_claim_id{0};
    std::size_t active_callbacks{0};
    ClaimPhase claim_phase{ClaimPhase::idle};
    bool in_flight{false};
    bool pending{false};
    bool stopping{false};
    RuntimeMutationLeaseHandoff active_mutation_lease;
    RuntimeMutationLeaseHandoff latest_mutation_lease;
};

KeeneticDnsRefreshCoordinator::KeeneticDnsRefreshCoordinator(
    BlockingExecutor& executor,
    PeriodicTaskMetricsRegistry& metrics,
    RefreshFn refresh,
    PostControlFn post_control,
    CommitFn commit)
    : state_(std::make_shared<State>(executor,
                                     metrics,
                                     std::move(refresh),
                                     std::move(post_control),
                                     std::move(commit))) {}

KeeneticDnsRefreshCoordinator::KeeneticDnsRefreshCoordinator(
    BlockingExecutor& executor,
    PeriodicTaskMetricsRegistry& metrics,
    RefreshFn refresh,
    PostControlFn post_control,
    CommitWithLeaseFn commit)
    : state_(std::make_shared<State>(executor,
                                     metrics,
                                     std::move(refresh),
                                     std::move(post_control),
                                     CommitFn{},
                                     std::move(commit))) {}

KeeneticDnsRefreshCoordinator::~KeeneticDnsRefreshCoordinator() {
    stop();
}

KeeneticDnsRefreshCoordinator::RequestResult
KeeneticDnsRefreshCoordinator::request(
    std::uint64_t runtime_generation,
    RuntimeMutationLeaseHandoff mutation_lease) noexcept {
    if (!state_) {
        return RequestResult::rejected;
    }
    return state_->request(runtime_generation, std::move(mutation_lease));
}

void KeeneticDnsRefreshCoordinator::stop() noexcept {
    if (state_) {
        state_->stop();
    }
}

} // namespace keen_pbr3
