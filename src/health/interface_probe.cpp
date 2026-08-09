#include "interface_probe.hpp"

#include "../log/logger.hpp"

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <limits>
#include <new>
#include <optional>
#include <pthread.h>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

namespace {

bool verified_reachable(const InterfaceProbeResult& result) {
    return result.success && result.attributed;
}

bool same_target_identity(const InterfaceProbe::Target& left,
                          const InterfaceProbe::Target& right) noexcept {
    return left.tag == right.tag && left.fwmark == right.fwmark &&
           left.interface == right.interface;
}

constexpr std::size_t kInterfaceProbeWorkerStackSize =
    static_cast<std::size_t>(1024) * 1024;

struct InterfaceProbeCompletion {
    std::optional<InterfaceProbe::Observation> observation;
    std::exception_ptr failure;
    bool acknowledged{false};
};

static_assert(
    std::is_nothrow_move_constructible_v<InterfaceProbe::Observation>,
    "interface probe completion publication must not allocate");

// Workers only measure. This coordinator owns target claims and a preallocated
// completion FIFO; measure_each's calling thread is the sole sink publisher.
// A successful worker waits for its sink acknowledgement before claiming
// another target, which makes sink rejection a precise stop boundary.
class InterfaceProbeMeasureState {
public:
    InterfaceProbeMeasureState(
        InterfaceProbe& probe,
        const std::vector<InterfaceProbe::Target>& targets,
        std::size_t worker_count)
        : probe_(probe),
          targets_(targets),
          worker_count_(worker_count),
          completions_(targets.size()),
          completion_order_(targets.size()) {}

    bool claim(std::size_t& target_index) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_requested_ || next_target_ >= targets_.size()) {
            return false;
        }
        target_index = next_target_++;
        return true;
    }

    bool publish_success(
        std::size_t target_index,
        InterfaceProbe::Observation observation) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stop_requested_) {
            return false;
        }

        auto& completion = completions_[target_index];
        completion.observation.emplace(std::move(observation));
        completion_order_[completion_count_++] = target_index;
        cv_.notify_all();

        cv_.wait(lock, [&]() {
            return stop_requested_ || completion.acknowledged;
        });
        return !stop_requested_;
    }

    void publish_failure(
        std::size_t target_index,
        std::exception_ptr failure) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_requested_) {
            return;
        }

        completions_[target_index].failure = std::move(failure);
        completion_order_[completion_count_++] = target_index;
        stop_requested_ = true;
        cv_.notify_all();
    }

    void publish_coordinator_failure(std::exception_ptr failure) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!stop_requested_) {
                coordinator_failure_ = std::move(failure);
                stop_requested_ = true;
            }
            cv_.notify_all();
        } catch (...) {
            // A failed synchronization primitive offers no recoverable
            // handoff. Keep the pthread entry noexcept; normal pthread mutexes
            // do not take this path.
        }
    }

    void worker_finished() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            ++workers_finished_;
            cv_.notify_all();
        } catch (...) {
        }
    }

    struct NextCompletion {
        std::size_t target_index{0};
        std::optional<InterfaceProbe::Observation> observation;
        std::exception_ptr failure;
        bool workers_finished_without_result{false};
    };

    NextCompletion wait_next(std::size_t consumed) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&]() {
            return consumed < completion_count_ ||
                   coordinator_failure_ != nullptr ||
                   workers_finished_ == worker_count_;
        });

        NextCompletion next;
        if (consumed < completion_count_) {
            next.target_index = completion_order_[consumed];
            auto& completion = completions_[next.target_index];
            next.failure = completion.failure;
            if (completion.observation) {
                next.observation.emplace(
                    std::move(*completion.observation));
                completion.observation.reset();
            }
            return next;
        }
        if (coordinator_failure_) {
            next.failure = coordinator_failure_;
            return next;
        }

        next.workers_finished_without_result = true;
        return next;
    }

    void acknowledge(std::size_t target_index) {
        std::lock_guard<std::mutex> lock(mutex_);
        completions_[target_index].acknowledged = true;
        cv_.notify_all();
    }

    void request_stop() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_requested_ = true;
            cv_.notify_all();
        } catch (...) {
        }
    }

    void worker_loop() noexcept {
        try {
            std::size_t target_index = 0;
            while (claim(target_index)) {
                std::optional<InterfaceProbe::Observation> observation;
                try {
                    observation.emplace(
                        probe_.measure_one(targets_[target_index]));
                } catch (...) {
                    publish_failure(
                        target_index, std::current_exception());
                    break;
                }
                if (!publish_success(
                        target_index, std::move(*observation))) {
                    break;
                }
            }
        } catch (...) {
            publish_coordinator_failure(std::current_exception());
        }
        worker_finished();
    }

private:
    InterfaceProbe& probe_;
    const std::vector<InterfaceProbe::Target>& targets_;
    const std::size_t worker_count_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::size_t next_target_{0};
    std::size_t completion_count_{0};
    std::size_t workers_finished_{0};
    bool stop_requested_{false};
    std::exception_ptr coordinator_failure_;
    std::vector<InterfaceProbeCompletion> completions_;
    std::vector<std::size_t> completion_order_;
};

struct InterfaceProbeWorkerStart {
    InterfaceProbeMeasureState* state{nullptr};
};

void* interface_probe_worker_entry(void* argument) noexcept {
    auto* start = static_cast<InterfaceProbeWorkerStart*>(argument);
    start->state->worker_loop();
    return nullptr;
}

class InterfaceProbeThreadGroup {
public:
    InterfaceProbeThreadGroup(
        InterfaceProbeMeasureState& state,
        std::size_t capacity)
        : state_(state), threads_(capacity) {}

    ~InterfaceProbeThreadGroup() {
        state_.request_stop();
        join();
    }

    void add(pthread_t thread) noexcept {
        threads_[created_++] = thread;
    }

    void join() noexcept {
        for (std::size_t index = 0; index < created_; ++index) {
            (void)pthread_join(threads_[index], nullptr);
        }
        created_ = 0;
    }

private:
    InterfaceProbeMeasureState& state_;
    std::vector<pthread_t> threads_;
    std::size_t created_{0};
};

class InterfaceProbePthreadAttributes {
public:
    InterfaceProbePthreadAttributes() {
        const int init_rc = pthread_attr_init(&attributes_);
        if (init_rc != 0) {
            throw std::system_error(
                init_rc, std::generic_category(),
                "pthread_attr_init failed for interface probes");
        }
        initialized_ = true;

        const long page_result = sysconf(_SC_PAGESIZE);
        const std::size_t page_size = page_result > 0
            ? static_cast<std::size_t>(page_result)
            : static_cast<std::size_t>(4096);
        const std::size_t minimum = std::max<std::size_t>(
            kInterfaceProbeWorkerStackSize,
            static_cast<std::size_t>(PTHREAD_STACK_MIN));
        const std::size_t stack_size =
            ((minimum + page_size - 1) / page_size) * page_size;
        const int stack_rc =
            pthread_attr_setstacksize(&attributes_, stack_size);
        if (stack_rc != 0) {
            (void)pthread_attr_destroy(&attributes_);
            initialized_ = false;
            throw std::system_error(
                stack_rc, std::generic_category(),
                "pthread_attr_setstacksize failed for interface probes");
        }
    }

    ~InterfaceProbePthreadAttributes() {
        if (initialized_) {
            (void)pthread_attr_destroy(&attributes_);
        }
    }

    pthread_attr_t* get() noexcept { return &attributes_; }

private:
    pthread_attr_t attributes_{};
    bool initialized_{false};
};

} // namespace

std::vector<std::string> InterfaceProbe::probe(
    const std::vector<Target>& targets) {
    return commit(measure(targets));
}

InterfaceProbe::Observation InterfaceProbe::measure_one(
    const Target& target) {
    const auto result = tester_.test(
        url_, target.fwmark, static_cast<uint32_t>(timeout_.count()),
        retry_, target.interface);

    InterfaceProbeResult measured;
    measured.success = result.success;
    measured.attributed = !target.interface.empty();
    measured.latency_ms = result.latency_ms;
    measured.error = result.error;
    measured.measured_at = clock_();

    try {
        Logger::instance().trace(
            "interface_probe",
            "tag={} fwmark={} interface={} attributed={} success={} latency_ms={} error={}",
            target.tag,
            target.fwmark,
            target.interface.empty() ? std::string("-") : target.interface,
            measured.attributed,
            result.success,
            result.latency_ms,
            result.error);
    } catch (...) {
    }

    return Observation{target, std::move(measured)};
}

std::vector<InterfaceProbe::Observation> InterfaceProbe::measure(
    const std::vector<Target>& targets) {
    std::vector<Observation> observations;
    observations.reserve(targets.size());

    for (const auto& target : targets) {
        observations.push_back(measure_one(target));
    }

    return observations;
}

bool InterfaceProbe::measure_each(
    const std::vector<Target>& targets,
    const std::function<bool(Observation)>& observation_sink) {
    if (!observation_sink) {
        return false;
    }
    if (targets.empty()) {
        return true;
    }

    const auto worker_count = std::min(
        max_parallel_probes(), targets.size());
    if (worker_count <= 1) {
        for (const auto& target : targets) {
            if (!observation_sink(measure_one(target))) {
                return false;
            }
        }
        return true;
    }

    // Every allocation needed by the coordinator and pthread bookkeeping is
    // complete before a worker can publish or before the sink is invoked.
    InterfaceProbeMeasureState state(*this, targets, worker_count);
    InterfaceProbeThreadGroup workers(state, worker_count);
    std::vector<InterfaceProbeWorkerStart> starts(
        worker_count, InterfaceProbeWorkerStart{&state});
    InterfaceProbePthreadAttributes attributes;

    try {
        for (std::size_t index = 0; index < worker_count; ++index) {
#ifdef KEEN_PBR3_TESTING
            auto injected = static_cast<std::ptrdiff_t>(index);
            if (fail_worker_creation_at_.compare_exchange_strong(
                    injected,
                    std::ptrdiff_t{-1},
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                throw std::runtime_error(
                    "synthetic interface probe worker creation failure");
            }
#endif
            pthread_t worker{};
            const int create_rc = pthread_create(
                &worker,
                attributes.get(),
                interface_probe_worker_entry,
                &starts[index]);
            if (create_rc != 0) {
                throw std::system_error(
                    create_rc,
                    std::generic_category(),
                    "pthread_create failed for interface probe");
            }
            workers.add(worker);
        }
    } catch (...) {
        // No sink publication starts until the complete worker set exists.
        state.request_stop();
        workers.join();
        throw;
    }

    std::size_t consumed = 0;
    while (consumed < targets.size()) {
        auto completion = state.wait_next(consumed);
        if (completion.failure) {
            state.request_stop();
            workers.join();
            std::rethrow_exception(completion.failure);
        }
        if (completion.workers_finished_without_result ||
            !completion.observation) {
            state.request_stop();
            workers.join();
            throw std::runtime_error(
                "interface probe workers ended before completing the round");
        }

        bool accepted = false;
        try {
            accepted = observation_sink(
                std::move(*completion.observation));
        } catch (...) {
            state.request_stop();
            workers.join();
            throw;
        }
        if (!accepted) {
            state.request_stop();
            workers.join();
            return false;
        }

        state.acknowledge(completion.target_index);
        ++consumed;
    }

    workers.join();
    return true;
}

bool InterfaceProbe::commit_observation(
    const Observation& observation) {
    // Prepare every allocation-bearing field before taking publication
    // authority. An allocation failure here leaves the previous exact
    // identity/result pair untouched.
    auto prepared = std::make_shared<const PublishedObservation>(
        PublishedObservation{
            observation.target,
            observation.result,
        });
    std::string tag = observation.target.tag;

    std::lock_guard<std::mutex> lock(mutex_);
    const auto previous = published_observations_.find(tag);
    const bool transitioned =
        previous != published_observations_.end() &&
        verified_reachable(previous->second->result) !=
            verified_reachable(observation.result);

#ifdef KEEN_PBR3_TESTING
    if (fail_next_commit_after_prepare_) {
        fail_next_commit_after_prepare_ = false;
        throw std::bad_alloc{};
    }
#endif

    if (previous != published_observations_.end()) {
        // The immutable observation pointer is statically nothrow-swappable,
        // so readers can observe only the complete old pair or complete new
        // pair. This also avoids relying on old libstdc++ string swap traits.
        previous->second.swap(prepared);
    } else {
        // std::map insertion has the strong guarantee. The fully prepared
        // key/value are not visible unless node publication succeeds.
        published_observations_.emplace(
            std::move(tag), std::move(prepared));
    }
    return transitioned;
}

std::vector<std::string> InterfaceProbe::commit(
    const std::vector<Observation>& observations) {
    std::vector<std::string> transitioned_tags;
    transitioned_tags.reserve(observations.size());

    std::lock_guard<std::mutex> lock(mutex_);
    // Batch publication has one commit point too: every allocation and every
    // sequential duplicate-tag transition is resolved on a private copy.
    // The live map changes only after the full return value is ready.
    auto candidate = published_observations_;
    for (const auto& observation : observations) {
        // Only an attributed success counts as reachable, so losing the
        // ability to attribute a transport is itself a transition: the
        // failover group must stop trusting the previous green.
        const auto previous = candidate.find(observation.target.tag);
        if (previous != candidate.end() &&
            verified_reachable(previous->second->result) !=
                verified_reachable(observation.result)) {
            transitioned_tags.push_back(observation.target.tag);
        }

        auto prepared = std::make_shared<const PublishedObservation>(
            PublishedObservation{
                observation.target,
                observation.result,
            });
        if (previous != candidate.end()) {
            previous->second.swap(prepared);
        } else {
            candidate.emplace(
                observation.target.tag, std::move(prepared));
        }
    }

    static_assert(
        noexcept(published_observations_.swap(candidate)),
        "interface observation batch publication must not throw");
    published_observations_.swap(candidate);

    return transitioned_tags;
}

#ifdef KEEN_PBR3_TESTING
void InterfaceProbe::fail_next_commit_after_prepare_for_testing() {
    std::lock_guard<std::mutex> lock(mutex_);
    fail_next_commit_after_prepare_ = true;
}

void InterfaceProbe::fail_worker_creation_at_for_testing(
    std::size_t worker_index) noexcept {
    if (worker_index >
        static_cast<std::size_t>(
            std::numeric_limits<std::ptrdiff_t>::max())) {
        fail_worker_creation_at_.store(-1, std::memory_order_release);
        return;
    }
    fail_worker_creation_at_.store(
        static_cast<std::ptrdiff_t>(worker_index),
        std::memory_order_release);
}
#endif

std::optional<InterfaceProbeResult> InterfaceProbe::result_for(
    const std::string& tag) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = published_observations_.find(tag);
    if (it == published_observations_.end()) {
        return std::nullopt;
    }
    return it->second->result;
}

std::optional<InterfaceProbeResult> InterfaceProbe::result_for(
    const Target& expected_target) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto observation =
        published_observations_.find(expected_target.tag);
    if (observation == published_observations_.end() ||
        !same_target_identity(
            observation->second->target, expected_target)) {
        return std::nullopt;
    }
    return observation->second->result;
}

void InterfaceProbe::retain_only(const std::vector<Target>& targets) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = published_observations_.begin();
         it != published_observations_.end();) {
        const Target* current = nullptr;
        bool duplicate_tag = false;
        for (const auto& target : targets) {
            if (target.tag != it->first) {
                continue;
            }
            if (current != nullptr) {
                duplicate_tag = true;
                break;
            }
            current = &target;
        }
        if (current == nullptr || duplicate_tag ||
            !same_target_identity(it->second->target, *current)) {
            it = published_observations_.erase(it);
        } else {
            ++it;
        }
    }
}

bool interface_probe_snapshot_is_current(
    std::uint64_t expected_runtime_generation,
    std::uint64_t current_runtime_generation,
    const std::vector<InterfaceProbe::Target>& expected_targets,
    const std::vector<InterfaceProbe::Target>& current_targets) noexcept {
    if (expected_runtime_generation != current_runtime_generation ||
        expected_targets.size() != current_targets.size()) {
        return false;
    }
    for (std::size_t index = 0; index < expected_targets.size(); ++index) {
        if (!same_target_identity(expected_targets[index],
                                  current_targets[index])) {
            return false;
        }
    }
    return true;
}

bool interface_probe_target_is_current(
    std::uint64_t expected_runtime_generation,
    std::uint64_t current_runtime_generation,
    const InterfaceProbe::Target& expected_target,
    const std::vector<InterfaceProbe::Target>& current_targets) noexcept {
    if (expected_runtime_generation != current_runtime_generation) {
        return false;
    }
    const InterfaceProbe::Target* matching_tag = nullptr;
    for (const auto& current : current_targets) {
        if (current.tag != expected_target.tag) {
            continue;
        }
        if (matching_tag != nullptr) {
            return false;
        }
        matching_tag = &current;
    }
    return matching_tag != nullptr &&
           same_target_identity(expected_target, *matching_tag);
}

} // namespace keen_pbr3
