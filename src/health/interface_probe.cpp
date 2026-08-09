#include "interface_probe.hpp"

#include "../log/logger.hpp"

#include <algorithm>
#include <new>

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
    for (const auto& target : targets) {
        if (!observation_sink(measure_one(target))) {
            return false;
        }
    }
    return true;
}

bool InterfaceProbe::commit_observation(
    const Observation& observation) {
    // Prepare every allocation-bearing field before taking publication
    // authority. An allocation failure here leaves the previous exact
    // identity/result pair untouched.
    PublishedObservation prepared{
        observation.target,
        observation.result,
    };
    std::string tag = observation.target.tag;

    std::lock_guard<std::mutex> lock(mutex_);
    const auto previous = published_observations_.find(tag);
    const bool transitioned =
        previous != published_observations_.end() &&
        verified_reachable(previous->second.result) !=
            verified_reachable(observation.result);

#ifdef KEEN_PBR3_TESTING
    if (fail_next_commit_after_prepare_) {
        fail_next_commit_after_prepare_ = false;
        throw std::bad_alloc{};
    }
#endif

    if (previous != published_observations_.end()) {
        // PublishedObservation is statically nothrow-swappable, so readers
        // can observe only the complete old pair or the complete new pair.
        using std::swap;
        swap(previous->second, prepared);
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
            verified_reachable(previous->second.result) !=
                verified_reachable(observation.result)) {
            transitioned_tags.push_back(observation.target.tag);
        }

        PublishedObservation prepared{
            observation.target,
            observation.result,
        };
        if (previous != candidate.end()) {
            using std::swap;
            swap(previous->second, prepared);
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
#endif

std::optional<InterfaceProbeResult> InterfaceProbe::result_for(
    const std::string& tag) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = published_observations_.find(tag);
    if (it == published_observations_.end()) {
        return std::nullopt;
    }
    return it->second.result;
}

std::optional<InterfaceProbeResult> InterfaceProbe::result_for(
    const Target& expected_target) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto observation =
        published_observations_.find(expected_target.tag);
    if (observation == published_observations_.end() ||
        !same_target_identity(
            observation->second.target, expected_target)) {
        return std::nullopt;
    }
    return observation->second.result;
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
            !same_target_identity(it->second.target, *current)) {
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
