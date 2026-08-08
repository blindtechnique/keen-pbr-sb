#include "interface_probe.hpp"

#include "../log/logger.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

bool verified_reachable(const InterfaceProbeResult& result) {
    return result.success && result.attributed;
}

} // namespace

std::vector<std::string> InterfaceProbe::probe(
    const std::vector<Target>& targets) {
    return commit(measure(targets));
}

std::vector<InterfaceProbe::Observation> InterfaceProbe::measure(
    const std::vector<Target>& targets) {
    std::vector<Observation> observations;
    observations.reserve(targets.size());

    for (const auto& target : targets) {
        const auto result = tester_.test(
            url_, target.fwmark, static_cast<uint32_t>(timeout_.count()),
            retry_, target.interface);

        InterfaceProbeResult measured;
        measured.success = result.success;
        measured.attributed = !target.interface.empty();
        measured.latency_ms = result.latency_ms;
        measured.error = result.error;
        measured.measured_at = std::chrono::steady_clock::now();

        Logger::instance().trace("interface_probe",
                                 "tag={} fwmark={} interface={} attributed={} success={} latency_ms={} error={}",
                                 target.tag,
                                 target.fwmark,
                                 target.interface.empty() ? std::string("-")
                                                          : target.interface,
                                 measured.attributed,
                                 result.success,
                                 result.latency_ms,
                                 result.error);

        observations.push_back(
            Observation{target, std::move(measured)});
    }

    return observations;
}

std::vector<std::string> InterfaceProbe::commit(
    const std::vector<Observation>& observations) {
    std::vector<std::string> transitioned_tags;

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& observation : observations) {
        const auto& target = observation.target;
        const auto& stored = observation.result;
        const auto previous = results_.find(target.tag);
        // Only an attributed success counts as reachable, so losing the
        // ability to attribute a transport is itself a transition: the
        // failover group must stop trusting the previous green.
        if (previous != results_.end() &&
            verified_reachable(previous->second) != verified_reachable(stored)) {
            transitioned_tags.push_back(target.tag);
        }
        results_[target.tag] = stored;
    }

    return transitioned_tags;
}

std::optional<InterfaceProbeResult> InterfaceProbe::result_for(
    const std::string& tag) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = results_.find(tag);
    if (it == results_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void InterfaceProbe::retain_only(const std::vector<std::string>& tags) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = results_.begin(); it != results_.end();) {
        if (std::find(tags.begin(), tags.end(), it->first) == tags.end()) {
            it = results_.erase(it);
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
        if (expected_targets[index].tag != current_targets[index].tag ||
            expected_targets[index].fwmark != current_targets[index].fwmark ||
            expected_targets[index].interface !=
                current_targets[index].interface) {
            return false;
        }
    }
    return true;
}

} // namespace keen_pbr3
