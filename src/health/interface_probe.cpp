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
    std::vector<std::string> transitioned_tags;

    for (const auto& target : targets) {
        const auto result = tester_.test(
            url_, target.fwmark, static_cast<uint32_t>(timeout_.count()),
            retry_, target.interface);

        InterfaceProbeResult stored;
        stored.success = result.success;
        stored.attributed = !target.interface.empty();
        stored.latency_ms = result.latency_ms;
        stored.error = result.error;
        stored.measured_at = std::chrono::steady_clock::now();

        Logger::instance().trace("interface_probe",
                                 "tag={} fwmark={} interface={} attributed={} success={} latency_ms={} error={}",
                                 target.tag,
                                 target.fwmark,
                                 target.interface.empty() ? std::string("-")
                                                          : target.interface,
                                 stored.attributed,
                                 result.success,
                                 result.latency_ms,
                                 result.error);

        std::lock_guard<std::mutex> lock(mutex_);
        const auto previous = results_.find(target.tag);
        // Only an attributed success counts as reachable, so losing the
        // ability to attribute a transport is itself a transition: the
        // failover group must stop trusting the previous green.
        if (previous != results_.end() &&
            verified_reachable(previous->second) != verified_reachable(stored)) {
            transitioned_tags.push_back(target.tag);
        }
        results_[target.tag] = std::move(stored);
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

} // namespace keen_pbr3
