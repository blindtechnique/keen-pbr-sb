#include "interface_probe.hpp"

#include "../log/logger.hpp"

#include <algorithm>

namespace keen_pbr3 {

std::vector<std::string> InterfaceProbe::probe(
    const std::vector<Target>& targets) {
    std::vector<std::string> transitioned_tags;

    for (const auto& target : targets) {
        RetryConfig retry;
        retry.attempts = 2;
        retry.interval_ms = 500;
        const auto result = tester_.test(
            url_, target.fwmark, static_cast<uint32_t>(timeout_.count()), retry);

        InterfaceProbeResult stored;
        stored.success = result.success;
        stored.latency_ms = result.latency_ms;
        stored.error = result.error;
        stored.measured_at = std::chrono::steady_clock::now();

        Logger::instance().trace("interface_probe",
                                 "tag={} fwmark={} success={} latency_ms={} error={}",
                                 target.tag,
                                 target.fwmark,
                                 result.success,
                                 result.latency_ms,
                                 result.error);

        std::lock_guard<std::mutex> lock(mutex_);
        const auto previous = results_.find(target.tag);
        if (previous != results_.end() &&
            previous->second.success != stored.success) {
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
