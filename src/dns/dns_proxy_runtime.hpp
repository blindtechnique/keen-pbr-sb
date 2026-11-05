#pragma once

#include "dns_balancer.hpp"
#include "dns_router.hpp"
#include <algorithm>
#include <mutex>
#include <stdexcept>

namespace keen_pbr3 {

// Serialized with resolver publication. A failing hook or listener restores the
// previous forwarder; DNS errors never change VPN health or restart a service.
class DnsProxyRuntime {
public:
    explicit DnsProxyRuntime(DnsBalancerOptions options = {}) : proxy_(std::move(options)) {}

    std::shared_ptr<const DnsServerRegistry> prepare_registry(const DnsConfig& config,
        const std::optional<KeeneticDnsSnapshot>& keenetic = std::nullopt) {
        return std::make_shared<const DnsServerRegistry>(config, keenetic,
            [this](std::size_t index) { return ports_.reserve(index); });
    }

    template<class Hook>
    int apply(const std::vector<DnsBalancerGroup>& groups,
              const DnsBalancerSettings& settings, Hook&& hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto previous_groups = groups_;
        const auto previous_settings = settings_;
        const bool changed = groups != groups_ || !(settings == settings_);
        try {
            if (changed && !groups.empty()) replace(groups, settings);
            const int result = hook();
            if (result != 0) {
                if (changed) replace(previous_groups, previous_settings);
                release_retired(groups, previous_groups);
                return result;
            }
            // First remove references from dnsmasq, then close unused listeners.
            if (changed && groups.empty()) replace(groups, settings);
            release_retired(previous_groups, groups);
            return 0;
        } catch (...) {
            if (changed) replace(previous_groups, previous_settings);
            release_retired(groups, previous_groups);
            throw;
        }
    }

    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        proxy_.stop();
        ports_.release_all();
        groups_.clear();
        settings_ = {};
    }

    template<class Hook>
    int deactivate(Hook&& hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            const int result = hook();
            replace({}, {});
            ports_.release_all();
            return result;
        } catch (...) { replace({}, {}); ports_.release_all(); throw; }
    }

private:
    static void release_retired(const std::vector<DnsBalancerGroup>& old_groups,
                                const std::vector<DnsBalancerGroup>& kept) {
        for (const auto& old : old_groups) {
            if (old.binding && std::none_of(kept.begin(), kept.end(),
                    [&](const auto& g) { return g.binding == old.binding; })) {
                old.binding->release();
            }
        }
    }
    void replace(const std::vector<DnsBalancerGroup>& groups, const DnsBalancerSettings& settings) {
        // Retire cached endpoint addresses and connection marks on configuration
        // changes, instead of retaining another generation's bootstrap results.
        proxy_.stop();
        if (!groups.empty() && !proxy_.configure(groups, settings).empty())
            throw std::runtime_error("Cannot bind the local DNS forwarder listener");
        groups_ = groups;
        settings_ = settings;
    }
    std::mutex mutex_;
    DnsProxyPorts ports_;
    DnsBalancer proxy_;
    std::vector<DnsBalancerGroup> groups_;
    DnsBalancerSettings settings_;
};

} // namespace keen_pbr3
