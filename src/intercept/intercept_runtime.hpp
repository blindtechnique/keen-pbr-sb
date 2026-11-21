#pragma once

#include "../firewall/interception.hpp"
#include "intercept_service.hpp"
#include <functional>

namespace keen_pbr3 {
class InterceptCleanupChannel;

// No scheduler, VPN health, conntrack deletion, or autonomous restart loop.
// Invoked solely by an already admitted firewall transaction and explicit STOP.
class InterceptRuntime final : public FirewallInterceptionRuntime {
public:
    using Factory = std::function<std::unique_ptr<InterceptService>()>;
    using Starter = std::function<void(InterceptService&, const InterceptServiceOptions&)>;
    explicit InterceptRuntime(Factory factory, Starter starter = {},
                              std::shared_ptr<InterceptCleanupChannel> cleanup = {})
        : factory_(std::move(factory)), starter_(std::move(starter)), cleanup_(std::move(cleanup)) {}
    ~InterceptRuntime() override;
    std::shared_ptr<FirewallInterceptionUpdate> begin_update() override;
    void stop() noexcept override;
    InterceptionHealth health() const override;

private:
    class Update;
    Factory factory_;
    Starter starter_;
    std::shared_ptr<InterceptCleanupChannel> cleanup_;
    std::shared_ptr<InterceptService> service_;
    uint64_t generation_{0};
    bool explicitly_stopped_{true};
    bool listening_dns_{false}, listening_l7_{false};
    struct Published {
        InterceptionHealth health;
        std::shared_ptr<InterceptService> service;
    };
    // A reader never inspects the mutable owner/service start-time probes.
    // Only this immutable publication and service atomics cross threads.
    std::shared_ptr<const Published> published_;
    void publish(const InterceptionHealth& health) noexcept;
};

std::shared_ptr<FirewallInterceptionRuntime> make_intercept_runtime(
    bool nftables, std::shared_ptr<InterceptCleanupChannel> cleanup = {});

} // namespace keen_pbr3
