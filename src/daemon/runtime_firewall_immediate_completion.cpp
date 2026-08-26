#include "runtime_firewall_immediate_completion.hpp"

#include <string>
#include <utility>

namespace keen_pbr3 {

RuntimeFirewallImmediateCompletionIntent::
    RuntimeFirewallImmediateCompletionIntent(
        RuntimeFirewallImmediateCompletionSpec spec,
        std::optional<PeriodicTaskRunToken> metric) noexcept
    : spec_(spec),
      metric_(std::move(metric)),
      consumed_(spec.kind == RuntimeFirewallImmediateIntentKind::none) {}

RuntimeFirewallImmediateCompletionIntent
RuntimeFirewallImmediateCompletionIntent::periodic_urltest(
    PeriodicTaskRunToken metric) noexcept {
    return RuntimeFirewallImmediateCompletionIntent{
        RuntimeFirewallImmediateCompletionSpec{
            RuntimeFirewallImmediateIntentKind::periodic_urltest_recovery,
            false,
            false},
        std::optional<PeriodicTaskRunToken>{std::move(metric)}};
}

RuntimeFirewallImmediateCompletionIntent
RuntimeFirewallImmediateCompletionIntent::periodic_owned_firewall(
    PeriodicTaskRunToken metric) noexcept {
    return RuntimeFirewallImmediateCompletionIntent{
        RuntimeFirewallImmediateCompletionSpec{
            RuntimeFirewallImmediateIntentKind::
                periodic_owned_firewall_repair,
            false,
            false},
        std::optional<PeriodicTaskRunToken>{std::move(metric)}};
}

RuntimeFirewallImmediateCompletionIntent
RuntimeFirewallImmediateCompletionIntent::netfilter(
    bool full_refresh,
    bool targeted_recovery_pending_before_refresh) noexcept {
    return RuntimeFirewallImmediateCompletionIntent{
        RuntimeFirewallImmediateCompletionSpec{
            RuntimeFirewallImmediateIntentKind::netfilter_refresh,
            full_refresh,
            targeted_recovery_pending_before_refresh},
        std::nullopt};
}

RuntimeFirewallImmediateCompletionIntent::SettleResult
RuntimeFirewallImmediateCompletionIntent::settle(
    RuntimeFirewallImmediateTerminalOutcome outcome) noexcept {
    if (consumed_) {
        return {SettleStatus::already_consumed, false};
    }

    const auto plan =
        plan_runtime_firewall_immediate_completion(spec_, outcome);
    if (plan.metric != RuntimeFirewallImmediateMetricAction::none) {
        if (!metric_.has_value()) {
            return {SettleStatus::retry, false};
        }
        bool finished = false;
        try {
            switch (plan.metric) {
            case RuntimeFirewallImmediateMetricAction::success:
                finished = metric_->success();
                break;
            case RuntimeFirewallImmediateMetricAction::failure:
                finished = metric_->failure(
                    std::string{plan.metric_detail});
                break;
            case RuntimeFirewallImmediateMetricAction::abandon:
                finished = metric_->abandon(
                    std::string{plan.metric_detail});
                break;
            case RuntimeFirewallImmediateMetricAction::none:
                break;
            }
        } catch (...) {
            return {SettleStatus::retry, false};
        }
        if (!finished) {
            return {SettleStatus::retry, false};
        }
        metric_.reset();
    }

    consumed_ = true;
    return {
        SettleStatus::consumed,
        plan.claim_broad_urltest_probe};
}

bool RuntimeFirewallImmediateCompletionIntent::pending() const noexcept {
    return !consumed_;
}

const RuntimeFirewallImmediateCompletionSpec&
RuntimeFirewallImmediateCompletionIntent::spec() const noexcept {
    return spec_;
}

} // namespace keen_pbr3
