#pragma once

#include "../runtime/periodic_task_metrics.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <type_traits>

namespace keen_pbr3 {

enum class RuntimeFirewallImmediateIntentKind : std::uint8_t {
    none,
    periodic_urltest_recovery,
    periodic_owned_firewall_repair,
    netfilter_refresh,
};

enum class RuntimeFirewallImmediateTerminalOutcome : std::uint8_t {
    verified_success,
    not_verified,
    shutdown,
};

enum class RuntimeFirewallImmediateMetricAction : std::uint8_t {
    none,
    success,
    failure,
    abandon,
};

struct RuntimeFirewallImmediateCompletionSpec final {
    RuntimeFirewallImmediateIntentKind kind{
        RuntimeFirewallImmediateIntentKind::none};
    bool full_refresh{false};
    bool targeted_recovery_pending_before_refresh{false};
};

struct RuntimeFirewallImmediateCompletionPlan final {
    RuntimeFirewallImmediateMetricAction metric{
        RuntimeFirewallImmediateMetricAction::none};
    std::string_view metric_detail;
    bool claim_broad_urltest_probe{false};
};

constexpr RuntimeFirewallImmediateCompletionPlan
plan_runtime_firewall_immediate_completion(
    const RuntimeFirewallImmediateCompletionSpec& spec,
    RuntimeFirewallImmediateTerminalOutcome outcome) noexcept {
    const bool periodic_urltest =
        spec.kind ==
        RuntimeFirewallImmediateIntentKind::periodic_urltest_recovery;
    const bool periodic_owned =
        spec.kind ==
        RuntimeFirewallImmediateIntentKind::periodic_owned_firewall_repair;
    if (periodic_urltest || periodic_owned) {
        if (outcome ==
            RuntimeFirewallImmediateTerminalOutcome::verified_success) {
            return {
                RuntimeFirewallImmediateMetricAction::success,
                {},
                false};
        }
        if (outcome == RuntimeFirewallImmediateTerminalOutcome::shutdown) {
            return {
                RuntimeFirewallImmediateMetricAction::abandon,
                "runtime firewall shutdown",
                false};
        }
        return {
            RuntimeFirewallImmediateMetricAction::failure,
            periodic_urltest
                ? std::string_view{
                      "URLTEST firewall recovery did not converge"}
                : std::string_view{
                      "owned SNAT repair did not converge"},
            false};
    }

    const bool claim_broad_probe =
        spec.kind ==
            RuntimeFirewallImmediateIntentKind::netfilter_refresh &&
        outcome ==
            RuntimeFirewallImmediateTerminalOutcome::verified_success &&
        spec.full_refresh &&
        !spec.targeted_recovery_pending_before_refresh;
    return {
        RuntimeFirewallImmediateMetricAction::none,
        {},
        claim_broad_probe};
}

class RuntimeFirewallImmediateCompletionIntent final {
public:
    enum class SettleStatus : std::uint8_t {
        consumed,
        already_consumed,
        retry,
    };

    struct SettleResult final {
        SettleStatus status{SettleStatus::already_consumed};
        bool broad_urltest_probe_claimed{false};
    };

    RuntimeFirewallImmediateCompletionIntent() noexcept = default;
    ~RuntimeFirewallImmediateCompletionIntent() = default;

    RuntimeFirewallImmediateCompletionIntent(
        RuntimeFirewallImmediateCompletionIntent&&) noexcept = default;
    RuntimeFirewallImmediateCompletionIntent& operator=(
        RuntimeFirewallImmediateCompletionIntent&&) noexcept = default;

    RuntimeFirewallImmediateCompletionIntent(
        const RuntimeFirewallImmediateCompletionIntent&) = delete;
    RuntimeFirewallImmediateCompletionIntent& operator=(
        const RuntimeFirewallImmediateCompletionIntent&) = delete;

    static RuntimeFirewallImmediateCompletionIntent periodic_urltest(
        PeriodicTaskRunToken metric) noexcept;
    static RuntimeFirewallImmediateCompletionIntent
    periodic_owned_firewall(PeriodicTaskRunToken metric) noexcept;
    static RuntimeFirewallImmediateCompletionIntent netfilter(
        bool full_refresh,
        bool targeted_recovery_pending_before_refresh) noexcept;

    SettleResult settle(
        RuntimeFirewallImmediateTerminalOutcome outcome) noexcept;
    bool pending() const noexcept;
    const RuntimeFirewallImmediateCompletionSpec& spec() const noexcept;

private:
    RuntimeFirewallImmediateCompletionIntent(
        RuntimeFirewallImmediateCompletionSpec spec,
        std::optional<PeriodicTaskRunToken> metric) noexcept;

    RuntimeFirewallImmediateCompletionSpec spec_;
    std::optional<PeriodicTaskRunToken> metric_;
    bool consumed_{true};
};

static_assert(
    !std::is_copy_constructible_v<
        RuntimeFirewallImmediateCompletionIntent>);
static_assert(
    std::is_nothrow_move_constructible_v<
        RuntimeFirewallImmediateCompletionIntent>);
static_assert(
    std::is_nothrow_move_assignable_v<
        RuntimeFirewallImmediateCompletionIntent>);

} // namespace keen_pbr3
