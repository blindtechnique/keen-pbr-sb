#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_tail_effect_dispatch.hpp"

#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

struct NoexceptStartVisitor {
    void operator()(RuntimeFirewallStartAncillaryEffect) const noexcept {}
};

struct ThrowingMetaVisitor {
    void operator()(
        RuntimeFirewallMetaTailEffect,
        const RuntimeFirewallMetaTailPlan&) const {
        throw std::runtime_error("meta effect failed");
    }
};

struct ThrowingConntrackVisitor {
    void operator()(
        RuntimeFirewallConntrackTailEffect,
        const RuntimeFirewallConntrackTailPlan&) const {
        throw std::runtime_error("conntrack effect failed");
    }
};

struct ThrowingBackgroundSuccessVisitor {
    void operator()(RuntimeFirewallBackgroundSuccessEffect) const {
        throw std::runtime_error("background success effect failed");
    }
};

struct ThrowingBackgroundFailureVisitor {
    void operator()(RuntimeFirewallBackgroundFailureEffect) const {
        throw std::runtime_error("background failure effect failed");
    }
};

static_assert(noexcept(dispatch_runtime_firewall_start_ancillary_effects(
    NoexceptStartVisitor{})));

static_assert(!noexcept(dispatch_runtime_firewall_meta_tail_effects(
    std::declval<const RuntimeFirewallMetaTailPlan&>(),
    ThrowingMetaVisitor{})));
static_assert(!noexcept(dispatch_runtime_firewall_conntrack_tail_effects(
    std::declval<const RuntimeFirewallConntrackTailPlan&>(),
    ThrowingConntrackVisitor{})));
static_assert(!noexcept(
    dispatch_runtime_firewall_background_success_effects(
        ThrowingBackgroundSuccessVisitor{})));
static_assert(!noexcept(
    dispatch_runtime_firewall_background_failure_effects(
        true,
        ThrowingBackgroundFailureVisitor{})));

} // namespace

TEST_CASE("Meta effects preserve incident cleanup and refresh order") {
    MetaUdp443ActivationPlan cleanup;
    RuntimeFirewallMetaTailPlan plan;
    plan.cleanup_source = RuntimeFirewallMetaCleanupSource::candidate;
    plan.cleanup_plan = &cleanup;
    plan.cleanup_attempt = 1U;
    plan.incident_action =
        RuntimeFirewallMetaIncidentAction::degraded;
    plan.incident_detail = "forward hook degraded";
    plan.full_refresh = true;
    plan.refresh_detail = "refresh Meta state";

    std::vector<RuntimeFirewallMetaTailEffect> effects;
    dispatch_runtime_firewall_meta_tail_effects(
        plan,
        [&effects](
            RuntimeFirewallMetaTailEffect effect,
            const RuntimeFirewallMetaTailPlan&) {
            effects.push_back(effect);
        });

    CHECK(effects ==
          std::vector<RuntimeFirewallMetaTailEffect>{
              RuntimeFirewallMetaTailEffect::report_degraded,
              RuntimeFirewallMetaTailEffect::schedule_cleanup,
              RuntimeFirewallMetaTailEffect::schedule_full_refresh});

    plan.incident_action = RuntimeFirewallMetaIncidentAction::reset;
    plan.cleanup_source = RuntimeFirewallMetaCleanupSource::none;
    plan.cleanup_plan = nullptr;
    plan.full_refresh = false;
    effects.clear();
    dispatch_runtime_firewall_meta_tail_effects(
        plan,
        [&effects](
            RuntimeFirewallMetaTailEffect effect,
            const RuntimeFirewallMetaTailPlan&) {
            effects.push_back(effect);
        });
    CHECK(effects ==
          std::vector<RuntimeFirewallMetaTailEffect>{
              RuntimeFirewallMetaTailEffect::reset_incident});
}

TEST_CASE("Meta visitor failure propagates and stops later effects") {
    MetaUdp443ActivationPlan cleanup;
    RuntimeFirewallMetaTailPlan plan;
    plan.cleanup_source = RuntimeFirewallMetaCleanupSource::candidate;
    plan.cleanup_plan = &cleanup;
    plan.incident_action = RuntimeFirewallMetaIncidentAction::degraded;
    plan.full_refresh = true;

    std::vector<RuntimeFirewallMetaTailEffect> effects;
    CHECK_THROWS_AS(
        dispatch_runtime_firewall_meta_tail_effects(
            plan,
            [&effects](
                RuntimeFirewallMetaTailEffect effect,
                const RuntimeFirewallMetaTailPlan&) {
                effects.push_back(effect);
                throw std::runtime_error("stop Meta dispatch");
            }),
        std::runtime_error);
    CHECK(effects ==
          std::vector<RuntimeFirewallMetaTailEffect>{
              RuntimeFirewallMetaTailEffect::report_degraded});
}

TEST_CASE("conntrack effects report before scheduling retry") {
    OwnedConntrackCleanupSnapshot snapshot;
    RuntimeFirewallConntrackTailPlan plan;
    plan.native_source_cleanup_failed = true;
    plan.native_source_cleanup_failure_detail = "source cleanup failed";
    plan.cleanup_retry_snapshot = &snapshot;

    std::vector<RuntimeFirewallConntrackTailEffect> effects;
    dispatch_runtime_firewall_conntrack_tail_effects(
        plan,
        [&effects](
            RuntimeFirewallConntrackTailEffect effect,
            const RuntimeFirewallConntrackTailPlan&) {
            effects.push_back(effect);
        });

    CHECK(effects ==
          std::vector<RuntimeFirewallConntrackTailEffect>{
              RuntimeFirewallConntrackTailEffect::report_failure,
              RuntimeFirewallConntrackTailEffect::schedule_retry});
}

TEST_CASE("conntrack visitor failure propagates and stops retry") {
    OwnedConntrackCleanupSnapshot snapshot;
    RuntimeFirewallConntrackTailPlan plan;
    plan.native_source_cleanup_failed = true;
    plan.cleanup_retry_snapshot = &snapshot;

    std::vector<RuntimeFirewallConntrackTailEffect> effects;
    CHECK_THROWS_AS(
        dispatch_runtime_firewall_conntrack_tail_effects(
            plan,
            [&effects](
                RuntimeFirewallConntrackTailEffect effect,
                const RuntimeFirewallConntrackTailPlan&) {
                effects.push_back(effect);
                throw std::runtime_error("stop conntrack dispatch");
            }),
        std::runtime_error);
    CHECK(effects ==
          std::vector<RuntimeFirewallConntrackTailEffect>{
              RuntimeFirewallConntrackTailEffect::report_failure});
}

TEST_CASE("START ancillary effects keep their exact order") {
    std::vector<RuntimeFirewallStartAncillaryEffect> effects;
    dispatch_runtime_firewall_start_ancillary_effects(
        [&effects](RuntimeFirewallStartAncillaryEffect effect) {
            effects.push_back(effect);
        });

    CHECK(effects ==
          std::vector<RuntimeFirewallStartAncillaryEffect>{
              RuntimeFirewallStartAncillaryEffect::reset_idle_observer,
              RuntimeFirewallStartAncillaryEffect::schedule_snat_health,
              RuntimeFirewallStartAncillaryEffect::
                  schedule_internal_vpn_catalog,
              RuntimeFirewallStartAncillaryEffect::
                  clear_runtime_firewall_incident,
              RuntimeFirewallStartAncillaryEffect::reconcile_remote_access,
              RuntimeFirewallStartAncillaryEffect::
                  schedule_keenetic_dns_refresh,
              RuntimeFirewallStartAncillaryEffect::refresh_resolver_hash,
              RuntimeFirewallStartAncillaryEffect::log_runtime_started,
              RuntimeFirewallStartAncillaryEffect::
                  reconcile_post_success_conntrack});
}

TEST_CASE("each START ancillary failure is isolated from later effects") {
    constexpr std::size_t effect_count = 9U;
    for (std::size_t failing_index = 0U;
         failing_index < effect_count;
         ++failing_index) {
        std::vector<RuntimeFirewallStartAncillaryEffect> effects;
        std::size_t index = 0U;
        dispatch_runtime_firewall_start_ancillary_effects(
            [&effects, &index, failing_index](
                RuntimeFirewallStartAncillaryEffect effect) {
                effects.push_back(effect);
                if (index++ == failing_index) {
                    throw std::runtime_error("isolated START effect failure");
                }
            });
        CHECK(effects.size() == effect_count);
    }
}

TEST_CASE("background success effects preserve exact order") {
    std::vector<RuntimeFirewallBackgroundSuccessEffect> effects;
    dispatch_runtime_firewall_background_success_effects(
        [&effects](RuntimeFirewallBackgroundSuccessEffect effect) {
            effects.push_back(effect);
        });

    CHECK(effects ==
          std::vector<RuntimeFirewallBackgroundSuccessEffect>{
              RuntimeFirewallBackgroundSuccessEffect::
                  release_urltest_recovery,
              RuntimeFirewallBackgroundSuccessEffect::
                  release_resolver_and_maybe_retry,
              RuntimeFirewallBackgroundSuccessEffect::
                  clear_runtime_firewall_incident,
              RuntimeFirewallBackgroundSuccessEffect::
                  reconcile_remote_access,
              RuntimeFirewallBackgroundSuccessEffect::publish_runtime_state,
              RuntimeFirewallBackgroundSuccessEffect::
                  log_refresh_complete});
}

TEST_CASE("background success failure stops dispatch and propagates") {
    constexpr std::size_t effect_count = 6U;
    for (std::size_t failing_index = 0U;
         failing_index < effect_count;
         ++failing_index) {
        std::vector<RuntimeFirewallBackgroundSuccessEffect> effects;
        std::size_t index = 0U;
        CHECK_THROWS_AS(
            dispatch_runtime_firewall_background_success_effects(
                [&effects, &index, failing_index](
                    RuntimeFirewallBackgroundSuccessEffect effect) {
                    effects.push_back(effect);
                    if (index++ == failing_index) {
                        throw std::runtime_error(
                            "background success effect failed");
                    }
                }),
            std::runtime_error);
        CHECK(effects.size() == failing_index + 1U);
    }
}

TEST_CASE("background failure publishes before incident and refresh") {
    std::vector<RuntimeFirewallBackgroundFailureEffect> effects;
    dispatch_runtime_firewall_background_failure_effects(
        true,
        [&effects](RuntimeFirewallBackgroundFailureEffect effect) {
            effects.push_back(effect);
        });
    CHECK(effects ==
          std::vector<RuntimeFirewallBackgroundFailureEffect>{
              RuntimeFirewallBackgroundFailureEffect::
                  publish_runtime_pairing_best_effort,
              RuntimeFirewallBackgroundFailureEffect::
                  record_and_log_incident,
              RuntimeFirewallBackgroundFailureEffect::
                  schedule_ambiguous_refresh});

    effects.clear();
    dispatch_runtime_firewall_background_failure_effects(
        false,
        [&effects](RuntimeFirewallBackgroundFailureEffect effect) {
            effects.push_back(effect);
        });
    CHECK(effects ==
          std::vector<RuntimeFirewallBackgroundFailureEffect>{
              RuntimeFirewallBackgroundFailureEffect::
                  publish_runtime_pairing_best_effort,
              RuntimeFirewallBackgroundFailureEffect::
                  record_and_log_incident});
}

TEST_CASE("background failure visitor exception propagates without blanket catch") {
    std::vector<RuntimeFirewallBackgroundFailureEffect> effects;
    CHECK_THROWS_AS(
        dispatch_runtime_firewall_background_failure_effects(
            true,
            [&effects](RuntimeFirewallBackgroundFailureEffect effect) {
                effects.push_back(effect);
                throw std::runtime_error(
                    "background failure effect failed");
            }),
        std::runtime_error);
    CHECK(effects ==
          std::vector<RuntimeFirewallBackgroundFailureEffect>{
              RuntimeFirewallBackgroundFailureEffect::
                  publish_runtime_pairing_best_effort});
}

} // namespace keen_pbr3
