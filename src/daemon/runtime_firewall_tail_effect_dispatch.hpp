#pragma once

#include "runtime_firewall_conntrack_tail_plan.hpp"
#include "runtime_firewall_meta_tail_plan.hpp"

#include <cstdint>

namespace keen_pbr3 {

// Stateless, synchronous dispatch only. The caller remains the sole owner of
// every scheduler, incident latch, generation fence and recovery operation.
enum class RuntimeFirewallMetaTailEffect : std::uint8_t {
    reset_incident,
    report_degraded,
    schedule_cleanup,
    schedule_full_refresh,
};

template <typename Visit>
void dispatch_runtime_firewall_meta_tail_effects(
    const RuntimeFirewallMetaTailPlan& plan,
    Visit&& visit) {
    if (plan.incident_action ==
        RuntimeFirewallMetaIncidentAction::reset) {
        visit(RuntimeFirewallMetaTailEffect::reset_incident, plan);
    } else if (plan.incident_action ==
               RuntimeFirewallMetaIncidentAction::degraded) {
        visit(RuntimeFirewallMetaTailEffect::report_degraded, plan);
    }

    if (plan.schedule_cleanup()) {
        visit(RuntimeFirewallMetaTailEffect::schedule_cleanup, plan);
    }
    if (plan.full_refresh) {
        visit(RuntimeFirewallMetaTailEffect::schedule_full_refresh, plan);
    }
}

enum class RuntimeFirewallConntrackTailEffect : std::uint8_t {
    report_failure,
    schedule_retry,
};

template <typename Visit>
void dispatch_runtime_firewall_conntrack_tail_effects(
    const RuntimeFirewallConntrackTailPlan& plan,
    Visit&& visit) {
    if (plan.report_native_source_cleanup_failure()) {
        visit(RuntimeFirewallConntrackTailEffect::report_failure, plan);
    }
    if (plan.schedule_owned_cleanup_retry()) {
        visit(RuntimeFirewallConntrackTailEffect::schedule_retry, plan);
    }
}

// Ordinary START ancillary effects are deliberately independent. This is the
// existing post-publication contract: one notifier, logger or scheduler
// failure must not suppress later ancillary effects or strand the terminal.
enum class RuntimeFirewallStartAncillaryEffect : std::uint8_t {
    reset_idle_observer,
    schedule_snat_health,
    schedule_internal_vpn_catalog,
    clear_runtime_firewall_incident,
    reconcile_remote_access,
    schedule_keenetic_dns_refresh,
    refresh_resolver_hash,
    log_runtime_started,
    reconcile_post_success_conntrack,
};

template <typename Visit>
void dispatch_runtime_firewall_start_ancillary_effects(
    Visit&& visit) noexcept {
    const auto invoke = [&visit](
                            RuntimeFirewallStartAncillaryEffect effect)
                            noexcept {
        try {
            visit(effect);
        } catch (...) {
        }
    };

    invoke(RuntimeFirewallStartAncillaryEffect::reset_idle_observer);
    invoke(RuntimeFirewallStartAncillaryEffect::schedule_snat_health);
    invoke(RuntimeFirewallStartAncillaryEffect::
               schedule_internal_vpn_catalog);
    invoke(RuntimeFirewallStartAncillaryEffect::
               clear_runtime_firewall_incident);
    invoke(RuntimeFirewallStartAncillaryEffect::reconcile_remote_access);
    invoke(RuntimeFirewallStartAncillaryEffect::
               schedule_keenetic_dns_refresh);
    invoke(RuntimeFirewallStartAncillaryEffect::refresh_resolver_hash);
    invoke(RuntimeFirewallStartAncillaryEffect::log_runtime_started);
    invoke(RuntimeFirewallStartAncillaryEffect::
               reconcile_post_success_conntrack);
}

// Background success intentionally has no per-effect catch. If an effect
// throws, the caller must leave tail progress unfinished and may replay the
// preceding idempotent effects on the next drain.
enum class RuntimeFirewallBackgroundSuccessEffect : std::uint8_t {
    release_urltest_recovery,
    release_resolver_and_maybe_retry,
    clear_runtime_firewall_incident,
    reconcile_remote_access,
    publish_runtime_state,
    log_refresh_complete,
};

template <typename Visit>
void dispatch_runtime_firewall_background_success_effects(Visit&& visit) {
    visit(RuntimeFirewallBackgroundSuccessEffect::
              release_urltest_recovery);
    visit(RuntimeFirewallBackgroundSuccessEffect::
              release_resolver_and_maybe_retry);
    visit(RuntimeFirewallBackgroundSuccessEffect::
              clear_runtime_firewall_incident);
    visit(RuntimeFirewallBackgroundSuccessEffect::reconcile_remote_access);
    visit(RuntimeFirewallBackgroundSuccessEffect::publish_runtime_state);
    visit(RuntimeFirewallBackgroundSuccessEffect::log_refresh_complete);
}

// The first failure callback retains the caller's existing best-effort
// publish-and-warn body. The dispatcher itself adds no catch: incident
// recording remains after publication, and an unexpected later exception
// leaves progress unfinished exactly as before.
enum class RuntimeFirewallBackgroundFailureEffect : std::uint8_t {
    publish_runtime_pairing_best_effort,
    record_and_log_incident,
    schedule_ambiguous_refresh,
};

template <typename Visit>
void dispatch_runtime_firewall_background_failure_effects(
    bool commit_ambiguous,
    Visit&& visit) {
    visit(RuntimeFirewallBackgroundFailureEffect::
              publish_runtime_pairing_best_effort);
    visit(RuntimeFirewallBackgroundFailureEffect::record_and_log_incident);
    if (commit_ambiguous) {
        visit(RuntimeFirewallBackgroundFailureEffect::
                  schedule_ambiguous_refresh);
    }
}

} // namespace keen_pbr3
