#include "runtime_firewall_backend_transaction.hpp"

#include <exception>
#include <utility>

namespace keen_pbr3 {
namespace {

bool is_meta_preflight_phase(
    RuntimeFirewallBackendTransactionPhase phase) noexcept {
    return phase == RuntimeFirewallBackendTransactionPhase::
                        initial_meta_preflight ||
           phase == RuntimeFirewallBackendTransactionPhase::
                        fallback_meta_preflight;
}

void record_failure(
    RuntimeFirewallBackendTransactionResult& result,
    RuntimeFirewallBackendTransactionPhase phase,
    RuntimeFirewallBackendFailureKind kind,
    const std::string& message,
    bool external_repair = false) {
    if (is_meta_preflight_phase(phase)) {
        kind = RuntimeFirewallBackendFailureKind::meta_preflight;
    }
    result.failure = RuntimeFirewallBackendFailure{
        phase, kind, message, external_repair};
}

} // namespace

RuntimeFirewallBackendTransactionResult
execute_runtime_firewall_backend_transaction(
    const RuntimeFirewallBackendTransactionInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services) {
    RuntimeFirewallBackendTransactionResult result;
    result.operation_serial = input.operation_serial;
    result.runtime_generation = input.runtime_generation;

    FirewallApplyMode effective_mode = input.requested_mode;
    if (effective_mode == FirewallApplyMode::RulesOnly &&
        (input.previous_list_fingerprints.empty() ||
         input.requested_list_fingerprints !=
             input.previous_list_fingerprints)) {
        // This is ordinary generation drift, not a backend refusal: stream
        // the pinned generation without manufacturing a fallback warning.
        effective_mode = FirewallApplyMode::PreserveSets;
    }

    auto phase = RuntimeFirewallBackendTransactionPhase::initial_stage;
    const auto stage_with = [&](FirewallApplyMode mode) {
        PreviousRuntimeFirewall previous;
        if (mode == FirewallApplyMode::RulesOnly) {
            previous.rule_states = &input.previous_rules;
            previous.list_usage = &input.previous_list_usage;
            previous.list_content_state =
                &input.previous_list_content_state;
        }
        return stage_runtime_firewall_from_snapshot(
            input.config,
            input.outbound_marks,
            input.urltest_selections,
            input.list_max_file_size_bytes,
            input.list_cache_snapshot,
            firewall,
            mode,
            &input.effective_internal_vpn_servers,
            &input.effective_internal_vpn_targets,
            &input.candidate_native_vpn_direct_egress_snat_selectors,
            input.udp_call_affinity_ipset_available,
            input.keenetic_dns_snapshot,
            input.force_clear_dynamic_sets,
            previous);
    };
    const auto meta_preflight = [
        &input, &meta_services, &phase](
        const StagedRuntimeFirewall& staged,
        RuntimeFirewallBackendTransactionPhase preflight_phase) {
        phase = preflight_phase;
        MetaUdp443ActivationInput meta_input;
        meta_input.config = input.config;
        meta_input.candidate_rules = staged.rule_states;
        meta_input.candidate_list_content_state =
            staged.list_content_state;
        meta_input.forwarded_scope_allows_unmarked_cleanup =
            input.forwarded_scope_allows_unmarked_cleanup;
        meta_input.committed_fwmark =
            input.committed_meta_udp443_fwmark;
        meta_input.committed_owned_mask =
            input.committed_meta_udp443_owned_mask;
        return prepare_meta_udp443_activation_or_throw(
            meta_input, meta_services);
    };

    try {
        StagedRuntimeFirewall staged;
        try {
            staged = stage_with(effective_mode);
        } catch (const FirewallRulesOnlyError& error) {
            if (effective_mode != FirewallApplyMode::RulesOnly) {
                throw;
            }
            result.rules_only_fallback = RuntimeFirewallRulesOnlyFallback{
                RuntimeFirewallBackendTransactionPhase::initial_stage,
                error.what(),
                error.external_repair()};
            phase = RuntimeFirewallBackendTransactionPhase::fallback_stage;
            staged = stage_with(FirewallApplyMode::PreserveSets);
            result.meta_activation_plan = meta_preflight(
                staged,
                RuntimeFirewallBackendTransactionPhase::
                    fallback_meta_preflight);
        }

        if (result.rules_only_fallback.has_value()) {
            // A staging refusal already consumed the one permitted fallback.
            // Passing no callback makes any later refusal terminal.
            phase = RuntimeFirewallBackendTransactionPhase::fallback_commit;
            result.commit_entered = true;
            staged = commit_runtime_firewall_with_rules_only_fallback(
                firewall, std::move(staged), {});
            result.commit_returned = true;
        } else {
            result.meta_activation_plan = meta_preflight(
                staged,
                RuntimeFirewallBackendTransactionPhase::
                    initial_meta_preflight);
            phase = RuntimeFirewallBackendTransactionPhase::initial_commit;
            result.commit_entered = true;
            staged = commit_runtime_firewall_with_rules_only_fallback(
                firewall,
                std::move(staged),
                [&](const FirewallRulesOnlyError& error) {
                    result.rules_only_fallback =
                        RuntimeFirewallRulesOnlyFallback{
                            RuntimeFirewallBackendTransactionPhase::
                                initial_commit,
                            error.what(),
                            error.external_repair()};
                    phase =
                        RuntimeFirewallBackendTransactionPhase::fallback_stage;
                    result.meta_activation_plan.reset();
                    auto fallback =
                        stage_with(FirewallApplyMode::PreserveSets);
                    result.meta_activation_plan = meta_preflight(
                        fallback,
                        RuntimeFirewallBackendTransactionPhase::
                            fallback_meta_preflight);
                    // The commit helper performs the fallback commit after the
                    // callback returns. Set the phase before returning so a
                    // backend exception is classified at the exact boundary.
                    phase = RuntimeFirewallBackendTransactionPhase::
                        fallback_commit;
                    return fallback;
                });
            result.commit_returned = true;
        }

        result.committed_firewall = std::move(staged);
        return result;
    } catch (const FirewallRulesOnlyError& error) {
        record_failure(
            result,
            phase,
            RuntimeFirewallBackendFailureKind::rules_only_refusal,
            error.what(),
            error.external_repair());
    } catch (const TransientFirewallError& error) {
        record_failure(
            result,
            phase,
            RuntimeFirewallBackendFailureKind::transient_firewall,
            error.what());
    } catch (const FirewallError& error) {
        record_failure(
            result,
            phase,
            RuntimeFirewallBackendFailureKind::firewall,
            error.what());
    } catch (const std::exception& error) {
        record_failure(
            result,
            phase,
            RuntimeFirewallBackendFailureKind::unexpected_exception,
            error.what());
    } catch (...) {
        record_failure(
            result,
            phase,
            RuntimeFirewallBackendFailureKind::unknown_exception,
            "non-standard exception");
    }
    return result;
}

RuntimeFirewallBackendTransactionResult
execute_runtime_firewall_backend_transaction(
    const RuntimeFirewallBackendTransactionInput& input,
    Firewall& firewall,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink) {
    SystemMetaUdp443ActivationBackendServices meta_services{
        conntrack_manager, netlink};
    return execute_runtime_firewall_backend_transaction(
        input, firewall, meta_services);
}

} // namespace keen_pbr3
