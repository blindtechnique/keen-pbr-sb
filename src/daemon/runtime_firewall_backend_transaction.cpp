#include "runtime_firewall_backend_transaction.hpp"

#include <exception>
#include <utility>

namespace keen_pbr3 {
namespace {

void record_failure(
    RuntimeFirewallBackendTransactionResult& result,
    RuntimeFirewallBackendTransactionPhase phase,
    RuntimeFirewallBackendFailureKind kind,
    const std::string& message,
    bool external_repair = false) {
    result.failure = RuntimeFirewallBackendFailure{
        phase, kind, message, external_repair};
}

} // namespace

RuntimeFirewallBackendTransactionResult
execute_runtime_firewall_backend_transaction(
    const RuntimeFirewallBackendTransactionInput& input,
    Firewall& firewall) {
    RuntimeFirewallBackendTransactionResult result;
    result.operation_serial = input.operation_serial;
    result.config_generation = input.config_generation;

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

    try {
        StagedRuntimeFirewall staged;
        try {
            staged = stage_with(input.requested_mode);
        } catch (const FirewallRulesOnlyError& error) {
            if (input.requested_mode != FirewallApplyMode::RulesOnly) {
                throw;
            }
            result.rules_only_fallback = RuntimeFirewallRulesOnlyFallback{
                RuntimeFirewallBackendTransactionPhase::initial_stage,
                error.what(),
                error.external_repair()};
            phase = RuntimeFirewallBackendTransactionPhase::fallback_stage;
            staged = stage_with(FirewallApplyMode::PreserveSets);
        }

        if (result.rules_only_fallback.has_value()) {
            // A staging refusal already consumed the one permitted fallback.
            // Passing no callback makes any later refusal terminal.
            phase = RuntimeFirewallBackendTransactionPhase::fallback_commit;
            staged = commit_runtime_firewall_with_rules_only_fallback(
                firewall, std::move(staged), {});
        } else {
            phase = RuntimeFirewallBackendTransactionPhase::initial_commit;
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
                    auto fallback =
                        stage_with(FirewallApplyMode::PreserveSets);
                    // The commit helper performs the fallback commit after the
                    // callback returns. Set the phase before returning so a
                    // backend exception is classified at the exact boundary.
                    phase = RuntimeFirewallBackendTransactionPhase::
                        fallback_commit;
                    return fallback;
                });
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

} // namespace keen_pbr3
