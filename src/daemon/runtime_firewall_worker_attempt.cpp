#include "runtime_firewall_worker_attempt.hpp"

#include <chrono>
#include <exception>
#include <new>
#include <set>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

// Both result alternatives share one control block allocated before the
// backend callback can enter COMMIT. The optional owns inline storage, so
// publishing the exact result performs only the statically proven nothrow move
// construction above. An escaped runner can therefore return the untouched
// conservative result without allocating or repairing evidence post-COMMIT.
struct RuntimeFirewallDurableResultHolder {
    RuntimeFirewallWorkerAttemptResult conservative;
    std::optional<RuntimeFirewallWorkerAttemptResult> completed;
};

RuntimeFirewallWorkerInspectionFailure standard_failure(
    const std::exception& error) {
    std::string message{"backend inspection threw an exception"};
    try {
        message = error.what();
    } catch (...) {
    }
    return RuntimeFirewallWorkerInspectionFailure{
        RuntimeFirewallWorkerInspectionFailureKind::standard_exception,
        std::move(message)};
}

RuntimeFirewallWorkerInspectionFailure unknown_failure() {
    return RuntimeFirewallWorkerInspectionFailure{
        RuntimeFirewallWorkerInspectionFailureKind::unknown_exception,
        "backend inspection threw a non-standard exception"};
}

class RecordingMetaUdp443ActivationBackendServices final
    : public MetaUdp443ActivationBackendServices {
public:
    RecordingMetaUdp443ActivationBackendServices(
        MetaUdp443ActivationBackendServices& delegate,
        RuntimeFirewallWorkerFastnatObservation& observation)
        : delegate_(delegate), observation_(observation) {}

    bool fastnat_is_disabled_or_unavailable() override {
        observation_.attempted = true;
        observation_.disabled_or_unavailable.reset();
        observation_.failure = {};
        try {
            const bool value =
                delegate_.fastnat_is_disabled_or_unavailable();
            observation_.disabled_or_unavailable = value;
            return value;
        } catch (const std::exception& error) {
            observation_.failure = standard_failure(error);
            throw;
        } catch (...) {
            observation_.failure = unknown_failure();
            throw;
        }
    }

    ConntrackCleanupResult probe_exact_cleanup_capability(
        bool ipv6_enabled) override {
        return delegate_.probe_exact_cleanup_capability(ipv6_enabled);
    }

    std::vector<DumpedInterface> dump_interfaces() override {
        return delegate_.dump_interfaces();
    }

    ConntrackFlowObservation observe_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        std::uint32_t owned_mask,
        const ConntrackFlowObservationOptions& options,
        const std::vector<std::string>& media_guard_source_addresses,
        const std::vector<std::string>& media_seed_destination_cidrs,
        const std::set<std::uint32_t>& media_seed_owned_marks) override {
        return delegate_.observe_forwarded_destination_flows(
            destination_cidrs,
            local_interface_addresses,
            owned_mask,
            options,
            media_guard_source_addresses,
            media_seed_destination_cidrs,
            media_seed_owned_marks);
    }

private:
    MetaUdp443ActivationBackendServices& delegate_;
    RuntimeFirewallWorkerFastnatObservation& observation_;
};

void initialize_transaction_identity(
    RuntimeFirewallWorkerAttemptResult& result,
    const RuntimeFirewallBackendTransactionInput& input) noexcept {
    result.transaction.operation_serial = input.operation_serial;
    result.transaction.runtime_generation = input.runtime_generation;
}

bool owned_conntrack_cleanup_authority_valid(
    const RuntimeFirewallWorkerAttemptInput& input,
    const OwnedConntrackCleanupSnapshot& snapshot,
    bool expected_ipv6_enabled) {
    const auto expected_mask = fwmark_mask_value(
        input.transaction.config.fwmark.value_or(FwmarkConfig{}));
    bool marks_well_formed = expected_mask != 0U;
    for (const auto mark : snapshot.marks) {
        if (mark == 0U || (mark & ~expected_mask) != 0U) {
            marks_well_formed = false;
            break;
        }
    }
    if (marks_well_formed) {
        for (const auto mark : snapshot.priority_marks) {
            if (snapshot.marks.count(mark) == 0U) {
                marks_well_formed = false;
                break;
            }
        }
    }

    return snapshot.runtime_generation ==
               input.transaction.runtime_generation &&
           snapshot.runtime_generation != 0U &&
           snapshot.owned_mask == expected_mask &&
           snapshot.ipv6_enabled == expected_ipv6_enabled &&
           marks_well_formed;
}

void initialize_owned_conntrack_cleanup_authority(
    RuntimeFirewallWorkerAttemptResult& result,
    const RuntimeFirewallWorkerAttemptInput& input) {
    result.owned_conntrack_cleanup_mode =
        input.owned_conntrack_cleanup_mode;
    if (input.owned_conntrack_cleanup_mode !=
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot) {
        return;
    }
    const bool expected_ipv6_enabled =
        resolve_ipv6_support(input.transaction.config).enabled;

    const auto& missing_snat_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    result.missing_snat_cleanup_authority_valid =
        missing_snat_snapshot.has_value() &&
        owned_conntrack_cleanup_authority_valid(
            input, *missing_snat_snapshot, expected_ipv6_enabled);

    const auto& mandatory_snapshot =
        input.mandatory_owned_conntrack_cleanup_snapshot;
    result.mandatory_cleanup_authority_valid =
        !mandatory_snapshot.has_value() ||
        owned_conntrack_cleanup_authority_valid(
            input, *mandatory_snapshot, expected_ipv6_enabled);

    result.exact_cleanup_authority_valid =
        result.missing_snat_cleanup_authority_valid &&
        result.mandatory_cleanup_authority_valid;
}

void select_owned_conntrack_cleanup_authority(
    RuntimeFirewallWorkerAttemptResult& result,
    const RuntimeFirewallWorkerAttemptInput& input) {
    if (input.operation_kind !=
            RuntimeFirewallWorkerOperationKind::config_preapply ||
        input.owned_conntrack_cleanup_mode !=
            RuntimeFirewallOwnedConntrackCleanupMode::
                exact_pre_mutation_snapshot ||
        !result.exact_cleanup_authority_valid) {
        return;
    }

    std::optional<OwnedConntrackCleanupSnapshot> selected =
        input.mandatory_owned_conntrack_cleanup_snapshot;
    if (result.owned_snat_before.state ==
        std::optional<OwnedSnatState>{OwnedSnatState::missing}) {
        if (selected.has_value()) {
            selected = merge_owned_conntrack_cleanup_snapshot(
                std::move(*selected),
                *input.pre_mutation_owned_conntrack_cleanup_snapshot);
        } else {
            selected =
                input.pre_mutation_owned_conntrack_cleanup_snapshot;
        }
    }

    result.selected_owned_conntrack_cleanup_snapshot =
        std::move(selected);
    result.exact_cleanup_required =
        result.selected_owned_conntrack_cleanup_snapshot.has_value() &&
        !result.selected_owned_conntrack_cleanup_snapshot->marks.empty();
}

static_assert(
    std::is_nothrow_destructible_v<
        RuntimeFirewallWorkerRoutePreparation> &&
        std::is_nothrow_move_constructible_v<
            RuntimeFirewallWorkerRoutePreparation>,
    "route preparation evidence must transfer without a post-mutation "
    "exception gap");

void replace_route_preparation(
    RuntimeFirewallWorkerRoutePreparation& destination,
    RuntimeFirewallWorkerRoutePreparation&& source) noexcept {
    // Entware GCC 8's old libstdc++ ABI does not advertise string swap or
    // move-assignment as noexcept. Reconstruct the already-allocated result
    // subobject with the statically proven nothrow move constructor instead.
    // Placement new itself performs no allocation, so no exception boundary
    // can open after routing mutation and before firewall COMMIT.
    auto* storage = std::addressof(destination);
    storage->~RuntimeFirewallWorkerRoutePreparation();
    ::new (static_cast<void*>(storage))
        RuntimeFirewallWorkerRoutePreparation(std::move(source));
}

void initialize_conservative_durable_result(
    RuntimeFirewallWorkerAttemptResult& result,
    const RuntimeFirewallWorkerAttemptInput& input) {
    result.operation_kind = input.operation_kind;
    initialize_owned_conntrack_cleanup_authority(result, input);
    initialize_transaction_identity(result, input.transaction);
    result.transaction_executed = true;
    result.owned_snat_inspection_required =
        input.inspect_owned_snat ||
        input.operation_kind ==
            RuntimeFirewallWorkerOperationKind::config_preapply;
    result.pre_mutation_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    result.mandatory_owned_conntrack_cleanup_snapshot =
        input.mandatory_owned_conntrack_cleanup_snapshot;

    // The runner is the complete stage/preflight/COMMIT/inspection boundary.
    // If it escapes, this adapter cannot prove which part completed. Prepare
    // the pessimistic result before invoking it so neither error formatting nor
    // terminal allocation is attempted after a possibly successful COMMIT.
    result.transaction.commit_entered = true;
    result.transaction.commit_returned = false;
    result.transaction.failure = RuntimeFirewallBackendFailure{
        RuntimeFirewallBackendTransactionPhase::initial_commit,
        RuntimeFirewallBackendFailureKind::unexpected_exception,
        "worker attempt escaped before publishing its typed terminal result",
        false};
}

void inspect_owned_snat(
    Firewall& firewall,
    RuntimeFirewallWorkerOwnedSnatObservation& observation) {
    observation.attempted = true;
    try {
        observation.state = firewall.inspect_owned_snat_state();
    } catch (const std::exception& error) {
        observation.failure = standard_failure(error);
    } catch (...) {
        observation.failure = unknown_failure();
    }
}

void inspect_forward_udp_reject(
    Firewall& firewall,
    RuntimeFirewallWorkerForwardUdpRejectObservation& observation) {
    observation.attempted = true;
    try {
        observation.state = firewall.inspect_forward_udp_reject_state();
    } catch (const std::exception& error) {
        observation.failure = standard_failure(error);
    } catch (...) {
        observation.failure = unknown_failure();
    }
}

void inspect_fastnat(
    MetaUdp443ActivationBackendServices& meta_services,
    RuntimeFirewallWorkerFastnatObservation& observation) {
    observation.attempted = true;
    observation.disabled_or_unavailable.reset();
    observation.failure = {};
    try {
        observation.disabled_or_unavailable =
            meta_services.fastnat_is_disabled_or_unavailable();
    } catch (const std::exception& error) {
        observation.failure = standard_failure(error);
    } catch (...) {
        observation.failure = unknown_failure();
    }
}

void cleanup_native_direct_egress_sources(
    const RuntimeFirewallWorkerAttemptInput& input,
    ConntrackManager& conntrack_manager,
    RuntimeFirewallWorkerAttemptResult& result) {
    if (input.operation_kind ==
            RuntimeFirewallWorkerOperationKind::config_preapply ||
        runtime_firewall_worker_operation_is_config_generation(
            input.operation_kind) ||
        runtime_firewall_worker_operation_is_urltest_generation(
            input.operation_kind) ||
        !result.transaction.committed()) {
        // commit_entered without a returned committed candidate is ambiguous.
        // It must trigger a fresh resnapshot, never destructive cleanup under
        // selectors which may not be authoritative in the kernel.
        return;
    }

    auto& cleanup = result.native_direct_egress_source_cleanup;
    try {
        cleanup.affected_source_cidrs =
            changed_native_vpn_direct_egress_source_cidrs(
                input.transaction
                    .previous_native_vpn_direct_egress_snat_selectors,
                input.transaction
                    .candidate_native_vpn_direct_egress_snat_selectors);
        if (cleanup.affected_source_cidrs.empty()) {
            return;
        }

        cleanup.attempted = true;
        cleanup.summary = conntrack_manager.delete_ipv4_source_cidrs(
            cleanup.affected_source_cidrs,
            ConntrackSourceCleanupOptions{
                std::chrono::seconds{4},
                /*max_source_cidrs=*/32U});
    } catch (const std::exception& error) {
        cleanup.failure = standard_failure(error);
    } catch (...) {
        cleanup.failure = unknown_failure();
    }
}

void cleanup_owned_conntrack_after_commit(
    const RuntimeFirewallWorkerAttemptInput& input,
    ConntrackManager& conntrack_manager,
    RuntimeFirewallWorkerAttemptResult& result) {
    select_owned_conntrack_cleanup_authority(result, input);
    const bool exact_pre_mutation_cleanup =
        input.owned_conntrack_cleanup_mode ==
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    const bool committed_candidate_cleanup =
        input.owned_conntrack_cleanup_mode ==
            RuntimeFirewallOwnedConntrackCleanupMode::
                committed_candidate &&
        input.operation_kind ==
            RuntimeFirewallWorkerOperationKind::reconcile_generation;
    const bool exact_preapply_observation_admitted =
        (result.owned_snat_before.state ==
             std::optional<OwnedSnatState>{OwnedSnatState::healthy} ||
         result.owned_snat_before.state ==
             std::optional<OwnedSnatState>{OwnedSnatState::missing}) &&
        !result.owned_snat_before.failure.failed();
    const bool exact_preapply_verified =
        exact_pre_mutation_cleanup &&
        input.operation_kind ==
            RuntimeFirewallWorkerOperationKind::config_preapply &&
        result.exact_cleanup_authority_valid &&
        result.exact_cleanup_required &&
        exact_preapply_observation_admitted &&
        result.owned_snat_after.state ==
            std::optional<OwnedSnatState>{OwnedSnatState::healthy} &&
        !result.owned_snat_after.failure.failed() &&
        (!result.transaction_executed ||
         result.transaction.committed());
    if (input.owned_conntrack_cleanup_mode ==
            RuntimeFirewallOwnedConntrackCleanupMode::none ||
        (!exact_pre_mutation_cleanup &&
         !committed_candidate_cleanup) ||
        (exact_pre_mutation_cleanup && !exact_preapply_verified) ||
        (committed_candidate_cleanup &&
         !result.transaction.committed())) {
        return;
    }

    auto& cleanup = result.post_commit_owned_conntrack_cleanup;
    if (exact_pre_mutation_cleanup) {
        cleanup.snapshot =
            result.selected_owned_conntrack_cleanup_snapshot;
    } else {
        cleanup.snapshot = make_owned_conntrack_cleanup_snapshot(
            input.transaction.runtime_generation,
            input.transaction.config,
            input.transaction.outbound_marks,
            result.transaction.committed_firewall->rule_states,
            input.transaction.urltest_selections);
    }
    if (!cleanup.snapshot.has_value() || !cleanup.snapshot->valid()) {
        return;
    }
    cleanup.attempted = true;
    try {
        cleanup.summary = conntrack_manager.delete_marks_ordered(
            ordered_owned_conntrack_marks(*cleanup.snapshot),
            cleanup.snapshot->owned_mask,
            ConntrackCleanupOptions{
                cleanup.snapshot->ipv6_enabled,
                std::chrono::seconds{4}});
    } catch (const std::exception& error) {
        cleanup.failure = standard_failure(error);
    } catch (...) {
        cleanup.failure = unknown_failure();
    }
}

RuntimeFirewallBackendTransactionResult escaped_transaction_failure(
    const RuntimeFirewallBackendTransactionInput& input,
    RuntimeFirewallBackendFailureKind kind,
    std::string message) {
    RuntimeFirewallBackendTransactionResult result;
    result.operation_serial = input.operation_serial;
    result.runtime_generation = input.runtime_generation;
    // The wrapped transaction is specified to contain every backend fault.
    // If that contract ever regresses and an exception escapes, the wrapper
    // cannot prove where it escaped. Classify the COMMIT boundary as entered
    // so the control loop never restores or replays the old generation on an
    // invented pre-COMMIT guarantee.
    result.commit_entered = true;
    result.failure = RuntimeFirewallBackendFailure{
        RuntimeFirewallBackendTransactionPhase::initial_stage,
        kind,
        std::move(message),
        false};
    return result;
}

} // namespace

RuntimeFirewallWorkerAttemptResult execute_runtime_firewall_worker_attempt(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services) {
    RuntimeFirewallWorkerAttemptResult result;
    result.operation_kind = input.operation_kind;
    initialize_owned_conntrack_cleanup_authority(result, input);
    initialize_transaction_identity(result, input.transaction);
    const bool config_preapply = input.operation_kind ==
        RuntimeFirewallWorkerOperationKind::config_preapply;
    result.owned_snat_inspection_required =
        input.inspect_owned_snat || config_preapply;
    result.pre_mutation_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    result.mandatory_owned_conntrack_cleanup_snapshot =
        input.mandatory_owned_conntrack_cleanup_snapshot;
    result.meta_publication_epoch_before =
        firewall.meta_udp443_publication_epoch();
    result.meta_publication_epoch_after =
        result.meta_publication_epoch_before;

    if (result.owned_snat_inspection_required) {
        inspect_owned_snat(firewall, result.owned_snat_before);
        if (result.owned_snat_before.failure.failed()) {
            // A required pre-observation is admission, not mutation. Do not
            // execute or replay the transaction without its exact baseline.
            result.meta_publication_epoch_after =
                firewall.meta_udp443_publication_epoch();
            return result;
        }
        if (config_preapply &&
            !result.exact_cleanup_authority_valid) {
            // Repairing missing SNAT without the exact old-generation cleanup
            // authority would leave the generation barrier unverifiable.
            // Healthy state is likewise not permission to ignore a malformed
            // mandatory remainder.
            result.meta_publication_epoch_after =
                firewall.meta_udp443_publication_epoch();
            return result;
        }
        if (config_preapply &&
            result.owned_snat_before.state !=
                std::optional<OwnedSnatState>{OwnedSnatState::missing}) {
            // Healthy state needs a second observation around the exact
            // cleanup boundary but no redundant firewall COMMIT. Unknown is
            // deliberately not repaired or treated as success.
            inspect_owned_snat(firewall, result.owned_snat_after);
            result.meta_publication_epoch_after =
                firewall.meta_udp443_publication_epoch();
            return result;
        }
    }

    RecordingMetaUdp443ActivationBackendServices recording_meta{
        meta_services, result.fastnat};
    result.transaction_executed = true;
    try {
        result.transaction = execute_runtime_firewall_backend_transaction(
            input.transaction, firewall, recording_meta);
    } catch (const std::exception& error) {
        // The transaction function is itself non-throwing for backend faults.
        // Retain a final safety net so a future adapter regression cannot tear
        // down the worker or cause an automatic replay.
        result.transaction = escaped_transaction_failure(
            input.transaction,
            RuntimeFirewallBackendFailureKind::unexpected_exception,
            standard_failure(error).message);
    } catch (...) {
        result.transaction = escaped_transaction_failure(
            input.transaction,
            RuntimeFirewallBackendFailureKind::unknown_exception,
            "backend transaction threw a non-standard exception");
    }

    // Snapshot the publication boundary immediately after the transaction,
    // before any fallible health query. It remains evidence even when the
    // transaction or a later inspection failed.
    result.meta_publication_epoch_after =
        firewall.meta_udp443_publication_epoch();

    if (result.transaction.commit_entered && !config_preapply) {
        inspect_forward_udp_reject(
            firewall, result.forward_udp_reject_after_commit);
        if (result.transaction.meta_activation_plan.has_value()) {
            // Call the original service, not the recording preflight adapter:
            // this is a second observation after the COMMIT boundary and must
            // remain separately attributable in the terminal result.
            inspect_fastnat(meta_services, result.fastnat_after_commit);
        }
    }
    if (result.owned_snat_inspection_required) {
        inspect_owned_snat(firewall, result.owned_snat_after);
    }
    return result;
}

RuntimeFirewallWorkerAttemptResult execute_runtime_firewall_worker_attempt(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink) {
    SystemMetaUdp443ActivationBackendServices meta_services{
        conntrack_manager, netlink};
    return execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);
}

RuntimeFirewallWorkerAttemptResult execute_runtime_firewall_worker_attempt(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services,
    ConntrackManager& conntrack_manager) {
    auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);
    cleanup_native_direct_egress_sources(
        input, conntrack_manager, result);
    cleanup_owned_conntrack_after_commit(
        input, conntrack_manager, result);
    return result;
}

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    RuntimeFirewallWorkerAttemptRunner run_attempt) {
    // The control block, both result slots and every potentially allocating
    // conservative field are ready before backend execution. Failure here
    // propagates without invoking run_attempt and cannot lose a COMMIT outcome.
    auto durable =
        std::make_shared<RuntimeFirewallDurableResultHolder>();
    initialize_conservative_durable_result(durable->conservative, input);

    try {
        if (run_attempt) {
            auto completed = run_attempt();
            // The optional is a separate inline slot. Even on a toolchain
            // whose old string ABI makes move assignment potentially throwing,
            // exact publication uses the nothrow move construction asserted in
            // the public contract and cannot damage conservative evidence.
            durable->completed.emplace(std::move(completed));
            const auto* exact =
                std::addressof(*durable->completed);
            return RuntimeFirewallWorkerAttemptResultPtr{durable, exact};
        }
    } catch (...) {
        // Do not inspect the backend, allocate an exception message, or change
        // the prebuilt evidence here. The exact boundary is unknowable and the
        // retained commit-entered result deliberately forbids replay.
    }
    return RuntimeFirewallWorkerAttemptResultPtr{
        durable, std::addressof(durable->conservative)};
}

RuntimeFirewallWorkerAttemptResult
execute_runtime_firewall_worker_attempt_with_route_preparation(
    const RuntimeFirewallWorkerAttemptInput& input,
    RuntimeRouteHealthServices& route_health_services,
    RuntimeRouteWorkerMutationRunner run_route_mutation,
    RuntimeFirewallWorkerAttemptRunner run_firewall_attempt) {
    RuntimeFirewallWorkerAttemptResult preparation_result;
    preparation_result.operation_kind = input.operation_kind;
    initialize_owned_conntrack_cleanup_authority(
        preparation_result, input);
    initialize_transaction_identity(preparation_result, input.transaction);
    preparation_result.owned_snat_inspection_required =
        input.inspect_owned_snat ||
        input.operation_kind ==
            RuntimeFirewallWorkerOperationKind::config_preapply;
    preparation_result.pre_mutation_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    preparation_result.mandatory_owned_conntrack_cleanup_snapshot =
        input.mandatory_owned_conntrack_cleanup_snapshot;
    auto& route_preparation = preparation_result.route_preparation;
    route_preparation.required =
        static_cast<bool>(input.route_mutation_checkpoint);
    if (input.route_mutation_checkpoint) {
        auto observation = execute_runtime_route_health_plan(
            input.route_health_request, route_health_services);
        const bool observation_succeeded = observation.succeeded();
        route_preparation.observation_succeeded =
            observation_succeeded;
        std::swap(route_preparation.observation_failure.stage,
                  observation.failure.stage);
        std::swap(route_preparation.observation_failure.kind,
                  observation.failure.kind);
        route_preparation.observation_failure.detail.swap(
            observation.failure.detail);

        if (!observation_succeeded || !observation.plan) {
            return preparation_result;
        }

        // Shutdown/cancellation can win while the live observation is in
        // progress. Never enter the routing owner after the publication
        // checkpoint has already been terminalized.
        if (input.route_mutation_checkpoint->state() ==
                RuntimeRouteMutationCheckpointState::acked ||
            !run_route_mutation) {
            return preparation_result;
        }

        try {
            auto mutation = run_route_mutation(
                *observation.plan, input.route_reconcile_mode);
            route_preparation.worker_mutation_ack = mutation.ack;
            route_preparation.worker_mutation_failure_detail.swap(
                mutation.failure_detail);
        } catch (const std::exception& error) {
            route_preparation.worker_mutation_ack =
                RuntimeRouteMutationAck::mutation_failed;
            try {
                route_preparation.worker_mutation_failure_detail =
                    error.what();
            } catch (...) {
            }
        } catch (...) {
            route_preparation.worker_mutation_ack =
                RuntimeRouteMutationAck::mutation_failed;
            try {
                route_preparation.worker_mutation_failure_detail =
                    "runtime route worker mutation failed";
            } catch (...) {
            }
        }

        if (!route_preparation.worker_mutation_ack.has_value() ||
            *route_preparation.worker_mutation_ack !=
                RuntimeRouteMutationAck::applied) {
            return preparation_result;
        }

        route_preparation.checkpoint_published =
            input.route_mutation_checkpoint->publish(
                std::move(observation.plan));
        if (!route_preparation.checkpoint_published) {
            return preparation_result;
        }

        const auto ack = input.route_mutation_checkpoint->wait_ack();
        route_preparation.mutation_ack = ack;
        if (ack != RuntimeRouteMutationAck::applied) {
            return preparation_result;
        }
    }

    if (!run_firewall_attempt) {
        return preparation_result;
    }
    auto result = run_firewall_attempt();
    // Assignment and string swap are not guaranteed nothrow on the target
    // GCC 8 ABI. Reconstruct the result subobject from the already-built
    // pre-COMMIT evidence so transfer cannot escape into the durable adapter
    // and be mistaken for an ambiguous firewall COMMIT.
    replace_route_preparation(
        result.route_preparation,
        std::move(preparation_result.route_preparation));
    return result;
}

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
    const RuntimeFirewallWorkerAttemptInput& input,
    RuntimeRouteHealthServices& route_health_services,
    RuntimeRouteWorkerMutationRunner run_route_mutation,
    RuntimeFirewallWorkerAttemptRunner run_firewall_attempt) {
    return execute_runtime_firewall_worker_attempt_durable(
        input,
        [&input,
         &route_health_services,
         run_route_mutation = std::move(run_route_mutation),
         run_firewall_attempt = std::move(run_firewall_attempt)]() mutable {
            return
                execute_runtime_firewall_worker_attempt_with_route_preparation(
                    input,
                    route_health_services,
                    std::move(run_route_mutation),
                    std::move(run_firewall_attempt));
        });
}

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services) {
    return execute_runtime_firewall_worker_attempt_durable(
        input,
        [&input, &firewall, &meta_services]() {
            return execute_runtime_firewall_worker_attempt(
                input, firewall, meta_services);
        });
}

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services,
    ConntrackManager& conntrack_manager) {
    return execute_runtime_firewall_worker_attempt_durable(
        input,
        [&input, &firewall, &meta_services, &conntrack_manager]() {
            return execute_runtime_firewall_worker_attempt(
                input,
                firewall,
                meta_services,
                conntrack_manager);
        });
}

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink) {
    SystemRuntimeRouteHealthServices route_health_services{netlink};
    SystemMetaUdp443ActivationBackendServices meta_services{
        conntrack_manager, netlink};
    return
        execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
        input,
        route_health_services,
        [](const RuntimeRouteHealthPlan&, RouteReconcileMode) {
            RuntimeRouteWorkerMutationResult result;
            result.ack = RuntimeRouteMutationAck::mutation_failed;
            result.failure_detail =
                "no combined routing owner was supplied";
            return result;
        },
        [&input, &firewall, &meta_services, &conntrack_manager]() {
            return execute_runtime_firewall_worker_attempt(
                input,
                firewall,
                meta_services,
                conntrack_manager);
        });
}

} // namespace keen_pbr3
