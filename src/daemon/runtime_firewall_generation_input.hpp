#pragma once

#include "runtime_firewall_worker_attempt.hpp"

namespace keen_pbr3 {

// Route mutation policy which belongs to one immutable runtime generation
// snapshot. Identity and routing inputs are deliberately absent: the builder
// derives them from the transaction so a candidate cannot accidentally pair
// its firewall body with another generation's route plan.
struct RuntimeFirewallGenerationRoutePolicy final {
    std::uint64_t route_epoch{0U};
    RouteReconcileMode reconcile_mode{RouteReconcileMode::DeferredRepair};
    std::shared_ptr<RuntimeRouteMutationCheckpoint> mutation_checkpoint;
};

// Exact conntrack authority selected on the control loop before the worker is
// admitted. The builder only transfers this policy; it never infers or widens
// cleanup authority from the candidate transaction.
struct RuntimeFirewallGenerationCleanupPolicy final {
    bool inspect_owned_snat{false};
    std::optional<OwnedConntrackCleanupSnapshot>
        pre_mutation_owned_conntrack_cleanup_snapshot;
    std::optional<OwnedConntrackCleanupSnapshot>
        mandatory_owned_conntrack_cleanup_snapshot;
    RuntimeFirewallOwnedConntrackCleanupMode mode{
        RuntimeFirewallOwnedConntrackCleanupMode::none};
};

// Complete owned snapshot used to build one worker input. Callers finish the
// backend transaction first, then move this value across the builder seam;
// no Daemon state is read while route identity or cleanup policy is attached.
struct RuntimeFirewallGenerationSnapshot final {
    RuntimeFirewallWorkerOperationKind operation_kind{
        RuntimeFirewallWorkerOperationKind::reconcile_generation};
    RuntimeFirewallBackendTransactionInput transaction;
    RuntimeFirewallGenerationRoutePolicy route;
    RuntimeFirewallGenerationCleanupPolicy cleanup;
};

RuntimeFirewallWorkerAttemptInput make_runtime_firewall_worker_attempt_input(
    RuntimeFirewallGenerationSnapshot snapshot);

} // namespace keen_pbr3
