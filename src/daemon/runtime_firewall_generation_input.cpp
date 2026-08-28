#include "runtime_firewall_generation_input.hpp"

#include <utility>

namespace keen_pbr3 {

RuntimeFirewallWorkerAttemptInput make_runtime_firewall_worker_attempt_input(
    RuntimeFirewallGenerationSnapshot snapshot) {
    RuntimeFirewallWorkerAttemptInput input;
    input.operation_kind = snapshot.operation_kind;
    input.transaction = std::move(snapshot.transaction);

    // Build the route request only from the now-owned transaction. There is
    // no second config/mark/selector source which could drift while a future
    // prepared candidate waits for owner admission.
    input.route_health_request.operation_serial =
        input.transaction.operation_serial;
    input.route_health_request.runtime_generation =
        input.transaction.runtime_generation;
    input.route_health_request.route_epoch = snapshot.route.route_epoch;
    input.route_health_request.config = input.transaction.config;
    input.route_health_request.outbound_marks =
        input.transaction.outbound_marks;
    input.route_health_request.urltest_selections =
        input.transaction.urltest_selections;
    input.route_reconcile_mode = snapshot.route.reconcile_mode;
    input.route_mutation_checkpoint =
        std::move(snapshot.route.mutation_checkpoint);

    input.inspect_owned_snat = snapshot.cleanup.inspect_owned_snat;
    input.pre_mutation_owned_conntrack_cleanup_snapshot = std::move(
        snapshot.cleanup.pre_mutation_owned_conntrack_cleanup_snapshot);
    input.mandatory_owned_conntrack_cleanup_snapshot = std::move(
        snapshot.cleanup.mandatory_owned_conntrack_cleanup_snapshot);
    input.owned_conntrack_cleanup_mode = snapshot.cleanup.mode;
    return input;
}

} // namespace keen_pbr3
