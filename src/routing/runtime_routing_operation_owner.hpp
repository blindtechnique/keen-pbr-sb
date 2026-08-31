#pragma once

#include "policy_rule.hpp"
#include "route_table.hpp"
#include "runtime_routing_transaction.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Exact identity of one desired routing generation. runtime_generation alone
// is insufficient: two URLTest selections can be produced inside the same
// configuration generation.
struct RuntimeRoutingOperationIdentity final {
    std::uint64_t operation_serial{0U};
    std::uint64_t runtime_generation{0U};
    std::uint64_t intent_serial{0U};
    std::uint64_t base_inventory_revision{0U};
    std::uint64_t route_epoch{0U};
};

enum class RuntimeRoutingMutationPhase : std::uint8_t {
    prepared,
    observing_prior_routes,
    adding_routes,
    adding_rules,
    committing_replacements,
    removing_orphaned_rules,
    removing_obsolete_rules,
    removing_obsolete_routes,
    adopting_committed_inventory,
    complete,
    failed,
    cleared,
};

enum class RuntimeRoutingOperationOutcome : std::uint8_t {
    idle,
    compatibility_converged,
    compatibility_cleanup_pending,
    exact_candidate_committed,
    exact_candidate_rolled_back,
    exact_committed_cleanup_pending,
    exact_partial_unknown,
    exact_stale_before_mutation,
    exact_precondition_failed,
    rejected_invalid_identity,
    rejected_replay,
    rejected_stale_inventory,
    route_unavailable,
    partial_failure,
    cleared,
};

// This is a lifetime-durable, in-memory journal. It deliberately is not a
// disk WAL: kernel protocol-186 evidence remains the restart recovery source.
// R1 hardening will extend this record with preallocated per-object receipts
// before this owner is allowed to execute in the production worker.
struct RuntimeRoutingMutationJournal final {
    RuntimeRoutingOperationIdentity identity;
    RuntimeRoutingMutationPhase phase{
        RuntimeRoutingMutationPhase::prepared};
    bool mutation_boundary_entered{false};
    RuntimeRoutingOperationOutcome outcome{
        RuntimeRoutingOperationOutcome::partial_failure};
    std::string failure_detail;
};

// No reference to RouteTable or PolicyRuleManager escapes the owner. Readers
// retain an immutable copy while a later operation advances the revision.
struct RuntimeRoutingInventorySnapshot final {
    std::uint64_t revision{1U};
    std::uint64_t highest_consumed_operation_serial{0U};
    std::uint64_t highest_consumed_runtime_generation{0U};
    std::uint64_t highest_consumed_intent_serial{0U};
    std::uint64_t highest_consumed_route_epoch{0U};
    std::optional<RuntimeRoutingOperationIdentity> last_identity;
    RuntimeRoutingMutationPhase phase{
        RuntimeRoutingMutationPhase::prepared};
    RuntimeRoutingOperationOutcome outcome{
        RuntimeRoutingOperationOutcome::idle};
    // False means the owner could publish only its preallocated conservative
    // preimage, not an exact copy of its post-operation manager ledgers. The
    // marker is prepared before netlink I/O, so allocation failure after a
    // kernel mutation cannot leave an older snapshot looking authoritative.
    bool inventory_complete{true};
    // False means at least one mutating call returned without proving its
    // kernel effect. The manager ledger may be copied exactly while still
    // being only a conservative recovery ledger rather than proven live state.
    bool kernel_state_known{true};
    std::vector<RouteSpec> routes;
    std::vector<RuleSpec> rules;
};

using RuntimeRoutingInventorySnapshotPtr =
    std::shared_ptr<const RuntimeRoutingInventorySnapshot>;

enum class RuntimeRoutingInventoryAuthority : std::uint8_t {
    authoritative,
    missing,
    inventory_incomplete,
    kernel_state_unknown,
};

inline RuntimeRoutingInventoryAuthority
classify_runtime_routing_inventory(
    const RuntimeRoutingInventorySnapshotPtr& inventory) noexcept {
    if (!inventory) {
        return RuntimeRoutingInventoryAuthority::missing;
    }
    if (!inventory->inventory_complete) {
        return RuntimeRoutingInventoryAuthority::inventory_incomplete;
    }
    if (!inventory->kernel_state_known) {
        return RuntimeRoutingInventoryAuthority::kernel_state_unknown;
    }
    return RuntimeRoutingInventoryAuthority::authoritative;
}

using RuntimeRoutingInventorySnapshotFactory = std::function<
    std::shared_ptr<RuntimeRoutingInventorySnapshot>()>;
using RuntimeRoutingMutationJournalPtr =
    std::shared_ptr<const RuntimeRoutingMutationJournal>;
using RuntimeRoutingCompatibilityFenceProbe = std::function<bool()>;

struct RuntimeRoutingOperationRequest final {
    RuntimeRoutingOperationIdentity identity;
    std::vector<RouteSpec> desired_routes;
    std::vector<RuleSpec> desired_rules;
    std::vector<RuntimeRoutingExternalTableAuthority>
        authorized_external_tables;
    RouteReconcileMode mode{RouteReconcileMode::Strict};
};

struct RuntimeRoutingOperationResult final {
    RuntimeRoutingOperationIdentity identity;
    RuntimeRoutingOperationOutcome outcome{
        RuntimeRoutingOperationOutcome::partial_failure};
    RuntimeRoutingMutationJournalPtr journal;
    RuntimeRoutingPublishedJournalPtr exact_journal;
    RuntimeRoutingInventorySnapshotPtr inventory;
    RuntimeRoutingFailureStage exact_failure_stage{
        RuntimeRoutingFailureStage::none};
    bool route_interface_unavailable{false};
    std::string detail;

    bool compatibility_converged() const noexcept {
        return outcome ==
            RuntimeRoutingOperationOutcome::compatibility_converged;
    }
};

// Persistent combined owner for route and policy-rule manager ledgers. The
// facade is the R1 ownership boundary: all manager access is serialized and
// readers receive copies. The daemon may run the explicitly named
// compatibility methods off-loop under its existing global mutation
// admission, but their partial-prefix result remains compatibility-only.
// Production generation changes use reconcile_exact() and its published
// transaction journal.
class RuntimeRoutingOperationOwner final {
public:
    explicit RuntimeRoutingOperationOwner(
        RouteNetlinkOperations& route_netlink,
        RuleNetlinkOperations& rule_netlink,
        RouteTable::InterfaceReadinessProbe interface_readiness_probe = {},
        RouteTable::NowFunction now = {},
        RuntimeRoutingInventorySnapshotFactory inventory_factory = {});
    ~RuntimeRoutingOperationOwner() noexcept;

    RuntimeRoutingOperationOwner(
        const RuntimeRoutingOperationOwner&) = delete;
    RuntimeRoutingOperationOwner& operator=(
        const RuntimeRoutingOperationOwner&) = delete;

    RuntimeRoutingOperationResult reconcile(
        const RuntimeRoutingOperationRequest& request);
    RuntimeRoutingOperationResult reconcile_exact(
        const RuntimeRoutingOperationRequest& request,
        const RuntimeRoutingCurrentFenceProbe& current_fence);

    // Compatibility entry points retained for startup and convergent repair.
    // Unlike exposing RouteTable and PolicyRuleManager, these keep every
    // legacy mutation and both ledgers inside the same serialized owner and
    // propagate the original failure to the caller.
    RuntimeRoutingInventorySnapshotPtr populate_initial_generation(
        const std::vector<RouteSpec>& desired_routes,
        const std::vector<RuleSpec>& desired_rules);
    RuntimeRoutingInventorySnapshotPtr reconcile_compatibility_generation(
        const std::vector<RouteSpec>& desired_routes,
        const std::vector<RuleSpec>& desired_rules,
        RouteReconcileMode mode = RouteReconcileMode::Strict,
        RuntimeRoutingCompatibilityFenceProbe current_fence = {});

    RuntimeRoutingInventorySnapshotPtr snapshot() const;
    RuntimeRoutingPublishedJournalPtr exact_journal() const;

    // Compatibility seams needed while the remaining direct Daemon users are
    // migrated behind this owner. They are serialized but not asynchronous.
    void notify_interface_up(const std::string& interface_name) noexcept;
    RuntimeRoutingInventorySnapshotPtr clear();

private:
    struct PreparedInventoryPublication final {
        std::shared_ptr<RuntimeRoutingInventorySnapshot> writable;
        RuntimeRoutingInventorySnapshotPtr immutable;
    };

    RuntimeRoutingOperationResult rejected_result(
        const RuntimeRoutingOperationRequest& request,
        RuntimeRoutingOperationOutcome outcome) const;
    PreparedInventoryPublication prepare_inventory_publication_locked(
        const std::vector<RouteSpec>& routes,
        const std::vector<RuleSpec>& rules,
        const std::optional<RuntimeRoutingOperationIdentity>& identity,
        bool inventory_complete,
        bool kernel_state_known);
    RuntimeRoutingInventorySnapshotPtr commit_prepared_inventory_locked(
        PreparedInventoryPublication prepared,
        RuntimeRoutingMutationPhase phase,
        RuntimeRoutingOperationOutcome outcome,
        bool advance_revision = true) noexcept;
    RuntimeRoutingInventorySnapshotPtr
    publish_actual_inventory_or_fallback_locked(
        PreparedInventoryPublication fallback,
        const std::optional<RuntimeRoutingOperationIdentity>& identity,
        RuntimeRoutingMutationPhase phase,
        RuntimeRoutingOperationOutcome outcome,
        bool kernel_state_known,
        bool advance_revision) noexcept;
    void consume_pending_interface_notifications_locked() noexcept;
    void discard_pending_interface_notifications_locked() noexcept;
    bool clear_ledgers_locked();
    std::shared_ptr<RuntimeRoutingInventorySnapshot>
    allocate_inventory_snapshot();

    mutable std::mutex mutex_;
    mutable std::mutex pending_interface_mutex_;
    std::set<std::string> pending_interface_up_;
    RuntimeRoutingInventorySnapshotFactory inventory_factory_;
    RouteNetlinkOperations& route_netlink_;
    RuleNetlinkOperations& rule_netlink_;
    RouteTable routes_;
    PolicyRuleManager rules_;
    std::uint64_t inventory_revision_{1U};
    std::uint64_t highest_consumed_operation_serial_{0U};
    std::uint64_t highest_consumed_runtime_generation_{0U};
    std::uint64_t highest_consumed_intent_serial_{0U};
    std::uint64_t highest_consumed_route_epoch_{0U};
    RuntimeRoutingInventorySnapshotPtr published_inventory_;
    std::shared_ptr<RuntimeRoutingMutationJournal> active_journal_;
    RuntimeRoutingPublishedJournalPtr active_exact_journal_;
};

} // namespace keen_pbr3
