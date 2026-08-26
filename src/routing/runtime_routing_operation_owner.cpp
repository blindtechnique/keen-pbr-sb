#include "runtime_routing_operation_owner.hpp"

#include "../log/logger.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <new>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace keen_pbr3 {
namespace {

bool identity_is_valid(
    const RuntimeRoutingOperationIdentity& identity) noexcept {
    return identity.operation_serial != 0U &&
           identity.runtime_generation != 0U &&
           identity.intent_serial != 0U &&
           identity.base_inventory_revision != 0U &&
           identity.route_epoch != 0U;
}

void retain_failure_detail(RuntimeRoutingMutationJournal& journal,
                           const char* detail) noexcept {
    try {
        journal.failure_detail = detail != nullptr ? detail : "";
    } catch (...) {
        journal.failure_detail.clear();
    }
}

} // namespace

RuntimeRoutingOperationOwner::RuntimeRoutingOperationOwner(
    RouteNetlinkOperations& route_netlink,
    RuleNetlinkOperations& rule_netlink,
    RouteTable::InterfaceReadinessProbe interface_readiness_probe,
    RouteTable::NowFunction now,
    RuntimeRoutingInventorySnapshotFactory inventory_factory)
    : inventory_factory_(std::move(inventory_factory)),
      routes_(
          route_netlink,
          false,
          std::move(interface_readiness_probe),
          std::move(now),
          /*cleanup_on_destruction=*/false),
      rules_(
          rule_netlink,
          false,
          /*cleanup_on_destruction=*/false) {
    if (dynamic_cast<void*>(&route_netlink) !=
        dynamic_cast<void*>(&rule_netlink)) {
        throw std::invalid_argument(
            "runtime routing owner requires one combined route/rule backend");
    }
    auto initial = allocate_inventory_snapshot();
    initial->revision = inventory_revision_;
    RuntimeRoutingInventorySnapshotPtr immutable = std::move(initial);
    std::atomic_store_explicit(
        &published_inventory_,
        std::move(immutable),
        std::memory_order_release);
}

RuntimeRoutingOperationOwner::~RuntimeRoutingOperationOwner() noexcept {
    // Empty both manager ledgers while the combined owner is still alive.
    // Their destructors are disarmed for this owner, so even a failed
    // best-effort cleanup cannot create an unlocked second mutation path.
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            auto protected_tables = rules_.clear();
            const auto live_dependency_tables =
                rules_.protect_route_tables_with_live_rules(
                    routes_.get_routes());
            protected_tables.insert(
                live_dependency_tables.begin(),
                live_dependency_tables.end());
            (void)routes_.clear(protected_tables);
        } catch (...) {
        }
        discard_pending_interface_notifications_locked();
        active_journal_.reset();
    } catch (...) {
    }
}

RuntimeRoutingInventorySnapshotPtr
RuntimeRoutingOperationOwner::snapshot() const {
    return std::atomic_load_explicit(
        &published_inventory_, std::memory_order_acquire);
}

RuntimeRoutingOperationResult
RuntimeRoutingOperationOwner::rejected_result(
    const RuntimeRoutingOperationRequest& request,
    RuntimeRoutingOperationOutcome outcome) const {
    RuntimeRoutingOperationResult result;
    result.identity = request.identity;
    result.outcome = outcome;
    result.inventory = std::atomic_load_explicit(
        &published_inventory_, std::memory_order_acquire);
    return result;
}

RuntimeRoutingOperationOwner::PreparedInventoryPublication
RuntimeRoutingOperationOwner::prepare_inventory_publication_locked(
    const std::vector<RouteSpec>& routes,
    const std::vector<RuleSpec>& rules,
    const std::optional<RuntimeRoutingOperationIdentity>& identity,
    bool inventory_complete,
    bool kernel_state_known) {
    PreparedInventoryPublication prepared;
    prepared.writable = allocate_inventory_snapshot();
    prepared.writable->revision = inventory_revision_ + 1U;
    prepared.writable->highest_consumed_operation_serial =
        highest_consumed_operation_serial_;
    prepared.writable->highest_consumed_runtime_generation =
        highest_consumed_runtime_generation_;
    prepared.writable->highest_consumed_intent_serial =
        highest_consumed_intent_serial_;
    prepared.writable->highest_consumed_route_epoch =
        highest_consumed_route_epoch_;
    prepared.writable->last_identity = identity;
    prepared.writable->inventory_complete = inventory_complete;
    prepared.writable->kernel_state_known = kernel_state_known;
    prepared.writable->routes = routes;
    prepared.writable->rules = rules;
    prepared.immutable = prepared.writable;
    return prepared;
}

std::shared_ptr<RuntimeRoutingInventorySnapshot>
RuntimeRoutingOperationOwner::allocate_inventory_snapshot() {
    auto snapshot = inventory_factory_
        ? inventory_factory_()
        : std::make_shared<RuntimeRoutingInventorySnapshot>();
    if (!snapshot) {
        throw std::bad_alloc();
    }
    return snapshot;
}

RuntimeRoutingInventorySnapshotPtr
RuntimeRoutingOperationOwner::commit_prepared_inventory_locked(
    PreparedInventoryPublication prepared,
    RuntimeRoutingMutationPhase phase,
    RuntimeRoutingOperationOutcome outcome,
    bool advance_revision) noexcept {
    if (advance_revision) ++inventory_revision_;
    prepared.writable->revision = inventory_revision_;
    prepared.writable->phase = phase;
    prepared.writable->outcome = outcome;
    std::atomic_store_explicit(
        &published_inventory_,
        prepared.immutable,
        std::memory_order_release);
    return prepared.immutable;
}

RuntimeRoutingInventorySnapshotPtr
RuntimeRoutingOperationOwner::publish_actual_inventory_or_fallback_locked(
    PreparedInventoryPublication fallback,
    const std::optional<RuntimeRoutingOperationIdentity>& identity,
    RuntimeRoutingMutationPhase phase,
    RuntimeRoutingOperationOutcome outcome,
    bool kernel_state_known,
    bool advance_revision) noexcept {
    try {
        // This copy deliberately happens after the manager operations: stale
        // exact deletes are convergent and can leave an obsolete object in a
        // manager ledger. Publishing desired_* here would hide that retained
        // object from runtime health and the next recovery pass.
        auto actual = prepare_inventory_publication_locked(
            routes_.get_routes(),
            rules_.get_rules(),
            identity,
            /*inventory_complete=*/true,
            kernel_state_known);
        return commit_prepared_inventory_locked(
            std::move(actual), phase, outcome, advance_revision);
    } catch (...) {
        // The fallback and both vectors were allocated before netlink I/O.
        // Never turn a completed kernel generation into a worker failure just
        // because its exact immutable publication could not be allocated.
        // Readers can distinguish the conservative preimage through
        // inventory_complete=false and a later reconciliation will replace
        // it with an exact ledger.
        try {
            Logger::instance().warn(
                "Could not publish exact runtime routing inventory; "
                "retaining a conservative incomplete snapshot");
        } catch (...) {
        }
        fallback.writable->kernel_state_known = kernel_state_known;
        return commit_prepared_inventory_locked(
            std::move(fallback), phase, outcome, advance_revision);
    }
}

void RuntimeRoutingOperationOwner::consume_pending_interface_notifications_locked()
    noexcept {
    try {
        std::set<std::string> pending;
        {
            std::lock_guard<std::mutex> pending_lock(
                pending_interface_mutex_);
            pending.swap(pending_interface_up_);
        }
        for (const auto& interface_name : pending) {
            routes_.notify_interface_up(interface_name);
        }
    } catch (...) {
    }
}

void RuntimeRoutingOperationOwner::discard_pending_interface_notifications_locked()
    noexcept {
    try {
        std::lock_guard<std::mutex> pending_lock(
            pending_interface_mutex_);
        pending_interface_up_.clear();
    } catch (...) {
    }
}

bool RuntimeRoutingOperationOwner::clear_ledgers_locked() {
    auto protected_tables = rules_.clear();
    const auto live_dependency_tables =
        rules_.protect_route_tables_with_live_rules(routes_.get_routes());
    protected_tables.insert(
        live_dependency_tables.begin(), live_dependency_tables.end());
    const auto uncertain_route_tables = routes_.clear(protected_tables);
    return protected_tables.empty() && uncertain_route_tables.empty();
}

RuntimeRoutingInventorySnapshotPtr
RuntimeRoutingOperationOwner::populate_initial_generation(
    const std::vector<RouteSpec>& desired_routes,
    const std::vector<RuleSpec>& desired_rules) {
    std::lock_guard<std::mutex> lock(mutex_);
    bool mutation_boundary_entered = false;
    bool kernel_state_known = true;
    bool desired_routes_live = true;
    PreparedInventoryPublication fallback;
    try {
        consume_pending_interface_notifications_locked();
        fallback = prepare_inventory_publication_locked(
            routes_.get_routes(),
            rules_.get_rules(),
            std::nullopt,
            /*inventory_complete=*/false,
            /*kernel_state_known=*/true);
        const std::set<std::uint32_t> prior_generated_route_tables =
            routes_.live_generated_route_tables();

        // Preserve populate_routing_state(): every route precedes every rule,
        // and a failed initial generation removes the complete owned prefix.
        // The owner can, however, retain a conservative ledger after an
        // uncertain shutdown cleanup. Use the live-aware paths so a repeated
        // startup restores a vanished tracked object instead of mistaking the
        // ledger entry for proof that it is still present in the kernel.
        mutation_boundary_entered = true;
        try {
            desired_routes_live = routes_.add_missing(
                desired_routes, RouteReconcileMode::Strict);
            rules_.add_missing(desired_rules);
        } catch (...) {
            kernel_state_known = clear_ledgers_locked();
            throw;
        }

        routes_.finalize_pending_replacements();
        auto protected_tables = rules_.remove_orphaned_generated(
            desired_rules, prior_generated_route_tables);
        const auto retained_rule_tables =
            rules_.remove_obsolete(desired_rules);
        protected_tables.insert(
            retained_rule_tables.begin(), retained_rule_tables.end());
        const bool rule_cleanup_known = protected_tables.empty();
        const auto live_dependency_tables =
            rules_.protect_route_tables_with_live_rules(
                routes_.get_routes(),
                prior_generated_route_tables,
                desired_rules);
        protected_tables.insert(
            live_dependency_tables.begin(),
            live_dependency_tables.end());
        const auto uncertain_route_tables = routes_.remove_obsolete(
            desired_routes, protected_tables);
        kernel_state_known = desired_routes_live &&
            rule_cleanup_known &&
            uncertain_route_tables.empty();
        routes_.adopt_live_generated_desired(desired_routes);
        try {
            const auto live_tables = routes_.live_generated_route_tables();
            rules_.adopt_live_generated_desired(
                desired_rules, live_tables);
        } catch (...) {
            // Match the existing best-effort post-commit adoption contract.
        }

        return publish_actual_inventory_or_fallback_locked(
            std::move(fallback),
            std::nullopt,
            RuntimeRoutingMutationPhase::complete,
            kernel_state_known
                ? RuntimeRoutingOperationOutcome::compatibility_converged
                : RuntimeRoutingOperationOutcome::
                      compatibility_cleanup_pending,
            kernel_state_known,
            /*advance_revision=*/true);
    } catch (...) {
        if (mutation_boundary_entered && fallback.immutable) {
            (void)publish_actual_inventory_or_fallback_locked(
                std::move(fallback),
                std::nullopt,
                RuntimeRoutingMutationPhase::failed,
                RuntimeRoutingOperationOutcome::partial_failure,
                /*kernel_state_known=*/false,
                mutation_boundary_entered);
        }
        throw;
    }
}

RuntimeRoutingInventorySnapshotPtr
RuntimeRoutingOperationOwner::reconcile_compatibility_generation(
    const std::vector<RouteSpec>& desired_routes,
    const std::vector<RuleSpec>& desired_rules,
    RouteReconcileMode mode,
    RuntimeRoutingCompatibilityFenceProbe current_fence) {
    std::lock_guard<std::mutex> lock(mutex_);
    bool mutation_boundary_entered = false;
    bool kernel_state_known = true;
    bool desired_routes_live = true;
    PreparedInventoryPublication fallback;
    try {
        consume_pending_interface_notifications_locked();
        fallback = prepare_inventory_publication_locked(
            routes_.get_routes(),
            rules_.get_rules(),
            std::nullopt,
            /*inventory_complete=*/false,
            /*kernel_state_known=*/true);
        // Close the check-before-owner race. This compatibility fence is not
        // a kernel CAS and cannot detect an external writer during a netlink
        // call; the exact R1b backend remains responsible for that stronger
        // guarantee.
        if (current_fence && !current_fence()) return {};
        const std::set<std::uint32_t> prior_generated_route_tables =
            routes_.live_generated_route_tables();

        mutation_boundary_entered = true;
        desired_routes_live = routes_.add_missing(desired_routes, mode);
        try {
            rules_.add_missing(desired_rules);
        } catch (...) {
            routes_.rollback_pending_replacements();
            throw;
        }
        routes_.finalize_pending_replacements();
        auto protected_tables = rules_.remove_orphaned_generated(
            desired_rules, prior_generated_route_tables);
        const auto retained_rule_tables =
            rules_.remove_obsolete(desired_rules);
        protected_tables.insert(
            retained_rule_tables.begin(), retained_rule_tables.end());
        const bool rule_cleanup_known = protected_tables.empty();
        const auto live_dependency_tables =
            rules_.protect_route_tables_with_live_rules(
                routes_.get_routes(),
                prior_generated_route_tables,
                desired_rules);
        protected_tables.insert(
            live_dependency_tables.begin(),
            live_dependency_tables.end());
        const auto uncertain_route_tables = routes_.remove_obsolete(
            desired_routes, protected_tables);
        kernel_state_known = desired_routes_live &&
            rule_cleanup_known &&
            uncertain_route_tables.empty();
        routes_.adopt_live_generated_desired(desired_routes);
        try {
            const auto live_tables = routes_.live_generated_route_tables();
            rules_.adopt_live_generated_desired(
                desired_rules, live_tables);
        } catch (...) {
        }

        return publish_actual_inventory_or_fallback_locked(
            std::move(fallback),
            std::nullopt,
            RuntimeRoutingMutationPhase::complete,
            kernel_state_known
                ? RuntimeRoutingOperationOutcome::compatibility_converged
                : RuntimeRoutingOperationOutcome::
                      compatibility_cleanup_pending,
            kernel_state_known,
            /*advance_revision=*/true);
    } catch (...) {
        if (mutation_boundary_entered && fallback.immutable) {
            (void)publish_actual_inventory_or_fallback_locked(
                std::move(fallback),
                std::nullopt,
                RuntimeRoutingMutationPhase::failed,
                RuntimeRoutingOperationOutcome::partial_failure,
                /*kernel_state_known=*/false,
                mutation_boundary_entered);
        }
        throw;
    }
}

RuntimeRoutingOperationResult RuntimeRoutingOperationOwner::reconcile(
    const RuntimeRoutingOperationRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    consume_pending_interface_notifications_locked();

    if (!identity_is_valid(request.identity)) {
        return rejected_result(
            request,
            RuntimeRoutingOperationOutcome::rejected_invalid_identity);
    }
    if (request.identity.operation_serial <=
            highest_consumed_operation_serial_ ||
        request.identity.intent_serial <=
            highest_consumed_intent_serial_ ||
        request.identity.runtime_generation <
            highest_consumed_runtime_generation_ ||
        request.identity.route_epoch < highest_consumed_route_epoch_) {
        return rejected_result(
            request,
            RuntimeRoutingOperationOutcome::rejected_replay);
    }

    // Preallocate a clone before consuming the identity. If allocation fails,
    // the request remains retryable. Once consumed, publish the high-water
    // marks independently of the routing revision so every later failure --
    // including one before the first kernel write -- is externally visible
    // and the same identity cannot appear reusable to a lock-free reader.
    const auto current = std::atomic_load_explicit(
        &published_inventory_, std::memory_order_acquire);
    auto consumed_writable = allocate_inventory_snapshot();
    *consumed_writable = *current;

    const bool base_revision_matches =
        request.identity.base_inventory_revision == inventory_revision_;
    std::shared_ptr<RuntimeRoutingMutationJournal> prepared_journal;
    PreparedInventoryPublication fallback;
    if (base_revision_matches) {
        // Allocate every required terminal object before consuming the
        // identity. An allocation failure therefore leaves the request
        // retryable instead of creating a replay-only operation with no
        // journal/result.
        prepared_journal =
            std::make_shared<RuntimeRoutingMutationJournal>();
        fallback = prepare_inventory_publication_locked(
            routes_.get_routes(),
            rules_.get_rules(),
            request.identity,
            /*inventory_complete=*/false,
            /*kernel_state_known=*/true);
    }

    // Consume every structurally valid serial before checking its base. The
    // same operation cannot later be replayed with a rewritten revision.
    highest_consumed_operation_serial_ =
        request.identity.operation_serial;
    highest_consumed_runtime_generation_ = std::max(
        highest_consumed_runtime_generation_,
        request.identity.runtime_generation);
    highest_consumed_intent_serial_ = request.identity.intent_serial;
    highest_consumed_route_epoch_ = std::max(
        highest_consumed_route_epoch_, request.identity.route_epoch);
    consumed_writable->highest_consumed_operation_serial =
        highest_consumed_operation_serial_;
    consumed_writable->highest_consumed_runtime_generation =
        highest_consumed_runtime_generation_;
    consumed_writable->highest_consumed_intent_serial =
        highest_consumed_intent_serial_;
    consumed_writable->highest_consumed_route_epoch =
        highest_consumed_route_epoch_;
    RuntimeRoutingInventorySnapshotPtr consumed_immutable =
        std::move(consumed_writable);
    std::atomic_store_explicit(
        &published_inventory_,
        std::move(consumed_immutable),
        std::memory_order_release);

    if (!base_revision_matches) {
        // This advances no inventory revision and performs no live/kernel I/O.
        // Publish only the consumed serial so later readers can prove replay
        // rejection without confusing it with a routing-state mutation.
        return rejected_result(
            request,
            RuntimeRoutingOperationOutcome::rejected_stale_inventory);
    }

    fallback.writable->highest_consumed_operation_serial =
        highest_consumed_operation_serial_;
    fallback.writable->highest_consumed_runtime_generation =
        highest_consumed_runtime_generation_;
    fallback.writable->highest_consumed_intent_serial =
        highest_consumed_intent_serial_;
    fallback.writable->highest_consumed_route_epoch =
        highest_consumed_route_epoch_;

    active_journal_ = std::move(prepared_journal);
    active_journal_->identity = request.identity;
    active_journal_->phase = RuntimeRoutingMutationPhase::prepared;

    RuntimeRoutingOperationResult result;
    result.identity = request.identity;
    result.journal = active_journal_;

    bool kernel_state_known = true;
    bool desired_routes_live = true;

    try {
        active_journal_->phase =
            RuntimeRoutingMutationPhase::observing_prior_routes;
        const std::set<std::uint32_t> prior_generated_route_tables =
            routes_.live_generated_route_tables();

        active_journal_->phase =
            RuntimeRoutingMutationPhase::adding_routes;
        active_journal_->mutation_boundary_entered = true;
        desired_routes_live = routes_.add_missing(
            request.desired_routes, request.mode);

        active_journal_->phase =
            RuntimeRoutingMutationPhase::adding_rules;
        try {
            rules_.add_missing(request.desired_rules);
        } catch (...) {
            routes_.rollback_pending_replacements();
            throw;
        }

        active_journal_->phase =
            RuntimeRoutingMutationPhase::committing_replacements;
        routes_.finalize_pending_replacements();

        active_journal_->phase =
            RuntimeRoutingMutationPhase::removing_orphaned_rules;
        auto protected_tables = rules_.remove_orphaned_generated(
            request.desired_rules, prior_generated_route_tables);

        active_journal_->phase =
            RuntimeRoutingMutationPhase::removing_obsolete_rules;
        const auto retained_rule_tables =
            rules_.remove_obsolete(request.desired_rules);
        protected_tables.insert(
            retained_rule_tables.begin(), retained_rule_tables.end());
        const bool rule_cleanup_known = protected_tables.empty();
        const auto live_dependency_tables =
            rules_.protect_route_tables_with_live_rules(
                routes_.get_routes(),
                prior_generated_route_tables,
                request.desired_rules);
        protected_tables.insert(
            live_dependency_tables.begin(),
            live_dependency_tables.end());

        active_journal_->phase =
            RuntimeRoutingMutationPhase::removing_obsolete_routes;
        const auto uncertain_route_tables = routes_.remove_obsolete(
            request.desired_routes, protected_tables);
        kernel_state_known = desired_routes_live &&
            rule_cleanup_known &&
            uncertain_route_tables.empty();

        active_journal_->phase =
            RuntimeRoutingMutationPhase::adopting_committed_inventory;
        routes_.adopt_live_generated_desired(request.desired_routes);
        try {
            const auto live_tables = routes_.live_generated_route_tables();
            rules_.adopt_live_generated_desired(
                request.desired_rules, live_tables);
        } catch (...) {
            // Preserve the compatibility reconciler's best-effort adoption.
            // This facade is not yet the exact production commit authority.
        }

        active_journal_->phase = RuntimeRoutingMutationPhase::complete;
        active_journal_->outcome = kernel_state_known
            ? RuntimeRoutingOperationOutcome::compatibility_converged
            : RuntimeRoutingOperationOutcome::compatibility_cleanup_pending;
        result.outcome = active_journal_->outcome;
        result.inventory = publish_actual_inventory_or_fallback_locked(
            std::move(fallback),
            request.identity,
            RuntimeRoutingMutationPhase::complete,
            result.outcome,
            kernel_state_known,
            /*advance_revision=*/true);
        result.journal = active_journal_;
        return result;
    } catch (const RouteInterfaceUnavailableError& error) {
        active_journal_->phase = RuntimeRoutingMutationPhase::failed;
        active_journal_->outcome =
            RuntimeRoutingOperationOutcome::route_unavailable;
        retain_failure_detail(*active_journal_, error.what());
        result.outcome = RuntimeRoutingOperationOutcome::route_unavailable;
    } catch (const std::exception& error) {
        active_journal_->phase = RuntimeRoutingMutationPhase::failed;
        active_journal_->outcome =
            RuntimeRoutingOperationOutcome::partial_failure;
        retain_failure_detail(*active_journal_, error.what());
        result.outcome = RuntimeRoutingOperationOutcome::partial_failure;
    } catch (...) {
        active_journal_->phase = RuntimeRoutingMutationPhase::failed;
        active_journal_->outcome =
            RuntimeRoutingOperationOutcome::partial_failure;
        retain_failure_detail(
            *active_journal_, "routing reconciliation failed");
        result.outcome = RuntimeRoutingOperationOutcome::partial_failure;
    }

    if (active_journal_->mutation_boundary_entered) {
        result.inventory = publish_actual_inventory_or_fallback_locked(
            std::move(fallback),
            request.identity,
            RuntimeRoutingMutationPhase::failed,
            result.outcome,
            /*kernel_state_known=*/false,
            /*advance_revision=*/true);
    } else {
        // A failed observation or fence before the first write cannot make a
        // previously authoritative inventory incomplete.
        result.inventory = snapshot();
    }
    result.journal = active_journal_;
    return result;
}

void RuntimeRoutingOperationOwner::notify_interface_up(
    const std::string& interface_name) noexcept {
    if (interface_name.empty()) return;
    try {
        std::unique_lock<std::mutex> owner_lock(
            mutex_, std::try_to_lock);
        if (owner_lock.owns_lock()) {
            consume_pending_interface_notifications_locked();
            routes_.notify_interface_up(interface_name);
            return;
        }
        std::lock_guard<std::mutex> pending_lock(
            pending_interface_mutex_);
        pending_interface_up_.insert(interface_name);
    } catch (...) {
    }
}

RuntimeRoutingInventorySnapshotPtr
RuntimeRoutingOperationOwner::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    PreparedInventoryPublication fallback;
    try {
        fallback = prepare_inventory_publication_locked(
            routes_.get_routes(),
            rules_.get_rules(),
            std::nullopt,
            /*inventory_complete=*/false,
            /*kernel_state_known=*/true);
        const bool kernel_state_known = clear_ledgers_locked();
        discard_pending_interface_notifications_locked();
        active_journal_.reset();
        return publish_actual_inventory_or_fallback_locked(
            std::move(fallback),
            std::nullopt,
            kernel_state_known
                ? RuntimeRoutingMutationPhase::cleared
                : RuntimeRoutingMutationPhase::failed,
            kernel_state_known
                ? RuntimeRoutingOperationOutcome::cleared
                : RuntimeRoutingOperationOutcome::partial_failure,
            kernel_state_known,
            /*advance_revision=*/true);
    } catch (...) {
        if (fallback.immutable) {
            (void)publish_actual_inventory_or_fallback_locked(
                std::move(fallback),
                std::nullopt,
                RuntimeRoutingMutationPhase::failed,
                RuntimeRoutingOperationOutcome::partial_failure,
                /*kernel_state_known=*/false,
                /*advance_revision=*/true);
        }
        throw;
    }
}

} // namespace keen_pbr3
