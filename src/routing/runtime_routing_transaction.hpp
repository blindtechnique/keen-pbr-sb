#pragma once

#include <cstdint>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "netlink.hpp"

namespace keen_pbr3 {

struct RuntimeRoutingTransactionIdentity {
    std::uint64_t operation_serial{0};
    std::uint64_t runtime_generation{0};
    std::uint64_t intent_serial{0};
    std::uint64_t base_inventory_revision{0};
    std::uint64_t route_epoch{0};
};

// Explicit authority for a user-selected kernel table which is not populated
// by a keen-pbr protocol-186 route.  TABLE outbounds are valid only when this
// exact table/family authority is part of the immutable request and the table
// is observed non-empty immediately before its rule becomes active.
struct RuntimeRoutingExternalTableAuthority {
    std::uint32_t table{0};
    int family{0};
};

// Supplied by the single persistent owner immediately before execution.  The
// transaction is deliberately stateless: replay tracking remains the owner's
// responsibility and a stale request is rejected before the first netlink I/O.
struct RuntimeRoutingCurrentFence {
    std::uint64_t last_operation_serial{0};
    std::uint64_t runtime_generation{0};
    std::uint64_t intent_serial{0};
    std::uint64_t inventory_revision{0};
    std::uint64_t route_epoch{0};
};

struct RuntimeRoutingTransactionRequest {
    RuntimeRoutingTransactionIdentity identity;
    std::vector<RouteSpec> desired_routes;
    std::vector<RuleSpec> desired_rules;
    // Exact owner ledger from the request's base inventory.  It is the primary
    // source for retiring old TABLE rules; kernel heuristics are recovery-only.
    std::vector<RuleSpec> prior_owned_rules;
    std::vector<RuntimeRoutingExternalTableAuthority>
        authorized_external_tables;
    // Restart recovery may explicitly opt into the legacy kernel-shape
    // heuristic. Normal transactions delete rules only from prior_owned_rules.
    bool allow_recovery_rule_heuristic{false};
};

enum class RuntimeRoutingTerminal {
    prepared,
    running,
    stale_before_mutation,
    candidate_rolled_back,
    candidate_committed,
    committed_cleanup_pending,
    partial_unknown,
    precondition_failed,
};

enum class RuntimeRoutingFailureStage : std::uint8_t {
    none,
    journal_publish,
    fence,
    candidate_route,
    candidate_rule_dependency,
    candidate_rule,
    candidate_verify,
    rollback_rule,
    rollback_route,
    cleanup_rule,
    cleanup_route,
    committed_verify,
    unexpected_exception,
};

enum class RuntimeRoutingStaleReason {
    none,
    zero_identity,
    replayed_operation,
    runtime_generation_changed,
    intent_changed,
    inventory_revision_changed,
    route_epoch_changed,
};

enum class RuntimeRoutingJournalOperation {
    add_candidate_route,
    replace_candidate_route,
    add_candidate_rule,
    verify_candidate,
    delete_stale_rule,
    verify_stale_rule_absence,
    delete_obsolete_route,
    verify_committed_state,
    rollback_created_rule,
    rollback_created_route,
    restore_replaced_route,
};

enum class RuntimeRoutingJournalState {
    planned,
    completed,
    verified,
    rolled_back,
    skipped,
    failed,
    unknown,
};

enum class RuntimeRoutingJournalReceipt : std::uint8_t {
    none,
    created,
    already_present,
    replaced,
    deleted_or_absent,
    precondition_mismatch,
    effect_unknown,
};

struct RuntimeRoutingJournalEntry {
    RuntimeRoutingJournalOperation operation;
    RuntimeRoutingJournalState state{RuntimeRoutingJournalState::planned};
    RuntimeRoutingJournalReceipt receipt{
        RuntimeRoutingJournalReceipt::none};
    std::optional<RouteSpec> route;
    std::optional<RuleSpec> rule;
};

// Lifetime-owned record published before the first kernel write.  Publishers
// and results receive only shared_ptr<const ...>, so they cannot invalidate
// the precomputed receipt indices. The executor is the sole entries writer.
//
// Reader protocol: acquire-load terminal first. While it is prepared/running,
// entries must not be read (the synchronous publisher callback itself runs
// before the executor starts and may inspect the immutable payloads). Once a
// terminal value is observed, its release/acquire edge makes every entry state
// and receipt stable for the rest of the record lifetime.
struct RuntimeRoutingPublishedJournal {
    RuntimeRoutingTransactionIdentity identity;
    std::vector<RuntimeRoutingJournalEntry> entries;
    std::atomic<RuntimeRoutingTerminal> terminal{
        RuntimeRoutingTerminal::prepared};
    std::atomic<RuntimeRoutingFailureStage> failure_stage{
        RuntimeRoutingFailureStage::none};
    std::atomic<bool> mutation_started{false};
    std::atomic<bool> candidate_exact_verified{false};

    RuntimeRoutingTerminal acquire_terminal() const noexcept {
        return terminal.load(std::memory_order_acquire);
    }

    static bool entries_stable_after(
        RuntimeRoutingTerminal acquired_terminal) noexcept {
        return acquired_terminal != RuntimeRoutingTerminal::prepared &&
               acquired_terminal != RuntimeRoutingTerminal::running;
    }
};

using RuntimeRoutingPublishedJournalPtr =
    std::shared_ptr<const RuntimeRoutingPublishedJournal>;
using RuntimeRoutingJournalPublisher = std::function<bool(
    const RuntimeRoutingPublishedJournalPtr&)>;

struct RuntimeRoutingTransactionResult {
    RuntimeRoutingTransactionIdentity identity;
    RuntimeRoutingTerminal terminal{RuntimeRoutingTerminal::precondition_failed};
    RuntimeRoutingStaleReason stale_reason{RuntimeRoutingStaleReason::none};
    bool mutation_started{false};
    bool candidate_exact_verified{false};
    bool stale_rule_absence_proven{false};
    bool route_cleanup_attempted{false};
    std::string detail;
    std::vector<RuntimeRoutingJournalEntry> journal;
    RuntimeRoutingPublishedJournalPtr published_journal;
};

using RuntimeRoutingCurrentFenceProbe =
    std::function<RuntimeRoutingCurrentFence()>;

// Executes one exact combined route/rule transaction.  It owns no thread and
// performs no persistence; callers must serialize it through one durable
// operation owner.  Every possible forward, cleanup, and rollback entry is
// allocated before the first mutating netlink call.
//
// Production wiring is intentionally blocked until its backend can provide an
// honest complete rule inventory plus exclusive/conditional route replacement
// and rule deletion. NetlinkManager currently fails those exact operations
// closed; the transaction is a locally verified prerequisite, not production
// authority.
RuntimeRoutingTransactionResult execute_runtime_routing_transaction(
    const RuntimeRoutingTransactionRequest& request,
    const RuntimeRoutingCurrentFenceProbe& current_fence,
    RouteNetlinkOperations& route_netlink,
    RuleNetlinkOperations& rule_netlink,
    const RuntimeRoutingJournalPublisher& publish_journal);

} // namespace keen_pbr3
