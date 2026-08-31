#include "runtime_routing_transaction.hpp"

#include "policy_rule.hpp"
#include "route_table.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <exception>
#include <iterator>
#include <netinet/in.h>
#include <set>
#include <utility>

namespace keen_pbr3 {
namespace {

using Journal = std::vector<RuntimeRoutingJournalEntry>;

struct PlannedRouteMutation {
    RouteSpec candidate;
    std::vector<RouteSpec> preimages;
    std::size_t forward_journal{0};
    std::vector<std::size_t> rollback_journals;
    bool replace{false};
    bool created_receipt{false};
    bool replacement_receipt{false};
};

struct PlannedRuleMutation {
    RuleSpec candidate;
    std::size_t forward_journal{0};
    std::size_t rollback_journal{0};
    bool created_receipt{false};
};

struct PlannedCleanupRule {
    RuleSpec stale;
    std::size_t journal{0};
};

struct PlannedCleanupRoute {
    RouteSpec stale;
    std::size_t journal{0};
};

struct Plan {
    std::vector<PlannedRouteMutation> routes;
    std::vector<PlannedRuleMutation> rules;
    std::vector<PlannedCleanupRule> stale_rules;
    std::vector<PlannedCleanupRoute> stale_routes;
    std::size_t candidate_verify_journal{0};
    std::size_t stale_absence_journal{0};
    std::size_t committed_verify_journal{0};
    std::set<std::uint32_t> corroborated_tables;
    std::shared_ptr<RuntimeRoutingPublishedJournal> published_journal;
};

Journal& journal(Plan& plan) noexcept {
    return plan.published_journal->entries;
}

bool identity_has_zero(const RuntimeRoutingTransactionIdentity& identity) {
    return identity.operation_serial == 0 ||
           identity.runtime_generation == 0 ||
           identity.intent_serial == 0 ||
           identity.base_inventory_revision == 0 ||
           identity.route_epoch == 0;
}

RuntimeRoutingStaleReason stale_reason(
    const RuntimeRoutingTransactionIdentity& identity,
    const RuntimeRoutingCurrentFence& current) noexcept {
    if (identity_has_zero(identity)) {
        return RuntimeRoutingStaleReason::zero_identity;
    }
    if (identity.operation_serial <= current.last_operation_serial) {
        return RuntimeRoutingStaleReason::replayed_operation;
    }
    if (identity.runtime_generation != current.runtime_generation) {
        return RuntimeRoutingStaleReason::runtime_generation_changed;
    }
    if (identity.intent_serial != current.intent_serial) {
        return RuntimeRoutingStaleReason::intent_changed;
    }
    if (identity.base_inventory_revision != current.inventory_revision) {
        return RuntimeRoutingStaleReason::inventory_revision_changed;
    }
    if (identity.route_epoch != current.route_epoch) {
        return RuntimeRoutingStaleReason::route_epoch_changed;
    }
    return RuntimeRoutingStaleReason::none;
}

enum class FenceProbeState {
    current,
    stale,
    unavailable,
};

FenceProbeState observe_fence(
    const RuntimeRoutingTransactionRequest& request,
    const RuntimeRoutingCurrentFenceProbe& probe,
    RuntimeRoutingStaleReason& observed_reason) noexcept {
    if (!probe) return FenceProbeState::unavailable;
    try {
        observed_reason = stale_reason(request.identity, probe());
        return observed_reason == RuntimeRoutingStaleReason::none
            ? FenceProbeState::current
            : FenceProbeState::stale;
    } catch (...) {
        observed_reason = RuntimeRoutingStaleReason::none;
        return FenceProbeState::unavailable;
    }
}

RuntimeRoutingJournalEntry route_entry(
    RuntimeRoutingJournalOperation operation,
    const RouteSpec& route) {
    RuntimeRoutingJournalEntry entry;
    entry.operation = operation;
    entry.route = route;
    return entry;
}

RuntimeRoutingJournalEntry rule_entry(
    RuntimeRoutingJournalOperation operation,
    const RuleSpec& rule) {
    RuntimeRoutingJournalEntry entry;
    entry.operation = operation;
    entry.rule = rule;
    return entry;
}

RuntimeRoutingJournalEntry marker_entry(
    RuntimeRoutingJournalOperation operation) {
    RuntimeRoutingJournalEntry entry;
    entry.operation = operation;
    return entry;
}

std::uint32_t exact_route_kernel_metric(
    std::uint32_t metric,
    int family) noexcept {
    return family == AF_INET6 && metric == 0U ? 1024U : metric;
}

bool exact_route_same_slot(
    const RouteSpec& expected,
    const DumpedRoute& actual) noexcept {
    return expected.destination == actual.destination &&
           expected.table == actual.table &&
           expected.family == actual.family &&
           exact_route_kernel_metric(expected.metric, expected.family) ==
               exact_route_kernel_metric(actual.metric, actual.family);
}

bool exact_route_matches_live(
    const RouteSpec& expected,
    const DumpedRoute& actual) noexcept {
    return actual.exact_identity_representable &&
           exact_route_same_slot(expected, actual) &&
           expected.interface == actual.interface &&
           expected.gateway == actual.gateway &&
           expected.blackhole == actual.blackhole &&
           expected.unreachable == actual.unreachable &&
           expected.protocol == actual.protocol;
}

bool route_present(const RouteSpec& expected,
                   const std::vector<DumpedRoute>& live) {
    return std::any_of(
        live.begin(), live.end(), [&](const DumpedRoute& candidate) {
            return exact_route_matches_live(expected, candidate);
        });
}

bool route_specs_equal(const RouteSpec& left, const RouteSpec& right) {
    return left.destination == right.destination &&
           left.table == right.table &&
           left.interface == right.interface &&
           left.gateway == right.gateway &&
           left.blackhole == right.blackhole &&
           left.unreachable == right.unreachable &&
           left.family == right.family &&
           left.metric == right.metric &&
           left.protocol == right.protocol;
}

bool canonical_address_for_family(
    const std::string& address,
    int family) noexcept {
    std::array<unsigned char, sizeof(in6_addr)> binary{};
    if (inet_pton(family, address.c_str(), binary.data()) != 1) {
        return false;
    }
    std::array<char, INET6_ADDRSTRLEN> canonical{};
    if (inet_ntop(
            family,
            binary.data(),
            canonical.data(),
            canonical.size()) == nullptr) {
        return false;
    }
    return address == canonical.data();
}

DumpedRoute dumped_route_from_spec(const RouteSpec& spec) {
    return DumpedRoute{
        spec.destination,
        spec.table,
        spec.interface,
        spec.gateway,
        spec.blackhole,
        spec.unreachable,
        spec.family,
        spec.metric,
        spec.protocol};
}

bool slot_matches_preimages(
    const RouteSpec& candidate,
    const std::vector<RouteSpec>& preimages,
    const std::vector<DumpedRoute>& live) {
    std::vector<RouteSpec> current;
    current.reserve(preimages.size());
    for (const auto& route : live) {
        if (exact_route_same_slot(candidate, route)) {
            if (!route.exact_identity_representable) return false;
            current.push_back(
                route_table_detail::route_spec_from_live(route));
        }
    }
    if (current.size() != preimages.size()) return false;
    return std::all_of(
        preimages.begin(), preimages.end(), [&](const RouteSpec& previous) {
            return std::any_of(
                current.begin(), current.end(), [&](const RouteSpec& actual) {
                    return route_specs_equal(previous, actual);
                });
        });
}

enum class ExactSlotState {
    empty,
    exact_single,
    mismatch,
};

ExactSlotState exact_slot_state(
    const RouteSpec& expected,
    const std::vector<DumpedRoute>& live) {
    std::size_t slot_count = 0U;
    bool exact = false;
    for (const auto& route : live) {
        if (!exact_route_same_slot(expected, route)) {
            continue;
        }
        ++slot_count;
        exact = exact || exact_route_matches_live(expected, route);
    }
    if (slot_count == 0U) return ExactSlotState::empty;
    if (slot_count == 1U && exact) return ExactSlotState::exact_single;
    return ExactSlotState::mismatch;
}

bool rule_present(const RuleSpec& expected,
                  const std::vector<DumpedRule>& live) {
    return std::any_of(
        live.begin(), live.end(), [&](const DumpedRule& candidate) {
            return candidate.exact_identity_representable &&
                   policy_rule_detail::rule_matches_live(expected, candidate);
        });
}

bool rule_occupies_same_identity(
    const RuleSpec& expected,
    const DumpedRule& actual) noexcept {
    return expected.fwmark == actual.fwmark &&
           expected.fwmask == actual.fwmask &&
           expected.table == actual.table &&
           expected.priority == actual.priority &&
           expected.family == actual.family;
}

ExactSlotState exact_rule_state(
    const RuleSpec& expected,
    const std::vector<DumpedRule>& live) {
    std::size_t identity_count = 0U;
    bool exact = false;
    for (const auto& rule : live) {
        if (!rule_occupies_same_identity(expected, rule)) {
            continue;
        }
        ++identity_count;
        exact = exact ||
            (rule.exact_identity_representable &&
             policy_rule_detail::rule_matches_live(expected, rule));
    }
    if (identity_count == 0U) return ExactSlotState::empty;
    if (identity_count == 1U && exact) {
        return ExactSlotState::exact_single;
    }
    return ExactSlotState::mismatch;
}

std::vector<RuleSpec> concrete_rules(
    const std::vector<RuleSpec>& logical_rules) {
    std::vector<RuleSpec> concrete;
    concrete.reserve(logical_rules.size() * 2);
    for (const auto& logical : logical_rules) {
        if (logical.family == 0) {
            for (const int family : {AF_INET, AF_INET6}) {
                RuleSpec value = logical;
                value.family = family;
                if (std::none_of(
                        concrete.begin(), concrete.end(),
                        [&](const RuleSpec& candidate) {
                            return candidate.fwmark == value.fwmark &&
                                   candidate.fwmask == value.fwmask &&
                                   candidate.table == value.table &&
                                   candidate.priority == value.priority &&
                                   candidate.family == value.family;
                        })) {
                    concrete.push_back(std::move(value));
                }
            }
        } else if (std::none_of(
                       concrete.begin(), concrete.end(),
                       [&](const RuleSpec& candidate) {
                           return candidate.fwmark == logical.fwmark &&
                                  candidate.fwmask == logical.fwmask &&
                                  candidate.table == logical.table &&
                                  candidate.priority == logical.priority &&
                                  candidate.family == logical.family;
                       })) {
            concrete.push_back(logical);
        }
    }
    return concrete;
}

bool desired_managed_anchor(
    const RuleSpec& rule,
    const std::vector<RouteSpec>& desired_routes) {
    return std::any_of(
        desired_routes.begin(), desired_routes.end(),
        [&](const RouteSpec& route) {
            return route.table == rule.table && route.family == rule.family;
        });
}

bool external_table_authorized(
    const RuleSpec& rule,
    const std::vector<RuntimeRoutingExternalTableAuthority>& authorities) {
    return std::any_of(
        authorities.begin(), authorities.end(),
        [&](const RuntimeRoutingExternalTableAuthority& authority) {
            return authority.table == rule.table &&
                   authority.family == rule.family;
        });
}

bool rule_dependency_present(
    const RuntimeRoutingTransactionRequest& request,
    const RuleSpec& rule,
    const std::vector<DumpedRoute>& live_routes) {
    if (desired_managed_anchor(rule, request.desired_routes)) {
        return std::any_of(
            request.desired_routes.begin(), request.desired_routes.end(),
            [&](const RouteSpec& route) {
                return route.table == rule.table &&
                       route.family == rule.family &&
                       exact_slot_state(route, live_routes) ==
                           ExactSlotState::exact_single;
            });
    }
    return external_table_authorized(
        rule, request.authorized_external_tables);
}

bool all_rule_dependencies_present(
    const RuntimeRoutingTransactionRequest& request,
    const std::vector<DumpedRoute>& live_routes) {
    const auto desired_concrete = concrete_rules(request.desired_rules);
    return std::all_of(
        desired_concrete.begin(), desired_concrete.end(),
        [&](const RuleSpec& rule) {
            return rule_dependency_present(request, rule, live_routes);
        });
}

std::string exception_detail(const char* stage) {
    try {
        throw;
    } catch (const std::exception& error) {
        return std::string(stage) + ": " + error.what();
    } catch (...) {
        return std::string(stage) + ": unknown exception";
    }
}

bool all_desired_exact(
    const RuntimeRoutingTransactionRequest& request,
    const std::vector<DumpedRoute>& routes,
    const std::vector<DumpedRule>& rules) {
    if (!std::all_of(
            request.desired_routes.begin(), request.desired_routes.end(),
            [&](const RouteSpec& route) {
                return exact_slot_state(route, routes) ==
                    ExactSlotState::exact_single;
            })) {
        return false;
    }
    if (!all_rule_dependencies_present(request, routes)) {
        return false;
    }
    const auto desired_concrete = concrete_rules(request.desired_rules);
    return std::all_of(
        desired_concrete.begin(), desired_concrete.end(),
        [&](const RuleSpec& rule) {
            return exact_rule_state(rule, rules) ==
                ExactSlotState::exact_single;
        });
}

bool expected_inventory_exact(
    const std::vector<RouteSpec>& expected_routes,
    const std::vector<RuleSpec>& expected_rules,
    const std::vector<DumpedRoute>& live_routes,
    const std::vector<DumpedRule>& live_rules) {
    if (!std::all_of(
            expected_routes.begin(), expected_routes.end(),
            [&](const RouteSpec& route) {
                return exact_slot_state(route, live_routes) ==
                    ExactSlotState::exact_single;
            })) {
        return false;
    }

    const bool has_unexpected_generated_route = std::any_of(
        live_routes.begin(), live_routes.end(),
        [&](const DumpedRoute& live) {
            if (!route_table_detail::is_generated_route_candidate(live)) {
                return false;
            }
            return std::none_of(
                expected_routes.begin(), expected_routes.end(),
                [&](const RouteSpec& expected) {
                    return exact_route_matches_live(expected, live);
                });
        });
    if (has_unexpected_generated_route) return false;

    const auto concrete = concrete_rules(expected_rules);
    return std::all_of(
        concrete.begin(), concrete.end(), [&](const RuleSpec& rule) {
            return exact_rule_state(rule, live_rules) ==
                ExactSlotState::exact_single;
        });
}

std::optional<Plan> build_plan(
    const RuntimeRoutingTransactionRequest& request,
    const std::vector<DumpedRoute>& live_routes,
    const std::vector<DumpedRule>& live_rules,
    std::string& error) {
    Plan plan;
    plan.published_journal =
        std::make_shared<RuntimeRoutingPublishedJournal>();
    plan.published_journal->identity = request.identity;
    for (const auto& authority : request.authorized_external_tables) {
        if (authority.table == 0 ||
            (authority.family != AF_INET && authority.family != AF_INET6)) {
            error = "external table authority is invalid";
            return std::nullopt;
        }
    }
    for (const auto& logical : request.desired_rules) {
        if (logical.family != 0 && logical.family != AF_INET &&
            logical.family != AF_INET6) {
            error = "candidate rule has an unsupported address family";
            return std::nullopt;
        }
        if (logical.priority == 0 || logical.table == 0 ||
            logical.fwmark == 0 || logical.fwmask == 0) {
            error = "candidate rule contains a wildcard identity field";
            return std::nullopt;
        }
    }
    for (const auto& prior : request.prior_owned_rules) {
        if (prior.family != 0 && prior.family != AF_INET &&
            prior.family != AF_INET6) {
            error = "prior owned rule has an unsupported address family";
            return std::nullopt;
        }
        if (prior.priority == 0 || prior.table == 0 ||
            prior.fwmark == 0 || prior.fwmask == 0) {
            error = "prior owned rule contains a wildcard identity field";
            return std::nullopt;
        }
    }
    const auto desired_concrete = concrete_rules(request.desired_rules);
    for (const auto& rule : desired_concrete) {
        const bool managed = desired_managed_anchor(
            rule, request.desired_routes);
        const bool external = external_table_authorized(
            rule, request.authorized_external_tables);
        if (!managed && !external) {
            error = "candidate rule has no owned route anchor or external table authority";
            return std::nullopt;
        }
    }

    for (std::size_t index = 0U;
         index < request.desired_routes.size(); ++index) {
        const auto& candidate = request.desired_routes[index];
        if (candidate.family != AF_INET && candidate.family != AF_INET6) {
            error = "candidate route must have an explicit address family";
            return std::nullopt;
        }
        // The runtime transaction currently owns only policy-table default
        // routes. Reject textual aliases instead of writing one kernel image
        // and then comparing its canonical dump with a different input string.
        if (candidate.destination != "default") {
            error = "candidate route destination is not canonical default";
            return std::nullopt;
        }
        if (candidate.blackhole && candidate.unreachable) {
            error = "candidate route has conflicting terminal route types";
            return std::nullopt;
        }
        if ((candidate.blackhole || candidate.unreachable) &&
            (candidate.interface.has_value() ||
             candidate.gateway.has_value())) {
            error =
                "terminal candidate route cannot contain a nexthop";
            return std::nullopt;
        }
        if (candidate.interface.has_value() && candidate.interface->empty()) {
            error = "candidate route contains an empty interface identity";
            return std::nullopt;
        }
        if (candidate.gateway.has_value() &&
            !canonical_address_for_family(
                *candidate.gateway, candidate.family)) {
            error = "candidate route gateway is not canonical for its family";
            return std::nullopt;
        }
        if (!candidate.blackhole && !candidate.unreachable &&
            !candidate.interface.has_value() &&
            !candidate.gateway.has_value()) {
            error = "unicast candidate route has no nexthop identity";
            return std::nullopt;
        }
        const auto ownership_probe = dumped_route_from_spec(candidate);
        if (!route_table_detail::is_generated_route_candidate(
                ownership_probe)) {
            error = "candidate route is outside the keen-pbr ownership namespace";
            return std::nullopt;
        }
        bool duplicate = false;
        for (std::size_t previous = 0U; previous < index; ++previous) {
            const auto& earlier = request.desired_routes[previous];
            if (route_specs_equal(candidate, earlier)) {
                duplicate = true;
                break;
            }
            if (exact_route_same_slot(
                    candidate, dumped_route_from_spec(earlier))) {
                error = "two candidate routes occupy the same kernel slot";
                return std::nullopt;
            }
        }
        if (duplicate) continue;
        const auto live_state = exact_slot_state(candidate, live_routes);
        if (live_state == ExactSlotState::exact_single) {
            continue;
        }
        if (live_state == ExactSlotState::mismatch &&
            route_present(candidate, live_routes)) {
            error = "candidate route is not the only image in its kernel slot";
            return std::nullopt;
        }
        std::vector<RouteSpec> collisions;
        for (const auto& live : live_routes) {
            if (!exact_route_same_slot(candidate, live)) {
                continue;
            }
            if (!live.exact_identity_representable ||
                !route_table_detail::is_generated_route_candidate(live)) {
                error = "foreign route occupies a candidate kernel slot";
                return std::nullopt;
            }
            collisions.push_back(route_table_detail::route_spec_from_live(live));
        }
        if (collisions.size() > 1U) {
            error = "multiple managed routes occupy a candidate kernel slot";
            return std::nullopt;
        }
        PlannedRouteMutation mutation;
        mutation.candidate = candidate;
        mutation.preimages = std::move(collisions);
        mutation.replace = !mutation.preimages.empty();
        mutation.forward_journal = journal(plan).size();
        journal(plan).push_back(route_entry(
            mutation.replace
                ? RuntimeRoutingJournalOperation::replace_candidate_route
                : RuntimeRoutingJournalOperation::add_candidate_route,
            candidate));
        if (mutation.replace) {
            mutation.rollback_journals.reserve(mutation.preimages.size());
            for (const auto& preimage : mutation.preimages) {
                mutation.rollback_journals.push_back(journal(plan).size());
                journal(plan).push_back(route_entry(
                    RuntimeRoutingJournalOperation::restore_replaced_route,
                    preimage));
            }
        } else {
            mutation.rollback_journals.push_back(journal(plan).size());
            journal(plan).push_back(route_entry(
                RuntimeRoutingJournalOperation::rollback_created_route,
                candidate));
        }
        plan.routes.push_back(std::move(mutation));
    }

    for (const auto& candidate : desired_concrete) {
        const auto live_state = exact_rule_state(candidate, live_rules);
        if (live_state == ExactSlotState::exact_single) {
            continue;
        }
        if (live_state == ExactSlotState::mismatch) {
            error = "foreign or unrepresentable rule occupies a candidate identity";
            return std::nullopt;
        }
        PlannedRuleMutation mutation;
        mutation.candidate = candidate;
        mutation.forward_journal = journal(plan).size();
        journal(plan).push_back(rule_entry(
            RuntimeRoutingJournalOperation::add_candidate_rule, candidate));
        mutation.rollback_journal = journal(plan).size();
        journal(plan).push_back(rule_entry(
            RuntimeRoutingJournalOperation::rollback_created_rule, candidate));
        plan.rules.push_back(std::move(mutation));
    }

    plan.candidate_verify_journal = journal(plan).size();
    journal(plan).push_back(marker_entry(
        RuntimeRoutingJournalOperation::verify_candidate));

    for (const auto& route : live_routes) {
        if (route.exact_identity_representable &&
            route_table_detail::is_generated_route_candidate(route)) {
            plan.corroborated_tables.insert(route.table);
        }
    }
    std::vector<RuleSpec> stale_rules;
    if (request.allow_recovery_rule_heuristic) {
        stale_rules = policy_rule_detail::find_orphaned_generated_rules(
            request.desired_rules, live_rules, plan.corroborated_tables);
    }
    const auto prior_owned_concrete = concrete_rules(request.prior_owned_rules);
    for (const auto& prior : prior_owned_concrete) {
        if (!rule_present(prior, live_rules)) {
            continue;
        }
        const bool still_desired = std::any_of(
            desired_concrete.begin(), desired_concrete.end(),
            [&](const RuleSpec& desired) {
                return desired.fwmark == prior.fwmark &&
                       desired.fwmask == prior.fwmask &&
                       desired.table == prior.table &&
                       desired.priority == prior.priority &&
                       desired.family == prior.family;
            });
        const bool already_planned = std::any_of(
            stale_rules.begin(), stale_rules.end(),
            [&](const RuleSpec& stale) {
                return stale.fwmark == prior.fwmark &&
                       stale.fwmask == prior.fwmask &&
                       stale.table == prior.table &&
                       stale.priority == prior.priority &&
                       stale.family == prior.family;
            });
        if (!still_desired && !already_planned) {
            stale_rules.push_back(prior);
        }
    }
    for (const auto& stale : stale_rules) {
        PlannedCleanupRule cleanup;
        cleanup.stale = stale;
        cleanup.journal = journal(plan).size();
        journal(plan).push_back(rule_entry(
            RuntimeRoutingJournalOperation::delete_stale_rule, stale));
        plan.stale_rules.push_back(std::move(cleanup));
    }
    plan.stale_absence_journal = journal(plan).size();
    journal(plan).push_back(marker_entry(
        RuntimeRoutingJournalOperation::verify_stale_rule_absence));

    for (const auto& live : live_routes) {
        if (!route_table_detail::is_generated_route_candidate(live)) {
            continue;
        }
        const bool desired = std::any_of(
            request.desired_routes.begin(), request.desired_routes.end(),
            [&](const RouteSpec& candidate) {
                return exact_route_matches_live(candidate, live);
            });
        if (desired) {
            continue;
        }
        // A replacement already owns retirement of its exact old image. A
        // later delete built from that old image can match the kernel slot
        // rather than every nexthop field and must never delete the committed
        // candidate occupying the same slot.
        const bool replacement_slot = std::any_of(
            request.desired_routes.begin(), request.desired_routes.end(),
            [&](const RouteSpec& candidate) {
                return exact_route_same_slot(candidate, live);
            });
        if (replacement_slot) continue;
        PlannedCleanupRoute cleanup;
        cleanup.stale = route_table_detail::route_spec_from_live(live);
        cleanup.journal = journal(plan).size();
        journal(plan).push_back(route_entry(
            RuntimeRoutingJournalOperation::delete_obsolete_route,
            cleanup.stale));
        plan.stale_routes.push_back(std::move(cleanup));
    }
    plan.committed_verify_journal = journal(plan).size();
    journal(plan).push_back(marker_entry(
        RuntimeRoutingJournalOperation::verify_committed_state));
    return plan;
}

bool verify_created_rules_absent(
    const std::vector<PlannedRuleMutation>& rules,
    RuleNetlinkOperations& netlink) {
    const auto live = netlink.dump_policy_rules();
    return std::none_of(
        rules.begin(), rules.end(), [&](const PlannedRuleMutation& mutation) {
            return mutation.created_receipt &&
                   exact_rule_state(mutation.candidate, live) !=
                       ExactSlotState::empty;
        });
}

bool rollback_candidate(
    Plan& plan,
    RouteNetlinkOperations& route_netlink,
    RuleNetlinkOperations& rule_netlink,
    RuntimeRoutingFailureStage& failure_stage) noexcept {
    for (auto it = plan.rules.rbegin(); it != plan.rules.rend(); ++it) {
        auto& rollback_entry = journal(plan)[it->rollback_journal];
        if (!it->created_receipt) {
            rollback_entry.state = RuntimeRoutingJournalState::skipped;
            continue;
        }
        try {
            const auto receipt = rule_netlink.delete_rule_if_exact(
                it->candidate, it->candidate.family);
            if (receipt == RuleExactDeleteResult::PreconditionMismatch) {
                rollback_entry.receipt =
                    RuntimeRoutingJournalReceipt::precondition_mismatch;
                rollback_entry.state = RuntimeRoutingJournalState::unknown;
                failure_stage = RuntimeRoutingFailureStage::rollback_rule;
                continue;
            }
            rollback_entry.receipt =
                RuntimeRoutingJournalReceipt::deleted_or_absent;
            rollback_entry.state = RuntimeRoutingJournalState::rolled_back;
        } catch (...) {
            rollback_entry.receipt =
                RuntimeRoutingJournalReceipt::effect_unknown;
            rollback_entry.state = RuntimeRoutingJournalState::unknown;
        }
    }

    try {
        if (!verify_created_rules_absent(plan.rules, rule_netlink)) {
            failure_stage = RuntimeRoutingFailureStage::rollback_rule;
            return false;
        }
    } catch (...) {
        failure_stage = RuntimeRoutingFailureStage::rollback_rule;
        return false;
    }

    for (auto it = plan.routes.rbegin(); it != plan.routes.rend(); ++it) {
        auto set_rollback_state = [&](RuntimeRoutingJournalState state) {
            for (const auto index : it->rollback_journals) {
                journal(plan)[index].state = state;
            }
        };
        if (it->created_receipt) {
            try {
                const auto before = route_netlink.dump_routes(
                    it->candidate.family);
                const auto before_state = exact_slot_state(
                    it->candidate, before);
                if (before_state == ExactSlotState::empty) {
                    for (const auto index : it->rollback_journals) {
                        journal(plan)[index].receipt =
                            RuntimeRoutingJournalReceipt::deleted_or_absent;
                    }
                    set_rollback_state(
                        RuntimeRoutingJournalState::rolled_back);
                    continue;
                }
                if (before_state != ExactSlotState::exact_single) {
                    for (const auto index : it->rollback_journals) {
                        journal(plan)[index].receipt =
                            RuntimeRoutingJournalReceipt::precondition_mismatch;
                    }
                    set_rollback_state(RuntimeRoutingJournalState::unknown);
                    failure_stage = RuntimeRoutingFailureStage::rollback_route;
                    return false;
                }
                const auto receipt = route_netlink.delete_route_if_exact(
                    it->candidate);
                if (receipt ==
                    RouteExactDeleteResult::PreconditionMismatch) {
                    for (const auto index : it->rollback_journals) {
                        journal(plan)[index].receipt =
                            RuntimeRoutingJournalReceipt::precondition_mismatch;
                    }
                    set_rollback_state(RuntimeRoutingJournalState::unknown);
                    failure_stage = RuntimeRoutingFailureStage::rollback_route;
                    return false;
                }
                for (const auto index : it->rollback_journals) {
                    journal(plan)[index].receipt =
                        RuntimeRoutingJournalReceipt::deleted_or_absent;
                }
                const auto live = route_netlink.dump_routes(it->candidate.family);
                if (exact_slot_state(it->candidate, live) !=
                    ExactSlotState::empty) {
                    set_rollback_state(RuntimeRoutingJournalState::unknown);
                    failure_stage = RuntimeRoutingFailureStage::rollback_route;
                    return false;
                }
                set_rollback_state(RuntimeRoutingJournalState::rolled_back);
            } catch (...) {
                for (const auto index : it->rollback_journals) {
                    journal(plan)[index].receipt =
                        RuntimeRoutingJournalReceipt::effect_unknown;
                }
                set_rollback_state(RuntimeRoutingJournalState::unknown);
                failure_stage = RuntimeRoutingFailureStage::rollback_route;
                return false;
            }
        } else if (it->replacement_receipt) {
            try {
                const auto before = route_netlink.dump_routes(
                    it->candidate.family);
                if (slot_matches_preimages(
                        it->candidate, it->preimages, before)) {
                    for (const auto index : it->rollback_journals) {
                        journal(plan)[index].receipt =
                            RuntimeRoutingJournalReceipt::already_present;
                    }
                    set_rollback_state(
                        RuntimeRoutingJournalState::rolled_back);
                    continue;
                }
                if (exact_slot_state(it->candidate, before) !=
                    ExactSlotState::exact_single) {
                    for (const auto index : it->rollback_journals) {
                        journal(plan)[index].receipt =
                            RuntimeRoutingJournalReceipt::precondition_mismatch;
                    }
                    set_rollback_state(RuntimeRoutingJournalState::unknown);
                    failure_stage = RuntimeRoutingFailureStage::rollback_route;
                    return false;
                }
                const auto receipt = route_netlink.replace_route_if_exact(
                    it->candidate, it->preimages.front());
                if (receipt ==
                    RouteExactReplaceResult::PreconditionMismatch) {
                    for (const auto index : it->rollback_journals) {
                        journal(plan)[index].receipt =
                            RuntimeRoutingJournalReceipt::precondition_mismatch;
                    }
                    set_rollback_state(RuntimeRoutingJournalState::unknown);
                    failure_stage = RuntimeRoutingFailureStage::rollback_route;
                    return false;
                }
                for (const auto index : it->rollback_journals) {
                    journal(plan)[index].receipt =
                        RuntimeRoutingJournalReceipt::replaced;
                }
                for (auto previous = std::next(it->preimages.begin());
                     previous != it->preimages.end(); ++previous) {
                    (void)route_netlink.add_route(*previous);
                }
                const auto live = route_netlink.dump_routes(
                    it->candidate.family);
                if (!slot_matches_preimages(
                        it->candidate, it->preimages, live)) {
                    set_rollback_state(RuntimeRoutingJournalState::unknown);
                    failure_stage = RuntimeRoutingFailureStage::rollback_route;
                    return false;
                }
                set_rollback_state(RuntimeRoutingJournalState::rolled_back);
            } catch (...) {
                for (const auto index : it->rollback_journals) {
                    journal(plan)[index].receipt =
                        RuntimeRoutingJournalReceipt::effect_unknown;
                }
                set_rollback_state(RuntimeRoutingJournalState::unknown);
                failure_stage = RuntimeRoutingFailureStage::rollback_route;
                return false;
            }
        } else {
            set_rollback_state(RuntimeRoutingJournalState::skipped);
        }
    }
    return true;
}

void mark_unused_rollbacks_skipped(Plan& plan) {
    for (auto& rule : plan.rules) {
        journal(plan)[rule.rollback_journal].state =
            RuntimeRoutingJournalState::skipped;
    }
    for (auto& route : plan.routes) {
        for (const auto index : route.rollback_journals) {
            journal(plan)[index].state =
                RuntimeRoutingJournalState::skipped;
        }
    }
}

} // namespace

RuntimeRoutingTransactionResult execute_runtime_routing_transaction(
    const RuntimeRoutingTransactionRequest& request,
    const RuntimeRoutingCurrentFenceProbe& current_fence,
    RouteNetlinkOperations& route_netlink,
    RuleNetlinkOperations& rule_netlink,
    const RuntimeRoutingJournalPublisher& publish_journal) {
    RuntimeRoutingTransactionResult result;
    result.identity = request.identity;
    RuntimeRoutingCurrentFence current;
    try {
        if (!current_fence) {
            result.terminal = RuntimeRoutingTerminal::precondition_failed;
            result.detail = "current routing fence probe is unavailable";
            return result;
        }
        current = current_fence();
    } catch (...) {
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail = exception_detail("current routing fence unavailable");
        return result;
    }
    result.stale_reason = stale_reason(request.identity, current);
    if (result.stale_reason != RuntimeRoutingStaleReason::none) {
        result.terminal = RuntimeRoutingTerminal::stale_before_mutation;
        result.detail = "runtime routing transaction fence is stale";
        return result;
    }

    if (dynamic_cast<void*>(&route_netlink) !=
            dynamic_cast<void*>(&rule_netlink) ||
        !route_netlink.supports_exact_route_transaction() ||
        !rule_netlink.supports_exact_rule_transaction()) {
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail =
            "routing backend lacks exact transactional capabilities";
        return result;
    }

    std::unique_ptr<ExactRoutingTransactionLease> exact_lease;
    try {
        exact_lease =
            route_netlink.acquire_exact_transaction_lease();
    } catch (...) {
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail =
            exception_detail("routing backend exact lease unavailable");
        return result;
    }
    if (!exact_lease) {
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail =
            "routing backend lacks one combined exact transaction lease";
        return result;
    }

    std::vector<DumpedRoute> initial_routes;
    std::vector<DumpedRule> initial_rules;
    try {
        initial_routes = route_netlink.dump_routes();
        initial_rules = rule_netlink.dump_policy_rules();
    } catch (...) {
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail = exception_detail("initial exact inventory unavailable");
        return result;
    }
    if (request.require_prior_preimage_proof) {
        result.prior_preimage_observed = true;
        result.prior_preimage_exact = expected_inventory_exact(
            request.prior_routes,
            request.prior_rules,
            initial_routes,
            initial_rules);
    }

    std::string plan_error;
    auto maybe_plan = build_plan(
        request, initial_routes, initial_rules, plan_error);
    if (!maybe_plan.has_value()) {
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail = std::move(plan_error);
        return result;
    }
    Plan plan = std::move(*maybe_plan);
    result.published_journal = plan.published_journal;
    // From this point the journal's size and operation payloads are immutable.
    // The caller must retain the exact shared record before execution is
    // allowed to cross the mutation boundary.
    bool journal_retained = false;
    try {
        journal_retained = publish_journal &&
            publish_journal(plan.published_journal);
    } catch (...) {
        journal_retained = false;
    }
    if (!journal_retained) {
        plan.published_journal->failure_stage.store(
            RuntimeRoutingFailureStage::journal_publish,
            std::memory_order_relaxed);
        plan.published_journal->terminal.store(
            RuntimeRoutingTerminal::precondition_failed,
            std::memory_order_release);
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail = "routing journal was not retained before execution";
        result.journal = journal(plan);
        return result;
    }

    // Planning and both initial dumps may block. Re-read the authoritative
    // owner fence at the last allocation-free boundary before the first
    // mutating call; a changed route epoch or URLTest intent gets zero writes.
    const auto final_planning_fence = observe_fence(
        request, current_fence, result.stale_reason);
    if (final_planning_fence == FenceProbeState::unavailable) {
        plan.published_journal->failure_stage.store(
            RuntimeRoutingFailureStage::fence,
            std::memory_order_relaxed);
        plan.published_journal->terminal.store(
            RuntimeRoutingTerminal::precondition_failed,
            std::memory_order_release);
        result.terminal = RuntimeRoutingTerminal::precondition_failed;
        result.detail = "final routing fence unavailable";
        return result;
    }
    if (final_planning_fence == FenceProbeState::stale) {
        plan.published_journal->failure_stage.store(
            RuntimeRoutingFailureStage::fence,
            std::memory_order_relaxed);
        plan.published_journal->terminal.store(
            RuntimeRoutingTerminal::stale_before_mutation,
            std::memory_order_release);
        result.terminal = RuntimeRoutingTerminal::stale_before_mutation;
        result.detail = "runtime routing transaction fence changed while planning";
        return result;
    }

    auto enter_mutation = [&]() noexcept {
        result.mutation_started = true;
        plan.published_journal->mutation_started.store(
            true, std::memory_order_relaxed);
        plan.published_journal->terminal.store(
            RuntimeRoutingTerminal::running,
            std::memory_order_release);
    };

    auto retain_result_detail = [&](const char* detail) noexcept {
        try {
            result.detail = detail != nullptr ? detail : "";
        } catch (...) {
            result.detail.clear();
        }
    };
    auto retain_result_journal = [&]() noexcept {
        try {
            result.journal = journal(plan);
        } catch (...) {
            result.journal.clear();
        }
    };

    auto fail_candidate = [&](RuntimeRoutingFailureStage failure_stage,
                              bool ambiguous,
                              const char* detail) {
        if (ambiguous) {
            result.terminal = RuntimeRoutingTerminal::partial_unknown;
        } else if (rollback_candidate(
                       plan,
                       route_netlink,
                       rule_netlink,
                       failure_stage)) {
            bool prior_preimage_restored = true;
            if (request.require_prior_preimage_proof) {
                try {
                    const auto final_routes = route_netlink.dump_routes();
                    const auto final_rules =
                        rule_netlink.dump_policy_rules();
                    result.prior_preimage_observed = true;
                    result.prior_preimage_exact = expected_inventory_exact(
                        request.prior_routes,
                        request.prior_rules,
                        final_routes,
                        final_rules);
                    prior_preimage_restored =
                        result.prior_preimage_exact;
                } catch (...) {
                    result.prior_preimage_observed = false;
                    result.prior_preimage_exact = false;
                    prior_preimage_restored = false;
                }
            }
            if (prior_preimage_restored) {
                result.terminal =
                    RuntimeRoutingTerminal::candidate_rolled_back;
            } else {
                failure_stage =
                    RuntimeRoutingFailureStage::rollback_route;
                result.terminal = RuntimeRoutingTerminal::partial_unknown;
            }
        } else {
            result.terminal = RuntimeRoutingTerminal::partial_unknown;
        }
        plan.published_journal->failure_stage.store(
            failure_stage, std::memory_order_relaxed);
        plan.published_journal->terminal.store(
            result.terminal, std::memory_order_release);
        retain_result_detail(detail);
        retain_result_journal();
        return result;
    };

    auto fail_forward_fence = [&](RuntimeRoutingJournalEntry& entry,
                                  const char* detail) {
        entry.state = result.stale_reason == RuntimeRoutingStaleReason::none
            ? RuntimeRoutingJournalState::unknown
            : RuntimeRoutingJournalState::failed;
        if (result.mutation_started) {
            return fail_candidate(
                RuntimeRoutingFailureStage::fence, false, detail);
        }
        result.terminal = result.stale_reason == RuntimeRoutingStaleReason::none
            ? RuntimeRoutingTerminal::precondition_failed
            : RuntimeRoutingTerminal::stale_before_mutation;
        plan.published_journal->failure_stage.store(
            RuntimeRoutingFailureStage::fence,
            std::memory_order_relaxed);
        plan.published_journal->terminal.store(
            result.terminal, std::memory_order_release);
        retain_result_detail(detail);
        retain_result_journal();
        return result;
    };

    for (auto& mutation : plan.routes) {
        auto& entry = journal(plan)[mutation.forward_journal];
        try {
            if (mutation.replace) {
                const auto current_slot = route_netlink.dump_routes(
                    mutation.candidate.family);
                if (!slot_matches_preimages(
                        mutation.candidate,
                        mutation.preimages,
                        current_slot)) {
                    entry.state = RuntimeRoutingJournalState::failed;
                    entry.receipt =
                        RuntimeRoutingJournalReceipt::precondition_mismatch;
                    return fail_candidate(
                        RuntimeRoutingFailureStage::candidate_route,
                        false,
                        "managed route slot changed after transaction planning");
                }
                const auto fence = observe_fence(
                    request, current_fence, result.stale_reason);
                if (fence != FenceProbeState::current) {
                    return fail_forward_fence(
                        entry,
                        "routing fence changed before route replacement");
                }
                enter_mutation();
                const auto receipt = route_netlink.replace_route_if_exact(
                    mutation.preimages.front(), mutation.candidate);
                if (receipt ==
                    RouteExactReplaceResult::PreconditionMismatch) {
                    entry.receipt =
                        RuntimeRoutingJournalReceipt::precondition_mismatch;
                    entry.state = RuntimeRoutingJournalState::failed;
                    return fail_candidate(
                        RuntimeRoutingFailureStage::candidate_route,
                        false,
                        "exact managed route replacement was refused");
                }
                mutation.replacement_receipt = true;
                entry.receipt = RuntimeRoutingJournalReceipt::replaced;
            } else {
                const auto fence = observe_fence(
                    request, current_fence, result.stale_reason);
                if (fence != FenceProbeState::current) {
                    return fail_forward_fence(
                        entry,
                        "routing fence changed before route creation");
                }
                enter_mutation();
                const auto receipt = route_netlink.add_route(mutation.candidate);
                mutation.created_receipt = receipt == RouteAddResult::Created;
                entry.receipt = receipt == RouteAddResult::Created
                    ? RuntimeRoutingJournalReceipt::created
                    : RuntimeRoutingJournalReceipt::already_present;
            }
            entry.state = RuntimeRoutingJournalState::completed;
        } catch (const RouteInterfaceUnavailableError& error) {
            result.route_interface_unavailable = true;
            entry.state = RuntimeRoutingJournalState::unknown;
            entry.receipt = RuntimeRoutingJournalReceipt::effect_unknown;
            try {
                const auto live = route_netlink.dump_routes(
                    mutation.candidate.family);
                if (!route_present(mutation.candidate, live)) {
                    entry.state = RuntimeRoutingJournalState::failed;
                    entry.receipt =
                        RuntimeRoutingJournalReceipt::deleted_or_absent;
                    return fail_candidate(
                        RuntimeRoutingFailureStage::candidate_route,
                        false,
                        error.what());
                }
            } catch (...) {
            }
            return fail_candidate(
                RuntimeRoutingFailureStage::candidate_route,
                true,
                error.what());
        } catch (...) {
            entry.state = RuntimeRoutingJournalState::unknown;
            entry.receipt = RuntimeRoutingJournalReceipt::effect_unknown;
            try {
                const auto live = route_netlink.dump_routes(
                    mutation.candidate.family);
                if (!route_present(mutation.candidate, live)) {
                    entry.state = RuntimeRoutingJournalState::failed;
                    entry.receipt =
                        RuntimeRoutingJournalReceipt::deleted_or_absent;
                    return fail_candidate(
                        RuntimeRoutingFailureStage::candidate_route,
                        false,
                        "candidate route mutation failed");
                }
            } catch (...) {
            }
            return fail_candidate(
                RuntimeRoutingFailureStage::candidate_route,
                true,
                "candidate route mutation result is unknown");
        }
    }

    for (auto& mutation : plan.rules) {
        auto& entry = journal(plan)[mutation.forward_journal];
        try {
            const auto current_routes = route_netlink.dump_routes(
                mutation.candidate.family);
            if (!rule_dependency_present(
                    request, mutation.candidate, current_routes)) {
                entry.state = RuntimeRoutingJournalState::failed;
                return fail_candidate(
                    RuntimeRoutingFailureStage::candidate_rule_dependency,
                    false,
                    "candidate rule route dependency disappeared");
            }
            const auto current_rules = rule_netlink.dump_policy_rules(
                mutation.candidate.family);
            const auto current_state = exact_rule_state(
                mutation.candidate, current_rules);
            if (current_state == ExactSlotState::mismatch) {
                entry.state = RuntimeRoutingJournalState::failed;
                return fail_candidate(
                    RuntimeRoutingFailureStage::candidate_rule,
                    false,
                    "foreign rule occupied the candidate identity");
            }
            if (current_state == ExactSlotState::exact_single) {
                entry.receipt =
                    RuntimeRoutingJournalReceipt::already_present;
                entry.state = RuntimeRoutingJournalState::completed;
                continue;
            }
            const auto fence = observe_fence(
                request, current_fence, result.stale_reason);
            if (fence != FenceProbeState::current) {
                return fail_forward_fence(
                    entry,
                    "routing fence changed before rule creation");
            }
            enter_mutation();
            const auto receipt = rule_netlink.add_rule_for_family(
                mutation.candidate, mutation.candidate.family);
            mutation.created_receipt = receipt == RuleAddResult::Created;
            entry.receipt = receipt == RuleAddResult::Created
                ? RuntimeRoutingJournalReceipt::created
                : RuntimeRoutingJournalReceipt::already_present;
            entry.state = RuntimeRoutingJournalState::completed;
        } catch (...) {
            entry.state = RuntimeRoutingJournalState::unknown;
            entry.receipt = RuntimeRoutingJournalReceipt::effect_unknown;
            try {
                const auto live = rule_netlink.dump_policy_rules(
                    mutation.candidate.family);
                if (exact_rule_state(mutation.candidate, live) ==
                    ExactSlotState::empty) {
                    entry.state = RuntimeRoutingJournalState::failed;
                    entry.receipt =
                        RuntimeRoutingJournalReceipt::deleted_or_absent;
                    return fail_candidate(
                        RuntimeRoutingFailureStage::candidate_rule,
                        false,
                        "candidate rule mutation failed");
                }
            } catch (...) {
            }
            return fail_candidate(
                RuntimeRoutingFailureStage::candidate_rule,
                true,
                "candidate rule mutation result is unknown");
        }
    }

    try {
        const auto live_routes = route_netlink.dump_routes();
        const auto live_rules = rule_netlink.dump_policy_rules();
        if (!all_desired_exact(request, live_routes, live_rules)) {
            journal(plan)[plan.candidate_verify_journal].state =
                RuntimeRoutingJournalState::failed;
            return fail_candidate(
                RuntimeRoutingFailureStage::candidate_verify,
                false,
                "candidate exact verification failed");
        }
        const auto fence = observe_fence(
            request, current_fence, result.stale_reason);
        if (fence != FenceProbeState::current) {
            return fail_forward_fence(
                journal(plan)[plan.candidate_verify_journal],
                "routing fence changed before candidate commit");
        }
        journal(plan)[plan.candidate_verify_journal].state =
            RuntimeRoutingJournalState::verified;
        result.candidate_exact_verified = true;
        plan.published_journal->candidate_exact_verified.store(
            true, std::memory_order_relaxed);
    } catch (...) {
        journal(plan)[plan.candidate_verify_journal].state =
            RuntimeRoutingJournalState::unknown;
        return fail_candidate(
            RuntimeRoutingFailureStage::candidate_verify,
            true,
            "candidate exact verification unavailable");
    }

    mark_unused_rollbacks_skipped(plan);
    bool cleanup_pending = false;
    bool cleanup_superseded = false;
    RuntimeRoutingFailureStage cleanup_failure_stage =
        RuntimeRoutingFailureStage::none;
    for (auto& cleanup : plan.stale_rules) {
        auto& entry = journal(plan)[cleanup.journal];
        if (cleanup_superseded) {
            entry.state = RuntimeRoutingJournalState::skipped;
            continue;
        }
        try {
            const auto before = rule_netlink.dump_policy_rules(
                cleanup.stale.family);
            const auto before_state = exact_rule_state(
                cleanup.stale, before);
            if (before_state == ExactSlotState::empty) {
                entry.state = RuntimeRoutingJournalState::skipped;
                continue;
            }
            if (before_state != ExactSlotState::exact_single) {
                entry.receipt =
                    RuntimeRoutingJournalReceipt::precondition_mismatch;
                entry.state = RuntimeRoutingJournalState::failed;
                cleanup_pending = true;
                cleanup_failure_stage =
                    RuntimeRoutingFailureStage::cleanup_rule;
                continue;
            }
            const auto fence = observe_fence(
                request, current_fence, result.stale_reason);
            if (fence != FenceProbeState::current) {
                entry.state = RuntimeRoutingJournalState::skipped;
                cleanup_pending = true;
                cleanup_superseded = true;
                cleanup_failure_stage = RuntimeRoutingFailureStage::fence;
                continue;
            }
            enter_mutation();
            const auto receipt = rule_netlink.delete_rule_if_exact(
                cleanup.stale, cleanup.stale.family);
            if (receipt == RuleExactDeleteResult::PreconditionMismatch) {
                entry.receipt =
                    RuntimeRoutingJournalReceipt::precondition_mismatch;
                entry.state = RuntimeRoutingJournalState::failed;
                cleanup_pending = true;
                cleanup_failure_stage =
                    RuntimeRoutingFailureStage::cleanup_rule;
                continue;
            }
            entry.receipt =
                RuntimeRoutingJournalReceipt::deleted_or_absent;
            const auto live = rule_netlink.dump_policy_rules(
                cleanup.stale.family);
            if (exact_rule_state(cleanup.stale, live) !=
                ExactSlotState::empty) {
                entry.state = RuntimeRoutingJournalState::failed;
                cleanup_pending = true;
                cleanup_failure_stage =
                    RuntimeRoutingFailureStage::cleanup_rule;
            } else {
                entry.state = RuntimeRoutingJournalState::completed;
            }
        } catch (...) {
            entry.state = RuntimeRoutingJournalState::unknown;
            entry.receipt = RuntimeRoutingJournalReceipt::effect_unknown;
            cleanup_pending = true;
            cleanup_failure_stage = RuntimeRoutingFailureStage::cleanup_rule;
        }
    }

    try {
        const auto live = rule_netlink.dump_policy_rules();
        result.stale_rule_absence_proven = std::none_of(
            plan.stale_rules.begin(), plan.stale_rules.end(),
            [&](const PlannedCleanupRule& cleanup) {
                return exact_rule_state(cleanup.stale, live) !=
                    ExactSlotState::empty;
            });
        journal(plan)[plan.stale_absence_journal].state =
            result.stale_rule_absence_proven
                ? RuntimeRoutingJournalState::verified
                : RuntimeRoutingJournalState::failed;
    } catch (...) {
        journal(plan)[plan.stale_absence_journal].state =
            RuntimeRoutingJournalState::unknown;
        result.stale_rule_absence_proven = false;
    }

    if (!result.stale_rule_absence_proven) {
        cleanup_pending = true;
        if (cleanup_failure_stage == RuntimeRoutingFailureStage::none) {
            cleanup_failure_stage =
                RuntimeRoutingFailureStage::cleanup_rule;
        }
        for (auto& cleanup : plan.stale_routes) {
            journal(plan)[cleanup.journal].state =
                RuntimeRoutingJournalState::skipped;
        }
    } else {
        for (auto& cleanup : plan.stale_routes) {
            auto& entry = journal(plan)[cleanup.journal];
            if (cleanup_superseded) {
                entry.state = RuntimeRoutingJournalState::skipped;
                cleanup_pending = true;
                continue;
            }
            try {
                // Policy rules have no ownership protocol. Even a rule which
                // did not satisfy the generated-rule heuristic is a live
                // dependency on this exact table; retain the protocol-186
                // route anchor rather than orphaning an unclassified rule.
                const auto current_rules = rule_netlink.dump_policy_rules();
                const bool table_still_referenced = std::any_of(
                    current_rules.begin(), current_rules.end(),
                    [&](const DumpedRule& rule) {
                        return rule.table == cleanup.stale.table &&
                               rule.family == cleanup.stale.family;
                    });
                if (table_still_referenced) {
                    entry.state = RuntimeRoutingJournalState::skipped;
                    result.stale_rule_absence_proven = false;
                    cleanup_pending = true;
                    cleanup_failure_stage =
                        RuntimeRoutingFailureStage::cleanup_route;
                    continue;
                }
                const auto before = route_netlink.dump_routes(
                    cleanup.stale.family);
                const auto before_state = exact_slot_state(
                    cleanup.stale, before);
                if (before_state == ExactSlotState::empty) {
                    entry.state = RuntimeRoutingJournalState::skipped;
                    continue;
                }
                if (before_state != ExactSlotState::exact_single) {
                    entry.state = RuntimeRoutingJournalState::failed;
                    cleanup_pending = true;
                    cleanup_failure_stage =
                        RuntimeRoutingFailureStage::cleanup_route;
                    continue;
                }
                const auto fence = observe_fence(
                    request, current_fence, result.stale_reason);
                if (fence != FenceProbeState::current) {
                    entry.state = RuntimeRoutingJournalState::skipped;
                    cleanup_pending = true;
                    cleanup_superseded = true;
                    cleanup_failure_stage = RuntimeRoutingFailureStage::fence;
                    continue;
                }
                result.route_cleanup_attempted = true;
                enter_mutation();
                const auto receipt = route_netlink.delete_route_if_exact(
                    cleanup.stale);
                if (receipt ==
                    RouteExactDeleteResult::PreconditionMismatch) {
                    entry.receipt =
                        RuntimeRoutingJournalReceipt::precondition_mismatch;
                    entry.state = RuntimeRoutingJournalState::failed;
                    cleanup_pending = true;
                    cleanup_failure_stage =
                        RuntimeRoutingFailureStage::cleanup_route;
                    continue;
                }
                entry.receipt =
                    RuntimeRoutingJournalReceipt::deleted_or_absent;
                const auto live = route_netlink.dump_routes(
                    cleanup.stale.family);
                if (exact_slot_state(cleanup.stale, live) !=
                    ExactSlotState::empty) {
                    entry.state = RuntimeRoutingJournalState::failed;
                    cleanup_pending = true;
                    cleanup_failure_stage =
                        RuntimeRoutingFailureStage::cleanup_route;
                } else {
                    entry.state = RuntimeRoutingJournalState::completed;
                }
            } catch (...) {
                entry.state = RuntimeRoutingJournalState::unknown;
                entry.receipt = RuntimeRoutingJournalReceipt::effect_unknown;
                cleanup_pending = true;
                cleanup_failure_stage =
                    RuntimeRoutingFailureStage::cleanup_route;
            }
        }
    }

    try {
        const auto live_routes = route_netlink.dump_routes();
        const auto live_rules = rule_netlink.dump_policy_rules();
        const auto final_fence = observe_fence(
            request, current_fence, result.stale_reason);
        if (final_fence != FenceProbeState::current) {
            cleanup_pending = true;
            cleanup_failure_stage = RuntimeRoutingFailureStage::fence;
        }
        if (!all_desired_exact(request, live_routes, live_rules)) {
            journal(plan)[plan.committed_verify_journal].state =
                RuntimeRoutingJournalState::failed;
            result.terminal = RuntimeRoutingTerminal::partial_unknown;
            plan.published_journal->failure_stage.store(
                RuntimeRoutingFailureStage::committed_verify,
                std::memory_order_relaxed);
        } else {
            journal(plan)[plan.committed_verify_journal].state =
                RuntimeRoutingJournalState::verified;
            const bool stale_route_remains = std::any_of(
                plan.stale_routes.begin(), plan.stale_routes.end(),
                [&](const PlannedCleanupRoute& cleanup) {
                    return exact_slot_state(cleanup.stale, live_routes) !=
                        ExactSlotState::empty;
                });
            const bool stale_rule_remains = std::any_of(
                plan.stale_rules.begin(), plan.stale_rules.end(),
                [&](const PlannedCleanupRule& cleanup) {
                    return exact_rule_state(cleanup.stale, live_rules) !=
                        ExactSlotState::empty;
                });
            const bool stale_table_still_referenced = std::any_of(
                plan.stale_routes.begin(), plan.stale_routes.end(),
                [&](const PlannedCleanupRoute& cleanup) {
                    return std::any_of(
                        live_rules.begin(), live_rules.end(),
                        [&](const DumpedRule& rule) {
                            return rule.table == cleanup.stale.table &&
                                   rule.family == cleanup.stale.family;
                        });
                });
            cleanup_pending = cleanup_pending || stale_route_remains ||
                stale_rule_remains || stale_table_still_referenced;
            result.terminal = cleanup_pending
                ? RuntimeRoutingTerminal::committed_cleanup_pending
                : RuntimeRoutingTerminal::candidate_committed;
            plan.published_journal->failure_stage.store(
                cleanup_pending
                    ? (cleanup_failure_stage ==
                               RuntimeRoutingFailureStage::none
                           ? RuntimeRoutingFailureStage::cleanup_route
                           : cleanup_failure_stage)
                    : RuntimeRoutingFailureStage::none,
                std::memory_order_relaxed);
        }
    } catch (...) {
        journal(plan)[plan.committed_verify_journal].state =
            RuntimeRoutingJournalState::unknown;
        result.terminal = RuntimeRoutingTerminal::committed_cleanup_pending;
        plan.published_journal->failure_stage.store(
            RuntimeRoutingFailureStage::committed_verify,
            std::memory_order_relaxed);
    }
    plan.published_journal->terminal.store(
        result.terminal, std::memory_order_release);
    try {
        result.journal = journal(plan);
    } catch (...) {
        result.journal.clear();
    }
    return result;
}

} // namespace keen_pbr3
