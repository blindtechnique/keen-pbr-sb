#include <doctest/doctest.h>

#include "../src/config/route_failure_policy.hpp"
#include "../src/config/routing_state.hpp"

using namespace keen_pbr3;

namespace {

Outbound failure_interface(const std::string& tag) {
    Outbound outbound{};
    outbound.tag = tag;
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = "n" + tag;
    outbound.strict_enforcement = false;
    return outbound;
}

Outbound failure_group(const std::string& tag, std::vector<std::string> children) {
    Outbound outbound{};
    outbound.tag = tag;
    outbound.type = OutboundType::URLTEST;
    OutboundGroup group{};
    group.outbounds = std::move(children);
    outbound.outbound_groups = std::vector<OutboundGroup>{group};
    return outbound;
}

Config failure_config(api::FailurePolicy policy) {
    Config config{};
    config.outbounds = std::vector<Outbound>{
        failure_interface("primary"), failure_interface("backup"),
        failure_interface("other")};
    RouteRule rule{};
    rule.outbound = "primary";
    rule.list = std::vector<std::string>{"sites"};
    rule.failure_policy = policy;
    if (policy == api::FailurePolicy::FALLBACK) rule.fallback_outbound = "backup";
    RouteConfig route{};
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;
    config.lists = std::map<std::string, ListConfig>{{"sites", ListConfig{}}};
    return config;
}

const OutboundMarkMap failure_marks{{"primary", 0x10000}, {"backup", 0x20000},
                                    {"other", 0x30000}, {"group", 0x40000},
                                    {"nested", 0x50000}};

} // namespace

TEST_CASE("rule failure policy inherit preserves shared outbound behaviour") {
    auto config = failure_config(api::FailurePolicy::INHERIT);
    const RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable}};
    const auto states = build_fw_rule_states(config, failure_marks, nullptr, &health);
    REQUIRE(states.size() == 1);
    CHECK(states[0].action_type == RuleActionType::Mark);
    CHECK(states[0].fwmark == 0x10000);
    CHECK(states[0].effective_outbound_tag.empty());
    CHECK_FALSE(route_failure_policies_enabled(config));
    CHECK_FALSE(config.outbounds->front().strict_enforcement.value_or(true));
}

TEST_CASE("rule failure block retains unknown primary and blocks only observed failure") {
    const auto config = failure_config(api::FailurePolicy::BLOCK);
    CHECK(route_failure_policies_enabled(config));
    CHECK(build_fw_rule_states(config, failure_marks)[0].action_type == RuleActionType::Mark);
    for (const auto state : {RouteFailureHealth::unknown, RouteFailureHealth::healthy}) {
        const RouteFailureHealthSnapshot health{{"primary", state}};
        CHECK(build_fw_rule_states(config, failure_marks, nullptr, &health)[0].fwmark == 0x10000);
    }
    const RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable}};
    const auto states = build_fw_rule_states(config, failure_marks, nullptr, &health);
    CHECK(states[0].action_type == RuleActionType::Drop);
    CHECK(states[0].effective_outbound_tag == "(blocked)");
    CHECK(states[0].fwmark == 0);
    CHECK(states[0].list_names == std::vector<std::string>{"sites"});
    CHECK(states[0].set_names == std::vector<std::string>{
        "kpbr4_sites", "kpbr6_sites", "kpbr4d_sites", "kpbr6d_sites"});
}

TEST_CASE("rule fallback requires a usable backup path and returns to primary") {
    const auto config = failure_config(api::FailurePolicy::FALLBACK);
    RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable},
                                     {"backup", RouteFailureHealth::healthy}};
    auto states = build_fw_rule_states(config, failure_marks, nullptr, &health);
    CHECK(states[0].action_type == RuleActionType::Mark);
    CHECK(states[0].fwmark == 0x20000);
    CHECK(states[0].outbound_tag == "primary");
    CHECK(states[0].effective_outbound_tag == "backup");
    // The fallback need not alter its global strict=false policy: a later
    // observed failure changes this rule's classifier to DROP instead.
    for (const auto backup : {RouteFailureHealth::unknown, RouteFailureHealth::unavailable}) {
        health["backup"] = backup;
        CHECK(build_fw_rule_states(config, failure_marks, nullptr, &health)[0].action_type ==
              RuleActionType::Drop);
    }
    health.erase("backup");
    CHECK(build_fw_rule_states(config, failure_marks, nullptr, &health)[0].action_type ==
          RuleActionType::Drop);
    health["primary"] = RouteFailureHealth::healthy;
    states = build_fw_rule_states(config, failure_marks, nullptr, &health);
    CHECK(states[0].fwmark == 0x10000);
    CHECK(states[0].effective_outbound_tag.empty());
}

TEST_CASE("different rule policies do not change their shared primary mark or each other") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    auto inherit = config.route->rules->front();
    inherit.failure_policy = api::FailurePolicy::INHERIT;
    inherit.fallback_outbound.reset();
    config.route->rules->push_back(inherit);
    auto block = inherit;
    block.failure_policy = api::FailurePolicy::BLOCK;
    config.route->rules->push_back(block);
    const RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable},
                                           {"backup", RouteFailureHealth::healthy}};
    const auto states = build_fw_rule_states(config, failure_marks, nullptr, &health);
    REQUIRE(states.size() == 3);
    CHECK(states[0].fwmark == 0x20000);
    CHECK(states[1].fwmark == 0x10000);
    CHECK(states[2].action_type == RuleActionType::Drop);
    CHECK(failure_marks.at("primary") == 0x10000);
}

TEST_CASE("fallback group follows its committed nested selected leaf") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"nested", "other"}));
    config.outbounds->push_back(failure_group("nested", {"backup"}));
    config.route->rules->front().fallback_outbound = "group";
    std::map<std::string, std::string> selections{{"group", "nested"}, {"nested", "backup"}};
    RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable},
                                     {"backup", RouteFailureHealth::healthy}};
    auto states = build_fw_rule_states(config, failure_marks, &selections, &health);
    CHECK(states[0].fwmark == 0x20000);
    CHECK(states[0].effective_outbound_tag == "backup");
    selections.clear();
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].action_type ==
          RuleActionType::Drop);
}

TEST_CASE("selected leaf link failure overrides a healthy group observation") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"primary"}));
    config.route->rules->front().outbound = "group";
    const std::map<std::string, std::string> selections{{"group", "primary"}};
    const RouteFailureHealthSnapshot health{{"group", RouteFailureHealth::healthy},
                                           {"primary", RouteFailureHealth::link_unavailable},
                                           {"backup", RouteFailureHealth::healthy}};
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].fwmark == 0x20000);
}

TEST_CASE("link disappearance overrides successful probe without inventing link-up health") {
    RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::healthy}};
    merge_route_failure_link_health(health, {{"primary", false}, {"backup", true}});
    CHECK(health.at("primary") == RouteFailureHealth::link_unavailable);
    CHECK(health.count("backup") == 0);
    const auto config = failure_config(api::FailurePolicy::FALLBACK);
    CHECK(build_fw_rule_states(config, failure_marks, nullptr, &health)[0].action_type ==
          RuleActionType::Drop);
}

TEST_CASE("unknown first observation and disabled rules preserve ordinary routing") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    const RouteFailureHealthSnapshot empty;
    const auto initial = select_route_failure_target(config.route->rules->front(),
        *config.outbounds, nullptr, &empty);
    CHECK_FALSE(initial.drop);
    CHECK(initial.outbound_tag == "primary");
    config.route->rules->front().enabled = false;
    CHECK_FALSE(route_failure_policies_enabled(config));
    const RouteFailureHealthSnapshot failed{{"primary", RouteFailureHealth::unavailable}};
    CHECK(build_fw_rule_states(config, failure_marks, nullptr, &failed)[0].action_type ==
          RuleActionType::Skip);
}

TEST_CASE("bad or cyclic group cursor never proves a healthy fallback") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"nested"}));
    config.outbounds->push_back(failure_group("nested", {"group"}));
    config.route->rules->front().fallback_outbound = "group";
    RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable},
                                     {"backup", RouteFailureHealth::healthy}};
    std::map<std::string, std::string> selections{{"group", "backup"}};
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].action_type ==
          RuleActionType::Drop);
    selections = {{"group", "nested"}, {"nested", "group"}};
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].action_type ==
          RuleActionType::Drop);
}

TEST_CASE("mark-only TABLE success cannot make a selected group fallback healthy") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"external"}));
    auto external = failure_interface("external");
    external.type = OutboundType::TABLE;
    external.interface.reset();
    external.table = 123;
    config.outbounds->push_back(external);
    config.route->rules->front().fallback_outbound = "group";
    const std::map<std::string, std::string> selections{{"group", "external"}};
    const RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::unavailable},
                                           {"external", RouteFailureHealth::healthy},
                                           {"group", RouteFailureHealth::healthy}};
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].action_type ==
          RuleActionType::Drop);
}

TEST_CASE("group without selection is unavailable only when all child paths are absent") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"primary", "other"}));
    config.route->rules->front().outbound = "group";
    const std::map<std::string, std::string> selections;
    RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::link_unavailable},
                                     {"backup", RouteFailureHealth::healthy}};
    CHECK(route_failure_health_for("group", *config.outbounds, &selections, &health) ==
          RouteFailureHealth::unknown);
    health["other"] = RouteFailureHealth::link_unavailable;
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].fwmark == 0x20000);
}

TEST_CASE("group uses its existing selector result instead of independent probe timing") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"primary"}));
    config.route->rules->front().outbound = "group";
    const std::map<std::string, std::string> selections{{"group", "primary"}};
    RouteFailureHealthSnapshot health{{"primary", route_failure_probe_health(true, false)},
                                     {"group", RouteFailureHealth::healthy},
                                     {"backup", RouteFailureHealth::healthy}};
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].fwmark == 0x10000);
    health["primary"] = RouteFailureHealth::healthy;
    health["group"] = route_failure_probe_health(true, false);
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].fwmark == 0x10000);
}

TEST_CASE("one attributed HTTP endpoint failure is degraded and never transport absence") {
    const auto failed_endpoint = route_failure_probe_health(true, false);
    CHECK(failed_endpoint == RouteFailureHealth::degraded);
    CHECK_FALSE(route_failure_is_unavailable(failed_endpoint));
    CHECK(route_failure_is_usable(failed_endpoint));
    CHECK(route_failure_probe_health(false, false) == RouteFailureHealth::unknown);
    CHECK(route_failure_probe_health(false, true) == RouteFailureHealth::unknown);
    CHECK(route_failure_probe_health(true, true) == RouteFailureHealth::healthy);
    for (const auto policy : {api::FailurePolicy::BLOCK, api::FailurePolicy::FALLBACK}) {
        const auto config = failure_config(policy);
        RouteFailureHealthSnapshot health{{"primary", failed_endpoint}, {"backup", failed_endpoint}};
        merge_route_failure_link_health(health, {{"primary", true}, {"backup", true}});
        const auto states = build_fw_rule_states(config, failure_marks, nullptr, &health);
        REQUIRE(states.size() == 1);
        CHECK(states[0].action_type == RuleActionType::Mark);
        CHECK(states[0].fwmark == 0x10000);
        CHECK(states[0].effective_outbound_tag.empty());
    }
}

TEST_CASE("degraded backup remains usable unless its real link or gateway disappears") {
    const auto config = failure_config(api::FailurePolicy::FALLBACK);
    RouteFailureHealthSnapshot health{{"primary", route_failure_probe_health(true, false)},
                                     {"backup", route_failure_probe_health(true, false)}};
    merge_route_failure_link_health(health, {{"primary", false}, {"backup", true}});
    const auto fallback = build_fw_rule_states(config, failure_marks, nullptr, &health);
    CHECK(fallback[0].fwmark == 0x20000);
    CHECK(fallback[0].effective_outbound_tag == "backup");
    CHECK(health.at("backup") == RouteFailureHealth::degraded);
    merge_route_failure_link_health(health, {{"backup", false}});
    const auto unavailable = build_fw_rule_states(config, failure_marks, nullptr, &health);
    CHECK(unavailable[0].action_type == RuleActionType::Drop);
    CHECK(unavailable[0].effective_outbound_tag == "(blocked)");
}

TEST_CASE("same endpoint failing for every group child does not declare the group unavailable") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"primary", "other"}));
    config.route->rules->front().outbound = "group";
    std::map<std::string, std::string> selections{{"group", "primary"}};
    const RouteFailureHealthSnapshot health{{"primary", route_failure_probe_health(true, false)},
                                           {"other", route_failure_probe_health(true, false)},
                                           {"group", route_failure_probe_health(true, false)},
                                           {"backup", RouteFailureHealth::healthy}};
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].fwmark == 0x10000);
    CHECK(selections.at("group") == "primary");
    selections.clear();
    CHECK(route_failure_health_for("group", *config.outbounds, &selections, &health) ==
          RouteFailureHealth::unknown);
    // No working selection is invented: the existing group mark/kill-switch
    // stays in charge rather than replacing it with the per-rule backup.
    const auto no_selection = build_fw_rule_states(config, failure_marks, &selections, &health);
    CHECK(no_selection[0].fwmark == 0x40000);
    CHECK(no_selection[0].effective_outbound_tag.empty());
}

TEST_CASE("degraded selected group is a usable fallback but an unselected group is not") {
    auto config = failure_config(api::FailurePolicy::FALLBACK);
    config.outbounds->push_back(failure_group("group", {"backup"}));
    config.route->rules->front().fallback_outbound = "group";
    std::map<std::string, std::string> selections{{"group", "backup"}};
    RouteFailureHealthSnapshot health{{"primary", RouteFailureHealth::link_unavailable},
                                     {"backup", route_failure_probe_health(true, false)},
                                     {"group", route_failure_probe_health(true, false)}};
    const auto states = build_fw_rule_states(config, failure_marks, &selections, &health);
    CHECK(states[0].fwmark == 0x20000);
    CHECK(states[0].effective_outbound_tag == "backup");
    selections.clear();
    CHECK(build_fw_rule_states(config, failure_marks, &selections, &health)[0].action_type ==
          RuleActionType::Drop);
}
