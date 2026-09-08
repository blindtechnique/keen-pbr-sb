#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/firewall/firewall_runtime.hpp"
#include "../src/routing/firewall_state.hpp"

#include <algorithm>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("route failure fallback receives existing OpenConnect forwarding") {
    auto config = parse_config(R"json({
      "outbounds": [
        {"tag":"main","type":"interface","interface":"nwg1"},
        {"tag":"reserve","type":"interface","interface":"nwg2"},
        {"tag":"unrelated","type":"interface","interface":"nwg3"},
        {"tag":"reserve_group","type":"urltest","url":"https://example.org",
         "outbound_groups":[{"outbounds":["reserve"]}]}
      ],
      "route":{"rules":[{"outbound":"main","dest_addr":"198.51.100.0/24",
        "failure_policy":"fallback","fallback_outbound":"reserve_group"}]}
    })json");
    const OutboundMarkMap marks{{"main", 0x10000U}, {"reserve", 0x20000U},
                                {"unrelated", 0x30000U}, {"reserve_group", 0x40000U}};
    InternalVpnRuntimeTarget target;
    target.stable_id = "ndms-service:oc-server";
    target.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    target.process_clients = true;
    target.source_cidrs_v4 = {"172.29.9.0/24"};
    target.verified_ingress_interfaces = {"oc17"};
    std::vector<FirewallNativeForwardSelector> expected{
        {"oc17", "172.29.9.0/24", "nwg1", 0x10000U},
        {"oc17", "172.29.9.0/24", "nwg2", 0x20000U},
        {"oc17", "172.29.9.0/24", "nwg2", 0x40000U}};
    std::sort(expected.begin(), expected.end());
    CHECK(select_openconnect_forward_selectors(config, marks, {target}, false) == expected);

    SUBCASE("disabled rule does not grant either path") {
        config.route->rules->front().enabled = false;
        CHECK(select_openconnect_forward_selectors(config, marks, {target}, false).empty());
    }
    SUBCASE("bypass mode does not enable tunnel forwarding") {
        target.process_clients = false;
        CHECK(select_openconnect_forward_selectors(config, marks, {target}, false).empty());
    }
    SUBCASE("inherit does not consume a stale reserve reference") {
        config.route->rules->front().failure_policy = api::FailurePolicy::INHERIT;
        const std::vector<FirewallNativeForwardSelector> only_primary{
            {"oc17", "172.29.9.0/24", "nwg1", 0x10000U}};
        CHECK(select_openconnect_forward_selectors(config, marks, {target}, false) == only_primary);
    }
}

TEST_CASE("firewall state resolves only the applied rule override") {
    FirewallState state;
    state.set_urltest_selection("main_group", "primary");
    RuleState rule{};
    rule.outbound_tag = "main_group";
    rule.action_type = RuleActionType::Mark;
    CHECK(state.resolve_effective_outbound(rule) == "primary");
    rule.effective_outbound_tag = "reserve";
    CHECK(state.resolve_effective_outbound(rule) == "reserve");
    CHECK(state.get_urltest_selections().at("main_group") == "primary");
}
