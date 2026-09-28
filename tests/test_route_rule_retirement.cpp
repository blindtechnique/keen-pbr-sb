#include <doctest/doctest.h>
#include "../src/config/route_rule_retirement.hpp"
#include "../src/routing/retired_rule_conntrack.hpp"

using namespace keen_pbr3;

namespace {
Config retirement_fixture() {
    return parse_config(R"({
      "outbounds":[{"tag":"vpn","type":"interface","interface":"tun1"},{"tag":"other","type":"interface","interface":"tun2"}],
      "lists":{"music":{"domains":["example.org"]},"other":{"domains":["other.org"]}},
      "route":{"rules":[{"id":"music","list":["music"],"outbound":"vpn"},{"id":"other","list":["other"],"outbound":"other"}]},
      "dns":{"servers":[{"tag":"vpn_dns","address":"1.1.1.1","detour":"vpn"}],"rules":[
        {"id":"music_dns","list":["music"],"server":"vpn_dns","route_rule_ids":["music"]},
        {"id":"manual_dns","list":["other"],"server":"vpn_dns"}]}
    })");
}
}

TEST_CASE("Deleting a route retires its DNS binding but preserves independent DNS") {
    const auto before = retirement_fixture();
    auto after = before;
    after.route->rules->erase(after.route->rules->begin());
    retire_route_dns_bindings(after, before);
    REQUIRE(after.dns->rules->size() == 1U);
    CHECK(after.dns->rules->front().id == "manual_dns");
    CHECK(before.dns->rules->size() == 2U);
    // Idempotent stage/validation does not touch the surviving DNS rule.
    const auto once = nlohmann::json(after);
    retire_route_dns_bindings(after, before);
    CHECK(nlohmann::json(after) == once);
}

TEST_CASE("Shared DNS binding is narrowed and follows surviving route owners") {
    auto before = retirement_fixture();
    before.dns->rules->front().list = {"music", "other"};
    before.dns->rules->front().route_rule_ids = std::vector<std::string>{"music", "other"};
    auto after = before;
    after.route->rules->erase(after.route->rules->begin());
    retire_route_dns_bindings(after, before);
    REQUIRE(after.dns->rules->size() == 2U);
    CHECK(after.dns->rules->front().list == std::vector<std::string>{"other"});
    CHECK(after.dns->rules->front().route_rule_ids == std::optional<std::vector<std::string>>{{"other"}});
}

TEST_CASE("Deleting one route preserves a list still used by another route") {
    const auto before = retirement_fixture();
    auto after = before;
    after.route->rules->front().id = "replacement";
    retire_route_dns_bindings(after, before);
    CHECK(after.dns->rules->front().list == std::vector<std::string>{"music"});
    CHECK(after.dns->rules->front().route_rule_ids == std::optional<std::vector<std::string>>{{"replacement"}});
}

TEST_CASE("Legacy catalogue DNS bindings are removed only on their matching detour") {
    auto before = retirement_fixture();
    before.lists->at("music").catalog_identity = std::string(64, 'a');
    before.dns->rules->front().route_rule_ids.reset();
    auto after = before;
    after.route->rules->erase(after.route->rules->begin());
    retire_route_dns_bindings(after, before);
    REQUIRE(after.dns->rules->size() == 1U);
    auto independent = before;
    independent.dns->servers->front().detour = "other";
    auto edited = independent;
    edited.route->rules->erase(edited.route->rules->begin());
    retire_route_dns_bindings(edited, independent);
    CHECK(edited.dns->rules->size() == 2U);
}

TEST_CASE("Retired rule conntrack cleanup targets old route marks only") {
    const auto before = retirement_fixture();
    auto after = before;
    after.route->rules->erase(after.route->rules->begin());
    RuleState first{};
    first.rule_index = 0;
    first.action_type = RuleActionType::Mark;
    first.fwmark = 0x10001U; // foreign low bit is not part of the selector
    first.fwmark_ipv6 = 0x30000U;
    RuleState second = first;
    second.rule_index = 1;
    second.fwmark = 0x20000U;
    second.fwmark_ipv6.reset();
    const OutboundMarkMap marks{{"vpn", 0x10000U}, {"other", 0x20000U}};
    CHECK(retired_rule_conntrack_marks(before, after, {first, second}, marks) ==
          std::vector<std::uint32_t>{0x10000U, 0x30000U});
    auto renamed = before;
    renamed.route->rules->front().display_name = "New label";
    CHECK(retired_rule_conntrack_marks(before, renamed, {first, second}, marks).empty());
    auto disabled = before;
    disabled.route->rules->front().enabled = false;
    CHECK(retired_rule_conntrack_marks(before, disabled, {first, second}, marks).size() == 2U);
}

TEST_CASE("Retired group cleanup includes old leaf marks but not unrelated routes") {
    auto before = retirement_fixture();
    auto& group = before.outbounds->front();
    group.type = OutboundType::URLTEST;
    group.interface.reset();
    OutboundGroup children;
    children.outbounds = {"leaf_a", "leaf_b"};
    group.outbound_groups = std::vector<OutboundGroup>{children};
    auto after = before;
    after.route->rules->erase(after.route->rules->begin());
    CHECK(retired_rule_conntrack_marks(before, after, {},
        {{"leaf_a", 0x10000U}, {"leaf_b", 0x30000U}, {"other", 0x20000U}}) ==
        std::vector<std::uint32_t>{0x10000U, 0x30000U});
}
