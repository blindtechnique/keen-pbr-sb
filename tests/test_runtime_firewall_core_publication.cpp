#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_core_publication.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {
namespace {

RuleState rule_named(
    const std::string& name,
    std::size_t index,
    std::uint32_t fwmark) {
    RuleState rule{};
    rule.rule_index = index;
    rule.list_names = {name + "-list"};
    rule.set_names = {name + "-set"};
    rule.outbound_tag = name + "-outbound";
    rule.action_type = RuleActionType::Mark;
    rule.fwmark = fwmark;
    return rule;
}

RuntimeFirewallCorePublication publication_named(
    const std::string& name,
    std::size_t index,
    std::uint32_t fwmark,
    std::uint32_t meta_fwmark,
    std::uint32_t meta_mask) {
    RuntimeFirewallCorePublication publication;
    publication.prepared = true;
    publication.committed = true;
    publication.rules = {rule_named(name, index, fwmark)};
    publication.list_content_state.static_destinations.emplace(
        name + "-list",
        std::vector<std::string>{name + "-destination"});
    publication.list_content_state.domain_entry_lists.emplace(
        name + "-domain-list");
    publication.list_content_state.truncated_static_destination_lists.emplace(
        name + "-truncated-list");

    ListSetUsage usage;
    usage.has_static_entries = true;
    usage.dynamic_timeout = static_cast<std::uint32_t>(index);
    usage.static_destinations = {name + "-usage-destination"};
    publication.list_usage.emplace(name + "-list", std::move(usage));
    publication.list_fingerprints.emplace(
        name + "-list",
        name + "-fingerprint");

    InternalVpnServer server;
    server.interface = name + "-vpn";
    server.ndms_id = name + "-ndms";
    server.process_clients = true;
    publication.internal_vpn_servers.push_back(std::move(server));

    InternalVpnRuntimeTarget target;
    target.stable_id = name + "-service";
    target.interface = name + "-service-interface";
    target.source_cidrs_v4 = {name + "-source"};
    publication.internal_vpn_service_targets.push_back(std::move(target));

    publication.native_vpn_direct_egress_snat_selectors.push_back(
        FirewallSourceEgressSnatSelector{
            name + "-egress",
            name + "-cidr"});
    publication.committed_meta_fwmark = meta_fwmark;
    publication.committed_meta_owned_mask = meta_mask;
    return publication;
}

struct ActiveCore final {
    FirewallState firewall_state;
    AppliedListContentState list_content_state;
    std::map<std::string, ListSetUsage> list_usage;
    std::map<std::string, std::string> list_fingerprints;
    std::vector<InternalVpnServer> internal_vpn_servers;
    std::vector<InternalVpnRuntimeTarget> internal_vpn_service_targets;
    std::vector<FirewallSourceEgressSnatSelector>
        native_vpn_direct_egress_snat_selectors;
    std::optional<std::uint32_t> committed_meta_fwmark;
    std::uint32_t committed_meta_owned_mask{0U};

    RuntimeFirewallCorePublicationTarget target() noexcept {
        return {
            firewall_state,
            list_content_state,
            list_usage,
            list_fingerprints,
            internal_vpn_servers,
            internal_vpn_service_targets,
            native_vpn_direct_egress_snat_selectors,
            committed_meta_fwmark,
            committed_meta_owned_mask};
    }
};

void load_active(
    ActiveCore& active,
    RuntimeFirewallCorePublication publication) {
    active.firewall_state.set_rules(std::move(publication.rules));
    active.list_content_state = std::move(publication.list_content_state);
    active.list_usage = std::move(publication.list_usage);
    active.list_fingerprints = std::move(publication.list_fingerprints);
    active.internal_vpn_servers =
        std::move(publication.internal_vpn_servers);
    active.internal_vpn_service_targets =
        std::move(publication.internal_vpn_service_targets);
    active.native_vpn_direct_egress_snat_selectors =
        std::move(publication.native_vpn_direct_egress_snat_selectors);
    active.committed_meta_fwmark = publication.committed_meta_fwmark;
    active.committed_meta_owned_mask =
        publication.committed_meta_owned_mask;
}

void check_active_named(
    const ActiveCore& active,
    const std::string& name,
    std::uint32_t meta_fwmark,
    std::uint32_t meta_mask) {
    REQUIRE(active.firewall_state.get_rules().size() == 1U);
    CHECK(
        active.firewall_state.get_rules().front().outbound_tag ==
        name + "-outbound");
    CHECK(
        active.list_content_state.static_destinations.count(
            name + "-list") == 1U);
    CHECK(
        active.list_content_state.domain_entry_lists.count(
            name + "-domain-list") == 1U);
    CHECK(
        active.list_content_state.truncated_static_destination_lists.count(
            name + "-truncated-list") == 1U);
    CHECK(active.list_usage.count(name + "-list") == 1U);
    CHECK(
        active.list_fingerprints.at(name + "-list") ==
        name + "-fingerprint");
    REQUIRE(active.internal_vpn_servers.size() == 1U);
    CHECK(
        active.internal_vpn_servers.front().interface ==
        name + "-vpn");
    REQUIRE(active.internal_vpn_service_targets.size() == 1U);
    CHECK(
        active.internal_vpn_service_targets.front().stable_id ==
        name + "-service");
    REQUIRE(
        active.native_vpn_direct_egress_snat_selectors.size() == 1U);
    CHECK(
        active.native_vpn_direct_egress_snat_selectors.front().interface ==
        name + "-egress");
    CHECK(active.committed_meta_fwmark == meta_fwmark);
    CHECK(active.committed_meta_owned_mask == meta_mask);
}

void check_publication_named(
    const RuntimeFirewallCorePublication& publication,
    const std::string& name,
    std::uint32_t meta_fwmark,
    std::uint32_t meta_mask) {
    REQUIRE(publication.rules.size() == 1U);
    CHECK(publication.rules.front().outbound_tag == name + "-outbound");
    CHECK(
        publication.list_content_state.static_destinations.count(
            name + "-list") == 1U);
    CHECK(publication.list_usage.count(name + "-list") == 1U);
    CHECK(
        publication.list_fingerprints.at(name + "-list") ==
        name + "-fingerprint");
    REQUIRE(publication.internal_vpn_servers.size() == 1U);
    CHECK(
        publication.internal_vpn_servers.front().interface ==
        name + "-vpn");
    REQUIRE(publication.internal_vpn_service_targets.size() == 1U);
    CHECK(
        publication.internal_vpn_service_targets.front().stable_id ==
        name + "-service");
    REQUIRE(
        publication.native_vpn_direct_egress_snat_selectors.size() == 1U);
    CHECK(
        publication.native_vpn_direct_egress_snat_selectors.front().interface ==
        name + "-egress");
    CHECK(publication.committed_meta_fwmark == meta_fwmark);
    CHECK(publication.committed_meta_owned_mask == meta_mask);
}

static_assert(noexcept(publish_runtime_firewall_core(
    std::declval<RuntimeFirewallCorePublicationTarget>(),
    std::declval<RuntimeFirewallCorePublication&>(),
    RuntimeFirewallCoreMetaPublication::exchange_preimage)));
static_assert(
    std::is_nothrow_move_assignable_v<RuntimeFirewallCorePublication>);

} // namespace

TEST_CASE("runtime firewall core publication exchanges one exact tuple") {
    constexpr std::uint32_t base_meta = 0x00010000U;
    constexpr std::uint32_t base_mask = 0x00ff0000U;
    constexpr std::uint32_t candidate_meta = 0x00040000U;
    constexpr std::uint32_t candidate_mask = 0x000f0000U;
    ActiveCore active;
    load_active(
        active,
        publication_named("base", 1U, 0x10000U, base_meta, base_mask));
    auto candidate = publication_named(
        "candidate",
        2U,
        0x40000U,
        candidate_meta,
        candidate_mask);

    publish_runtime_firewall_core(
        active.target(),
        candidate,
        RuntimeFirewallCoreMetaPublication::exchange_preimage);

    check_active_named(active, "candidate", candidate_meta, candidate_mask);
    check_publication_named(candidate, "base", base_meta, base_mask);

    publish_runtime_firewall_core(
        active.target(),
        candidate,
        RuntimeFirewallCoreMetaPublication::exchange_preimage);

    check_active_named(active, "base", base_meta, base_mask);
    check_publication_named(
        candidate,
        "candidate",
        candidate_meta,
        candidate_mask);
}

TEST_CASE("separate rollback publications retain the candidate Meta cursor") {
    constexpr std::uint32_t candidate_meta = 0x00040000U;
    constexpr std::uint32_t candidate_mask = 0x000f0000U;
    ActiveCore active;
    load_active(
        active,
        publication_named("base", 1U, 0x10000U, 0x10000U, 0xff0000U));
    auto candidate = publication_named(
        "candidate",
        2U,
        0x40000U,
        candidate_meta,
        candidate_mask);

    publish_runtime_firewall_core(
        active.target(),
        candidate,
        RuntimeFirewallCoreMetaPublication::retain_candidate);

    check_active_named(active, "candidate", candidate_meta, candidate_mask);
    CHECK(candidate.rules.front().outbound_tag == "base-outbound");
    CHECK(candidate.committed_meta_fwmark == candidate_meta);
    CHECK(candidate.committed_meta_owned_mask == candidate_mask);
}

TEST_CASE("core publication exchanges an empty Meta cursor exactly") {
    ActiveCore active;
    load_active(
        active,
        publication_named("base", 1U, 0x10000U, 0x10000U, 0xff0000U));
    auto candidate = publication_named(
        "candidate", 2U, 0x40000U, 0x40000U, 0x0f0000U);
    candidate.committed_meta_fwmark.reset();
    candidate.committed_meta_owned_mask = 0U;

    publish_runtime_firewall_core(
        active.target(),
        candidate,
        RuntimeFirewallCoreMetaPublication::exchange_preimage);

    CHECK_FALSE(active.committed_meta_fwmark.has_value());
    CHECK(active.committed_meta_owned_mask == 0U);
    CHECK(candidate.committed_meta_fwmark == 0x10000U);
    CHECK(candidate.committed_meta_owned_mask == 0xff0000U);
}

} // namespace keen_pbr3
