#include <doctest/doctest.h>

#include "../src/runtime/meta_udp_443_activation_contract.hpp"
#include "../src/runtime/whatsapp_catalog_identity.hpp"

#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

class FakeMetaUdp443ActivationBackend final
    : public MetaUdp443ActivationBackendServices {
public:
    bool fastnat_disabled{true};
    ConntrackCleanupResult capability{ConntrackCleanupResult::Succeeded};
    std::vector<DumpedInterface> interfaces;
    ConntrackFlowObservation observation;
    bool fail_interface_dump{false};
    std::vector<std::string> calls;

    std::size_t fastnat_calls{0U};
    std::size_t capability_calls{0U};
    std::size_t interface_calls{0U};
    std::size_t observation_calls{0U};
    bool observed_ipv6_capability{false};
    std::vector<std::string> observed_destinations;
    std::vector<std::string> observed_local_addresses;
    std::uint32_t observed_owned_mask{0U};
    ConntrackFlowObservationOptions observed_options;
    std::vector<std::string> observed_media_guard_sources;
    std::vector<std::string> observed_media_seed_destinations;
    std::set<std::uint32_t> observed_media_seed_owned_marks;

    bool fastnat_is_disabled_or_unavailable() override {
        calls.push_back("fastnat");
        ++fastnat_calls;
        return fastnat_disabled;
    }

    ConntrackCleanupResult probe_exact_cleanup_capability(
        bool ipv6_enabled) override {
        calls.push_back("capability");
        ++capability_calls;
        observed_ipv6_capability = ipv6_enabled;
        return capability;
    }

    std::vector<DumpedInterface> dump_interfaces() override {
        calls.push_back("interfaces");
        ++interface_calls;
        if (fail_interface_dump) {
            throw NetlinkError("recorded Netlink observation failure");
        }
        return interfaces;
    }

    ConntrackFlowObservation observe_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        std::uint32_t owned_mask,
        const ConntrackFlowObservationOptions& options,
        const std::vector<std::string>& media_guard_source_addresses,
        const std::vector<std::string>& media_seed_destination_cidrs,
        const std::set<std::uint32_t>& media_seed_owned_marks) override {
        calls.push_back("observation");
        ++observation_calls;
        observed_destinations = destination_cidrs;
        observed_local_addresses = local_interface_addresses;
        observed_owned_mask = owned_mask;
        observed_options = options;
        observed_media_guard_sources = media_guard_source_addresses;
        observed_media_seed_destinations =
            media_seed_destination_cidrs;
        observed_media_seed_owned_marks = media_seed_owned_marks;
        return observation;
    }
};

Config meta_activation_config(bool messages_first = true) {
    const auto policy = messages_first
        ? R"json("meta_udp443_policy": "messages_first",)json"
        : std::string{};
    return parse_config(
        std::string{R"json({
          "daemon": {
            )json"} + policy + R"json(
            "ipv6_enabled": false
          },
          "fwmark": {"mask": "0x00FF0000"},
          "lists": {
            "companion": {
              "catalog_identity": ")json" +
        kWhatsappIpCatalogIdentity + R"json(",
              "ip_cidrs": ["31.13.64.0/18"]
            }
          }
        })json");
}

RuleState active_meta_rule() {
    RuleState rule;
    rule.rule_index = 0U;
    rule.list_names = {"companion"};
    rule.set_names = {"kpbr4s_companion"};
    rule.outbound_tag = "vpn";
    rule.action_type = RuleActionType::Mark;
    rule.fwmark = 0x00070000U;
    return rule;
}

ConntrackExactForwardedFlow exact_udp443_flow(std::uint32_t mark = 0U) {
    ConntrackExactForwardedFlow flow;
    flow.family = ConntrackFlowFamily::Ipv4;
    flow.protocol = ConntrackFlowProtocol::Udp;
    flow.source = "192.168.1.44";
    flow.destination = "31.13.66.10";
    flow.source_port = 42000U;
    flow.destination_port = 443U;
    flow.mark = mark;
    return flow;
}

MetaUdp443ActivationInput active_input() {
    MetaUdp443ActivationInput input;
    input.config = meta_activation_config();
    input.candidate_rules = {active_meta_rule()};
    input.candidate_list_content_state.static_destinations["companion"] = {
        "157.240.0.0/16",
        "31.13.64.0/18",
        "31.13.64.0/18",
    };
    input.forwarded_scope_allows_unmarked_cleanup = true;
    input.committed_fwmark = 0x00060000U;
    input.committed_owned_mask = 0x00FF0000U;
    return input;
}

FakeMetaUdp443ActivationBackend successful_backend() {
    FakeMetaUdp443ActivationBackend backend;
    DumpedInterface first;
    first.name = "br0";
    first.ipv4_addresses = {"192.168.1.1/24", "10.0.0.1/24"};
    DumpedInterface second;
    second.name = "nwg0";
    second.ipv4_addresses = {"10.0.0.1/24"};
    backend.interfaces = {std::move(first), std::move(second)};
    backend.observation.media_seed_flows = {exact_udp443_flow()};
    return backend;
}

} // namespace

TEST_CASE("Meta activation contract returns exact worker-owned authority") {
    auto input = active_input();
    auto backend = successful_backend();

    const auto plan = prepare_meta_udp443_activation_or_throw(
        input, backend);

    REQUIRE(plan.has_value());
    CHECK(plan->expected_fwmark == 0x00070000U);
    CHECK(plan->owned_mask == 0x00FF0000U);
    CHECK(plan->cleanup_owned_marks ==
          std::set<std::uint32_t>{0x00060000U, 0x00070000U});
    CHECK(plan->destination_selectors ==
          std::vector<std::string>{
              "157.240.0.0/16", "31.13.64.0/18"});
    CHECK_FALSE(plan->ipv6_enabled);
    CHECK(plan->allow_unmarked_cleanup);
    CHECK(plan->exact_flows ==
          std::vector<ConntrackExactForwardedFlow>{exact_udp443_flow()});

    CHECK(backend.fastnat_calls == 1U);
    CHECK(backend.capability_calls == 1U);
    CHECK_FALSE(backend.observed_ipv6_capability);
    CHECK(backend.interface_calls == 1U);
    CHECK(backend.observation_calls == 1U);
    CHECK(backend.observed_destinations == plan->destination_selectors);
    CHECK(backend.observed_media_seed_destinations ==
          plan->destination_selectors);
    CHECK(backend.observed_local_addresses ==
          std::vector<std::string>{"10.0.0.1/24", "192.168.1.1/24"});
    CHECK(backend.observed_owned_mask == 0x00FF0000U);
    CHECK(backend.observed_options.max_flows == 256U);
    CHECK(backend.observed_options.max_destination_input_cidrs == 1024U);
    CHECK(backend.observed_options.max_snapshot_bytes ==
          2U * 1024U * 1024U);
    CHECK(backend.observed_options.max_snapshot_lines == 8192U);
    CHECK(backend.observed_options.allow_foreign_mark_bits_for_media);
    CHECK_FALSE(
        backend.observed_options.include_ordinary_destination_flows);
    CHECK(backend.observed_options.media_seed_udp_destination_port == 443U);
    CHECK(backend.observed_media_guard_sources.empty());
    CHECK(backend.observed_media_seed_owned_marks.empty());
    CHECK(backend.calls ==
          std::vector<std::string>{
              "fastnat", "capability", "interfaces", "observation"});
}

TEST_CASE("inactive Meta policy performs no backend observation") {
    auto input = active_input();
    input.config = meta_activation_config(false);
    auto backend = successful_backend();

    const auto plan = prepare_meta_udp443_activation_or_throw(
        input, backend);

    CHECK_FALSE(plan.has_value());
    CHECK(backend.fastnat_calls == 0U);
    CHECK(backend.capability_calls == 0U);
    CHECK(backend.interface_calls == 0U);
    CHECK(backend.observation_calls == 0U);
}

TEST_CASE("forwarded scope keeps zero-mark activation tuples untouched") {
    auto input = active_input();
    input.forwarded_scope_allows_unmarked_cleanup = false;
    auto backend = successful_backend();

    const auto plan = prepare_meta_udp443_activation_or_throw(
        input, backend);

    REQUIRE(plan.has_value());
    CHECK_FALSE(plan->allow_unmarked_cleanup);
    CHECK(plan->exact_flows.empty());
    CHECK(backend.observation_calls == 1U);
}

TEST_CASE("Meta activation contract preserves fail-closed error boundaries") {
    auto input = active_input();
    auto backend = successful_backend();

    SUBCASE("FastNAT must be verified off") {
        backend.fastnat_disabled = false;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "daemon.meta_udp443_policy=messages_first requires verified "
            "FastNAT-off packet traversal",
            MetaUdp443ActivationError);
        CHECK(backend.capability_calls == 0U);
    }

    SUBCASE("conntrack utility must exist") {
        backend.capability = ConntrackCleanupResult::CommandUnavailable;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "daemon.meta_udp443_policy=messages_first requires the "
            "conntrack utility for exact activation cleanup",
            MetaUdp443ActivationError);
        CHECK(backend.interface_calls == 0U);
    }

    SUBCASE("conntrack capability failure is distinct from absence") {
        backend.capability = ConntrackCleanupResult::Failed;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "daemon.meta_udp443_policy=messages_first could not verify "
            "the exact conntrack cleanup capability",
            MetaUdp443ActivationError);
        CHECK(backend.interface_calls == 0U);
    }

    SUBCASE("active committed policy cannot change mark mask") {
        input.committed_owned_mask = 0x000F0000U;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "Meta UDP/443 messages-first cannot change the fwmark mask "
            "while the policy is active; switch to balanced first",
            MetaUdp443ActivationError);
        CHECK(backend.capability_calls == 0U);
    }

    SUBCASE("previous committed mark must belong to the owned mask") {
        input.committed_fwmark = 0x01000001U;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "Meta UDP/443 messages-first cannot prove the previously "
            "committed route mark for exact activation cleanup",
            MetaUdp443ActivationError);
        CHECK(backend.capability_calls == 0U);
    }

    SUBCASE("authoritative destination coverage must be complete") {
        input.candidate_list_content_state.domain_entry_lists.insert(
            "companion");
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "Meta UDP/443 messages-first policy requires complete "
            "authoritative activation cleanup coverage before publication",
            MetaUdp443ActivationError);
        CHECK(backend.interface_calls == 0U);
    }

    SUBCASE("authoritative destination coverage cannot be empty") {
        input.candidate_list_content_state.static_destinations.clear();
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "Meta UDP/443 messages-first policy requires complete "
            "authoritative activation cleanup coverage before publication",
            MetaUdp443ActivationError);
        CHECK(backend.interface_calls == 0U);
    }

    SUBCASE(
        "authoritative destination coverage cannot contain a global selector") {
        input.candidate_list_content_state.static_destinations["companion"] = {
            "0.0.0.0/0"};
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "Meta UDP/443 messages-first policy requires complete "
            "authoritative activation cleanup coverage before publication",
            MetaUdp443ActivationError);
        CHECK(backend.interface_calls == 0U);
    }

    SUBCASE("conntrack activation snapshot must be complete") {
        backend.observation.snapshot_unavailable = true;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "Meta UDP/443 messages-first policy requires a complete exact "
            "conntrack activation snapshot before publication",
            MetaUdp443ActivationError);
        CHECK(backend.observation_calls == 1U);
    }

    SUBCASE("backend observation exceptions propagate unchanged") {
        backend.fail_interface_dump = true;
        CHECK_THROWS_WITH_AS(
            prepare_meta_udp443_activation_or_throw(input, backend),
            "recorded Netlink observation failure",
            NetlinkError);
        CHECK(backend.interface_calls == 1U);
        CHECK(backend.observation_calls == 0U);
    }
}
