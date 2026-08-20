#include "doctest/doctest.h"

#include "../src/keenetic/ndms_native_config_dependencies.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

Outbound interface_outbound(std::string tag, std::string interface_name) {
    Outbound outbound;
    outbound.tag = std::move(tag);
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = std::move(interface_name);
    return outbound;
}

InternalVpnServer internal_server(
    std::string interface_name,
    std::optional<std::string> ndms_id = std::nullopt) {
    InternalVpnServer server;
    server.interface = std::move(interface_name);
    server.ndms_id = std::move(ndms_id);
    return server;
}

NdmsNativeConfigDependencySnapshot snapshot_from(
    const Config& active,
    const std::optional<Config>& staged = std::nullopt) {
    NdmsNativeConfigDependencySnapshot snapshot;
    snapshot.active = project_ndms_native_config_dependencies(active);
    if (staged.has_value()) {
        snapshot.staged =
            project_ndms_native_config_dependencies(*staged);
    }
    return snapshot;
}

NdmsNativeKeenPbrDependencyObservation observe(
    const NdmsNativeConfigDependencySnapshot& snapshot) {
    return observe_ndms_native_config_dependencies(
        snapshot, "Wireguard5", std::string{"nwg5"});
}

bool completes_with_active_view(NdmsNativeConfigDependencyView view) {
    NdmsNativeConfigDependencySnapshot snapshot;
    snapshot.active = std::move(view);
    return observe(snapshot).complete;
}

} // namespace

static_assert(!std::is_same_v<
              decltype(NdmsNativeConfigDependencySnapshot{}.active),
              Config>);

TEST_CASE("native config dependency projection covers all active and staged kinds") {
    Config active;
    active.outbounds = std::vector<Outbound>{
        interface_outbound("vpn-active", "nwg5"),
        interface_outbound("other", "nwg6"),
    };
    active.route = RouteConfig{};
    active.route->inbound_interfaces =
        std::vector<std::string>{"nwg7", "nwg5"};
    active.route->internal_vpn_servers =
        std::vector<InternalVpnServer>{
            internal_server("nwg8", "Wireguard5"),
        };
    active.ui_preferences = UiPreferencesConfig{};
    active.ui_preferences->hidden_native_interface_ids =
        std::vector<std::string>{"Wireguard6", "Wireguard5"};

    Config staged;
    staged.outbounds = std::vector<Outbound>{
        interface_outbound("vpn-draft", "nwg5"),
    };
    staged.route = RouteConfig{};
    staged.route->inbound_interfaces =
        std::vector<std::string>{"nwg5"};
    staged.route->internal_vpn_servers =
        std::vector<InternalVpnServer>{internal_server("nwg5")};
    staged.ui_preferences = UiPreferencesConfig{};
    staged.ui_preferences->hidden_native_interface_ids =
        std::vector<std::string>{"Wireguard5"};

    const auto observed = observe(snapshot_from(active, staged));
    REQUIRE(observed.complete);
    CHECK(observed.firmware_interface_name == "Wireguard5");
    CHECK(observed.kernel_interface_name ==
          std::optional<std::string>{"nwg5"});
    CHECK(observed.references ==
          std::vector<NdmsNativeKeenPbrDependency>{
              {NdmsNativeKeenPbrDependencyKind::interface_outbound,
               "active:outbound:vpn-active"},
              {NdmsNativeKeenPbrDependencyKind::interface_outbound,
               "staged:outbound:vpn-draft"},
              {NdmsNativeKeenPbrDependencyKind::internal_vpn_policy,
               "active:route.internal_vpn_servers:Wireguard5"},
              {NdmsNativeKeenPbrDependencyKind::internal_vpn_policy,
               "staged:route.internal_vpn_servers:Wireguard5"},
              {NdmsNativeKeenPbrDependencyKind::inbound_interface_policy,
               "active:route.inbound_interfaces:nwg5"},
              {NdmsNativeKeenPbrDependencyKind::inbound_interface_policy,
               "staged:route.inbound_interfaces:nwg5"},
              {NdmsNativeKeenPbrDependencyKind::native_interface_preference,
               "active:ui_preferences.hidden_native_interface_ids:Wireguard5"},
              {NdmsNativeKeenPbrDependencyKind::native_interface_preference,
               "staged:ui_preferences.hidden_native_interface_ids:Wireguard5"},
          });
    CHECK(observed.keen_pbr_dependency_revision ==
          ndms_native_keen_pbr_dependency_revision(observed));
}

TEST_CASE("native config dependency projection excludes unrelated sensitive config") {
    const std::string secret = "user:password@private.invalid/token";
    Config config;
    auto target = interface_outbound("vpn", "nwg5");
    target.display_name = secret;
    target.gateway = secret;
    target.url = secret;
    Outbound unrelated;
    unrelated.tag = secret;
    unrelated.type = OutboundType::URLTEST;
    unrelated.url = secret;
    config.outbounds = std::vector<Outbound>{target, unrelated};

    ListConfig list;
    list.url = std::string{"https://"} + secret;
    config.lists = std::map<std::string, ListConfig>{{secret, list}};
    config.route = RouteConfig{};
    config.route->inbound_interfaces =
        std::vector<std::string>{"nwg5"};
    config.route->internal_vpn_servers =
        std::vector<InternalVpnServer>{
            internal_server("nwg5", "Wireguard5"),
        };
    config.ui_preferences = UiPreferencesConfig{};
    config.ui_preferences->hidden_native_interface_ids =
        std::vector<std::string>{"Wireguard5"};

    const auto projected = project_ndms_native_config_dependencies(config);
    REQUIRE(projected.interface_outbounds.size() == 1U);
    CHECK(projected.interface_outbounds.front().tag == "vpn");
    CHECK(projected.interface_outbounds.front().interface ==
          std::optional<std::string>{"nwg5"});
    CHECK(projected.route_inbound_kernel_interface_ids ==
          std::vector<std::string>{"nwg5"});
    REQUIRE(projected.internal_vpn_servers.size() == 1U);
    CHECK(projected.internal_vpn_servers.front().interface == "nwg5");
    CHECK(projected.internal_vpn_servers.front().ndms_id ==
          std::optional<std::string>{"Wireguard5"});
    CHECK(projected.hidden_native_firmware_interface_ids ==
          std::vector<std::string>{"Wireguard5"});

    const auto observed = observe_ndms_native_config_dependencies(
        NdmsNativeConfigDependencySnapshot{projected, std::nullopt},
        "Wireguard5",
        std::string{"nwg5"});
    REQUIRE(observed.complete);
    for (const auto& reference : observed.references) {
        CHECK(reference.dependent_id.find(secret) == std::string::npos);
    }
    CHECK(observed.keen_pbr_dependency_revision.find(secret) ==
          std::string::npos);

    Config without_unrelated = config;
    without_unrelated.lists.reset();
    without_unrelated.outbounds->pop_back();
    without_unrelated.outbounds->front().display_name.reset();
    without_unrelated.outbounds->front().gateway.reset();
    without_unrelated.outbounds->front().url.reset();
    const auto without_unrelated_observed =
        observe(snapshot_from(without_unrelated));
    REQUIRE(without_unrelated_observed.complete);
    CHECK(without_unrelated_observed.references == observed.references);
    CHECK(without_unrelated_observed.keen_pbr_dependency_revision ==
          observed.keen_pbr_dependency_revision);
}

TEST_CASE("native config dependency revision is reorder stable and relevant sensitive") {
    Config first;
    first.outbounds = std::vector<Outbound>{
        interface_outbound("vpn-b", "nwg5"),
        interface_outbound("other", "nwg7"),
        interface_outbound("vpn-a", "nwg5"),
    };
    first.route = RouteConfig{};
    first.route->inbound_interfaces =
        std::vector<std::string>{"nwg8", "nwg5"};
    first.route->internal_vpn_servers =
        std::vector<InternalVpnServer>{
            internal_server("nwg8", "Wireguard5"),
            internal_server("nwg9", "Wireguard9"),
        };
    first.ui_preferences = UiPreferencesConfig{};
    first.ui_preferences->hidden_native_interface_ids =
        std::vector<std::string>{"Wireguard8", "Wireguard5"};

    Config reordered = first;
    std::reverse(reordered.outbounds->begin(), reordered.outbounds->end());
    std::reverse(
        reordered.route->inbound_interfaces->begin(),
        reordered.route->inbound_interfaces->end());
    std::reverse(
        reordered.route->internal_vpn_servers->begin(),
        reordered.route->internal_vpn_servers->end());
    std::reverse(
        reordered.ui_preferences->hidden_native_interface_ids->begin(),
        reordered.ui_preferences->hidden_native_interface_ids->end());

    const auto first_observed = observe(snapshot_from(first));
    const auto reordered_observed = observe(snapshot_from(reordered));
    REQUIRE(first_observed.complete);
    REQUIRE(reordered_observed.complete);
    CHECK(first_observed.references == reordered_observed.references);
    CHECK(first_observed.keen_pbr_dependency_revision ==
          reordered_observed.keen_pbr_dependency_revision);

    Config relevant_change = reordered;
    for (auto& outbound : *relevant_change.outbounds) {
        if (outbound.tag == "vpn-b") outbound.tag = "vpn-c";
    }
    const auto changed_observed = observe(snapshot_from(relevant_change));
    REQUIRE(changed_observed.complete);
    CHECK(changed_observed.keen_pbr_dependency_revision !=
          first_observed.keen_pbr_dependency_revision);

    NdmsNativeConfigDependencySnapshot staged_only;
    staged_only.staged = project_ndms_native_config_dependencies(first);
    const auto staged_observed = observe(staged_only);
    REQUIRE(staged_observed.complete);
    CHECK(staged_observed.keen_pbr_dependency_revision !=
          first_observed.keen_pbr_dependency_revision);
    for (const auto& reference : staged_observed.references) {
        CHECK(reference.dependent_id.rfind("staged:", 0U) == 0U);
    }
}

TEST_CASE("native config dependency scan fails closed on duplicate identities") {
    SUBCASE("interface outbound tag") {
        NdmsNativeConfigDependencyView view;
        view.interface_outbounds = {
            {"vpn", std::string{"nwg5"}},
            {"vpn", std::string{"nwg5"}},
        };
        CHECK_FALSE(completes_with_active_view(std::move(view)));
    }
    SUBCASE("route inbound interface") {
        NdmsNativeConfigDependencyView view;
        view.route_inbound_kernel_interface_ids = {"nwg5", "nwg5"};
        CHECK_FALSE(completes_with_active_view(std::move(view)));
    }
    SUBCASE("internal server ambiguity") {
        NdmsNativeConfigDependencyView view;
        view.internal_vpn_servers = {
            {"nwg5", std::nullopt},
            {"nwg8", std::string{"Wireguard5"}},
        };
        CHECK_FALSE(completes_with_active_view(std::move(view)));
    }
    SUBCASE("hidden native interface") {
        NdmsNativeConfigDependencyView view;
        view.hidden_native_firmware_interface_ids = {
            "Wireguard5", "Wireguard5"};
        CHECK_FALSE(completes_with_active_view(std::move(view)));
    }
    SUBCASE("empty matching outbound identity") {
        NdmsNativeConfigDependencyView view;
        view.interface_outbounds = {
            {"", std::string{"nwg5"}},
        };
        CHECK_FALSE(completes_with_active_view(std::move(view)));
    }
}

TEST_CASE("native config dependency scan is exact and stable when empty") {
    Config config;
    config.outbounds = std::vector<Outbound>{
        interface_outbound("other", "nwg6"),
    };
    config.route = RouteConfig{};
    config.route->inbound_interfaces =
        std::vector<std::string>{"nwg6"};
    config.route->internal_vpn_servers =
        std::vector<InternalVpnServer>{
            internal_server("nwg6", "Wireguard6"),
        };
    config.ui_preferences = UiPreferencesConfig{};
    config.ui_preferences->hidden_native_interface_ids =
        std::vector<std::string>{"Wireguard6"};

    const auto snapshot = snapshot_from(config);
    const auto first = observe(snapshot);
    const auto second = observe(snapshot);
    REQUIRE(first.complete);
    CHECK(first.references.empty());
    CHECK(first.keen_pbr_dependency_revision ==
          second.keen_pbr_dependency_revision);
}

TEST_CASE("native config dependency scan fails closed on unsafe identity") {
    NdmsNativeConfigDependencySnapshot snapshot;

    CHECK_FALSE(observe_ndms_native_config_dependencies(
                    snapshot, "Wireguard4", std::string{"nwg4"})
                    .complete);
    CHECK_FALSE(observe_ndms_native_config_dependencies(
                    snapshot, "Wireguard5", std::nullopt)
                    .complete);
    CHECK_FALSE(observe_ndms_native_config_dependencies(
                    snapshot, "Wireguard5", std::string{"bad/name"})
                    .complete);
}

TEST_CASE("native config dependency provider reads one coherent snapshot and fails closed") {
    int calls = 0;
    NdmsNativeConfigDependencyProvider available{
        [&calls]() -> std::optional<NdmsNativeConfigDependencySnapshot> {
            ++calls;
            return NdmsNativeConfigDependencySnapshot{};
        }};
    CHECK(available.observe_dependencies(
              "Wireguard5", std::string{"nwg5"})
              .complete);
    CHECK(calls == 1);

    NdmsNativeConfigDependencyProvider absent{
        []() -> std::optional<NdmsNativeConfigDependencySnapshot> {
            return std::nullopt;
        }};
    CHECK_FALSE(absent.observe_dependencies(
                    "Wireguard5", std::string{"nwg5"})
                    .complete);

    NdmsNativeConfigDependencyProvider throwing{
        []() -> std::optional<NdmsNativeConfigDependencySnapshot> {
            throw std::runtime_error("unavailable");
        }};
    CHECK_FALSE(throwing.observe_dependencies(
                     "Wireguard5", std::string{"nwg5"})
                     .complete);
}
