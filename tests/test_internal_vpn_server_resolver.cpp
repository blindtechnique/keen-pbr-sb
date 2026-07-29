#include <doctest/doctest.h>
#include <nlohmann/json.hpp>

#include "../src/keenetic/internal_vpn_server_resolver.hpp"
#include "../src/keenetic/internal_vpn_runtime_generation.hpp"
#include "../src/daemon/daemon.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

InternalVpnServer server_policy(
    std::string interface_name,
    bool process_clients,
    std::optional<std::string> ndms_id = std::nullopt) {
    InternalVpnServer result{};
    result.interface = std::move(interface_name);
    result.ndms_id = std::move(ndms_id);
    result.process_clients = process_clients;
    return result;
}

} // namespace

TEST_CASE("internal VPN resolver preserves existing legacy interface") {
    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg0", true)},
        NdmsInterfaceCatalog{},
        false,
        {"lo", "nwg0"});

    CHECK(result.complete());
    REQUIRE(result.effective_servers.size() == 1);
    CHECK(result.effective_servers.front().interface == "nwg0");
    CHECK_FALSE(result.effective_servers.front().ndms_id.has_value());
}

TEST_CASE("internal VPN resolver rejects vanished legacy fallback") {
    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg0", false)},
        NdmsInterfaceCatalog{},
        false,
        {"lo"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::legacy_interface_missing);
}

TEST_CASE("internal VPN stable id survives WireGuard kernel renumbering") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"StableServer",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard2"},
             {"description", "Office server"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg0", true, "StableServer")},
        catalog,
        true,
        {"lo", "nwg2"});

    CHECK(result.complete());
    REQUIRE(result.effective_servers.size() == 1);
    CHECK(result.effective_servers.front().interface == "nwg2");
    CHECK(
        result.effective_servers.front().ndms_id ==
        std::optional<std::string>{"StableServer"});
}

TEST_CASE("internal VPN explicitly confirmed role-less WireGuard server survives renumbering") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"RolelessServer",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard6"},
             {"global", false},
             {"address", "10.60.0.1/24"},
         }},
    });
    REQUIRE(catalog.tunnels.size() == 1);
    CHECK(catalog.tunnels.front().internal_vpn_server_candidate);
    CHECK(
        catalog.tunnels.front()
            .internal_vpn_server_role_confirmation_required);

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg0", true, "RolelessServer")},
        catalog,
        true,
        {"lo", "nwg6"});

    CHECK(result.complete());
    REQUIRE(result.effective_servers.size() == 1);
    CHECK(result.effective_servers.front().interface == "nwg6");
}

TEST_CASE("internal VPN rejects a client-shaped or explicit-client WireGuard id") {
    for (const auto& entry :
         std::vector<nlohmann::json>{
             nlohmann::json{
                 {"type", "Wireguard"},
                 {"interface-name", "Wireguard6"},
                 {"global", true},
                 {"address", "10.60.0.2/32"},
             },
             nlohmann::json{
                 {"type", "Wireguard"},
                 {"interface-name", "Wireguard6"},
                 {"role", "client"},
                 {"global", false},
                 {"address", "10.60.0.1/24"},
             },
         }) {
        const auto catalog = parse_ndms_interface_catalog(
            nlohmann::json{{"NotAServer", entry}});
        const auto result = resolve_internal_vpn_server_policies(
            {server_policy("nwg6", true, "NotAServer")},
            catalog,
            true,
            {"lo", "nwg6"});

        CHECK_FALSE(result.complete());
        CHECK(result.effective_servers.empty());
        REQUIRE(result.issues.size() == 1);
        CHECK(
            result.issues.front().error ==
            InternalVpnServerResolutionError::unsupported_role);
    }
}

TEST_CASE("internal VPN stable id rejects unverified saved AWG kernel name") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"AwgServer",
         {
             {"type", "AmneziaWG"},
             {"interface-name", "Amnezia0"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg7", true, "AwgServer")},
        catalog,
        true,
        {"nwg7"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    CHECK(result.safe_degraded_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::kernel_interface_unresolved);
}

TEST_CASE("internal VPN stale NDMS cannot promote a live saved kernel name") {
    const auto configured =
        server_policy("nwg4", false, "StableServer");
    const auto stale_catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"StableServer",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard4"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {configured}, stale_catalog, false, {"nwg4"});
    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::catalog_not_authoritative);
}

TEST_CASE("internal VPN authoritative catalog does not mask missing id") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"DifferentServer",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard1"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg0", false, "DeletedServer")},
        catalog,
        true,
        {"nwg0", "nwg1"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    CHECK(result.safe_degraded_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::stable_id_missing);
}

TEST_CASE("internal VPN authoritative missing id never captures a reused saved name") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"DifferentServer",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard7"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("nwg7", true, "DeletedServer")},
        catalog,
        true,
        {"lo", "nwg7"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    CHECK(result.safe_degraded_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::stable_id_missing);
}

TEST_CASE("internal VPN stable id accepts OpenVPN server on exact live name") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"OpenVpnServer",
         {
             {"type", "OpenVPN"},
             {"interface-name", "tun0"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("tun0", true, "OpenVpnServer")},
        catalog,
        true,
        {"lo", "tun0"});

    CHECK(result.complete());
    REQUIRE(result.effective_servers.size() == 1);
    CHECK(result.effective_servers.front().interface == "tun0");
}

TEST_CASE("internal VPN stable id rejects unresolved L2TP server") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"L2tpServer",
         {
             {"type", "L2TP"},
             {"interface-name", "L2tp0"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("ppp7", false, "L2tpServer")},
        catalog,
        true,
        {"lo", "ppp7"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    CHECK(result.safe_degraded_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::kernel_interface_unresolved);
}

TEST_CASE("internal VPN stable id rejects proxy even with server role") {
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"ProxyServer",
         {
             {"type", "Proxy"},
             {"proxy-type", "socks5"},
             {"interface-name", "proxy0"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        {server_policy("proxy0", true, "ProxyServer")},
        catalog,
        true,
        {"lo", "proxy0"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    CHECK(result.safe_degraded_servers.empty());
    REQUIRE(result.issues.size() == 1);
    CHECK(
        result.issues.front().error ==
        InternalVpnServerResolutionError::unsupported_kind);
}

TEST_CASE("internal VPN incomplete observation may retain an all-included verified generation") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true, "WgServer"),
        server_policy("nwg1", true, "AwgServer"),
    };
    InternalVpnServerResolution incomplete;
    incomplete.effective_servers = {
        server_policy("nwg4", true, "WgServer"),
    };
    incomplete.issues.push_back({
        InternalVpnServerResolutionError::catalog_not_authoritative,
        "nwg1",
        "AwgServer",
    });
    incomplete.retain_verified_include_ndms_ids = {
        "WgServer",
        "AwgServer",
    };
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg7", true, "WgServer"),
        server_policy("nwg8", true, "AwgServer"),
    };

    const auto selected = select_internal_vpn_server_generation(
        configured, incomplete, previous);

    CHECK(selected.usable());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::retained_previous);
    REQUIRE(selected.effective_servers.size() == 2);
    CHECK(selected.effective_servers[0].interface == "nwg7");
    CHECK(selected.effective_servers[0].ndms_id ==
          std::optional<std::string>{"WgServer"});
    CHECK(selected.effective_servers[0].process_clients);
    CHECK(selected.effective_servers[1].interface == "nwg8");
    CHECK(selected.effective_servers[1].ndms_id ==
          std::optional<std::string>{"AwgServer"});
    CHECK(selected.effective_servers[1].process_clients);
}

TEST_CASE("internal VPN inconclusive observation never retains an old bypass") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true, "WgServer"),
        server_policy("nwg1", false, "AwgServer"),
    };
    InternalVpnServerResolution incomplete;
    incomplete.issues.push_back({
        InternalVpnServerResolutionError::catalog_not_authoritative,
        "nwg1",
        "AwgServer",
    });
    incomplete.retain_verified_include_ndms_ids = {"WgServer"};
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg7", true, "WgServer"),
        server_policy("nwg8", false, "AwgServer"),
    };

    const auto selected = select_internal_vpn_server_generation(
        configured, incomplete, previous);

    CHECK(selected.usable());
    REQUIRE(selected.effective_servers.size() == 1);
    CHECK(selected.effective_servers.front().interface == "nwg7");
    CHECK(selected.effective_servers.front().process_clients);
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::retained_previous);
}

TEST_CASE("internal VPN incomplete first observation degrades without bypass") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true, "WgServer"),
    };
    InternalVpnServerResolution incomplete;
    incomplete.issues.push_back({
        InternalVpnServerResolutionError::catalog_not_authoritative,
        "nwg0",
        "WgServer",
    });

    const auto selected = select_internal_vpn_server_generation(
        configured, incomplete, {});

    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::safe_degraded_candidate);
}

TEST_CASE("internal VPN changed policy cannot reuse previous generation") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", false, "WgServer"),
    };
    InternalVpnServerResolution incomplete;
    incomplete.issues.push_back({
        InternalVpnServerResolutionError::catalog_not_authoritative,
        "nwg0",
        "WgServer",
    });
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg7", true, "WgServer"),
    };

    const auto selected = select_internal_vpn_server_generation(
        configured, incomplete, previous);

    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::safe_degraded_candidate);
}

TEST_CASE("internal VPN authoritative deletion invalidates previous generation") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true, "DeletedServer"),
    };
    InternalVpnServerResolution missing;
    missing.issues.push_back({
        InternalVpnServerResolutionError::stable_id_missing,
        "nwg0",
        "DeletedServer",
    });
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg7", true, "DeletedServer"),
    };

    const auto selected = select_internal_vpn_server_generation(
        configured, missing, previous);

    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::safe_degraded_candidate);
}

TEST_CASE("internal VPN authoritative role change invalidates previous generation") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", false, "FormerServer"),
    };
    InternalVpnServerResolution role_changed;
    role_changed.issues.push_back({
        InternalVpnServerResolutionError::unsupported_role,
        "nwg0",
        "FormerServer",
    });
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg8", false, "FormerServer"),
    };

    const auto selected = select_internal_vpn_server_generation(
        configured, role_changed, previous);

    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::safe_degraded_candidate);
}

TEST_CASE("internal VPN partial authoritative observation publishes only verified includes") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true, "ServerA"),
        server_policy("nwg1", true, "ServerB"),
    };
    const auto catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"ServerA",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard4"},
             {"role", "server"},
         }},
    });

    const auto result = resolve_internal_vpn_server_policies(
        configured, catalog, true, {"lo", "nwg4"});
    CHECK_FALSE(result.complete());
    REQUIRE(result.verified_includes_for_lkg.size() == 1);
    CHECK(result.verified_includes_for_lkg.front().interface == "nwg4");
    CHECK(result.verified_includes_for_lkg.front().ndms_id ==
          std::optional<std::string>{"ServerA"});

    const auto stale = resolve_internal_vpn_server_policies(
        configured, catalog, false, {"lo", "nwg4"});
    const auto retained = select_internal_vpn_server_generation(
        configured, stale, result.verified_includes_for_lkg);
    REQUIRE(retained.effective_servers.size() == 1);
    CHECK(retained.effective_servers.front().ndms_id ==
          std::optional<std::string>{"ServerA"});
}

TEST_CASE("mixed stale stable and missing legacy rows retain only the verified stable identity") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true, "ServerA"),
        server_policy("vanished0", true),
    };
    const auto stale = resolve_internal_vpn_server_policies(
        configured,
        NdmsInterfaceCatalog{},
        false,
        // nwg0 has been reused after ServerA was verified on nwg1.
        {"lo", "nwg0", "nwg1"});
    CHECK_FALSE(stale.complete());
    CHECK(stale.retain_verified_include_ndms_ids ==
          std::vector<std::string>{"ServerA"});

    const auto retained = select_internal_vpn_server_generation(
        configured,
        stale,
        {server_policy("nwg1", true, "ServerA")});
    REQUIRE(retained.effective_servers.size() == 1);
    CHECK(retained.effective_servers.front().interface == "nwg1");
    CHECK(retained.effective_servers.front().ndms_id ==
          std::optional<std::string>{"ServerA"});
    CHECK(
        retained.source ==
        InternalVpnServerGenerationSource::retained_previous);
}

TEST_CASE("internal VPN include LKG replaces authoritative rows and drops deleted identities") {
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg1", true, "ServerA"),
        server_policy("nwg2", true, "ServerB"),
    };
    const auto fresh = std::vector<InternalVpnServer>{
        server_policy("nwg4", true, "ServerA"),
    };

    const auto next = merge_internal_vpn_verified_includes_lkg(
        previous, fresh, {});

    REQUIRE(next.size() == 1);
    CHECK(next.front().interface == "nwg4");
    CHECK(next.front().ndms_id ==
          std::optional<std::string>{"ServerA"});
}

TEST_CASE("internal VPN include LKG retains only explicitly inconclusive stable identities") {
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg1", true, "ServerA"),
        server_policy("nwg2", true, "ServerB"),
        server_policy("nwg3", false, "ServerC"),
    };

    const auto next = merge_internal_vpn_verified_includes_lkg(
        previous, {}, {"ServerA", "ServerC"});

    REQUIRE(next.size() == 1);
    CHECK(next.front().interface == "nwg1");
    CHECK(next.front().ndms_id ==
          std::optional<std::string>{"ServerA"});
}

TEST_CASE("fresh internal VPN binding wins over retained interface collision") {
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg4", true, "StaleServer"),
    };
    const auto fresh = std::vector<InternalVpnServer>{
        server_policy("nwg4", true, "FreshServer"),
    };

    const auto next = merge_internal_vpn_verified_includes_lkg(
        previous, fresh, {"StaleServer"});

    REQUIRE(next.size() == 1);
    CHECK(next.front().ndms_id ==
          std::optional<std::string>{"FreshServer"});
}

TEST_CASE("verified stable identity wins over a stale saved-name fallback") {
    const auto configured =
        std::vector<InternalVpnServer>{
            server_policy("nwg0", true, "ServerA"),
        };
    const auto stale = resolve_internal_vpn_server_policies(
        configured,
        NdmsInterfaceCatalog{},
        false,
        // Both names exist: nwg0 may now belong to an unrelated interface.
        {"lo", "nwg0", "nwg1"});
    REQUIRE(stale.safe_degraded_servers.size() == 1);
    CHECK(stale.safe_degraded_servers.front().interface == "nwg0");

    const auto retained = select_internal_vpn_server_generation(
        configured,
        stale,
        {server_policy("nwg1", true, "ServerA")});
    REQUIRE(retained.effective_servers.size() == 1);
    CHECK(retained.effective_servers.front().interface == "nwg1");
}

TEST_CASE("internal VPN vanished legacy row cannot retain previous kernel name") {
    const auto configured = std::vector<InternalVpnServer>{
        server_policy("nwg0", true),
    };
    InternalVpnServerResolution incomplete;
    incomplete.issues.push_back({
        InternalVpnServerResolutionError::legacy_interface_missing,
        "nwg0",
        {},
    });
    const auto previous = std::vector<InternalVpnServer>{
        server_policy("nwg0", true),
    };

    const auto selected = select_internal_vpn_server_generation(
        configured, incomplete, previous);

    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::safe_degraded_candidate);
}

TEST_CASE("internal VPN unverified enabled policy may only force exact live ingress") {
    const auto configured =
        server_policy("nwg4", true, "StableServer");
    const auto result = resolve_internal_vpn_server_policies(
        {configured},
        NdmsInterfaceCatalog{},
        false,
        {"lo", "nwg4"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    REQUIRE(result.safe_degraded_servers.size() == 1);
    CHECK(result.safe_degraded_servers.front().interface == "nwg4");
    CHECK(result.safe_degraded_servers.front().process_clients);
}

TEST_CASE("internal VPN unverified disabled policy never creates bypass") {
    const auto configured =
        server_policy("nwg4", false, "StableServer");
    const auto result = resolve_internal_vpn_server_policies(
        {configured},
        NdmsInterfaceCatalog{},
        false,
        {"lo", "nwg4"});

    CHECK_FALSE(result.complete());
    CHECK(result.effective_servers.empty());
    CHECK(result.safe_degraded_servers.empty());
    const auto selected = select_internal_vpn_server_generation(
        {configured}, result, {});
    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
}

TEST_CASE("internal VPN apply-time stale observation drops a prepared bypass") {
    const auto configured =
        std::vector<InternalVpnServer>{
            server_policy("nwg4", false, "StableServer"),
        };
    const auto fresh_catalog = parse_ndms_interface_catalog(nlohmann::json{
        {"StableServer",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard4"},
             {"role", "server"},
         }},
    });
    const auto prepared = resolve_internal_vpn_server_policies(
        configured, fresh_catalog, true, {"lo", "nwg4"});
    REQUIRE(prepared.complete());
    REQUIRE(prepared.effective_servers.size() == 1);
    CHECK_FALSE(prepared.effective_servers.front().process_clients);

    const auto revalidated = resolve_internal_vpn_server_policies(
        configured, fresh_catalog, false, {"lo", "nwg4"});
    REQUIRE_FALSE(revalidated.complete());
    const auto selected = select_internal_vpn_server_generation(
        configured,
        revalidated,
        // The daemon LKG contains verified includes only. A previously
        // prepared exclusion is therefore never eligible for retention.
        {});

    CHECK(selected.usable());
    CHECK(selected.effective_servers.empty());
    CHECK(
        selected.source ==
        InternalVpnServerGenerationSource::safe_degraded_candidate);
}

TEST_CASE("internal VPN NDMS catalog is required only for stable policies") {
    CHECK_FALSE(internal_vpn_server_policies_require_ndms_catalog({}));
    CHECK_FALSE(internal_vpn_server_policies_require_ndms_catalog({
        server_policy("nwg0", true),
        server_policy("tun0", false),
    }));
    CHECK(internal_vpn_server_policies_require_ndms_catalog({
        server_policy("nwg0", true),
        server_policy("nwg1", true, "WireguardServer"),
    }));
}

TEST_CASE("stable degraded runtime generations request an asynchronous catalog refresh") {
    Config stable_config{};
    RouteConfig stable_route{};
    stable_route.internal_vpn_servers = std::vector<InternalVpnServer>{
        server_policy("nwg7", false, "StableServer"),
    };
    stable_config.route = stable_route;

    CHECK_FALSE(internal_vpn_resolution_requires_catalog_refresh(
        stable_config, InternalVpnRuntimeResolutionState::verified));
    CHECK(internal_vpn_resolution_requires_catalog_refresh(
        stable_config, InternalVpnRuntimeResolutionState::degraded));
    CHECK(internal_vpn_resolution_requires_catalog_refresh(
        stable_config,
        InternalVpnRuntimeResolutionState::retained_verified_includes));
    CHECK(internal_vpn_resolution_requires_catalog_refresh(
        stable_config,
        InternalVpnRuntimeResolutionState::authoritative_negative));

    Config legacy_config{};
    RouteConfig legacy_route{};
    legacy_route.internal_vpn_servers = std::vector<InternalVpnServer>{
        server_policy("nwg7", false),
    };
    legacy_config.route = legacy_route;
    CHECK_FALSE(internal_vpn_resolution_requires_catalog_refresh(
        legacy_config, InternalVpnRuntimeResolutionState::degraded));
}

TEST_CASE("failed native VPN runtime generation restores the previous in-memory mapping") {
    std::vector<InternalVpnServer> active{
        server_policy("nwg7", false, "StableServer"),
    };
    const std::vector<InternalVpnServer> candidate{};

    {
        InternalVpnRuntimeGenerationTransaction failed_apply(
            active, candidate);
        CHECK(active.empty());
        // No commit: model a routing/firewall exception.
    }
    REQUIRE(active.size() == 1);
    CHECK(active.front().interface == "nwg7");
    CHECK_FALSE(active.front().process_clients);

    {
        InternalVpnRuntimeGenerationTransaction successful_apply(
            active, candidate);
        CHECK(active.empty());
        successful_apply.commit();
    }
    CHECK(active.empty());
}

TEST_CASE("authoritative worker candidate publishes only after kernel apply succeeds") {
    std::vector<InternalVpnServer> active{
        server_policy("nwg7", false, "StableServer"),
    };
    const std::vector<InternalVpnServer> revoked_candidate{};
    bool lkg_published = false;

    CHECK_THROWS_AS(
        commit_internal_vpn_runtime_generation(
            active,
            revoked_candidate,
            [] {
                throw std::runtime_error("firewall commit failed");
            },
            [&lkg_published] {
                lkg_published = true;
            }),
        std::runtime_error);
    REQUIRE(active.size() == 1);
    CHECK(active.front().interface == "nwg7");
    CHECK_FALSE(lkg_published);

    commit_internal_vpn_runtime_generation(
        active,
        revoked_candidate,
        [] {},
        [&lkg_published] {
            lkg_published = true;
        });
    CHECK(active.empty());
    CHECK(lkg_published);

    active = {
        server_policy("nwg7", false, "StableServer"),
    };
    CHECK_THROWS_AS(
        commit_internal_vpn_runtime_generation(
            active,
            revoked_candidate,
            [] {},
            [] {
                throw std::runtime_error("LKG publication failed");
            }),
        std::runtime_error);
    // The kernel callback succeeded, so the candidate active map remains
    // committed even when the secondary LKG publication fails.
    CHECK(active.empty());
}

TEST_CASE("resolver failure after firewall commit keeps matching native VPN generation") {
    std::vector<InternalVpnServer> active{
        server_policy("nwg0", true, "StableServer"),
    };
    const std::vector<InternalVpnServer> candidate{
        server_policy("nwg4", true, "StableServer"),
    };

    try {
        InternalVpnRuntimeGenerationTransaction transaction(active, candidate);
        // Model successful routing/firewall COMMIT.
        transaction.commit();
        // Resolver reload is a secondary stage and must not roll active
        // ingress identity back to the pre-COMMIT kernel interface.
        throw std::runtime_error("resolver reload failed");
    } catch (const std::runtime_error&) {
    }

    REQUIRE(active.size() == 1);
    CHECK(active.front().interface == "nwg4");
}

TEST_CASE("interface events remain relevant for non-outbound internal VPN servers") {
    Config config{};
    CHECK_FALSE(interface_event_affects_managed_runtime(config, "nwg9"));
    CHECK_FALSE(config_has_stable_internal_vpn_server_policy(config));

    RouteConfig route{};
    route.internal_vpn_servers = std::vector<InternalVpnServer>{
        server_policy("nwg7", true, "StableServer"),
    };
    config.route = route;

    CHECK(interface_event_affects_managed_runtime(config, "nwg7"));
    CHECK(config_has_stable_internal_vpn_server_policy(config));
    // Unrelated/new names do not trigger an immediate firewall rebuild. The
    // event handler uses the stable-policy predicate above to schedule only
    // the coalesced async NDMS refresh.
    CHECK_FALSE(interface_event_affects_managed_runtime(config, "eth9"));
    CHECK_FALSE(interface_event_affects_managed_runtime(config, "nwg9"));
    CHECK(interface_event_affects_managed_runtime(
        config,
        {server_policy("nwg9", true, "StableServer")},
        "nwg9"));

    const auto deleted = InterfaceMonitor::describe_link_transition(
        "nwg7", false, true, false);
    CHECK(interface_event_requires_runtime_observation(deleted));
    CHECK(interface_event_affects_managed_runtime(
        config, {}, deleted.interface_name));

    // A newly created kernel name is not yet present in the persisted or
    // effective rows, but its topology event must survive the daemon's early
    // filter so the stable-ID catalog refresh can discover the renumbering.
    const auto created = InterfaceMonitor::describe_link_transition(
        "nwg9", true, std::nullopt, true);
    CHECK(interface_event_requires_runtime_observation(created));
    CHECK_FALSE(interface_event_affects_managed_runtime(
        config, {}, created.interface_name));
    CHECK(config_has_stable_internal_vpn_server_policy(config));
}

} // namespace keen_pbr3
