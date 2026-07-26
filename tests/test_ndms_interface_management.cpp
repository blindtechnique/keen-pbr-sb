#include <doctest/doctest.h>

#include "keenetic/ndms_interface_inventory.hpp"
#include "keenetic/ndms_interface_management.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

bool has_blocker(
    const NdmsInterfaceManagementReadiness& readiness,
    const NdmsInterfaceManagementBlocker blocker) {
    return std::find(
               readiness.blockers.begin(),
               readiness.blockers.end(),
               blocker) != readiness.blockers.end();
}

NdmsTunnelInterface parsed_interface(
    const nlohmann::json& entry,
    const std::string& id = "Wireguard1",
    const std::vector<std::string>& runtime_names = {"nwg1"}) {
    const auto catalog = parse_ndms_interface_catalog(
        nlohmann::json{{id, entry}},
        runtime_names);
    REQUIRE(catalog.tunnels.size() == 1);
    return catalog.tunnels.front();
}

} // namespace

TEST_CASE("WG and AWG clients are management candidates but operations stay disabled") {
    for (const auto& type : {"Wireguard", "AmneziaWireguard"}) {
        CAPTURE(type);
        const auto interface = parsed_interface(
            {{"type", type},
             {"interface-name", "Wireguard1"},
             {"role", "client"}});

        const auto readiness =
            assess_ndms_interface_management(interface);

        CHECK(readiness.candidate);
        CHECK(readiness.identity_stable);
        CHECK_FALSE(readiness.observed_revision.empty());
        CHECK(readiness.observed_revision.size() == 72);
        CHECK_FALSE(readiness.configuration_snapshot_available);
        CHECK_FALSE(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::unsupported_kind));
        CHECK_FALSE(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::role_unknown));
        CHECK_FALSE(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::unsupported_role));
        CHECK_FALSE(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::kernel_identity_unresolved));
        CHECK(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::typed_rci_unavailable));
        CHECK(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::automatic_backup_unavailable));
        CHECK(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::ownership_unknown));
        CHECK(has_blocker(
            readiness,
            NdmsInterfaceManagementBlocker::optimistic_revision_unavailable));
        CHECK(
            readiness.blockers ==
            std::vector<NdmsInterfaceManagementBlocker>{
                NdmsInterfaceManagementBlocker::typed_rci_unavailable,
                NdmsInterfaceManagementBlocker::automatic_backup_unavailable,
                NdmsInterfaceManagementBlocker::ownership_unknown,
                NdmsInterfaceManagementBlocker::
                    optimistic_revision_unavailable});
    }
}

TEST_CASE("unsupported kinds and roles have precise local blockers") {
    const auto openvpn = parsed_interface(
        {{"type", "OpenVPN"},
         {"interface-name", "ovpn0"},
         {"role", "client"}},
        "OpenVpn0",
        {"ovpn0"});
    const auto unsupported =
        assess_ndms_interface_management(openvpn);
    CHECK_FALSE(unsupported.candidate);
    CHECK(unsupported.identity_stable);
    CHECK(has_blocker(
        unsupported,
        NdmsInterfaceManagementBlocker::unsupported_kind));

    const auto server = parsed_interface(
        {{"type", "Wireguard"},
         {"interface-name", "Wireguard1"},
         {"role", "server"}});
    const auto server_readiness =
        assess_ndms_interface_management(server);
    CHECK_FALSE(server_readiness.candidate);
    CHECK_FALSE(has_blocker(
        server_readiness,
        NdmsInterfaceManagementBlocker::unsupported_kind));
    CHECK(has_blocker(
        server_readiness,
        NdmsInterfaceManagementBlocker::unsupported_role));
    CHECK_FALSE(has_blocker(
        server_readiness,
        NdmsInterfaceManagementBlocker::role_unknown));

    const auto unknown_role = parsed_interface(
        {{"type", "Wireguard"},
         {"interface-name", "Wireguard1"}});
    const auto unknown_readiness =
        assess_ndms_interface_management(unknown_role);
    CHECK_FALSE(unknown_readiness.candidate);
    CHECK(has_blocker(
        unknown_readiness,
        NdmsInterfaceManagementBlocker::role_unknown));
    CHECK_FALSE(has_blocker(
        unknown_readiness,
        NdmsInterfaceManagementBlocker::unsupported_role));
}

TEST_CASE("missing kernel identity blocks future management") {
    const auto interface = parsed_interface(
        {{"type", "Wireguard"},
         {"interface-name", "Wireguard1"},
         {"role", "client"}},
        "Wireguard1",
        {});

    const auto readiness =
        assess_ndms_interface_management(interface);

    CHECK(readiness.candidate);
    CHECK_FALSE(readiness.identity_stable);
    CHECK(has_blocker(
        readiness,
        NdmsInterfaceManagementBlocker::kernel_identity_unresolved));
}

TEST_CASE("observed revision ignores live state and changes with structure") {
    const auto base_entry = nlohmann::json{
        {"type", "Wireguard"},
        {"interface-name", "Wireguard1"},
        {"role", "client"},
        {"description", "Primary"},
        {"mtu", 1420},
        {"connected", false},
        {"link", false},
    };
    auto live_changed_entry = base_entry;
    live_changed_entry["connected"] = true;
    live_changed_entry["link"] = true;
    auto structure_changed_entry = live_changed_entry;
    structure_changed_entry["mtu"] = 1380;

    const auto base = parsed_interface(base_entry);
    const auto live_changed = parsed_interface(live_changed_entry);
    const auto structure_changed =
        parsed_interface(structure_changed_entry);

    CHECK(base.inventory_revision == live_changed.inventory_revision);
    CHECK(
        assess_ndms_interface_management(base).observed_revision ==
        assess_ndms_interface_management(live_changed).observed_revision);
    CHECK(base.inventory_revision != structure_changed.inventory_revision);
    CHECK(
        assess_ndms_interface_management(base).observed_revision !=
        assess_ndms_interface_management(structure_changed).observed_revision);
}

TEST_CASE("raw inventory credentials are not retained in management state") {
    const std::string secret = "private-key-material-that-must-not-leak";
    const auto first = parsed_interface(
        {{"type", "Wireguard"},
         {"interface-name", "Wireguard1"},
         {"role", "client"},
         {"private-key", secret}});
    const auto second = parsed_interface(
        {{"type", "Wireguard"},
         {"interface-name", "Wireguard1"},
         {"role", "client"},
         {"private-key", "a-different-private-key"}});

    const auto first_readiness =
        assess_ndms_interface_management(first);
    const auto second_readiness =
        assess_ndms_interface_management(second);

    CHECK(first.inventory_revision.find(secret) == std::string::npos);
    CHECK(first.inventory_revision == second.inventory_revision);
    CHECK(
        first_readiness.observed_revision ==
        second_readiness.observed_revision);
    CHECK(first_readiness.observed_revision.find(secret) == std::string::npos);
    CHECK(first_readiness.observed_revision.rfind("ndms-v1-", 0) == 0);
}

TEST_CASE("management blocker names are stable machine-readable tokens") {
    CHECK(
        std::string{ndms_interface_management_blocker_name(
            NdmsInterfaceManagementBlocker::unsupported_kind)} ==
        "unsupported_kind");
    CHECK(
        std::string{ndms_interface_management_blocker_name(
            NdmsInterfaceManagementBlocker::unsupported_role)} ==
        "unsupported_role");
    CHECK(
        std::string{ndms_interface_management_blocker_name(
            NdmsInterfaceManagementBlocker::optimistic_revision_unavailable)} ==
        "optimistic_revision_unavailable");
}
