#include <doctest/doctest.h>

#include "../src/daemon/runtime_internal_vpn_lkg_store.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

InternalVpnServer server(
    std::string interface_name,
    std::string ndms_id) {
    InternalVpnServer result;
    result.interface = std::move(interface_name);
    result.ndms_id = std::move(ndms_id);
    result.process_clients = true;
    return result;
}

InternalVpnRuntimeTarget service_target(
    std::string stable_id,
    std::string cidr) {
    InternalVpnRuntimeTarget result;
    result.stable_id = std::move(stable_id);
    result.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    result.process_clients = true;
    result.source_cidrs_v4.push_back(std::move(cidr));
    return result;
}

const InternalVpnServer* find_server(
    const std::vector<InternalVpnServer>& servers,
    const std::string& ndms_id) {
    const auto found = std::find_if(
        servers.begin(),
        servers.end(),
        [&ndms_id](const auto& candidate) {
            return candidate.ndms_id ==
                std::optional<std::string>{ndms_id};
        });
    return found == servers.end() ? nullptr : &*found;
}

const InternalVpnRuntimeTarget* find_service_target(
    const std::vector<InternalVpnRuntimeTarget>& targets,
    const std::string& stable_id) {
    const auto found = std::find_if(
        targets.begin(),
        targets.end(),
        [&stable_id](const auto& candidate) {
            return candidate.stable_id == stable_id;
        });
    return found == targets.end() ? nullptr : &*found;
}

InternalVpnRuntimeResolution server_resolution(
    InternalVpnRuntimeResolutionState state,
    std::vector<InternalVpnServer> verified,
    std::vector<std::string> retain = {}) {
    InternalVpnRuntimeResolution result;
    result.state = state;
    result.verified_includes_for_lkg = std::move(verified);
    result.retain_verified_include_ndms_ids = std::move(retain);
    return result;
}

InternalVpnServiceRuntimeResolution service_resolution(
    InternalVpnRuntimeResolutionState state,
    std::vector<InternalVpnRuntimeTarget> verified,
    std::vector<std::string> retain = {}) {
    InternalVpnServiceRuntimeResolution result;
    result.state = state;
    result.verified_includes_for_lkg = std::move(verified);
    result.retain_verified_include_service_ids = std::move(retain);
    return result;
}

} // namespace

TEST_CASE("runtime internal VPN LKG ignores unverified generations") {
    RuntimeInternalVpnLkgStore store;

    store.update_servers(server_resolution(
        InternalVpnRuntimeResolutionState::degraded,
        {server("nwg1", "server-1")}));
    store.update_service_targets(service_resolution(
        InternalVpnRuntimeResolutionState::
            retained_verified_includes,
        {service_target("service-1", "10.1.0.0/24")}));

    CHECK(store.snapshot_servers().empty());
    CHECK(store.snapshot_service_targets().empty());
}

TEST_CASE("runtime internal VPN LKG preserves both existing merge contracts") {
    RuntimeInternalVpnLkgStore store;
    store.update_servers(server_resolution(
        InternalVpnRuntimeResolutionState::verified,
        {
            server("nwg1", "server-1"),
            server("nwg2", "server-2"),
        }));
    store.update_service_targets(service_resolution(
        InternalVpnRuntimeResolutionState::verified,
        {
            service_target("service-1", "10.1.0.0/24"),
            service_target("service-2", "10.2.0.0/24"),
        }));

    store.update_servers(server_resolution(
        InternalVpnRuntimeResolutionState::authoritative_negative,
        {server("nwg7", "server-1")},
        {"server-2"}));
    store.update_service_targets(service_resolution(
        InternalVpnRuntimeResolutionState::authoritative_negative,
        {service_target("service-1", "10.7.0.0/24")},
        {"service-2"}));

    const auto servers = store.snapshot_servers();
    REQUIRE(servers.size() == 2U);
    REQUIRE(find_server(servers, "server-1") != nullptr);
    CHECK(find_server(servers, "server-1")->interface == "nwg7");
    REQUIRE(find_server(servers, "server-2") != nullptr);
    CHECK(find_server(servers, "server-2")->interface == "nwg2");

    const auto targets = store.snapshot_service_targets();
    REQUIRE(targets.size() == 2U);
    REQUIRE(find_service_target(targets, "service-1") != nullptr);
    CHECK(
        find_service_target(targets, "service-1")
            ->source_cidrs_v4 ==
        std::vector<std::string>{"10.7.0.0/24"});
    REQUIRE(find_service_target(targets, "service-2") != nullptr);
    CHECK(
        find_service_target(targets, "service-2")
            ->source_cidrs_v4 ==
        std::vector<std::string>{"10.2.0.0/24"});
}

TEST_CASE(
    "runtime internal VPN LKG publication exchanges one exact reversible pair") {
    RuntimeInternalVpnLkgStore store;
    store.update_servers(server_resolution(
        InternalVpnRuntimeResolutionState::verified,
        {server("nwg1", "server-1")}));
    store.update_service_targets(service_resolution(
        InternalVpnRuntimeResolutionState::verified,
        {service_target("service-1", "10.1.0.0/24")}));

    auto publication = store.prepare_publication(
        server_resolution(
            InternalVpnRuntimeResolutionState::verified,
            {server("nwg9", "server-9")}),
        service_resolution(
            InternalVpnRuntimeResolutionState::verified,
            {service_target("service-9", "10.9.0.0/24")}));

    REQUIRE(store.snapshot_servers().size() == 1U);
    CHECK(store.snapshot_servers().front().interface == "nwg1");
    REQUIRE(publication.servers.size() == 1U);
    CHECK(publication.servers.front().interface == "nwg9");

    store.exchange(publication);
    REQUIRE(store.snapshot_servers().size() == 1U);
    CHECK(store.snapshot_servers().front().interface == "nwg9");
    REQUIRE(store.snapshot_service_targets().size() == 1U);
    CHECK(
        store.snapshot_service_targets().front().stable_id ==
        "service-9");
    REQUIRE(publication.servers.size() == 1U);
    CHECK(publication.servers.front().interface == "nwg1");
    REQUIRE(publication.service_targets.size() == 1U);
    CHECK(publication.service_targets.front().stable_id == "service-1");

    store.exchange(publication);
    REQUIRE(store.snapshot_servers().size() == 1U);
    CHECK(store.snapshot_servers().front().interface == "nwg1");
    REQUIRE(store.snapshot_service_targets().size() == 1U);
    CHECK(
        store.snapshot_service_targets().front().stable_id ==
        "service-1");
    REQUIRE(publication.servers.size() == 1U);
    CHECK(publication.servers.front().interface == "nwg9");
    REQUIRE(publication.service_targets.size() == 1U);
    CHECK(publication.service_targets.front().stable_id == "service-9");
}

} // namespace keen_pbr3
