#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/health/runtime_outbound_state.hpp"

#include <netinet/in.h>

using namespace keen_pbr3;

TEST_CASE("failed urltest result does not publish default zero latency") {
    URLTestResult result;
    result.success = false;
    result.latency_ms = 0;
    result.error = "probe timed out";

    CHECK_FALSE(
        runtime_outbound_detail::latency_from_urltest_result(result).has_value());
    CHECK(result.error == "probe timed out");
}

TEST_CASE("successful urltest result publishes measured latency") {
    URLTestResult result;
    result.success = true;
    result.latency_ms = 247;

    CHECK(
        runtime_outbound_detail::latency_from_urltest_result(result) ==
        std::optional<int64_t>{247});
}

namespace {

using runtime_outbound_detail::ProbeVerdict;

// The kernel state the builder reads, modelled directly. Only dump_routes is
// exercised; the mutating operations exist to satisfy the interface.
class ModelledRoutes final : public RouteNetlinkOperations {
public:
    explicit ModelledRoutes(std::vector<DumpedRoute> routes)
        : routes_(std::move(routes)) {}

    RouteAddResult add_route(const RouteSpec&) override {
        return RouteAddResult::Created;
    }
    void replace_route(const RouteSpec&) override {}
    void delete_route(const RouteSpec&) override {}
    std::vector<DumpedRoute> dump_routes(int) override { return routes_; }

private:
    std::vector<DumpedRoute> routes_;
};

DumpedRoute default_route_via(uint32_t table, std::string interface) {
    DumpedRoute route;
    route.destination = "default";
    route.table = table;
    route.interface = std::move(interface);
    route.family = AF_INET;
    return route;
}

// A single non-strict interface outbound. Table 150 is the first table the
// allocator hands out, so the outbound's policy table is 150.
Config config_with_single_interface_outbound(const std::string& interface) {
    Outbound outbound;
    outbound.tag = "dead_tunnel";
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = interface;
    outbound.strict_enforcement = false;

    Config config;
    config.outbounds = std::vector<Outbound>{outbound};
    return config;
}

constexpr uint32_t kOutboundTable = 150;

InterfaceProbeResult probe_result(bool success, bool attributed,
                                  std::chrono::steady_clock::time_point at) {
    InterfaceProbeResult probe;
    probe.success = success;
    probe.attributed = attributed;
    probe.latency_ms = success ? 163 : 0;
    probe.error = success ? "" : "HTTP request failed: Connection timed out";
    probe.measured_at = at;
    return probe;
}

api::RuntimeOutboundsResponse build_for(
    const Config& config,
    RouteNetlinkOperations& routes,
    std::optional<InterfaceProbeResult> probe,
    std::chrono::steady_clock::time_point now) {
    return build_runtime_outbounds_response(
        config,
        routes,
        [](const std::string&) -> std::optional<UrltestState> {
            return std::nullopt;
        },
        [&probe](const std::string&) { return probe; },
        now);
}

} // namespace

TEST_CASE("interface state keeps reachable IPv4 when its IPv6 gateway has no route") {
    auto config = config_with_single_interface_outbound("lo");
    config.outbounds->front().gateway = "192.0.2.1";
    config.outbounds->front().gateway6 = "2001:db8::1";
    config.daemon.emplace();
    SUBCASE("IPv6 disabled") { config.daemon->ipv6_enabled = false; }
    SUBCASE("IPv6 enabled") { config.daemon->ipv6_enabled = true; }
    auto connected = default_route_via(254, "lo");
    connected.destination = "192.0.2.0/24";
    // No installed outbound default and no probe: the verdict depends on
    // link reachability rather than an unrelated positive signal.
    ModelledRoutes routes({connected});
    const auto response = build_for(config, routes, std::nullopt,
                                   std::chrono::steady_clock::now());
    REQUIRE(response.outbounds.size() == 1);
    CHECK(response.outbounds.front().status == api::ResolverLiveStatus::UNKNOWN);
    CHECK(response.outbounds.front().interfaces.front().status ==
          api::RuntimeInterfaceStatusEnum::UNKNOWN);
}

TEST_CASE("interface state does not treat disabled IPv6 as a usable exit") {
    auto config = config_with_single_interface_outbound("lo");
    config.outbounds->front().gateway6 = "2001:db8::1";
    config.daemon.emplace();
    config.daemon->ipv6_enabled = false;
    auto connected = default_route_via(254, "lo");
    connected.destination = "2001:db8::/64";
    connected.family = AF_INET6;
    ModelledRoutes routes({connected});
    const auto response = build_for(config, routes, std::nullopt,
                                   std::chrono::steady_clock::now());
    REQUIRE(response.outbounds.size() == 1);
    CHECK(response.outbounds.front().status == api::ResolverLiveStatus::UNAVAILABLE);
}

TEST_CASE("interface probe freshness follows the production rotation cadence") {
    CHECK(runtime_outbound_detail::interface_probe_freshness_limit(2) ==
          std::chrono::seconds{60});
    CHECK(runtime_outbound_detail::interface_probe_freshness_limit(5) ==
          std::chrono::seconds{80});
    CHECK(runtime_outbound_detail::interface_probe_freshness_limit(12) ==
          std::chrono::seconds{140});
}

TEST_CASE("probe classification refuses to call unattributable evidence health") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);

    SUBCASE("no probe has ever run") {
        CHECK(runtime_outbound_detail::classify_interface_probe(std::nullopt,
                                                                now) ==
              ProbeVerdict::Unverifiable);
    }

    SUBCASE("an unpinned success only proves the router has internet") {
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(true, /*attributed=*/false, now), now) ==
              ProbeVerdict::Unverifiable);
    }

    SUBCASE("a pinned success is the only thing that verifies a transport") {
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(true, /*attributed=*/true, now), now) ==
              ProbeVerdict::Verified);
    }

    SUBCASE("a pinned failure is a real failure") {
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(false, /*attributed=*/true, now), now) ==
              ProbeVerdict::Failed);
    }

    SUBCASE("a success older than the freshness limit stops counting") {
        const auto stale = now - std::chrono::seconds(61);
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(true, /*attributed=*/true, stale), now) ==
              ProbeVerdict::Unverifiable);
    }

    SUBCASE("a success inside the freshness limit still counts") {
        const auto recent = now - std::chrono::seconds(59);
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(true, /*attributed=*/true, recent), now) ==
              ProbeVerdict::Verified);
    }

    SUBCASE("cadence boundary is current at the limit and stale after it") {
        const auto freshness_limit =
            runtime_outbound_detail::interface_probe_freshness_limit(12);
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(
                      true, /*attributed=*/true, now - freshness_limit),
                  now, freshness_limit) == ProbeVerdict::Verified);
        CHECK(runtime_outbound_detail::classify_interface_probe(
                  probe_result(
                      true, /*attributed=*/true,
                      now - freshness_limit - std::chrono::seconds{1}),
                  now, freshness_limit) == ProbeVerdict::Unverifiable);
    }

    // steady_clock's epoch is boot time on Linux, so an unstamped result is
    // only old once the machine has been up a while. The clock is injected
    // here rather than read, so this pins the rule and not the uptime.
    SUBCASE("a never-measured result is not silently fresh") {
        InterfaceProbeResult never_measured;
        never_measured.success = true;
        never_measured.attributed = true;
        CHECK(runtime_outbound_detail::classify_interface_probe(never_measured,
                                                                now) ==
              ProbeVerdict::Unverifiable);
    }
}

TEST_CASE(
    "runtime outbound builder derives probe freshness from configured "
    "interface count") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);

    Config config;
    std::vector<Outbound> outbounds;
    for (std::size_t index = 0; index < 12; ++index) {
        Outbound outbound;
        outbound.tag = "member-" + std::to_string(index);
        outbound.type = OutboundType::INTERFACE;
        outbound.interface = "nwg" + std::to_string(index);
        outbounds.push_back(std::move(outbound));
    }

    api::OutboundGroupElement members;
    members.outbounds = std::vector<std::string>{"member-0"};
    Outbound urltest;
    urltest.tag = "group";
    urltest.type = OutboundType::URLTEST;
    urltest.outbound_groups =
        std::vector<api::OutboundGroupElement>{members};
    outbounds.push_back(std::move(urltest));
    config.outbounds = std::move(outbounds);

    ModelledRoutes routes({default_route_via(kOutboundTable, "nwg0"),
                           default_route_via(162, "nwg0"),
                           default_route_via(254, "nwg0")});
    const auto response = build_for(
        config,
        routes,
        probe_result(
            /*success=*/true, /*attributed=*/true,
            now - std::chrono::seconds{100}),
        now);

    REQUIRE(response.outbounds.size() == 13);
    CHECK(response.outbounds.front().status ==
          api::ResolverLiveStatus::HEALTHY);
    REQUIRE(response.outbounds.front().interfaces.size() == 1);
    CHECK(response.outbounds.front().interfaces.front().status ==
          api::RuntimeInterfaceStatusEnum::ACTIVE);
    CHECK(response.outbounds.front().interfaces.front().latency_ms ==
          std::optional<int64_t>{163});

    // The URLTEST fallback classification receives that same calculated
    // limit; it must not silently fall back to the old fixed 60 seconds.
    const auto& group_state = response.outbounds.back();
    REQUIRE(group_state.interfaces.size() == 1);
    CHECK(group_state.interfaces.front().latency_ms ==
          std::optional<int64_t>{163});
}

// The reported defect: a tunnel device stays UP after its remote server is
// deleted, so keen-pbr's own default route through it is still installed and
// still matches the outbound. Route shape alone therefore described a dead
// transport as working.
TEST_CASE(
    "interface outbound whose pinned probe failed is not reported healthy "
    "while its default route is still installed") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);
    const auto config = config_with_single_interface_outbound("hy1");
    ModelledRoutes routes({default_route_via(kOutboundTable, "hy1")});

    const auto response =
        build_for(config, routes,
                  probe_result(/*success=*/false, /*attributed=*/true, now),
                  now);

    REQUIRE(response.outbounds.size() == 1);
    const auto& outbound = response.outbounds.front();
    CHECK(outbound.tag == "dead_tunnel");
    // Degraded, not unavailable. The device is there and its route is
    // installed; what happened is that one pinned check against one endpoint
    // did not answer. That is what the contract already calls degraded -
    // openapi.yaml: "interface exists but recent checks failed" - and calling
    // it unavailable would say this transport has no exit at all on the
    // strength of a single gstatic timeout.
    CHECK(outbound.status == api::ResolverLiveStatus::DEGRADED);
    REQUIRE(outbound.interfaces.size() == 1);
    CHECK(outbound.interfaces.front().status ==
          api::RuntimeInterfaceStatusEnum::DEGRADED);
    // The defect this case was written for stays covered: it is still not
    // healthy, and route shape alone no longer describes it as working.
    CHECK(outbound.status != api::ResolverLiveStatus::HEALTHY);
    // A failed transport must not publish a latency figure.
    CHECK_FALSE(outbound.interfaces.front().latency_ms.has_value());
}

// The other half of the same rule. Unavailable is kept for a missing
// interface or route, or for a confirmed combination of signals - here the
// probe failed and there is no route to the device at all, which is two
// independent signals agreeing rather than one endpoint timing out.
TEST_CASE(
    "interface outbound whose pinned probe failed with no route installed is "
    "reported unavailable") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);
    const auto config = config_with_single_interface_outbound("hy1");
    ModelledRoutes routes({});

    const auto response =
        build_for(config, routes,
                  probe_result(/*success=*/false, /*attributed=*/true, now),
                  now);

    REQUIRE(response.outbounds.size() == 1);
    const auto& outbound = response.outbounds.front();
    CHECK(outbound.status == api::ResolverLiveStatus::UNAVAILABLE);
    REQUIRE(outbound.interfaces.size() == 1);
    CHECK(outbound.interfaces.front().status ==
          api::RuntimeInterfaceStatusEnum::UNAVAILABLE);
}

// The non-strict outbound carries no companion blackhole rule, so when its
// table holds no usable default the marked packet falls through to main and
// leaves over the WAN. An unpinned probe then answers "yes" for every
// outbound on the router.
TEST_CASE(
    "interface outbound with no usable default is not reported healthy on an "
    "unattributable probe success") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);
    const auto config = config_with_single_interface_outbound("tchcrnr_vls");
    // The outbound's own table is empty: nothing routes through it.
    ModelledRoutes routes({});

    const auto response =
        build_for(config, routes,
                  probe_result(/*success=*/true, /*attributed=*/false, now),
                  now);

    REQUIRE(response.outbounds.size() == 1);
    const auto& outbound = response.outbounds.front();
    CHECK(outbound.status != api::ResolverLiveStatus::HEALTHY);
    REQUIRE(outbound.interfaces.size() == 1);
    CHECK(outbound.interfaces.front().status !=
          api::RuntimeInterfaceStatusEnum::ACTIVE);
    // The WAN's latency must never be published as this transport's latency.
    CHECK_FALSE(outbound.interfaces.front().latency_ms.has_value());
}

TEST_CASE(
    "interface outbound with a stale success reports cannot-verify rather "
    "than current health") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);
    const auto config = config_with_single_interface_outbound("hy1");
    ModelledRoutes routes({default_route_via(kOutboundTable, "hy1")});

    const auto response = build_for(
        config, routes,
        probe_result(/*success=*/true, /*attributed=*/true,
                     now - std::chrono::minutes(30)),
        now);

    REQUIRE(response.outbounds.size() == 1);
    const auto& outbound = response.outbounds.front();
    CHECK(outbound.status == api::ResolverLiveStatus::UNKNOWN);
    REQUIRE(outbound.interfaces.size() == 1);
    const auto& interface_state = outbound.interfaces.front();
    CHECK(interface_state.status == api::RuntimeInterfaceStatusEnum::UNKNOWN);
    CHECK_FALSE(interface_state.latency_ms.has_value());
    REQUIRE(interface_state.detail.has_value());
    CHECK(interface_state.detail->find("cannot verify") != std::string::npos);
}

// A urltest member falls back to the interface probe when urltest itself has
// no result for it. That fallback must respect attribution too, or a group
// member shows the router's WAN latency as its own.
TEST_CASE(
    "urltest member does not borrow an unattributable probe latency") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);

    Outbound child;
    child.tag = "member";
    child.type = OutboundType::INTERFACE;
    child.interface = "hy1";

    api::OutboundGroupElement group;
    group.outbounds = std::vector<std::string>{"member"};

    Outbound urltest;
    urltest.tag = "group";
    urltest.type = OutboundType::URLTEST;
    urltest.outbound_groups =
        std::vector<api::OutboundGroupElement>{group};

    Config config;
    config.outbounds = std::vector<Outbound>{child, urltest};

    ModelledRoutes routes({});

    const auto response = build_runtime_outbounds_response(
        config,
        routes,
        [](const std::string&) -> std::optional<UrltestState> {
            return std::nullopt;
        },
        [&now](const std::string&) {
            return probe_result(/*success=*/true, /*attributed=*/false, now);
        },
        now);

    REQUIRE(response.outbounds.size() == 2);
    for (const auto& outbound : response.outbounds) {
        for (const auto& member : outbound.interfaces) {
            CHECK_FALSE(member.latency_ms.has_value());
        }
    }
}

TEST_CASE(
    "selected urltest child needs a successful probe before it is active and "
    "the group is healthy") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);

    Outbound child;
    child.tag = "member";
    child.type = OutboundType::INTERFACE;
    child.interface = "nwg5";

    api::OutboundGroupElement members;
    members.outbounds = std::vector<std::string>{"member"};

    Outbound urltest;
    urltest.tag = "group";
    urltest.type = OutboundType::URLTEST;
    urltest.outbound_groups =
        std::vector<api::OutboundGroupElement>{members};

    Config config;
    config.outbounds = std::vector<Outbound>{child, urltest};

    // The child consumes table 150 and the group table 151. Table 151 has the
    // metric-0 route that used to short-circuit the member to ACTIVE even when
    // its latest URLTEST probe had failed.
    ModelledRoutes routes({default_route_via(151, "nwg5"),
                           default_route_via(254, "nwg5")});

    auto build_with = [&](std::optional<URLTestResult> latest_result) {
        UrltestState manager_state;
        manager_state.selected_outbound = "member";
        if (latest_result.has_value()) {
            manager_state.last_results.emplace("member", *latest_result);
        }

        return build_runtime_outbounds_response(
            config,
            routes,
            [&manager_state](const std::string& tag)
                -> std::optional<UrltestState> {
                return tag == "group"
                    ? std::optional<UrltestState>{manager_state}
                    : std::nullopt;
            },
            [](const std::string&)
                -> std::optional<InterfaceProbeResult> {
                return std::nullopt;
            },
            now);
    };

    SUBCASE("a failed selected probe publishes degraded rather than green") {
        URLTestResult failed;
        failed.success = false;
        failed.error = "probe timed out";

        const auto response = build_with(failed);
        REQUIRE(response.outbounds.size() == 2);
        const auto& group_state = response.outbounds.at(1);
        CHECK(group_state.status == api::ResolverLiveStatus::DEGRADED);
        REQUIRE(group_state.interfaces.size() == 1);
        CHECK(group_state.interfaces.front().status ==
              api::RuntimeInterfaceStatusEnum::DEGRADED);
        CHECK(group_state.interfaces.front().status !=
              api::RuntimeInterfaceStatusEnum::ACTIVE);
        CHECK(group_state.status != api::ResolverLiveStatus::HEALTHY);
        CHECK_FALSE(group_state.interfaces.front().latency_ms.has_value());
    }

    SUBCASE("a selected route without probe evidence remains unknown") {
        const auto response = build_with(std::nullopt);
        REQUIRE(response.outbounds.size() == 2);
        const auto& group_state = response.outbounds.at(1);
        CHECK(group_state.status == api::ResolverLiveStatus::UNKNOWN);
        REQUIRE(group_state.interfaces.size() == 1);
        CHECK(group_state.interfaces.front().status ==
              api::RuntimeInterfaceStatusEnum::UNKNOWN);
        CHECK(group_state.interfaces.front().status !=
              api::RuntimeInterfaceStatusEnum::ACTIVE);
        CHECK(group_state.status != api::ResolverLiveStatus::HEALTHY);
    }

    SUBCASE("a successful selected probe still publishes active and healthy") {
        URLTestResult success;
        success.success = true;
        success.latency_ms = 91;

        const auto response = build_with(success);
        REQUIRE(response.outbounds.size() == 2);
        const auto& group_state = response.outbounds.at(1);
        CHECK(group_state.status == api::ResolverLiveStatus::HEALTHY);
        REQUIRE(group_state.interfaces.size() == 1);
        CHECK(group_state.interfaces.front().status ==
              api::RuntimeInterfaceStatusEnum::ACTIVE);
        CHECK(group_state.interfaces.front().latency_ms ==
              std::optional<int64_t>{91});
    }
}

TEST_CASE(
    "interface outbound with a fresh pinned success is still reported "
    "healthy and active") {
    const auto now = std::chrono::steady_clock::time_point{} +
                     std::chrono::hours(9);
    const auto config = config_with_single_interface_outbound("nwg1");
    ModelledRoutes routes({default_route_via(kOutboundTable, "nwg1")});

    const auto response =
        build_for(config, routes,
                  probe_result(/*success=*/true, /*attributed=*/true, now),
                  now);

    REQUIRE(response.outbounds.size() == 1);
    const auto& outbound = response.outbounds.front();
    CHECK(outbound.status == api::ResolverLiveStatus::HEALTHY);
    REQUIRE(outbound.interfaces.size() == 1);
    CHECK(outbound.interfaces.front().status ==
          api::RuntimeInterfaceStatusEnum::ACTIVE);
    CHECK(outbound.interfaces.front().latency_ms == std::optional<int64_t>{163});
}

#endif // WITH_API
