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
    CHECK(outbound.status == api::ResolverLiveStatus::UNAVAILABLE);
    REQUIRE(outbound.interfaces.size() == 1);
    CHECK(outbound.interfaces.front().status ==
          api::RuntimeInterfaceStatusEnum::UNAVAILABLE);
    // A failed transport must not publish a latency figure.
    CHECK_FALSE(outbound.interfaces.front().latency_ms.has_value());
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
