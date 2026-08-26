#include <doctest/doctest.h>

#include "../src/daemon/runtime_route_health_plan.hpp"

#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

Outbound interface_outbound(
    std::string tag,
    std::string interface,
    std::optional<std::string> gateway = std::nullopt) {
    Outbound outbound;
    outbound.tag = std::move(tag);
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = std::move(interface);
    outbound.gateway = std::move(gateway);
    return outbound;
}

RuntimeRouteHealthRequest route_health_request() {
    RuntimeRouteHealthRequest request;
    request.operation_serial = 41U;
    request.runtime_generation = 17U;
    request.route_epoch = 9U;

    IprouteConfig iproute;
    iproute.table_start = 100U;
    request.config.iproute = iproute;

    DaemonConfig daemon;
    daemon.strict_enforcement = false;
    request.config.daemon = daemon;

    auto up = interface_outbound("up", "wg-up", "10.8.0.1");
    auto down = interface_outbound("down", "wg-down");
    auto missing = interface_outbound("missing", "wg-missing");
    auto no_gateway =
        interface_outbound("no_gateway", "wg-no-gateway", "10.9.0.1");
    Outbound fixed;
    fixed.tag = "fixed";
    fixed.type = OutboundType::TABLE;
    fixed.table = 220U;
    request.config.outbounds = std::vector<Outbound>{
        std::move(up),
        std::move(down),
        std::move(missing),
        std::move(no_gateway),
        std::move(fixed),
    };
    request.outbound_marks = {
        {"up", 1U},
        {"down", 2U},
        {"missing", 3U},
        {"no_gateway", 4U},
        {"fixed", 5U},
    };
    return request;
}

class FakeRuntimeRouteHealthServices final
    : public RuntimeRouteHealthServices {
public:
    enum class ThrowAt {
        none,
        ipv6,
        routes,
        interfaces,
        unknown_interfaces,
    };

    Ipv6SupportDecision resolve_ipv6(const Config&) override {
        ++ipv6_calls;
        if (throw_at == ThrowAt::ipv6) {
            throw std::runtime_error("ipv6 failed");
        }
        return ipv6_decision;
    }

    std::vector<DumpedRoute> dump_routes() override {
        ++route_calls;
        if (throw_at == ThrowAt::routes) {
            throw std::runtime_error("route dump failed");
        }
        return routes;
    }

    std::vector<DumpedInterface> dump_interfaces() override {
        ++interface_calls;
        if (throw_at == ThrowAt::interfaces) {
            throw std::runtime_error("interface dump failed");
        }
        if (throw_at == ThrowAt::unknown_interfaces) throw 17;
        return interfaces;
    }

    ThrowAt throw_at{ThrowAt::none};
    Ipv6SupportDecision ipv6_decision{
        false, Ipv6SupportDecision::Reason::UnsupportedBySystem};
    std::vector<DumpedRoute> routes;
    std::vector<DumpedInterface> interfaces;
    int ipv6_calls{0};
    int route_calls{0};
    int interface_calls{0};
};

RuntimeRouteHealthPlanPtr checkpoint_plan() {
    auto plan = std::make_shared<RuntimeRouteHealthPlan>();
    plan->operation_serial = 73U;
    plan->runtime_generation = 19U;
    plan->route_epoch = 4U;
    return plan;
}

} // namespace

TEST_CASE("runtime route health plan observes once and completes interface reachability") {
    auto request = route_health_request();
    const auto original_marks = request.outbound_marks;
    FakeRuntimeRouteHealthServices services;
    services.routes.push_back(DumpedRoute{
        "10.8.0.0/24",
        254U,
        std::optional<std::string>{"wg-up"},
        std::nullopt,
        false,
        false,
        AF_INET,
        0U,
        0U});
    services.interfaces = {
        DumpedInterface{"wg-up", true},
        DumpedInterface{"wg-down", false},
        DumpedInterface{"wg-no-gateway", true},
    };

    static_assert(noexcept(execute_runtime_route_health_plan(
        std::declval<const RuntimeRouteHealthRequest&>(),
        std::declval<RuntimeRouteHealthServices&>())));
    const auto result =
        execute_runtime_route_health_plan(request, services);

    REQUIRE(result.succeeded());
    REQUIRE(result.plan);
    CHECK(services.ipv6_calls == 1);
    CHECK(services.route_calls == 1);
    CHECK(services.interface_calls == 1);
    CHECK(result.operation_serial == 41U);
    CHECK(result.runtime_generation == 17U);
    CHECK(result.route_epoch == 9U);
    CHECK(result.plan->operation_serial == 41U);
    CHECK(result.plan->runtime_generation == 17U);
    CHECK(result.plan->route_epoch == 9U);
    CHECK_FALSE(result.plan->ipv6_decision.enabled);
    CHECK(result.plan->routes_snapshot.size() == 1U);
    CHECK(result.plan->interfaces_snapshot.size() == 3U);

    REQUIRE(result.plan->reachability.size() == 4U);
    CHECK(result.plan->reachability.at("up"));
    CHECK_FALSE(result.plan->reachability.at("down"));
    CHECK_FALSE(result.plan->reachability.at("missing"));
    CHECK_FALSE(result.plan->reachability.at("no_gateway"));
    CHECK(result.plan->reachability.count("fixed") == 0U);
    CHECK(request.outbound_marks == original_marks);
    CHECK_FALSE(result.plan->routing.routes.empty());
}

TEST_CASE("runtime route health plan retains the exact failed observation stage") {
    auto request = route_health_request();

    SUBCASE("standard route dump failure stops before interface observation") {
        FakeRuntimeRouteHealthServices services;
        services.throw_at =
            FakeRuntimeRouteHealthServices::ThrowAt::routes;

        const auto result =
            execute_runtime_route_health_plan(request, services);

        CHECK_FALSE(result.succeeded());
        CHECK_FALSE(result.plan);
        CHECK(result.failure.stage ==
              RuntimeRouteHealthFailureStage::dump_routes);
        CHECK(result.failure.kind ==
              RuntimeRouteHealthFailureKind::standard_exception);
        CHECK(result.failure.detail == "route dump failed");
        CHECK(services.ipv6_calls == 1);
        CHECK(services.route_calls == 1);
        CHECK(services.interface_calls == 0);
    }

    SUBCASE("unknown interface failure is not converted into absence") {
        FakeRuntimeRouteHealthServices services;
        services.throw_at =
            FakeRuntimeRouteHealthServices::ThrowAt::unknown_interfaces;

        const auto result =
            execute_runtime_route_health_plan(request, services);

        CHECK_FALSE(result.succeeded());
        CHECK_FALSE(result.plan);
        CHECK(result.failure.stage ==
              RuntimeRouteHealthFailureStage::dump_interfaces);
        CHECK(result.failure.kind ==
              RuntimeRouteHealthFailureKind::unknown_exception);
        CHECK(services.ipv6_calls == 1);
        CHECK(services.route_calls == 1);
        CHECK(services.interface_calls == 1);
    }
}

TEST_CASE("runtime route mutation checkpoint publishes and acknowledges exactly once") {
    RuntimeRouteMutationCheckpoint checkpoint;
    const auto plan = checkpoint_plan();

    CHECK(checkpoint.state() ==
          RuntimeRouteMutationCheckpointState::empty);
    CHECK(checkpoint.publish(plan));
    CHECK_FALSE(checkpoint.publish(plan));
    CHECK(checkpoint.state() ==
          RuntimeRouteMutationCheckpointState::plan_ready);

    auto claim = checkpoint.try_claim_control();
    REQUIRE(claim.has_value());
    CHECK(claim->plan() == plan);
    CHECK(checkpoint.state() ==
          RuntimeRouteMutationCheckpointState::control_claimed);
    CHECK_FALSE(checkpoint.try_claim_control().has_value());
    CHECK(claim->acknowledge(RuntimeRouteMutationAck::applied));
    CHECK_FALSE(claim->acknowledge(RuntimeRouteMutationAck::stale));
    CHECK(checkpoint.state() ==
          RuntimeRouteMutationCheckpointState::acked);
    CHECK(checkpoint.wait_ack() == RuntimeRouteMutationAck::applied);
    CHECK_FALSE(checkpoint.cancel());
}

TEST_CASE("runtime route mutation checkpoint retries an unacked RAII claim") {
    RuntimeRouteMutationCheckpoint checkpoint;
    const auto plan = checkpoint_plan();
    REQUIRE(checkpoint.publish(plan));

    {
        auto abandoned = checkpoint.try_claim_control();
        REQUIRE(abandoned.has_value());
        CHECK(abandoned->plan() == plan);
    }
    CHECK(checkpoint.state() ==
          RuntimeRouteMutationCheckpointState::plan_ready);

    auto retry = checkpoint.try_claim_control();
    REQUIRE(retry.has_value());
    CHECK(retry->acknowledge(
        RuntimeRouteMutationAck::route_unavailable));
    CHECK(checkpoint.wait_ack() ==
          RuntimeRouteMutationAck::route_unavailable);
}

TEST_CASE("runtime route mutation checkpoint cancellation wakes the worker") {
    using namespace std::chrono_literals;

    RuntimeRouteMutationCheckpoint checkpoint;
    REQUIRE(checkpoint.publish(checkpoint_plan()));
    auto waiting = std::async(std::launch::async, [&checkpoint]() {
        return checkpoint.wait_ack();
    });

    CHECK(waiting.wait_for(20ms) == std::future_status::timeout);
    CHECK(checkpoint.cancel());
    REQUIRE(waiting.wait_for(1s) == std::future_status::ready);
    CHECK(waiting.get() == RuntimeRouteMutationAck::shutdown);
    CHECK(checkpoint.state() ==
          RuntimeRouteMutationCheckpointState::acked);
    CHECK_FALSE(checkpoint.cancel());
    CHECK_FALSE(checkpoint.try_claim_control().has_value());
}
