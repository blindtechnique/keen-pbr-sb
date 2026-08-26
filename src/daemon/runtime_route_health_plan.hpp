#pragma once

#include "../config/routing_state.hpp"
#include "../routing/netlink.hpp"
#include "../util/ipv6_support.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Immutable once handed to the worker. Every daemon-owned input needed to
// build the desired routing generation is copied before live observation
// starts; the observer never reads Daemon, FirewallState, RouteTable or
// PolicyRuleManager.
struct RuntimeRouteHealthRequest final {
    std::uint64_t operation_serial{0U};
    std::uint64_t runtime_generation{0U};
    std::uint64_t route_epoch{0U};
    Config config;
    OutboundMarkMap outbound_marks;
    std::map<std::string, std::string> urltest_selections;
};

enum class RuntimeRouteHealthFailureStage : std::uint8_t {
    none,
    resolve_ipv6,
    dump_routes,
    dump_interfaces,
    build_reachability,
    plan_routing,
};

enum class RuntimeRouteHealthFailureKind : std::uint8_t {
    none,
    standard_exception,
    unknown_exception,
};

struct RuntimeRouteHealthFailure final {
    RuntimeRouteHealthFailureStage stage{
        RuntimeRouteHealthFailureStage::none};
    RuntimeRouteHealthFailureKind kind{
        RuntimeRouteHealthFailureKind::none};
    std::string detail;

    bool failed() const noexcept {
        return kind != RuntimeRouteHealthFailureKind::none;
    }
};

// Complete immutable worker result. routes_snapshot contains the one live
// route dump used both for main-table gateway reachability and for the later
// worker mutation. interfaces_snapshot is likewise the
// one link/address dump used for every interface outbound.
struct RuntimeRouteHealthPlan final {
    std::uint64_t operation_serial{0U};
    std::uint64_t runtime_generation{0U};
    std::uint64_t route_epoch{0U};
    Ipv6SupportDecision ipv6_decision;
    std::vector<DumpedRoute> routes_snapshot;
    std::vector<DumpedInterface> interfaces_snapshot;
    OutboundReachabilitySnapshot reachability;
    PlannedRoutingState routing;
};

using RuntimeRouteHealthPlanPtr =
    std::shared_ptr<const RuntimeRouteHealthPlan>;

struct RuntimeRouteHealthExecutionResult final {
    std::uint64_t operation_serial{0U};
    std::uint64_t runtime_generation{0U};
    std::uint64_t route_epoch{0U};
    RuntimeRouteHealthPlanPtr plan;
    RuntimeRouteHealthFailure failure;

    bool succeeded() const noexcept {
        return static_cast<bool>(plan) && !failure.failed();
    }
};

// Narrow injectable live-observation boundary. Production performs exactly
// one call to each dump method per execution; tests can prove call counts and
// failure classification without constructing a real NetlinkManager.
class RuntimeRouteHealthServices {
public:
    virtual ~RuntimeRouteHealthServices() = default;

    virtual Ipv6SupportDecision resolve_ipv6(const Config& config) = 0;
    virtual std::vector<DumpedRoute> dump_routes() = 0;
    virtual std::vector<DumpedInterface> dump_interfaces() = 0;
};

class SystemRuntimeRouteHealthServices final
    : public RuntimeRouteHealthServices {
public:
    explicit SystemRuntimeRouteHealthServices(NetlinkManager& netlink)
        : netlink_(netlink) {}

    Ipv6SupportDecision resolve_ipv6(const Config& config) override;
    std::vector<DumpedRoute> dump_routes() override;
    std::vector<DumpedInterface> dump_interfaces() override;

private:
    NetlinkManager& netlink_;
};

// Every service exception is converted into a typed result. No partial plan
// is published and no live observation is retried inside this function.
RuntimeRouteHealthExecutionResult execute_runtime_route_health_plan(
    const RuntimeRouteHealthRequest& request,
    RuntimeRouteHealthServices& services) noexcept;

enum class RuntimeRouteMutationAck : std::uint8_t {
    applied,
    stale,
    route_unavailable,
    mutation_failed,
    shutdown,
};

enum class RuntimeRouteMutationCheckpointState : std::uint8_t {
    empty,
    plan_ready,
    control_claimed,
    acked,
};

// One typed publication rendezvous after the worker has released the combined
// routing owner. It is not an operation state machine: the retry
// coordinator's running claim and terminal mailbox remain the sole
// authorities. An unacked RAII control claim returns the checkpoint to
// plan_ready so the owner's watchdog can post the same idempotent pump again.
class RuntimeRouteMutationCheckpoint final {
private:
    struct SharedState;

public:
    class ControlClaim final {
    public:
        ~ControlClaim() noexcept;

        ControlClaim(const ControlClaim&) = delete;
        ControlClaim& operator=(const ControlClaim&) = delete;
        ControlClaim(ControlClaim&& other) noexcept;
        ControlClaim& operator=(ControlClaim&& other) noexcept;

        RuntimeRouteHealthPlanPtr plan() const noexcept;
        bool acknowledge(RuntimeRouteMutationAck ack) noexcept;

    private:
        friend class RuntimeRouteMutationCheckpoint;

        explicit ControlClaim(
            std::shared_ptr<SharedState> state) noexcept;
        void release_for_retry() noexcept;

        std::shared_ptr<SharedState> state_;
        bool active_{true};
    };

    RuntimeRouteMutationCheckpoint();
    ~RuntimeRouteMutationCheckpoint() noexcept;

    RuntimeRouteMutationCheckpoint(
        const RuntimeRouteMutationCheckpoint&) = delete;
    RuntimeRouteMutationCheckpoint& operator=(
        const RuntimeRouteMutationCheckpoint&) = delete;
    RuntimeRouteMutationCheckpoint(
        RuntimeRouteMutationCheckpoint&&) = delete;
    RuntimeRouteMutationCheckpoint& operator=(
        RuntimeRouteMutationCheckpoint&&) = delete;

    bool publish(RuntimeRouteHealthPlanPtr plan) noexcept;
    std::optional<ControlClaim> try_claim_control() noexcept;
    RuntimeRouteMutationAck wait_ack() noexcept;
    bool cancel() noexcept;
    RuntimeRouteMutationCheckpointState state() const noexcept;

private:
    std::shared_ptr<SharedState> state_;
};

} // namespace keen_pbr3
