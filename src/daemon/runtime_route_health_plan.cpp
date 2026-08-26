#include "runtime_route_health_plan.hpp"

#include <arpa/inet.h>
#include <charconv>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <system_error>
#include <utility>

namespace keen_pbr3 {

namespace {

bool parse_ip(const std::string& value, int family, void* output) noexcept {
    return inet_pton(family, value.c_str(), output) == 1;
}

bool ipv4_prefix_contains(const in_addr& network,
                          const in_addr& candidate,
                          int prefix_length) noexcept {
    if (prefix_length <= 0) return true;
    if (prefix_length > 32) return false;
    const std::uint32_t network_bits = ntohl(network.s_addr);
    const std::uint32_t candidate_bits = ntohl(candidate.s_addr);
    const std::uint32_t mask = prefix_length == 32
        ? 0xFFFFFFFFU
        : (~0U << (32 - prefix_length));
    return (network_bits & mask) == (candidate_bits & mask);
}

bool ipv6_prefix_contains(const in6_addr& network,
                          const in6_addr& candidate,
                          int prefix_length) noexcept {
    if (prefix_length <= 0) return true;
    if (prefix_length > 128) return false;
    const int full_bytes = prefix_length / 8;
    const int extra_bits = prefix_length % 8;
    if (full_bytes > 0 &&
        std::memcmp(
            network.s6_addr,
            candidate.s6_addr,
            static_cast<std::size_t>(full_bytes)) != 0) {
        return false;
    }
    if (extra_bits == 0) return true;
    const std::uint8_t mask = static_cast<std::uint8_t>(
        0xFFU << (8 - extra_bits));
    return (network.s6_addr[full_bytes] & mask) ==
           (candidate.s6_addr[full_bytes] & mask);
}

bool route_contains_ip(const DumpedRoute& route,
                       const std::string& ip) {
    // Preserve the compatibility helper's semantics: a default route on the
    // exact interface reaches either gateway family.
    if (route.destination == "default") return true;

    const auto slash = route.destination.find('/');
    if (slash == std::string::npos) {
        return route.destination == ip;
    }

    const std::string network = route.destination.substr(0U, slash);
    const std::string prefix = route.destination.substr(slash + 1U);
    int prefix_length = -1;
    const auto converted = std::from_chars(
        prefix.data(), prefix.data() + prefix.size(), prefix_length);
    if (converted.ec != std::errc{} ||
        converted.ptr != prefix.data() + prefix.size()) {
        return false;
    }

    const int family = ip.find(':') == std::string::npos
        ? AF_INET
        : AF_INET6;
    const int network_family =
        network.find(':') == std::string::npos ? AF_INET : AF_INET6;
    if (family != network_family) return false;

    if (family == AF_INET) {
        in_addr network_address{};
        in_addr candidate_address{};
        return parse_ip(network, AF_INET, &network_address) &&
               parse_ip(ip, AF_INET, &candidate_address) &&
               ipv4_prefix_contains(
                   network_address, candidate_address, prefix_length);
    }

    in6_addr network_address{};
    in6_addr candidate_address{};
    return parse_ip(network, AF_INET6, &network_address) &&
           parse_ip(ip, AF_INET6, &candidate_address) &&
           ipv6_prefix_contains(
               network_address, candidate_address, prefix_length);
}

bool interface_has_gateway_route(
    const std::vector<DumpedRoute>& routes,
    const std::string& interface,
    const std::string& gateway) {
    for (const auto& route : routes) {
        if (route.table != 254U || route.blackhole || route.unreachable) {
            continue;
        }
        if (!route.interface || *route.interface != interface) continue;
        if (route_contains_ip(route, gateway)) return true;
    }
    return false;
}

OutboundReachabilitySnapshot build_reachability_snapshot(
    const Config& config,
    const std::vector<DumpedRoute>& routes,
    const std::vector<DumpedInterface>& interfaces) {
    std::map<std::string, bool> interface_admin_state;
    for (const auto& interface : interfaces) {
        const auto inserted = interface_admin_state.emplace(
            interface.name, interface.admin_up);
        if (!inserted.second) {
            // A normal netlink dump has one row per name. Treat any duplicate
            // disagreement conservatively instead of selecting a stale UP.
            inserted.first->second =
                inserted.first->second && interface.admin_up;
        }
    }

    OutboundReachabilitySnapshot reachability;
    for (const auto& outbound :
         config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::INTERFACE) continue;

        const std::string interface = outbound.interface.value_or("");
        const auto observed = interface_admin_state.find(interface);
        bool reachable = !interface.empty() &&
            observed != interface_admin_state.end() &&
            observed->second;
        if (reachable && outbound.gateway.has_value()) {
            reachable = interface_has_gateway_route(
                routes, interface, *outbound.gateway);
        }
        if (reachable && outbound.gateway6.has_value()) {
            reachable = interface_has_gateway_route(
                routes, interface, *outbound.gateway6);
        }
        reachability.insert_or_assign(outbound.tag, reachable);
    }
    return reachability;
}

void retain_failure_detail(RuntimeRouteHealthFailure& failure,
                           const char* detail) noexcept {
    try {
        failure.detail = detail != nullptr ? detail : "";
    } catch (...) {
        failure.detail.clear();
    }
}

} // namespace

Ipv6SupportDecision SystemRuntimeRouteHealthServices::resolve_ipv6(
    const Config& config) {
    return resolve_ipv6_support(config);
}

std::vector<DumpedRoute>
SystemRuntimeRouteHealthServices::dump_routes() {
    return netlink_.dump_routes();
}

std::vector<DumpedInterface>
SystemRuntimeRouteHealthServices::dump_interfaces() {
    return netlink_.dump_interfaces();
}

RuntimeRouteHealthExecutionResult execute_runtime_route_health_plan(
    const RuntimeRouteHealthRequest& request,
    RuntimeRouteHealthServices& services) noexcept {
    RuntimeRouteHealthExecutionResult result;
    result.operation_serial = request.operation_serial;
    result.runtime_generation = request.runtime_generation;
    result.route_epoch = request.route_epoch;

    RuntimeRouteHealthFailureStage stage =
        RuntimeRouteHealthFailureStage::resolve_ipv6;
    try {
        auto ipv6_decision = services.resolve_ipv6(request.config);

        stage = RuntimeRouteHealthFailureStage::dump_routes;
        auto routes = services.dump_routes();

        stage = RuntimeRouteHealthFailureStage::dump_interfaces;
        auto interfaces = services.dump_interfaces();

        stage = RuntimeRouteHealthFailureStage::build_reachability;
        auto reachability = build_reachability_snapshot(
            request.config, routes, interfaces);

        stage = RuntimeRouteHealthFailureStage::plan_routing;
        auto routing = plan_routing_state(
            request.config,
            request.outbound_marks,
            reachability,
            &request.urltest_selections,
            ipv6_decision.enabled);

        RuntimeRouteHealthPlan plan;
        plan.operation_serial = request.operation_serial;
        plan.runtime_generation = request.runtime_generation;
        plan.route_epoch = request.route_epoch;
        plan.ipv6_decision = ipv6_decision;
        plan.routes_snapshot = std::move(routes);
        plan.interfaces_snapshot = std::move(interfaces);
        plan.reachability = std::move(reachability);
        plan.routing = std::move(routing);
        result.plan = std::make_shared<const RuntimeRouteHealthPlan>(
            std::move(plan));
        return result;
    } catch (const std::exception& error) {
        result.failure.stage = stage;
        result.failure.kind =
            RuntimeRouteHealthFailureKind::standard_exception;
        retain_failure_detail(result.failure, error.what());
    } catch (...) {
        result.failure.stage = stage;
        result.failure.kind =
            RuntimeRouteHealthFailureKind::unknown_exception;
        retain_failure_detail(
            result.failure, "runtime route health observation failed");
    }
    result.plan.reset();
    return result;
}

struct RuntimeRouteMutationCheckpoint::SharedState final {
    mutable std::mutex mutex;
    std::condition_variable ack_ready;
    RuntimeRouteHealthPlanPtr plan;
    bool control_claimed{false};
    std::optional<RuntimeRouteMutationAck> ack;
};

RuntimeRouteMutationCheckpoint::ControlClaim::ControlClaim(
    std::shared_ptr<SharedState> state) noexcept
    : state_(std::move(state)) {}

RuntimeRouteMutationCheckpoint::ControlClaim::~ControlClaim() noexcept {
    release_for_retry();
}

RuntimeRouteMutationCheckpoint::ControlClaim::ControlClaim(
    ControlClaim&& other) noexcept
    : state_(std::move(other.state_)),
      active_(std::exchange(other.active_, false)) {}

RuntimeRouteMutationCheckpoint::ControlClaim&
RuntimeRouteMutationCheckpoint::ControlClaim::operator=(
    ControlClaim&& other) noexcept {
    if (this == &other) return *this;
    release_for_retry();
    state_ = std::move(other.state_);
    active_ = std::exchange(other.active_, false);
    return *this;
}

RuntimeRouteHealthPlanPtr
RuntimeRouteMutationCheckpoint::ControlClaim::plan() const noexcept {
    if (!state_ || !active_) return {};
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->plan;
    } catch (...) {
        return {};
    }
}

bool RuntimeRouteMutationCheckpoint::ControlClaim::acknowledge(
    RuntimeRouteMutationAck ack) noexcept {
    if (!state_ || !active_) return false;
    bool accepted = false;
    try {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->control_claimed && !state_->ack.has_value()) {
                state_->ack = ack;
                accepted = true;
            }
            active_ = false;
        }
        if (accepted) state_->ack_ready.notify_all();
    } catch (...) {
        return false;
    }
    return accepted;
}

void RuntimeRouteMutationCheckpoint::ControlClaim::release_for_retry()
    noexcept {
    if (!state_ || !active_) return;
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->control_claimed && !state_->ack.has_value()) {
            state_->control_claimed = false;
        }
        active_ = false;
    } catch (...) {
    }
}

RuntimeRouteMutationCheckpoint::RuntimeRouteMutationCheckpoint()
    : state_(std::make_shared<SharedState>()) {}

RuntimeRouteMutationCheckpoint::~RuntimeRouteMutationCheckpoint() noexcept {
    (void)cancel();
}

bool RuntimeRouteMutationCheckpoint::publish(
    RuntimeRouteHealthPlanPtr plan) noexcept {
    if (!state_ || !plan) return false;
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->plan || state_->ack.has_value()) return false;
        state_->plan = std::move(plan);
        return true;
    } catch (...) {
        return false;
    }
}

std::optional<RuntimeRouteMutationCheckpoint::ControlClaim>
RuntimeRouteMutationCheckpoint::try_claim_control() noexcept {
    if (!state_) return std::nullopt;
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->plan || state_->control_claimed ||
            state_->ack.has_value()) {
            return std::nullopt;
        }
        state_->control_claimed = true;
        ControlClaim claim{state_};
        return std::optional<ControlClaim>{std::move(claim)};
    } catch (...) {
        return std::nullopt;
    }
}

RuntimeRouteMutationAck RuntimeRouteMutationCheckpoint::wait_ack() noexcept {
    if (!state_) return RuntimeRouteMutationAck::shutdown;
    try {
        std::unique_lock<std::mutex> lock(state_->mutex);
        state_->ack_ready.wait(lock, [this]() {
            return state_->ack.has_value();
        });
        return *state_->ack;
    } catch (...) {
        (void)cancel();
        return RuntimeRouteMutationAck::shutdown;
    }
}

bool RuntimeRouteMutationCheckpoint::cancel() noexcept {
    if (!state_) return false;
    bool cancelled = false;
    try {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (!state_->ack.has_value()) {
                state_->ack = RuntimeRouteMutationAck::shutdown;
                cancelled = true;
            }
        }
        if (cancelled) state_->ack_ready.notify_all();
    } catch (...) {
        return false;
    }
    return cancelled;
}

RuntimeRouteMutationCheckpointState
RuntimeRouteMutationCheckpoint::state() const noexcept {
    if (!state_) return RuntimeRouteMutationCheckpointState::acked;
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->ack.has_value()) {
            return RuntimeRouteMutationCheckpointState::acked;
        }
        if (state_->control_claimed) {
            return RuntimeRouteMutationCheckpointState::control_claimed;
        }
        return state_->plan
            ? RuntimeRouteMutationCheckpointState::plan_ready
            : RuntimeRouteMutationCheckpointState::empty;
    } catch (...) {
        return RuntimeRouteMutationCheckpointState::acked;
    }
}

} // namespace keen_pbr3
