#pragma once

#include "meta_udp_443_activation_plan.hpp"

#include "../config/config.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/netlink.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

class MetaUdp443ActivationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Immutable, fully owned policy input captured before blocking backend
// observation begins. It can cross a worker boundary without retaining any
// Daemon field or control-loop object.
struct MetaUdp443ActivationInput {
    Config config;
    std::vector<RuleState> candidate_rules;
    AppliedListContentState candidate_list_content_state;
    bool forwarded_scope_allows_unmarked_cleanup{false};
    std::optional<std::uint32_t> committed_fwmark;
    std::uint32_t committed_owned_mask{0U};
};

// Narrow read-only production seam. Implementations may wrap the real
// ConntrackManager and NetlinkManager, while deterministic tests provide
// immutable observations without executing system commands.
class MetaUdp443ActivationBackendServices {
public:
    virtual ~MetaUdp443ActivationBackendServices() = default;

    virtual bool fastnat_is_disabled_or_unavailable() = 0;
    virtual ConntrackCleanupResult probe_exact_cleanup_capability(
        bool ipv6_enabled) = 0;
    virtual std::vector<DumpedInterface> dump_interfaces() = 0;
    virtual ConntrackFlowObservation observe_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        std::uint32_t owned_mask,
        const ConntrackFlowObservationOptions& options,
        const std::vector<std::string>& media_guard_source_addresses,
        const std::vector<std::string>& media_seed_destination_cidrs,
        const std::set<std::uint32_t>& media_seed_owned_marks) = 0;
};

// Explicit production adapter used by delayed backend transactions. It owns
// no daemon state: the caller retains and serializes the two backend services
// for the complete observation boundary.
class SystemMetaUdp443ActivationBackendServices final
    : public MetaUdp443ActivationBackendServices {
public:
    SystemMetaUdp443ActivationBackendServices(
        ConntrackManager& conntrack_manager,
        NetlinkManager& netlink);

    bool fastnat_is_disabled_or_unavailable() override;
    ConntrackCleanupResult probe_exact_cleanup_capability(
        bool ipv6_enabled) override;
    std::vector<DumpedInterface> dump_interfaces() override;
    ConntrackFlowObservation observe_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        std::uint32_t owned_mask,
        const ConntrackFlowObservationOptions& options,
        const std::vector<std::string>& media_guard_source_addresses,
        const std::vector<std::string>& media_seed_destination_cidrs,
        const std::set<std::uint32_t>& media_seed_owned_marks) override;

private:
    ConntrackManager& conntrack_manager_;
    NetlinkManager& netlink_;
};

// The bounded observation contract shared by initial activation and its
// generation-fenced retry. Keeping it here prevents the two paths from
// silently acquiring different conntrack limits or filters.
ConntrackFlowObservationOptions
meta_udp443_activation_observation_options(bool ipv6_enabled);

// Exact system FastNAT observation used by the production adapter and by the
// daemon's existing health/recovery callers.
bool system_fastnat_is_disabled_or_unavailable();

// Worker-safe policy preflight. Policy failures use a runtime-owned exception;
// backend exceptions propagate unchanged. The Daemon compatibility wrapper
// translates only MetaUdp443ActivationError back to DaemonError.
std::optional<MetaUdp443ActivationPlan>
prepare_meta_udp443_activation_or_throw(
    const MetaUdp443ActivationInput& input,
    MetaUdp443ActivationBackendServices& services);

// Production adapter overload. Both mutable services are explicit and no
// Daemon reference is retained or consulted. The caller still owns mutation
// admission, backend serialization and generation fencing; this adapter is a
// read-only observation seam, not an operation coordinator.
std::optional<MetaUdp443ActivationPlan>
prepare_meta_udp443_activation_or_throw(
    const MetaUdp443ActivationInput& input,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink);

} // namespace keen_pbr3
