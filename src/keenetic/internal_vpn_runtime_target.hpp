#pragma once

#include "../config/config.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

enum class InternalVpnRuntimeMatchKind : std::uint8_t {
    interface,
    source_pool,
};

// Runtime-only, verified ingress selector. Persisted configuration stores a
// stable NDMS identity; source pools are always re-derived from a fresh,
// bounded firmware observation.
struct InternalVpnRuntimeTarget {
    std::string stable_id;
    InternalVpnRuntimeMatchKind match_kind{
        InternalVpnRuntimeMatchKind::interface};
    bool process_clients{true};
    // Stable NDMS binding retained for diagnostics and reconciliation. It is
    // not trusted as a kernel interface until the current Netlink inventory
    // verifies an exact match in `interface`.
    std::optional<std::string> bound_interface_id;
    std::optional<std::string> interface;
    std::vector<std::string> source_cidrs_v4;
    std::vector<std::string> source_cidrs_v6;
};

inline InternalVpnRuntimeTarget internal_vpn_interface_runtime_target(
    const InternalVpnServer& server) {
    InternalVpnRuntimeTarget target;
    target.stable_id = server.ndms_id.has_value()
        ? "ndms-interface:" + *server.ndms_id
        : "kernel-interface:" + server.interface;
    target.match_kind = InternalVpnRuntimeMatchKind::interface;
    target.process_clients = server.process_clients;
    target.interface = server.interface;
    return target;
}

inline std::vector<InternalVpnRuntimeTarget>
internal_vpn_interface_runtime_targets(
    const std::vector<InternalVpnServer>& servers) {
    std::vector<InternalVpnRuntimeTarget> result;
    result.reserve(servers.size());
    for (const auto& server : servers) {
        result.push_back(internal_vpn_interface_runtime_target(server));
    }
    return result;
}

} // namespace keen_pbr3
