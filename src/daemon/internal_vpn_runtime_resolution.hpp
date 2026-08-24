#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../config/config.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"

namespace keen_pbr3 {

enum class InternalVpnRuntimeResolutionState : std::uint8_t {
    verified,
    retained_verified_includes,
    degraded,
    authoritative_negative,
};

struct InternalVpnRuntimeResolution {
    std::vector<InternalVpnServer> effective_servers;
    InternalVpnRuntimeResolutionState state{
        InternalVpnRuntimeResolutionState::degraded};
    std::vector<InternalVpnServer> verified_includes_for_lkg;
    std::vector<std::string> retain_verified_include_ndms_ids;
};

struct InternalVpnServiceRuntimeResolution {
    std::vector<InternalVpnRuntimeTarget> effective_targets;
    InternalVpnRuntimeResolutionState state{
        InternalVpnRuntimeResolutionState::degraded};
    std::vector<InternalVpnRuntimeTarget> verified_includes_for_lkg;
    std::vector<std::string> retain_verified_include_service_ids;
};

// One immutable, generation-fenced native-VPN observation. Keeping both
// resolution domains in the same allocation makes partial or mixed catalogue
// hand-offs structurally impossible.
struct PreparedNativeVpnCatalog {
    std::uint64_t runtime_generation{0U};
    InternalVpnRuntimeResolution interface_resolution;
    InternalVpnServiceRuntimeResolution service_resolution;
    bool schedule_catalog_refresh{true};
};

using PreparedNativeVpnCatalogPtr =
    std::shared_ptr<const PreparedNativeVpnCatalog>;

} // namespace keen_pbr3
