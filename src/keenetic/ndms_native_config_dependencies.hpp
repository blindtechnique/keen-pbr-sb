#pragma once

#include "ndms_native_cooperative_delete.hpp"

#include "../config/config.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct NdmsNativeConfigInterfaceOutboundDependency final {
    std::string tag;
    std::optional<std::string> interface;
};

struct NdmsNativeConfigInternalVpnServerDependency final {
    std::string interface;
    std::optional<std::string> ndms_id;
};

// Narrow, owned projection of only the configuration fields that can retain a
// native interface. In particular, this type cannot carry list contents,
// URLs, credentials, DNS configuration or unrelated routing rules.
struct NdmsNativeConfigDependencyView final {
    std::vector<NdmsNativeConfigInterfaceOutboundDependency>
        interface_outbounds;
    std::vector<std::string> route_inbound_kernel_interface_ids;
    std::vector<NdmsNativeConfigInternalVpnServerDependency>
        internal_vpn_servers;
    std::vector<std::string> hidden_native_firmware_interface_ids;
};

// One coherent pair of owned projections. `active` is what the running router
// integration currently uses; `staged` is the optional unsaved panel draft.
// A native interface cannot be deleted while either view refers to it. The
// reader must capture both projections in one ConfigStore synchronization
// boundary; the provider invokes it exactly once per observation.
struct NdmsNativeConfigDependencySnapshot final {
    NdmsNativeConfigDependencyView active;
    std::optional<NdmsNativeConfigDependencyView> staged;
};

// Pure projector for use while the caller owns the ConfigStore read boundary.
// Allocation failures propagate to that caller and are converted to an
// unavailable, fail-closed observation by the provider.
NdmsNativeConfigDependencyView project_ndms_native_config_dependencies(
    const Config& config);

using NdmsNativeConfigDependencySnapshotReader =
    std::function<std::optional<NdmsNativeConfigDependencySnapshot>()>;

// Production adapter for the delete coordinator's deliberately narrow
// dependency seam. It never mutates ConfigStore and reports only stable,
// redacted dependent identities; configuration contents and credentials do
// not cross the boundary.
class NdmsNativeConfigDependencyProvider final
    : public NdmsNativeKeenPbrDependencyProvider {
public:
    explicit NdmsNativeConfigDependencyProvider(
        NdmsNativeConfigDependencySnapshotReader reader);

    NdmsNativeKeenPbrDependencyObservation observe_dependencies(
        const std::string& firmware_interface_name,
        const std::optional<std::string>& kernel_interface_name)
        noexcept override;

private:
    NdmsNativeConfigDependencySnapshotReader reader_;
};

// Pure helper used by the adapter and focused tests. Any malformed identity,
// duplicate dependent identity or unavailable snapshot returns an incomplete
// observation, which blocks delete.
NdmsNativeKeenPbrDependencyObservation
observe_ndms_native_config_dependencies(
    const NdmsNativeConfigDependencySnapshot& snapshot,
    const std::string& firmware_interface_name,
    const std::optional<std::string>& kernel_interface_name) noexcept;

} // namespace keen_pbr3
