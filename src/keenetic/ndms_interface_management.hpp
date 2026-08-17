#pragma once

#include "ndms_interface_inventory.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NdmsInterfaceManagementBlocker {
    unsupported_kind,
    role_unknown,
    unsupported_role,
    kernel_identity_unresolved,
    typed_rci_unavailable,
    automatic_backup_unavailable,
    ownership_unknown,
    optimistic_revision_unavailable,
};

struct NdmsInterfaceManagementReadiness {
    bool candidate{false};
    bool identity_stable{false};
    std::string observed_revision;
    bool configuration_snapshot_available{false};
    std::vector<NdmsInterfaceManagementBlocker> blockers;
};

// Assesses whether an already discovered NDMS interface can enter a future
// typed management workflow. This domain is deliberately read-only: the
// observed revision is diagnostic evidence, not a mutation precondition, and
// every operation capability remains disabled until all global guards exist.
NdmsInterfaceManagementReadiness assess_ndms_interface_management(
    const NdmsTunnelInterface& interface);

const char* ndms_interface_management_blocker_name(
    NdmsInterfaceManagementBlocker blocker) noexcept;

} // namespace keen_pbr3
