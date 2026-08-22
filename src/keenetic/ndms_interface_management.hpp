#pragma once

#include "ndms_interface_inventory.hpp"
#include "ndms_native_exact_mutation_transport.hpp"
#include "ndms_native_writer_lease.hpp"

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

enum class NdmsNativeInterfaceLifecycleAction {
    up,
    down,
    restart,
};

enum class NdmsNativeInterfaceLifecycleStatus {
    completed,
    not_started,
    outcome_unknown,
};

struct NdmsNativeInterfaceLifecycleResult final {
    NdmsNativeInterfaceLifecycleStatus status{
        NdmsNativeInterfaceLifecycleStatus::not_started};
    bool request_may_have_been_dispatched{false};
};

// Applies the ordinary Keenetic up/down lifecycle command to an already
// discovered Wireguard interface and persists the resulting state. It does
// not create, edit, rename or delete an interface.
class NdmsNativeInterfaceLifecycleCoordinator final {
public:
    explicit NdmsNativeInterfaceLifecycleCoordinator(
        NdmsNativeExactMutationBackend& backend) noexcept;

    NdmsNativeInterfaceLifecycleResult apply_once(
        NdmsNativeWriterLease& writer,
        std::string interface_name,
        NdmsNativeInterfaceLifecycleAction action) noexcept;

private:
    NdmsNativeExactMutationTransportResult dispatch_once(
        NdmsNativeExactMutationRequest request,
        NdmsNativeExactMutationPreDispatchGuard& guard);

    NdmsNativeExactMutationBackend* backend_{nullptr};
};

} // namespace keen_pbr3
