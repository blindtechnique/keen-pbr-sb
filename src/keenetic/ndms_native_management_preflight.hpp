#pragma once

#include "ndms_interface_management.hpp"
#include "ndms_rci_observation.hpp"
#include "ndms_rci_restorable_snapshot.hpp"

#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The paths below were measured on KeeneticOS 5.1.1. They are fixed-origin
// RCI paths, never user-provided URLs. Their responses are parsed locally and
// must not be returned to API clients because configuration documents can
// contain peer credentials and endpoints.
enum class NdmsNativeRciReadDocument {
    running_configuration,
    runtime_state,
    amnezia_asc,
};

struct NdmsNativeRciReadRequest {
    NdmsNativeRciReadDocument document{
        NdmsNativeRciReadDocument::running_configuration};
    std::string relative_path;
    bool sensitive_response{true};
};

// Returns a plan only for the measured Keenetic identity family WireguardN.
// No request is executed here and no mutation path is constructed.
std::optional<std::vector<NdmsNativeRciReadRequest>>
measured_ndms_native_read_plan(
    const NdmsTunnelInterface& interface);

enum class NdmsNativeMutationMode {
    disabled,
};

struct NdmsNativeMutationCapabilities {
    bool can_create{false};
    bool can_edit{false};
    bool can_delete{false};
    bool can_apply_import{false};
};

// Parsing and preview are deliberately independent from applying a parsed
// candidate to Keenetic. This lets a future UI accept URI/.conf input and
// show an exact preview without implying that native mutation is enabled.
struct NdmsNativeImportCapabilities {
    bool can_parse_wireguard_conf{false};
    bool can_build_preview{false};
    bool can_apply{false};
};

// These switches describe production facilities, not caller intent. The
// current production defaults are deliberately all false. Even a test or a
// future caller that supplies every facility cannot enable mutation in this
// preflight-only slice: `mutation_release_disabled` remains a hard blocker.
struct NdmsNativeMutationFacilities {
    bool wireguard_conf_parser{false};
    bool import_preview_builder{false};
    // True only for authenticated TLS or a trusted local-only transport.
    // Authentication over the ordinary WAN HTTP listener is not sufficient.
    bool protected_secret_transport{false};
    bool private_key_backup_source{false};
    bool ownership_verification{false};
    bool typed_mutation_commands{false};
    bool optimistic_compare_and_swap{false};
    bool automatic_rollback{false};
};

enum class NdmsNativePreflightBlocker {
    catalog_not_fresh,
    unsupported_kind,
    role_unknown,
    unsupported_role,
    kernel_identity_unresolved,
    measured_rci_read_plan_unavailable,
    rci_observation_unavailable,
    rci_observation_mismatch,
    restorable_snapshot_unavailable,
    restorable_snapshot_mismatch,
    protected_secret_transport_unavailable,
    private_key_backup_unavailable,
    ownership_unverified,
    typed_mutation_commands_unavailable,
    optimistic_revision_unavailable,
    automatic_rollback_unavailable,
    mutation_release_disabled,
};

struct NdmsNativeManagementPreflightInput {
    bool catalog_fresh{false};

    // Non-owning evidence valid only for the duration of the pure assessment.
    // The preflight copies safe revision tokens only, never either document.
    const NdmsRciTunnelObservation* observation{nullptr};
    const NdmsRciRestorableSnapshot* restorable_snapshot{nullptr};

    NdmsNativeMutationFacilities facilities;
};

struct NdmsNativeManagementPreflight {
    NdmsNativeMutationMode mutation_mode{
        NdmsNativeMutationMode::disabled};
    NdmsNativeMutationCapabilities capabilities;
    NdmsNativeImportCapabilities import_capabilities;
    bool candidate{false};
    bool catalog_fresh{false};
    bool inventory_identity_stable{false};
    bool measured_read_plan_available{false};
    bool observation_verified{false};
    bool restorable_snapshot_verified{false};

    // Digests only. Raw RCI documents, peer material and keys are never kept.
    std::string inventory_revision;
    std::optional<std::string> observation_revision;
    std::optional<std::string> restorable_snapshot_revision;
    std::vector<NdmsNativeRciReadRequest> read_plan;
    std::vector<NdmsNativePreflightBlocker> blockers;
};

// Pure first-stage capability assessment for an already inventoried native
// interface. It does not perform RCI I/O, construct write commands, acquire
// credentials, mutate configuration or decide ownership.
NdmsNativeManagementPreflight preflight_ndms_native_management(
    const NdmsTunnelInterface& interface,
    const NdmsNativeManagementPreflightInput& input = {});

const char* ndms_native_rci_read_document_name(
    NdmsNativeRciReadDocument document) noexcept;

const char* ndms_native_preflight_blocker_name(
    NdmsNativePreflightBlocker blocker) noexcept;

} // namespace keen_pbr3
