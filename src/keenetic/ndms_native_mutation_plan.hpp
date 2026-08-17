#pragma once

#include "ndms_native_tunnel_import.hpp"

#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace keen_pbr3 {

// This module describes only the three non-secret RCI command shapes measured
// on KeeneticOS 5.1.1. It deliberately has no JSON serializer, HTTP client or
// execution hook. In particular, a plan is not an enabled mutation
// capability.
struct NdmsNativeSetInterfaceDownOperation {
    std::string interface_name;
};

struct NdmsNativeSetInterfaceDescriptionOperation {
    std::string interface_name;
    std::string description;
};

struct NdmsNativeDeleteInterfaceOperation {
    std::string interface_name;
};

using NdmsNativeMutationOperation = std::variant<
    NdmsNativeSetInterfaceDownOperation,
    NdmsNativeSetInterfaceDescriptionOperation,
    NdmsNativeDeleteInterfaceOperation>;

enum class NdmsNativeMutationIntent {
    create,
    edit,
    erase,
    import,
};

enum class NdmsNativeMutationPlanSemantics {
    // Operations are shown in their intended order, but neither the stock RCI
    // surface nor this pure module provides an atomic transaction.
    ordered_non_atomic_preview,
};

// There is deliberately no `trusted` enumerator. Until a verifier with opaque
// construction exists, caller claims can be retained for a redacted preview
// but can never authorize an operation.
enum class NdmsNativeEvidenceProvenance {
    caller_supplied_untrusted,
};

// The revision strings are one-way digests produced by the existing NDMS
// inventory/observation/snapshot parsers. These caller-supplied receipts are
// target-bound but explicitly untrusted; raw RCI documents and credentials
// are not retained.
struct NdmsNativeTargetAbsenceEvidence {
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    NdmsNativeEvidenceProvenance provenance{
        NdmsNativeEvidenceProvenance::caller_supplied_untrusted};
    bool target_absent{false};
    std::string inventory_revision;
};

struct NdmsNativeOwnedTargetEvidence {
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    NdmsNativeEvidenceProvenance provenance{
        NdmsNativeEvidenceProvenance::caller_supplied_untrusted};
    bool ownership_verified{false};
    std::string inventory_revision;
    std::string observation_revision;
    std::string restorable_snapshot_revision;
};

struct NdmsNativeExpectTargetAbsent {
    std::string inventory_revision;
};

struct NdmsNativeExpectOwnedTarget {
    std::string inventory_revision;
    std::string observation_revision;
    std::string restorable_snapshot_revision;
};

using NdmsNativeMutationGuard = std::variant<
    NdmsNativeExpectTargetAbsent,
    NdmsNativeExpectOwnedTarget>;

using NdmsNativeUntrustedEvidence = std::variant<
    NdmsNativeTargetAbsenceEvidence,
    NdmsNativeOwnedTargetEvidence>;

struct NdmsNativeCreateMutationDraft {
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::optional<std::string> description;
    NdmsNativeTargetAbsenceEvidence evidence;
};

struct NdmsNativeEditMutationDraft {
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::optional<std::string> description;
    bool set_down{false};
    NdmsNativeOwnedTargetEvidence evidence;
};

struct NdmsNativeDeleteMutationDraft {
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    NdmsNativeOwnedTargetEvidence evidence;
};

struct NdmsNativeImportMutationDraft {
    std::string interface_name;
    std::optional<std::string> description;
    NdmsNativeTargetAbsenceEvidence evidence;
};

enum class NdmsNativeMutationValidationError {
    invalid_interface_name,
    invalid_description,
    target_absence_unverified,
    inventory_revision_invalid,
    create_description_required,
    evidence_target_mismatch,
    evidence_kind_mismatch,
    evidence_provenance_invalid,
    ownership_unverified,
    observation_revision_invalid,
    restorable_snapshot_revision_invalid,
    edit_has_no_fields,
};

enum class NdmsNativeMutationPlanBlocker {
    // The production capability remains hard-disabled independently of whether
    // the pure plan is structurally valid.
    mutation_release_disabled,

    // Caller-built bools and digests are not authorization. A future trusted
    // verifier must produce an opaque, target-bound receipt before any guard
    // or operation may be emitted.
    trusted_verifier_unavailable,

    // More than one measured command would cross a partial-application
    // boundary. A future executor must provide a durable rollback protocol;
    // this preview module deliberately does not.
    non_atomic_apply_requires_rollback,

    // Current import parsing owns credentials safely, but the measured
    // non-secret command set is not sufficient to apply them. No secret is
    // copied into this plan while that boundary remains unproven.
    secret_bearing_import_apply_unavailable,

    // Creating an AWG identity also requires an ASC writer. Only the ASC read
    // shape is currently measured and production-safe.
    amnezia_asc_apply_unavailable,
};

// Safe, copyable and preview-only. It contains no credential type or raw
// import body. `import_preview` is the already-redacted representation from
// NdmsNativeTunnelImport.
struct NdmsNativeMutationPlan {
    NdmsNativeMutationIntent intent{NdmsNativeMutationIntent::create};
    NdmsNativeMutationPlanSemantics semantics{
        NdmsNativeMutationPlanSemantics::ordered_non_atomic_preview};
    bool executable{false};
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};

    // Safe requested-field preview. It is separate from operations because no
    // operation is emitted while evidence has only caller provenance.
    std::optional<std::string> description;
    bool down_requested{false};
    bool delete_requested{false};
    std::optional<NdmsNativeUntrustedEvidence> untrusted_evidence;

    std::optional<NdmsNativeMutationGuard> guard;
    std::vector<NdmsNativeMutationOperation> operations;
    std::optional<NdmsNativeTunnelImportPreview> import_preview;
    std::vector<NdmsNativeMutationValidationError> validation_errors;
    std::vector<NdmsNativeMutationPlanBlocker> blockers{
        NdmsNativeMutationPlanBlocker::mutation_release_disabled,
        NdmsNativeMutationPlanBlocker::trusted_verifier_unavailable};
};

// Strictly allowlists the measured Keenetic identity family Wireguard0..126.
// It is not a generic RCI path validator.
bool is_measured_ndms_native_mutation_name(
    const std::string& interface_name) noexcept;

// Checks only that a redacted, blocked preview is internally consistent. A
// true result never means the preview is executable or authorized.
bool ndms_native_mutation_preview_is_consistent(
    const NdmsNativeMutationPlan& plan) noexcept;

NdmsNativeMutationPlan plan_ndms_native_create_mutation(
    const NdmsNativeCreateMutationDraft& draft);

NdmsNativeMutationPlan plan_ndms_native_edit_mutation(
    const NdmsNativeEditMutationDraft& draft);

NdmsNativeMutationPlan plan_ndms_native_delete_mutation(
    const NdmsNativeDeleteMutationDraft& draft);

// Import intentionally reuses the create requested-field preview
// (description/implicit create, then force down). With no trusted verifier it
// emits neither step as an operation. The parsed candidate contributes only
// its redacted preview; secret-bearing configuration operations remain absent.
NdmsNativeMutationPlan plan_ndms_native_import_mutation(
    const NdmsNativeImportMutationDraft& draft,
    const NdmsNativeTunnelImport& imported);

const char* ndms_native_mutation_intent_name(
    NdmsNativeMutationIntent intent) noexcept;

const char* ndms_native_mutation_plan_semantics_name(
    NdmsNativeMutationPlanSemantics semantics) noexcept;

const char* ndms_native_mutation_operation_name(
    const NdmsNativeMutationOperation& operation) noexcept;

const char* ndms_native_mutation_validation_error_name(
    NdmsNativeMutationValidationError error) noexcept;

const char* ndms_native_mutation_plan_blocker_name(
    NdmsNativeMutationPlanBlocker blocker) noexcept;

} // namespace keen_pbr3
