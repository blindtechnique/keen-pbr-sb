#include "ndms_native_mutation_plan.hpp"

#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace keen_pbr3 {

namespace {

constexpr std::size_t kMaximumDescriptionBytes = 512U;

bool has_prefix(const std::string& value,
                const std::string_view prefix) noexcept {
    return value.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool lowercase_hex_revision(const std::string& value,
                            const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           has_prefix(value, prefix) &&
           std::all_of(
               value.begin() +
                   static_cast<std::ptrdiff_t>(prefix.size()),
               value.end(),
               [](const unsigned char character) {
                   return (character >= '0' && character <= '9') ||
                          (character >= 'a' && character <= 'f');
               });
}

bool valid_utf8_without_nul(const std::string& value) noexcept {
    for (std::size_t offset = 0U; offset < value.size();) {
        const auto first = static_cast<unsigned char>(value[offset]);
        if (first == 0U) return false;

        std::size_t continuation_count = 0U;
        std::uint32_t codepoint = 0U;
        if (first <= 0x7FU) {
            ++offset;
            continue;
        }
        if (first >= 0xC2U && first <= 0xDFU) {
            continuation_count = 1U;
            codepoint = first & 0x1FU;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            continuation_count = 2U;
            codepoint = first & 0x0FU;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            continuation_count = 3U;
            codepoint = first & 0x07U;
        } else {
            return false;
        }

        if (offset + continuation_count >= value.size()) return false;
        for (std::size_t index = 1U;
             index <= continuation_count;
             ++index) {
            const auto continuation =
                static_cast<unsigned char>(value[offset + index]);
            if ((continuation & 0xC0U) != 0x80U) return false;
            codepoint =
                (codepoint << 6U) | (continuation & 0x3FU);
        }

        const auto second = static_cast<unsigned char>(value[offset + 1U]);
        if ((first == 0xE0U && second < 0xA0U) ||
            (first == 0xEDU && second > 0x9FU) ||
            (first == 0xF0U && second < 0x90U) ||
            (first == 0xF4U && second > 0x8FU) ||
            codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            return false;
        }
        offset += continuation_count + 1U;
    }
    return true;
}

bool valid_description(
    const std::optional<std::string>& description) noexcept {
    return !description ||
           (description->size() <= kMaximumDescriptionBytes &&
            valid_utf8_without_nul(*description));
}

void validate_common(
    const std::string& interface_name,
    const std::optional<std::string>& description,
    NdmsNativeMutationPlan& plan) {
    if (!is_measured_ndms_native_mutation_name(interface_name)) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::invalid_interface_name);
    }
    if (!valid_description(description)) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::invalid_description);
    }
}

void validate_absence_evidence(
    const NdmsNativeTargetAbsenceEvidence& evidence,
    const std::string& interface_name,
    const NdmsNativeTunnelImportKind kind,
    NdmsNativeMutationPlan& plan) {
    if (evidence.interface_name != interface_name) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                evidence_target_mismatch);
    }
    if (evidence.kind != kind) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                evidence_kind_mismatch);
    }
    if (evidence.provenance !=
        NdmsNativeEvidenceProvenance::caller_supplied_untrusted) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                evidence_provenance_invalid);
    }
    if (!evidence.target_absent) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                target_absence_unverified);
    }
    if (!lowercase_hex_revision(
            evidence.inventory_revision, "ndms-v1-")) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                inventory_revision_invalid);
    }
}

void validate_owned_evidence(
    const NdmsNativeOwnedTargetEvidence& evidence,
    const std::string& interface_name,
    const NdmsNativeTunnelImportKind kind,
    NdmsNativeMutationPlan& plan) {
    if (evidence.interface_name != interface_name) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                evidence_target_mismatch);
    }
    if (evidence.kind != kind) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                evidence_kind_mismatch);
    }
    if (evidence.provenance !=
        NdmsNativeEvidenceProvenance::caller_supplied_untrusted) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                evidence_provenance_invalid);
    }
    if (!evidence.ownership_verified) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::ownership_unverified);
    }
    if (!lowercase_hex_revision(
            evidence.inventory_revision, "ndms-v1-")) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                inventory_revision_invalid);
    }
    if (!lowercase_hex_revision(
            evidence.observation_revision, "ndms-rci-v1-")) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                observation_revision_invalid);
    }
    if (!lowercase_hex_revision(
            evidence.restorable_snapshot_revision,
            "ndms-rci-full-v1-")) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                restorable_snapshot_revision_invalid);
    }
}

void add_non_atomic_blocker_if_needed(
    NdmsNativeMutationPlan& plan) {
    if (plan.description.has_value() && plan.down_requested) {
        plan.blockers.push_back(
            NdmsNativeMutationPlanBlocker::
                non_atomic_apply_requires_rollback);
    }
}

NdmsNativeMutationPlan create_plan(
    const NdmsNativeCreateMutationDraft& draft) {
    NdmsNativeMutationPlan plan;
    plan.intent = NdmsNativeMutationIntent::create;
    plan.interface_name = draft.interface_name;
    plan.kind = draft.kind;
    plan.description = draft.description;
    plan.down_requested = true;
    plan.untrusted_evidence = draft.evidence;

    validate_common(draft.interface_name, draft.description, plan);
    validate_absence_evidence(
        draft.evidence, draft.interface_name, draft.kind, plan);
    if (!draft.description || draft.description->empty()) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::
                create_description_required);
    }
    if (!plan.validation_errors.empty()) return plan;

    add_non_atomic_blocker_if_needed(plan);
    if (draft.kind ==
        NdmsNativeTunnelImportKind::amnezia_wireguard) {
        plan.blockers.push_back(
            NdmsNativeMutationPlanBlocker::
                amnezia_asc_apply_unavailable);
    }
    return plan;
}

} // namespace

bool is_measured_ndms_native_mutation_name(
    const std::string& interface_name) noexcept {
    return parse_ndms_wireguard_identity(interface_name).has_value();
}

bool ndms_native_mutation_preview_is_consistent(
    const NdmsNativeMutationPlan& plan) noexcept {
    if (plan.executable ||
        plan.semantics != NdmsNativeMutationPlanSemantics::
            ordered_non_atomic_preview ||
        !plan.validation_errors.empty() ||
        !is_measured_ndms_native_mutation_name(plan.interface_name) ||
        !valid_description(plan.description) ||
        plan.guard.has_value() || !plan.operations.empty() ||
        !plan.untrusted_evidence.has_value()) {
        return false;
    }

    const bool known_kind =
        plan.kind == NdmsNativeTunnelImportKind::wireguard ||
        plan.kind ==
            NdmsNativeTunnelImportKind::amnezia_wireguard;
    if (!known_kind) return false;

    const auto absence_evidence_matches = [&]() {
        if (!std::holds_alternative<NdmsNativeTargetAbsenceEvidence>(
                *plan.untrusted_evidence)) {
            return false;
        }
        const auto& evidence =
            std::get<NdmsNativeTargetAbsenceEvidence>(
                *plan.untrusted_evidence);
        return evidence.interface_name == plan.interface_name &&
               evidence.kind == plan.kind &&
               evidence.provenance ==
                   NdmsNativeEvidenceProvenance::
                       caller_supplied_untrusted &&
               evidence.target_absent &&
               lowercase_hex_revision(
                   evidence.inventory_revision, "ndms-v1-");
    };
    const auto owned_evidence_matches = [&]() {
        if (!std::holds_alternative<NdmsNativeOwnedTargetEvidence>(
                *plan.untrusted_evidence)) {
            return false;
        }
        const auto& evidence =
            std::get<NdmsNativeOwnedTargetEvidence>(
                *plan.untrusted_evidence);
        return evidence.interface_name == plan.interface_name &&
               evidence.kind == plan.kind &&
               evidence.provenance ==
                   NdmsNativeEvidenceProvenance::
                       caller_supplied_untrusted &&
               evidence.ownership_verified &&
               lowercase_hex_revision(
                   evidence.inventory_revision, "ndms-v1-") &&
               lowercase_hex_revision(
                   evidence.observation_revision,
                   "ndms-rci-v1-") &&
               lowercase_hex_revision(
                   evidence.restorable_snapshot_revision,
                   "ndms-rci-full-v1-");
    };

    switch (plan.intent) {
    case NdmsNativeMutationIntent::create:
        if (!absence_evidence_matches() ||
            !plan.description || plan.description->empty() ||
            !plan.down_requested || plan.delete_requested ||
            plan.import_preview.has_value()) {
            return false;
        }
        break;
    case NdmsNativeMutationIntent::edit:
        if (!owned_evidence_matches() ||
            (!plan.description && !plan.down_requested) ||
            plan.delete_requested || plan.import_preview.has_value()) {
            return false;
        }
        break;
    case NdmsNativeMutationIntent::erase:
        if (!owned_evidence_matches() || plan.description ||
            plan.down_requested || !plan.delete_requested ||
            plan.import_preview.has_value()) {
            return false;
        }
        break;
    case NdmsNativeMutationIntent::import:
        if (!absence_evidence_matches() ||
            !plan.description || plan.description->empty() ||
            !plan.down_requested || plan.delete_requested ||
            !plan.import_preview ||
            plan.import_preview->kind != plan.kind ||
            !lowercase_hex_revision(
                plan.import_preview->revision,
                "ndms-native-import-v1-")) {
            return false;
        }
        break;
    default:
        return false;
    }

    // In this version there is no trusted receipt producer. Therefore the
    // only exact safe sequence is an empty guard and operation list. The
    // typed operation model cannot accidentally become executable by caller
    // mutation because any added guard/operation was rejected above.
    std::size_t blocker = 0U;
    const auto require_blocker = [&](const NdmsNativeMutationPlanBlocker
                                         expected) {
        return blocker < plan.blockers.size() &&
               plan.blockers[blocker++] == expected;
    };
    if (!require_blocker(
            NdmsNativeMutationPlanBlocker::
                mutation_release_disabled) ||
        !require_blocker(
            NdmsNativeMutationPlanBlocker::
                trusted_verifier_unavailable)) {
        return false;
    }
    if (plan.description && plan.down_requested &&
        !require_blocker(
            NdmsNativeMutationPlanBlocker::
                non_atomic_apply_requires_rollback)) {
        return false;
    }
    if (plan.kind ==
            NdmsNativeTunnelImportKind::amnezia_wireguard &&
        (plan.intent == NdmsNativeMutationIntent::create ||
         plan.intent == NdmsNativeMutationIntent::import) &&
        !require_blocker(
            NdmsNativeMutationPlanBlocker::
                amnezia_asc_apply_unavailable)) {
        return false;
    }
    if (plan.intent == NdmsNativeMutationIntent::import &&
        !require_blocker(
            NdmsNativeMutationPlanBlocker::
                secret_bearing_import_apply_unavailable)) {
        return false;
    }
    return blocker == plan.blockers.size();
}

NdmsNativeMutationPlan plan_ndms_native_create_mutation(
    const NdmsNativeCreateMutationDraft& draft) {
    return create_plan(draft);
}

NdmsNativeMutationPlan plan_ndms_native_edit_mutation(
    const NdmsNativeEditMutationDraft& draft) {
    NdmsNativeMutationPlan plan;
    plan.intent = NdmsNativeMutationIntent::edit;
    plan.interface_name = draft.interface_name;
    plan.kind = draft.kind;
    plan.description = draft.description;
    plan.down_requested = draft.set_down;
    plan.untrusted_evidence = draft.evidence;

    validate_common(draft.interface_name, draft.description, plan);
    validate_owned_evidence(
        draft.evidence, draft.interface_name, draft.kind, plan);
    if (!draft.description && !draft.set_down) {
        plan.validation_errors.push_back(
            NdmsNativeMutationValidationError::edit_has_no_fields);
    }
    if (!plan.validation_errors.empty()) return plan;

    add_non_atomic_blocker_if_needed(plan);
    return plan;
}

NdmsNativeMutationPlan plan_ndms_native_delete_mutation(
    const NdmsNativeDeleteMutationDraft& draft) {
    NdmsNativeMutationPlan plan;
    plan.intent = NdmsNativeMutationIntent::erase;
    plan.interface_name = draft.interface_name;
    plan.kind = draft.kind;
    plan.delete_requested = true;
    plan.untrusted_evidence = draft.evidence;

    validate_common(draft.interface_name, std::nullopt, plan);
    validate_owned_evidence(
        draft.evidence, draft.interface_name, draft.kind, plan);
    if (!plan.validation_errors.empty()) return plan;

    return plan;
}

NdmsNativeMutationPlan plan_ndms_native_import_mutation(
    const NdmsNativeImportMutationDraft& draft,
    const NdmsNativeTunnelImport& imported) {
    NdmsNativeCreateMutationDraft create_draft;
    create_draft.interface_name = draft.interface_name;
    create_draft.kind = imported.kind;
    create_draft.description = draft.description;
    create_draft.evidence = draft.evidence;

    auto plan = create_plan(create_draft);
    plan.intent = NdmsNativeMutationIntent::import;
    plan.import_preview =
        build_ndms_native_tunnel_import_preview(imported);
    if (!plan.validation_errors.empty()) return plan;

    plan.blockers.push_back(
        NdmsNativeMutationPlanBlocker::
            secret_bearing_import_apply_unavailable);
    return plan;
}

const char* ndms_native_mutation_intent_name(
    const NdmsNativeMutationIntent intent) noexcept {
    switch (intent) {
    case NdmsNativeMutationIntent::create:
        return "create";
    case NdmsNativeMutationIntent::edit:
        return "edit";
    case NdmsNativeMutationIntent::erase:
        return "delete";
    case NdmsNativeMutationIntent::import:
        return "import";
    }
    return "unknown";
}

const char* ndms_native_mutation_plan_semantics_name(
    const NdmsNativeMutationPlanSemantics semantics) noexcept {
    switch (semantics) {
    case NdmsNativeMutationPlanSemantics::
        ordered_non_atomic_preview:
        return "ordered_non_atomic_preview";
    }
    return "unknown";
}

const char* ndms_native_mutation_operation_name(
    const NdmsNativeMutationOperation& operation) noexcept {
    return std::visit(
        [](const auto& typed_operation) -> const char* {
            using Operation = std::decay_t<decltype(typed_operation)>;
            if constexpr (std::is_same_v<
                                     Operation,
                                     NdmsNativeSetInterfaceDownOperation>) {
                return "set_interface_down";
            } else if constexpr (std::is_same_v<
                                     Operation,
                                     NdmsNativeSetInterfaceDescriptionOperation>) {
                return "set_interface_description";
            } else {
                return "delete_interface";
            }
        },
        operation);
}

const char* ndms_native_mutation_validation_error_name(
    const NdmsNativeMutationValidationError error) noexcept {
    switch (error) {
    case NdmsNativeMutationValidationError::invalid_interface_name:
        return "invalid_interface_name";
    case NdmsNativeMutationValidationError::invalid_description:
        return "invalid_description";
    case NdmsNativeMutationValidationError::target_absence_unverified:
        return "target_absence_unverified";
    case NdmsNativeMutationValidationError::inventory_revision_invalid:
        return "inventory_revision_invalid";
    case NdmsNativeMutationValidationError::create_description_required:
        return "create_description_required";
    case NdmsNativeMutationValidationError::evidence_target_mismatch:
        return "evidence_target_mismatch";
    case NdmsNativeMutationValidationError::evidence_kind_mismatch:
        return "evidence_kind_mismatch";
    case NdmsNativeMutationValidationError::evidence_provenance_invalid:
        return "evidence_provenance_invalid";
    case NdmsNativeMutationValidationError::ownership_unverified:
        return "ownership_unverified";
    case NdmsNativeMutationValidationError::observation_revision_invalid:
        return "observation_revision_invalid";
    case NdmsNativeMutationValidationError::
        restorable_snapshot_revision_invalid:
        return "restorable_snapshot_revision_invalid";
    case NdmsNativeMutationValidationError::edit_has_no_fields:
        return "edit_has_no_fields";
    }
    return "unknown";
}

const char* ndms_native_mutation_plan_blocker_name(
    const NdmsNativeMutationPlanBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeMutationPlanBlocker::mutation_release_disabled:
        return "mutation_release_disabled";
    case NdmsNativeMutationPlanBlocker::trusted_verifier_unavailable:
        return "trusted_verifier_unavailable";
    case NdmsNativeMutationPlanBlocker::
        non_atomic_apply_requires_rollback:
        return "non_atomic_apply_requires_rollback";
    case NdmsNativeMutationPlanBlocker::
        secret_bearing_import_apply_unavailable:
        return "secret_bearing_import_apply_unavailable";
    case NdmsNativeMutationPlanBlocker::
        amnezia_asc_apply_unavailable:
        return "amnezia_asc_apply_unavailable";
    }
    return "unknown";
}

} // namespace keen_pbr3
