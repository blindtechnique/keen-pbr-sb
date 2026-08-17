#include <doctest/doctest.h>

#include "keenetic/ndms_native_mutation_plan.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <type_traits>
#include <variant>

using namespace keen_pbr3;

namespace {

std::string revision(const std::string& prefix, const char digit) {
    return prefix + std::string(64U, digit);
}

NdmsNativeTargetAbsenceEvidence absent_target(
    const std::string& interface_name = "Wireguard99",
    const NdmsNativeTunnelImportKind kind =
        NdmsNativeTunnelImportKind::wireguard) {
    return {
        interface_name,
        kind,
        NdmsNativeEvidenceProvenance::caller_supplied_untrusted,
        true,
        revision("ndms-v1-", 'a'),
    };
}

NdmsNativeOwnedTargetEvidence owned_target(
    const std::string& interface_name = "Wireguard4",
    const NdmsNativeTunnelImportKind kind =
        NdmsNativeTunnelImportKind::wireguard) {
    return {
        interface_name,
        kind,
        NdmsNativeEvidenceProvenance::caller_supplied_untrusted,
        true,
        revision("ndms-v1-", 'a'),
        revision("ndms-rci-v1-", 'b'),
        revision("ndms-rci-full-v1-", 'c'),
    };
}

bool has_error(const NdmsNativeMutationPlan& plan,
               const NdmsNativeMutationValidationError error) {
    return std::find(
               plan.validation_errors.begin(),
               plan.validation_errors.end(), error) !=
           plan.validation_errors.end();
}

bool has_blocker(const NdmsNativeMutationPlan& plan,
                 const NdmsNativeMutationPlanBlocker blocker) {
    return std::find(
               plan.blockers.begin(), plan.blockers.end(), blocker) !=
           plan.blockers.end();
}

std::string key(const char value) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::string raw(32U, value);
    std::string output;
    for (std::size_t offset = 0U; offset < raw.size(); offset += 3U) {
        const auto first = static_cast<unsigned char>(raw[offset]);
        const bool second_present = offset + 1U < raw.size();
        const bool third_present = offset + 2U < raw.size();
        const auto second = second_present
            ? static_cast<unsigned char>(raw[offset + 1U]) : 0U;
        const auto third = third_present
            ? static_cast<unsigned char>(raw[offset + 2U]) : 0U;
        const std::uint32_t block =
            (static_cast<std::uint32_t>(first) << 16U) |
            (static_cast<std::uint32_t>(second) << 8U) |
            static_cast<std::uint32_t>(third);
        output.push_back(alphabet[(block >> 18U) & 0x3FU]);
        output.push_back(alphabet[(block >> 12U) & 0x3FU]);
        output.push_back(second_present
                             ? alphabet[(block >> 6U) & 0x3FU] : '=');
        output.push_back(third_present
                             ? alphabet[block & 0x3FU] : '=');
    }
    return output;
}

std::string awg_conf() {
    return
        "[Interface]\n"
        "Address = 10.8.0.2/32\n"
        "PrivateKey = " + key('P') + "\n"
        "Jc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\n"
        "H1 = 101010101\nH2 = 202020202\n"
        "H3 = 303030303\nH4 = 404040404\n"
        "\n[Peer]\n"
        "PublicKey = " + key('K') + "\n"
        "PresharedKey = " + key('S') + "\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "Endpoint = vpn.example.test:443\n";
}

std::string safe_plan_text(const NdmsNativeMutationPlan& plan) {
    std::string result = plan.interface_name;
    if (plan.description) result += *plan.description;
    if (plan.untrusted_evidence) {
        std::visit(
            [&](const auto& evidence) {
                result += evidence.interface_name;
                result += evidence.inventory_revision;
                using Evidence = std::decay_t<decltype(evidence)>;
                if constexpr (std::is_same_v<
                                  Evidence,
                                  NdmsNativeOwnedTargetEvidence>) {
                    result += evidence.observation_revision;
                    result += evidence.restorable_snapshot_revision;
                }
            },
            *plan.untrusted_evidence);
    }
    if (plan.guard) {
        std::visit(
            [&](const auto& guard) {
                result += guard.inventory_revision;
                using Guard = std::decay_t<decltype(guard)>;
                if constexpr (std::is_same_v<
                                  Guard,
                                  NdmsNativeExpectOwnedTarget>) {
                    result += guard.observation_revision;
                    result += guard.restorable_snapshot_revision;
                }
            },
            *plan.guard);
    }
    for (const auto& operation : plan.operations) {
        std::visit(
            [&](const auto& typed_operation) {
                result += typed_operation.interface_name;
                using Operation =
                    std::decay_t<decltype(typed_operation)>;
                if constexpr (std::is_same_v<
                                  Operation,
                                  NdmsNativeSetInterfaceDescriptionOperation>) {
                    result += typed_operation.description;
                }
            },
            operation);
    }
    if (plan.import_preview) {
        result += plan.import_preview->revision;
        if (plan.import_preview->endpoint_host) {
            result += *plan.import_preview->endpoint_host;
        }
        for (const auto& name :
             plan.import_preview->amnezia_parameter_names) {
            result += name;
        }
    }
    for (const auto error : plan.validation_errors) {
        result += ndms_native_mutation_validation_error_name(error);
    }
    for (const auto blocker : plan.blockers) {
        result += ndms_native_mutation_plan_blocker_name(blocker);
    }
    return result;
}

} // namespace

static_assert(std::is_copy_constructible_v<NdmsNativeMutationPlan>);
static_assert(std::is_copy_assignable_v<NdmsNativeMutationPlan>);
static_assert(!std::is_copy_constructible_v<NdmsNativeTunnelImport>);
static_assert(std::variant_size_v<NdmsNativeMutationOperation> == 3U);
static_assert(std::is_constructible_v<
              NdmsNativeMutationOperation,
              NdmsNativeSetInterfaceDownOperation>);

TEST_CASE("native mutation names are a strict measured allowlist") {
    for (const auto& accepted :
         {"Wireguard0", "Wireguard5", "Wireguard99",
          "Wireguard100", "Wireguard126"}) {
        CAPTURE(accepted);
        CHECK(is_measured_ndms_native_mutation_name(accepted));
    }
    for (const auto& rejected :
         {"Wireguard", "Wireguard00", "Wireguard01", "Wireguard127",
          "wireguard5", "Wireguard5/../../system", "Wireguard5?x"}) {
        CAPTURE(rejected);
        CHECK_FALSE(is_measured_ndms_native_mutation_name(rejected));
    }
}

TEST_CASE("create plan is a non-executable target-bound preview") {
    NdmsNativeCreateMutationDraft draft;
    draft.interface_name = "Wireguard99";
    draft.description = "keen-pbr owned preview";
    draft.evidence = absent_target();

    const auto plan = plan_ndms_native_create_mutation(draft);
    CHECK(plan.intent == NdmsNativeMutationIntent::create);
    CHECK(plan.semantics ==
          NdmsNativeMutationPlanSemantics::
              ordered_non_atomic_preview);
    CHECK_FALSE(plan.executable);
    CHECK(plan.kind == NdmsNativeTunnelImportKind::wireguard);
    CHECK(ndms_native_mutation_preview_is_consistent(plan));
    CHECK(plan.description ==
          std::optional<std::string>{"keen-pbr owned preview"});
    CHECK(plan.down_requested);
    CHECK_FALSE(plan.delete_requested);
    REQUIRE(plan.untrusted_evidence.has_value());
    REQUIRE(std::holds_alternative<
            NdmsNativeTargetAbsenceEvidence>(
                *plan.untrusted_evidence));
    const auto& evidence =
        std::get<NdmsNativeTargetAbsenceEvidence>(
            *plan.untrusted_evidence);
    CHECK(evidence.interface_name == plan.interface_name);
    CHECK(evidence.kind == plan.kind);
    CHECK(evidence.provenance ==
          NdmsNativeEvidenceProvenance::caller_supplied_untrusted);
    CHECK_FALSE(plan.guard.has_value());
    CHECK(plan.operations.empty());

    CHECK(plan.blockers ==
          std::vector<NdmsNativeMutationPlanBlocker>{
              NdmsNativeMutationPlanBlocker::mutation_release_disabled,
              NdmsNativeMutationPlanBlocker::
                  trusted_verifier_unavailable,
              NdmsNativeMutationPlanBlocker::
                  non_atomic_apply_requires_rollback});
    CHECK_FALSE(plan.import_preview.has_value());
}

TEST_CASE("edit preview can request down but has no enable representation") {
    NdmsNativeEditMutationDraft disable;
    disable.interface_name = "Wireguard7";
    disable.kind = NdmsNativeTunnelImportKind::amnezia_wireguard;
    disable.description = "renamed";
    disable.set_down = true;
    disable.evidence = owned_target(
        disable.interface_name, disable.kind);

    const auto down_plan = plan_ndms_native_edit_mutation(disable);
    REQUIRE(ndms_native_mutation_preview_is_consistent(down_plan));
    CHECK(down_plan.down_requested);
    CHECK(down_plan.operations.empty());
    CHECK_FALSE(down_plan.guard.has_value());
    CHECK(has_blocker(
        down_plan,
        NdmsNativeMutationPlanBlocker::
            trusted_verifier_unavailable));
    CHECK(has_blocker(
        down_plan,
        NdmsNativeMutationPlanBlocker::
            non_atomic_apply_requires_rollback));

    const NdmsNativeMutationOperation only_state_operation =
        NdmsNativeSetInterfaceDownOperation{"Wireguard7"};
    CHECK(std::string{ndms_native_mutation_operation_name(
              only_state_operation)} == "set_interface_down");
}

TEST_CASE("edit and delete require exact owned revision evidence") {
    NdmsNativeEditMutationDraft empty_edit;
    empty_edit.interface_name = "Wireguard4";
    empty_edit.evidence = owned_target(empty_edit.interface_name);
    const auto empty_plan =
        plan_ndms_native_edit_mutation(empty_edit);
    CHECK(has_error(
        empty_plan,
        NdmsNativeMutationValidationError::edit_has_no_fields));
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        empty_plan));
    CHECK(empty_plan.operations.empty());

    NdmsNativeDeleteMutationDraft deletion;
    deletion.interface_name = "Wireguard4";
    deletion.evidence = owned_target(deletion.interface_name);
    deletion.evidence.ownership_verified = false;
    deletion.evidence.observation_revision = "attacker-controlled";
    const auto rejected =
        plan_ndms_native_delete_mutation(deletion);
    CHECK(has_error(
        rejected,
        NdmsNativeMutationValidationError::ownership_unverified));
    CHECK(has_error(
        rejected,
        NdmsNativeMutationValidationError::
            observation_revision_invalid));
    CHECK_FALSE(rejected.guard.has_value());
    CHECK(rejected.operations.empty());

    deletion.evidence = owned_target(deletion.interface_name);
    const auto accepted =
        plan_ndms_native_delete_mutation(deletion);
    REQUIRE(ndms_native_mutation_preview_is_consistent(accepted));
    CHECK(accepted.delete_requested);
    CHECK(accepted.operations.empty());
    CHECK_FALSE(accepted.guard.has_value());
    CHECK(has_blocker(
        accepted,
        NdmsNativeMutationPlanBlocker::
            trusted_verifier_unavailable));
}

TEST_CASE("caller evidence is exactly target and kind bound") {
    NdmsNativeCreateMutationDraft create;
    create.interface_name = "Wireguard99";
    create.kind = NdmsNativeTunnelImportKind::amnezia_wireguard;
    create.description = "owned marker";
    create.evidence = absent_target(
        "Wireguard98", NdmsNativeTunnelImportKind::wireguard);

    const auto rejected =
        plan_ndms_native_create_mutation(create);
    CHECK(has_error(
        rejected,
        NdmsNativeMutationValidationError::
            evidence_target_mismatch));
    CHECK(has_error(
        rejected,
        NdmsNativeMutationValidationError::
            evidence_kind_mismatch));
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        rejected));
    CHECK_FALSE(rejected.guard.has_value());
    CHECK(rejected.operations.empty());
}

TEST_CASE("structural validation rejects every caller tamper boundary") {
    NdmsNativeCreateMutationDraft draft;
    draft.interface_name = "Wireguard99";
    draft.description = "owned marker";
    draft.evidence = absent_target(draft.interface_name);
    const auto original =
        plan_ndms_native_create_mutation(draft);
    REQUIRE(ndms_native_mutation_preview_is_consistent(original));

    auto executable = original;
    executable.executable = true;
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        executable));

    auto semantics = original;
    semantics.semantics =
        static_cast<NdmsNativeMutationPlanSemantics>(77);
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        semantics));

    auto no_release_blocker = original;
    no_release_blocker.blockers.erase(
        no_release_blocker.blockers.begin());
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        no_release_blocker));

    auto duplicate_blocker = original;
    duplicate_blocker.blockers.push_back(
        NdmsNativeMutationPlanBlocker::mutation_release_disabled);
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        duplicate_blocker));

    auto forged_guard = original;
    forged_guard.guard = NdmsNativeExpectTargetAbsent{
        revision("ndms-v1-", 'a')};
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        forged_guard));

    auto matching_operation = original;
    matching_operation.operations.push_back(
        NdmsNativeSetInterfaceDownOperation{original.interface_name});
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        matching_operation));

    auto wrong_target_operation = original;
    wrong_target_operation.operations.push_back(
        NdmsNativeSetInterfaceDownOperation{"Wireguard98"});
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        wrong_target_operation));

    auto wrong_receipt_target = original;
    std::get<NdmsNativeTargetAbsenceEvidence>(
        *wrong_receipt_target.untrusted_evidence)
        .interface_name = "Wireguard98";
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        wrong_receipt_target));

    auto wrong_intent = original;
    wrong_intent.intent = NdmsNativeMutationIntent::erase;
    CHECK_FALSE(ndms_native_mutation_preview_is_consistent(
        wrong_intent));
}

TEST_CASE("invalid create inputs fail without leaving partial operations") {
    NdmsNativeCreateMutationDraft draft;
    draft.interface_name = "Wireguard99/../../system";
    draft.description = std::string{"bad\0description", 15U};
    draft.evidence.target_absent = false;
    draft.evidence.inventory_revision = "stale";

    const auto plan = plan_ndms_native_create_mutation(draft);
    CHECK(has_error(
        plan,
        NdmsNativeMutationValidationError::invalid_interface_name));
    CHECK(has_error(
        plan,
        NdmsNativeMutationValidationError::invalid_description));
    CHECK(has_error(
        plan,
        NdmsNativeMutationValidationError::target_absence_unverified));
    CHECK(has_error(
        plan,
        NdmsNativeMutationValidationError::inventory_revision_invalid));
    CHECK_FALSE(plan.guard.has_value());
    CHECK(plan.operations.empty());
}

TEST_CASE("create requires a non-empty ownership description") {
    NdmsNativeCreateMutationDraft draft;
    draft.interface_name = "Wireguard99";
    draft.evidence = absent_target();

    const auto missing = plan_ndms_native_create_mutation(draft);
    CHECK(has_error(
        missing,
        NdmsNativeMutationValidationError::
            create_description_required));
    CHECK(missing.operations.empty());

    draft.description = "";
    const auto empty = plan_ndms_native_create_mutation(draft);
    CHECK(has_error(
        empty,
        NdmsNativeMutationValidationError::
            create_description_required));
    CHECK(empty.operations.empty());
}

TEST_CASE("import reuses create but retains only the redacted preview") {
    const auto private_key = key('P');
    const auto preshared_key = key('S');
    const auto imported = parse_ndms_native_tunnel_import(awg_conf());

    NdmsNativeImportMutationDraft draft;
    draft.interface_name = "Wireguard99";
    draft.description = "import preview";
    draft.evidence = absent_target(
        draft.interface_name, imported.kind);
    const auto plan =
        plan_ndms_native_import_mutation(draft, imported);

    CHECK(plan.intent == NdmsNativeMutationIntent::import);
    CHECK(plan.kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    REQUIRE(ndms_native_mutation_preview_is_consistent(plan));
    CHECK(plan.operations.empty());
    CHECK_FALSE(plan.guard.has_value());
    CHECK(plan.description ==
          std::optional<std::string>{"import preview"});
    CHECK(plan.down_requested);

    REQUIRE(plan.import_preview.has_value());
    CHECK(plan.import_preview->kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    CHECK(plan.import_preview->has_private_key);
    CHECK(plan.import_preview->preshared_key_count == 1U);
    CHECK(plan.import_preview->peer_count == 1U);
    CHECK(has_blocker(
        plan,
        NdmsNativeMutationPlanBlocker::
            mutation_release_disabled));
    CHECK(has_blocker(
        plan,
        NdmsNativeMutationPlanBlocker::
            trusted_verifier_unavailable));
    CHECK(has_blocker(
        plan,
        NdmsNativeMutationPlanBlocker::
            non_atomic_apply_requires_rollback));
    CHECK(has_blocker(
        plan,
        NdmsNativeMutationPlanBlocker::
            secret_bearing_import_apply_unavailable));
    CHECK(has_blocker(
        plan,
        NdmsNativeMutationPlanBlocker::
            amnezia_asc_apply_unavailable));

    const auto visible = safe_plan_text(plan);
    CHECK(visible.find(private_key) == std::string::npos);
    CHECK(visible.find(preshared_key) == std::string::npos);
}

TEST_CASE("mutation plan names are stable machine-readable tokens") {
    const NdmsNativeMutationOperation operation =
        NdmsNativeDeleteInterfaceOperation{"Wireguard9"};
    CHECK(std::string{ndms_native_mutation_intent_name(
              NdmsNativeMutationIntent::erase)} == "delete");
    CHECK(std::string{ndms_native_mutation_plan_semantics_name(
              NdmsNativeMutationPlanSemantics::
                  ordered_non_atomic_preview)} ==
          "ordered_non_atomic_preview");
    CHECK(std::string{ndms_native_mutation_operation_name(operation)} ==
          "delete_interface");
    CHECK(std::string{ndms_native_mutation_validation_error_name(
              NdmsNativeMutationValidationError::ownership_unverified)} ==
          "ownership_unverified");
    CHECK(std::string{ndms_native_mutation_plan_blocker_name(
              NdmsNativeMutationPlanBlocker::
                  secret_bearing_import_apply_unavailable)} ==
          "secret_bearing_import_apply_unavailable");
}
