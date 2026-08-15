#include "ndms_native_create_policy.hpp"

namespace keen_pbr3 {

NdmsNativeCreatePolicy preview_ndms_native_create_policy() {
    return {};
}

bool ndms_native_create_policy_is_consistent(
    const NdmsNativeCreatePolicy& policy) noexcept {
    const NdmsNativeCreatePolicy expected;
    return policy.preview_only && !policy.apply_available &&
           policy.operation == expected.operation &&
           policy.request_name.empty() &&
           policy.batch_item_count == 1U &&
           policy.allocator_range == expected.allocator_range &&
           policy.eligible_returned_targets ==
               expected.eligible_returned_targets &&
           policy.protected_targets == expected.protected_targets &&
           policy.journal_state ==
               NdmsNativeDormantFacilityState::dormant &&
           policy.reconcile_barrier_state ==
               NdmsNativeDormantFacilityState::dormant &&
           policy.blockers == expected.blockers;
}

bool ndms_native_created_target_is_eligible(
    const std::string& interface_name) noexcept {
    const auto identity =
        parse_ndms_wireguard_identity(interface_name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity);
}

bool ndms_native_created_target_is_protected(
    const std::string& interface_name) noexcept {
    const auto identity =
        parse_ndms_wireguard_identity(interface_name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_protected(*identity);
}

const char* ndms_native_create_policy_blocker_name(
    const NdmsNativeCreatePolicyBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeCreatePolicyBlocker::writer_disabled:
        return "writer_disabled";
    case NdmsNativeCreatePolicyBlocker::allocator_range_unfenced:
        return "allocator_range_unfenced";
    case NdmsNativeCreatePolicyBlocker::
        recovery_journal_not_integrated:
        return "recovery_journal_not_integrated";
    case NdmsNativeCreatePolicyBlocker::
        reconcile_barrier_not_integrated:
        return "reconcile_barrier_not_integrated";
    }
    return "unknown";
}

const char* ndms_native_dormant_facility_state_name(
    const NdmsNativeDormantFacilityState state) noexcept {
    switch (state) {
    case NdmsNativeDormantFacilityState::dormant:
        return "dormant";
    }
    return "unknown";
}

} // namespace keen_pbr3
