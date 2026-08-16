#include "ndms_native_remove_policy.hpp"

#include "ndms_native_interface_delete.hpp"

namespace keen_pbr3 {

const char* ndms_native_remove_policy_blocker_name(
    const NdmsNativeRemovePolicyBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeRemovePolicyBlocker::writer_disabled:
        return "writer_disabled";
    case NdmsNativeRemovePolicyBlocker::
        no_claims_can_exist_until_import_works:
        return "no_claims_can_exist_until_import_works";
    }
    return "writer_disabled";
}

NdmsNativeRemovePolicy preview_ndms_native_remove_policy() {
    return {};
}

bool ndms_native_remove_policy_is_consistent(
    const NdmsNativeRemovePolicy& policy) noexcept {
    const NdmsNativeRemovePolicy expected;
    return policy.preview_only && !policy.apply_available &&
           policy.operation == expected.operation &&
           policy.removable_targets == expected.removable_targets &&
           policy.protected_targets == expected.protected_targets &&
           policy.blockers == expected.blockers;
}

bool ndms_native_removable_target(
    const std::string& interface_name) noexcept {
    return ndms_native_created_target_is_eligible(interface_name);
}

} // namespace keen_pbr3
