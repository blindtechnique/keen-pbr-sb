#include "ndms_native_tunnel_removal.hpp"

#include "ndms_native_create_policy.hpp"

namespace keen_pbr3 {

const char* ndms_native_tunnel_removal_outcome_name(
    const NdmsNativeTunnelRemovalOutcome outcome) noexcept {
    switch (outcome) {
    case NdmsNativeTunnelRemovalOutcome::removed:
        return "removed";
    case NdmsNativeTunnelRemovalOutcome::not_owned:
        return "not_owned";
    case NdmsNativeTunnelRemovalOutcome::refused:
        return "refused";
    case NdmsNativeTunnelRemovalOutcome::failed:
        return "failed";
    case NdmsNativeTunnelRemovalOutcome::removed_claim_survived:
        return "removed_claim_survived";
    }
    return "failed";
}

NdmsNativeTunnelRemovalOutcome remove_owned_ndms_tunnel(
    const std::string& interface_name,
    NdmsNativeOwnershipStore& ownership_store,
    const NdmsNativeInterfaceDeleteDependencies& delete_dependencies) {
    // Decided before the store is consulted. The store refuses to hold a
    // claim over a protected slot, but it reports that refusal as
    // `unreadable` - the same state a torn claim produces - and collapsing
    // "cannot be claimed" into "could not be read" would answer an operator
    // naming Wireguard0 with a retryable failure instead of the truth.
    if (!ndms_native_created_target_is_eligible(interface_name)) {
        return NdmsNativeTunnelRemovalOutcome::not_owned;
    }
    const auto claim = ownership_store.read(interface_name);
    switch (claim.state) {
    case NdmsNativeOwnershipReadState::absent:
        return NdmsNativeTunnelRemovalOutcome::not_owned;
    case NdmsNativeOwnershipReadState::unreadable:
        // A torn claim is evidence of an interrupted publish. Reading it as
        // "not ours" would refuse to clean up something that is ours; reading
        // it as ours would authorize a delete on bytes we cannot parse.
        return NdmsNativeTunnelRemovalOutcome::failed;
    case NdmsNativeOwnershipReadState::valid:
        break;
    }
    if (!claim.record.has_value()) {
        return NdmsNativeTunnelRemovalOutcome::failed;
    }
    // The marker comes from the claim, never from the caller. An operator gets
    // to name the interface; what authorizes the delete is what keen-pbr
    // durably recorded about it.
    const auto deleted = delete_exact_owned_ndms_interface(
        interface_name, claim.record->marker, delete_dependencies);
    switch (deleted) {
    case NdmsNativeImportRecoveryDeleteOutcome::refused:
        return NdmsNativeTunnelRemovalOutcome::refused;
    case NdmsNativeImportRecoveryDeleteOutcome::failed:
        // The claim stays: the interface may still be there, and a retired
        // claim over a surviving interface is how keen-pbr forgets something
        // it is still responsible for.
        return NdmsNativeTunnelRemovalOutcome::failed;
    case NdmsNativeImportRecoveryDeleteOutcome::deleted_confirmed:
        break;
    }
    // Absence is proven. Retiring the claim is what keeps the store from
    // asserting ownership of a slot that is now free - and a failure to retire
    // it is reported rather than folded into success.
    return ownership_store.remove_exact(*claim.record)
               ? NdmsNativeTunnelRemovalOutcome::removed
               : NdmsNativeTunnelRemovalOutcome::removed_claim_survived;
}

} // namespace keen_pbr3
