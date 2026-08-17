#include "ndms_native_ownership_reconcile.hpp"

namespace keen_pbr3 {

namespace {

// Absence has one shape here and it is deliberately strict: both the
// configuration and the runtime document must agree the interface is gone.
// Retiring a claim over an interface that is only half absent would let
// keen-pbr forget something the router still has.
enum class InterfacePresence { present, absent, unknown };

InterfacePresence presence_of(
    const std::string& interface_name,
    const NdmsNativeInterfaceDeleteDependencies& dependencies) {
    const auto describes = [](const std::optional<nlohmann::json>& document) {
        return document.has_value() && document->is_object() &&
               !document->empty();
    };
    const auto config = dependencies.read_document(
        "show/rc/interface/" + interface_name);
    const auto runtime =
        dependencies.read_document("show/interface/" + interface_name);
    if (!config.has_value() || !runtime.has_value()) {
        return InterfacePresence::unknown;
    }
    if (describes(config) || describes(runtime)) {
        return InterfacePresence::present;
    }
    return InterfacePresence::absent;
}

} // namespace

NdmsNativeOwnershipReconcileResult reconcile_ndms_native_ownership_claims(
    NdmsNativeOwnershipStore& ownership_store,
    const bool wal_transaction_in_flight,
    const NdmsNativeInterfaceDeleteDependencies& read_dependencies) {
    NdmsNativeOwnershipReconcileResult result;
    if (!read_dependencies.read_document) return result;
    if (wal_transaction_in_flight) {
        // The dispatcher owns every claim while its transaction is live, and
        // it retracts them itself. A second remover racing it would turn its
        // retirement into a `removed_claim_survived` for no reason.
        result.store_readable = true;
        result.skipped_transaction_in_flight = true;
        return result;
    }

    const auto listing = ownership_store.list_claimed_interfaces();
    if (!listing.readable) return result;
    result.store_readable = true;

    for (const auto& interface_name : listing.interface_names) {
        ++result.claims_examined;
        const auto claim = ownership_store.read(interface_name);
        if (claim.state != NdmsNativeOwnershipReadState::valid ||
            !claim.record.has_value()) {
            // A torn claim is not evidence that the interface is gone, and it
            // cannot be removed exactly because its bytes will not parse.
            result.unresolved.push_back(interface_name);
            continue;
        }
        switch (presence_of(interface_name, read_dependencies)) {
        case InterfacePresence::present:
            // Still ours and still there. Nothing to do - this is the normal
            // state of a healthy import.
            continue;
        case InterfacePresence::unknown:
            // A read we could not complete is not absence. Leaving the claim
            // costs nothing; retiring it on a guess would forget an interface
            // the router may still have.
            result.unresolved.push_back(interface_name);
            continue;
        case InterfacePresence::absent:
            break;
        }
        if (ownership_store.remove_exact(*claim.record)) {
            result.retired.push_back(interface_name);
        } else {
            result.unresolved.push_back(interface_name);
        }
    }
    return result;
}

} // namespace keen_pbr3
