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
    const NdmsNativeInterfaceReadDependencies& dependencies) {
    const auto classify = [](const std::optional<nlohmann::json>& document) {
        if (!document.has_value()) return InterfacePresence::unknown;
        if (document->is_null()) return InterfacePresence::absent;
        if (document->is_object() && !document->empty()) {
            return InterfacePresence::present;
        }
        // Empty objects, arrays and scalars are not the measured absence
        // shape. Treating a successfully parsed but unexpected document as
        // absence could retire a live interface's ownership claim.
        return InterfacePresence::unknown;
    };
    const auto config = dependencies.read_document(
        "show/rc/interface/" + interface_name);
    const auto runtime =
        dependencies.read_document("show/interface/" + interface_name);
    const auto config_presence = classify(config);
    const auto runtime_presence = classify(runtime);
    if (config_presence == InterfacePresence::present ||
        runtime_presence == InterfacePresence::present) {
        return InterfacePresence::present;
    }
    if (config_presence == InterfacePresence::absent &&
        runtime_presence == InterfacePresence::absent) {
        return InterfacePresence::absent;
    }
    return InterfacePresence::unknown;
}

} // namespace

bool ndms_native_ownership_reconciliation_permitted(
    const bool import_wal_transaction_in_flight,
    const NdmsNativeDeleteWalReadiness delete_wal_readiness) noexcept {
    return !import_wal_transaction_in_flight &&
           delete_wal_readiness == NdmsNativeDeleteWalReadiness::clean;
}

NdmsNativeOwnershipReconcileResult reconcile_ndms_native_ownership_claims(
    NdmsNativeOwnershipStore& ownership_store,
    const bool wal_transaction_in_flight,
    const NdmsNativeInterfaceReadDependencies& read_dependencies,
    const NdmsNativeDeleteWalReadiness delete_wal_readiness) {
    NdmsNativeOwnershipReconcileResult result;
    if (!read_dependencies.read_document) return result;
    if (!ndms_native_ownership_reconciliation_permitted(
            wal_transaction_in_flight, delete_wal_readiness)) {
        // The dispatcher owns every claim while its transaction is live, and
        // it retracts them itself. A second remover racing it would turn its
        // retirement into a `removed_claim_survived` for no reason.
        result.store_readable = true;
        result.skipped_transaction_in_flight =
            wal_transaction_in_flight;
        result.skipped_delete_wal_not_clean =
            delete_wal_readiness !=
            NdmsNativeDeleteWalReadiness::clean;
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
        if (ndms_native_ownership_is_delete_tombstone(*claim.record)) {
            result.retained_tombstones.push_back(interface_name);
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
