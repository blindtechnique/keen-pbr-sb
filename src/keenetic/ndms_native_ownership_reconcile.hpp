#pragma once

#include "ndms_native_interface_read.hpp"
#include "ndms_native_ownership_store.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Retires ownership claims whose interface no longer exists.
//
// It only ever removes claims for interfaces whose configuration and runtime
// documents are both authoritatively absent. It never deletes an interface,
// never publishes, and never receives a command-execution capability.
struct NdmsNativeOwnershipReconcileResult {
    // False when the claim directory could not be enumerated. Distinguished
    // from "nothing to do" because an unreadable store must not be reported
    // as a clean one.
    bool store_readable{false};
    // True when a WAL transaction was in flight and reconciliation was
    // therefore skipped entirely - the dispatcher owns those claims, and a
    // second remover racing it would turn its retirement into a failure.
    bool skipped_transaction_in_flight{false};
    std::size_t claims_examined{0U};
    std::vector<std::string> retired;
    // A claim whose interface is gone but whose file would not go away, or
    // whose bytes could not be parsed. Kept separate from `retired`: these
    // still assert ownership and an operator has to know.
    std::vector<std::string> unresolved;
};

// `wal_transaction_in_flight` is supplied by the caller rather than read here,
// so this stays free of the WAL store and keeps working for a future caller
// whose transactions live somewhere else.
NdmsNativeOwnershipReconcileResult reconcile_ndms_native_ownership_claims(
    NdmsNativeOwnershipStore& ownership_store,
    bool wal_transaction_in_flight,
    const NdmsNativeInterfaceReadDependencies& read_dependencies);

} // namespace keen_pbr3
