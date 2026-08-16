#pragma once

#include "ndms_native_interface_delete.hpp"
#include "ndms_native_ownership_store.hpp"

#include <string>

namespace keen_pbr3 {

// Operator-initiated removal of a tunnel keen-pbr created.
//
// Distinct from the recovery rollback, which finishes an interrupted
// transaction from its WAL. This one has no transaction in flight: the import
// completed, its ownership claim is on disk, and the operator now wants the
// tunnel gone. Composed entirely from parts that already exist, so it invents
// no new authority - and notably it needs no allocator fence, because
// removing a slot allocates nothing.
enum class NdmsNativeTunnelRemovalOutcome {
    removed,
    // No claim: keen-pbr does not own this interface, so it is not ours to
    // remove however the caller reached us.
    not_owned,
    // A claim exists and the interface refused the delete - it stopped
    // carrying our marker, or it sits outside the managed range.
    refused,
    // The world could not be read, the command failed, or absence could not
    // be proven. The claim is deliberately left standing.
    failed,
    // The interface is gone but its claim could not be retired. Reported
    // separately because the router is already in the intended state while
    // the store is not, and a caller that treats this as success leaves a
    // durable assertion of ownership over a free slot.
    removed_claim_survived,
};

const char* ndms_native_tunnel_removal_outcome_name(
    NdmsNativeTunnelRemovalOutcome outcome) noexcept;

// The claim is read first and the marker for the delete comes from it, never
// from the caller: an operator asking to remove "Wireguard5" must not also get
// to say which marker authorizes it. A torn claim fails rather than being read
// as absence - "not ours" must never be the reading of an interrupted publish.
NdmsNativeTunnelRemovalOutcome remove_owned_ndms_tunnel(
    const std::string& interface_name,
    NdmsNativeOwnershipStore& ownership_store,
    const NdmsNativeInterfaceDeleteDependencies& delete_dependencies);

} // namespace keen_pbr3
