#pragma once

#include "ndms_native_create_policy.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

// Removal is a different capability from creation and has different blockers,
// which the create policy cannot express because it describes one operation.
//
// The distinction is not cosmetic. Creation is blocked by a firmware fact:
// the stock import posts `"name":""`, so the slot is chosen by the firmware,
// and KeeneticOS 5.1.1 offers neither a bounded atomic allocator nor a global
// writer lease to make that choice safe against a racing writer. Removal
// allocates nothing, names its target exactly, and therefore needs no
// allocator fence at all. Reporting one readiness for both would tell an
// operator that removing a tunnel waits on a guarantee it never needed.
enum class NdmsNativeRemovePolicyBlocker {
    // The master switch. No operator-facing path is enabled yet: the
    // primitives exist and are tested, but nothing routes to them.
    writer_disabled,
    // Removal is reachable only for interfaces keen-pbr durably claimed.
    // Nothing publishes claims yet, because publishing one requires a
    // completed import - which creation cannot perform on this firmware. So
    // removal is presently a capability with nothing to act on.
    no_claims_can_exist_until_import_works,
};

const char* ndms_native_remove_policy_blocker_name(
    NdmsNativeRemovePolicyBlocker blocker) noexcept;

// Safe description of the removal capability. Carries no interface name,
// marker or claim - only what the operation is and why it is not yet offered.
struct NdmsNativeRemovePolicy {
    bool preview_only{true};
    bool apply_available{false};
    // What the router is actually told. Pinned here so the readiness report
    // and the implementation cannot describe different commands.
    std::string operation{"no interface"};
    // Only interfaces in the managed candidate range can ever be claimed, so
    // only they can ever be removed by keen-pbr.
    NdmsNativeWireguardTargetRange removable_targets{5U, 98U};
    std::vector<NdmsNativeWireguardTargetRange> protected_targets{
        {0U, 4U},
        {99U, 126U},
    };
    // Deliberately absent from the blockers: removal needs no allocator
    // fence, and listing one would be false.
    std::vector<NdmsNativeRemovePolicyBlocker> blockers{
        NdmsNativeRemovePolicyBlocker::writer_disabled,
        NdmsNativeRemovePolicyBlocker::
            no_claims_can_exist_until_import_works,
    };
};

NdmsNativeRemovePolicy preview_ndms_native_remove_policy();

// True never authorizes a mutation. It checks that the published description
// still matches the immutable contract above.
bool ndms_native_remove_policy_is_consistent(
    const NdmsNativeRemovePolicy& policy) noexcept;

// The exact interfaces keen-pbr may ever remove. Shares the create policy's
// eligibility rule rather than restating it: two definitions of "managed
// candidate" is how they come to disagree.
bool ndms_native_removable_target(
    const std::string& interface_name) noexcept;

} // namespace keen_pbr3
