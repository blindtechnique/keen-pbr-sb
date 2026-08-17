#pragma once

#include "ndms_wireguard_identity.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct NdmsNativeWireguardTargetRange {
    std::uint8_t first_index{0};
    std::uint8_t last_index{0};

    bool contains(std::uint8_t index) const noexcept {
        return index >= first_index && index <= last_index;
    }

    bool operator==(
        const NdmsNativeWireguardTargetRange& other) const noexcept {
        return first_index == other.first_index &&
               last_index == other.last_index;
    }
};

enum class NdmsNativeCreatePolicyBlocker {
    writer_disabled,
    allocator_range_unfenced,
    recovery_journal_not_integrated,
    reconcile_barrier_not_integrated,
};

enum class NdmsNativeDormantFacilityState {
    dormant,
};

// Safe description of the measured stock create-only primitive. It contains
// no import body, filename, endpoint or credential. In particular,
// request_name is a fixed empty literal rather than caller-controlled input.
struct NdmsNativeCreatePolicy {
    bool preview_only{true};
    bool apply_available{false};
    std::string operation{"interface.wireguard.import"};
    std::string request_name;
    std::size_t batch_item_count{1U};
    // Stock firmware scans 0..126. Only canonical post-results 5..98 enter
    // the managed candidate range; 99..126 remain protected/unsupported.
    NdmsNativeWireguardTargetRange allocator_range{0U, 126U};
    NdmsNativeWireguardTargetRange eligible_returned_targets{5U, 98U};
    std::vector<NdmsNativeWireguardTargetRange> protected_targets{
        {0U, 4U},
        {99U, 126U},
    };
    NdmsNativeDormantFacilityState journal_state{
        NdmsNativeDormantFacilityState::dormant};
    NdmsNativeDormantFacilityState reconcile_barrier_state{
        NdmsNativeDormantFacilityState::dormant};
    std::vector<NdmsNativeCreatePolicyBlocker> blockers{
        NdmsNativeCreatePolicyBlocker::writer_disabled,
        NdmsNativeCreatePolicyBlocker::allocator_range_unfenced,
        NdmsNativeCreatePolicyBlocker::recovery_journal_not_integrated,
        NdmsNativeCreatePolicyBlocker::reconcile_barrier_not_integrated,
    };
};

NdmsNativeCreatePolicy preview_ndms_native_create_policy();

// Checks the immutable preview contract. True never authorizes a mutation.
bool ndms_native_create_policy_is_consistent(
    const NdmsNativeCreatePolicy& policy) noexcept;

bool ndms_native_created_target_is_eligible(
    const std::string& interface_name) noexcept;

bool ndms_native_created_target_is_protected(
    const std::string& interface_name) noexcept;

const char* ndms_native_create_policy_blocker_name(
    NdmsNativeCreatePolicyBlocker blocker) noexcept;

const char* ndms_native_dormant_facility_state_name(
    NdmsNativeDormantFacilityState state) noexcept;

} // namespace keen_pbr3
