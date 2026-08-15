#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

enum class NdmsWireguardSlotClass : std::uint8_t {
    protected_system,
    managed_candidate,
    protected_sentinel,
};

// Canonical KeeneticOS WireGuard identity. Only the measured family
// Wireguard0..Wireguard126 is accepted; leading zeroes and path-like suffixes
// are rejected before a caller can use the value in an RCI path or policy.
struct NdmsWireguardIdentity {
    std::uint8_t slot{0};
    NdmsWireguardSlotClass slot_class{
        NdmsWireguardSlotClass::protected_system};

    std::string canonical_name() const;
};

std::optional<NdmsWireguardIdentity>
parse_ndms_wireguard_identity(std::string_view value) noexcept;

bool ndms_wireguard_identity_is_managed_candidate(
    const NdmsWireguardIdentity& identity) noexcept;

bool ndms_wireguard_identity_is_protected(
    const NdmsWireguardIdentity& identity) noexcept;

const char* ndms_wireguard_slot_class_name(
    NdmsWireguardSlotClass value) noexcept;

} // namespace keen_pbr3
