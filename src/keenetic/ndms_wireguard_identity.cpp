#include "ndms_wireguard_identity.hpp"

#include <string_view>

namespace keen_pbr3 {

namespace {

constexpr std::string_view kPrefix{"Wireguard"};

NdmsWireguardSlotClass classify_slot(const unsigned int slot) noexcept {
    if (slot <= 4U) {
        return NdmsWireguardSlotClass::protected_system;
    }
    if (slot <= 98U) {
        return NdmsWireguardSlotClass::managed_candidate;
    }
    return NdmsWireguardSlotClass::protected_sentinel;
}

} // namespace

std::string NdmsWireguardIdentity::canonical_name() const {
    return "Wireguard" + std::to_string(slot);
}

std::optional<NdmsWireguardIdentity>
parse_ndms_wireguard_identity(const std::string_view value) noexcept {
    if (value.size() <= kPrefix.size() ||
        value.compare(0U, kPrefix.size(), kPrefix) != 0) {
        return std::nullopt;
    }

    const auto suffix = value.substr(kPrefix.size());
    if (suffix.empty() || suffix.size() > 3U ||
        (suffix.size() > 1U && suffix.front() == '0')) {
        return std::nullopt;
    }

    unsigned int slot = 0U;
    for (const char character : suffix) {
        if (character < '0' || character > '9') {
            return std::nullopt;
        }
        slot = slot * 10U +
               static_cast<unsigned int>(character - '0');
    }
    if (slot > 126U) return std::nullopt;

    return NdmsWireguardIdentity{
        static_cast<std::uint8_t>(slot), classify_slot(slot)};
}

bool ndms_wireguard_identity_is_managed_candidate(
    const NdmsWireguardIdentity& identity) noexcept {
    return identity.slot_class ==
           NdmsWireguardSlotClass::managed_candidate;
}

bool ndms_wireguard_identity_is_protected(
    const NdmsWireguardIdentity& identity) noexcept {
    return !ndms_wireguard_identity_is_managed_candidate(identity);
}

const char* ndms_wireguard_slot_class_name(
    const NdmsWireguardSlotClass value) noexcept {
    switch (value) {
    case NdmsWireguardSlotClass::protected_system:
        return "protected_system";
    case NdmsWireguardSlotClass::managed_candidate:
        return "managed_candidate";
    case NdmsWireguardSlotClass::protected_sentinel:
        return "protected_sentinel";
    }
    return "unknown";
}

} // namespace keen_pbr3
