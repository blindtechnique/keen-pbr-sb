#include "ndms_native_import_recovery_probe.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace keen_pbr3 {
namespace {

void update_revision_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    std::array<unsigned char, 8U> encoded_size{};
    for (std::size_t index = 0U; index < encoded_size.size(); ++index) {
        encoded_size[index] = static_cast<unsigned char>(
            size >> (56U - index * 8U));
    }
    hasher.update(encoded_size.data(), encoded_size.size());
    hasher.update(value.data(), value.size());
}

const char* slot_state_name(
    const NdmsWireguardCatalogSlotState state) noexcept {
    switch (state) {
    case NdmsWireguardCatalogSlotState::absent:
        return "absent";
    case NdmsWireguardCatalogSlotState::occupied:
        return "occupied";
    case NdmsWireguardCatalogSlotState::unsafe:
        return "unsafe";
    }
    return "unsafe";
}

} // namespace

std::string ndms_native_import_recovery_catalog_revision(
    const NdmsInterfaceCatalog& catalog,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>&
        target_evidence) {
    Sha256 hasher;
    update_revision_field(
        hasher, "keen-pbr.ndms-native-import.recovery-catalog.v1");
    update_revision_field(
        hasher, catalog.firmware_available ? "1" : "0");
    update_revision_field(
        hasher, catalog.wireguard_slot_evidence_complete ? "1" : "0");
    for (std::size_t index = 0U;
         index < catalog.wireguard_slots.size(); ++index) {
        const auto& slot = catalog.wireguard_slots[index];
        update_revision_field(hasher, std::to_string(index));
        update_revision_field(hasher, slot_state_name(slot.state));
        update_revision_field(hasher, slot.structural_revision);
    }

    std::vector<const NdmsNativeImportRecoveryTargetEvidence*> ordered;
    ordered.reserve(target_evidence.size());
    for (const auto& item : target_evidence) ordered.push_back(&item);
    std::sort(
        ordered.begin(), ordered.end(),
        [](const NdmsNativeImportRecoveryTargetEvidence* left,
           const NdmsNativeImportRecoveryTargetEvidence* right) {
            if (left->interface_name != right->interface_name) {
                return left->interface_name < right->interface_name;
            }
            if (left->link_down != right->link_down) {
                return left->link_down < right->link_down;
            }
            return left->full_revision < right->full_revision;
        });
    update_revision_field(hasher, std::to_string(ordered.size()));
    for (const auto* item : ordered) {
        update_revision_field(hasher, item->interface_name);
        update_revision_field(hasher, item->link_down ? "1" : "0");
        update_revision_field(hasher, item->full_revision);
    }
    return std::string{kNdmsNativeObservationCatalogRevisionPrefix} +
           hasher.hex_digest();
}

} // namespace keen_pbr3
