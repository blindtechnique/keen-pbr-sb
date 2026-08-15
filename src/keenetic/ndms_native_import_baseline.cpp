#include "ndms_native_import_baseline.hpp"

#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kSlotRevisionPrefix{
    "ndms-wg-slot-v1-"};

static_assert(
    kNdmsNativeImportOccupancyBytes ==
        (kNdmsWireguardCatalogSlotCount + 7U) / 8U,
    "the persisted occupancy must cover exactly Wireguard0..126");

bool lower_hex(const std::string_view value) noexcept {
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

bool prefixed_sha256(
    const std::string_view value,
    const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           value.compare(0U, prefix.size(), prefix) == 0 &&
           lower_hex(value.substr(prefix.size()));
}

void update_tagged_field(
    Sha256& hasher,
    const std::uint8_t tag,
    const void* data,
    const std::size_t size) {
    // Canonical v1 framing: one tag octet, an unsigned 64-bit big-endian
    // payload length, then the exact payload bytes. Every digest below walks
    // fixed fields or the fixed slot array; it never hashes JSON, an object
    // representation, a native-endian integer or std::hash output.
    hasher.update(&tag, sizeof(tag));
    std::array<std::uint8_t, 8U> encoded_size{};
    std::uint64_t remaining = size;
    for (std::size_t index = 0U;
         index < encoded_size.size(); ++index) {
        encoded_size[encoded_size.size() - 1U - index] =
            static_cast<std::uint8_t>(remaining & 0xffU);
        remaining >>= 8U;
    }
    hasher.update(encoded_size.data(), encoded_size.size());
    hasher.update(data, size);
}

void update_tagged_field(
    Sha256& hasher,
    const std::uint8_t tag,
    const std::string_view value) {
    update_tagged_field(
        hasher, tag, value.data(), value.size());
}

template <std::size_t Size>
void update_tagged_field(
    Sha256& hasher,
    const std::uint8_t tag,
    const std::array<std::uint8_t, Size>& value) {
    update_tagged_field(
        hasher, tag, value.data(), value.size());
}

template <typename Unsigned>
void update_unsigned_field(
    Sha256& hasher,
    const std::uint8_t tag,
    Unsigned value) {
    static_assert(
        std::is_unsigned<Unsigned>::value,
        "baseline digest integers must be unsigned");
    std::array<std::uint8_t, sizeof(Unsigned)> encoded{};
    for (std::size_t index = 0U; index < encoded.size(); ++index) {
        encoded[encoded.size() - 1U - index] =
            static_cast<std::uint8_t>(value & 0xffU);
        value >>= 8U;
    }
    update_tagged_field(hasher, tag, encoded);
}

bool slot_evidence_is_valid(
    const NdmsWireguardCatalogSlotEvidence& evidence) noexcept {
    switch (evidence.state) {
    case NdmsWireguardCatalogSlotState::absent:
        return evidence.structural_revision.empty();
    case NdmsWireguardCatalogSlotState::occupied:
        return prefixed_sha256(
            evidence.structural_revision,
            kSlotRevisionPrefix);
    case NdmsWireguardCatalogSlotState::unsafe:
        return false;
    }
    return false;
}

bool all_slot_evidence_is_valid(
    const NdmsInterfaceCatalog& catalog) noexcept {
    return std::all_of(
        catalog.wireguard_slots.begin(),
        catalog.wireguard_slots.end(),
        slot_evidence_is_valid);
}

bool authoritative_catalog_snapshot(
    const NdmsCatalogSnapshot& snapshot) noexcept {
    return snapshot.catalog.firmware_available &&
           snapshot.status == NdmsCatalogCacheStatus::fresh &&
           snapshot.refreshed && snapshot.observed_at.has_value() &&
           snapshot.observation_generation != 0U &&
           snapshot.observation_epoch == snapshot.invalidation_epoch &&
           snapshot.catalog.wireguard_slot_evidence_complete &&
           all_slot_evidence_is_valid(snapshot.catalog);
}

std::array<std::uint8_t, kNdmsNativeImportOccupancyBytes>
build_occupancy(const NdmsInterfaceCatalog& catalog) noexcept {
    std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes> occupancy{};
    for (std::size_t slot = 0U;
         slot < catalog.wireguard_slots.size(); ++slot) {
        if (catalog.wireguard_slots[slot].state !=
            NdmsWireguardCatalogSlotState::occupied) {
            continue;
        }
        occupancy[slot / 8U] = static_cast<std::uint8_t>(
            occupancy[slot / 8U] |
            static_cast<std::uint8_t>(
                std::uint8_t{1U} << (slot % 8U)));
    }
    return occupancy;
}

std::string occupancy_hex(
    const std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes>& occupancy) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(kNdmsNativeImportOccupancyHexCharacters);
    for (const auto byte : occupancy) {
        result.push_back(hex[byte >> 4U]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
}

std::optional<std::uint8_t> first_free_slot(
    const NdmsInterfaceCatalog& catalog) noexcept {
    for (std::size_t slot = 0U;
         slot < catalog.wireguard_slots.size(); ++slot) {
        if (catalog.wireguard_slots[slot].state ==
            NdmsWireguardCatalogSlotState::absent) {
            return static_cast<std::uint8_t>(slot);
        }
    }
    return std::nullopt;
}

std::string protected_catalog_digest(
    const NdmsInterfaceCatalog& catalog,
    const std::uint8_t expected_target_slot) {
    constexpr std::string_view domain{
        "keen-pbr.ndms-native-import.protected-catalog.v1"};
    Sha256 hasher;
    update_tagged_field(hasher, 0U, domain);
    update_unsigned_field(
        hasher, 1U, expected_target_slot);
    for (std::size_t slot = 0U;
         slot < catalog.wireguard_slots.size(); ++slot) {
        if (slot == expected_target_slot) continue;
        const auto slot_number = static_cast<std::uint8_t>(slot);
        const auto& evidence = catalog.wireguard_slots[slot];
        const std::uint8_t occupied =
            evidence.state == NdmsWireguardCatalogSlotState::occupied
                ? 1U
                : 0U;
        update_unsigned_field(hasher, 2U, slot_number);
        update_unsigned_field(hasher, 3U, occupied);
        if (occupied != 0U) {
            update_tagged_field(
                hasher, 4U, evidence.structural_revision);
        }
    }
    return std::string{kNdmsNativeImportProtectedCatalogDigestPrefix} +
           hasher.hex_digest();
}

std::string baseline_digest(
    const std::string_view expected_target,
    const std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes>& occupancy,
    const std::string_view protected_digest,
    const std::uint64_t observation_generation,
    const std::uint64_t observation_epoch,
    const std::uint64_t invalidation_epoch,
    const std::uint32_t maintenance_base_generation,
    const std::uint64_t allocator_generation) {
    constexpr std::string_view domain{
        "keen-pbr.ndms-native-import.baseline.v1"};
    Sha256 hasher;
    update_tagged_field(hasher, 0U, domain);
    update_tagged_field(hasher, 1U, expected_target);
    update_tagged_field(hasher, 2U, occupancy);
    update_tagged_field(hasher, 3U, protected_digest);
    update_unsigned_field(
        hasher, 4U, observation_generation);
    update_unsigned_field(hasher, 5U, observation_epoch);
    update_unsigned_field(hasher, 6U, invalidation_epoch);
    update_unsigned_field(
        hasher, 7U, maintenance_base_generation);
    update_unsigned_field(hasher, 8U, allocator_generation);
    return std::string{kNdmsNativeImportBaselineDigestPrefix} +
           hasher.hex_digest();
}

NdmsNativeImportBaselineBuildResult failure(
    const NdmsNativeImportBaselineBuildError error) noexcept {
    return {error, std::nullopt};
}

bool occupancy_contains(
    const std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes>& occupancy,
    const std::uint8_t slot) noexcept {
    return (occupancy[slot / 8U] &
            static_cast<std::uint8_t>(
                std::uint8_t{1U} << (slot % 8U))) != 0U;
}

std::optional<std::array<
    std::uint8_t,
    kNdmsNativeImportOccupancyBytes>>
parse_occupancy_hex(const std::string_view value) noexcept {
    if (value.size() !=
            kNdmsNativeImportOccupancyHexCharacters ||
        !lower_hex(value)) {
        return std::nullopt;
    }

    const auto nibble = [](const char character) noexcept {
        return static_cast<std::uint8_t>(
            character >= '0' && character <= '9'
                ? character - '0'
                : character - 'a' + 10);
    };
    std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes> occupancy{};
    for (std::size_t index = 0U;
         index < occupancy.size(); ++index) {
        occupancy[index] = static_cast<std::uint8_t>(
            static_cast<std::uint8_t>(
                nibble(value[index * 2U]) << 4U) |
            nibble(value[index * 2U + 1U]));
    }
    return occupancy;
}

std::optional<std::uint8_t> first_free_slot(
    const std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes>& occupancy) noexcept {
    for (std::size_t slot = 0U;
         slot < kNdmsWireguardCatalogSlotCount; ++slot) {
        const auto narrowed = static_cast<std::uint8_t>(slot);
        if (!occupancy_contains(occupancy, narrowed)) return narrowed;
    }
    return std::nullopt;
}

} // namespace

bool NdmsNativeImportPersistedBaseline::operator==(
    const NdmsNativeImportPersistedBaseline& other) const noexcept {
    return expected_created_interface ==
               other.expected_created_interface &&
           expected_target_slot == other.expected_target_slot &&
           occupancy_hex == other.occupancy_hex &&
           protected_catalog_sha256 ==
               other.protected_catalog_sha256 &&
           observation_generation == other.observation_generation &&
           observation_epoch == other.observation_epoch &&
           invalidation_epoch == other.invalidation_epoch &&
           maintenance_base_generation ==
               other.maintenance_base_generation &&
           allocator_generation == other.allocator_generation &&
           baseline_sha256 == other.baseline_sha256;
}

NdmsNativeImportBaselineEvidence::NdmsNativeImportBaselineEvidence(
    std::string expected_created_interface,
    const std::uint8_t expected_target_slot,
    std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes> occupancy,
    std::string occupancy_hex_value,
    std::string protected_catalog_sha256,
    const std::uint64_t observation_generation,
    const std::uint64_t observation_epoch,
    const std::uint64_t invalidation_epoch,
    const std::uint32_t maintenance_base_generation,
    const std::uint64_t allocator_generation,
    std::string baseline_sha256)
    : expected_created_interface_(
          std::move(expected_created_interface)),
      expected_target_slot_(expected_target_slot),
      occupancy_(occupancy),
      occupancy_hex_(std::move(occupancy_hex_value)),
      protected_catalog_sha256_(
          std::move(protected_catalog_sha256)),
      observation_generation_(observation_generation),
      observation_epoch_(observation_epoch),
      invalidation_epoch_(invalidation_epoch),
      maintenance_base_generation_(maintenance_base_generation),
      allocator_generation_(allocator_generation),
      baseline_sha256_(std::move(baseline_sha256)) {}

const std::string&
NdmsNativeImportBaselineEvidence::expected_created_interface()
    const noexcept {
    return expected_created_interface_;
}

std::uint8_t NdmsNativeImportBaselineEvidence::expected_target_slot()
    const noexcept {
    return expected_target_slot_;
}

const std::array<
    std::uint8_t,
    kNdmsNativeImportOccupancyBytes>&
NdmsNativeImportBaselineEvidence::occupancy() const noexcept {
    return occupancy_;
}

const std::string& NdmsNativeImportBaselineEvidence::occupancy_hex()
    const noexcept {
    return occupancy_hex_;
}

const std::string&
NdmsNativeImportBaselineEvidence::protected_catalog_sha256()
    const noexcept {
    return protected_catalog_sha256_;
}

std::uint64_t
NdmsNativeImportBaselineEvidence::observation_generation()
    const noexcept {
    return observation_generation_;
}

std::uint64_t NdmsNativeImportBaselineEvidence::observation_epoch()
    const noexcept {
    return observation_epoch_;
}

std::uint64_t NdmsNativeImportBaselineEvidence::invalidation_epoch()
    const noexcept {
    return invalidation_epoch_;
}

std::uint32_t
NdmsNativeImportBaselineEvidence::maintenance_base_generation()
    const noexcept {
    return maintenance_base_generation_;
}

std::uint64_t NdmsNativeImportBaselineEvidence::allocator_generation()
    const noexcept {
    return allocator_generation_;
}

const std::string& NdmsNativeImportBaselineEvidence::baseline_sha256()
    const noexcept {
    return baseline_sha256_;
}

NdmsNativeImportPersistedBaseline persist_ndms_native_import_baseline(
    const NdmsNativeImportBaselineEvidence& baseline) {
    return {
        baseline.expected_created_interface(),
        baseline.expected_target_slot(),
        baseline.occupancy_hex(),
        baseline.protected_catalog_sha256(),
        baseline.observation_generation(),
        baseline.observation_epoch(),
        baseline.invalidation_epoch(),
        baseline.maintenance_base_generation(),
        baseline.allocator_generation(),
        baseline.baseline_sha256(),
    };
}

bool valid_ndms_native_import_persisted_baseline(
    const NdmsNativeImportPersistedBaseline& baseline) noexcept {
    try {
        const auto identity = parse_ndms_wireguard_identity(
            baseline.expected_created_interface);
        if (!identity.has_value() ||
            !ndms_wireguard_identity_is_managed_candidate(*identity) ||
            identity->canonical_name() !=
                baseline.expected_created_interface ||
            identity->slot != baseline.expected_target_slot) {
            return false;
        }

        const auto occupancy =
            parse_occupancy_hex(baseline.occupancy_hex);
        if (!occupancy.has_value()) return false;
        // Wireguard127 is outside the measured fixed namespace. Its spare
        // bitmap bit must remain zero so no alternate representation exists.
        if (((*occupancy)[kNdmsNativeImportOccupancyBytes - 1U] &
             std::uint8_t{0x80U}) != 0U ||
            occupancy_contains(
                *occupancy, baseline.expected_target_slot)) {
            return false;
        }
        const auto first_free = first_free_slot(*occupancy);
        if (!first_free.has_value() ||
            *first_free != baseline.expected_target_slot) {
            return false;
        }

        if (!prefixed_sha256(
                baseline.protected_catalog_sha256,
                kNdmsNativeImportProtectedCatalogDigestPrefix) ||
            !prefixed_sha256(
                baseline.baseline_sha256,
                kNdmsNativeImportBaselineDigestPrefix) ||
            baseline.observation_generation == 0U ||
            baseline.observation_epoch != baseline.invalidation_epoch ||
            baseline.maintenance_base_generation ==
                std::numeric_limits<std::uint32_t>::max() ||
            baseline.allocator_generation == 0U) {
            return false;
        }

        return baseline.baseline_sha256 == baseline_digest(
            baseline.expected_created_interface,
            *occupancy,
            baseline.protected_catalog_sha256,
            baseline.observation_generation,
            baseline.observation_epoch,
            baseline.invalidation_epoch,
            baseline.maintenance_base_generation,
            baseline.allocator_generation);
    } catch (...) {
        return false;
    }
}

NdmsNativeImportBaselineBuildResult build_ndms_native_import_baseline(
    const NdmsCatalogSnapshot& snapshot,
    const std::string_view expected_created_interface,
    const std::uint32_t maintenance_base_generation,
    const std::uint64_t allocator_generation) {
    if (!snapshot.catalog.firmware_available) {
        return failure(
            NdmsNativeImportBaselineBuildError::firmware_unavailable);
    }
    if (snapshot.status != NdmsCatalogCacheStatus::fresh) {
        return failure(
            NdmsNativeImportBaselineBuildError::catalog_not_fresh);
    }
    if (!snapshot.refreshed) {
        return failure(
            NdmsNativeImportBaselineBuildError::catalog_not_refreshed);
    }
    if (!snapshot.observed_at.has_value()) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                catalog_observation_missing);
    }
    if (snapshot.observation_generation == 0U) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                observation_generation_invalid);
    }
    if (snapshot.observation_epoch != snapshot.invalidation_epoch) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                observation_epoch_mismatch);
    }
    if (!snapshot.catalog.wireguard_slot_evidence_complete) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                slot_evidence_incomplete);
    }
    if (!all_slot_evidence_is_valid(snapshot.catalog)) {
        return failure(
            NdmsNativeImportBaselineBuildError::slot_evidence_invalid);
    }

    const auto expected_identity =
        parse_ndms_wireguard_identity(expected_created_interface);
    if (!expected_identity.has_value() ||
        !ndms_wireguard_identity_is_managed_candidate(
            *expected_identity)) {
        return failure(
            NdmsNativeImportBaselineBuildError::expected_target_invalid);
    }

    const auto first_free = first_free_slot(snapshot.catalog);
    if (!first_free.has_value()) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                allocator_namespace_full);
    }
    const auto first_free_identity = NdmsWireguardIdentity{
        *first_free,
        *first_free <= 4U
            ? NdmsWireguardSlotClass::protected_system
            : (*first_free <= 98U
                   ? NdmsWireguardSlotClass::managed_candidate
                   : NdmsWireguardSlotClass::protected_sentinel)};
    if (ndms_wireguard_identity_is_protected(first_free_identity)) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                first_free_target_protected);
    }
    if (snapshot.catalog.wireguard_slots[expected_identity->slot].state !=
        NdmsWireguardCatalogSlotState::absent) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                expected_target_occupied);
    }
    if (*first_free != expected_identity->slot) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                expected_target_not_first_free);
    }
    if (maintenance_base_generation ==
        std::numeric_limits<std::uint32_t>::max()) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                maintenance_generation_exhausted);
    }
    if (allocator_generation == 0U) {
        return failure(
            NdmsNativeImportBaselineBuildError::
                allocator_generation_invalid);
    }

    const auto occupancy = build_occupancy(snapshot.catalog);
    auto occupancy_hex_value = occupancy_hex(occupancy);
    auto protected_digest = protected_catalog_digest(
        snapshot.catalog, expected_identity->slot);
    auto complete_digest = baseline_digest(
        expected_created_interface,
        occupancy,
        protected_digest,
        snapshot.observation_generation,
        snapshot.observation_epoch,
        snapshot.invalidation_epoch,
        maintenance_base_generation,
        allocator_generation);

    return {
        NdmsNativeImportBaselineBuildError::none,
        NdmsNativeImportBaselineEvidence{
            std::string{expected_created_interface},
            expected_identity->slot,
            occupancy,
            std::move(occupancy_hex_value),
            std::move(protected_digest),
            snapshot.observation_generation,
            snapshot.observation_epoch,
            snapshot.invalidation_epoch,
            maintenance_base_generation,
            allocator_generation,
            std::move(complete_digest)},
    };
}

NdmsNativeImportBaselineComparison::
NdmsNativeImportBaselineComparison(
    const bool current_catalog_authoritative,
    const bool target_absent_in_baseline,
    const bool protected_catalog_unchanged) noexcept
    : current_catalog_authoritative_(
          current_catalog_authoritative),
      target_absent_in_baseline_(target_absent_in_baseline),
      protected_catalog_unchanged_(protected_catalog_unchanged) {}

bool NdmsNativeImportBaselineComparison::
current_catalog_authoritative() const noexcept {
    return current_catalog_authoritative_;
}

bool NdmsNativeImportBaselineComparison::
target_absent_in_baseline() const noexcept {
    return target_absent_in_baseline_;
}

bool NdmsNativeImportBaselineComparison::
protected_catalog_unchanged() const noexcept {
    return protected_catalog_unchanged_;
}

NdmsNativeImportBaselineComparison
compare_ndms_native_import_baseline(
    const NdmsNativeImportBaselineEvidence& baseline,
    const NdmsCatalogSnapshot& current) {
    const bool target_was_absent = !occupancy_contains(
        baseline.occupancy_, baseline.expected_target_slot_);
    if (!authoritative_catalog_snapshot(current)) {
        return {false, target_was_absent, false};
    }
    const auto current_protected_digest = protected_catalog_digest(
        current.catalog, baseline.expected_target_slot_);
    return {
        true,
        target_was_absent,
        current_protected_digest ==
            baseline.protected_catalog_sha256_,
    };
}

NdmsNativeImportBaselineComparison
compare_ndms_native_import_baseline(
    const NdmsNativeImportPersistedBaseline& baseline,
    const NdmsCatalogSnapshot& current) {
    if (!valid_ndms_native_import_persisted_baseline(baseline)) {
        return {false, false, false};
    }
    const auto occupancy = parse_occupancy_hex(
        baseline.occupancy_hex);
    if (!occupancy.has_value()) return {false, false, false};

    const bool target_was_absent = !occupancy_contains(
        *occupancy, baseline.expected_target_slot);
    if (!authoritative_catalog_snapshot(current)) {
        return {false, target_was_absent, false};
    }
    const auto current_protected_digest = protected_catalog_digest(
        current.catalog, baseline.expected_target_slot);
    return {
        true,
        target_was_absent,
        current_protected_digest ==
            baseline.protected_catalog_sha256,
    };
}

const char* ndms_native_import_baseline_build_error_name(
    const NdmsNativeImportBaselineBuildError error) noexcept {
    switch (error) {
    case NdmsNativeImportBaselineBuildError::none:
        return "none";
    case NdmsNativeImportBaselineBuildError::firmware_unavailable:
        return "firmware_unavailable";
    case NdmsNativeImportBaselineBuildError::catalog_not_fresh:
        return "catalog_not_fresh";
    case NdmsNativeImportBaselineBuildError::catalog_not_refreshed:
        return "catalog_not_refreshed";
    case NdmsNativeImportBaselineBuildError::
            catalog_observation_missing:
        return "catalog_observation_missing";
    case NdmsNativeImportBaselineBuildError::
            observation_generation_invalid:
        return "observation_generation_invalid";
    case NdmsNativeImportBaselineBuildError::observation_epoch_mismatch:
        return "observation_epoch_mismatch";
    case NdmsNativeImportBaselineBuildError::slot_evidence_incomplete:
        return "slot_evidence_incomplete";
    case NdmsNativeImportBaselineBuildError::slot_evidence_invalid:
        return "slot_evidence_invalid";
    case NdmsNativeImportBaselineBuildError::expected_target_invalid:
        return "expected_target_invalid";
    case NdmsNativeImportBaselineBuildError::allocator_namespace_full:
        return "allocator_namespace_full";
    case NdmsNativeImportBaselineBuildError::
            first_free_target_protected:
        return "first_free_target_protected";
    case NdmsNativeImportBaselineBuildError::expected_target_occupied:
        return "expected_target_occupied";
    case NdmsNativeImportBaselineBuildError::
            expected_target_not_first_free:
        return "expected_target_not_first_free";
    case NdmsNativeImportBaselineBuildError::
            maintenance_generation_exhausted:
        return "maintenance_generation_exhausted";
    case NdmsNativeImportBaselineBuildError::
            allocator_generation_invalid:
        return "allocator_generation_invalid";
    }
    return "slot_evidence_invalid";
}

} // namespace keen_pbr3
