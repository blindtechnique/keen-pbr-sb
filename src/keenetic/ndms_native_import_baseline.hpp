#pragma once

#include "ndms_catalog_cache.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

inline constexpr std::size_t
    kNdmsNativeImportOccupancyBytes = 16U;
inline constexpr std::size_t
    kNdmsNativeImportOccupancyHexCharacters =
        kNdmsNativeImportOccupancyBytes * 2U;

inline constexpr char
    kNdmsNativeImportProtectedCatalogDigestPrefix[] =
        "ndms-protected-wg-catalog-v1-";
inline constexpr char kNdmsNativeImportBaselineDigestPrefix[] =
    "ndms-native-import-baseline-v1-";

// Exported for the recovery probe builder: a live catalog must be compared
// against the baseline with the digest the baseline recorded, and two
// implementations of one digest is how they silently diverge.
std::string ndms_native_import_protected_catalog_digest(
    const NdmsInterfaceCatalog& catalog,
    std::uint8_t expected_target_slot);

enum class NdmsNativeImportBaselineBuildError : std::uint8_t {
    none,
    firmware_unavailable,
    catalog_not_fresh,
    catalog_not_refreshed,
    catalog_observation_missing,
    observation_generation_invalid,
    observation_epoch_mismatch,
    slot_evidence_incomplete,
    slot_evidence_invalid,
    expected_target_invalid,
    allocator_namespace_full,
    first_free_target_protected,
    expected_target_occupied,
    expected_target_not_first_free,
    maintenance_generation_exhausted,
    allocator_generation_invalid,
};

class NdmsNativeImportBaselineEvidence;
class NdmsNativeImportBaselineComparison;
struct NdmsNativeImportBaselineBuildResult;

// Exact bounded representation allowed to cross the durable WAL boundary.
// It contains no raw RCI object, label, endpoint or WireGuard configuration.
// Aggregate instances are untrusted until strict validation. The executor
// obtains its value only by projecting immutable Evidence; the WAL parser
// revalidates every field and recomputes baseline_sha256 on load.
struct NdmsNativeImportPersistedBaseline final {
    std::string expected_created_interface;
    std::uint8_t expected_target_slot{0U};
    std::string occupancy_hex;
    std::string protected_catalog_sha256;
    std::uint64_t observation_generation{0U};
    std::uint64_t observation_epoch{0U};
    std::uint64_t invalidation_epoch{0U};
    std::uint32_t maintenance_base_generation{0U};
    std::uint64_t allocator_generation{0U};
    std::string baseline_sha256;

    bool operator==(
        const NdmsNativeImportPersistedBaseline& other) const noexcept;
};

NdmsNativeImportBaselineBuildResult build_ndms_native_import_baseline(
    const NdmsCatalogSnapshot& snapshot,
    std::string_view expected_created_interface,
    std::uint32_t maintenance_base_generation,
    std::uint64_t allocator_generation);

// Immutable, bounded and non-secret evidence captured before an import. Raw
// RCI ids, labels, endpoint material and per-slot revisions are deliberately
// absent. Observation counters bind one accepted in-process catalog snapshot;
// they are provenance, not a clock that may be compared across restarts.
class NdmsNativeImportBaselineEvidence final {
public:
    NdmsNativeImportBaselineEvidence(
        const NdmsNativeImportBaselineEvidence&) = default;
    NdmsNativeImportBaselineEvidence(
        NdmsNativeImportBaselineEvidence&&) noexcept = default;
    NdmsNativeImportBaselineEvidence& operator=(
        const NdmsNativeImportBaselineEvidence&) = delete;
    NdmsNativeImportBaselineEvidence& operator=(
        NdmsNativeImportBaselineEvidence&&) = delete;

    const std::string& expected_created_interface() const noexcept;
    std::uint8_t expected_target_slot() const noexcept;
    const std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes>&
    occupancy() const noexcept;
    const std::string& occupancy_hex() const noexcept;
    const std::string& protected_catalog_sha256() const noexcept;
    std::uint64_t observation_generation() const noexcept;
    std::uint64_t observation_epoch() const noexcept;
    std::uint64_t invalidation_epoch() const noexcept;
    std::uint32_t maintenance_base_generation() const noexcept;
    std::uint64_t allocator_generation() const noexcept;
    const std::string& baseline_sha256() const noexcept;

private:
    friend NdmsNativeImportBaselineBuildResult
    build_ndms_native_import_baseline(
        const NdmsCatalogSnapshot&,
        std::string_view,
        std::uint32_t,
        std::uint64_t);
    friend class NdmsNativeImportBaselineComparison;
    friend NdmsNativeImportBaselineComparison
    compare_ndms_native_import_baseline(
        const NdmsNativeImportBaselineEvidence&,
        const NdmsCatalogSnapshot&);

    NdmsNativeImportBaselineEvidence(
        std::string expected_created_interface,
        std::uint8_t expected_target_slot,
        std::array<
            std::uint8_t,
            kNdmsNativeImportOccupancyBytes> occupancy,
        std::string occupancy_hex,
        std::string protected_catalog_sha256,
        std::uint64_t observation_generation,
        std::uint64_t observation_epoch,
        std::uint64_t invalidation_epoch,
        std::uint32_t maintenance_base_generation,
        std::uint64_t allocator_generation,
        std::string baseline_sha256);

    std::string expected_created_interface_;
    std::uint8_t expected_target_slot_{0U};
    std::array<
        std::uint8_t,
        kNdmsNativeImportOccupancyBytes> occupancy_{};
    std::string occupancy_hex_;
    std::string protected_catalog_sha256_;
    std::uint64_t observation_generation_{0U};
    std::uint64_t observation_epoch_{0U};
    std::uint64_t invalidation_epoch_{0U};
    std::uint32_t maintenance_base_generation_{0U};
    std::uint64_t allocator_generation_{0U};
    std::string baseline_sha256_;
};

struct NdmsNativeImportBaselineBuildResult final {
    NdmsNativeImportBaselineBuildError error{
        NdmsNativeImportBaselineBuildError::firmware_unavailable};
    std::optional<NdmsNativeImportBaselineEvidence> evidence;

    bool success() const noexcept {
        return error == NdmsNativeImportBaselineBuildError::none &&
               evidence.has_value();
    }
};

// Redacted facts derived only by compare_ndms_native_import_baseline(). There
// is no public constructor and no caller-provided equality/absence boolean.
class NdmsNativeImportBaselineComparison final {
public:
    NdmsNativeImportBaselineComparison(
        const NdmsNativeImportBaselineComparison&) = default;
    NdmsNativeImportBaselineComparison(
        NdmsNativeImportBaselineComparison&&) noexcept = default;
    NdmsNativeImportBaselineComparison& operator=(
        const NdmsNativeImportBaselineComparison&) = delete;
    NdmsNativeImportBaselineComparison& operator=(
        NdmsNativeImportBaselineComparison&&) = delete;

    bool current_catalog_authoritative() const noexcept;
    bool target_absent_in_baseline() const noexcept;
    bool protected_catalog_unchanged() const noexcept;

private:
    friend NdmsNativeImportBaselineComparison
    compare_ndms_native_import_baseline(
        const NdmsNativeImportBaselineEvidence&,
        const NdmsCatalogSnapshot&);
    friend NdmsNativeImportBaselineComparison
    compare_ndms_native_import_baseline(
        const NdmsNativeImportPersistedBaseline&,
        const NdmsCatalogSnapshot&);

    NdmsNativeImportBaselineComparison(
        bool current_catalog_authoritative,
        bool target_absent_in_baseline,
        bool protected_catalog_unchanged) noexcept;

    bool current_catalog_authoritative_{false};
    bool target_absent_in_baseline_{false};
    bool protected_catalog_unchanged_{false};
};

NdmsNativeImportBaselineComparison
compare_ndms_native_import_baseline(
    const NdmsNativeImportBaselineEvidence& baseline,
    const NdmsCatalogSnapshot& current);

// Restart-safe pure comparison. Invalid persisted evidence produces only
// false facts; it is never reconstructed into authoritative Evidence.
NdmsNativeImportBaselineComparison
compare_ndms_native_import_baseline(
    const NdmsNativeImportPersistedBaseline& baseline,
    const NdmsCatalogSnapshot& current);

NdmsNativeImportPersistedBaseline persist_ndms_native_import_baseline(
    const NdmsNativeImportBaselineEvidence& baseline);

// Validates the exact v1 baseline digest framing and all allocator invariants:
// the target is managed, absent, byte-for-byte equal to its slot, and the
// first free slot in Wireguard0..126. This is intentionally usable by the WAL
// parser without reconstructing authoritative in-memory evidence.
bool valid_ndms_native_import_persisted_baseline(
    const NdmsNativeImportPersistedBaseline& baseline) noexcept;

const char* ndms_native_import_baseline_build_error_name(
    NdmsNativeImportBaselineBuildError error) noexcept;

} // namespace keen_pbr3
