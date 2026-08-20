#pragma once

#include "ndms_native_import_wal.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {

inline constexpr std::uint32_t kNdmsNativeDeleteWalSchemaVersion = 2U;
inline constexpr std::size_t kNdmsNativeDeleteWalMaximumBytes =
    64U * 1024U;
inline constexpr std::string_view kNdmsNativeDeleteDependencyRevisionPrefix{
    "ndms-native-delete-deps-v1-"};
inline constexpr std::string_view kNdmsNativeOwnershipTombstoneRevisionPrefix{
    "ndms-native-owner-tombstone-v1-"};

enum class NdmsNativeDeleteWalPhase : std::uint8_t {
    prepared,
    delete_may_be_inflight,
    running_absence_verified,
    save_may_be_inflight,
    save_acknowledged_unverified,
    cleanup,
};

// One ordered pair of direct observations. Runtime state is deliberately read
// and durably sequenced before running configuration. The pair proves only
// what those two live endpoints returned; it does not prove startup/saved
// configuration and is never presented as a whole-configuration CAS receipt.
struct NdmsNativeDeleteObservationPair final {
    std::string runtime_catalog_revision;
    std::uint64_t runtime_sequence{0U};
    std::string running_config_catalog_revision;
    std::uint64_t running_config_sequence{0U};

    bool operator==(
        const NdmsNativeDeleteObservationPair& other) const noexcept;
};

// Non-secret, restart-safe record for one exact panel-owned delete. The fixed
// store admits at most one record, so target names are evidence rather than
// filenames and an unfinished transaction cannot be hidden by selecting a
// different interface.
struct NdmsNativeDeleteWalRecord final {
    std::uint32_t schema_version{kNdmsNativeDeleteWalSchemaVersion};
    std::string transaction_id;
    NdmsNativeDeleteWalPhase phase{NdmsNativeDeleteWalPhase::prepared};
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};

    // Exact active ownership claim (legacy v2 or current v3) and encrypted
    // snapshot binding.
    std::string ownership_revision;
    std::string ownership_transaction_id;
    std::string marker;
    std::string snapshot_revision;
    std::string target_full_revision;

    // Complete typed dependency scan observed empty before admission.
    std::string keen_pbr_dependency_revision;
    // Kernel name admitted by that scan, when direct runtime observation had
    // one. It is immutable recovery evidence, not a new lookup hint.
    std::optional<std::string> kernel_interface_name;

    // Durable pre-mutation observations and the epoch they admitted.
    NdmsNativeDeleteObservationPair preflight_observations;
    NdmsNativeObservationBinding observation_binding;

    // Both acknowledgements are explicit owner decisions, never inferred.
    bool owner_global_save_acknowledged{false};
    bool external_writer_race_accepted{false};

    std::optional<NdmsNativeDeleteObservationPair>
        delete_absence_observations;
    std::optional<NdmsNativeDeleteObservationPair>
        post_save_absence_observations;
    std::optional<std::string> tombstone_revision;
    std::string integrity;

    bool operator==(
        const NdmsNativeDeleteWalRecord& other) const noexcept;
};

class NdmsNativeDeleteWalError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

bool valid_ndms_native_delete_observation_pair(
    const NdmsNativeDeleteObservationPair& pair) noexcept;
bool valid_ndms_native_delete_wal_record(
    const NdmsNativeDeleteWalRecord& record) noexcept;
bool valid_ndms_native_delete_wal_transition(
    NdmsNativeDeleteWalPhase before,
    NdmsNativeDeleteWalPhase after) noexcept;

std::string ndms_native_delete_wal_integrity(
    const NdmsNativeDeleteWalRecord& record);
std::string serialize_ndms_native_delete_wal(
    const NdmsNativeDeleteWalRecord& record);
NdmsNativeDeleteWalRecord parse_ndms_native_delete_wal(
    std::string_view serialized);

const char* ndms_native_delete_wal_phase_name(
    NdmsNativeDeleteWalPhase phase) noexcept;

} // namespace keen_pbr3
