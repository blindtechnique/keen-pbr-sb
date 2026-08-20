#pragma once

#include "ndms_native_import_baseline.hpp"
#include "ndms_native_observation_store.hpp"
#include "ndms_native_tunnel_import.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {

constexpr std::size_t kNdmsNativeImportWalMaximumBytes =
    64U * 1024U;

class NdmsNativeImportWalError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class NdmsNativeImportWalPhase {
    prepared,
    import_may_be_inflight,
    response_recorded,
    target_verified,
    ownership_published,
    rollback_requested,
    delete_may_be_inflight,
    absence_verified,
};

// Pure, non-secret crash intent. This record is deliberately dormant: the
// codec performs no disk I/O and no caller can infer that boot recovery is
// integrated merely because this type exists.
struct NdmsNativeImportWalRecord {
    std::string transaction_id;
    NdmsNativeImportExecutionMode execution_mode{
        NdmsNativeImportExecutionMode::allocator_fenced};
    NdmsNativeImportWalPhase phase{
        NdmsNativeImportWalPhase::prepared};
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::string marker;
    std::string candidate_revision;
    // Domain-separated digest over transaction id, marker, candidate
    // revision and the baseline's exact expected target. It is recomputed by
    // the v2 parser and never substitutes for the secret request body.
    std::string request_binding_sha256;
    std::string generation_ticket;
    std::uint32_t maintenance_base_generation{0};
    NdmsNativeObservationBinding observation_binding;
    NdmsNativeImportPersistedBaseline baseline;
    std::optional<std::uint32_t> reserved_generation;
    // Digest of serialize_ndms_native_import_response_manifest_v3(). The WAL
    // never stores even the redacted free-form representation itself.
    std::optional<std::string> response_manifest_sha256;
    std::optional<std::string> created_interface;
    // Canonical revision of the encrypted panel-delete snapshot prepared
    // from the same parse as the request. It survives into ownership so a
    // later delete cannot pair a claim with another snapshot.
    std::string snapshot_revision;
    std::optional<std::string> target_full_revision;
    std::optional<std::string> ownership_revision;

    bool operator==(const NdmsNativeImportWalRecord& other) const noexcept;
};

// Shared non-secret binding primitive used by both the executor and WAL v4
// validation. This overload never accepts or retains raw configuration.
std::string ndms_native_import_request_binding_digest(
    std::string_view transaction_id,
    std::string_view marker,
    std::string_view candidate_revision,
    NdmsNativeTunnelImportKind kind,
    std::string_view expected_created_interface);

std::string serialize_ndms_native_import_wal(
    const NdmsNativeImportWalRecord& record);

NdmsNativeImportWalRecord parse_ndms_native_import_wal(
    std::string_view body);

bool valid_ndms_native_import_wal_transition(
    NdmsNativeImportWalPhase from,
    NdmsNativeImportWalPhase to) noexcept;

struct NdmsNativeImportRecoveryObservation {
    bool authoritative{false};
    bool generation_advanced{false};
    bool protected_catalog_unchanged{false};
    std::size_t marker_match_count{0U};
    std::optional<std::string> marker_target;
    bool target_absent_in_baseline{false};
    bool target_down{false};
    bool target_fingerprint_matches{false};
    bool ownership_record_matches{false};
    bool stable_absence{false};
};

enum class NdmsNativeImportRecoveryAction {
    retry_read_only_observation,
    abort_without_mutation,
    rollback_delete_exact_owned,
    resume_forward_reconcile,
    retry_exact_owned_delete,
    complete_rollback,
    block_unknown,
};

NdmsNativeImportRecoveryAction classify_ndms_native_import_recovery(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryObservation& observation) noexcept;

const char* ndms_native_import_wal_phase_name(
    NdmsNativeImportWalPhase phase) noexcept;

const char* ndms_native_import_recovery_action_name(
    NdmsNativeImportRecoveryAction action) noexcept;

} // namespace keen_pbr3
