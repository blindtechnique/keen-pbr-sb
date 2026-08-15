#pragma once

#include "ndms_native_import_wal_store.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The startup core accepts at most the same number of observations as the
// hardened WAL store can contain. The current transaction admission contract
// is stricter still: more than one valid WAL record blocks globally.
constexpr std::size_t
    kNdmsNativeImportStartupRecoveryMaximumObservations =
        kNdmsNativeImportWalStoreMaximumRecords;

// A caller must provide one typed observation for the exact transaction found
// in the WAL inventory. The core never fills missing catalog, generation,
// baseline, ownership or stability evidence from defaults or heuristics.
struct NdmsNativeImportStartupRecoveryObservation final {
    std::string transaction_id;
    NdmsNativeImportRecoveryObservation observation;
};

enum class NdmsNativeImportStartupRecoveryDisposition {
    // The store exists, its complete inventory is safe, and it is empty.
    clean,
    // One record and one authoritative observation were classified. The
    // reported action was deliberately not dispatched.
    classified_report_only,
    // Recovery cannot be classified safely from this bounded snapshot.
    block_unknown,
};

enum class NdmsNativeImportStartupRecoveryBlocker {
    inventory_absent,
    inventory_unsafe_store,
    inventory_io_error,
    inventory_lock_busy,
    inventory_directory_limit_exceeded,
    inventory_record_limit_exceeded,
    inventory_entry_invalid,
    multiple_unfinished_transactions,
    observation_limit_exceeded,
    observation_identity_invalid,
    observation_duplicate,
    observation_missing,
    observation_extra,
    observation_not_authoritative,
    classifier_blocked_unknown,
    classified_action_not_dispatched,
};

// Immutable, non-secret blocker. A transaction id is included only after it
// passed the canonical lower-hex identity check. Filenames, marker text,
// interface names, revisions and observation details are never exposed.
class NdmsNativeImportStartupRecoveryBlockerSummary final {
public:
    NdmsNativeImportStartupRecoveryBlockerSummary(
        const NdmsNativeImportStartupRecoveryBlockerSummary&) = default;
    NdmsNativeImportStartupRecoveryBlockerSummary(
        NdmsNativeImportStartupRecoveryBlockerSummary&&) noexcept = default;
    NdmsNativeImportStartupRecoveryBlockerSummary& operator=(
        const NdmsNativeImportStartupRecoveryBlockerSummary&) = delete;
    NdmsNativeImportStartupRecoveryBlockerSummary& operator=(
        NdmsNativeImportStartupRecoveryBlockerSummary&&) = delete;

    NdmsNativeImportStartupRecoveryBlocker blocker() const noexcept;
    const std::optional<std::string>& transaction_id() const noexcept;

private:
    friend class NdmsNativeImportStartupRecoverySummary;

    NdmsNativeImportStartupRecoveryBlockerSummary(
        NdmsNativeImportStartupRecoveryBlocker blocker,
        std::optional<std::string> transaction_id);

    NdmsNativeImportStartupRecoveryBlocker blocker_;
    std::optional<std::string> transaction_id_;
};

// Immutable report for the only WAL record that was actually classified.
// The core deliberately omits all record and observation evidence except the
// safe identity, phase and classifier action.
class NdmsNativeImportStartupRecoveryItemSummary final {
public:
    NdmsNativeImportStartupRecoveryItemSummary(
        const NdmsNativeImportStartupRecoveryItemSummary&) = default;
    NdmsNativeImportStartupRecoveryItemSummary(
        NdmsNativeImportStartupRecoveryItemSummary&&) noexcept = default;
    NdmsNativeImportStartupRecoveryItemSummary& operator=(
        const NdmsNativeImportStartupRecoveryItemSummary&) = delete;
    NdmsNativeImportStartupRecoveryItemSummary& operator=(
        NdmsNativeImportStartupRecoveryItemSummary&&) = delete;

    const std::string& transaction_id() const noexcept;
    NdmsNativeImportWalPhase phase() const noexcept;
    NdmsNativeImportRecoveryAction action() const noexcept;
    bool observation_authoritative() const noexcept;
    bool action_dispatched() const noexcept;

private:
    friend class NdmsNativeImportStartupRecoverySummary;

    NdmsNativeImportStartupRecoveryItemSummary(
        std::string transaction_id,
        NdmsNativeImportWalPhase phase,
        NdmsNativeImportRecoveryAction action,
        bool observation_authoritative);

    std::string transaction_id_;
    NdmsNativeImportWalPhase phase_;
    NdmsNativeImportRecoveryAction action_;
    bool observation_authoritative_{false};
};

// An immutable snapshot. It is never an authority token for a later writer:
// every reported action must be revalidated by a future mutation coordinator.
class NdmsNativeImportStartupRecoverySummary final {
public:
    NdmsNativeImportStartupRecoverySummary(
        const NdmsNativeImportStartupRecoverySummary&) = default;
    NdmsNativeImportStartupRecoverySummary(
        NdmsNativeImportStartupRecoverySummary&&) noexcept = default;
    NdmsNativeImportStartupRecoverySummary& operator=(
        const NdmsNativeImportStartupRecoverySummary&) = delete;
    NdmsNativeImportStartupRecoverySummary& operator=(
        NdmsNativeImportStartupRecoverySummary&&) = delete;

    NdmsNativeImportStartupRecoveryDisposition disposition() const noexcept;
    NdmsNativeImportWalInventoryState inventory_state() const noexcept;
    std::size_t wal_record_count() const noexcept;
    std::size_t supplied_observation_count() const noexcept;
    const std::vector<NdmsNativeImportStartupRecoveryItemSummary>&
    items() const noexcept;
    const std::vector<NdmsNativeImportStartupRecoveryBlockerSummary>&
    blockers() const noexcept;

    // This core has no RCI transport, WAL-removal or retry dependency. These
    // fixed false values make that boundary explicit to every consumer.
    bool side_effects_dispatched() const noexcept;
    bool retry_dispatched() const noexcept;

private:
    friend NdmsNativeImportStartupRecoverySummary
    scan_ndms_native_import_startup_recovery(
        const NdmsNativeImportWalStore&,
        const std::vector<
            NdmsNativeImportStartupRecoveryObservation>&);

    NdmsNativeImportStartupRecoverySummary() = default;

    void add_blocker(
        NdmsNativeImportStartupRecoveryBlocker blocker,
        std::optional<std::string> transaction_id = std::nullopt);
    void add_item(
        const NdmsNativeImportWalRecord& record,
        NdmsNativeImportRecoveryAction action,
        bool observation_authoritative);

    NdmsNativeImportStartupRecoveryDisposition disposition_{
        NdmsNativeImportStartupRecoveryDisposition::block_unknown};
    NdmsNativeImportWalInventoryState inventory_state_{
        NdmsNativeImportWalInventoryState::io_error};
    std::size_t wal_record_count_{0U};
    std::size_t supplied_observation_count_{0U};
    std::vector<NdmsNativeImportStartupRecoveryItemSummary> items_;
    std::vector<NdmsNativeImportStartupRecoveryBlockerSummary> blockers_;
};

// Takes exactly one bounded WAL inventory snapshot. It performs no RCI call,
// no observation retry, no WAL removal and no recovery action. Missing,
// duplicate or extra observations, any non-ready inventory and multiple valid
// records all produce a global block_unknown report before classification.
NdmsNativeImportStartupRecoverySummary
scan_ndms_native_import_startup_recovery(
    const NdmsNativeImportWalStore& store,
    const std::vector<NdmsNativeImportStartupRecoveryObservation>&
        observations);

const char* ndms_native_import_startup_recovery_disposition_name(
    NdmsNativeImportStartupRecoveryDisposition disposition) noexcept;
const char* ndms_native_import_startup_recovery_blocker_name(
    NdmsNativeImportStartupRecoveryBlocker blocker) noexcept;

} // namespace keen_pbr3
