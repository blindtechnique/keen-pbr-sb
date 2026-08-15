#include "ndms_native_import_startup_recovery.hpp"

#include "ndms_native_import_identity.hpp"

#include <algorithm>
#include <utility>

namespace keen_pbr3 {
namespace {

NdmsNativeImportStartupRecoveryBlocker inventory_blocker(
    const NdmsNativeImportWalInventoryState state) noexcept {
    switch (state) {
    case NdmsNativeImportWalInventoryState::absent:
        return NdmsNativeImportStartupRecoveryBlocker::inventory_absent;
    case NdmsNativeImportWalInventoryState::unsafe_store:
        return NdmsNativeImportStartupRecoveryBlocker::
            inventory_unsafe_store;
    case NdmsNativeImportWalInventoryState::io_error:
        return NdmsNativeImportStartupRecoveryBlocker::
            inventory_io_error;
    case NdmsNativeImportWalInventoryState::busy:
        return NdmsNativeImportStartupRecoveryBlocker::
            inventory_lock_busy;
    case NdmsNativeImportWalInventoryState::directory_limit_exceeded:
        return NdmsNativeImportStartupRecoveryBlocker::
            inventory_directory_limit_exceeded;
    case NdmsNativeImportWalInventoryState::record_limit_exceeded:
        return NdmsNativeImportStartupRecoveryBlocker::
            inventory_record_limit_exceeded;
    case NdmsNativeImportWalInventoryState::ready:
        return NdmsNativeImportStartupRecoveryBlocker::
            inventory_entry_invalid;
    }
    return NdmsNativeImportStartupRecoveryBlocker::inventory_io_error;
}

bool observations_have_invalid_identity(
    const std::vector<NdmsNativeImportStartupRecoveryObservation>&
        observations) noexcept {
    return std::any_of(
        observations.begin(), observations.end(), [](const auto& item) {
            return !valid_ndms_native_import_transaction_id(
                item.transaction_id);
        });
}

std::optional<std::string> duplicate_observation_identity(
    const std::vector<NdmsNativeImportStartupRecoveryObservation>&
        observations) {
    for (std::size_t left = 0U; left < observations.size(); ++left) {
        for (std::size_t right = left + 1U;
             right < observations.size(); ++right) {
            if (observations[left].transaction_id ==
                observations[right].transaction_id) {
                return observations[left].transaction_id;
            }
        }
    }
    return std::nullopt;
}

} // namespace

NdmsNativeImportStartupRecoveryBlockerSummary::
    NdmsNativeImportStartupRecoveryBlockerSummary(
        const NdmsNativeImportStartupRecoveryBlocker blocker,
        std::optional<std::string> transaction_id)
    : blocker_(blocker),
      transaction_id_(std::move(transaction_id)) {}

NdmsNativeImportStartupRecoveryBlocker
NdmsNativeImportStartupRecoveryBlockerSummary::blocker() const noexcept {
    return blocker_;
}

const std::optional<std::string>&
NdmsNativeImportStartupRecoveryBlockerSummary::transaction_id()
    const noexcept {
    return transaction_id_;
}

NdmsNativeImportStartupRecoveryItemSummary::
    NdmsNativeImportStartupRecoveryItemSummary(
        std::string transaction_id,
        const NdmsNativeImportWalPhase phase,
        const NdmsNativeImportRecoveryAction action,
        const bool observation_authoritative)
    : transaction_id_(std::move(transaction_id)),
      phase_(phase),
      action_(action),
      observation_authoritative_(observation_authoritative) {}

const std::string&
NdmsNativeImportStartupRecoveryItemSummary::transaction_id()
    const noexcept {
    return transaction_id_;
}

NdmsNativeImportWalPhase
NdmsNativeImportStartupRecoveryItemSummary::phase() const noexcept {
    return phase_;
}

NdmsNativeImportRecoveryAction
NdmsNativeImportStartupRecoveryItemSummary::action() const noexcept {
    return action_;
}

bool NdmsNativeImportStartupRecoveryItemSummary::
    observation_authoritative() const noexcept {
    return observation_authoritative_;
}

bool NdmsNativeImportStartupRecoveryItemSummary::action_dispatched()
    const noexcept {
    return false;
}

NdmsNativeImportStartupRecoveryDisposition
NdmsNativeImportStartupRecoverySummary::disposition() const noexcept {
    return disposition_;
}

NdmsNativeImportWalInventoryState
NdmsNativeImportStartupRecoverySummary::inventory_state() const noexcept {
    return inventory_state_;
}

std::size_t NdmsNativeImportStartupRecoverySummary::wal_record_count()
    const noexcept {
    return wal_record_count_;
}

std::size_t
NdmsNativeImportStartupRecoverySummary::supplied_observation_count()
    const noexcept {
    return supplied_observation_count_;
}

const std::vector<NdmsNativeImportStartupRecoveryItemSummary>&
NdmsNativeImportStartupRecoverySummary::items() const noexcept {
    return items_;
}

const std::vector<NdmsNativeImportStartupRecoveryBlockerSummary>&
NdmsNativeImportStartupRecoverySummary::blockers() const noexcept {
    return blockers_;
}

bool NdmsNativeImportStartupRecoverySummary::side_effects_dispatched()
    const noexcept {
    return false;
}

bool NdmsNativeImportStartupRecoverySummary::retry_dispatched()
    const noexcept {
    return false;
}

void NdmsNativeImportStartupRecoverySummary::add_blocker(
    const NdmsNativeImportStartupRecoveryBlocker blocker,
    std::optional<std::string> transaction_id) {
    blockers_.push_back(
        NdmsNativeImportStartupRecoveryBlockerSummary(
            blocker, std::move(transaction_id)));
}

void NdmsNativeImportStartupRecoverySummary::add_item(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryAction action,
    const bool observation_authoritative) {
    items_.push_back(NdmsNativeImportStartupRecoveryItemSummary(
        record.transaction_id,
        record.phase,
        action,
        observation_authoritative));
}

NdmsNativeImportStartupRecoverySummary
scan_ndms_native_import_startup_recovery(
    const NdmsNativeImportWalStore& store,
    const std::vector<NdmsNativeImportStartupRecoveryObservation>&
        observations) {
    NdmsNativeImportStartupRecoverySummary summary;
    summary.supplied_observation_count_ = observations.size();

    // Exactly one bounded snapshot. No per-record load follows this call: a
    // second unlocked read would create a misleading mixed-time report.
    const auto inventory = store.try_inventory();
    summary.inventory_state_ = inventory.state;
    summary.wal_record_count_ = inventory.items.size();

    if (inventory.state != NdmsNativeImportWalInventoryState::ready) {
        summary.add_blocker(inventory_blocker(inventory.state));
        return summary;
    }
    if (!inventory.recovery_permitted()) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                inventory_entry_invalid);
        return summary;
    }
    if (inventory.items.size() > 1U) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                multiple_unfinished_transactions);
        return summary;
    }
    if (observations.size() >
        kNdmsNativeImportStartupRecoveryMaximumObservations) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                observation_limit_exceeded);
        return summary;
    }
    if (observations_have_invalid_identity(observations)) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                observation_identity_invalid);
        return summary;
    }
    if (const auto duplicate =
            duplicate_observation_identity(observations)) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                observation_duplicate,
            duplicate);
        return summary;
    }

    if (inventory.items.empty()) {
        if (!observations.empty()) {
            summary.add_blocker(
                NdmsNativeImportStartupRecoveryBlocker::
                    observation_extra,
                observations.front().transaction_id);
            return summary;
        }
        summary.disposition_ =
            NdmsNativeImportStartupRecoveryDisposition::clean;
        return summary;
    }

    const auto& inventory_item = inventory.items.front();
    // recovery_permitted() already proves these optionals exist. Recheck the
    // cross-field identity instead of trusting a future store implementation.
    if (!inventory_item.transaction_id.has_value() ||
        !inventory_item.record.has_value() ||
        inventory_item.record->transaction_id !=
            *inventory_item.transaction_id) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                inventory_entry_invalid);
        return summary;
    }
    const std::string& transaction_id =
        *inventory_item.transaction_id;

    const auto match = std::find_if(
        observations.begin(), observations.end(),
        [&transaction_id](const auto& item) {
            return item.transaction_id == transaction_id;
        });
    if (match == observations.end()) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                observation_missing,
            transaction_id);
        if (!observations.empty()) {
            summary.add_blocker(
                NdmsNativeImportStartupRecoveryBlocker::
                    observation_extra,
                observations.front().transaction_id);
        }
        return summary;
    }
    if (observations.size() != 1U) {
        const auto extra = std::find_if(
            observations.begin(), observations.end(),
            [&transaction_id](const auto& item) {
                return item.transaction_id != transaction_id;
            });
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::observation_extra,
            extra == observations.end()
                ? std::optional<std::string>{}
                : std::optional<std::string>{extra->transaction_id});
        return summary;
    }

    const auto action = classify_ndms_native_import_recovery(
        *inventory_item.record, match->observation);
    summary.add_item(
        *inventory_item.record,
        action,
        match->observation.authoritative);

    if (!match->observation.authoritative) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                observation_not_authoritative,
            transaction_id);
        return summary;
    }
    if (action == NdmsNativeImportRecoveryAction::block_unknown) {
        summary.add_blocker(
            NdmsNativeImportStartupRecoveryBlocker::
                classifier_blocked_unknown,
            transaction_id);
        return summary;
    }

    summary.disposition_ =
        NdmsNativeImportStartupRecoveryDisposition::
            classified_report_only;
    summary.add_blocker(
        NdmsNativeImportStartupRecoveryBlocker::
            classified_action_not_dispatched,
        transaction_id);
    return summary;
}

const char* ndms_native_import_startup_recovery_disposition_name(
    const NdmsNativeImportStartupRecoveryDisposition disposition) noexcept {
    switch (disposition) {
    case NdmsNativeImportStartupRecoveryDisposition::clean:
        return "clean";
    case NdmsNativeImportStartupRecoveryDisposition::
        classified_report_only:
        return "classified_report_only";
    case NdmsNativeImportStartupRecoveryDisposition::block_unknown:
        return "block_unknown";
    }
    return "unknown";
}

const char* ndms_native_import_startup_recovery_blocker_name(
    const NdmsNativeImportStartupRecoveryBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeImportStartupRecoveryBlocker::inventory_absent:
        return "inventory_absent";
    case NdmsNativeImportStartupRecoveryBlocker::inventory_unsafe_store:
        return "inventory_unsafe_store";
    case NdmsNativeImportStartupRecoveryBlocker::inventory_io_error:
        return "inventory_io_error";
    case NdmsNativeImportStartupRecoveryBlocker::inventory_lock_busy:
        return "inventory_lock_busy";
    case NdmsNativeImportStartupRecoveryBlocker::
        inventory_directory_limit_exceeded:
        return "inventory_directory_limit_exceeded";
    case NdmsNativeImportStartupRecoveryBlocker::
        inventory_record_limit_exceeded:
        return "inventory_record_limit_exceeded";
    case NdmsNativeImportStartupRecoveryBlocker::
        inventory_entry_invalid:
        return "inventory_entry_invalid";
    case NdmsNativeImportStartupRecoveryBlocker::
        multiple_unfinished_transactions:
        return "multiple_unfinished_transactions";
    case NdmsNativeImportStartupRecoveryBlocker::
        observation_limit_exceeded:
        return "observation_limit_exceeded";
    case NdmsNativeImportStartupRecoveryBlocker::
        observation_identity_invalid:
        return "observation_identity_invalid";
    case NdmsNativeImportStartupRecoveryBlocker::observation_duplicate:
        return "observation_duplicate";
    case NdmsNativeImportStartupRecoveryBlocker::observation_missing:
        return "observation_missing";
    case NdmsNativeImportStartupRecoveryBlocker::observation_extra:
        return "observation_extra";
    case NdmsNativeImportStartupRecoveryBlocker::
        observation_not_authoritative:
        return "observation_not_authoritative";
    case NdmsNativeImportStartupRecoveryBlocker::
        classifier_blocked_unknown:
        return "classifier_blocked_unknown";
    case NdmsNativeImportStartupRecoveryBlocker::
        classified_action_not_dispatched:
        return "classified_action_not_dispatched";
    }
    return "unknown";
}

} // namespace keen_pbr3
