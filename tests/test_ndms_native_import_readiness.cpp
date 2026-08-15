#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_readiness.hpp"

#include <string>
#include <utility>

using namespace keen_pbr3;

namespace {

NdmsNativeImportWalInventory valid_nonempty_inventory() {
    NdmsNativeImportWalInventory inventory;
    inventory.state = NdmsNativeImportWalInventoryState::ready;

    NdmsNativeImportWalInventoryItem item;
    item.state = NdmsNativeImportWalLoadState::valid;
    item.transaction_id = std::string(32U, 'a');
    item.record = NdmsNativeImportWalRecord{};
    inventory.items.push_back(std::move(item));
    return inventory;
}

} // namespace

TEST_CASE("native import readiness distinguishes never-activated and empty journals") {
    NdmsNativeImportWalInventory absent;
    absent.state = NdmsNativeImportWalInventoryState::absent;
    CHECK(summarize_ndms_native_import_readiness(absent) ==
          NdmsNativeImportJournalReadinessState::
              clean_never_activated);

    NdmsNativeImportWalInventory empty;
    empty.state = NdmsNativeImportWalInventoryState::ready;
    CHECK(summarize_ndms_native_import_readiness(empty) ==
          NdmsNativeImportJournalReadinessState::clean);
}

TEST_CASE("native import readiness reports every valid retained journal as recovery-required") {
    for (const auto phase : {
             NdmsNativeImportWalPhase::prepared,
             NdmsNativeImportWalPhase::import_may_be_inflight,
             NdmsNativeImportWalPhase::response_recorded,
             NdmsNativeImportWalPhase::target_verified,
             NdmsNativeImportWalPhase::ownership_published,
             NdmsNativeImportWalPhase::rollback_requested,
             NdmsNativeImportWalPhase::delete_may_be_inflight,
             NdmsNativeImportWalPhase::absence_verified,
         }) {
        auto inventory = valid_nonempty_inventory();
        inventory.items.front().record->phase = phase;
        CAPTURE(static_cast<int>(phase));
        CHECK(summarize_ndms_native_import_readiness(inventory) ==
              NdmsNativeImportJournalReadinessState::
                  recovery_required);
    }
}

TEST_CASE("native import readiness rejects incomplete or unsafe inventories") {
    auto missing_record = valid_nonempty_inventory();
    missing_record.items.front().record.reset();
    CHECK(summarize_ndms_native_import_readiness(missing_record) ==
          NdmsNativeImportJournalReadinessState::unsafe);

    auto missing_identity = valid_nonempty_inventory();
    missing_identity.items.front().transaction_id.reset();
    CHECK(summarize_ndms_native_import_readiness(missing_identity) ==
          NdmsNativeImportJournalReadinessState::unsafe);

    auto unsafe_entry = valid_nonempty_inventory();
    unsafe_entry.items.front().state =
        NdmsNativeImportWalLoadState::unsafe_entry;
    CHECK(summarize_ndms_native_import_readiness(unsafe_entry) ==
          NdmsNativeImportJournalReadinessState::unsafe);

    for (const auto state : {
             NdmsNativeImportWalInventoryState::unsafe_store,
             NdmsNativeImportWalInventoryState::directory_limit_exceeded,
             NdmsNativeImportWalInventoryState::record_limit_exceeded,
        }) {
        NdmsNativeImportWalInventory inventory;
        inventory.state = state;
        CAPTURE(static_cast<int>(state));
        CHECK(summarize_ndms_native_import_readiness(inventory) ==
              NdmsNativeImportJournalReadinessState::unsafe);
    }
}

TEST_CASE("native import readiness collapses unavailable inventory without identity data") {
    for (const auto inventory_state : {
             NdmsNativeImportWalInventoryState::busy,
             NdmsNativeImportWalInventoryState::io_error,
         }) {
        NdmsNativeImportWalInventory inventory;
        inventory.state = inventory_state;
        CAPTURE(static_cast<int>(inventory_state));
        CHECK(summarize_ndms_native_import_readiness(inventory) ==
              NdmsNativeImportJournalReadinessState::unavailable);
    }

    for (const auto state : {
             NdmsNativeImportJournalReadinessState::
                 clean_never_activated,
             NdmsNativeImportJournalReadinessState::clean,
             NdmsNativeImportJournalReadinessState::recovery_required,
             NdmsNativeImportJournalReadinessState::unsafe,
             NdmsNativeImportJournalReadinessState::unavailable,
         }) {
        const std::string name{
            ndms_native_import_journal_readiness_state_name(state)};
        CHECK_FALSE(name.empty());
        CHECK(name.find("Wireguard") == std::string::npos);
        CHECK(name.find("kpbr-ni") == std::string::npos);
    }
}
