#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_recovery_dispatch.hpp"

#include "../src/keenetic/ndms_catalog_cache.hpp"
#include "../src/keenetic/ndms_interface_inventory.hpp"
#include "../src/keenetic/ndms_native_ownership_store.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-nir-disp-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
        fs::remove(fs::path(path.string() + ".recovery-lock"), error);
    }

    fs::path path;
};

NdmsNativeImportPersistedBaseline dispatch_baseline() {
    auto payload = nlohmann::json::object();
    for (const std::uint8_t slot : {0U, 1U, 2U, 3U, 4U, 6U}) {
        const auto name = "Wireguard" + std::to_string(slot);
        payload[name] = {
            {"type", "Bridge"},
            {"interface-name", name},
            {"description", "occupied-slot"},
        };
    }
    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(payload);
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    snapshot.observed_at = std::chrono::steady_clock::time_point{
        std::chrono::seconds{123}};
    snapshot.observation_generation = 7U;
    snapshot.observation_epoch = 3U;
    snapshot.invalidation_epoch = 3U;
    auto built = build_ndms_native_import_baseline(
        snapshot, "Wireguard5", 41U, 17U);
    REQUIRE(built.success());
    REQUIRE(built.evidence.has_value());
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord prepared_record() {
    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        "ndms-native-import-v1-" + std::string(64U, 'b');
    record.snapshot_revision = record.candidate_revision;
    record.observation_binding = {std::string(32U, 'd'), 9U, 7U};
    record.baseline = dispatch_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.kind,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        "ndms-create-ticket-v1-" + std::string(64U, 'c');
    record.maintenance_base_generation = 41U;
    return record;
}

NdmsNativeImportWalRecord inflight_record() {
    auto record = prepared_record();
    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    record.reserved_generation = 42U;
    return record;
}

NdmsNativeImportWalStore store_for(const TempDirectory& directory) {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return NdmsNativeImportWalStore(directory.path, hooks);
}

NdmsNativeImportRecoveryObservation absent_observation() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.stable_absence = true;
    return observation;
}

NdmsNativeImportRecoveryObservation owned_target_observation() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.marker_match_count = 1U;
    observation.marker_target = "Wireguard5";
    observation.target_absent_in_baseline = true;
    observation.target_down = true;
    observation.target_fingerprint_matches = true;
    return observation;
}

class FakeSnapshotRetirer final
    : public NdmsNativeImportSnapshotRetirer {
public:
    bool remove_if_present_exact(
        const std::string& expected_interface,
        const std::string& transaction_id,
        const std::string& marker,
        const std::string& snapshot_revision) override {
        ++calls;
        interface = expected_interface;
        transaction = transaction_id;
        ownership_marker = marker;
        revision = snapshot_revision;
        return succeeds;
    }

    bool succeeds{true};
    std::size_t calls{0U};
    std::string interface;
    std::string transaction;
    std::string ownership_marker;
    std::string revision;
};

} // namespace

TEST_CASE("an aborted transaction dispatches to an empty, admissible store") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    auto admission = admit_ndms_native_import_recovery(
        store, record, absent_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    FakeSnapshotRetirer snapshots;

    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt, nullptr,
        nullptr, nullptr, &snapshots);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::completed);
    CHECK(result.completed_steps == 1U);
    CHECK(snapshots.calls == 1U);
    CHECK(snapshots.interface == "Wireguard5");
    CHECK(snapshots.transaction == record.transaction_id);
    CHECK(snapshots.ownership_marker == record.marker);
    CHECK(snapshots.revision == record.snapshot_revision);

    // The store is empty and admits the next transaction: the whole point of
    // finishing a recovery.
    CHECK(store.publish_prepared_exclusive(prepared_record()) ==
          NdmsNativeImportWalAdmissionState::admitted);
}

TEST_CASE("prepared recovery cannot orphan or ignore a rollback snapshot") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);
    auto admission = admit_ndms_native_import_recovery(
        store, record, absent_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    const auto missing = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt, nullptr);
    CHECK(missing.state == NdmsNativeImportRecoveryDispatchState::
                               snapshot_retirer_missing);
    CHECK(missing.completed_steps == 0U);

    FakeSnapshotRetirer snapshots;
    snapshots.succeeds = false;
    const auto refused = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt, nullptr,
        nullptr, nullptr, &snapshots);
    CHECK(refused.state ==
          NdmsNativeImportRecoveryDispatchState::step_failed);
    REQUIRE(refused.failed_step.has_value());
    CHECK(*refused.failed_step ==
          NdmsNativeImportRecoveryStep::remove_wal_record);
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::valid);
}

TEST_CASE("a rollback publishes intent, deletes under it, and finishes") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    REQUIRE(*admission.action ==
            NdmsNativeImportRecoveryAction::rollback_delete_exact_owned);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    std::size_t deletes = 0U;
    NdmsNativeImportWalPhase phase_at_delete{};
    FakeSnapshotRetirer snapshots;
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [&](const std::string& target, const std::string& marker) {
            ++deletes;
            CHECK(target == "Wireguard5");
            CHECK(marker == record.marker);
            // The intent is durable before the delete runs: a crash right
            // here must recover as a retried delete, not as a deletion nobody
            // recorded the reason for.
            const auto loaded = store.load(record.transaction_id);
            REQUIRE(loaded.recovery_permitted());
            phase_at_delete = loaded.record->phase;
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        }, nullptr, nullptr, &snapshots);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::completed);
    CHECK(result.completed_steps == 6U);
    CHECK(deletes == 1U);
    CHECK(phase_at_delete ==
          NdmsNativeImportWalPhase::delete_may_be_inflight);
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
    CHECK(snapshots.calls == 1U);
}

TEST_CASE("a failed delete leaves the durable account of how far this got") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    FakeSnapshotRetirer snapshots;

    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::failed;
        }, nullptr, nullptr, &snapshots);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::step_failed);
    REQUIRE(result.failed_step.has_value());
    CHECK(*result.failed_step ==
          NdmsNativeImportRecoveryStep::delete_exact_owned_target);
    CHECK(result.completed_steps == 3U);

    // Nothing unwound: the record still says delete_may_be_inflight, which is
    // exactly what the next recovery pass classifies from.
    const auto loaded = store.load(record.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    CHECK(loaded.record->phase ==
          NdmsNativeImportWalPhase::delete_may_be_inflight);
}

TEST_CASE("the dispatcher refuses before the first step, loudly") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    const auto no_executor = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5", nullptr);
    CHECK(no_executor.state ==
          NdmsNativeImportRecoveryDispatchState::target_missing);

    const auto no_target = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt,
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(no_target.state ==
          NdmsNativeImportRecoveryDispatchState::target_missing);

    // A protected name reaching this far is refused by the last line of
    // defence, however it got past the earlier ones.
    const auto protected_slot = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard0",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(protected_slot.state ==
          NdmsNativeImportRecoveryDispatchState::target_not_eligible);

    NdmsNativeImportRecoveryLease released_lease =
        std::move(admission.lease);
    { const auto discard = std::move(released_lease); (void)discard; }
    const auto no_lease = dispatch_ndms_native_import_recovery(
        store, released_lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(no_lease.state ==
          NdmsNativeImportRecoveryDispatchState::lease_not_held);

    // Every refusal above left the record untouched.
    const auto loaded = store.load(record.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    CHECK(loaded.record->phase ==
          NdmsNativeImportWalPhase::import_may_be_inflight);
}

namespace {

// The record a crash between publish_ownership and
// advance_wal_ownership_published leaves behind: target_verified on disk,
// claim already durable.
NdmsNativeImportWalRecord verified_record() {
    auto record = inflight_record();
    record.phase = NdmsNativeImportWalPhase::target_verified;
    record.response_manifest_sha256 =
        "ndms-import-response-manifest-v3-" + std::string(64U, 'f');
    record.created_interface = "Wireguard5";
    record.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'd');
    return record;
}

NdmsNativeOwnershipRecord claim_of(
    const NdmsNativeImportWalRecord& record) {
    NdmsNativeOwnershipRecord claim;
    claim.interface_name = *record.created_interface;
    claim.transaction_id = record.transaction_id;
    claim.marker = record.marker;
    claim.kind = record.kind;
    claim.snapshot_revision = record.snapshot_revision;
    claim.target_full_revision = *record.target_full_revision;
    return claim;
}

// The WAL store owns its directory outright: any name it does not recognize
// makes the whole inventory unsafe - that is the design, and it caught this
// file's first draft putting the ownership directory INSIDE the store. Root
// the two stores as siblings under the temp directory instead.
NdmsNativeImportWalStore sibling_wal_store(const TempDirectory& directory) {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return NdmsNativeImportWalStore(directory.path / "wal", hooks);
}

void publish_verified_chain(NdmsNativeImportWalStore& store,
                            const NdmsNativeImportWalRecord& verified) {
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    auto inflight = inflight_record();
    store.publish(inflight);
    auto responded = inflight;
    responded.phase = NdmsNativeImportWalPhase::response_recorded;
    responded.response_manifest_sha256 = verified.response_manifest_sha256;
    store.publish(responded);
    store.publish(verified);
}

} // namespace

TEST_CASE("rolling back a published claim retracts it, and only it") {
    // The crash this exists for: forward completion published the ownership
    // claim, died before advancing the WAL, and recovery rolls back from
    // target_verified. Before the retraction step the rollback deleted the
    // interface and removed the WAL record but left the claim - a durable
    // assertion that keen-pbr owns a slot that is now free, covering whatever
    // an operator later creates there by hand.
    TempDirectory directory;
    auto store = sibling_wal_store(directory);
    NdmsNativeOwnershipStore ownership(directory.path / "ownership");
    const auto record = verified_record();
    publish_verified_chain(store, record);
    ownership.publish(claim_of(record));
    REQUIRE(ownership.read("Wireguard5").state ==
            NdmsNativeOwnershipReadState::valid);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    REQUIRE(*admission.action ==
            NdmsNativeImportRecoveryAction::rollback_delete_exact_owned);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    FakeSnapshotRetirer snapshots;

    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        },
        &ownership, nullptr, &snapshots);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::completed);
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
    // The whole point: the store reports clean AND the claim is gone.
    CHECK(ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
}

TEST_CASE("a rollback that could hold a claim refuses without the store") {
    TempDirectory directory;
    auto store = sibling_wal_store(directory);
    const auto record = verified_record();
    publish_verified_chain(store, record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    // This record carries the exact fields publish_ownership builds a claim
    // from, so a dispatcher without the store cannot know whether a claim
    // stands - and must refuse before the first step rather than roll back
    // around it.
    const auto refused = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        },
        nullptr);
    CHECK(refused.state == NdmsNativeImportRecoveryDispatchState::
                               ownership_store_missing);
    CHECK(refused.completed_steps == 0U);
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::valid);

    // An inflight record has no such fields, no possible claim, and keeps
    // its store-less rollback - the pre-existing crash-driver path.
    const auto bare = inflight_record();
    CHECK_FALSE(bare.created_interface.has_value());
}

TEST_CASE("published ownership stable absence retires snapshot and WAL last") {
    TempDirectory directory;
    auto store = sibling_wal_store(directory);
    NdmsNativeOwnershipStore ownership(directory.path / "ownership");
    auto record = verified_record();
    publish_verified_chain(store, record);
    record.phase = NdmsNativeImportWalPhase::ownership_published;
    record.ownership_revision = ownership.publish(claim_of(record));
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, absent_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    REQUIRE(admission.action ==
            NdmsNativeImportRecoveryAction::complete_rollback);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    const auto missing_snapshot = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt, nullptr,
        &ownership);
    CHECK(missing_snapshot.state ==
          NdmsNativeImportRecoveryDispatchState::snapshot_retirer_missing);
    REQUIRE(store.load(record.transaction_id).record.has_value());
    CHECK(store.load(record.transaction_id).record->phase ==
          NdmsNativeImportWalPhase::ownership_published);

    std::size_t delete_calls = 0U;
    FakeSnapshotRetirer snapshots;
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt,
        [&delete_calls](const std::string&, const std::string&) {
            ++delete_calls;
            return NdmsNativeImportRecoveryDeleteOutcome::failed;
        },
        &ownership, nullptr, &snapshots);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::completed);
    CHECK(result.completed_steps == 3U);
    CHECK(delete_calls == 0U);
    CHECK(snapshots.calls == 1U);
    CHECK(ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
}

TEST_CASE("a foreign claim blocks rollback and survives untouched") {
    TempDirectory directory;
    auto store = sibling_wal_store(directory);
    NdmsNativeOwnershipStore ownership(directory.path / "ownership");
    const auto record = verified_record();
    publish_verified_chain(store, record);
    // Another transaction's claim over the same slot. Retracting it would
    // erase somebody else's ownership on the strength of our rollback.
    auto foreign = claim_of(record);
    foreign.transaction_id = std::string(32U, 'e');
    foreign.marker = "kpbr-ni-v1-" + foreign.transaction_id;
    ownership.publish(foreign);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    FakeSnapshotRetirer snapshots;
    std::size_t delete_calls = 0U;
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [&delete_calls](const std::string&, const std::string&) {
            ++delete_calls;
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        },
        &ownership, nullptr, &snapshots);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::step_failed);
    REQUIRE(result.failed_step.has_value());
    CHECK(*result.failed_step ==
          NdmsNativeImportRecoveryStep::remove_ownership_claim);
    CHECK(result.completed_steps == 1U);
    CHECK(delete_calls == 0U);
    CHECK(snapshots.calls == 0U);

    const auto surviving = ownership.read("Wireguard5");
    REQUIRE(surviving.state == NdmsNativeOwnershipReadState::valid);
    CHECK(surviving.record->transaction_id == foreign.transaction_id);
    const auto retained = store.load(record.transaction_id);
    REQUIRE(retained.record.has_value());
    CHECK(retained.record->phase ==
          NdmsNativeImportWalPhase::rollback_requested);
}

TEST_CASE("a torn claim stops the rollback instead of being read as absent") {
    TempDirectory directory;
    auto store = sibling_wal_store(directory);
    NdmsNativeOwnershipStore ownership(directory.path / "ownership");
    const auto record = verified_record();
    publish_verified_chain(store, record);
    ownership.publish(claim_of(record));
    {
        std::ofstream torn(directory.path / "ownership" / "Wireguard5",
                           std::ios::binary | std::ios::trunc);
        torn << "half a claim";
    }

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    FakeSnapshotRetirer snapshots;
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        },
        &ownership, nullptr, &snapshots);
    // A torn claim is evidence of an interrupted publish. Reading it as
    // "nothing to retract" and carrying on is exactly the collapse the
    // ownership store refuses elsewhere; the dispatcher must not shortcut it.
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::step_failed);
    REQUIRE(result.failed_step.has_value());
    CHECK(*result.failed_step ==
          NdmsNativeImportRecoveryStep::remove_ownership_claim);
    // The WAL still holds the durable account for the next pass.
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::valid);
}

} // namespace keen_pbr3
