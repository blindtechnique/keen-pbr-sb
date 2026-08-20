// Crash-at-each-phase driver for the native-import WAL machinery.
//
// Not part of any test target: cross-compiled by hand and run on the router,
// where the property under test actually lives - that a process killed
// between any two dispatch steps leaves a durable WAL the next run finishes
// from, on the real filesystem, through real fsync.
//
//   nir-crash-driver run <dir> <forward|rollback> <crash-at-step>
//       Seeds a transaction, dispatches the plan, and _exit(137)s immediately
//       before the given step executes. Exit 0 means the plan finished
//       without reaching the crash point.
//   nir-crash-driver recover <dir>
//       Plays the surviving WAL to completion through the same admission and
//       dispatch the daemon would use. Exit 0 only when the store ends empty
//       and consistent.
//
// The deleted "interface" is simulated: this driver exercises the durability
// chain, not RCI. The real importer's crash acceptance stays with the audited
// hardware probe protocol.

#include "../src/keenetic/ndms_native_import_forward_plan.hpp"
#include "../src/keenetic/ndms_native_import_recovery_dispatch.hpp"
#include "../src/keenetic/ndms_native_ownership_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

#include <unistd.h>

namespace keen_pbr3 {
namespace {

const std::string kRevision = "ndms-rci-full-v1-" + std::string(64U, 'd');

NdmsNativeImportPersistedBaseline driver_baseline() {
    auto payload = nlohmann::json::object();
    for (const unsigned slot : {0U, 1U, 2U, 3U, 4U, 6U}) {
        const auto name = "Wireguard" + std::to_string(slot);
        payload[name] = {{"type", "Bridge"},
                         {"interface-name", name},
                         {"description", "occupied-slot"}};
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
    if (!built.success() || !built.evidence.has_value()) {
        std::fprintf(stderr, "baseline fixture failed\n");
        std::exit(2);
    }
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord response_recorded_record() {
    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        "ndms-native-import-v1-" + std::string(64U, 'b');
    record.snapshot_revision = record.candidate_revision;
    record.observation_binding = {std::string(32U, 'd'), 9U, 7U};
    record.baseline = driver_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id, record.marker,
            record.candidate_revision,
            record.kind,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        "ndms-create-ticket-v1-" + std::string(64U, 'c');
    record.maintenance_base_generation = 41U;
    record.phase = NdmsNativeImportWalPhase::response_recorded;
    record.reserved_generation = 42U;
    record.response_manifest_sha256 =
        "ndms-import-response-manifest-v3-" + std::string(64U, 'e');
    return record;
}

NdmsNativeImportRecoveryObservation owned_observation(
    const std::optional<std::string>& published_ownership) {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.marker_match_count = 1U;
    observation.marker_target = "Wireguard5";
    observation.target_absent_in_baseline = true;
    observation.target_down = true;
    observation.target_fingerprint_matches = true;
    observation.ownership_record_matches =
        published_ownership.has_value();
    return observation;
}

NdmsNativeImportWalStore store_for(const std::string& directory) {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return NdmsNativeImportWalStore(
        std::filesystem::path(directory) / "wal", hooks);
}

class SimulatedSnapshotRetirer final
    : public NdmsNativeImportSnapshotRetirer {
public:
    bool remove_if_present_exact(
        const std::string&,
        const std::string&,
        const std::string&,
        const std::string&) override {
        // This durability-only driver never creates a secret snapshot; exact
        // absence is part of its simulated state.
        return true;
    }
};

int seed_and_run(const std::string& directory,
                 const std::string& mode,
                 const unsigned crash_at) {
    auto store = store_for(directory);
    NdmsNativeOwnershipStore ownership(
        std::filesystem::path(directory) / "ownership");
    SimulatedSnapshotRetirer snapshots;

    auto prepared = response_recorded_record();
    prepared.phase = NdmsNativeImportWalPhase::prepared;
    prepared.reserved_generation.reset();
    prepared.response_manifest_sha256.reset();
    if (store.publish_prepared_exclusive(prepared) !=
        NdmsNativeImportWalAdmissionState::admitted) {
        std::fprintf(stderr, "seed admission refused\n");
        return 2;
    }
    auto inflight = response_recorded_record();
    inflight.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    inflight.response_manifest_sha256.reset();
    store.publish(inflight);
    const auto record = response_recorded_record();
    store.publish(record);

    unsigned step_index = 0U;
    const auto crash_observer =
        [&](NdmsNativeImportRecoveryStep) {
            if (step_index++ == crash_at) ::_exit(137);
        };

    if (mode == "forward") {
        const auto completion = plan_ndms_native_import_forward_completion(
            record, owned_observation(std::nullopt), kRevision);
        if (!completion.actionable()) return 2;
        auto admission =
            admit_ndms_native_import_forward(store, record, completion);
        if (admission.state !=
            NdmsNativeImportRecoveryAdmissionState::admitted) {
            return 2;
        }
        const auto result = dispatch_ndms_native_import_recovery(
            store, admission.lease, completion.enriched, completion.plan,
            std::nullopt, nullptr, &ownership, crash_observer);
        return result.state ==
                       NdmsNativeImportRecoveryDispatchState::completed
                   ? 0
                   : 2;
    }
    // rollback
    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_observation(std::nullopt));
    if (admission.state !=
            NdmsNativeImportRecoveryAdmissionState::admitted ||
        !admission.action.has_value()) {
        return 2;
    }
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::deleted_confirmed;
        },
        nullptr, crash_observer, &snapshots);
    return result.state ==
                   NdmsNativeImportRecoveryDispatchState::completed
               ? 0
               : 2;
}

int recover(const std::string& directory) {
    auto store = store_for(directory);
    NdmsNativeOwnershipStore ownership(
        std::filesystem::path(directory) / "ownership");
    SimulatedSnapshotRetirer snapshots;

    const auto inventory = store.try_inventory();
    if (inventory.state == NdmsNativeImportWalInventoryState::ready &&
        inventory.items.empty()) {
        std::printf("store already empty\n");
        return 0;
    }
    if (!inventory.recovery_permitted() || inventory.items.size() != 1U ||
        !inventory.items.front().record.has_value()) {
        std::fprintf(stderr, "inventory not recoverable\n");
        return 2;
    }
    const auto record = *inventory.items.front().record;
    std::printf("surviving phase: %s\n",
                ndms_native_import_wal_phase_name(record.phase));

    const auto claim = ownership.read("Wireguard5");
    // The simulated world answers the way a real catalog read would: the
    // fake delete always confirms, so once the WAL says absence_verified the
    // target is gone and the honest observation is a stable absence. Feeding
    // "present" there makes the classifier block - correctly, as the first
    // run of this driver proved: a target reappearing after proven absence is
    // nobody's to delete.
    NdmsNativeImportRecoveryObservation observation;
    if (record.phase == NdmsNativeImportWalPhase::absence_verified) {
        observation.authoritative = true;
        observation.generation_advanced = true;
        observation.protected_catalog_unchanged = true;
        observation.stable_absence = true;
    } else {
        observation = owned_observation(
            claim.state == NdmsNativeOwnershipReadState::valid
                ? claim.revision
                : std::nullopt);
    }

    auto admission =
        admit_ndms_native_import_recovery(store, record, observation);
    if (admission.state !=
            NdmsNativeImportRecoveryAdmissionState::admitted ||
        !admission.action.has_value()) {
        std::fprintf(stderr, "recovery not admitted: %s\n",
                     ndms_native_import_recovery_admission_state_name(
                         admission.state));
        return 2;
    }
    std::printf("recovery action: %s\n",
                ndms_native_import_recovery_action_name(
                    *admission.action));
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);
    if (!plan.actionable()) {
        std::fprintf(stderr, "no plan for admitted action\n");
        return 2;
    }
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::deleted_confirmed;
        },
        &ownership, nullptr, &snapshots);
    if (result.state !=
        NdmsNativeImportRecoveryDispatchState::completed) {
        std::fprintf(stderr, "recovery dispatch failed at %zu\n",
                     result.completed_steps);
        return 2;
    }
    const auto after = store.try_inventory();
    if (after.state != NdmsNativeImportWalInventoryState::ready ||
        !after.items.empty()) {
        std::fprintf(stderr, "store not empty after recovery\n");
        return 2;
    }
    // The claim invariant the retraction step exists for. A forward resume
    // rests on the published claim and must keep it; every other outcome is a
    // rollback or an abort, after which a surviving claim would durably
    // assert keen-pbr ownership of a slot that is now free - the exact
    // residue the crash window between publish_ownership and
    // advance_wal_ownership_published used to leave.
    const auto final_claim = ownership.read("Wireguard5");
    const bool forward_completed =
        *admission.action ==
        NdmsNativeImportRecoveryAction::resume_forward_reconcile;
    if (forward_completed &&
        final_claim.state != NdmsNativeOwnershipReadState::valid) {
        std::fprintf(stderr, "forward recovery lost the ownership claim\n");
        return 2;
    }
    if (!forward_completed &&
        final_claim.state != NdmsNativeOwnershipReadState::absent) {
        std::fprintf(stderr, "claim survived a rollback recovery\n");
        return 2;
    }
    std::printf("recovered clean (claim %s)\n",
                forward_completed ? "kept" : "retired");
    return 0;
}

} // namespace
} // namespace keen_pbr3

int main(int argc, char** argv) {
    using namespace keen_pbr3;
    if (argc >= 3 && std::string(argv[1]) == "recover") {
        return recover(argv[2]);
    }
    if (argc >= 5 && std::string(argv[1]) == "run") {
        return seed_and_run(argv[2], argv[3],
                            static_cast<unsigned>(std::atoi(argv[4])));
    }
    std::fprintf(
        stderr,
        "usage: %s run <dir> <forward|rollback> <crash-at-step> | "
        "recover <dir>\n",
        argv[0]);
    return 2;
}
