#include <doctest/doctest.h>

#include "keenetic/ndms_native_cooperative_import.hpp"
#include "keenetic/ndms_native_import_identity.hpp"

#include "runtime/runtime_mutation_admission.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

static_assert(!std::is_copy_constructible_v<
              NdmsNativeCooperativeImportCoordinator>);
static_assert(!std::is_default_constructible_v<
              NdmsNativeCooperativeImportCoordinator>);

namespace {

constexpr char kPrivateKey[] =
    "UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFA=";
constexpr char kPublicKey[] =
    "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s=";
constexpr char kAuthority[] =
    "0123456789abcdef0123456789abcdef";

std::string plain_config() {
    return std::string{"[Interface]\nPrivateKey = "} + kPrivateKey +
           "\nAddress = 10.7.0.2/32\n\n[Peer]\nPublicKey = " +
           kPublicKey +
           "\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0\n";
}

std::string amnezia_config() {
    auto config = plain_config();
    const auto peer = config.find("\n\n[Peer]");
    if (peer == std::string::npos) {
        throw std::runtime_error("invalid test AWG config");
    }
    config.insert(
        peer,
        "\nJc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\n"
        "H1 = 101\nH2 = 202\nH3 = 303\nH4 = 404\n");
    return config;
}

class TempDirectory final {
public:
    TempDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "keen-pbr-native-coordinator-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const auto* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        root = created;
    }

    ~TempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    }

    std::filesystem::path root;
};

class HeldRecoveryLock final {
public:
    explicit HeldRecoveryLock(std::filesystem::path path) {
        descriptor_ = ::open(
            path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
            0600);
        if (descriptor_ >= 0 &&
            ::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    ~HeldRecoveryLock() {
        if (descriptor_ >= 0) (void)::close(descriptor_);
    }

    bool held() const noexcept { return descriptor_ >= 0; }

private:
    int descriptor_{-1};
};

struct MaintenanceState final {
    bool held{true};
    bool fail_reserve{false};
    std::size_t fail_verify_call{0U};
    std::uint32_t generation{41U};
    std::size_t reserve_calls{0U};
    std::size_t verify_calls{0U};
};

class FakeMaintenanceLease final : public MaintenanceLease {
public:
    explicit FakeMaintenanceLease(
        std::shared_ptr<MaintenanceState> state)
        : state_(std::move(state)), base_(state_->generation) {}

    std::uint32_t base_generation() const noexcept override {
        return base_;
    }

    std::uint32_t reserve(const std::uint32_t expected) override {
        ++state_->reserve_calls;
        if (!state_->held || state_->fail_reserve ||
            expected != state_->generation ||
            state_->generation ==
                std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("synthetic generation refusal");
        }
        return ++state_->generation;
    }

    void verify_held() override {
        ++state_->verify_calls;
        if (!state_->held ||
            state_->fail_verify_call == state_->verify_calls) {
            throw std::runtime_error("synthetic writer loss");
        }
    }

private:
    std::shared_ptr<MaintenanceState> state_;
    std::uint32_t base_{0U};
};

NdmsNativeWriterAdmission acquire_writer(
    const std::filesystem::path& state,
    RuntimeMutationAdmission& runtime,
    const std::shared_ptr<MaintenanceState>& maintenance) {
    auto runtime_lease = runtime.try_acquire("cooperative-import-test");
    REQUIRE(runtime_lease.has_value());
    NdmsNativeWriterLeaseTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return admit_ndms_native_writer(
        state,
        std::make_unique<FakeMaintenanceLease>(maintenance),
        std::move(*runtime_lease),
        hooks);
}

nlohmann::json catalog_payload(
    const std::vector<std::uint8_t>& occupied,
    const std::optional<std::string>& marker = std::nullopt,
    const bool target_without_marker = false,
    const std::uint8_t marker_slot = 5U,
    const std::optional<std::uint8_t> second_marker_slot =
        std::nullopt) {
    auto payload = nlohmann::json::object();
    for (const auto slot : occupied) {
        const auto name = "Wireguard" + std::to_string(slot);
        const bool carries_marker =
            slot == marker_slot ||
            (second_marker_slot.has_value() &&
             slot == *second_marker_slot);
        payload[name] = {
            {"type",
             carries_marker &&
                     (marker.has_value() || target_without_marker)
                 ? "Wireguard"
                 : "Bridge"},
            {"interface-name", name},
            {"description",
             marker.has_value() && carries_marker
                 ? *marker
                 : "occupied-slot-" + std::to_string(slot)},
            {"connected", false},
            {"link", false},
        };
    }
    return payload;
}

NdmsCatalogSnapshot snapshot_for(
    const std::vector<std::uint8_t>& occupied,
    const std::optional<std::string>& marker = std::nullopt,
    const bool target_without_marker = false,
    const std::uint8_t marker_slot = 5U,
    const std::optional<std::uint8_t> second_marker_slot =
        std::nullopt) {
    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(
        catalog_payload(
            occupied,
            marker,
            target_without_marker,
            marker_slot,
            second_marker_slot));
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    snapshot.observed_at = std::chrono::steady_clock::time_point{
        std::chrono::seconds{123}};
    return snapshot;
}

class FakeObservationGateway final
    : public NdmsNativeCooperativeImportObservationGateway {
public:
    NdmsNativeDirectCatalogObservation observe_catalog(
        const NdmsNativeDirectCatalogScope scope) noexcept override {
        catalog_scopes.push_back(scope);
        if (fail_catalog_scope == scope) {
            return {
                std::nullopt,
                NdmsNativeDirectObservationFailure::transport_failed,
                scope};
        }
        const auto& occupied =
            scope == NdmsNativeDirectCatalogScope::runtime_state
                ? runtime_occupied
                : running_occupied;
        return {
            snapshot_for(occupied),
            NdmsNativeDirectObservationFailure::none,
            scope};
    }

    NdmsNativeDirectRecoveryObservation observe_recovery(
        const NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept override {
        ++recovery_calls;
        recovery_scopes.push_back(scope);
        NdmsNativeDirectRecoveryObservation result;
        result.requested_catalog_scope = scope;
        result.catalog_scope = scope;
        if (fail_recovery_call == recovery_calls ||
            !expected_target.has_value()) {
            result.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
            return result;
        }
        const bool omit_marker =
            (scope == NdmsNativeDirectCatalogScope::runtime_state &&
             omit_runtime_marker) ||
            (scope == NdmsNativeDirectCatalogScope::running_config &&
             omit_running_marker);
        const auto marker_identity = parse_ndms_wireguard_identity(
            recovery_marker_target);
        const auto second_marker_identity =
            recovery_second_marker_target.has_value()
                ? parse_ndms_wireguard_identity(
                      *recovery_second_marker_target)
                : std::optional<NdmsWireguardIdentity>{};
        if (!marker_identity.has_value() ||
            (recovery_second_marker_target.has_value() &&
             !second_marker_identity.has_value())) {
            result.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
            return result;
        }
        std::vector<std::uint8_t> default_recovery_occupied{
            0U, 1U, 2U, 3U, 4U, 6U};
        if (recovery_target_present) {
            default_recovery_occupied.push_back(marker_identity->slot);
            if (second_marker_identity.has_value()) {
                default_recovery_occupied.push_back(
                    second_marker_identity->slot);
            }
            if (extra_recovery_slot.has_value()) {
                default_recovery_occupied.push_back(
                    *extra_recovery_slot);
            }
            std::sort(default_recovery_occupied.begin(),
                      default_recovery_occupied.end());
            default_recovery_occupied.erase(
                std::unique(default_recovery_occupied.begin(),
                            default_recovery_occupied.end()),
                default_recovery_occupied.end());
        }
        const auto& recovery_occupied =
            scope == NdmsNativeDirectCatalogScope::running_config &&
                    running_recovery_occupied.has_value()
                ? *running_recovery_occupied
                : default_recovery_occupied;
        result.snapshot = snapshot_for(
            recovery_occupied,
            omit_marker || !recovery_target_present
                ? std::optional<std::string>{}
                : std::optional<std::string>{marker},
            omit_marker && recovery_target_present,
            marker_identity->slot,
            second_marker_identity.has_value()
                ? std::optional<std::uint8_t>{
                      second_marker_identity->slot}
                : std::nullopt);
        if ((running_extra_structural_drift &&
             scope == NdmsNativeDirectCatalogScope::running_config) ||
            (runtime_extra_structural_drift &&
             scope == NdmsNativeDirectCatalogScope::runtime_state)) {
            result.snapshot->catalog.wireguard_slots[4U]
                .structural_revision =
                "ndms-wg-slot-v1-" + std::string(64U, 'c');
        }
        const auto& observed_target = recovery_target_present
            ? recovery_marker_target
            : *expected_target;
        const auto& kernel_interface =
            scope == NdmsNativeDirectCatalogScope::runtime_state
                ? runtime_kernel_interface
                : running_kernel_interface;
        if (kernel_interface.has_value()) {
            for (auto& tunnel : result.snapshot->catalog.tunnels) {
                if (tunnel.firmware_interface_name == observed_target) {
                    tunnel.kernel_name = kernel_interface;
                } else if (recovery_second_marker_target.has_value() &&
                           tunnel.firmware_interface_name ==
                               *recovery_second_marker_target) {
                    tunnel.kernel_name = kernel_interface;
                }
            }
        }
        const auto revision_digit =
            (drift_second && recovery_calls == 2U) ||
                    (running_revision_mismatch &&
                     scope ==
                         NdmsNativeDirectCatalogScope::running_config)
                ? 'b'
                : 'a';
        result.target_evidence.push_back(
            {observed_target,
             recovery_target_down,
             "ndms-rci-full-v1-" +
                 std::string(64U, revision_digit)});
        result.target_protocols.push_back(
            {observed_target, protocol});
        if (recovery_target_present &&
            recovery_second_marker_target.has_value()) {
            result.target_evidence.push_back(
                {*recovery_second_marker_target,
                 recovery_target_down,
                 "ndms-rci-full-v1-" +
                     std::string(64U, revision_digit)});
            result.target_protocols.push_back(
                {*recovery_second_marker_target, protocol});
        }
        result.catalog_revision =
            ndms_native_import_recovery_catalog_revision(
                result.snapshot->catalog, result.target_evidence);
        result.failure = NdmsNativeDirectObservationFailure::none;
        if (after_recovery_observation) {
            after_recovery_observation(recovery_calls);
        }
        return result;
    }

    std::vector<std::uint8_t> runtime_occupied{
        0U, 1U, 2U, 3U, 4U, 6U};
    std::vector<std::uint8_t> running_occupied{
        0U, 1U, 2U, 3U, 4U, 6U};
    NdmsNativeAscClass protocol{
        NdmsNativeAscClass::plain_wireguard};
    std::size_t fail_recovery_call{0U};
    bool drift_second{false};
    bool running_revision_mismatch{false};
    bool omit_runtime_marker{false};
    bool omit_running_marker{false};
    bool recovery_target_present{true};
    bool recovery_target_down{true};
    bool running_extra_structural_drift{false};
    bool runtime_extra_structural_drift{false};
    std::string recovery_marker_target{"Wireguard5"};
    std::optional<std::string> recovery_second_marker_target;
    std::optional<std::uint8_t> extra_recovery_slot;
    std::optional<std::string> runtime_kernel_interface{"nwg5"};
    std::optional<std::string> running_kernel_interface{"nwg5"};
    std::optional<std::vector<std::uint8_t>>
        running_recovery_occupied;
    std::optional<NdmsNativeDirectCatalogScope> fail_catalog_scope;
    std::size_t recovery_calls{0U};
    std::vector<NdmsNativeDirectCatalogScope> catalog_scopes;
    std::vector<NdmsNativeDirectCatalogScope> recovery_scopes;
    std::function<void(std::size_t)> after_recovery_observation;
};

class FakeBackend final : public NdmsNativeLoopbackRciPostBackend {
private:
    NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeImportPreDispatchGuard& guard,
        NdmsNativeImportBackendTrace& trace) override {
        ++calls;
        saw_secret_body = !request_body.empty();
        NdmsNativeImportRawTransportResponse response;
        trace.pre_dispatch_guard_evaluated = true;
        if (!guard.authorize_dispatch()) return response;
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        ++perform_calls;
        response.request_may_have_been_dispatched = true;
        response.transport_ok = true;
        response.status_code = 200;
        response.content_type_seen = true;
        response.content_type_is_json = true;
        CHECK(response.body.write_secret_body_chunk(
            response_body));
        return response;
    }

public:
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    bool saw_secret_body{false};
    std::string response_body{
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])"};
};

class FakeDeleteBackend final : public NdmsNativeExactMutationBackend {
private:
    NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeExactMutationPreDispatchGuard& guard,
        NdmsNativeExactMutationBackendTrace& trace) override {
        ++calls;
        bodies.emplace_back(
            request_body.view().data(), request_body.view().size());
        trace.pre_dispatch_guard_evaluated = true;
        if (before_guard) before_guard(calls);
        if (!guard.authorize_dispatch()) {
            return NdmsNativeExactMutationRawResponse{};
        }
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        ++perform_calls;
        if (apply_effect && gateway != nullptr) {
            if (enable_target) {
                gateway->recovery_target_down = false;
            } else {
                gateway->recovery_target_present = false;
            }
        }
        if (after_perform) after_perform(calls);
        if (throw_after_perform) {
            throw std::runtime_error("synthetic recovery delete crash");
        }
        NdmsNativeExactMutationRawResponse response;
        response.request_may_have_been_dispatched = true;
        response.transport_ok = transport_ok;
        response.status_code = 200;
        response.content_type_seen = true;
        response.content_type_is_json = true;
        CHECK(response.body.write_secret_body_chunk(
            acknowledged ? "{}" : R"({"status":"error"})"));
        return response;
    }

public:
    FakeObservationGateway* gateway{nullptr};
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    bool apply_effect{true};
    bool enable_target{false};
    bool acknowledged{true};
    bool transport_ok{true};
    bool throw_after_perform{false};
    std::function<void(std::size_t)> before_guard;
    std::function<void(std::size_t)> after_perform;
    std::vector<std::string> bodies;
};

class FakeClock final : public NdmsNativeImportExecutorClock {
public:
    NdmsNativeAllocatorMonotonicTime now() const noexcept override {
        return NdmsNativeAllocatorMonotonicTime{
            std::chrono::seconds{1000}};
    }
};

struct FaultControl final {
    bool fail_wal_directory_fsync{false};
    bool fail_snapshot_before_publish{false};
    bool fail_snapshot_after_rename{false};
    bool fail_snapshot_absence_fsync{false};
    bool fail_snapshot_remove_fsync{false};
    bool fail_ownership_after_publish{false};
    bool fail_ownership_absence_fsync{false};
    bool fail_wal_remove{false};
    std::function<void()> after_next_wal_directory_fsync;
};

NdmsNativeObservationStoreTestHooks observation_hooks() {
    NdmsNativeObservationStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.authority_id_factory = [] {
        return std::string{kAuthority};
    };
    return hooks;
}

NdmsNativeImportWalStoreTestHooks wal_hooks(
    const std::shared_ptr<FaultControl>& faults) {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](
        const NdmsNativeImportWalStoreFaultStage stage) {
        if (stage ==
                NdmsNativeImportWalStoreFaultStage::directory_fsync &&
            faults->after_next_wal_directory_fsync) {
            auto callback =
                std::move(faults->after_next_wal_directory_fsync);
            callback();
        }
        if (faults->fail_wal_directory_fsync &&
            stage ==
                NdmsNativeImportWalStoreFaultStage::directory_fsync) {
            throw std::runtime_error(
                "synthetic WAL directory fsync crash");
        }
        if (faults->fail_wal_remove &&
            stage == NdmsNativeImportWalStoreFaultStage::remove) {
            throw std::runtime_error("synthetic WAL remove crash");
        }
    };
    return hooks;
}

NdmsNativeSecretSnapshotStoreTestHooks snapshot_hooks(
    const std::shared_ptr<FaultControl>& faults) {
    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](
        const NdmsNativeSecretSnapshotStoreFaultStage stage) {
        if (faults->fail_snapshot_absence_fsync &&
            stage == NdmsNativeSecretSnapshotStoreFaultStage::
                absence_directory_fsync) {
            throw std::runtime_error(
                "synthetic snapshot absence fsync failure");
        }
        if (faults->fail_snapshot_remove_fsync &&
            stage == NdmsNativeSecretSnapshotStoreFaultStage::
                post_unlink_directory_fsync) {
            throw std::runtime_error(
                "synthetic snapshot remove fsync failure");
        }
        if (faults->fail_snapshot_before_publish &&
            stage == NdmsNativeSecretSnapshotStoreFaultStage::
                pre_publish_after_file_fsync) {
            throw std::runtime_error("synthetic snapshot crash");
        }
        if (faults->fail_snapshot_after_rename &&
            stage == NdmsNativeSecretSnapshotStoreFaultStage::
                post_rename_directory_fsync) {
            throw std::runtime_error(
                "synthetic snapshot directory fsync crash");
        }
    };
    return hooks;
}

NdmsNativeOwnershipStoreTestHooks ownership_hooks(
    const std::shared_ptr<FaultControl>& faults) {
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](
        const NdmsNativeOwnershipStoreFaultStage stage) {
        if (faults->fail_ownership_absence_fsync &&
            stage == NdmsNativeOwnershipStoreFaultStage::
                absence_directory_fsync) {
            throw std::runtime_error(
                "synthetic ownership absence fsync failure");
        }
        if (faults->fail_ownership_after_publish &&
            stage == NdmsNativeOwnershipStoreFaultStage::
                post_rename_directory_fsync) {
            throw std::runtime_error("synthetic ownership crash");
        }
    };
    return hooks;
}

NdmsNativeDeleteWalStoreTestHooks delete_wal_hooks() {
    NdmsNativeDeleteWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

std::string revision(
    const std::string_view prefix, const char digit) {
    return std::string{prefix} + std::string(64U, digit);
}

NdmsNativeDeleteWalRecord unfinished_delete_record() {
    const std::string ownership_transaction(32U, 'd');
    NdmsNativeDeleteWalRecord record;
    record.transaction_id = std::string(32U, 'e');
    record.interface_name = "Wireguard5";
    record.kind = NdmsNativeTunnelImportKind::wireguard;
    record.ownership_revision = revision(
        "ndms-native-owner-v3-", '1');
    record.ownership_transaction_id = ownership_transaction;
    record.marker = std::string{kNdmsNativeImportMarkerPrefix} +
                    ownership_transaction;
    record.snapshot_revision = revision(
        "ndms-native-import-v1-", '2');
    record.target_full_revision = revision(
        "ndms-rci-full-v1-", '3');
    record.keen_pbr_dependency_revision = revision(
        kNdmsNativeDeleteDependencyRevisionPrefix, '4');
    record.preflight_observations = {
        revision(kNdmsNativeObservationCatalogRevisionPrefix, '5'),
        1U,
        revision(kNdmsNativeObservationCatalogRevisionPrefix, '6'),
        2U,
    };
    record.observation_binding = {kAuthority, 1U, 2U};
    record.owner_global_save_acknowledged = true;
    record.external_writer_race_accepted = true;
    record.integrity = ndms_native_delete_wal_integrity(record);
    return record;
}

struct Fixture final {
    explicit Fixture(const bool activate_and_save = false)
        : faults(std::make_shared<FaultControl>()),
          maintenance(std::make_shared<MaintenanceState>()),
          writer(acquire_writer(
              directory.root / "native-mutation",
              runtime,
              maintenance)),
          observations(
              directory.root / "native-mutation",
              observation_hooks()),
          wal(directory.root / "wal", wal_hooks(faults)),
          delete_wal(
              directory.root / "delete-wal",
              delete_wal_hooks()),
          snapshots(
              directory.root / "keys" /
                  "native-import-snapshot.key",
              directory.root / "native-import-snapshots",
              snapshot_hooks(faults)),
          ownership(
              directory.root / "ownership",
              ownership_hooks(faults)),
          coordinator(
              NdmsNativeCooperativeImportCoordinatorTestIssuer::issue(
                  observations,
                  wal,
                  delete_wal,
                  snapshots,
                  ownership,
                   gateway,
                   backend,
                   delete_backend,
                   clock,
                   activate_and_save ? &activation_backend : nullptr)) {
        REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
        delete_backend.gateway = &gateway;
        activation_backend.gateway = &gateway;
        activation_backend.enable_target = true;
    }

    NdmsNativeCooperativeImportResult run(
        std::string config = plain_config(),
        const NdmsNativeExternalWriterRaceAcceptance acceptance =
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted) {
        return coordinator.import_once(
            writer.lease, std::move(config), acceptance);
    }

    TempDirectory directory;
    std::shared_ptr<FaultControl> faults;
    RuntimeMutationAdmission runtime;
    std::shared_ptr<MaintenanceState> maintenance;
    NdmsNativeWriterAdmission writer;
    NdmsNativeObservationStore observations;
    NdmsNativeImportWalStore wal;
    NdmsNativeDeleteWalStore delete_wal;
    NdmsNativeSecretSnapshotStore snapshots;
    NdmsNativeOwnershipStore ownership;
    FakeObservationGateway gateway;
    FakeBackend backend;
    FakeDeleteBackend delete_backend;
    FakeDeleteBackend activation_backend;
    FakeClock clock;
    NdmsNativeCooperativeImportCoordinator coordinator;
};

NdmsNativeOwnershipRecord target_ownership_record(
    const NdmsNativeOwnershipLifecycle lifecycle =
        NdmsNativeOwnershipLifecycle::active_running_only) {
    NdmsNativeOwnershipRecord record;
    record.interface_name = "Wireguard5";
    record.transaction_id = std::string(32U, '7');
    record.marker = std::string{kNdmsNativeImportMarkerPrefix} +
                    record.transaction_id;
    record.snapshot_revision = revision(
        "ndms-native-import-v1-", '8');
    record.target_full_revision = revision(
        "ndms-rci-full-v1-", '9');
    record.lifecycle = lifecycle;
    if (lifecycle != NdmsNativeOwnershipLifecycle::active_running_only) {
        NdmsNativeOwnershipLifecycleEvidence evidence;
        evidence.transaction_id = std::string(32U, '6');
        evidence.observation_binding = {std::string(32U, '5'), 2U, 3U};
        evidence.runtime_catalog_revision = revision(
            kNdmsNativeObservationCatalogRevisionPrefix, '4');
        evidence.runtime_sequence = 4U;
        evidence.running_config_catalog_revision = revision(
            kNdmsNativeObservationCatalogRevisionPrefix, '3');
        evidence.running_config_sequence = 5U;
        record.lifecycle_evidence = std::move(evidence);
    }
    return record;
}

void check_target_precheck_wrote_no_mutation(
    Fixture& fixture,
    const NdmsNativeCooperativeImportResult& result) {
    CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
    CHECK(result.expected_interface ==
          std::optional<std::string>{"Wireguard5"});
    CHECK_FALSE(result.created_interface.has_value());
    CHECK_FALSE(result.created_kernel_interface.has_value());
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK_FALSE(result.wal_may_require_recovery);
    CHECK_FALSE(result.rollback_snapshot_may_be_retained);
    CHECK_FALSE(result.ownership_published);
    CHECK(fixture.backend.calls == 0U);
    CHECK(fixture.backend.perform_calls == 0U);
    CHECK(fixture.maintenance->reserve_calls == 0U);
    CHECK(fixture.gateway.catalog_scopes.size() == 2U);
    CHECK(fixture.gateway.recovery_calls == 0U);
    CHECK(fixture.observations.read().state ==
          NdmsNativeObservationReadState::absent);
    const auto inventory = fixture.wal.try_inventory();
    CHECK(inventory.state == NdmsNativeImportWalInventoryState::absent);
    CHECK(inventory.items.empty());
}

NdmsNativeCooperativeImportResult run_target_precheck(Fixture& fixture) {
    auto raw = plain_config();
    auto result = fixture.coordinator.import_once(
        fixture.writer.lease,
        std::move(raw),
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);
    CHECK(raw.empty());
    return result;
}

void check_response_recorded_wal(
    Fixture& fixture,
    const NdmsNativeCooperativeImportResult& result) {
    REQUIRE(result.transaction_id.has_value());
    const auto loaded = fixture.wal.load(*result.transaction_id);
    REQUIRE(loaded.state == NdmsNativeImportWalLoadState::valid);
    REQUIRE(loaded.record.has_value());
    CHECK(loaded.record->phase ==
          NdmsNativeImportWalPhase::response_recorded);
    CHECK(loaded.record->execution_mode ==
          NdmsNativeImportExecutionMode::cooperative_stock_import);
}

NdmsNativeCooperativeImportResult leave_response_recorded(
    Fixture& fixture) {
    fixture.gateway.fail_recovery_call = 1U;
    const auto result = fixture.run();
    REQUIRE(result.status ==
            NdmsNativeCooperativeImportStatus::recovery_required);
    check_response_recorded_wal(fixture, result);
    fixture.gateway.fail_recovery_call = 0U;
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    return result;
}

NdmsNativeCooperativeImportResult leave_ambiguous_response_recorded(
    Fixture& fixture,
    std::string config = plain_config()) {
    fixture.backend.response_body =
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard7","intersects":""}}}}])";
    const auto result = fixture.run(std::move(config));
    REQUIRE(result.status ==
            NdmsNativeCooperativeImportStatus::recovery_required);
    REQUIRE(result.executor_stop ==
            NdmsNativeImportExecutionStop::ambiguous_response);
    REQUIRE(result.transaction_id.has_value());
    const auto loaded = fixture.wal.load(*result.transaction_id);
    REQUIRE(loaded.record.has_value());
    REQUIRE(loaded.record->phase ==
            NdmsNativeImportWalPhase::response_recorded);
    REQUIRE_FALSE(loaded.record->created_interface.has_value());
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    return result;
}

NdmsNativeCooperativeImportResult leave_prepared(
    Fixture& fixture,
    const bool snapshot_may_be_visible) {
    fixture.faults->fail_snapshot_before_publish =
        !snapshot_may_be_visible;
    fixture.faults->fail_snapshot_after_rename =
        snapshot_may_be_visible;
    const auto result = fixture.run();
    REQUIRE(result.status ==
            NdmsNativeCooperativeImportStatus::recovery_required);
    REQUIRE(result.transaction_id.has_value());
    const auto loaded = fixture.wal.load(*result.transaction_id);
    REQUIRE(loaded.record.has_value());
    REQUIRE(loaded.record->phase ==
            NdmsNativeImportWalPhase::prepared);
    fixture.faults->fail_snapshot_before_publish = false;
    fixture.faults->fail_snapshot_after_rename = false;
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    return result;
}

NdmsNativeCooperativeImportResult leave_import_may_be_inflight(
    Fixture& fixture) {
    fixture.maintenance->fail_reserve = true;
    const auto result = fixture.run();
    fixture.maintenance->fail_reserve = false;
    REQUIRE(result.status ==
            NdmsNativeCooperativeImportStatus::recovery_required);
    REQUIRE(result.executor_stop ==
            NdmsNativeImportExecutionStop::generation_reservation_failed);
    REQUIRE(result.transaction_id.has_value());
    auto loaded = fixture.wal.load(*result.transaction_id);
    REQUIRE(loaded.record.has_value());
    REQUIRE(loaded.record->phase ==
            NdmsNativeImportWalPhase::prepared);
    const auto snapshot = fixture.snapshots.read_panel_delete_snapshot(
        loaded.record->baseline.expected_created_interface,
        loaded.record->transaction_id,
        loaded.record->marker);
    REQUIRE(snapshot.state == NdmsNativeSecretReadState::valid);
    REQUIRE(snapshot.snapshot.has_value());
    REQUIRE(snapshot.snapshot->canonical_revision() ==
            loaded.record->snapshot_revision);
    auto inflight = *loaded.record;
    inflight.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    inflight.reserved_generation =
        inflight.maintenance_base_generation + 1U;
    fixture.wal.publish(inflight);
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    return result;
}

NdmsNativeCooperativeImportResult leave_verified_forward_phase(
    Fixture& fixture,
    const NdmsNativeImportWalPhase phase) {
    REQUIRE((phase == NdmsNativeImportWalPhase::target_verified ||
             phase == NdmsNativeImportWalPhase::ownership_published));
    fixture.faults->fail_ownership_after_publish =
        phase == NdmsNativeImportWalPhase::target_verified;
    fixture.faults->fail_wal_remove =
        phase == NdmsNativeImportWalPhase::ownership_published;
    const auto result = fixture.run();
    REQUIRE(result.status ==
            NdmsNativeCooperativeImportStatus::recovery_required);
    REQUIRE(result.transaction_id.has_value());
    const auto loaded = fixture.wal.load(*result.transaction_id);
    REQUIRE(loaded.record.has_value());
    REQUIRE(loaded.record->phase == phase);
    fixture.faults->fail_ownership_after_publish = false;
    fixture.faults->fail_wal_remove = false;
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    return result;
}

void check_resume_never_imports_or_saves(
    const NdmsNativeCooperativeImportResumeResult& result) {
    CHECK_FALSE(result.ndms_import_request_dispatched);
    CHECK_FALSE(result.system_configuration_save_performed);
}

void check_resume_is_router_read_only(
    const NdmsNativeCooperativeImportResumeResult& result) {
    check_resume_never_imports_or_saves(result);
    CHECK_FALSE(result.ndms_delete_dispatched);
    CHECK_FALSE(result.external_ndms_writer_race_excluded);
}

} // namespace

TEST_CASE("cooperative import requires explicit external-writer acceptance") {
    Fixture fixture;
    auto raw = plain_config();
    const auto result = fixture.coordinator.import_once(
        fixture.writer.lease,
        std::move(raw),
        NdmsNativeExternalWriterRaceAcceptance::not_accepted);

    CHECK(raw.empty());
    CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
    CHECK(result.stop == NdmsNativeCooperativeImportStop::
          external_writer_race_not_accepted);
    CHECK_FALSE(result.external_ndms_writer_race_excluded);
    CHECK_FALSE(result.external_ndms_writer_race_accepted);
    CHECK_FALSE(result.system_configuration_save_performed);
    CHECK(fixture.gateway.catalog_scopes.empty());
    CHECK(fixture.backend.calls == 0U);
    CHECK(fixture.maintenance->reserve_calls == 0U);
}

TEST_CASE("cooperative import wipes secrets on missing or lost writer") {
    SUBCASE("moved-from writer is refused before the delete WAL read") {
        Fixture fixture;
        auto retained_writer = std::move(fixture.writer.lease);
        REQUIRE(retained_writer.held());
        auto raw = plain_config();

        const auto result = fixture.coordinator.import_once(
            fixture.writer.lease,
            std::move(raw),
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(raw.empty());
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::writer_missing);
        CHECK_FALSE(result.delete_wal_readiness.has_value());
        CHECK(fixture.gateway.catalog_scopes.empty());
        CHECK(fixture.backend.calls == 0U);
    }

    SUBCASE("lost outer maintenance lease is refused and wiped") {
        Fixture fixture;
        fixture.maintenance->held = false;
        auto raw = plain_config();

        const auto result = fixture.coordinator.import_once(
            fixture.writer.lease,
            std::move(raw),
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(raw.empty());
        CHECK(result.stop == NdmsNativeCooperativeImportStop::writer_lost);
        CHECK_FALSE(result.delete_wal_readiness.has_value());
        CHECK(fixture.gateway.catalog_scopes.empty());
        CHECK(fixture.backend.calls == 0U);
    }
}

TEST_CASE("cooperative import requires a clean cross-kind delete WAL") {
    SUBCASE("unfinished delete blocks before every import observation") {
        Fixture fixture;
        REQUIRE(fixture.delete_wal.publish_prepared_exclusive(
            unfinished_delete_record()));
        auto raw = plain_config();

        const auto result = fixture.coordinator.import_once(
            fixture.writer.lease,
            std::move(raw),
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(raw.empty());
        CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::delete_wal_not_clean);
        CHECK(result.delete_wal_readiness ==
              std::optional<NdmsNativeDeleteWalReadiness>{
                  NdmsNativeDeleteWalReadiness::unfinished});
        CHECK_FALSE(result.transaction_id.has_value());
        CHECK(fixture.gateway.catalog_scopes.empty());
        CHECK(fixture.backend.calls == 0U);
        CHECK(fixture.maintenance->reserve_calls == 0U);
        CHECK(fixture.observations.read().state ==
              NdmsNativeObservationReadState::absent);
        const auto import_inventory = fixture.wal.try_inventory();
        CHECK(import_inventory.state ==
              NdmsNativeImportWalInventoryState::absent);
        CHECK(import_inventory.items.empty());
    }

    SUBCASE("unsafe delete store also blocks fail-closed") {
        Fixture fixture;
        const auto state = fixture.directory.root / "delete-wal";
        REQUIRE(std::filesystem::create_directory(state));
        std::filesystem::permissions(
            state,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
        const auto unknown = state / "unknown-entry";
        const int descriptor = ::open(
            unknown.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        REQUIRE(descriptor >= 0);
        REQUIRE(::close(descriptor) == 0);

        const auto result = fixture.run();

        CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::delete_wal_not_clean);
        CHECK(result.delete_wal_readiness ==
              std::optional<NdmsNativeDeleteWalReadiness>{
                  NdmsNativeDeleteWalReadiness::unsafe});
        CHECK(fixture.gateway.catalog_scopes.empty());
        CHECK(fixture.backend.calls == 0U);
        CHECK(fixture.observations.read().state ==
              NdmsNativeObservationReadState::absent);
    }
}

TEST_CASE("cooperative import preserves recovery binding when import WAL is unfinished") {
    Fixture fixture;
    fixture.gateway.fail_recovery_call = 2U;
    const auto first = fixture.run();
    REQUIRE(first.status ==
            NdmsNativeCooperativeImportStatus::recovery_required);
    check_response_recorded_wal(fixture, first);
    const auto ledger_before = fixture.observations.read();
    REQUIRE(ledger_before.state == NdmsNativeObservationReadState::valid);
    REQUIRE(ledger_before.ledger.has_value());
    const auto backend_calls_before = fixture.backend.calls;
    const auto reserve_calls_before = fixture.maintenance->reserve_calls;
    fixture.gateway.catalog_scopes.clear();
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.fail_recovery_call = 0U;
    auto raw = plain_config();

    const auto second = fixture.coordinator.import_once(
        fixture.writer.lease,
        std::move(raw),
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

    CHECK(raw.empty());
    CHECK(second.status == NdmsNativeCooperativeImportStatus::blocked);
    CHECK(second.stop ==
          NdmsNativeCooperativeImportStop::import_wal_not_clean);
    CHECK(second.import_wal_readiness ==
          std::optional<NdmsNativeCooperativeImportWalReadiness>{
              NdmsNativeCooperativeImportWalReadiness::unfinished});
    CHECK_FALSE(second.transaction_id.has_value());
    CHECK(fixture.gateway.catalog_scopes.empty());
    CHECK(fixture.gateway.recovery_calls == 0U);
    CHECK(fixture.backend.calls == backend_calls_before);
    CHECK(fixture.maintenance->reserve_calls == reserve_calls_before);
    const auto ledger_after = fixture.observations.read();
    REQUIRE(ledger_after.state == NdmsNativeObservationReadState::valid);
    REQUIRE(ledger_after.ledger.has_value());
    CHECK(*ledger_after.ledger == *ledger_before.ledger);
    check_response_recorded_wal(fixture, first);
    const auto old_record = fixture.wal.load(*first.transaction_id);
    REQUIRE(old_record.record.has_value());
    CHECK(old_record.record->observation_binding.authority_id ==
          ledger_after.ledger->authority_id);
    CHECK(old_record.record->observation_binding.mutation_epoch ==
          ledger_after.ledger->mutation_epoch);
}

TEST_CASE("cooperative import treats unsafe import WAL inventory as read-only") {
    Fixture fixture;
    const auto state = fixture.wal.state_directory();
    REQUIRE(std::filesystem::create_directory(state));
    std::filesystem::permissions(
        state,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
    const auto unknown = state / "unknown-entry";
    const int descriptor = ::open(
        unknown.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600);
    REQUIRE(descriptor >= 0);
    REQUIRE(::close(descriptor) == 0);
    auto raw = plain_config();

    const auto result = fixture.coordinator.import_once(
        fixture.writer.lease,
        std::move(raw),
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

    CHECK(raw.empty());
    CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
    CHECK(result.stop ==
          NdmsNativeCooperativeImportStop::import_wal_not_clean);
    CHECK(result.import_wal_readiness ==
          std::optional<NdmsNativeCooperativeImportWalReadiness>{
              NdmsNativeCooperativeImportWalReadiness::unsafe});
    CHECK_FALSE(result.transaction_id.has_value());
    CHECK(fixture.gateway.catalog_scopes.empty());
    CHECK(fixture.backend.calls == 0U);
    CHECK(fixture.maintenance->reserve_calls == 0U);
    CHECK(fixture.observations.read().state ==
          NdmsNativeObservationReadState::absent);
}

TEST_CASE("cooperative import compares both direct prewrite scopes") {
    SUBCASE("runtime catalog failure writes no durable import state") {
        Fixture fixture;
        fixture.gateway.fail_catalog_scope =
            NdmsNativeDirectCatalogScope::runtime_state;

        const auto result = fixture.run();

        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::runtime_catalog_failed);
        CHECK(result.direct_observation_failure ==
              std::optional<NdmsNativeDirectObservationFailure>{
                  NdmsNativeDirectObservationFailure::transport_failed});
        CHECK_FALSE(result.expected_interface.has_value());
        CHECK_FALSE(result.created_interface.has_value());
        REQUIRE(result.transaction_id.has_value());
        CHECK(fixture.wal.load(*result.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        CHECK(fixture.observations.read().state ==
              NdmsNativeObservationReadState::absent);
        CHECK(fixture.backend.calls == 0U);
        CHECK(fixture.gateway.catalog_scopes.size() == 1U);
    }

    SUBCASE("running-config failure writes no durable import state") {
        Fixture fixture;
        fixture.gateway.fail_catalog_scope =
            NdmsNativeDirectCatalogScope::running_config;

        const auto result = fixture.run();

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              running_config_catalog_failed);
        CHECK(result.direct_observation_failure ==
              std::optional<NdmsNativeDirectObservationFailure>{
                  NdmsNativeDirectObservationFailure::transport_failed});
        CHECK_FALSE(result.expected_interface.has_value());
        CHECK_FALSE(result.created_interface.has_value());
        REQUIRE(result.transaction_id.has_value());
        CHECK(fixture.wal.load(*result.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        CHECK(fixture.observations.read().state ==
              NdmsNativeObservationReadState::absent);
        CHECK(fixture.backend.calls == 0U);
        CHECK(fixture.gateway.catalog_scopes.size() == 2U);
    }

    SUBCASE("running-config occupancy divergence writes no WAL and posts nothing") {
        Fixture fixture;
        fixture.gateway.running_occupied.push_back(5U);

        const auto result = fixture.run();

        CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              prewrite_catalog_diverged);
        REQUIRE(result.transaction_id.has_value());
        CHECK_FALSE(result.created_interface.has_value());
        CHECK(fixture.wal.load(*result.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        CHECK(fixture.backend.calls == 0U);
        CHECK(fixture.maintenance->reserve_calls == 0U);
        REQUIRE(fixture.gateway.catalog_scopes.size() == 2U);
        CHECK(fixture.gateway.catalog_scopes[0] ==
              NdmsNativeDirectCatalogScope::runtime_state);
        CHECK(fixture.gateway.catalog_scopes[1] ==
              NdmsNativeDirectCatalogScope::running_config);
    }

    SUBCASE("stock first-free in a protected slot is refused") {
        Fixture fixture;
        fixture.gateway.runtime_occupied = {1U, 2U, 3U, 4U, 6U};
        fixture.gateway.running_occupied =
            fixture.gateway.runtime_occupied;

        const auto result = fixture.run();

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              first_free_target_not_managed);
        CHECK_FALSE(result.expected_interface.has_value());
        CHECK_FALSE(result.created_interface.has_value());
        CHECK(fixture.backend.calls == 0U);
        REQUIRE(result.transaction_id.has_value());
        CHECK(fixture.wal.load(*result.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }

    SUBCASE("stock first-free above the managed range is refused") {
        Fixture fixture;
        fixture.gateway.runtime_occupied.clear();
        for (std::uint8_t slot = 0U; slot <= 98U; ++slot) {
            fixture.gateway.runtime_occupied.push_back(slot);
        }
        fixture.gateway.running_occupied =
            fixture.gateway.runtime_occupied;

        const auto result = fixture.run();

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              first_free_target_not_managed);
        CHECK_FALSE(result.expected_interface.has_value());
        CHECK_FALSE(result.created_interface.has_value());
        CHECK(fixture.backend.calls == 0U);
        REQUIRE(result.transaction_id.has_value());
        CHECK(fixture.wal.load(*result.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }
}

TEST_CASE("cooperative import requires durable absence of target artifacts") {
    SUBCASE("an active ownership claim reserves an absent runtime slot") {
        Fixture fixture;
        const auto claim = target_ownership_record();
        const auto revision_before = fixture.ownership.publish(claim);

        const auto result = run_target_precheck(fixture);

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              ownership_target_not_available);
        check_target_precheck_wrote_no_mutation(fixture, result);
        const auto retained = fixture.ownership.read("Wireguard5");
        REQUIRE(retained.state == NdmsNativeOwnershipReadState::valid);
        CHECK(retained.revision ==
              std::optional<std::string>{revision_before});
        REQUIRE(retained.record.has_value());
        CHECK(*retained.record == claim);
        CHECK_FALSE(std::filesystem::exists(
            fixture.directory.root / "native-import-snapshots"));
    }

    SUBCASE("a delete tombstone reserves an absent runtime slot") {
        Fixture fixture;
        const auto claim = target_ownership_record(
            NdmsNativeOwnershipLifecycle::
                deleted_save_acknowledged_unverified);
        const auto revision_before = fixture.ownership.publish(claim);

        const auto result = run_target_precheck(fixture);

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              ownership_target_not_available);
        check_target_precheck_wrote_no_mutation(fixture, result);
        const auto retained = fixture.ownership.read("Wireguard5");
        REQUIRE(retained.state == NdmsNativeOwnershipReadState::valid);
        CHECK(retained.revision ==
              std::optional<std::string>{revision_before});
        REQUIRE(retained.record.has_value());
        CHECK(*retained.record == claim);
        CHECK_FALSE(std::filesystem::exists(
            fixture.directory.root / "native-import-snapshots"));
    }

    SUBCASE("an unreadable ownership claim is never collapsed to absence") {
        Fixture fixture;
        const auto state = fixture.directory.root / "ownership";
        REQUIRE(std::filesystem::create_directory(state));
        std::filesystem::permissions(
            state,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
        const auto path = state / "Wireguard5";
        const int descriptor = ::open(
            path.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        REQUIRE(descriptor >= 0);
        const std::string torn{"keen-pbr-native-ownership-v3\nWireguard5\n"};
        REQUIRE(::write(descriptor, torn.data(), torn.size()) ==
                static_cast<ssize_t>(torn.size()));
        REQUIRE(::close(descriptor) == 0);

        const auto result = run_target_precheck(fixture);

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              ownership_target_not_available);
        check_target_precheck_wrote_no_mutation(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::unreadable);
        CHECK(std::filesystem::exists(path));
        CHECK_FALSE(std::filesystem::exists(
            fixture.directory.root / "native-import-snapshots"));
    }

    SUBCASE("ownership absence fsync failure stops before snapshot admission") {
        Fixture fixture;
        fixture.faults->fail_ownership_absence_fsync = true;

        const auto result = run_target_precheck(fixture);

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              ownership_target_not_available);
        check_target_precheck_wrote_no_mutation(fixture, result);
        CHECK_FALSE(std::filesystem::exists(
            fixture.directory.root / "native-import-snapshots"));
    }

    SUBCASE("an orphan encrypted snapshot is preserved and blocks reuse") {
        Fixture fixture;
        const std::string transaction(32U, '2');
        const std::string marker =
            std::string{kNdmsNativeImportMarkerPrefix} + transaction;
        fixture.snapshots.publish(
            "Wireguard5", transaction, marker, "orphan-secret");

        const auto result = run_target_precheck(fixture);

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              snapshot_target_not_available);
        check_target_precheck_wrote_no_mutation(fixture, result);
        auto retained = fixture.snapshots.read(
            "Wireguard5", transaction, marker);
        REQUIRE(retained.state == NdmsNativeSecretReadState::valid);
        REQUIRE(retained.secret != nullptr);
        CHECK(*retained.secret == "orphan-secret");
    }

    SUBCASE("snapshot absence fsync failure stops before mutation admission") {
        Fixture fixture;
        fixture.faults->fail_snapshot_absence_fsync = true;

        const auto result = run_target_precheck(fixture);

        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              snapshot_target_not_available);
        check_target_precheck_wrote_no_mutation(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
        CHECK_FALSE(std::filesystem::exists(
            fixture.directory.root / "native-import-snapshots" /
                "Wireguard5"));
    }
}

TEST_CASE("cooperative WG import completes ownership and exact WAL cleanup") {
    Fixture fixture;
    const auto result = fixture.run();

    const auto executor_stop = result.executor_stop.value_or(
        NdmsNativeImportExecutionStop::none);
    CAPTURE(static_cast<int>(result.stop));
    CAPTURE(static_cast<int>(executor_stop));
    REQUIRE(result.status == NdmsNativeCooperativeImportStatus::completed);
    CHECK(result.stop == NdmsNativeCooperativeImportStop::none);
    CHECK(result.external_ndms_writer_race_accepted);
    CHECK_FALSE(result.external_ndms_writer_race_excluded);
    CHECK(result.delete_wal_readiness ==
          std::optional<NdmsNativeDeleteWalReadiness>{
              NdmsNativeDeleteWalReadiness::clean});
    CHECK(result.import_wal_readiness ==
          std::optional<NdmsNativeCooperativeImportWalReadiness>{
              NdmsNativeCooperativeImportWalReadiness::clean});
    CHECK_FALSE(result.system_configuration_save_performed);
    CHECK(result.request_may_have_been_dispatched);
    CHECK_FALSE(result.wal_may_require_recovery);
    CHECK(result.rollback_snapshot_may_be_retained);
    CHECK(result.ownership_published);
    REQUIRE(result.transaction_id.has_value());
    REQUIRE(result.created_interface ==
            std::optional<std::string>{"Wireguard5"});
    REQUIRE(result.created_kernel_interface ==
            std::optional<std::string>{"nwg5"});
    REQUIRE(result.expected_interface ==
            std::optional<std::string>{"Wireguard5"});
    REQUIRE(result.kind == std::optional<NdmsNativeTunnelImportKind>{
                               NdmsNativeTunnelImportKind::wireguard});
    CHECK(fixture.backend.calls == 1U);
    CHECK(fixture.backend.perform_calls == 1U);
    CHECK(fixture.backend.saw_secret_body);
    CHECK(fixture.gateway.recovery_calls == 2U);
    REQUIRE(fixture.gateway.recovery_scopes.size() == 2U);
    CHECK(fixture.gateway.recovery_scopes[0] ==
          NdmsNativeDirectCatalogScope::runtime_state);
    CHECK(fixture.gateway.recovery_scopes[1] ==
          NdmsNativeDirectCatalogScope::running_config);
    CHECK(fixture.maintenance->reserve_calls == 1U);
    CHECK(fixture.wal.load(*result.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);

    const auto ownership = fixture.ownership.read("Wireguard5");
    REQUIRE(ownership.state == NdmsNativeOwnershipReadState::valid);
    REQUIRE(ownership.record.has_value());
    CHECK(ownership.record->kind ==
          NdmsNativeTunnelImportKind::wireguard);
    CHECK(ownership.record->transaction_id == *result.transaction_id);
    CHECK(ownership.record->schema_version ==
          kNdmsNativeOwnershipSchemaVersion);
    CHECK(ownership.record->lifecycle ==
          NdmsNativeOwnershipLifecycle::active_running_only);
    CHECK_FALSE(ownership.record->lifecycle_evidence.has_value());

    const auto snapshot = fixture.snapshots.read_panel_delete_snapshot(
        "Wireguard5",
        *result.transaction_id,
        "kpbr-ni-v1-" + *result.transaction_id);
    REQUIRE(snapshot.state == NdmsNativeSecretReadState::valid);
    REQUIRE(snapshot.snapshot.has_value());
    CHECK(snapshot.snapshot->kind() ==
          NdmsNativeTunnelImportKind::wireguard);

    const auto ledger = fixture.observations.read();
    REQUIRE(ledger.state == NdmsNativeObservationReadState::valid);
    REQUIRE(ledger.ledger.has_value());
    CHECK(ledger.ledger->sequence == 3U);
    CHECK(ledger.ledger->mutation_epoch == 1U);
}

TEST_CASE("cooperative import enables the tunnel and saves KeeneticOS") {
    Fixture fixture(true);

    const auto result = fixture.run();

    REQUIRE(result.status == NdmsNativeCooperativeImportStatus::completed);
    CHECK(result.stop == NdmsNativeCooperativeImportStop::none);
    CHECK(result.system_configuration_save_performed);
    CHECK_FALSE(fixture.gateway.recovery_target_down);
    CHECK(fixture.activation_backend.calls == 2U);
    CHECK(fixture.activation_backend.perform_calls == 2U);
    REQUIRE(fixture.activation_backend.bodies.size() == 2U);
    CHECK(fixture.activation_backend.bodies[0] ==
          R"({"interface":{"Wireguard5":{"up":true}}})");
    CHECK(fixture.activation_backend.bodies[1] ==
          R"({"system":{"configuration":{"save":{}}}})");
    CHECK(fixture.gateway.recovery_calls == 4U);
    REQUIRE(result.transaction_id.has_value());
    CHECK(fixture.wal.load(*result.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
    const auto ownership = fixture.ownership.read("Wireguard5");
    REQUIRE(ownership.state == NdmsNativeOwnershipReadState::valid);
    REQUIRE(ownership.record.has_value());
    CHECK(ownership.record->target_full_revision ==
          "ndms-rci-full-v1-" + std::string(64U, 'a'));
}

TEST_CASE("cooperative AWG import binds the measured ASC protocol") {
    Fixture fixture;
    fixture.gateway.protocol = NdmsNativeAscClass::amnezia_wg;
    const auto result = fixture.run(amnezia_config());

    REQUIRE(result.status == NdmsNativeCooperativeImportStatus::completed);
    REQUIRE(result.kind.has_value());
    CHECK(*result.kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    const auto ownership = fixture.ownership.read("Wireguard5");
    REQUIRE(ownership.record.has_value());
    CHECK(ownership.record->kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
}

TEST_CASE("cooperative import requires exact post-import proof in both RCI scopes") {
    SUBCASE("runtime marker without running-config marker publishes no claim") {
        Fixture fixture;
        fixture.gateway.omit_running_marker = true;

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
        REQUIRE(fixture.gateway.recovery_scopes.size() == 2U);
        CHECK(fixture.gateway.recovery_scopes[0] ==
              NdmsNativeDirectCatalogScope::runtime_state);
        CHECK(fixture.gateway.recovery_scopes[1] ==
              NdmsNativeDirectCatalogScope::running_config);
    }

    SUBCASE("running-config target revision drift publishes no claim") {
        Fixture fixture;
        fixture.gateway.running_revision_mismatch = true;

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("scope occupancy divergence publishes no claim") {
        Fixture fixture;
        fixture.gateway.running_recovery_occupied =
            std::vector<std::uint8_t>{
                0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U};

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("missing running-config kernel identity publishes no claim") {
        Fixture fixture;
        fixture.gateway.running_kernel_interface.reset();

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.created_kernel_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("cross-scope kernel identity mismatch publishes no claim") {
        Fixture fixture;
        fixture.gateway.running_kernel_interface = "nwg6";

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.created_kernel_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("unsafe kernel identity publishes no claim") {
        Fixture fixture;
        fixture.gateway.runtime_kernel_interface = "nwg/5";
        fixture.gateway.running_kernel_interface = "nwg/5";

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.created_kernel_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }
}

TEST_CASE("cooperative import failure matrix retains exact recovery phase") {
    SUBCASE("prepared WAL fsync ambiguity does not claim a snapshot") {
        Fixture fixture;
        fixture.faults->fail_wal_directory_fsync = true;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::executor_blocked);
        CHECK(result.executor_stop ==
              std::optional<NdmsNativeImportExecutionStop>{
                  NdmsNativeImportExecutionStop::
                      prepared_wal_publish_failed});
        CHECK_FALSE(result.rollback_snapshot_may_be_retained);
        CHECK_FALSE(result.request_may_have_been_dispatched);
        CHECK(fixture.backend.calls == 0U);
        REQUIRE(result.transaction_id.has_value());
        const auto loaded = fixture.wal.load(*result.transaction_id);
        REQUIRE(loaded.record.has_value());
        CHECK(loaded.record->phase == NdmsNativeImportWalPhase::prepared);
    }

    SUBCASE("snapshot crash leaves prepared WAL and performs no POST") {
        Fixture fixture;
        fixture.faults->fail_snapshot_before_publish = true;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::executor_blocked);
        CHECK(result.expected_interface ==
              std::optional<std::string>{"Wireguard5"});
        CHECK_FALSE(result.created_interface.has_value());
        CHECK(result.rollback_snapshot_may_be_retained);
        CHECK(fixture.backend.calls == 0U);
        REQUIRE(result.transaction_id.has_value());
        const auto loaded = fixture.wal.load(*result.transaction_id);
        REQUIRE(loaded.record.has_value());
        CHECK(loaded.record->phase == NdmsNativeImportWalPhase::prepared);
    }

    SUBCASE("snapshot rename ambiguity truthfully reports retained material") {
        Fixture fixture;
        fixture.faults->fail_snapshot_after_rename = true;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::executor_blocked);
        CHECK(result.executor_stop ==
              std::optional<NdmsNativeImportExecutionStop>{
                  NdmsNativeImportExecutionStop::snapshot_publish_failed});
        CHECK(result.rollback_snapshot_may_be_retained);
        CHECK_FALSE(result.request_may_have_been_dispatched);
        CHECK(fixture.backend.calls == 0U);
        REQUIRE(result.transaction_id.has_value());
        const auto loaded = fixture.wal.load(*result.transaction_id);
        REQUIRE(loaded.record.has_value());
        CHECK(loaded.record->phase == NdmsNativeImportWalPhase::prepared);
    }

    SUBCASE("first stamped probe failure leaves response-recorded WAL") {
        Fixture fixture;
        fixture.gateway.fail_recovery_call = 1U;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              first_post_observation_failed);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK(fixture.gateway.recovery_calls == 1U);
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("second stamped probe failure leaves response-recorded WAL") {
        Fixture fixture;
        fixture.gateway.fail_recovery_call = 2U;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              second_post_observation_failed);
        CHECK_FALSE(result.created_interface.has_value());
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("two stamped probes that disagree never publish ownership") {
        Fixture fixture;
        fixture.gateway.drift_second = true;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_completion_blocked);
        CHECK_FALSE(result.created_interface.has_value());
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("WG response measured as AWG stays read-only in recovery") {
        Fixture fixture;
        fixture.gateway.protocol = NdmsNativeAscClass::amnezia_wg;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              post_observation_kind_mismatch);
        CHECK_FALSE(result.created_interface.has_value());
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("ownership crash after rename leaves target-verified WAL") {
        Fixture fixture;
        fixture.faults->fail_ownership_after_publish = true;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              ownership_publish_failed);
        REQUIRE(result.transaction_id.has_value());
        const auto loaded = fixture.wal.load(*result.transaction_id);
        REQUIRE(loaded.record.has_value());
        CHECK(loaded.record->phase ==
              NdmsNativeImportWalPhase::target_verified);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::valid);
        CHECK(result.created_interface ==
              std::optional<std::string>{"Wireguard5"});
    }

    SUBCASE("WAL remove crash leaves ownership-published WAL") {
        Fixture fixture;
        fixture.faults->fail_wal_remove = true;
        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportStop::wal_cleanup_failed);
        REQUIRE(result.transaction_id.has_value());
        const auto loaded = fixture.wal.load(*result.transaction_id);
        REQUIRE(loaded.record.has_value());
        CHECK(loaded.record->phase ==
              NdmsNativeImportWalPhase::ownership_published);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::valid);
    }

    SUBCASE("concurrent recoverer blocks forward CAS before ownership") {
        Fixture fixture;
        auto lock_path = fixture.wal.state_directory();
        lock_path += ".recovery-lock";
        HeldRecoveryLock concurrent_recoverer{lock_path};
        REQUIRE(concurrent_recoverer.held());

        const auto result = fixture.run();

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeImportStop::
              forward_admission_failed);
        REQUIRE(result.forward_admission_state.has_value());
        CHECK(*result.forward_admission_state ==
              NdmsNativeImportRecoveryAdmissionState::lease_busy);
        CHECK(result.created_interface ==
              std::optional<std::string>{"Wireguard5"});
        check_response_recorded_wal(fixture, result);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }
}

TEST_CASE("cooperative import resume reports authoritative no-work without router access") {
    Fixture fixture;

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease);

    CHECK(result.status ==
          NdmsNativeCooperativeImportResumeStatus::no_work);
    CHECK(result.stop ==
          NdmsNativeCooperativeImportResumeStop::none);
    CHECK(result.delete_wal_readiness ==
          std::optional<NdmsNativeDeleteWalReadiness>{
              NdmsNativeDeleteWalReadiness::clean});
    CHECK(result.import_wal_readiness ==
          std::optional<NdmsNativeCooperativeImportWalReadiness>{
              NdmsNativeCooperativeImportWalReadiness::clean});
    CHECK_FALSE(result.wal_may_require_recovery);
    CHECK_FALSE(result.wal_removed);
    check_resume_is_router_read_only(result);
    CHECK(fixture.gateway.recovery_calls == 0U);
    CHECK(fixture.backend.calls == 0U);
    CHECK(fixture.observations.read().state ==
          NdmsNativeObservationReadState::absent);
}

TEST_CASE("cooperative import resume forward-completes response-recorded WAL") {
    Fixture fixture;
    const auto interrupted = leave_response_recorded(fixture);
    REQUIRE(interrupted.transaction_id.has_value());
    const auto backend_calls_before = fixture.backend.calls;
    const auto reserve_calls_before = fixture.maintenance->reserve_calls;

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease);

    REQUIRE(result.status ==
            NdmsNativeCooperativeImportResumeStatus::completed);
    CHECK(result.stop ==
          NdmsNativeCooperativeImportResumeStop::none);
    CHECK(result.phase ==
          std::optional<NdmsNativeImportWalPhase>{
              NdmsNativeImportWalPhase::response_recorded});
    CHECK(result.transaction_id == interrupted.transaction_id);
    CHECK(result.expected_interface ==
          std::optional<std::string>{"Wireguard5"});
    CHECK(result.created_interface ==
          std::optional<std::string>{"Wireguard5"});
    CHECK(result.created_kernel_interface ==
          std::optional<std::string>{"nwg5"});
    CHECK(result.ownership_published);
    CHECK(result.wal_removed);
    CHECK_FALSE(result.wal_may_require_recovery);
    check_resume_is_router_read_only(result);
    CHECK(fixture.backend.calls == backend_calls_before);
    CHECK(fixture.maintenance->reserve_calls == reserve_calls_before);
    REQUIRE(fixture.gateway.recovery_scopes.size() == 2U);
    CHECK(fixture.gateway.recovery_scopes[0] ==
          NdmsNativeDirectCatalogScope::runtime_state);
    CHECK(fixture.gateway.recovery_scopes[1] ==
          NdmsNativeDirectCatalogScope::running_config);
    CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);

    const auto ownership = fixture.ownership.read("Wireguard5");
    REQUIRE(ownership.state == NdmsNativeOwnershipReadState::valid);
    REQUIRE(ownership.record.has_value());
    CHECK(ownership.record->schema_version ==
          kNdmsNativeOwnershipSchemaVersion);
    CHECK(ownership.record->lifecycle ==
          NdmsNativeOwnershipLifecycle::active_running_only);
    CHECK_FALSE(ownership.record->lifecycle_evidence.has_value());
    const auto ledger = fixture.observations.read();
    REQUIRE(ledger.state == NdmsNativeObservationReadState::valid);
    REQUIRE(ledger.ledger.has_value());
    CHECK(ledger.ledger->sequence == 3U);
    CHECK(ledger.ledger->mutation_epoch == 1U);
}

TEST_CASE("cooperative import resume completes crashes at each local forward phase") {
    SUBCASE("target-verified WAL idempotently adopts its exact claim") {
        Fixture fixture;
        fixture.faults->fail_ownership_after_publish = true;
        const auto interrupted = fixture.run();
        REQUIRE(interrupted.transaction_id.has_value());
        REQUIRE(interrupted.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        const auto loaded = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(loaded.record.has_value());
        REQUIRE(loaded.record->phase ==
                NdmsNativeImportWalPhase::target_verified);
        const auto ownership_before =
            fixture.ownership.read("Wireguard5");
        REQUIRE(ownership_before.record.has_value());
        fixture.faults->fail_ownership_after_publish = false;
        fixture.gateway.recovery_calls = 0U;
        fixture.gateway.recovery_scopes.clear();
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::target_verified});
        CHECK(result.created_interface ==
              std::optional<std::string>{"Wireguard5"});
        CHECK(result.ownership_published);
        CHECK(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        const auto ownership_after =
            fixture.ownership.read("Wireguard5");
        REQUIRE(ownership_after.record.has_value());
        CHECK(*ownership_after.record == *ownership_before.record);
    }

    SUBCASE("ownership-published WAL performs exact cleanup only") {
        Fixture fixture;
        fixture.faults->fail_wal_remove = true;
        const auto interrupted = fixture.run();
        REQUIRE(interrupted.transaction_id.has_value());
        REQUIRE(interrupted.status ==
                NdmsNativeCooperativeImportStatus::recovery_required);
        const auto loaded = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(loaded.record.has_value());
        REQUIRE(loaded.record->phase ==
                NdmsNativeImportWalPhase::ownership_published);
        const auto ownership_before =
            fixture.ownership.read("Wireguard5");
        REQUIRE(ownership_before.record.has_value());
        fixture.faults->fail_wal_remove = false;
        fixture.gateway.recovery_calls = 0U;
        fixture.gateway.recovery_scopes.clear();
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::ownership_published});
        CHECK(result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      resume_forward_reconcile});
        CHECK(result.created_interface ==
              std::optional<std::string>{"Wireguard5"});
        CHECK(result.ownership_published);
        CHECK(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        const auto ownership_after =
            fixture.ownership.read("Wireguard5");
        REQUIRE(ownership_after.record.has_value());
        CHECK(*ownership_after.record == *ownership_before.record);
    }
}

TEST_CASE("verified forward phases retire authoritative stable absence without router writes") {
    Fixture fixture;
    auto phase = NdmsNativeImportWalPhase::target_verified;
    SUBCASE("target verified") {
        phase = NdmsNativeImportWalPhase::target_verified;
    }
    SUBCASE("ownership published") {
        phase = NdmsNativeImportWalPhase::ownership_published;
    }
    const auto interrupted =
        leave_verified_forward_phase(fixture, phase);
    const auto loaded = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(loaded.record.has_value());
    fixture.gateway.recovery_target_present = false;
    const auto backend_calls_before = fixture.backend.calls;

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease);

    REQUIRE(result.status ==
            NdmsNativeCooperativeImportResumeStatus::completed);
    CHECK(result.stop == NdmsNativeCooperativeImportResumeStop::none);
    CHECK(result.phase ==
          std::optional<NdmsNativeImportWalPhase>{phase});
    CHECK(result.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::complete_rollback});
    CHECK(result.recovery_admission_state ==
          std::optional<NdmsNativeImportRecoveryAdmissionState>{
              NdmsNativeImportRecoveryAdmissionState::admitted});
    CHECK(result.recovery_dispatch_state ==
          std::optional<NdmsNativeImportRecoveryDispatchState>{
              NdmsNativeImportRecoveryDispatchState::completed});
    CHECK_FALSE(result.ownership_published);
    CHECK(result.rollback_snapshot_retired);
    CHECK(result.wal_removed);
    CHECK_FALSE(result.wal_may_require_recovery);
    CHECK_FALSE(result.external_ndms_writer_race_accepted);
    CHECK(fixture.backend.calls == backend_calls_before);
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(result);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
    CHECK(fixture.snapshots.read_panel_delete_snapshot(
              loaded.record->baseline.expected_created_interface,
              loaded.record->transaction_id,
              loaded.record->marker)
              .state == NdmsNativeSecretReadState::absent);
}

TEST_CASE("verified stable absence never retracts a foreign ownership claim") {
    Fixture fixture;
    auto phase = NdmsNativeImportWalPhase::target_verified;
    SUBCASE("target verified") {
        phase = NdmsNativeImportWalPhase::target_verified;
    }
    SUBCASE("ownership published") {
        phase = NdmsNativeImportWalPhase::ownership_published;
    }
    const auto interrupted =
        leave_verified_forward_phase(fixture, phase);
    const auto loaded = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(loaded.record.has_value());
    const auto exact = fixture.ownership.read("Wireguard5");
    REQUIRE(exact.record.has_value());
    REQUIRE(fixture.ownership.remove_exact(*exact.record));
    auto foreign = *exact.record;
    foreign.transaction_id = std::string(32U, 'f');
    foreign.marker = std::string{kNdmsNativeImportMarkerPrefix} +
                     foreign.transaction_id;
    fixture.ownership.publish(foreign);
    fixture.gateway.recovery_target_present = false;

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease);

    CHECK(result.status ==
          NdmsNativeCooperativeImportResumeStatus::blocked);
    CHECK(result.stop ==
          NdmsNativeCooperativeImportResumeStop::ownership_not_exact);
    CHECK(result.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::complete_rollback});
    CHECK_FALSE(result.recovery_admission_state.has_value());
    CHECK_FALSE(result.recovery_dispatch_state.has_value());
    CHECK_FALSE(result.rollback_snapshot_retired);
    CHECK_FALSE(result.wal_removed);
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(result);
    const auto surviving = fixture.ownership.read("Wireguard5");
    REQUIRE(surviving.record.has_value());
    CHECK(*surviving.record == foreign);
    const auto retained = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(retained.record.has_value());
    CHECK(retained.record->phase == phase);
    CHECK(fixture.snapshots.read_panel_delete_snapshot(
              loaded.record->baseline.expected_created_interface,
              loaded.record->transaction_id,
              loaded.record->marker)
              .state == NdmsNativeSecretReadState::valid);
}

TEST_CASE("direct absence intent survives an ownership race and forbids later delete") {
    Fixture fixture;
    const auto interrupted = leave_verified_forward_phase(
        fixture, NdmsNativeImportWalPhase::ownership_published);
    const auto loaded = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(loaded.record.has_value());
    const auto exact = fixture.ownership.read("Wireguard5");
    REQUIRE(exact.record.has_value());
    auto foreign = *exact.record;
    foreign.transaction_id = std::string(32U, 'f');
    foreign.marker = std::string{kNdmsNativeImportMarkerPrefix} +
                     foreign.transaction_id;
    bool ownership_swapped = false;
    fixture.faults->after_next_wal_directory_fsync =
        [&fixture, expected = *exact.record, foreign,
         &ownership_swapped] {
            if (!fixture.ownership.remove_exact(expected)) return;
            static_cast<void>(fixture.ownership.publish(foreign));
            ownership_swapped = true;
        };
    fixture.gateway.recovery_target_present = false;

    const auto raced = fixture.coordinator.resume_once(
        fixture.writer.lease);

    REQUIRE(ownership_swapped);
    CHECK(raced.status ==
          NdmsNativeCooperativeImportResumeStatus::recovery_required);
    CHECK(raced.stop ==
          NdmsNativeCooperativeImportResumeStop::ownership_retract_failed);
    CHECK(raced.phase ==
          std::optional<NdmsNativeImportWalPhase>{
              NdmsNativeImportWalPhase::absence_verified});
    CHECK(raced.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::complete_rollback});
    CHECK(raced.recovery_failed_step ==
          std::optional<NdmsNativeImportRecoveryStep>{
              NdmsNativeImportRecoveryStep::remove_ownership_claim});
    CHECK_FALSE(raced.ownership_published);
    CHECK_FALSE(raced.rollback_snapshot_retired);
    CHECK_FALSE(raced.wal_removed);
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(raced);
    const auto surviving = fixture.ownership.read("Wireguard5");
    REQUIRE(surviving.record.has_value());
    CHECK(*surviving.record == foreign);
    REQUIRE(fixture.ownership.remove_exact(foreign));

    fixture.gateway.recovery_target_present = true;
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    const auto reappeared = fixture.coordinator.resume_once(
        fixture.writer.lease,
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

    CHECK(reappeared.status ==
          NdmsNativeCooperativeImportResumeStatus::blocked);
    CHECK(reappeared.stop ==
          NdmsNativeCooperativeImportResumeStop::
              recovery_action_not_actionable);
    CHECK(reappeared.phase ==
          std::optional<NdmsNativeImportWalPhase>{
              NdmsNativeImportWalPhase::absence_verified});
    CHECK(reappeared.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::block_unknown});
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(reappeared);
    const auto retained = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(retained.record.has_value());
    CHECK(retained.record->phase ==
          NdmsNativeImportWalPhase::absence_verified);
    CHECK(fixture.snapshots.read_panel_delete_snapshot(
              loaded.record->baseline.expected_created_interface,
              loaded.record->transaction_id,
              loaded.record->marker)
              .state == NdmsNativeSecretReadState::valid);
}

TEST_CASE("verified stable absence cleanup retries local retirement failures") {
    Fixture fixture;
    const auto interrupted = leave_verified_forward_phase(
        fixture, NdmsNativeImportWalPhase::ownership_published);
    fixture.gateway.recovery_target_present = false;
    auto expected_stop =
        NdmsNativeCooperativeImportResumeStop::snapshot_retirement_failed;
    bool snapshot_retired = false;
    SUBCASE("snapshot durability failure") {
        fixture.faults->fail_snapshot_remove_fsync = true;
        expected_stop = NdmsNativeCooperativeImportResumeStop::
            snapshot_retirement_failed;
        snapshot_retired = false;
    }
    SUBCASE("WAL removal failure") {
        fixture.faults->fail_wal_remove = true;
        expected_stop =
            NdmsNativeCooperativeImportResumeStop::wal_cleanup_failed;
        snapshot_retired = true;
    }

    const auto failed = fixture.coordinator.resume_once(
        fixture.writer.lease);

    CHECK(failed.status ==
          NdmsNativeCooperativeImportResumeStatus::recovery_required);
    CHECK(failed.stop == expected_stop);
    CHECK(failed.phase ==
          std::optional<NdmsNativeImportWalPhase>{
              NdmsNativeImportWalPhase::absence_verified});
    CHECK(failed.rollback_snapshot_retired == snapshot_retired);
    CHECK_FALSE(failed.wal_removed);
    CHECK_FALSE(failed.ownership_published);
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(failed);
    const auto retained = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(retained.record.has_value());
    CHECK(retained.record->phase ==
          NdmsNativeImportWalPhase::absence_verified);

    fixture.faults->fail_snapshot_remove_fsync = false;
    fixture.faults->fail_wal_remove = false;
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();
    const auto retried = fixture.coordinator.resume_once(
        fixture.writer.lease);

    REQUIRE(retried.status ==
            NdmsNativeCooperativeImportResumeStatus::completed);
    CHECK(retried.stop == NdmsNativeCooperativeImportResumeStop::none);
    CHECK(retried.phase ==
          std::optional<NdmsNativeImportWalPhase>{
              NdmsNativeImportWalPhase::absence_verified});
    CHECK(retried.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::complete_rollback});
    CHECK(retried.rollback_snapshot_retired);
    CHECK(retried.wal_removed);
    CHECK_FALSE(retried.ownership_published);
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(retried);
    CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
}

TEST_CASE("cooperative import resume requires dual-scope stable target proof") {
    SUBCASE("runtime-only marker leaves response WAL and ownership untouched") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.omit_running_marker = true;
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  observation_unstable);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        CHECK_FALSE(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        check_response_recorded_wal(fixture, interrupted);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("scope target revision mismatch leaves forward state untouched") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.running_revision_mismatch = true;
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  observation_unstable);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        CHECK_FALSE(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        check_response_recorded_wal(fixture, interrupted);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("scope occupancy mismatch leaves forward state untouched") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.running_recovery_occupied =
            std::vector<std::uint8_t>{
                0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U};
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  observation_unstable);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        CHECK_FALSE(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        check_response_recorded_wal(fixture, interrupted);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("missing kernel identity leaves forward state untouched") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.running_kernel_interface.reset();
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  observation_unstable);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.created_kernel_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        CHECK_FALSE(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        check_response_recorded_wal(fixture, interrupted);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }

    SUBCASE("kernel identity mismatch leaves forward state untouched") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.running_kernel_interface = "nwg6";
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  observation_unstable);
        CHECK_FALSE(result.created_interface.has_value());
        CHECK_FALSE(result.created_kernel_interface.has_value());
        CHECK_FALSE(result.ownership_published);
        CHECK_FALSE(result.wal_removed);
        check_resume_is_router_read_only(result);
        CHECK(fixture.backend.calls == backend_calls_before);
        check_response_recorded_wal(fixture, interrupted);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    }
}

TEST_CASE("cooperative import resume fails closed before reads on cross-kind and unsafe state") {
    SUBCASE("unfinished delete WAL blocks before durable recovery evidence") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        REQUIRE(fixture.delete_wal.publish_prepared_exclusive(
            unfinished_delete_record()));
        const auto ledger_before = fixture.observations.read();
        REQUIRE(ledger_before.ledger.has_value());
        const auto backend_calls_before = fixture.backend.calls;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  delete_wal_not_clean);
        CHECK(result.delete_wal_readiness ==
              std::optional<NdmsNativeDeleteWalReadiness>{
                  NdmsNativeDeleteWalReadiness::unfinished});
        CHECK_FALSE(result.transaction_id.has_value());
        CHECK(fixture.gateway.recovery_calls == 0U);
        CHECK(fixture.backend.calls == backend_calls_before);
        const auto ledger_after = fixture.observations.read();
        REQUIRE(ledger_after.ledger.has_value());
        CHECK(*ledger_after.ledger == *ledger_before.ledger);
        check_response_recorded_wal(fixture, interrupted);
        check_resume_is_router_read_only(result);
    }

    SUBCASE("unsafe import inventory blocks before direct observations") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        const auto unknown = fixture.wal.state_directory() / "unknown";
        const int descriptor = ::open(
            unknown.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        REQUIRE(descriptor >= 0);
        REQUIRE(::close(descriptor) == 0);
        const auto ledger_before = fixture.observations.read();
        REQUIRE(ledger_before.ledger.has_value());

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  import_wal_not_single_safe);
        CHECK(result.import_wal_readiness ==
              std::optional<NdmsNativeCooperativeImportWalReadiness>{
                  NdmsNativeCooperativeImportWalReadiness::unsafe});
        CHECK(fixture.gateway.recovery_calls == 0U);
        const auto ledger_after = fixture.observations.read();
        REQUIRE(ledger_after.ledger.has_value());
        CHECK(*ledger_after.ledger == *ledger_before.ledger);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
        check_resume_is_router_read_only(result);
    }
}

TEST_CASE("cooperative import recovery retires stable-absence startup records without router writes") {
    SUBCASE("prepared record with no visible snapshot") {
        Fixture fixture;
        const auto interrupted = leave_prepared(fixture, false);
        fixture.gateway.recovery_target_present = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.stop == NdmsNativeCooperativeImportResumeStop::none);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::prepared});
        CHECK(result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      abort_without_mutation});
        CHECK(result.recovery_admission_state ==
              std::optional<NdmsNativeImportRecoveryAdmissionState>{
                  NdmsNativeImportRecoveryAdmissionState::admitted});
        CHECK(result.recovery_dispatch_state ==
              std::optional<NdmsNativeImportRecoveryDispatchState>{
                  NdmsNativeImportRecoveryDispatchState::completed});
        CHECK(result.rollback_snapshot_retired);
        CHECK(result.wal_removed);
        CHECK_FALSE(result.wal_may_require_recovery);
        CHECK_FALSE(result.external_ndms_writer_race_accepted);
        CHECK(fixture.delete_backend.calls == 0U);
        check_resume_is_router_read_only(result);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        CHECK(fixture.snapshots.read_panel_delete_snapshot(
                  "Wireguard5",
                  *interrupted.transaction_id,
                  std::string{kNdmsNativeImportMarkerPrefix} +
                      *interrupted.transaction_id)
                  .state == NdmsNativeSecretReadState::absent);
    }

    SUBCASE("import-may-be-inflight record with retained snapshot") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.gateway.recovery_target_present = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::import_may_be_inflight});
        CHECK(result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      abort_without_mutation});
        CHECK(result.rollback_snapshot_retired);
        CHECK(result.wal_removed);
        CHECK_FALSE(result.wal_may_require_recovery);
        CHECK(fixture.delete_backend.calls == 0U);
        check_resume_is_router_read_only(result);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }

    SUBCASE("response-recorded stable absence aborts without deletion") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.recovery_target_present = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::response_recorded});
        CHECK(result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      abort_without_mutation});
        CHECK(result.rollback_snapshot_retired);
        CHECK(result.wal_removed);
        CHECK_FALSE(result.external_ndms_writer_race_accepted);
        CHECK(fixture.delete_backend.calls == 0U);
        check_resume_is_router_read_only(result);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }
}

TEST_CASE("cooperative import recovery never deletes a target from a prepared record") {
    Fixture fixture;
    const auto interrupted = leave_prepared(fixture, true);

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease,
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

    CHECK(result.status ==
          NdmsNativeCooperativeImportResumeStatus::blocked);
    CHECK(result.stop == NdmsNativeCooperativeImportResumeStop::
          recovery_action_not_actionable);
    CHECK(result.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::block_unknown});
    CHECK_FALSE(result.wal_removed);
    CHECK(result.wal_may_require_recovery);
    CHECK(fixture.delete_backend.calls == 0U);
    CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
          NdmsNativeImportWalLoadState::valid);
    check_resume_is_router_read_only(result);
}

TEST_CASE("cooperative import recovery retires snapshots durably before WAL-last cleanup") {
    SUBCASE("absent snapshot directory fsync failure keeps the prepared WAL") {
        Fixture fixture;
        const auto interrupted = leave_prepared(fixture, false);
        fixture.gateway.recovery_target_present = false;
        fixture.faults->fail_snapshot_absence_fsync = true;

        const auto failed = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(failed.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(failed.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  snapshot_retirement_failed);
        CHECK(failed.recovery_failed_step ==
              std::optional<NdmsNativeImportRecoveryStep>{
                  NdmsNativeImportRecoveryStep::remove_wal_record});
        CHECK_FALSE(failed.rollback_snapshot_retired);
        CHECK_FALSE(failed.wal_removed);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
        CHECK(fixture.delete_backend.calls == 0U);

        fixture.faults->fail_snapshot_absence_fsync = false;
        const auto recovered = fixture.coordinator.resume_once(
            fixture.writer.lease);
        CHECK(recovered.status ==
              NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(recovered.rollback_snapshot_retired);
        CHECK(recovered.wal_removed);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }

    SUBCASE("visible unlink without directory fsync keeps the inflight WAL") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.gateway.recovery_target_present = false;
        fixture.faults->fail_snapshot_remove_fsync = true;

        const auto failed = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(failed.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(failed.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  snapshot_retirement_failed);
        CHECK_FALSE(failed.rollback_snapshot_retired);
        CHECK_FALSE(failed.wal_removed);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
        CHECK(fixture.snapshots.read_panel_delete_snapshot(
                  "Wireguard5",
                  *interrupted.transaction_id,
                  std::string{kNdmsNativeImportMarkerPrefix} +
                      *interrupted.transaction_id)
                  .state == NdmsNativeSecretReadState::absent);
        CHECK(fixture.delete_backend.calls == 0U);

        fixture.faults->fail_snapshot_remove_fsync = false;
        const auto recovered = fixture.coordinator.resume_once(
            fixture.writer.lease);
        CHECK(recovered.status ==
              NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(recovered.rollback_snapshot_retired);
        CHECK(recovered.wal_removed);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }

    SUBCASE("response snapshot retirement failure keeps WAL-last") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.recovery_target_present = false;
        fixture.faults->fail_snapshot_remove_fsync = true;

        const auto failed = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(failed.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(failed.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  snapshot_retirement_failed);
        CHECK(failed.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      abort_without_mutation});
        CHECK_FALSE(failed.rollback_snapshot_retired);
        CHECK_FALSE(failed.wal_removed);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);

        fixture.faults->fail_snapshot_remove_fsync = false;
        const auto recovered = fixture.coordinator.resume_once(
            fixture.writer.lease);
        CHECK(recovered.status ==
              NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(recovered.rollback_snapshot_retired);
        CHECK(recovered.wal_removed);
    }
}

TEST_CASE("cooperative import recovery requires fresh acceptance before exact rollback delete") {
    Fixture fixture;
    const auto interrupted = leave_import_may_be_inflight(fixture);

    const auto unconfirmed = fixture.coordinator.resume_once(
        fixture.writer.lease);

    REQUIRE(unconfirmed.status ==
            NdmsNativeCooperativeImportResumeStatus::recovery_required);
    CHECK(unconfirmed.stop ==
          NdmsNativeCooperativeImportResumeStop::
              external_writer_race_not_accepted);
    CHECK(unconfirmed.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::
                  rollback_delete_exact_owned});
    CHECK_FALSE(unconfirmed.recovery_admission_state.has_value());
    CHECK_FALSE(unconfirmed.recovery_dispatch_state.has_value());
    CHECK_FALSE(unconfirmed.wal_removed);
    CHECK(fixture.delete_backend.calls == 0U);
    check_resume_is_router_read_only(unconfirmed);

    const auto confirmed = fixture.coordinator.resume_once(
        fixture.writer.lease,
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

    REQUIRE(confirmed.status ==
            NdmsNativeCooperativeImportResumeStatus::completed);
    CHECK(confirmed.stop == NdmsNativeCooperativeImportResumeStop::none);
    CHECK(confirmed.external_ndms_writer_race_accepted);
    CHECK(confirmed.recovery_admission_state ==
          std::optional<NdmsNativeImportRecoveryAdmissionState>{
              NdmsNativeImportRecoveryAdmissionState::admitted});
    CHECK(confirmed.recovery_dispatch_state ==
          std::optional<NdmsNativeImportRecoveryDispatchState>{
              NdmsNativeImportRecoveryDispatchState::completed});
    CHECK_FALSE(confirmed.recovery_failed_step.has_value());
    CHECK(confirmed.delete_perform_started);
    CHECK(confirmed.request_may_have_been_dispatched);
    CHECK(confirmed.ndms_delete_dispatched);
    CHECK(confirmed.delete_transport_outcome ==
          std::optional<NdmsNativeExactMutationResponseOutcome>{
              NdmsNativeExactMutationResponseOutcome::
                  acknowledged_needs_observation});
    CHECK(confirmed.rollback_snapshot_retired);
    CHECK(confirmed.wal_removed);
    CHECK_FALSE(confirmed.wal_may_require_recovery);
    CHECK_FALSE(confirmed.ownership_published);
    check_resume_never_imports_or_saves(confirmed);
    REQUIRE(fixture.delete_backend.bodies.size() == 1U);
    CHECK(fixture.delete_backend.bodies.front() ==
          R"({"interface":{"name":"Wireguard5","no":true}})");
    CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
}

TEST_CASE("cooperative import recovery rolls back only an exact divergent response target") {
    SUBCASE("redacted response still forward-completes the exact expected target") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.created_interface ==
              std::optional<std::string>{"Wireguard5"});
        CHECK(result.created_kernel_interface ==
              std::optional<std::string>{"nwg5"});
        CHECK(result.ownership_published);
        CHECK(result.wal_removed);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.delete_backend.perform_calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        check_resume_is_router_read_only(result);
    }

    SUBCASE("redacted response completes an already-up AWG target without consent") {
        Fixture fixture(true);
        fixture.gateway.protocol = NdmsNativeAscClass::amnezia_wg;
        const auto interrupted =
            leave_ambiguous_response_recorded(
                fixture, amnezia_config());
        fixture.gateway.recovery_target_down = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK_FALSE(result.external_ndms_writer_race_accepted);
        CHECK(result.created_interface ==
              std::optional<std::string>{"Wireguard5"});
        CHECK(result.created_kernel_interface ==
              std::optional<std::string>{"nwg5"});
        CHECK(result.ownership_published);
        CHECK(result.system_configuration_save_performed);
        CHECK(result.wal_removed);
        CHECK(fixture.activation_backend.calls == 2U);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }

    SUBCASE("bodyless entrance is zero-dispatch and fresh acceptance deletes once") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";

        const auto unconfirmed = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(unconfirmed.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(unconfirmed.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  external_writer_race_not_accepted);
        CHECK(unconfirmed.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      rollback_delete_exact_owned});
        CHECK(fixture.delete_backend.calls == 0U);
        check_resume_is_router_read_only(unconfirmed);

        const auto accepted = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        REQUIRE(accepted.status ==
                NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(accepted.external_ndms_writer_race_accepted);
        CHECK(accepted.ndms_delete_dispatched);
        CHECK(accepted.delete_perform_started);
        CHECK(accepted.rollback_snapshot_retired);
        CHECK(accepted.wal_removed);
        REQUIRE(fixture.delete_backend.bodies.size() == 1U);
        CHECK(fixture.delete_backend.bodies.front() ==
              R"({"interface":{"name":"Wireguard7","no":true}})");
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        check_resume_never_imports_or_saves(accepted);
    }

    SUBCASE("ambiguous exact delete remains delete-may with no in-call retry") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        fixture.delete_backend.apply_effect = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  delete_transport_ambiguous);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::delete_may_be_inflight});
        CHECK(result.request_may_have_been_dispatched);
        CHECK(fixture.delete_backend.calls == 1U);
        const auto durable = fixture.wal.load(
            *interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
    }

    SUBCASE("recorded expected target cannot redirect deletion") {
        Fixture fixture;
        const auto interrupted = leave_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }

    SUBCASE("up target is never deleted") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        fixture.gateway.recovery_target_down = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }

    SUBCASE("foreign ownership on the divergent target blocks deletion") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        auto foreign = target_ownership_record();
        foreign.interface_name = "Wireguard7";
        (void)fixture.ownership.publish(foreign);

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  ownership_not_exact);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }

    SUBCASE("one extra occupied slot blocks reconstructed proof") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        fixture.gateway.extra_recovery_slot = 8U;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }

    SUBCASE("benign running-scope structural difference remains actionable") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        fixture.gateway.running_extra_structural_drift = true;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  external_writer_race_not_accepted);
        CHECK(result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      rollback_delete_exact_owned});
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }

    SUBCASE("one extra runtime structural revision blocks reconstructed proof") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        fixture.gateway.runtime_extra_structural_drift = true;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }

    SUBCASE("multiple marker carriers block reconstructed proof") {
        Fixture fixture;
        const auto interrupted =
            leave_ambiguous_response_recorded(fixture);
        fixture.gateway.recovery_marker_target = "Wireguard7";
        fixture.gateway.recovery_second_marker_target = "Wireguard8";

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::blocked);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::valid);
    }
}

TEST_CASE("cooperative import rollback ambiguity remains resumable and never auto-retries") {
    Fixture fixture;
    const auto interrupted = leave_import_may_be_inflight(fixture);
    fixture.delete_backend.apply_effect = false;

    const auto ambiguous = fixture.coordinator.resume_once(
        fixture.writer.lease,
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

    REQUIRE(ambiguous.status ==
            NdmsNativeCooperativeImportResumeStatus::recovery_required);
    CHECK(ambiguous.stop ==
          NdmsNativeCooperativeImportResumeStop::
              delete_transport_ambiguous);
    CHECK(ambiguous.recovery_failed_step ==
          std::optional<NdmsNativeImportRecoveryStep>{
              NdmsNativeImportRecoveryStep::delete_exact_owned_target});
    CHECK(ambiguous.delete_perform_started);
    CHECK(ambiguous.request_may_have_been_dispatched);
    CHECK_FALSE(ambiguous.rollback_snapshot_retired);
    CHECK_FALSE(ambiguous.wal_removed);
    REQUIRE(fixture.delete_backend.calls == 1U);
    auto durable = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(durable.record.has_value());
    CHECK(durable.record->phase ==
          NdmsNativeImportWalPhase::delete_may_be_inflight);

    const auto unconfirmed = fixture.coordinator.resume_once(
        fixture.writer.lease);
    CHECK(unconfirmed.status ==
          NdmsNativeCooperativeImportResumeStatus::recovery_required);
    CHECK(unconfirmed.stop ==
          NdmsNativeCooperativeImportResumeStop::
              external_writer_race_not_accepted);
    CHECK(fixture.delete_backend.calls == 1U);

    fixture.delete_backend.apply_effect = true;
    const auto recovered = fixture.coordinator.resume_once(
        fixture.writer.lease,
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);
    CHECK(recovered.status ==
          NdmsNativeCooperativeImportResumeStatus::completed);
    CHECK(recovered.wal_removed);
    CHECK(recovered.rollback_snapshot_retired);
    CHECK(fixture.delete_backend.calls == 2U);
    check_resume_never_imports_or_saves(recovered);
}

TEST_CASE("cooperative import post-dispatch exceptions preserve recovery truth") {
    SUBCASE("transport throw after perform leaves delete-may without retry") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.delete_backend.apply_effect = false;
        fixture.delete_backend.throw_after_perform = true;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::delete_may_be_inflight});
        CHECK(result.delete_perform_started);
        CHECK(result.request_may_have_been_dispatched);
        CHECK(result.ndms_delete_dispatched);
        CHECK(result.delete_transport_outcome ==
              std::optional<NdmsNativeExactMutationResponseOutcome>{
                  NdmsNativeExactMutationResponseOutcome::
                      transport_failed});
        CHECK(fixture.delete_backend.calls == 1U);
        const auto durable = fixture.wal.load(
            *interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
        check_resume_never_imports_or_saves(result);
    }

    SUBCASE("step guard throw after confirmed delete latches recovery-required") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.gateway.after_recovery_observation =
            [&fixture](const std::size_t recovery_call) {
                if (recovery_call == 6U) {
                    fixture.maintenance->fail_verify_call =
                        fixture.maintenance->verify_calls + 5U;
                }
            };

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        REQUIRE(result.status ==
                NdmsNativeCooperativeImportResumeStatus::
                    recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::unexpected_failure);
        CHECK(result.phase ==
              std::optional<NdmsNativeImportWalPhase>{
                  NdmsNativeImportWalPhase::delete_may_be_inflight});
        CHECK(result.recovery_dispatch_state ==
              std::optional<NdmsNativeImportRecoveryDispatchState>{
                  NdmsNativeImportRecoveryDispatchState::step_failed});
        REQUIRE(result.recovery_failed_step.has_value());
        CHECK(static_cast<int>(*result.recovery_failed_step) ==
              static_cast<int>(NdmsNativeImportRecoveryStep::
                                   advance_wal_absence_verified));
        CHECK(result.delete_perform_started);
        CHECK(result.request_may_have_been_dispatched);
        CHECK(result.ndms_delete_dispatched);
        CHECK_FALSE(result.wal_removed);
        CHECK(fixture.delete_backend.calls == 1U);
        const auto durable = fixture.wal.load(
            *interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
        check_resume_never_imports_or_saves(result);
    }
}

TEST_CASE("cooperative import rollback revalidates exact state at the transport boundary") {
    SUBCASE("marker drift after admission rejects before perform") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.delete_backend.before_guard = [&fixture](std::size_t) {
            fixture.gateway.omit_runtime_marker = true;
        };

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::
                  recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  observation_unstable);
        CHECK(fixture.delete_backend.calls == 1U);
        CHECK(fixture.delete_backend.perform_calls == 0U);
        CHECK_FALSE(result.delete_perform_started);
        CHECK_FALSE(result.request_may_have_been_dispatched);
        auto durable = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
        check_resume_never_imports_or_saves(result);
    }

    SUBCASE("foreign ownership appearing after admission rejects before perform") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.delete_backend.before_guard = [&fixture](std::size_t) {
            (void)fixture.ownership.publish(target_ownership_record());
        };

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::
                  recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::ownership_not_exact);
        CHECK(fixture.delete_backend.perform_calls == 0U);
        CHECK_FALSE(result.request_may_have_been_dispatched);
        auto durable = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
        check_resume_never_imports_or_saves(result);
    }

    SUBCASE("snapshot removal after admission rejects before perform") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        const auto loaded = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(loaded.record.has_value());
        fixture.delete_backend.before_guard =
            [&fixture, record = *loaded.record](std::size_t) {
                CHECK(fixture.snapshots.remove_panel_delete_snapshot_exact(
                    record.baseline.expected_created_interface,
                    record.transaction_id,
                    record.marker,
                    record.snapshot_revision));
            };

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::
                  recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::snapshot_not_exact);
        CHECK(fixture.delete_backend.perform_calls == 0U);
        CHECK_FALSE(result.request_may_have_been_dispatched);
        auto durable = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
        check_resume_never_imports_or_saves(result);
    }

    SUBCASE("target reappearing after perform remains ambiguous") {
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        fixture.delete_backend.after_perform = [&fixture](std::size_t) {
            fixture.gateway.recovery_target_present = true;
        };

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease,
            NdmsNativeExternalWriterRaceAcceptance::owner_accepted);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::
                  recovery_required);
        CHECK(result.stop ==
              NdmsNativeCooperativeImportResumeStop::
                  delete_transport_ambiguous);
        CHECK(result.delete_perform_started);
        CHECK(result.request_may_have_been_dispatched);
        CHECK_FALSE(result.wal_removed);
        auto durable = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(durable.record.has_value());
        CHECK(durable.record->phase ==
              NdmsNativeImportWalPhase::delete_may_be_inflight);
        check_resume_never_imports_or_saves(result);
    }
}

TEST_CASE("cooperative import rollback retracts only its exact ownership claim") {
    Fixture fixture;
    fixture.faults->fail_ownership_after_publish = true;
    const auto interrupted = fixture.run();
    REQUIRE(interrupted.transaction_id.has_value());
    auto loaded = fixture.wal.load(*interrupted.transaction_id);
    REQUIRE(loaded.record.has_value());
    REQUIRE(loaded.record->phase ==
            NdmsNativeImportWalPhase::target_verified);
    fixture.faults->fail_ownership_after_publish = false;
    auto rollback = *loaded.record;
    rollback.phase = NdmsNativeImportWalPhase::rollback_requested;
    fixture.wal.publish(rollback);
    REQUIRE(fixture.ownership.read("Wireguard5").record.has_value());
    fixture.gateway.recovery_calls = 0U;
    fixture.gateway.recovery_scopes.clear();

    const auto unconfirmed = fixture.coordinator.resume_once(
        fixture.writer.lease);
    CHECK(unconfirmed.stop ==
          NdmsNativeCooperativeImportResumeStop::
              external_writer_race_not_accepted);
    CHECK(fixture.delete_backend.calls == 0U);

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease,
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted);
    CHECK(result.status ==
          NdmsNativeCooperativeImportResumeStatus::completed);
    CHECK(result.recovery_action ==
          std::optional<NdmsNativeImportRecoveryAction>{
              NdmsNativeImportRecoveryAction::
                  retry_exact_owned_delete});
    CHECK(result.wal_removed);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
    check_resume_never_imports_or_saves(result);
}

TEST_CASE("cooperative import recovery finishes stable absence from every durable rollback phase") {
    for (const auto terminal_phase : {
             NdmsNativeImportWalPhase::rollback_requested,
             NdmsNativeImportWalPhase::delete_may_be_inflight,
             NdmsNativeImportWalPhase::absence_verified}) {
        CAPTURE(ndms_native_import_wal_phase_name(terminal_phase));
        Fixture fixture;
        const auto interrupted = leave_import_may_be_inflight(fixture);
        auto loaded = fixture.wal.load(*interrupted.transaction_id);
        REQUIRE(loaded.record.has_value());
        auto current = *loaded.record;
        current.phase = NdmsNativeImportWalPhase::rollback_requested;
        fixture.wal.publish(current);
        if (terminal_phase ==
                NdmsNativeImportWalPhase::delete_may_be_inflight ||
            terminal_phase ==
                NdmsNativeImportWalPhase::absence_verified) {
            current.phase =
                NdmsNativeImportWalPhase::delete_may_be_inflight;
            fixture.wal.publish(current);
        }
        if (terminal_phase ==
            NdmsNativeImportWalPhase::absence_verified) {
            current.phase = NdmsNativeImportWalPhase::absence_verified;
            fixture.wal.publish(current);
        }
        fixture.gateway.recovery_target_present = false;

        const auto result = fixture.coordinator.resume_once(
            fixture.writer.lease);

        CHECK(result.status ==
              NdmsNativeCooperativeImportResumeStatus::completed);
        CHECK(result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::complete_rollback});
        CHECK(result.recovery_dispatch_state ==
              std::optional<NdmsNativeImportRecoveryDispatchState>{
                  NdmsNativeImportRecoveryDispatchState::completed});
        CHECK(result.rollback_snapshot_retired);
        CHECK(result.wal_removed);
        CHECK_FALSE(result.external_ndms_writer_race_accepted);
        CHECK(fixture.delete_backend.calls == 0U);
        CHECK(fixture.wal.load(*interrupted.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        check_resume_is_router_read_only(result);
    }
}

TEST_CASE("cooperative import resume shares the recovery CAS with concurrent recoverers") {
    Fixture fixture;
    const auto interrupted = leave_response_recorded(fixture);
    auto lock_path = fixture.wal.state_directory();
    lock_path += ".recovery-lock";
    HeldRecoveryLock concurrent_recoverer{lock_path};
    REQUIRE(concurrent_recoverer.held());
    const auto backend_calls_before = fixture.backend.calls;

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease);

    CHECK(result.stop ==
          NdmsNativeCooperativeImportResumeStop::
              forward_admission_failed);
    CHECK(result.forward_admission_state ==
          std::optional<NdmsNativeImportRecoveryAdmissionState>{
              NdmsNativeImportRecoveryAdmissionState::lease_busy});
    CHECK(result.created_interface ==
          std::optional<std::string>{"Wireguard5"});
    CHECK_FALSE(result.ownership_published);
    CHECK_FALSE(result.wal_removed);
    CHECK(fixture.backend.calls == backend_calls_before);
    check_response_recorded_wal(fixture, interrupted);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    check_resume_is_router_read_only(result);
}

TEST_CASE("cooperative import rejects malformed secret input before reads") {
    Fixture fixture;
    const auto result = fixture.run("not a tunnel config");

    CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
    CHECK(result.stop == NdmsNativeCooperativeImportStop::request_invalid);
    CHECK(result.request_error.has_value());
    CHECK(fixture.gateway.catalog_scopes.empty());
    CHECK(fixture.backend.calls == 0U);
}
