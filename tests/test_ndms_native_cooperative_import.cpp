#include <doctest/doctest.h>

#include "keenetic/ndms_native_cooperative_import.hpp"
#include "keenetic/ndms_native_import_identity.hpp"

#include "runtime/runtime_mutation_admission.hpp"

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
        if (!state_->held) {
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
    const std::optional<std::string>& marker = std::nullopt) {
    auto payload = nlohmann::json::object();
    for (const auto slot : occupied) {
        const auto name = "Wireguard" + std::to_string(slot);
        payload[name] = {
            {"type",
             marker.has_value() && slot == 5U
                 ? "Wireguard"
                 : "Bridge"},
            {"interface-name", name},
            {"description",
             marker.has_value() && slot == 5U
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
    const std::optional<std::string>& marker = std::nullopt) {
    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(
        catalog_payload(occupied, marker));
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
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept override {
        ++recovery_calls;
        NdmsNativeDirectRecoveryObservation result;
        if (fail_recovery_call == recovery_calls ||
            !expected_target.has_value()) {
            result.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
            return result;
        }
        result.snapshot = snapshot_for(
            {0U, 1U, 2U, 3U, 4U, 5U, 6U}, marker);
        const auto revision_digit =
            drift_second && recovery_calls == 2U ? 'b' : 'a';
        result.target_evidence.push_back(
            {*expected_target,
             true,
             "ndms-rci-full-v1-" +
                 std::string(64U, revision_digit)});
        result.target_protocols.push_back(
            {*expected_target, protocol});
        result.catalog_revision =
            ndms_native_import_recovery_catalog_revision(
                result.snapshot->catalog, result.target_evidence);
        result.failure = NdmsNativeDirectObservationFailure::none;
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
    std::optional<NdmsNativeDirectCatalogScope> fail_catalog_scope;
    std::size_t recovery_calls{0U};
    std::vector<NdmsNativeDirectCatalogScope> catalog_scopes;
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
            R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])"));
        return response;
    }

public:
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    bool saw_secret_body{false};
};

class FakeClock final : public NdmsNativeImportExecutorClock {
public:
    NdmsNativeAllocatorMonotonicTime now() const noexcept override {
        return NdmsNativeAllocatorMonotonicTime{
            std::chrono::seconds{1000}};
    }
};

struct FaultControl final {
    bool fail_snapshot_before_publish{false};
    bool fail_ownership_after_publish{false};
    bool fail_wal_remove{false};
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
        if (faults->fail_snapshot_before_publish &&
            stage == NdmsNativeSecretSnapshotStoreFaultStage::
                pre_publish_after_file_fsync) {
            throw std::runtime_error("synthetic snapshot crash");
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
    Fixture()
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
                  clock)) {
        REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
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
    FakeClock clock;
    NdmsNativeCooperativeImportCoordinator coordinator;
};

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
    REQUIRE(result.expected_interface ==
            std::optional<std::string>{"Wireguard5"});
    REQUIRE(result.kind == std::optional<NdmsNativeTunnelImportKind>{
                               NdmsNativeTunnelImportKind::wireguard});
    CHECK(fixture.backend.calls == 1U);
    CHECK(fixture.backend.perform_calls == 1U);
    CHECK(fixture.backend.saw_secret_body);
    CHECK(fixture.gateway.recovery_calls == 2U);
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

TEST_CASE("cooperative import failure matrix retains exact recovery phase") {
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

TEST_CASE("cooperative import rejects malformed secret input before reads") {
    Fixture fixture;
    const auto result = fixture.run("not a tunnel config");

    CHECK(result.status == NdmsNativeCooperativeImportStatus::blocked);
    CHECK(result.stop == NdmsNativeCooperativeImportStop::request_invalid);
    CHECK(result.request_error.has_value());
    CHECK(fixture.gateway.catalog_scopes.empty());
    CHECK(fixture.backend.calls == 0U);
}
