#include <doctest/doctest.h>

#include "keenetic/ndms_native_fresh_import_preflight.hpp"

#include "runtime/runtime_mutation_admission.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

using namespace keen_pbr3;

static_assert(!std::is_default_constructible_v<
              NdmsNativeFreshImportPreflight>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeFreshImportPreflight>);

namespace {

namespace fs = std::filesystem;

class FreshTempDirectory final {
public:
    FreshTempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() /
             "keen-pbr-fresh-preflight-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const auto* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        root = created;
    }

    ~FreshTempDirectory() {
        std::error_code error;
        fs::remove_all(root, error);
    }

    fs::path root;
};

struct FreshMaintenanceState final {
    bool held{true};
    std::uint32_t generation{61U};
};

class FreshMaintenanceLease final : public MaintenanceLease {
public:
    explicit FreshMaintenanceLease(
        std::shared_ptr<FreshMaintenanceState> state)
        : state_(std::move(state)), base_(state_->generation) {}

    std::uint32_t base_generation() const noexcept override {
        return base_;
    }

    std::uint32_t reserve(const std::uint32_t expected) override {
        if (!state_->held || expected != state_->generation ||
            state_->generation ==
                std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("synthetic fresh reserve");
        }
        return ++state_->generation;
    }

    void verify_held() override {
        if (!state_->held) {
            throw std::runtime_error("synthetic fresh writer loss");
        }
    }

private:
    std::shared_ptr<FreshMaintenanceState> state_;
    std::uint32_t base_{0U};
};

NdmsNativeWriterAdmission acquire_writer(
    const fs::path& state,
    RuntimeMutationAdmission& runtime,
    const std::shared_ptr<FreshMaintenanceState>& maintenance) {
    auto runtime_lease = runtime.try_acquire("fresh-preflight-test");
    REQUIRE(runtime_lease.has_value());
    NdmsNativeWriterLeaseTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return admit_ndms_native_writer(
        state,
        std::make_unique<FreshMaintenanceLease>(maintenance),
        std::move(*runtime_lease),
        hooks);
}

std::string base64_key(const char value) {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::string input(32U, value);
    std::string output;
    output.reserve(44U);
    for (std::size_t offset = 0U; offset < input.size(); offset += 3U) {
        const auto first = static_cast<unsigned char>(input[offset]);
        const bool second_present = offset + 1U < input.size();
        const bool third_present = offset + 2U < input.size();
        const auto second = second_present
            ? static_cast<unsigned char>(input[offset + 1U])
            : 0U;
        const auto third = third_present
            ? static_cast<unsigned char>(input[offset + 2U])
            : 0U;
        const auto block =
            (static_cast<unsigned int>(first) << 16U) |
            (static_cast<unsigned int>(second) << 8U) |
            static_cast<unsigned int>(third);
        output.push_back(alphabet[(block >> 18U) & 0x3fU]);
        output.push_back(alphabet[(block >> 12U) & 0x3fU]);
        output.push_back(second_present
                             ? alphabet[(block >> 6U) & 0x3fU]
                             : '=');
        output.push_back(third_present
                             ? alphabet[block & 0x3fU]
                             : '=');
    }
    return output;
}

std::string full_configuration() {
    return "[Interface]\nPrivateKey = " + base64_key('P') +
           "\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n\n"
           "[Peer]\nPublicKey = " + base64_key('K') +
           "\nPresharedKey = " + base64_key('S') +
           "\nEndpoint = vpn.example.test:443\n"
           "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n";
}

std::string digest(const std::string_view prefix, const char digit) {
    return std::string{prefix} + std::string(64U, digit);
}

class FakeFreshObservationGateway final
    : public NdmsNativeFreshImportPreflightObservationGateway {
public:
    NdmsNativeDirectCatalogObservation observe_catalog(
        const NdmsNativeDirectCatalogScope requested_scope)
        noexcept override {
        ++calls;
        if (before_observe) before_observe(calls);
        const bool runtime = requested_scope ==
            NdmsNativeDirectCatalogScope::runtime_state;
        NdmsNativeDirectCatalogObservation observation;
        observation.scope = scope_mismatch_call == calls
            ? (runtime
                   ? NdmsNativeDirectCatalogScope::running_config
                   : NdmsNativeDirectCatalogScope::runtime_state)
            : requested_scope;
        if (failure_call == calls) {
            observation.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
            return observation;
        }
        const auto first_free = runtime
            ? runtime_first_free
            : running_first_free;
        nlohmann::json payload = nlohmann::json::object();
        for (std::uint8_t slot = 0U; slot < first_free; ++slot) {
            const auto name = "Wireguard" + std::to_string(slot);
            payload[name] = runtime
                ? nlohmann::json{
                      {"type", "Wireguard"},
                      {"interface-name", name},
                      {"description", "occupied"},
                  }
                : nlohmann::json{
                      {"description", "occupied"},
                  };
        }
        NdmsCatalogSnapshot snapshot;
        snapshot.catalog = parse_ndms_interface_catalog(payload);
        snapshot.status = NdmsCatalogCacheStatus::fresh;
        snapshot.refreshed = !not_refreshed;
        snapshot.observed_at = std::chrono::steady_clock::time_point{
            std::chrono::seconds{456}};
        if (unsafe_call == calls) {
            snapshot.catalog.wireguard_slots[first_free].state =
                NdmsWireguardCatalogSlotState::unsafe;
        }
        observation.snapshot = std::move(snapshot);
        observation.failure = NdmsNativeDirectObservationFailure::none;
        return observation;
    }

    std::uint8_t runtime_first_free{5U};
    std::uint8_t running_first_free{5U};
    std::size_t calls{0U};
    std::size_t failure_call{0U};
    std::size_t scope_mismatch_call{0U};
    std::size_t unsafe_call{0U};
    bool not_refreshed{false};
    std::function<void(std::size_t)> before_observe;
};

class FakeFreshDependencyProvider final
    : public NdmsNativeKeenPbrDependencyProvider {
public:
    NdmsNativeKeenPbrDependencyObservation observe_dependencies(
        const std::string& firmware_interface_name,
        const std::optional<std::string>& kernel_interface_name)
        noexcept override {
        ++calls;
        observed_kernel_names.push_back(
            kernel_interface_name.value_or(std::string{}));
        if (before_observe) {
            before_observe(
                calls, firmware_interface_name, kernel_interface_name);
        }
        NdmsNativeKeenPbrDependencyObservation observation;
        observation.complete = complete;
        observation.firmware_interface_name = firmware_interface_name;
        observation.kernel_interface_name = kernel_interface_name;
        observation.references = references;
        try {
            observation.keen_pbr_dependency_revision =
                ndms_native_keen_pbr_dependency_revision(observation);
        } catch (...) {
            observation.complete = false;
        }
        return observation;
    }

    bool complete{true};
    std::vector<NdmsNativeKeenPbrDependency> references;
    std::size_t calls{0U};
    std::vector<std::string> observed_kernel_names;
    std::function<void(
        std::size_t,
        const std::string&,
        const std::optional<std::string>&)> before_observe;
};

class FakeFreshKernelInventory final
    : public NdmsNativeFreshImportKernelInventoryGateway {
public:
    NdmsNativeFreshImportKernelInventory observe() noexcept override {
        ++calls;
        if (before_observe) before_observe(calls);
        return {complete, names};
    }

    bool complete{true};
    std::vector<std::string> names{"lo"};
    std::size_t calls{0U};
    std::function<void(std::size_t)> before_observe;
};

struct FreshSnapshotFaultControl final {
    bool fail_absence_fsync{false};
    std::size_t absence_checks{0U};
    std::function<void(std::size_t)> before_absence_fsync;
};

NdmsNativeImportWalStoreTestHooks import_hooks() {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

NdmsNativeDeleteWalStoreTestHooks delete_hooks() {
    NdmsNativeDeleteWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.force_portable_linkat = true;
    return hooks;
}

NdmsNativeOwnershipStoreTestHooks ownership_hooks() {
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

NdmsNativeSecretSnapshotStoreTestHooks snapshot_hooks(
    const std::shared_ptr<FreshSnapshotFaultControl>& faults) {
    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](const auto stage) {
        if (faults->fail_absence_fsync &&
            stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         absence_directory_fsync) {
            throw std::runtime_error("synthetic absence fsync fault");
        }
        if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         absence_directory_fsync) {
            ++faults->absence_checks;
            if (faults->before_absence_fsync) {
                faults->before_absence_fsync(
                    faults->absence_checks);
            }
        }
    };
    return hooks;
}

struct FreshFixture final {
    FreshFixture()
        : maintenance(std::make_shared<FreshMaintenanceState>()),
          snapshot_faults(
              std::make_shared<FreshSnapshotFaultControl>()),
          writer(acquire_writer(
              directory.root / "native-writer", runtime, maintenance)),
          import_wal(directory.root / "import-wal", import_hooks()),
          delete_wal(directory.root / "delete-wal", delete_hooks()),
          ownership(directory.root / "ownership", ownership_hooks()),
          snapshots(
              directory.root / "keys" / "snapshot.key",
              directory.root / "snapshots",
              snapshot_hooks(snapshot_faults)),
          preflight(NdmsNativeFreshImportPreflightTestIssuer::issue(
              import_wal,
              delete_wal,
              ownership,
              snapshots,
              dependencies,
              gateway,
              kernel_inventory)) {
        REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
    }

    void publish_orphan_snapshot() {
        const std::string transaction(32U, 'a');
        const std::string marker = "kpbr-ni-v1-" + transaction;
        auto snapshot = make_ndms_native_panel_delete_snapshot(
            full_configuration(), marker);
        snapshots.publish_panel_delete_snapshot(
            "Wireguard5", transaction, marker, std::move(snapshot));
    }

    void publish_retained_tombstone() {
        NdmsNativeOwnershipRecord active;
        active.interface_name = "Wireguard5";
        active.transaction_id = std::string(32U, 'b');
        active.marker = "kpbr-ni-v1-" + active.transaction_id;
        active.snapshot_revision =
            digest("ndms-native-import-v1-", 'c');
        active.target_full_revision =
            digest("ndms-rci-full-v1-", 'd');
        ownership.publish(active);
        auto tombstone = active;
        tombstone.schema_version =
            kNdmsNativeOwnershipTombstoneSchemaVersion;
        tombstone.lifecycle = NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified;
        tombstone.lifecycle_evidence =
            NdmsNativeOwnershipLifecycleEvidence{
                std::string(32U, 'e'),
                {std::string(32U, 'f'), 5U, 6U},
                digest("ndms-native-catalog-v1-", '1'),
                7U,
                digest("ndms-native-catalog-v1-", '2'),
                8U,
                std::string{"nwg5"},
            };
        REQUIRE(ownership.replace_exact(active, tombstone).has_value());
    }

    FreshTempDirectory directory;
    RuntimeMutationAdmission runtime;
    std::shared_ptr<FreshMaintenanceState> maintenance;
    std::shared_ptr<FreshSnapshotFaultControl> snapshot_faults;
    NdmsNativeWriterAdmission writer;
    NdmsNativeImportWalStore import_wal;
    NdmsNativeDeleteWalStore delete_wal;
    NdmsNativeOwnershipStore ownership;
    NdmsNativeSecretSnapshotStore snapshots;
    FakeFreshDependencyProvider dependencies;
    FakeFreshObservationGateway gateway;
    FakeFreshKernelInventory kernel_inventory;
    NdmsNativeFreshImportPreflight preflight;
};

void simulate_sensitive_continuation(
    const NdmsNativeFreshImportPreflightResult& outcome,
    std::size_t& body_takes,
    std::size_t& dispatches) {
    if (!outcome.secret_body_may_be_taken()) return;
    ++body_takes;
    ++dispatches;
}

void require_no_sensitive_continuation(
    FreshFixture& fixture,
    const NdmsNativeFreshImportPreflightStop expected_stop) {
    std::size_t body_takes = 0U;
    std::size_t dispatches = 0U;
    const auto outcome = fixture.preflight.check_before_secret_take(
        fixture.writer.lease);
    simulate_sensitive_continuation(outcome, body_takes, dispatches);
    CHECK(outcome.stop == expected_stop);
    CHECK_FALSE(outcome.secret_body_may_be_taken());
    CHECK(body_takes == 0U);
    CHECK(dispatches == 0U);
}

} // namespace

TEST_CASE("fresh preflight admits only a clean exact stock first-free target") {
    FreshFixture fixture;
    std::size_t body_takes = 0U;
    std::size_t dispatches = 0U;
    const auto outcome = fixture.preflight.check_before_secret_take(
        fixture.writer.lease);
    simulate_sensitive_continuation(outcome, body_takes, dispatches);
    CHECK(outcome.status ==
          NdmsNativeFreshImportPreflightStatus::admitted);
    CHECK(outcome.stop == NdmsNativeFreshImportPreflightStop::none);
    CHECK(outcome.expected_first_free_target ==
          std::optional<std::string>{"Wireguard5"});
    CHECK(outcome.secret_body_may_be_taken());
    CHECK(body_takes == 1U);
    CHECK(dispatches == 1U);
    CHECK(fixture.gateway.calls == 4U);
    CHECK(fixture.kernel_inventory.calls == 2U);
    CHECK(fixture.dependencies.observed_kernel_names ==
          (std::vector<std::string>{
              "Wireguard5", "nwg5", "Wireguard5", "nwg5"}));
    CHECK(fixture.snapshot_faults->absence_checks == 2U);
}

TEST_CASE("first-free retained ownership blocks before secret take") {
    FreshFixture fixture;
    fixture.publish_retained_tombstone();
    require_no_sensitive_continuation(
        fixture,
        NdmsNativeFreshImportPreflightStop::
            first_free_target_retains_ownership);
}

TEST_CASE("first-free snapshot artifacts block before body or dispatch") {
    FreshFixture fixture;

    SUBCASE("bound orphan snapshot without a claim") {
        fixture.publish_orphan_snapshot();
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_snapshot_absence_unproven);
    }
    SUBCASE("unreadable published target file") {
        const auto state = fixture.directory.root / "snapshots";
        REQUIRE(fs::create_directories(state));
        REQUIRE(::chmod(state.c_str(), 0700) == 0);
        {
            std::ofstream output(
                state / "Wireguard5", std::ios::binary);
            output << "not-an-encrypted-snapshot";
        }
        REQUIRE(::chmod((state / "Wireguard5").c_str(), 0600) == 0);
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_snapshot_absence_unproven);
    }
    SUBCASE("foreign or malformed temporary makes the store unsafe") {
        const auto state = fixture.directory.root / "snapshots";
        REQUIRE(fs::create_directories(state));
        REQUIRE(::chmod(state.c_str(), 0700) == 0);
        {
            std::ofstream output(
                state / ".keen-pbr-secret-snapshot.invalid",
                std::ios::binary);
            output << "temporary";
        }
        REQUIRE(::chmod(
                    (state / ".keen-pbr-secret-snapshot.invalid").c_str(),
                    0600) == 0);
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_snapshot_absence_unproven);
    }
    SUBCASE("absence directory fsync failure is not absence proof") {
        fixture.snapshot_faults->fail_absence_fsync = true;
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_snapshot_absence_unproven);
    }
}

TEST_CASE("fresh preflight requires coherent fresh dual-scope allocation") {
    FreshFixture fixture;

    SUBCASE("runtime and running configuration disagree") {
        fixture.gateway.running_first_free = 6U;
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_scope_mismatch);
    }
    SUBCASE("stock first-free is protected") {
        fixture.gateway.runtime_first_free = 0U;
        fixture.gateway.running_first_free = 0U;
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_target_not_managed);
    }
    SUBCASE("an unsafe slot refuses the complete catalog") {
        fixture.gateway.unsafe_call = 1U;
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                observed_catalog_unsafe);
    }
    SUBCASE("a writer lost during preflight never admits body take") {
        fixture.maintenance->held = false;
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::writer_lost);
    }
}

TEST_CASE("fresh preflight rejects every possible stale live identity") {
    FreshFixture fixture;

    SUBCASE("the firmware-shaped kernel identity is still live") {
        fixture.kernel_inventory.names = {"Wireguard5", "lo"};
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_kernel_identity_present);
    }
    SUBCASE("the protocol kernel identity is still live") {
        fixture.kernel_inventory.names = {"lo", "nwg5"};
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_kernel_identity_present);
    }
}

TEST_CASE("fresh preflight rejects incomplete or unsafe kernel inventory") {
    FreshFixture fixture;

    SUBCASE("enumeration is incomplete") {
        fixture.kernel_inventory.complete = false;
    }
    SUBCASE("enumeration contains a duplicate") {
        fixture.kernel_inventory.names = {"lo", "lo"};
    }
    SUBCASE("enumeration contains an unsafe name") {
        fixture.kernel_inventory.names = {"bad/name"};
    }
    SUBCASE("enumeration exceeds its explicit bound") {
        fixture.kernel_inventory.names =
            std::vector<std::string>(4097U, "lo");
    }
    require_no_sensitive_continuation(
        fixture,
        NdmsNativeFreshImportPreflightStop::
            kernel_inventory_unavailable);
}

TEST_CASE("fresh preflight rejects dependencies for both candidate names") {
    FreshFixture fixture;

    SUBCASE("the firmware name is referenced") {
        fixture.dependencies.before_observe =
            [&fixture](
                const std::size_t,
                const std::string&,
                const std::optional<std::string>& kernel_name) {
                if (kernel_name ==
                    std::optional<std::string>{"Wireguard5"}) {
                    fixture.dependencies.references.push_back({
                        NdmsNativeKeenPbrDependencyKind::
                            interface_outbound,
                        "active:outbound:firmware"});
                }
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                keen_pbr_dependencies_present);
    }
    SUBCASE("the protocol kernel name is referenced") {
        fixture.dependencies.before_observe =
            [&fixture](
                const std::size_t,
                const std::string&,
                const std::optional<std::string>& kernel_name) {
                if (kernel_name ==
                    std::optional<std::string>{"nwg5"}) {
                    fixture.dependencies.references.push_back({
                        NdmsNativeKeenPbrDependencyKind::
                            interface_outbound,
                        "active:outbound:kernel"});
                }
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                keen_pbr_dependencies_present);
    }
    SUBCASE("the bounded dependency projection is incomplete") {
        fixture.dependencies.complete = false;
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                keen_pbr_dependency_scan_incomplete);
    }
}

TEST_CASE("fresh preflight rechecks every boundary after snapshot proof") {
    FreshFixture fixture;

    SUBCASE("an import WAL residue appears") {
        fixture.snapshot_faults->before_absence_fsync =
            [&fixture](const std::size_t check) {
                if (check != 1U) return;
                const auto state = fixture.import_wal.state_directory();
                fs::create_directories(state);
                ::chmod(state.c_str(), 0700);
                std::ofstream output(
                    state / "FOREIGN", std::ios::binary);
                output << "external import residue";
                output.close();
                ::chmod((state / "FOREIGN").c_str(), 0600);
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::import_wal_unsafe);
    }
    SUBCASE("a delete WAL residue appears") {
        fixture.snapshot_faults->before_absence_fsync =
            [&fixture](const std::size_t check) {
                if (check != 1U) return;
                const auto state = fixture.delete_wal.state_directory();
                fs::create_directories(state);
                ::chmod(state.c_str(), 0700);
                std::ofstream output(
                    state / kNdmsNativeDeleteWalFilename,
                    std::ios::binary);
                output << "not-a-delete-wal";
                output.close();
                ::chmod(
                    (state / kNdmsNativeDeleteWalFilename).c_str(),
                    0600);
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::delete_wal_unsafe);
    }
    SUBCASE("the stock first-free slot changes") {
        fixture.gateway.before_observe =
            [&fixture](const std::size_t call) {
                if (call == 3U) {
                    fixture.gateway.runtime_first_free = 6U;
                    fixture.gateway.running_first_free = 6U;
                }
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_scope_mismatch);
    }
    SUBCASE("a candidate kernel identity appears") {
        fixture.kernel_inventory.before_observe =
            [&fixture](const std::size_t call) {
                if (call == 2U) {
                    fixture.kernel_inventory.names = {"lo", "nwg5"};
                }
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_kernel_identity_present);
    }
    SUBCASE("a dependency appears") {
        fixture.dependencies.before_observe =
            [&fixture](
                const std::size_t call,
                const std::string&,
                const std::optional<std::string>&) {
                if (call == 3U) {
                    fixture.dependencies.references.push_back({
                        NdmsNativeKeenPbrDependencyKind::
                            interface_outbound,
                        "active:outbound:late"});
                }
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                keen_pbr_dependencies_present);
    }
    SUBCASE("an ownership claim appears") {
        fixture.snapshot_faults->before_absence_fsync =
            [&fixture](const std::size_t check) {
                if (check == 1U) fixture.publish_retained_tombstone();
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_target_retains_ownership);
    }
    SUBCASE("a snapshot artifact appears at the final proof") {
        fixture.snapshot_faults->before_absence_fsync =
            [&fixture](const std::size_t check) {
                if (check != 2U) return;
                const auto state = fixture.directory.root / "snapshots";
                std::ofstream output(
                    state / "Wireguard5", std::ios::binary);
                output << "external-reappearance";
                output.close();
                ::chmod((state / "Wireguard5").c_str(), 0600);
            };
        require_no_sensitive_continuation(
            fixture,
            NdmsNativeFreshImportPreflightStop::
                first_free_snapshot_absence_unproven);
    }
}

TEST_CASE("bounded ownership inventory failure blocks exact first-free") {
    FreshFixture fixture;
    const auto state = fixture.directory.root / "ownership";
    REQUIRE(fs::create_directories(state));
    REQUIRE(::chmod(state.c_str(), 0700) == 0);
    {
        std::ofstream output(state / "foreign-object", std::ios::binary);
        output << "foreign";
    }
    REQUIRE(::chmod((state / "foreign-object").c_str(), 0600) == 0);
    require_no_sensitive_continuation(
        fixture,
        NdmsNativeFreshImportPreflightStop::
            ownership_inventory_unreadable);
}

TEST_CASE("fresh preflight names are stable") {
    CHECK(std::string{ndms_native_fresh_import_preflight_status_name(
              NdmsNativeFreshImportPreflightStatus::admitted)} ==
          "admitted");
    CHECK(std::string{ndms_native_fresh_import_preflight_stop_name(
              NdmsNativeFreshImportPreflightStop::
                  first_free_snapshot_absence_unproven)} ==
          "first_free_snapshot_absence_unproven");
}
