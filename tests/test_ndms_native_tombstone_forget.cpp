#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_recovery_probe.hpp"
#include "keenetic/ndms_native_tombstone_forget.hpp"

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
              NdmsNativeTombstoneForgetCoordinator>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeTombstoneForgetCoordinator>);

namespace {

namespace fs = std::filesystem;

class ForgetTempDirectory final {
public:
    ForgetTempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() /
             "keen-pbr-tombstone-forget-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const auto* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        root = created;
    }

    ~ForgetTempDirectory() {
        std::error_code error;
        fs::remove_all(root, error);
    }

    fs::path root;
};

struct ForgetMaintenanceState final {
    bool held{true};
    std::uint32_t generation{51U};
};

class ForgetMaintenanceLease final : public MaintenanceLease {
public:
    explicit ForgetMaintenanceLease(
        std::shared_ptr<ForgetMaintenanceState> state)
        : state_(std::move(state)), base_(state_->generation) {}

    std::uint32_t base_generation() const noexcept override {
        return base_;
    }

    std::uint32_t reserve(const std::uint32_t expected) override {
        if (!state_->held || expected != state_->generation ||
            state_->generation ==
                std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("synthetic forget reserve");
        }
        return ++state_->generation;
    }

    void verify_held() override {
        if (!state_->held) {
            throw std::runtime_error("synthetic forget writer loss");
        }
    }

private:
    std::shared_ptr<ForgetMaintenanceState> state_;
    std::uint32_t base_{0U};
};

NdmsNativeWriterAdmission acquire_writer(
    const fs::path& state,
    RuntimeMutationAdmission& runtime,
    const std::shared_ptr<ForgetMaintenanceState>& maintenance) {
    auto runtime_lease = runtime.try_acquire("tombstone-forget-test");
    REQUIRE(runtime_lease.has_value());
    NdmsNativeWriterLeaseTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return admit_ndms_native_writer(
        state,
        std::make_unique<ForgetMaintenanceLease>(maintenance),
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

std::string full_configuration(const char address_digit = '8') {
    return "[Interface]\nPrivateKey = " + base64_key('P') +
           "\nAddress = 10." + std::string(1U, address_digit) +
           ".0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = " +
           base64_key('K') + "\nPresharedKey = " + base64_key('S') +
           "\nEndpoint = vpn.example.test:443\n"
           "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n";
}

std::string digest(const std::string_view prefix, const char digit) {
    return std::string{prefix} + std::string(64U, digit);
}

class FakeForgetObservationGateway final
    : public NdmsNativeTombstoneForgetObservationGateway {
public:
    NdmsNativeDirectRecoveryObservation observe_recovery(
        const NdmsNativeDirectCatalogScope scope,
        const std::string& requested_marker,
        const std::optional<std::string>& expected_target)
        noexcept override {
        ++calls;
        if (before_observe) before_observe(calls);
        NdmsNativeDirectRecoveryObservation result;
        result.requested_catalog_scope = scope;
        result.catalog_scope = scope_mismatch_call == calls
            ? (scope == NdmsNativeDirectCatalogScope::runtime_state
                   ? NdmsNativeDirectCatalogScope::running_config
                   : NdmsNativeDirectCatalogScope::runtime_state)
            : scope;
        if (failure_call == calls || requested_marker != marker ||
            expected_target !=
                std::optional<std::string>{interface_name}) {
            result.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
            return result;
        }

        nlohmann::json payload = nlohmann::json::object();
        for (std::uint8_t slot = 0U; slot <= 4U; ++slot) {
            const auto name = "Wireguard" + std::to_string(slot);
            payload[name] = {
                {"type", "Wireguard"},
                {"interface-name", name},
                {"description", "foreign"},
            };
        }
        const bool target_present =
            target_present_call == 0U || target_present_call == calls;
        if (target_present) {
            payload[interface_name] = {
                {"type", "Wireguard"},
                {"interface-name", interface_name},
                {"description", "external"},
            };
        }
        const bool marker_present =
            marker_present_call != 0U && marker_present_call == calls;
        if (marker_present) {
            payload["Wireguard6"] = {
                {"type", "Wireguard"},
                {"interface-name", "Wireguard6"},
                {"description", marker},
            };
        }
        NdmsCatalogSnapshot snapshot;
        snapshot.catalog = parse_ndms_interface_catalog(payload);
        snapshot.status = NdmsCatalogCacheStatus::fresh;
        snapshot.refreshed = true;
        snapshot.observed_at = std::chrono::steady_clock::time_point{
            std::chrono::seconds{321}};
        result.snapshot = std::move(snapshot);
        result.catalog_revision =
            ndms_native_import_recovery_catalog_revision(
                result.snapshot->catalog, result.target_evidence);
        result.failure = NdmsNativeDirectObservationFailure::none;
        return result;
    }

    std::string interface_name{"Wireguard5"};
    std::string marker;
    std::size_t calls{0U};
    std::size_t failure_call{0U};
    std::size_t scope_mismatch_call{0U};
    std::size_t target_present_call{99U};
    std::size_t marker_present_call{0U};
    std::function<void(std::size_t)> before_observe;
};

class FakeForgetDependencyProvider final
    : public NdmsNativeKeenPbrDependencyProvider {
public:
    NdmsNativeKeenPbrDependencyObservation observe_dependencies(
        const std::string& firmware_interface_name,
        const std::optional<std::string>& kernel_interface_name)
        noexcept override {
        ++calls;
        if (before_observe) before_observe(calls);
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
    std::function<void(std::size_t)> before_observe;
};

class FakeForgetKernelInventory final
    : public NdmsNativeTombstoneForgetKernelInventoryGateway {
public:
    NdmsNativeTombstoneForgetKernelInventory observe() noexcept override {
        ++calls;
        if (before_observe) before_observe(calls);
        return {complete, names};
    }

    bool complete{true};
    std::vector<std::string> names{"lo"};
    std::size_t calls{0U};
    std::function<void(std::size_t)> before_observe;
};

struct ForgetFaultControl final {
    bool snapshot_throw_after_unlink{false};
    bool ownership_throw_before_recheck{false};
    bool lose_writer_after_snapshot_unlink{false};
    std::function<void()> after_snapshot_unlink;
    std::shared_ptr<ForgetMaintenanceState> maintenance;
    std::vector<std::string> events;
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

NdmsNativeSecretSnapshotStoreTestHooks snapshot_hooks(
    const std::shared_ptr<ForgetFaultControl>& faults) {
    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](const auto stage) {
        if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         post_unlink_directory_fsync) {
            faults->events.push_back("snapshot.unlink.visible");
            if (faults->after_snapshot_unlink) {
                faults->after_snapshot_unlink();
            }
            if (faults->lose_writer_after_snapshot_unlink) {
                faults->maintenance->held = false;
            }
            if (faults->snapshot_throw_after_unlink) {
                throw std::runtime_error("synthetic snapshot unlink crash");
            }
        }
    };
    return hooks;
}

NdmsNativeOwnershipStoreTestHooks ownership_hooks(
    const std::shared_ptr<ForgetFaultControl>& faults) {
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](const auto stage) {
        if (stage == NdmsNativeOwnershipStoreFaultStage::
                         before_remove_inode_recheck &&
            faults->ownership_throw_before_recheck) {
            throw std::runtime_error("synthetic tombstone CAS crash");
        }
        if (stage == NdmsNativeOwnershipStoreFaultStage::
                         post_unlink_directory_fsync) {
            faults->events.push_back("tombstone.unlink.visible");
        }
    };
    return hooks;
}

struct ForgetFixture final {
    ForgetFixture()
        : maintenance(std::make_shared<ForgetMaintenanceState>()),
          faults(std::make_shared<ForgetFaultControl>()),
          writer(acquire_writer(
              directory.root / "native-writer", runtime, maintenance)),
          import_wal(directory.root / "import-wal", import_hooks()),
          delete_wal(directory.root / "delete-wal", delete_hooks()),
          snapshots(
              directory.root / "keys" / "snapshot.key",
              directory.root / "snapshots",
              snapshot_hooks(faults)),
          ownership(
              directory.root / "ownership",
              ownership_hooks(faults)),
          coordinator(
              NdmsNativeTombstoneForgetCoordinatorTestIssuer::issue(
                  import_wal,
                  delete_wal,
                  snapshots,
                  ownership,
                  dependencies,
                  gateway,
                  kernel_inventory)) {
        REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
        faults->maintenance = maintenance;
        REQUIRE(fs::create_directories(import_wal.state_directory()));
        REQUIRE(::chmod(import_wal.state_directory().c_str(), 0700) == 0);
        install_tombstone();
    }

    void install_tombstone() {
        active.interface_name = "Wireguard5";
        active.transaction_id = std::string(32U, 'c');
        active.marker = "kpbr-ni-v1-" + active.transaction_id;
        active.kind = NdmsNativeTunnelImportKind::wireguard;
        auto snapshot = make_ndms_native_panel_delete_snapshot(
            full_configuration(), active.marker);
        active.snapshot_revision =
            std::string{snapshot.canonical_revision()};
        active.target_full_revision =
            digest("ndms-rci-full-v1-", 'b');
        snapshots.publish_panel_delete_snapshot(
            active.interface_name,
            active.transaction_id,
            active.marker,
            std::move(snapshot));
        ownership.publish(active);

        tombstone = active;
        tombstone.schema_version =
            kNdmsNativeOwnershipTombstoneSchemaVersion;
        tombstone.lifecycle = NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified;
        tombstone.lifecycle_evidence =
            NdmsNativeOwnershipLifecycleEvidence{
                std::string(32U, 'd'),
                {std::string(32U, 'e'), 7U, 8U},
                digest("ndms-native-catalog-v1-", '1'),
                9U,
                digest("ndms-native-catalog-v1-", '2'),
                10U,
                std::string{"nwg5"},
            };
        const auto revision = ownership.replace_exact(active, tombstone);
        REQUIRE(revision.has_value());
        tombstone_revision = *revision;
        gateway.marker = tombstone.marker;
    }

    NdmsNativeTombstoneForgetRequest request() const {
        NdmsNativeTombstoneForgetRequest value;
        value.interface_name = tombstone.interface_name;
        value.confirmed_interface_name = tombstone.interface_name;
        value.expected_ownership_revision = tombstone_revision;
        value.exact_name_confirmation =
            NdmsNativeTombstoneExactNameConfirmation::confirmed;
        value.rollback_discard =
            NdmsNativeTombstoneRollbackDiscardAcknowledgement::
                permanently_discard_rollback_data;
        value.foreign_reappearance =
            NdmsNativeTombstoneForeignReappearanceAcknowledgement::
                accepted_reappearance_is_foreign;
        return value;
    }

    bool snapshot_retained() {
        const auto read = snapshots.read_panel_delete_snapshot(
            tombstone.interface_name,
            tombstone.transaction_id,
            tombstone.marker);
        return read.state == NdmsNativeSecretReadState::valid &&
               read.snapshot.has_value() &&
               read.snapshot->canonical_revision() ==
                   tombstone.snapshot_revision;
    }

    ForgetTempDirectory directory;
    RuntimeMutationAdmission runtime;
    std::shared_ptr<ForgetMaintenanceState> maintenance;
    std::shared_ptr<ForgetFaultControl> faults;
    NdmsNativeWriterAdmission writer;
    NdmsNativeImportWalStore import_wal;
    NdmsNativeDeleteWalStore delete_wal;
    NdmsNativeSecretSnapshotStore snapshots;
    NdmsNativeOwnershipStore ownership;
    FakeForgetDependencyProvider dependencies;
    FakeForgetObservationGateway gateway;
    FakeForgetKernelInventory kernel_inventory;
    NdmsNativeOwnershipRecord active;
    NdmsNativeOwnershipRecord tombstone;
    std::string tombstone_revision;
    NdmsNativeTombstoneForgetCoordinator coordinator;
};

void require_recovery_anchor(
    ForgetFixture& fixture,
    const NdmsNativeTombstoneForgetStop expected_stop) {
    const auto outcome = fixture.coordinator.forget_once(
        fixture.writer.lease, fixture.request());
    CHECK(outcome.status ==
          NdmsNativeTombstoneForgetStatus::recovery_required);
    CHECK(outcome.stop == expected_stop);
    CHECK(outcome.snapshot_state ==
          NdmsNativeTombstoneForgetArtifactState::absent_durable);
    CHECK(outcome.tombstone_state ==
          NdmsNativeTombstoneForgetArtifactState::retained);
    CHECK_FALSE(outcome.router_mutation_attempted);
    CHECK_FALSE(outcome.system_configuration_save_acknowledged);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
    CHECK_FALSE(fixture.snapshot_retained());
}

} // namespace

TEST_CASE("tombstone forget discards snapshot before exact ownership CAS") {
    ForgetFixture fixture;
    const auto outcome = fixture.coordinator.forget_once(
        fixture.writer.lease, fixture.request());
    CHECK(outcome.status == NdmsNativeTombstoneForgetStatus::forgotten);
    CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::none);
    CHECK(outcome.snapshot_state ==
          NdmsNativeTombstoneForgetArtifactState::absent_durable);
    CHECK(outcome.tombstone_state ==
          NdmsNativeTombstoneForgetArtifactState::absent_durable);
    CHECK_FALSE(outcome.router_mutation_attempted);
    CHECK_FALSE(outcome.system_configuration_save_acknowledged);
    CHECK(outcome.future_reappearance_is_foreign);
    CHECK(fixture.faults->events ==
          (std::vector<std::string>{
              "snapshot.unlink.visible",
              "tombstone.unlink.visible"}));
    CHECK(fixture.gateway.calls == 4U);
    CHECK(fixture.dependencies.calls == 2U);
    CHECK(fixture.kernel_inventory.calls == 2U);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    CHECK_FALSE(fixture.snapshot_retained());
}

TEST_CASE("forget confirmations and exact revision fail before retirement") {
    ForgetFixture fixture;
    auto request = fixture.request();

    SUBCASE("typed exact-name confirmation is required") {
        request.confirmed_interface_name = "Wireguard6";
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, request);
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              exact_name_not_confirmed);
    }
    SUBCASE("rollback discard warning is required") {
        request.rollback_discard =
            NdmsNativeTombstoneRollbackDiscardAcknowledgement::
                not_acknowledged;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, request);
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              rollback_discard_not_acknowledged);
    }
    SUBCASE("stale opaque revision is rejected") {
        request.expected_ownership_revision =
            "ndms-native-owner-tombstone-v1-" +
            std::string(64U, '0');
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, request);
        CHECK(outcome.stop ==
              NdmsNativeTombstoneForgetStop::ownership_changed);
    }
    CHECK(fixture.gateway.calls == 0U);
    CHECK(fixture.snapshot_retained());
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("forget requires clean journals dependencies and dual absence") {
    ForgetFixture fixture;

    SUBCASE("an absent import WAL directory is not retirement authority") {
        std::error_code error;
        fs::remove_all(fixture.import_wal.state_directory(), error);
        REQUIRE(!error);
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              import_wal_not_authoritatively_clean);
        CHECK(fixture.gateway.calls == 0U);
    }
    SUBCASE("a config dependency retains all evidence") {
        fixture.dependencies.references.push_back({
            NdmsNativeKeenPbrDependencyKind::interface_outbound,
            "active:outbound:wg"});
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              keen_pbr_dependencies_present);
    }
    SUBCASE("the retained kernel identity is still live") {
        fixture.kernel_inventory.names = {"lo", "nwg5"};
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              retained_kernel_interface_present);
    }
    SUBCASE("an incomplete kernel inventory retains all evidence") {
        fixture.kernel_inventory.complete = false;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              kernel_inventory_unavailable);
    }
    SUBCASE("runtime reappearance blocks local retirement") {
        fixture.gateway.target_present_call = 1U;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              observed_target_present);
    }
    SUBCASE("running-config marker reappearance blocks retirement") {
        fixture.gateway.target_present_call = 99U;
        fixture.gateway.marker_present_call = 2U;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              observed_marker_present);
    }
    CHECK(fixture.snapshot_retained());
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("forget rechecks all destructive-boundary evidence") {
    ForgetFixture fixture;
    fixture.gateway.target_present_call = 99U;

    SUBCASE("an import WAL residue appears after snapshot retirement") {
        fixture.faults->after_snapshot_unlink = [&fixture] {
            const auto state = fixture.import_wal.state_directory();
            std::ofstream output(
                state / "FOREIGN", std::ios::binary);
            output << "external import residue";
            output.close();
            ::chmod((state / "FOREIGN").c_str(), 0600);
        };
        require_recovery_anchor(
            fixture,
            NdmsNativeTombstoneForgetStop::
                import_wal_not_authoritatively_clean);
    }
    SUBCASE("a delete WAL residue appears after snapshot retirement") {
        fixture.faults->after_snapshot_unlink = [&fixture] {
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
        require_recovery_anchor(
            fixture,
            NdmsNativeTombstoneForgetStop::delete_wal_unsafe);
    }
    SUBCASE("a config dependency appears after snapshot retirement") {
        fixture.dependencies.before_observe =
            [&fixture](const std::size_t call) {
                if (call == 2U) {
                    fixture.dependencies.references.push_back({
                        NdmsNativeKeenPbrDependencyKind::
                            interface_outbound,
                        "active:outbound:late"});
                }
            };
        require_recovery_anchor(
            fixture,
            NdmsNativeTombstoneForgetStop::
                keen_pbr_dependencies_present);
    }
    SUBCASE("the retained kernel identity reappears") {
        fixture.kernel_inventory.before_observe =
            [&fixture](const std::size_t call) {
                if (call == 2U) {
                    fixture.kernel_inventory.names = {"lo", "nwg5"};
                }
            };
        require_recovery_anchor(
            fixture,
            NdmsNativeTombstoneForgetStop::
                retained_kernel_interface_present);
    }
    SUBCASE("the firmware target reappears") {
        fixture.gateway.target_present_call = 3U;
        require_recovery_anchor(
            fixture,
            NdmsNativeTombstoneForgetStop::observed_target_present);
    }
    SUBCASE("the retained marker reappears") {
        fixture.gateway.marker_present_call = 4U;
        require_recovery_anchor(
            fixture,
            NdmsNativeTombstoneForgetStop::observed_marker_present);
    }
}

TEST_CASE("snapshot-first crash outcomes remain truthful and resumable") {
    ForgetFixture fixture;
    fixture.gateway.target_present_call = 99U;

    SUBCASE("a visible snapshot unlink is durability-repaired in place") {
        fixture.faults->snapshot_throw_after_unlink = true;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.status ==
              NdmsNativeTombstoneForgetStatus::forgotten);
        CHECK(outcome.snapshot_state ==
              NdmsNativeTombstoneForgetArtifactState::absent_durable);
        CHECK(outcome.tombstone_state ==
              NdmsNativeTombstoneForgetArtifactState::absent_durable);
    }
    SUBCASE("a failed tombstone CAS leaves safe resumable evidence") {
        fixture.faults->ownership_throw_before_recheck = true;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.status ==
              NdmsNativeTombstoneForgetStatus::recovery_required);
        CHECK(outcome.stop == NdmsNativeTombstoneForgetStop::
              tombstone_retirement_failed);
        CHECK(outcome.snapshot_state ==
              NdmsNativeTombstoneForgetArtifactState::absent_durable);
        CHECK(outcome.tombstone_state ==
              NdmsNativeTombstoneForgetArtifactState::retained);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::valid);
    }
    SUBCASE("writer loss after snapshot unlink never removes tombstone") {
        fixture.faults->lose_writer_after_snapshot_unlink = true;
        const auto outcome = fixture.coordinator.forget_once(
            fixture.writer.lease, fixture.request());
        CHECK(outcome.status ==
              NdmsNativeTombstoneForgetStatus::recovery_required);
        CHECK(outcome.stop ==
              NdmsNativeTombstoneForgetStop::writer_lost);
        CHECK(outcome.snapshot_state ==
              NdmsNativeTombstoneForgetArtifactState::absent_durable);
        CHECK(outcome.tombstone_state ==
              NdmsNativeTombstoneForgetArtifactState::retained);
        CHECK(fixture.ownership.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::valid);
    }
}

TEST_CASE("forget accepts exact snapshot binding or proven prior absence") {
    ForgetFixture fixture;
    fixture.gateway.target_present_call = 99U;
    REQUIRE(fixture.snapshots.remove_panel_delete_snapshot_exact(
        fixture.tombstone.interface_name,
        fixture.tombstone.transaction_id,
        fixture.tombstone.marker,
        fixture.tombstone.snapshot_revision));
    REQUIRE(fixture.snapshots.ensure_absence_durable(
        fixture.tombstone.interface_name));

    const auto outcome = fixture.coordinator.forget_once(
        fixture.writer.lease, fixture.request());
    CHECK(outcome.status == NdmsNativeTombstoneForgetStatus::forgotten);
    CHECK(outcome.snapshot_state ==
          NdmsNativeTombstoneForgetArtifactState::absent_durable);
    CHECK(outcome.tombstone_state ==
          NdmsNativeTombstoneForgetArtifactState::absent_durable);
}

TEST_CASE("forget never retires a rebound encrypted snapshot") {
    ForgetFixture fixture;
    fixture.gateway.target_present_call = 99U;
    REQUIRE(fixture.snapshots.remove_panel_delete_snapshot_exact(
        fixture.tombstone.interface_name,
        fixture.tombstone.transaction_id,
        fixture.tombstone.marker,
        fixture.tombstone.snapshot_revision));
    auto rebound = make_ndms_native_panel_delete_snapshot(
        full_configuration('9'), fixture.tombstone.marker);
    fixture.snapshots.publish_panel_delete_snapshot(
        fixture.tombstone.interface_name,
        fixture.tombstone.transaction_id,
        fixture.tombstone.marker,
        std::move(rebound));

    const auto outcome = fixture.coordinator.forget_once(
        fixture.writer.lease, fixture.request());
    CHECK(outcome.stop ==
          NdmsNativeTombstoneForgetStop::snapshot_mismatch);
    CHECK(fixture.ownership.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("tombstone forget names are stable and non-secret") {
    CHECK(std::string{ndms_native_tombstone_forget_status_name(
              NdmsNativeTombstoneForgetStatus::recovery_required)} ==
          "recovery_required");
    CHECK(std::string{ndms_native_tombstone_forget_stop_name(
              NdmsNativeTombstoneForgetStop::observed_target_present)} ==
          "observed_target_present");
    CHECK(std::string{ndms_native_tombstone_forget_artifact_state_name(
              NdmsNativeTombstoneForgetArtifactState::absent_durable)} ==
          "absent_durable");
}
