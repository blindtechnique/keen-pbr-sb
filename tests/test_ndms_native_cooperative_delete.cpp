#include <doctest/doctest.h>

#include "keenetic/ndms_native_cooperative_delete.hpp"
#include "keenetic/ndms_native_import_identity.hpp"

#include "runtime/runtime_mutation_admission.hpp"

#include <algorithm>
#include <cerrno>
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
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace keen_pbr3;

static_assert(!std::is_default_constructible_v<
              NdmsNativeCooperativeDeleteCoordinator>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeCooperativeDeleteCoordinator>);

namespace {

namespace fs = std::filesystem;

constexpr char kAuthority[] =
    "0123456789abcdef0123456789abcdef";

class DeleteTempDirectory final {
public:
    DeleteTempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() /
             "keen-pbr-cooperative-delete-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const auto* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        root = created;
    }

    ~DeleteTempDirectory() {
        std::error_code error;
        fs::remove_all(root, error);
    }

    fs::path root;
};

struct DeleteMaintenanceState final {
    bool held{true};
    std::uint32_t generation{41U};
    std::size_t verify_calls{0U};
};

class DeleteMaintenanceLease final : public MaintenanceLease {
public:
    explicit DeleteMaintenanceLease(
        std::shared_ptr<DeleteMaintenanceState> state)
        : state_(std::move(state)), base_(state_->generation) {}

    std::uint32_t base_generation() const noexcept override {
        return base_;
    }

    std::uint32_t reserve(const std::uint32_t expected) override {
        if (!state_->held || expected != state_->generation ||
            state_->generation ==
                std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("synthetic delete writer reserve");
        }
        return ++state_->generation;
    }

    void verify_held() override {
        ++state_->verify_calls;
        if (!state_->held) {
            throw std::runtime_error("synthetic delete writer loss");
        }
    }

private:
    std::shared_ptr<DeleteMaintenanceState> state_;
    std::uint32_t base_{0U};
};

NdmsNativeWriterAdmission acquire_delete_writer(
    const fs::path& state,
    RuntimeMutationAdmission& runtime,
    const std::shared_ptr<DeleteMaintenanceState>& maintenance) {
    auto runtime_lease = runtime.try_acquire("cooperative-delete-test");
    REQUIRE(runtime_lease.has_value());
    NdmsNativeWriterLeaseTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return admit_ndms_native_writer(
        state,
        std::make_unique<DeleteMaintenanceLease>(maintenance),
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

std::string full_configuration(
    const NdmsNativeTunnelImportKind kind,
    const char address_digit = '8') {
    std::string configuration =
        "[Interface]\nPrivateKey = " + base64_key('P') +
        "\nAddress = 10." + std::string(1U, address_digit) +
        ".0.2/32\nDNS = 1.1.1.1\n";
    if (kind == NdmsNativeTunnelImportKind::amnezia_wireguard) {
        configuration +=
            "Jc = 4\nJmin = 40\nJmax = 70\n"
            "S1 = 100\nS2 = 200\nS3 = 300\nS4 = 400\n"
            "H1 = 101010101\nH2 = 202020202\n"
            "H3 = 303030303\nH4 = 404040404\n"
            "I1 = <r 8><c><t>\nI2 = <b 0x10>\n"
            "I3 = <c><t>\nI4 = <r 4>\nI5 = <b 0x20>\n";
    }
    configuration +=
        "\n[Peer]\nPublicKey = " + base64_key('K') +
        "\nPresharedKey = " + base64_key('S') +
        "\nEndpoint = vpn.example.test:443\n"
        "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n";
    return configuration;
}

std::string digest(const std::string_view prefix, const char digit) {
    return std::string{prefix} + std::string(64U, digit);
}

class FakeDeleteObservationGateway final
    : public NdmsNativeCooperativeDeleteObservationGateway {
public:
    NdmsNativeDirectRecoveryObservation observe_recovery(
        const NdmsNativeDirectCatalogScope scope,
        const std::string& requested_marker,
        const std::optional<std::string>& expected_target) noexcept override {
        ++calls;
        if (before_observe) before_observe(calls);
        const bool runtime =
            scope == NdmsNativeDirectCatalogScope::runtime_state;
        const bool observed_present =
            presence_override_on_call == calls
                ? presence_override_value
                : present;
        if (events != nullptr) {
            events->push_back(
                std::string{"observe."} +
                (runtime ? "runtime." : "running.") +
                (observed_present ? "present" : "absent"));
        }
        NdmsNativeDirectRecoveryObservation result;
        result.requested_catalog_scope = scope;
        result.catalog_scope =
            scope_mismatch_on_call == calls
                ? (runtime
                       ? NdmsNativeDirectCatalogScope::running_config
                       : NdmsNativeDirectCatalogScope::runtime_state)
                : scope;
        if (fail_on_call == calls ||
            requested_marker != marker ||
            expected_target !=
                std::optional<std::string>{interface_name}) {
            result.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
            return result;
        }

        nlohmann::json payload = nlohmann::json::object();
        if (observed_present) {
            const auto description = friendly_name.empty()
                ? marker
                : friendly_name + " · " + marker;
            payload[interface_name] = {
                {"type", "Wireguard"},
                {"interface-name", interface_name},
                {"description", description},
                {"connected", connected},
                {"link", connected},
            };
        } else {
            payload["Bridge0"] = {
                {"type", "Bridge"},
                {"interface-name", "br0"},
                {"description", "Home"},
            };
        }
        NdmsCatalogSnapshot snapshot;
        snapshot.catalog = runtime && observed_present && kernel_name
            ? parse_ndms_interface_catalog(payload, {*kernel_name})
            : parse_ndms_interface_catalog(payload);
        snapshot.status = NdmsCatalogCacheStatus::fresh;
        snapshot.refreshed = true;
        snapshot.observed_at = std::chrono::steady_clock::time_point{
            std::chrono::seconds{123}};
        result.snapshot = std::move(snapshot);
        if (observed_present) {
            const auto revision = drift_revision_on_call == calls
                ? digest("ndms-rci-full-v1-", '9')
                : target_full_revision;
            result.target_evidence.push_back(
                {interface_name, !connected, revision});
            result.target_protocols.push_back(
                {interface_name,
                 drift_kind_on_call == calls
                     ? (kind == NdmsNativeTunnelImportKind::wireguard
                            ? NdmsNativeAscClass::amnezia_wg
                            : NdmsNativeAscClass::plain_wireguard)
                     : (kind == NdmsNativeTunnelImportKind::wireguard
                            ? NdmsNativeAscClass::plain_wireguard
                            : NdmsNativeAscClass::amnezia_wg)});
        }
        result.catalog_revision =
            ndms_native_import_recovery_catalog_revision(
                result.snapshot->catalog, result.target_evidence);
        result.failure = NdmsNativeDirectObservationFailure::none;
        return result;
    }

    std::string interface_name{"Wireguard5"};
    std::string marker;
    std::string friendly_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::string target_full_revision;
    std::optional<std::string> kernel_name{std::string{"nwg5"}};
    bool present{true};
    std::size_t presence_override_on_call{0U};
    bool presence_override_value{false};
    bool connected{true};
    std::size_t calls{0U};
    std::size_t fail_on_call{0U};
    std::size_t scope_mismatch_on_call{0U};
    std::size_t drift_revision_on_call{0U};
    std::size_t drift_kind_on_call{0U};
    std::function<void(std::size_t)> before_observe;
    std::vector<std::string>* events{nullptr};
};

class FakeDependencyProvider final
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

class FakeExactDeleteBackend final
    : public NdmsNativeExactMutationBackend {
private:
    NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeExactMutationPreDispatchGuard& guard,
        NdmsNativeExactMutationBackendTrace& trace) override {
        ++calls;
        const std::string body{
            request_body.view().data(), request_body.view().size()};
        bodies.push_back(body);
        const bool deleting =
            body.find(R"("no":true)") != std::string::npos;
        trace.pre_dispatch_guard_evaluated = true;
        if (before_guard) before_guard(calls, deleting);
        if (!guard.authorize_dispatch()) {
            return NdmsNativeExactMutationRawResponse{};
        }
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        ++perform_calls;
        if (events != nullptr) {
            events->push_back(deleting ? "delete.perform" : "save.perform");
        }
        if (apply_effect && gateway != nullptr && deleting) {
            gateway->present = false;
        }
        if (reappear_after_save && gateway != nullptr && !deleting) {
            gateway->present = true;
        }
        if (after_perform) after_perform(calls, deleting);
        if (throw_after_perform_call == calls) {
            throw std::runtime_error("synthetic exact transport crash");
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
    FakeDeleteObservationGateway* gateway{nullptr};
    std::vector<std::string>* events{nullptr};
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    bool apply_effect{true};
    bool reappear_after_save{false};
    bool acknowledged{true};
    bool transport_ok{true};
    std::size_t throw_after_perform_call{0U};
    std::function<void(std::size_t, bool)> before_guard;
    std::function<void(std::size_t, bool)> after_perform;
    std::vector<std::string> bodies;
};

struct DeleteFaultControl final {
    std::size_t wal_publish_attempts{0U};
    std::size_t fail_wal_before_visibility_call{0U};
    std::function<void()> before_wal_visibility_failure;
    std::size_t wal_replace_calls{0U};
    std::size_t fail_wal_replace_call{0U};
    bool fail_wal_remove_after_unlink{false};
    bool fail_ownership_replace_after_visible{false};
    std::function<void()> after_ownership_replace;
    std::vector<std::string>* events{nullptr};
};

NdmsNativeObservationStoreTestHooks delete_observation_hooks() {
    NdmsNativeObservationStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.authority_id_factory = [] { return std::string{kAuthority}; };
    return hooks;
}

NdmsNativeImportWalStoreTestHooks import_wal_hooks() {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

NdmsNativeDeleteWalStoreTestHooks delete_wal_hooks(
    const std::shared_ptr<DeleteFaultControl>& faults) {
    NdmsNativeDeleteWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.force_portable_linkat = true;
    hooks.fault_injector = [faults](const auto stage) {
        if (stage == NdmsNativeDeleteWalStoreFaultStage::
                         after_temporary_file_fsync) {
            ++faults->wal_publish_attempts;
            if (faults->fail_wal_before_visibility_call ==
                faults->wal_publish_attempts) {
                if (faults->before_wal_visibility_failure) {
                    faults->before_wal_visibility_failure();
                }
                throw std::runtime_error(
                    "synthetic WAL pre-publication crash");
            }
        }
        if (stage == NdmsNativeDeleteWalStoreFaultStage::
                         after_replace_rename_before_directory_fsync) {
            ++faults->wal_replace_calls;
            if (faults->events != nullptr) {
                faults->events->push_back("wal.replace.visible");
            }
            if (faults->fail_wal_replace_call ==
                faults->wal_replace_calls) {
                throw std::runtime_error("synthetic WAL replace crash");
            }
        }
        if (stage == NdmsNativeDeleteWalStoreFaultStage::
                         after_unlink_before_directory_fsync) {
            if (faults->events != nullptr) {
                faults->events->push_back("wal.remove.visible");
            }
            if (faults->fail_wal_remove_after_unlink) {
                throw std::runtime_error("synthetic WAL unlink crash");
            }
        }
    };
    return hooks;
}

NdmsNativeSecretSnapshotStoreTestHooks delete_snapshot_hooks() {
    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

NdmsNativeOwnershipStoreTestHooks delete_ownership_hooks(
    const std::shared_ptr<DeleteFaultControl>& faults) {
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [faults](const auto stage) {
        if (stage == NdmsNativeOwnershipStoreFaultStage::
                        post_rename_directory_fsync) {
            if (faults->events != nullptr) {
                faults->events->push_back("ownership.replace.visible");
            }
            if (faults->after_ownership_replace) {
                faults->after_ownership_replace();
            }
            if (faults->fail_ownership_replace_after_visible) {
                throw std::runtime_error(
                    "synthetic ownership replace crash");
            }
        }
    };
    return hooks;
}

NdmsNativeImportPersistedBaseline import_baseline_fixture() {
    auto payload = nlohmann::json::object();
    for (const std::uint8_t slot : {0U, 1U, 2U, 3U, 4U, 6U}) {
        const auto name = "Wireguard" + std::to_string(slot);
        payload[name] = {
            {"type", "Bridge"},
            {"interface-name", name},
            {"description", "occupied"},
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
    const auto built = build_ndms_native_import_baseline(
        snapshot, "Wireguard5", 41U, 17U);
    if (!built.success() || !built.evidence) {
        throw std::runtime_error("cannot build import WAL fixture");
    }
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord unfinished_import_record() {
    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(32U, '7');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        digest("ndms-native-import-v1-", '8');
    record.snapshot_revision = record.candidate_revision;
    record.observation_binding = {std::string(32U, '9'), 9U, 7U};
    record.baseline = import_baseline_fixture();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.kind,
            record.baseline.expected_created_interface);
    record.generation_ticket = digest("ndms-create-ticket-v1-", 'a');
    record.maintenance_base_generation = 41U;
    return record;
}

struct DeleteFixture final {
    DeleteFixture()
        : faults(std::make_shared<DeleteFaultControl>()),
          maintenance(std::make_shared<DeleteMaintenanceState>()),
          writer(acquire_delete_writer(
              directory.root / "native-mutation",
              runtime,
              maintenance)),
          observations(
              directory.root / "native-mutation",
              delete_observation_hooks()),
          import_wal(
              directory.root / "import-wal", import_wal_hooks()),
          delete_wal(
              directory.root / "delete-wal", delete_wal_hooks(faults)),
          snapshots(
              directory.root / "keys" / "snapshot.key",
              directory.root / "snapshots",
              delete_snapshot_hooks()),
          ownership(
              directory.root / "ownership",
              delete_ownership_hooks(faults)),
          coordinator(
              NdmsNativeCooperativeDeleteCoordinatorTestIssuer::issue(
                  observations,
                  import_wal,
                  delete_wal,
                  snapshots,
                  ownership,
                  dependencies,
                  gateway,
                  backend,
                  [] { return std::string(32U, 'b'); })) {
        REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
        REQUIRE(fs::create_directories(import_wal.state_directory()));
        REQUIRE(::chmod(import_wal.state_directory().c_str(), 0700) == 0);
        static_cast<void>(observations.provision(writer.lease));
        gateway.events = &events;
        backend.gateway = &gateway;
        backend.events = &events;
        faults->events = &events;
    }

    std::string install_owned_target(
        const NdmsNativeTunnelImportKind kind =
            NdmsNativeTunnelImportKind::wireguard,
        const char transaction_digit = 'c',
        const char address_digit = '8') {
        const std::string transaction(32U, transaction_digit);
        const std::string marker = "kpbr-ni-v1-" + transaction;
        auto snapshot = make_ndms_native_panel_delete_snapshot(
            full_configuration(kind, address_digit), marker);
        const auto snapshot_revision =
            std::string{snapshot.canonical_revision()};
        snapshots.publish_panel_delete_snapshot(
            "Wireguard5",
            transaction,
            marker,
            std::move(snapshot));

        NdmsNativeOwnershipRecord claim;
        claim.interface_name = "Wireguard5";
        claim.transaction_id = transaction;
        claim.marker = marker;
        claim.kind = kind;
        claim.snapshot_revision = snapshot_revision;
        claim.target_full_revision =
            digest("ndms-rci-full-v1-", transaction_digit);
        ownership_revision = ownership.publish(claim);
        ownership_record = claim;

        gateway.interface_name = claim.interface_name;
        gateway.marker = claim.marker;
        gateway.kind = claim.kind;
        gateway.target_full_revision = claim.target_full_revision;
        gateway.present = true;
        gateway.connected = true;
        gateway.calls = 0U;
        gateway.presence_override_on_call = 0U;
        events.clear();
        faults->wal_publish_attempts = 0U;
        faults->wal_replace_calls = 0U;
        return ownership_revision;
    }

    NdmsNativeCooperativeDeleteRequest request(
        std::string expected_revision = {}) const {
        NdmsNativeCooperativeDeleteRequest request;
        request.interface_name = "Wireguard5";
        request.expected_ownership_revision = expected_revision.empty()
            ? ownership_revision
            : std::move(expected_revision);
        request.global_save_consent = NdmsNativeOwnerGlobalSaveConsent::
            acknowledged_all_pending_keenetic_changes;
        request.external_writer_race =
            NdmsNativeDeleteExternalWriterRaceAcceptance::owner_accepted;
        return request;
    }

    NdmsNativeCooperativeDeleteResumeAcknowledgement
    resume_acknowledgement() const {
        NdmsNativeCooperativeDeleteResumeAcknowledgement acknowledgement;
        acknowledgement.global_save_consent =
            NdmsNativeOwnerGlobalSaveConsent::
                acknowledged_all_pending_keenetic_changes;
        acknowledgement.external_writer_race =
            NdmsNativeDeleteExternalWriterRaceAcceptance::owner_accepted;
        return acknowledgement;
    }

    NdmsNativeCooperativeDeleteCoordinator restarted_coordinator() {
        return NdmsNativeCooperativeDeleteCoordinatorTestIssuer::issue(
            observations,
            import_wal,
            delete_wal,
            snapshots,
            ownership,
            dependencies,
            gateway,
            backend,
            [] { return std::string(32U, 'd'); });
    }

    bool snapshot_retained() {
        const auto read = snapshots.read_panel_delete_snapshot(
            ownership_record.interface_name,
            ownership_record.transaction_id,
            ownership_record.marker);
        return read.state == NdmsNativeSecretReadState::valid &&
               read.snapshot.has_value() &&
               read.snapshot->canonical_revision() ==
                   ownership_record.snapshot_revision;
    }

    DeleteTempDirectory directory;
    std::shared_ptr<DeleteFaultControl> faults;
    RuntimeMutationAdmission runtime;
    std::shared_ptr<DeleteMaintenanceState> maintenance;
    NdmsNativeWriterAdmission writer;
    NdmsNativeObservationStore observations;
    NdmsNativeImportWalStore import_wal;
    NdmsNativeDeleteWalStore delete_wal;
    NdmsNativeSecretSnapshotStore snapshots;
    NdmsNativeOwnershipStore ownership;
    FakeDependencyProvider dependencies;
    FakeDeleteObservationGateway gateway;
    FakeExactDeleteBackend backend;
    std::vector<std::string> events;
    std::string ownership_revision;
    NdmsNativeOwnershipRecord ownership_record;
    NdmsNativeCooperativeDeleteCoordinator coordinator;
};

NdmsNativeDeleteWalRecord stop_after_terminal_wal_is_visible(
    DeleteFixture& fixture) {
    fixture.faults->fail_wal_replace_call = 4U;
    const auto first = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());
    CHECK(first.status ==
          NdmsNativeCooperativeDeleteStatus::recovery_required);
    CHECK(first.stop == NdmsNativeCooperativeDeleteStop::
          delete_wal_publish_failed);
    const auto loaded = fixture.delete_wal.load();
    REQUIRE(loaded.record.has_value());
    REQUIRE(loaded.record->phase == NdmsNativeDeleteWalPhase::
            save_acknowledged_unverified);
    fixture.faults->fail_wal_replace_call = 0U;
    fixture.gateway.calls = 0U;
    return *loaded.record;
}

void overwrite_delete_wal_for_test(
    const NdmsNativeDeleteWalStore& store,
    const NdmsNativeDeleteWalRecord& record) {
    const auto serialized = serialize_ndms_native_delete_wal(record);
    const auto path = store.state_directory() /
                      kNdmsNativeDeleteWalFilename;
    const int descriptor = ::open(
        path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(descriptor >= 0);
    std::size_t offset = 0U;
    while (offset < serialized.size()) {
        const auto written = ::write(
            descriptor,
            serialized.data() + offset,
            serialized.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        REQUIRE(written > 0);
        offset += static_cast<std::size_t>(written);
    }
    REQUIRE(::fsync(descriptor) == 0);
    REQUIRE(::close(descriptor) == 0);
}

void corrupt_delete_wal_for_test(
    const NdmsNativeDeleteWalStore& store) {
    const auto path = store.state_directory() /
                      kNdmsNativeDeleteWalFilename;
    const int descriptor = ::open(
        path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(descriptor >= 0);
    constexpr std::string_view corrupt{"{"};
    REQUIRE(::write(descriptor, corrupt.data(), corrupt.size()) ==
            static_cast<ssize_t>(corrupt.size()));
    REQUIRE(::fsync(descriptor) == 0);
    REQUIRE(::close(descriptor) == 0);
}

void corrupt_delete_snapshot_for_test(const DeleteFixture& fixture) {
    const auto path = fixture.directory.root / "snapshots" / "Wireguard5";
    const int descriptor = ::open(
        path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(descriptor >= 0);
    constexpr std::string_view corrupt{"not-an-encrypted-snapshot"};
    REQUIRE(::write(descriptor, corrupt.data(), corrupt.size()) ==
            static_cast<ssize_t>(corrupt.size()));
    REQUIRE(::fsync(descriptor) == 0);
    REQUIRE(::close(descriptor) == 0);
}

std::size_t event_index(
    const std::vector<std::string>& events,
    const std::string& value,
    const std::size_t start = 0U) {
    const auto bounded_start = std::min(start, events.size());
    const auto found = std::find(
        events.begin() + static_cast<std::ptrdiff_t>(bounded_start),
        events.end(),
        value);
    return found == events.end()
        ? events.size()
        : static_cast<std::size_t>(found - events.begin());
}

void check_no_router_write(const DeleteFixture& fixture) {
    CHECK(fixture.backend.perform_calls == 0U);
    CHECK(fixture.delete_wal.readiness() ==
          NdmsNativeDeleteWalReadiness::clean);
}

void check_result_matches_durable_record(
    const NdmsNativeCooperativeDeleteResult& result,
    const NdmsNativeDeleteWalRecord& durable,
    const NdmsNativeDeleteWalPhase expected_phase) {
    REQUIRE(result.durable_phase.has_value());
    CHECK(*result.durable_phase == expected_phase);
    REQUIRE(result.transaction_id.has_value());
    CHECK(*result.transaction_id == durable.transaction_id);
    REQUIRE(result.interface_name.has_value());
    CHECK(*result.interface_name == durable.interface_name);
    REQUIRE(result.kind.has_value());
    CHECK(*result.kind == durable.kind);
    CHECK(result.external_writer_race_accepted ==
          durable.external_writer_race_accepted);
    CHECK(result.global_save_scope_acknowledged ==
          durable.owner_global_save_acknowledged);
}

} // namespace

TEST_CASE("keen-pbr delete dependency digest covers every scoped consumer") {
    NdmsNativeKeenPbrDependencyObservation base;
    base.complete = true;
    base.firmware_interface_name = "Wireguard5";
    base.kernel_interface_name = "nwg5";

    auto outbound = base;
    outbound.references.push_back(
        {NdmsNativeKeenPbrDependencyKind::interface_outbound,
         "outbound-1"});
    const auto outbound_revision =
        ndms_native_keen_pbr_dependency_revision(outbound);

    auto internal = base;
    internal.references.push_back(
        {NdmsNativeKeenPbrDependencyKind::internal_vpn_policy,
         "policy-1"});
    const auto internal_revision =
        ndms_native_keen_pbr_dependency_revision(internal);

    auto inbound = base;
    inbound.references.push_back(
        {NdmsNativeKeenPbrDependencyKind::inbound_interface_policy,
         "route.inbound_interfaces[0]"});
    const auto inbound_revision =
        ndms_native_keen_pbr_dependency_revision(inbound);

    auto preference = base;
    preference.references.push_back(
        {NdmsNativeKeenPbrDependencyKind::native_interface_preference,
         "ui_preferences.hidden_native_interface_ids[0]"});
    const auto preference_revision =
        ndms_native_keen_pbr_dependency_revision(preference);

    CHECK(outbound_revision != internal_revision);
    CHECK(outbound_revision != inbound_revision);
    CHECK(outbound_revision != preference_revision);
    CHECK(internal_revision != inbound_revision);
    CHECK(internal_revision != preference_revision);
    CHECK(inbound_revision != preference_revision);

    auto reordered = base;
    reordered.references = {
        preference.references.front(),
        inbound.references.front(),
    };
    auto canonical = base;
    canonical.references = {
        inbound.references.front(),
        preference.references.front(),
    };
    CHECK(ndms_native_keen_pbr_dependency_revision(reordered) ==
          ndms_native_keen_pbr_dependency_revision(canonical));

    auto unknown = base;
    unknown.references.push_back(
        {static_cast<NdmsNativeKeenPbrDependencyKind>(255U),
         "unknown"});
    CHECK_THROWS_AS(
        ndms_native_keen_pbr_dependency_revision(unknown),
        std::invalid_argument);
}

TEST_CASE("cooperative panel delete requires both explicit owner decisions") {
    SUBCASE("global save consent is checked before every durable action") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        auto request = fixture.request();
        request.global_save_consent =
            NdmsNativeOwnerGlobalSaveConsent::not_acknowledged;
        const auto before = fixture.observations.read();

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, request);

        CHECK(result.status == NdmsNativeCooperativeDeleteStatus::blocked);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              owner_global_save_not_acknowledged);
        check_no_router_write(fixture);
        CHECK(fixture.gateway.calls == 0U);
        const auto after = fixture.observations.read();
        REQUIRE(before.ledger.has_value());
        REQUIRE(after.ledger.has_value());
        CHECK(*before.ledger == *after.ledger);
    }

    SUBCASE("external writer race acceptance is also mandatory") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        auto request = fixture.request();
        request.external_writer_race =
            NdmsNativeDeleteExternalWriterRaceAcceptance::not_accepted;

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, request);

        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              external_writer_race_not_accepted);
        check_no_router_write(fixture);
        CHECK(fixture.gateway.calls == 0U);
    }
}

TEST_CASE("stale card ownership revision cannot delete a reused slot") {
    DeleteFixture fixture;
    const auto stale_revision = fixture.install_owned_target(
        NdmsNativeTunnelImportKind::wireguard, 'c', '8');
    REQUIRE(fixture.snapshots.remove_panel_delete_snapshot_exact(
        fixture.ownership_record.interface_name,
        fixture.ownership_record.transaction_id,
        fixture.ownership_record.marker,
        fixture.ownership_record.snapshot_revision));
    REQUIRE(fixture.ownership.remove_exact(fixture.ownership_record));
    const auto current_revision = fixture.install_owned_target(
        NdmsNativeTunnelImportKind::wireguard, 'd', '9');
    REQUIRE(stale_revision != current_revision);
    const auto delete_directory = fixture.delete_wal.state_directory();
    REQUIRE(fs::create_directories(delete_directory));
    REQUIRE(::chmod(delete_directory.c_str(), 0700) == 0);
    const auto untouched_temporary =
        delete_directory / ".native-panel-delete-wal.tmp.999.999";
    const int temporary_descriptor = ::open(
        untouched_temporary.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600);
    REQUIRE(temporary_descriptor >= 0);
    REQUIRE(::close(temporary_descriptor) == 0);

    const auto result = fixture.coordinator.delete_once(
        fixture.writer.lease,
        fixture.request(stale_revision));

    CHECK(result.status == NdmsNativeCooperativeDeleteStatus::blocked);
    CHECK(result.stop ==
          NdmsNativeCooperativeDeleteStop::ownership_changed);
    CHECK(fixture.backend.perform_calls == 0U);
    CHECK(fixture.gateway.calls == 0U);
    CHECK(fs::exists(untouched_temporary));
    const auto current = fixture.ownership.read("Wireguard5");
    REQUIRE(current.revision.has_value());
    CHECK(*current.revision == current_revision);
}

TEST_CASE("connected panel-owned WG and AWG delete to a durable tombstone") {
    for (const auto kind : {
             NdmsNativeTunnelImportKind::wireguard,
             NdmsNativeTunnelImportKind::amnezia_wireguard}) {
        CAPTURE(static_cast<unsigned int>(kind));
        DeleteFixture fixture;
        fixture.install_owned_target(kind);
        if (kind ==
            NdmsNativeTunnelImportKind::amnezia_wireguard) {
            fixture.gateway.friendly_name = "Мой AWG";
        }
        REQUIRE(fixture.gateway.connected);

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::none);
        CHECK(result.external_writer_race_accepted);
        CHECK_FALSE(result.external_writer_race_excluded);
        CHECK(result.global_save_scope_acknowledged);
        CHECK(result.system_configuration_save_acknowledged);
        CHECK(result.delete_perform_started);
        CHECK(result.save_perform_started);
        CHECK(result.request_may_have_been_dispatched);
        REQUIRE(result.transport_outcome.has_value());
        CHECK(*result.transport_outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  acknowledged_needs_observation);
        CHECK(result.ownership_tombstone_durable);
        CHECK(result.rollback_snapshot_retained);
        CHECK(fixture.backend.perform_calls == 2U);
        REQUIRE(fixture.backend.bodies.size() == 2U);
        CHECK(fixture.backend.bodies[0] ==
              R"({"interface":{"name":"Wireguard5","no":true}})");
        CHECK(fixture.backend.bodies[1] ==
              R"({"system":{"configuration":{"save":{}}}})");
        CHECK_FALSE(fixture.gateway.present);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::clean);
        const auto claim = fixture.ownership.read("Wireguard5");
        REQUIRE(claim.record.has_value());
        REQUIRE(claim.revision.has_value());
        CHECK(ndms_native_ownership_is_delete_tombstone(*claim.record));
        CHECK(claim.record->schema_version ==
              kNdmsNativeOwnershipTombstoneSchemaVersion);
        REQUIRE(claim.record->lifecycle_evidence.has_value());
        CHECK(claim.record->lifecycle_evidence->
                  deleted_kernel_interface_name ==
              std::optional<std::string>{"nwg5"});
        CHECK(claim.revision->rfind(
                  kNdmsNativeOwnershipTombstoneRevisionPrefix, 0U) == 0U);
        const auto inspection =
            fixture.ownership.inspect_bounded_read_only();
        REQUIRE(inspection.readable);
        REQUIRE(inspection.claims.size() == 1U);
        CHECK(inspection.claims.front().
                  retained_deletion_forget_capable);
        CHECK(fixture.snapshot_retained());

        const auto delete_perform =
            event_index(fixture.events, "delete.perform");
        const auto absence = event_index(
            fixture.events, "observe.runtime.absent", delete_perform + 1U);
        const auto save_perform =
            event_index(fixture.events, "save.perform", absence + 1U);
        const auto tombstone = event_index(
            fixture.events,
            "ownership.replace.visible",
            save_perform + 1U);
        const auto wal_remove = event_index(
            fixture.events, "wal.remove.visible", tombstone + 1U);
        CHECK(delete_perform < absence);
        CHECK(absence < save_perform);
        CHECK(save_perform < tombstone);
        CHECK(tombstone < wal_remove);
    }
}

TEST_CASE("every preflight mismatch remains read-only for the router") {
    SUBCASE("protected and noncanonical targets stop before stores") {
        DeleteFixture fixture;
        auto request = fixture.request(
            digest("ndms-native-owner-v3-", '1'));
        request.interface_name = "Wireguard4";
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, request);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              invalid_or_protected_target);
        check_no_router_write(fixture);
    }

    SUBCASE("missing ownership") {
        DeleteFixture fixture;
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease,
            fixture.request(digest("ndms-native-owner-v3-", '1')));
        CHECK(result.stop ==
              NdmsNativeCooperativeDeleteStop::ownership_absent);
        check_no_router_write(fixture);
    }

    SUBCASE("missing snapshot") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        REQUIRE(fixture.snapshots.remove_panel_delete_snapshot_exact(
            fixture.ownership_record.interface_name,
            fixture.ownership_record.transaction_id,
            fixture.ownership_record.marker,
            fixture.ownership_record.snapshot_revision));
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop ==
              NdmsNativeCooperativeDeleteStop::snapshot_absent);
        CHECK_FALSE(result.rollback_snapshot_retained);
        check_no_router_write(fixture);
    }

    SUBCASE("unreadable snapshot is never reported as retained") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        corrupt_delete_snapshot_for_test(fixture);
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop ==
              NdmsNativeCooperativeDeleteStop::snapshot_unreadable);
        CHECK_FALSE(result.rollback_snapshot_retained);
        check_no_router_write(fixture);
    }

    SUBCASE("keen-pbr dependency scan incomplete") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.dependencies.complete = false;
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              keen_pbr_dependency_scan_incomplete);
        check_no_router_write(fixture);
    }

    SUBCASE("keen-pbr references present") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.dependencies.references.push_back(
            {NdmsNativeKeenPbrDependencyKind::interface_outbound,
             "outbound-owned-by-keen-pbr"});
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              keen_pbr_dependencies_present);
        check_no_router_write(fixture);
    }

    SUBCASE("runtime and running scope cannot be mixed") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.gateway.scope_mismatch_on_call = 2U;
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observation_scope_mismatch);
        check_no_router_write(fixture);
    }

    SUBCASE("wrong exact target revision") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.gateway.drift_revision_on_call = 1U;
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_drifted);
        check_no_router_write(fixture);
    }

    SUBCASE("wrong WG or AWG kind") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.gateway.drift_kind_on_call = 1U;
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_drifted);
        check_no_router_write(fixture);
    }

    SUBCASE("same wrong exact target in both scopes is a typed mismatch") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.gateway.target_full_revision =
            digest("ndms-rci-full-v1-", '9');
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_mismatch);
        check_no_router_write(fixture);
    }
}

TEST_CASE("unfinished or unsafe import WAL blocks delete cross-kind") {
    SUBCASE("authoritative unfinished import") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        REQUIRE(fixture.import_wal.publish_prepared_exclusive(
                    unfinished_import_record()) ==
                NdmsNativeImportWalAdmissionState::admitted);

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              import_wal_not_authoritatively_clean);
        check_no_router_write(fixture);
        CHECK(fixture.gateway.calls == 0U);
    }

    SUBCASE("unsafe import inventory") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        const auto foreign =
            fixture.import_wal.state_directory() / "foreign";
        const int descriptor = ::open(
            foreign.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        REQUIRE(descriptor >= 0);
        REQUIRE(::close(descriptor) == 0);
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              import_wal_not_authoritatively_clean);
        check_no_router_write(fixture);
        CHECK(fixture.gateway.calls == 0U);
    }
}

TEST_CASE("one unfinished delete WAL refuses a second admission") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    static_cast<void>(stop_after_terminal_wal_is_visible(fixture));
    const auto performs_before = fixture.backend.perform_calls;

    const auto result = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());

    CHECK(result.stop ==
          NdmsNativeCooperativeDeleteStop::delete_wal_unfinished);
    CHECK(fixture.gateway.calls == 0U);
    CHECK(fixture.backend.perform_calls == performs_before);
    CHECK(fixture.delete_wal.readiness() ==
          NdmsNativeDeleteWalReadiness::unfinished);
    const auto claim = fixture.ownership.read("Wireguard5");
    REQUIRE(claim.record.has_value());
    CHECK(ndms_native_ownership_is_active(*claim.record));
    CHECK(fixture.snapshot_retained());
}

TEST_CASE("lost writer or guard drift never reaches backend perform") {
    SUBCASE("writer lost inside final delete guard") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.before_guard = [&](const auto, const bool deleting) {
            if (deleting) fixture.maintenance->held = false;
        };

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::writer_lost);
        CHECK_FALSE(result.durable_phase.has_value());
        CHECK_FALSE(result.transaction_id.has_value());
        CHECK_FALSE(result.interface_name.has_value());
        CHECK_FALSE(result.kind.has_value());
        CHECK_FALSE(result.external_writer_race_accepted);
        CHECK_FALSE(result.global_save_scope_acknowledged);
        CHECK(fixture.backend.calls == 1U);
        CHECK(fixture.backend.perform_calls == 0U);
        CHECK(fixture.gateway.present);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
        CHECK(fixture.snapshot_retained());
    }

    SUBCASE("external target revision changes inside guard") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.before_guard = [&](const auto, const bool deleting) {
            if (deleting) {
                fixture.gateway.target_full_revision =
                    digest("ndms-rci-full-v1-", '9');
            }
        };

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_mismatch);
        CHECK(fixture.backend.perform_calls == 0U);
        CHECK(fixture.gateway.present);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
    }

    SUBCASE("writer lost inside final save guard never performs save") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.before_guard = [&](const auto, const bool deleting) {
            if (!deleting) fixture.maintenance->held = false;
        };

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::writer_lost);
        CHECK_FALSE(result.durable_phase.has_value());
        CHECK_FALSE(result.transaction_id.has_value());
        CHECK_FALSE(result.interface_name.has_value());
        CHECK_FALSE(result.kind.has_value());
        CHECK_FALSE(result.external_writer_race_accepted);
        CHECK_FALSE(result.global_save_scope_acknowledged);
        CHECK(fixture.backend.calls == 2U);
        CHECK(fixture.backend.perform_calls == 1U);
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::save_may_be_inflight);
        CHECK(fixture.snapshot_retained());
    }

    SUBCASE("dependency added inside final save guard never performs save") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.before_guard = [&](const auto, const bool deleting) {
            if (!deleting) {
                fixture.dependencies.references.push_back(
                    {NdmsNativeKeenPbrDependencyKind::internal_vpn_policy,
                     "policy-added-inside-save-guard"});
            }
        };

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              keen_pbr_dependencies_present);
        CHECK(fixture.backend.calls == 2U);
        CHECK(fixture.backend.perform_calls == 1U);
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::save_may_be_inflight);
        CHECK(fixture.snapshot_retained());
    }

    SUBCASE("target reappears inside final save guard and save is rejected") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.before_guard = [&](const auto, const bool deleting) {
            if (!deleting) fixture.gateway.present = true;
        };

        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(result.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_drifted);
        CHECK(fixture.backend.calls == 2U);
        CHECK(fixture.backend.perform_calls == 1U);
        CHECK(fixture.gateway.present);
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::save_may_be_inflight);
        CHECK(fixture.snapshot_retained());
    }
}

TEST_CASE("delete and save ambiguity resume only from durable observation") {
    SUBCASE("delete transport fails before effect then restart retries exact delete") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.apply_effect = false;
        fixture.backend.throw_after_perform_call = 1U;
        const auto first = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(first.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(first.stop == NdmsNativeCooperativeDeleteStop::
              delete_transport_ambiguous);
        CHECK(fixture.gateway.present);
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::delete_may_be_inflight);

        fixture.backend.apply_effect = true;
        fixture.backend.throw_after_perform_call = 0U;
        auto restarted = fixture.restarted_coordinator();
        const auto second = restarted.resume_once(
            fixture.writer.lease, fixture.resume_acknowledgement());
        CHECK(second.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(fixture.backend.perform_calls == 3U);
        CHECK_FALSE(fixture.gateway.present);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::clean);
        CHECK(fixture.snapshot_retained());
    }

    SUBCASE("save acknowledgement loss retains WAL and restart saves again") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.throw_after_perform_call = 2U;
        const auto first = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(first.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(first.stop == NdmsNativeCooperativeDeleteStop::
              save_transport_ambiguous);
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::save_may_be_inflight);
        CHECK_FALSE(fixture.gateway.present);

        fixture.backend.throw_after_perform_call = 0U;
        auto restarted = fixture.restarted_coordinator();
        const auto no_current_ack = restarted.resume_once(
            fixture.writer.lease);
        CHECK(no_current_ack.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(no_current_ack.stop == NdmsNativeCooperativeDeleteStop::
              save_reconfirmation_required);
        CHECK(fixture.backend.perform_calls == 2U);

        NdmsNativeCooperativeDeleteResumeAcknowledgement save_only;
        save_only.global_save_consent = NdmsNativeOwnerGlobalSaveConsent::
            acknowledged_all_pending_keenetic_changes;
        const auto missing_race_ack = restarted.resume_once(
            fixture.writer.lease, save_only);
        CHECK(missing_race_ack.stop == NdmsNativeCooperativeDeleteStop::
              save_reconfirmation_required);
        CHECK(fixture.backend.perform_calls == 2U);

        NdmsNativeCooperativeDeleteResumeAcknowledgement race_only;
        race_only.external_writer_race =
            NdmsNativeDeleteExternalWriterRaceAcceptance::owner_accepted;
        const auto missing_save_ack = restarted.resume_once(
            fixture.writer.lease, race_only);
        CHECK(missing_save_ack.stop == NdmsNativeCooperativeDeleteStop::
              save_reconfirmation_required);
        CHECK(fixture.backend.perform_calls == 2U);

        const auto second = restarted.resume_once(
            fixture.writer.lease, fixture.resume_acknowledgement());
        CHECK(second.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(fixture.backend.perform_calls == 3U);
        CHECK(fixture.snapshot_retained());
    }
}

TEST_CASE("recovery never carries original save consent into a new invocation") {
    for (const auto recovered_phase : {
             NdmsNativeDeleteWalPhase::prepared,
             NdmsNativeDeleteWalPhase::delete_may_be_inflight}) {
        CAPTURE(recovered_phase);
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.backend.apply_effect = false;
        fixture.backend.throw_after_perform_call = 1U;
        const auto first = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        REQUIRE(first.stop == NdmsNativeCooperativeDeleteStop::
                delete_transport_ambiguous);
        const auto loaded = fixture.delete_wal.load();
        REQUIRE(loaded.record.has_value());
        auto recovered = *loaded.record;
        recovered.phase = recovered_phase;
        recovered.integrity = ndms_native_delete_wal_integrity(recovered);
        overwrite_delete_wal_for_test(fixture.delete_wal, recovered);

        fixture.backend.apply_effect = true;
        fixture.backend.throw_after_perform_call = 0U;
        const auto saves_before = std::count(
            fixture.events.begin(), fixture.events.end(), "save.perform");
        auto restarted = fixture.restarted_coordinator();
        const auto without_current_ack = restarted.resume_once(
            fixture.writer.lease);

        CHECK(without_current_ack.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(without_current_ack.stop ==
              NdmsNativeCooperativeDeleteStop::
                  save_reconfirmation_required);
        CHECK(without_current_ack.delete_perform_started);
        CHECK_FALSE(without_current_ack.save_perform_started);
        CHECK(without_current_ack.request_may_have_been_dispatched);
        CHECK_FALSE(
            without_current_ack.system_configuration_save_acknowledged);
        CHECK(std::count(
                  fixture.events.begin(),
                  fixture.events.end(),
                  "save.perform") == saves_before);
        const auto waiting = fixture.delete_wal.load();
        REQUIRE(waiting.record.has_value());
        CHECK(waiting.record->phase ==
              NdmsNativeDeleteWalPhase::running_absence_verified);

        const auto confirmed = restarted.resume_once(
            fixture.writer.lease, fixture.resume_acknowledgement());
        CHECK(confirmed.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(confirmed.stop == NdmsNativeCooperativeDeleteStop::none);
        CHECK_FALSE(confirmed.delete_perform_started);
        CHECK(confirmed.save_perform_started);
        CHECK(confirmed.request_may_have_been_dispatched);
        CHECK(confirmed.system_configuration_save_acknowledged);
        CHECK(std::count(
                  fixture.events.begin(),
                  fixture.events.end(),
                  "save.perform") == saves_before + 1);
    }
}

TEST_CASE("post-save reappearance retains claim snapshot and WAL") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    fixture.backend.reappear_after_save = true;

    const auto result = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());

    CHECK(result.status ==
          NdmsNativeCooperativeDeleteStatus::recovery_required);
    CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
          observed_target_reappeared_after_save);
    CHECK(result.delete_perform_started);
    CHECK(result.save_perform_started);
    CHECK(result.request_may_have_been_dispatched);
    CHECK(result.system_configuration_save_acknowledged);
    CHECK(fixture.gateway.present);
    CHECK(fixture.backend.perform_calls == 2U);
    const auto claim = fixture.ownership.read("Wireguard5");
    REQUIRE(claim.record.has_value());
    CHECK(ndms_native_ownership_is_active(*claim.record));
    CHECK_FALSE(ndms_native_ownership_is_delete_tombstone(*claim.record));
    CHECK(fixture.snapshot_retained());
    CHECK(fixture.delete_wal.readiness() ==
          NdmsNativeDeleteWalReadiness::unfinished);
}

TEST_CASE("terminal restart requires a newer dual-scope absence proof") {
    SUBCASE("snapshot lost before restart is not reported as retained") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        static_cast<void>(stop_after_terminal_wal_is_visible(fixture));
        REQUIRE(fixture.snapshots.remove_panel_delete_snapshot_exact(
            fixture.ownership_record.interface_name,
            fixture.ownership_record.transaction_id,
            fixture.ownership_record.marker,
            fixture.ownership_record.snapshot_revision));
        const auto performs_before = fixture.backend.perform_calls;

        auto restarted = fixture.restarted_coordinator();
        const auto result = restarted.resume_once(fixture.writer.lease);

        CHECK(result.stop ==
              NdmsNativeCooperativeDeleteStop::snapshot_mismatch);
        CHECK_FALSE(result.rollback_snapshot_retained);
        CHECK(fixture.backend.perform_calls == performs_before);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
    }

    SUBCASE("runtime scope reappearance blocks tombstone and cleanup") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        static_cast<void>(stop_after_terminal_wal_is_visible(fixture));
        const auto performs_before = fixture.backend.perform_calls;
        fixture.gateway.presence_override_on_call = 1U;
        fixture.gateway.presence_override_value = true;

        auto restarted = fixture.restarted_coordinator();
        const auto result = restarted.resume_once(fixture.writer.lease);

        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_drifted);
        CHECK(fixture.backend.perform_calls == performs_before);
        const auto claim = fixture.ownership.read("Wireguard5");
        REQUIRE(claim.record.has_value());
        CHECK(ndms_native_ownership_is_active(*claim.record));
        CHECK(fixture.snapshot_retained());
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
    }

    SUBCASE("running-config scope reappearance blocks tombstone and cleanup") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        static_cast<void>(stop_after_terminal_wal_is_visible(fixture));
        const auto performs_before = fixture.backend.perform_calls;
        fixture.gateway.presence_override_on_call = 2U;
        fixture.gateway.presence_override_value = true;

        auto restarted = fixture.restarted_coordinator();
        const auto result = restarted.resume_once(fixture.writer.lease);

        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              observed_target_drifted);
        CHECK(fixture.backend.perform_calls == performs_before);
        const auto claim = fixture.ownership.read("Wireguard5");
        REQUIRE(claim.record.has_value());
        CHECK(ndms_native_ownership_is_active(*claim.record));
        CHECK(fixture.snapshot_retained());
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
    }

    SUBCASE("either unreadable scope blocks tombstone and cleanup") {
        for (const auto failed_call : {1U, 2U}) {
            CAPTURE(failed_call);
            DeleteFixture fixture;
            fixture.install_owned_target();
            static_cast<void>(stop_after_terminal_wal_is_visible(fixture));
            const auto performs_before = fixture.backend.perform_calls;
            fixture.gateway.fail_on_call = failed_call;

            auto restarted = fixture.restarted_coordinator();
            const auto result = restarted.resume_once(
                fixture.writer.lease);

            CHECK(result.stop ==
                  (failed_call == 1U
                       ? NdmsNativeCooperativeDeleteStop::
                             runtime_observation_failed
                       : NdmsNativeCooperativeDeleteStop::
                             running_config_observation_failed));
            CHECK(fixture.backend.perform_calls == performs_before);
            const auto claim = fixture.ownership.read("Wireguard5");
            REQUIRE(claim.record.has_value());
            CHECK(ndms_native_ownership_is_active(*claim.record));
            CHECK(fixture.snapshot_retained());
            CHECK(fixture.delete_wal.readiness() ==
                  NdmsNativeDeleteWalReadiness::unfinished);
        }
    }

    SUBCASE("a valid but future stored pair rejects stale durable stamps") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        auto terminal = stop_after_terminal_wal_is_visible(fixture);
        REQUIRE(terminal.post_save_absence_observations.has_value());
        auto& stored = *terminal.post_save_absence_observations;
        stored.runtime_sequence = stored.running_config_sequence + 100U;
        stored.running_config_sequence = stored.runtime_sequence + 1U;
        terminal.integrity = ndms_native_delete_wal_integrity(terminal);
        overwrite_delete_wal_for_test(fixture.delete_wal, terminal);
        const auto performs_before = fixture.backend.perform_calls;

        auto restarted = fixture.restarted_coordinator();
        const auto result = restarted.resume_once(fixture.writer.lease);

        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              durable_observation_failed);
        CHECK(fixture.backend.perform_calls == performs_before);
        const auto claim = fixture.ownership.read("Wireguard5");
        REQUIRE(claim.record.has_value());
        CHECK(ndms_native_ownership_is_active(*claim.record));
        CHECK(fixture.snapshot_retained());
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
    }

    SUBCASE("dependency drift after save retains the active artifacts") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        static_cast<void>(stop_after_terminal_wal_is_visible(fixture));
        const auto performs_before = fixture.backend.perform_calls;
        fixture.dependencies.references.push_back(
            {NdmsNativeKeenPbrDependencyKind::interface_outbound,
             "outbound-added-after-save"});

        auto restarted = fixture.restarted_coordinator();
        const auto result = restarted.resume_once(fixture.writer.lease);

        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
              keen_pbr_dependencies_present);
        CHECK(fixture.backend.perform_calls == performs_before);
        const auto claim = fixture.ownership.read("Wireguard5");
        REQUIRE(claim.record.has_value());
        CHECK(ndms_native_ownership_is_active(*claim.record));
        CHECK(fixture.snapshot_retained());
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::unfinished);
    }

    SUBCASE("fresh restart pair permits tombstone then WAL-last cleanup") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        const auto terminal = stop_after_terminal_wal_is_visible(fixture);
        REQUIRE(terminal.post_save_absence_observations.has_value());
        const auto performs_before = fixture.backend.perform_calls;

        auto restarted = fixture.restarted_coordinator();
        const auto result = restarted.resume_once(fixture.writer.lease);

        CHECK(result.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(result.stop == NdmsNativeCooperativeDeleteStop::none);
        CHECK(fixture.backend.perform_calls == performs_before);
        CHECK(fixture.gateway.calls == 4U);
        const auto ledger = fixture.observations.read();
        REQUIRE(ledger.ledger.has_value());
        CHECK(ledger.ledger->sequence >
              terminal.post_save_absence_observations->
                  running_config_sequence);
        const auto claim = fixture.ownership.read("Wireguard5");
        REQUIRE(claim.record.has_value());
        CHECK(ndms_native_ownership_is_delete_tombstone(*claim.record));
        CHECK(fixture.snapshot_retained());
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::clean);
    }
}

TEST_CASE("reappearance after tombstone publication keeps cleanup WAL") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    fixture.faults->after_ownership_replace = [&fixture] {
        fixture.gateway.present = true;
    };

    const auto result = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());

    CHECK(result.status ==
          NdmsNativeCooperativeDeleteStatus::recovery_required);
    CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
          observed_target_reappeared_after_save);
    CHECK(fixture.backend.perform_calls == 2U);
    const auto claim = fixture.ownership.read("Wireguard5");
    REQUIRE(claim.record.has_value());
    CHECK(ndms_native_ownership_is_delete_tombstone(*claim.record));
    CHECK(fixture.snapshot_retained());
    const auto loaded = fixture.delete_wal.load();
    REQUIRE(loaded.record.has_value());
    CHECK(loaded.record->phase == NdmsNativeDeleteWalPhase::cleanup);
    CHECK(event_index(fixture.events, "wal.remove.visible") ==
          fixture.events.size());
}

TEST_CASE("dependency added before recovered save blocks save and tombstone") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    fixture.backend.throw_after_perform_call = 2U;
    const auto first = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());
    REQUIRE(first.stop ==
            NdmsNativeCooperativeDeleteStop::save_transport_ambiguous);
    REQUIRE(fixture.delete_wal.load().record.has_value());
    REQUIRE(fixture.delete_wal.load().record->phase ==
            NdmsNativeDeleteWalPhase::save_may_be_inflight);
    const auto performs_before = fixture.backend.perform_calls;
    fixture.backend.throw_after_perform_call = 0U;
    fixture.dependencies.references.push_back(
        {NdmsNativeKeenPbrDependencyKind::internal_vpn_policy,
         "policy-added-after-delete"});

    auto restarted = fixture.restarted_coordinator();
    const auto second = restarted.resume_once(
        fixture.writer.lease, fixture.resume_acknowledgement());

    CHECK(second.status ==
          NdmsNativeCooperativeDeleteStatus::recovery_required);
    CHECK(second.stop == NdmsNativeCooperativeDeleteStop::
          keen_pbr_dependencies_present);
    CHECK(fixture.backend.perform_calls == performs_before);
    const auto claim = fixture.ownership.read("Wireguard5");
    REQUIRE(claim.record.has_value());
    CHECK(ndms_native_ownership_is_active(*claim.record));
    CHECK_FALSE(ndms_native_ownership_is_delete_tombstone(*claim.record));
    CHECK(fixture.snapshot_retained());
    CHECK(fixture.delete_wal.readiness() ==
          NdmsNativeDeleteWalReadiness::unfinished);
}

TEST_CASE("delete failure phases come only from an exact durable reread") {
    struct TransitionCase final {
        const char* label;
        std::size_t publish_attempt;
        std::size_t replace_attempt;
        NdmsNativeDeleteWalPhase predecessor;
        NdmsNativeDeleteWalPhase successor;
    };
    const TransitionCase transitions[] = {
        {"prepared to delete-may-be-inflight", 2U, 1U,
         NdmsNativeDeleteWalPhase::prepared,
         NdmsNativeDeleteWalPhase::delete_may_be_inflight},
        {"observed absence to running-absence-verified", 3U, 2U,
         NdmsNativeDeleteWalPhase::delete_may_be_inflight,
         NdmsNativeDeleteWalPhase::running_absence_verified},
        {"running-absence-verified to save-may-be-inflight", 4U, 3U,
         NdmsNativeDeleteWalPhase::running_absence_verified,
         NdmsNativeDeleteWalPhase::save_may_be_inflight},
        {"tombstone to cleanup", 6U, 5U,
         NdmsNativeDeleteWalPhase::save_acknowledged_unverified,
         NdmsNativeDeleteWalPhase::cleanup},
    };

    for (const auto& transition : transitions) {
        CAPTURE(transition.label);
        {
            DeleteFixture fixture;
            fixture.install_owned_target();
            fixture.faults->fail_wal_before_visibility_call =
                transition.publish_attempt;

            const auto result = fixture.coordinator.delete_once(
                fixture.writer.lease, fixture.request());

            CHECK(result.status ==
                  NdmsNativeCooperativeDeleteStatus::recovery_required);
            CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
                  delete_wal_publish_failed);
            const auto loaded = fixture.delete_wal.load();
            REQUIRE(loaded.state == NdmsNativeDeleteWalLoadState::valid);
            REQUIRE(loaded.record.has_value());
            REQUIRE(loaded.record->phase == transition.predecessor);
            check_result_matches_durable_record(
                result, *loaded.record, transition.predecessor);
        }

        {
            DeleteFixture fixture;
            fixture.install_owned_target();
            fixture.faults->fail_wal_replace_call =
                transition.replace_attempt;

            const auto result = fixture.coordinator.delete_once(
                fixture.writer.lease, fixture.request());

            CHECK(result.status ==
                  NdmsNativeCooperativeDeleteStatus::recovery_required);
            CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
                  delete_wal_publish_failed);
            const auto loaded = fixture.delete_wal.load();
            REQUIRE(loaded.state == NdmsNativeDeleteWalLoadState::valid);
            REQUIRE(loaded.record.has_value());
            REQUIRE(loaded.record->phase == transition.successor);
            check_result_matches_durable_record(
                result, *loaded.record, transition.successor);
        }
    }
}

TEST_CASE("unreadable delete WAL never leaks guessed durable identity") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    fixture.faults->fail_wal_before_visibility_call = 2U;
    fixture.faults->before_wal_visibility_failure = [&fixture] {
        corrupt_delete_wal_for_test(fixture.delete_wal);
    };

    const auto result = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());

    CHECK(result.status ==
          NdmsNativeCooperativeDeleteStatus::recovery_required);
    CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
          delete_wal_publish_failed);
    CHECK(fixture.delete_wal.load().state ==
          NdmsNativeDeleteWalLoadState::corrupt_record);
    CHECK_FALSE(result.durable_phase.has_value());
    CHECK_FALSE(result.transaction_id.has_value());
    CHECK_FALSE(result.interface_name.has_value());
    CHECK_FALSE(result.kind.has_value());
    CHECK_FALSE(result.external_writer_race_accepted);
    CHECK_FALSE(result.global_save_scope_acknowledged);
}

TEST_CASE("failed initial WAL publication has no invented durable record") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    fixture.faults->fail_wal_before_visibility_call = 1U;

    const auto result = fixture.coordinator.delete_once(
        fixture.writer.lease, fixture.request());

    CHECK(result.status ==
          NdmsNativeCooperativeDeleteStatus::recovery_required);
    CHECK(result.stop == NdmsNativeCooperativeDeleteStop::
          delete_wal_publish_failed);
    CHECK(fixture.delete_wal.load().state ==
          NdmsNativeDeleteWalLoadState::absent);
    CHECK_FALSE(result.durable_phase.has_value());
    CHECK_FALSE(result.transaction_id.has_value());
    CHECK_FALSE(result.interface_name.has_value());
    CHECK_FALSE(result.kind.has_value());
    CHECK_FALSE(result.external_writer_race_accepted);
    CHECK_FALSE(result.global_save_scope_acknowledged);
}

TEST_CASE("visible WAL transition and cleanup crashes recover idempotently") {
    SUBCASE("visible prepared-to-inflight transition resumes") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.faults->fail_wal_replace_call = 1U;
        const auto first = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(first.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(first.stop == NdmsNativeCooperativeDeleteStop::
              delete_wal_publish_failed);
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::delete_may_be_inflight);
        CHECK(fixture.backend.perform_calls == 0U);

        fixture.faults->fail_wal_replace_call = 0U;
        auto restarted = fixture.restarted_coordinator();
        const auto second = restarted.resume_once(
            fixture.writer.lease, fixture.resume_acknowledgement());
        CHECK(second.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(fixture.snapshot_retained());
    }

    SUBCASE("visible tombstone publication resumes without rebinding claim") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.faults->fail_ownership_replace_after_visible = true;

        const auto first = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());

        CHECK(first.status ==
              NdmsNativeCooperativeDeleteStatus::recovery_required);
        CHECK(first.stop == NdmsNativeCooperativeDeleteStop::
              tombstone_publish_failed);
        const auto visible = fixture.ownership.read("Wireguard5");
        REQUIRE(visible.record.has_value());
        CHECK(ndms_native_ownership_is_delete_tombstone(*visible.record));
        REQUIRE(fixture.delete_wal.load().record.has_value());
        CHECK(fixture.delete_wal.load().record->phase ==
              NdmsNativeDeleteWalPhase::save_acknowledged_unverified);
        fixture.faults->fail_ownership_replace_after_visible = false;

        auto restarted = fixture.restarted_coordinator();
        const auto second = restarted.resume_once(fixture.writer.lease);

        CHECK(second.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(second.stop == NdmsNativeCooperativeDeleteStop::none);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::clean);
        CHECK(fixture.snapshot_retained());
    }

    SUBCASE("visible WAL unlink is terminal after exact reread") {
        DeleteFixture fixture;
        fixture.install_owned_target();
        fixture.faults->fail_wal_remove_after_unlink = true;
        const auto result = fixture.coordinator.delete_once(
            fixture.writer.lease, fixture.request());
        CHECK(result.status == NdmsNativeCooperativeDeleteStatus::
              save_acknowledged_unverified);
        CHECK(result.ownership_tombstone_durable);
        CHECK(fixture.delete_wal.readiness() ==
              NdmsNativeDeleteWalReadiness::clean);
        CHECK(fixture.snapshot_retained());
    }
}

TEST_CASE("unsafe delete WAL restart is fail-closed and performs nothing") {
    DeleteFixture fixture;
    fixture.install_owned_target();
    const auto wal_path = fixture.delete_wal.state_directory() /
                          kNdmsNativeDeleteWalFilename;
    REQUIRE(fs::create_directories(fixture.delete_wal.state_directory()));
    REQUIRE(::chmod(fixture.delete_wal.state_directory().c_str(), 0700) == 0);
    {
        const int descriptor = ::open(
            wal_path.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        REQUIRE(descriptor >= 0);
        const std::string legacy =
            R"({"schema_version":1,"phase":"prepared"})";
        REQUIRE(::write(descriptor, legacy.data(), legacy.size()) ==
                static_cast<ssize_t>(legacy.size()));
        REQUIRE(::close(descriptor) == 0);
    }

    const auto result = fixture.coordinator.resume_once(
        fixture.writer.lease);

    CHECK(result.stop ==
          NdmsNativeCooperativeDeleteStop::delete_wal_unsafe);
    CHECK(fixture.backend.perform_calls == 0U);
    CHECK(fixture.snapshot_retained());
    const auto claim = fixture.ownership.read("Wireguard5");
    REQUIRE(claim.record.has_value());
    CHECK(ndms_native_ownership_is_active(*claim.record));
}
