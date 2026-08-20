#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_executor.hpp"
#include "keenetic/ndms_native_import_forward_plan.hpp"
#include "keenetic/ndms_native_import_identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace keen_pbr3;

static_assert(!std::is_copy_constructible_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(!std::is_copy_constructible_v<
              std::optional<NdmsNativeAllocatorFenceReceipt>>);
static_assert(!std::is_default_constructible_v<
              NdmsNativeImportExecutorDependencies>);
static_assert(!std::is_constructible_v<
              NdmsNativeImportExecutorDependencies,
              NdmsNativeImportWalPublisher*,
              NdmsNativeImportSnapshotPublisher*,
              NdmsNativeImportGenerationCoordinator*,
              NdmsNativeLoopbackRciPostBackend*,
              NdmsNativeImportExecutorClock*>);

namespace {

constexpr const char* kPrivateKey =
    "UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFA=";
constexpr const char* kPublicKey =
    "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s=";

const auto kIssuedAt = NdmsNativeAllocatorMonotonicTime{
    std::chrono::seconds{1000}};
const auto kNow = kIssuedAt + std::chrono::seconds{5};
const auto kExpiresAt = kIssuedAt + std::chrono::seconds{30};

std::string plain_wireguard_config() {
    return std::string{"[Interface]\nPrivateKey = "} + kPrivateKey +
           "\nAddress = 10.7.0.2/32\n\n[Peer]\nPublicKey = " +
           kPublicKey +
           "\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0\n";
}

std::string amnezia_wireguard_config() {
    auto config = plain_wireguard_config();
    const auto peer = config.find("\n\n[Peer]");
    if (peer == std::string::npos) {
        throw std::runtime_error("invalid AWG executor fixture");
    }
    config.insert(
        peer,
        "\nJc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\n"
        "H1 = 101\nH2 = 202\nH3 = 303\nH4 = 404\n");
    return config;
}

std::string digest(const std::string& prefix, const char digit) {
    return prefix + std::string(64U, digit);
}

NdmsNativeImportBaselineEvidence authoritative_baseline(
    const std::uint32_t maintenance_generation,
    const std::uint64_t allocator_generation) {
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
    snapshot.observed_at = kIssuedAt;
    snapshot.observation_generation = 7U;
    snapshot.observation_epoch = 3U;
    snapshot.invalidation_epoch = 3U;
    auto built = build_ndms_native_import_baseline(
        snapshot,
        "Wireguard5",
        maintenance_generation,
        allocator_generation);
    if (!built.success() || !built.evidence.has_value()) {
        throw std::runtime_error("cannot build executor baseline fixture");
    }
    return *built.evidence;
}

NdmsNativeImportExecutionPlan execution_plan(
    const NdmsNativeAllocatorFenceMode mode =
        NdmsNativeAllocatorFenceMode::global_ndms_writer_lease) {
    NdmsNativeImportExecutionPlan plan;
    plan.expected_created_interface = "Wireguard5";
    plan.generation_ticket = digest(
        kNdmsNativeAllocatorGenerationTicketPrefix, 'c');
    plan.firmware_identity =
        kNdmsNativeAllocatorKeeneticOs511FirmwareIdentity;
    plan.allocator_implementation_digest = digest(
        kNdmsNativeAllocatorImplementationDigestPrefix, 'd');
    plan.observation_binding = {
        std::string(32U, 'a'), 9U, 7U};
    plan.fence_mode = mode;
    return plan;
}

NdmsNativeAllocatorFenceReceipt fence_receipt(
    const NdmsNativeImportExecutionPlan& plan,
    const NdmsNativeWireguardImportRequest& request,
    const std::uint64_t generation = 77U,
    const NdmsNativeAllocatorMonotonicTime expires_at = kExpiresAt) {
    NdmsNativeAllocatorFenceTestFields fields;
    fields.mode = plan.fence_mode;
    fields.range = ndms_native_allocator_required_range();
    fields.firmware_identity = plan.firmware_identity;
    fields.implementation_digest =
        plan.allocator_implementation_digest;
    fields.request_binding_digest =
        ndms_native_import_request_binding_digest(
            request, plan.expected_created_interface);
    fields.generation_ticket = plan.generation_ticket;
    fields.exact_target = plan.expected_created_interface;
    fields.generation = generation;
    fields.issued_at = kIssuedAt;
    fields.expires_at = expires_at;
    return NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
        std::move(fields));
}

class FakeClock final : public NdmsNativeImportExecutorClock {
public:
    NdmsNativeAllocatorMonotonicTime now() const noexcept override {
        if (times.empty()) return kNow;
        const auto selected = index < times.size()
            ? index : times.size() - 1U;
        ++index;
        return times[selected];
    }

    std::vector<NdmsNativeAllocatorMonotonicTime> times{kNow};
    mutable std::size_t index{0U};
};

class FakeGenerations final
    : public NdmsNativeImportGenerationCoordinator {
public:
    NdmsNativeImportGenerationSnapshot observe() override {
        if (events != nullptr) events->push_back("generation.observe");
        ++observe_calls;
        if (throw_on_observe == observe_calls) {
            throw std::runtime_error("synthetic generation observation");
        }
        return {maintenance_generation, allocator_generation};
    }

    std::optional<std::uint32_t> reserve_next(
        const std::string& transaction_id,
        const std::string& generation_ticket,
        const std::uint32_t base) override {
        if (events != nullptr) events->push_back("generation.reserve");
        ++reserve_calls;
        reserved_transaction_id = transaction_id;
        reserved_generation_ticket = generation_ticket;
        reserved_base = base;
        if (throw_on_reserve) {
            throw std::runtime_error("synthetic generation reservation");
        }
        if (!reservation.has_value()) return std::nullopt;
        maintenance_generation = *reservation;
        return reservation;
    }

    std::vector<std::string>* events{nullptr};
    std::uint32_t maintenance_generation{41U};
    std::uint64_t allocator_generation{77U};
    std::optional<std::uint32_t> reservation{42U};
    std::size_t observe_calls{0U};
    std::size_t reserve_calls{0U};
    std::size_t throw_on_observe{0U};
    bool throw_on_reserve{false};
    std::string reserved_transaction_id;
    std::string reserved_generation_ticket;
    std::uint32_t reserved_base{0U};
};

class FakeWalPublisher final : public NdmsNativeImportWalPublisher {
public:
    NdmsNativeImportWalAdmissionState begin_prepared_exclusive(
        const NdmsNativeImportWalRecord& record) override {
        if (!records.empty()) {
            ++exclusive_rejections;
            return NdmsNativeImportWalAdmissionState::
                unfinished_transaction_present;
        }
        publish_impl(record);
        return NdmsNativeImportWalAdmissionState::admitted;
    }

    void publish(const NdmsNativeImportWalRecord& record) override {
        publish_impl(record);
    }

    std::vector<std::string>* events{nullptr};
    std::size_t calls{0U};
    std::size_t fail_on_call{0U};
    std::size_t exclusive_rejections{0U};
    std::vector<NdmsNativeImportWalRecord> records;

private:
    void publish_impl(const NdmsNativeImportWalRecord& record) {
        if (events != nullptr) {
            events->push_back(
                std::string{"wal."} +
                ndms_native_import_wal_phase_name(record.phase));
        }
        ++calls;
        if (fail_on_call == calls) {
            throw std::runtime_error("synthetic WAL failure");
        }
        records.push_back(record);
    }
};

class FakeSnapshotPublisher final
    : public NdmsNativeImportSnapshotPublisher {
public:
    void publish(
        const std::string& expected_interface,
        const std::string& transaction_id,
        const std::string& marker,
        NdmsNativePanelDeleteSnapshot snapshot) override {
        if (events != nullptr) events->push_back("snapshot.publish");
        ++calls;
        published_interface = expected_interface;
        published_transaction_id = transaction_id;
        published_marker = marker;
        published_revision =
            std::string(snapshot.canonical_revision());
        published_kind = snapshot.kind();
        if (throw_on_publish) {
            throw std::runtime_error("synthetic snapshot publish failure");
        }
    }

    std::vector<std::string>* events{nullptr};
    std::size_t calls{0U};
    bool throw_on_publish{false};
    std::string published_interface;
    std::string published_transaction_id;
    std::string published_marker;
    std::string published_revision;
    NdmsNativeTunnelImportKind published_kind{
        NdmsNativeTunnelImportKind::wireguard};
};

class FakeBackend final : public NdmsNativeLoopbackRciPostBackend {
private:
    NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeImportPreDispatchGuard& guard,
        NdmsNativeImportBackendTrace& trace) override {
        ++calls;
        saw_nonempty_request = !request_body.empty();
        if (throw_before_guard) {
            throw std::runtime_error("synthetic backend setup failure");
        }
        NdmsNativeImportRawTransportResponse response;
        trace.pre_dispatch_guard_evaluated = true;
        if (!guard.authorize_dispatch()) return response;
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        ++perform_calls;
        if (events != nullptr) events->push_back("transport.post");
        response.request_may_have_been_dispatched = may_have_dispatched;
        response.transport_ok = transport_ok;
        response.status_code = status_code;
        response.content_type_seen = true;
        response.content_type_is_json = true;
        CHECK(response.body.write_secret_body_chunk(response_body));
        return response;
    }

public:
    std::vector<std::string>* events{nullptr};
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    bool saw_nonempty_request{false};
    bool throw_before_guard{false};
    bool may_have_dispatched{true};
    bool transport_ok{true};
    int status_code{200};
    std::string response_body{
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])"};
};

struct Fixture final {
    Fixture()
        : dependencies(
              NdmsNativeImportExecutorTestIssuer::issue(
                  &wal, &snapshots, &generations, &backend, &clock)) {
        generations.events = &events;
        wal.events = &events;
        snapshots.events = &events;
        backend.events = &events;
    }

    NdmsNativeImportBaselineEvidence baseline() const {
        return authoritative_baseline(
            generations.maintenance_generation,
            generations.allocator_generation);
    }

    std::vector<std::string> events;
    FakeWalPublisher wal;
    FakeSnapshotPublisher snapshots;
    FakeGenerations generations;
    FakeBackend backend;
    FakeClock clock;
    NdmsNativeImportExecutorDependencies dependencies;
};

} // namespace

TEST_CASE("native import request binding is deterministic, target- and kind-bound") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    const auto first = ndms_native_import_request_binding_digest(
        request, "Wireguard5");
    const auto repeated = ndms_native_import_request_binding_digest(
        request, "Wireguard5");
    const auto other_target = ndms_native_import_request_binding_digest(
        request, "Wireguard6");
    const auto from_persisted_identity =
        ndms_native_import_request_binding_digest(
            request.transaction_id(),
            request.marker(),
            request.candidate_revision(),
            request.kind(),
            "Wireguard5");
    const auto other_kind =
        ndms_native_import_request_binding_digest(
            request.transaction_id(),
            request.marker(),
            request.candidate_revision(),
            NdmsNativeTunnelImportKind::amnezia_wireguard,
            "Wireguard5");

    CHECK(first == repeated);
    CHECK(first == from_persisted_identity);
    CHECK(first != other_target);
    CHECK(first != other_kind);
    CHECK(first.rfind(
              kNdmsNativeAllocatorRequestBindingDigestPrefix, 0U) == 0U);
    CHECK(first.size() ==
          std::string_view{
              kNdmsNativeAllocatorRequestBindingDigestPrefix}.size() +
              64U);
    CHECK(first.find(kPrivateKey) == std::string::npos);
}

TEST_CASE("native import executor cannot dispatch without every authority") {
    SUBCASE("AWG uses the same kind-bound stock transaction") {
        Fixture fixture;
        const auto plan = execution_plan();
        auto prepared = prepare_ndms_native_import(
            amnezia_wireguard_config());
        const auto& request = prepared.request_identity();
        REQUIRE(request.kind() ==
                NdmsNativeTunnelImportKind::amnezia_wireguard);
        auto receipt = fence_receipt(plan, request);

        const auto result = execute_ndms_native_import_transaction(
            std::move(prepared),
            plan,
            fixture.baseline(),
            std::optional<NdmsNativeAllocatorFenceReceipt>{
                std::move(receipt)},
            fixture.dependencies);

        CHECK(result.status == NdmsNativeImportExecutionStatus::
              response_recorded_needs_verification);
        CHECK(result.stop == NdmsNativeImportExecutionStop::none);
        CHECK(fixture.wal.calls == 3U);
        CHECK(fixture.generations.reserve_calls == 1U);
        CHECK(fixture.backend.calls == 1U);
        REQUIRE(result.response_manifest.has_value());
        CHECK(result.response_manifest->request_kind ==
              NdmsNativeTunnelImportKind::amnezia_wireguard);
        for (const auto& record : fixture.wal.records) {
            CHECK(record.kind ==
                  NdmsNativeTunnelImportKind::amnezia_wireguard);
            const auto safe = serialize_ndms_native_import_wal(record);
            CHECK(safe.find(kPrivateKey) == std::string::npos);
            CHECK(safe.find("Jc = 4") == std::string::npos);
        }
    }

    SUBCASE("current firmware provider yields no fence") {
        Fixture fixture;
        const auto plan = execution_plan();
        auto prepared = prepare_ndms_native_import(
            plain_wireguard_config());
        const auto& request = prepared.request_identity();
        NdmsNativeKeeneticOs511AllocatorFenceProvider provider;
        NdmsNativeAllocatorFenceExpectation expectation;
        expectation.mode = plan.fence_mode;
        expectation.range = ndms_native_allocator_required_range();
        expectation.firmware_identity = plan.firmware_identity;
        expectation.implementation_digest =
            plan.allocator_implementation_digest;
        expectation.request_binding_digest =
            ndms_native_import_request_binding_digest(
                request, plan.expected_created_interface);
        expectation.generation_ticket = plan.generation_ticket;
        expectation.exact_target = plan.expected_created_interface;
        expectation.current_generation = 77U;
        expectation.now = kNow;
        auto unavailable = provider.try_acquire(expectation);
        REQUIRE_FALSE(unavailable.has_value());

        const auto result = execute_ndms_native_import_transaction(
            std::move(prepared),
            plan,
            fixture.baseline(),
            std::move(unavailable),
            fixture.dependencies);

        CHECK(result.status == NdmsNativeImportExecutionStatus::blocked);
        CHECK(result.stop == NdmsNativeImportExecutionStop::fence_required);
        CHECK(fixture.wal.calls == 0U);
        CHECK(fixture.generations.reserve_calls == 0U);
        CHECK(fixture.backend.calls == 0U);
    }

    SUBCASE("no WAL publisher") {
        Fixture fixture;
        const auto plan = execution_plan();
        auto prepared = prepare_ndms_native_import(
            plain_wireguard_config());
        const auto& request = prepared.request_identity();
        auto receipt = fence_receipt(plan, request);
        auto missing_wal = NdmsNativeImportExecutorTestIssuer::issue(
            nullptr,
            &fixture.snapshots,
            &fixture.generations,
            &fixture.backend,
            &fixture.clock);

        const auto result = execute_ndms_native_import_transaction(
            std::move(prepared),
            plan,
            fixture.baseline(),
            std::optional<NdmsNativeAllocatorFenceReceipt>{
                std::move(receipt)},
            missing_wal);

        CHECK(result.stop ==
              NdmsNativeImportExecutionStop::missing_dependency);
        CHECK(fixture.generations.observe_calls == 0U);
        CHECK(fixture.backend.calls == 0U);
    }
}

TEST_CASE("native import executor publishes prepared WAL before reservation") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    fixture.wal.fail_on_call = 1U;

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::prepared_wal_publish_failed);
    CHECK(fixture.events == std::vector<std::string>{
          "generation.observe", "wal.prepared"});
    CHECK(fixture.generations.reserve_calls == 0U);
    CHECK(fixture.backend.calls == 0U);
}

TEST_CASE("native import seals the exact snapshot after WAL and before reservation") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        amnezia_wireguard_config());
    const auto& request = prepared.request_identity();
    const auto transaction_id = std::string(request.transaction_id());
    const auto marker = std::string(request.marker());
    const auto revision = std::string(request.candidate_revision());
    auto receipt = fence_receipt(plan, request);
    fixture.snapshots.throw_on_publish = true;

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::snapshot_publish_failed);
    CHECK(result.prepared_wal_published);
    CHECK_FALSE(result.snapshot_published);
    CHECK(fixture.events == std::vector<std::string>{
          "generation.observe", "wal.prepared", "snapshot.publish"});
    CHECK(fixture.snapshots.calls == 1U);
    CHECK(fixture.snapshots.published_interface == "Wireguard5");
    CHECK(fixture.snapshots.published_transaction_id == transaction_id);
    CHECK(fixture.snapshots.published_marker == marker);
    CHECK(fixture.snapshots.published_revision == revision);
    CHECK(fixture.snapshots.published_kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    CHECK(fixture.generations.reserve_calls == 0U);
    CHECK(fixture.backend.calls == 0U);
    REQUIRE(fixture.wal.records.size() == 1U);
    CHECK(fixture.wal.records.front().phase ==
          NdmsNativeImportWalPhase::prepared);
}

TEST_CASE("receipt without the complete dispatch budget is rejected") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(
        plan,
        request,
        77U,
        kNow + std::chrono::seconds{5});

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status == NdmsNativeImportExecutionStatus::blocked);
    CHECK(result.stop == NdmsNativeImportExecutionStop::fence_invalid);
    CHECK(result.fence_error ==
          NdmsNativeAllocatorFenceValidationError::
              minimum_remaining_insufficient);
    CHECK(fixture.wal.calls == 0U);
    CHECK(fixture.generations.reserve_calls == 0U);
    CHECK(fixture.backend.calls == 0U);
}

TEST_CASE("native import executor publishes inflight WAL before transport") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    fixture.wal.fail_on_call = 2U;

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::inflight_wal_publish_failed);
    CHECK(fixture.events == std::vector<std::string>{
          "generation.observe", "wal.prepared", "snapshot.publish",
          "generation.reserve",
          "generation.observe", "wal.import_may_be_inflight"});
    CHECK(fixture.backend.calls == 0U);
}

TEST_CASE("expired fence after setup cannot start the network perform") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    fixture.clock.times = {kNow, kNow, kNow, kExpiresAt};

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::fence_lost_after_intent);
    CHECK(result.fence_error ==
          NdmsNativeAllocatorFenceValidationError::expired);
    CHECK(result.inflight_wal_published);
    CHECK(result.backend_call_confirmed);
    CHECK_FALSE(result.dispatch_perform_started);
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK(fixture.backend.calls == 1U);
    CHECK(fixture.backend.perform_calls == 0U);
    REQUIRE(fixture.wal.records.size() == 2U);
    CHECK(fixture.wal.records.back().phase ==
          NdmsNativeImportWalPhase::import_may_be_inflight);
}

TEST_CASE("pre-backend transport failure is never reported as dispatched") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    NdmsNativeImportTransportTestControl::fail_before_backend_once();

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::transport_failed);
    CHECK(result.inflight_wal_published);
    CHECK_FALSE(result.backend_call_confirmed);
    CHECK_FALSE(result.dispatch_perform_started);
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK(fixture.backend.calls == 0U);
    CHECK(fixture.backend.perform_calls == 0U);
    REQUIRE(fixture.wal.records.size() == 2U);
    CHECK(fixture.wal.records.back().phase ==
          NdmsNativeImportWalPhase::import_may_be_inflight);
}

TEST_CASE("backend setup failure is not mislabeled as a fence loss") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    fixture.backend.throw_before_guard = true;

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::transport_failed);
    CHECK(result.inflight_wal_published);
    CHECK(result.backend_call_confirmed);
    CHECK_FALSE(result.dispatch_perform_started);
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK(result.fence_error ==
          NdmsNativeAllocatorFenceValidationError::none);
    CHECK(fixture.backend.calls == 1U);
    CHECK(fixture.backend.perform_calls == 0U);
    REQUIRE(fixture.wal.records.size() == 2U);
    CHECK(fixture.wal.records.back().phase ==
          NdmsNativeImportWalPhase::import_may_be_inflight);
}

TEST_CASE("ambiguous native import response is recorded and never replayed") {
    Fixture fixture;
    const auto plan = execution_plan();
    fixture.backend.transport_ok = false;
    fixture.backend.status_code = 0;
    fixture.backend.response_body.clear();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);

    const auto first = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(first.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(first.stop ==
          NdmsNativeImportExecutionStop::ambiguous_response);
    CHECK(first.response_wal_published);
    CHECK(first.recovery_action ==
          NdmsNativeImportRecoveryAction::retry_read_only_observation);
    CHECK(fixture.backend.calls == 1U);
    REQUIRE(fixture.wal.records.size() == 3U);
    CHECK(fixture.wal.records.back().phase ==
          NdmsNativeImportWalPhase::response_recorded);

    auto second_prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    auto fresh_receipt = fence_receipt(
        plan, second_prepared.request_identity());
    const auto second = execute_ndms_native_import_transaction(
        std::move(second_prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(fresh_receipt)},
        fixture.dependencies);
    CHECK(second.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(second.stop ==
          NdmsNativeImportExecutionStop::unfinished_transaction_present);
    CHECK(second.recovery_action ==
          NdmsNativeImportRecoveryAction::retry_read_only_observation);
    CHECK(fixture.wal.exclusive_rejections == 1U);
    CHECK(fixture.generations.reserve_calls == 1U);
    CHECK(fixture.backend.calls == 1U);
    CHECK(fixture.wal.records.size() == 3U);
}

TEST_CASE("allocator receipt cannot authorize a swapped import request") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto authorized = prepare_ndms_native_import(
        plain_wireguard_config());
    auto receipt = fence_receipt(plan, authorized.request_identity());
    auto swapped = prepare_ndms_native_import(
        plain_wireguard_config());
    REQUIRE(authorized.request_identity().transaction_id() !=
            swapped.request_identity().transaction_id());

    const auto result = execute_ndms_native_import_transaction(
        std::move(swapped),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status == NdmsNativeImportExecutionStatus::blocked);
    CHECK(result.stop == NdmsNativeImportExecutionStop::fence_invalid);
    CHECK(result.fence_error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_mismatch);
    CHECK(fixture.wal.calls == 0U);
    CHECK(fixture.generations.reserve_calls == 0U);
    CHECK(fixture.backend.calls == 0U);
}

TEST_CASE("native import executor keeps one identity through durable order") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    const auto transaction_id = std::string(request.transaction_id());
    const auto marker = std::string(request.marker());
    const auto candidate_revision =
        std::string(request.candidate_revision());
    const auto baseline = fixture.baseline();
    const auto persisted_baseline =
        persist_ndms_native_import_baseline(baseline);
    const auto request_binding =
        ndms_native_import_request_binding_digest(
            request, plan.expected_created_interface);

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        baseline,
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status == NdmsNativeImportExecutionStatus::
          response_recorded_needs_verification);
    CHECK(result.stop == NdmsNativeImportExecutionStop::none);
    CHECK(result.prepared_wal_published);
    CHECK(result.snapshot_published);
    CHECK(result.inflight_wal_published);
    CHECK(result.response_wal_published);
    CHECK(result.backend_call_confirmed);
    CHECK(result.dispatch_perform_started);
    CHECK(result.request_may_have_been_dispatched);
    CHECK(fixture.backend.calls == 1U);
    CHECK(fixture.backend.perform_calls == 1U);
    CHECK(fixture.backend.saw_nonempty_request);
    REQUIRE(fixture.wal.records.size() == 3U);

    CHECK(fixture.events == std::vector<std::string>{
          "generation.observe", "wal.prepared", "snapshot.publish",
          "generation.reserve",
          "generation.observe", "wal.import_may_be_inflight",
          "generation.observe", "generation.observe", "transport.post",
          "wal.response_recorded"});
    CHECK(fixture.generations.reserved_transaction_id == transaction_id);
    CHECK(fixture.generations.reserved_generation_ticket ==
          plan.generation_ticket);
    CHECK(fixture.generations.reserved_base == 41U);

    for (const auto& record : fixture.wal.records) {
        CHECK(record.transaction_id == transaction_id);
        CHECK(record.marker == marker);
        CHECK(valid_ndms_native_import_marker(
            record.marker, record.transaction_id));
        CHECK(record.candidate_revision == candidate_revision);
        CHECK(record.request_binding_sha256 == request_binding);
        CHECK(record.generation_ticket == plan.generation_ticket);
        CHECK(record.maintenance_base_generation == 41U);
        CHECK(record.baseline == persisted_baseline);
        CHECK(valid_ndms_native_import_persisted_baseline(
            record.baseline));
        const auto serialized = serialize_ndms_native_import_wal(record);
        CHECK(serialized.find(kPrivateKey) == std::string::npos);
        CHECK(serialized.find("Endpoint") == std::string::npos);
    }
    CHECK_FALSE(fixture.wal.records[0].reserved_generation.has_value());
    CHECK(fixture.wal.records[1].reserved_generation == 42U);
    CHECK(fixture.wal.records[2].reserved_generation == 42U);
    REQUIRE(fixture.wal.records[2].response_manifest_sha256.has_value());
    CHECK(fixture.wal.records[2].response_manifest_sha256->rfind(
              "ndms-import-response-manifest-v3-", 0U) == 0U);
    CHECK(fixture.wal.records[2].created_interface == "Wireguard5");
}

TEST_CASE("unexpected returned targets stay recovery-only and never become ownership") {
    const auto run = [](const std::string& returned_target) {
        Fixture fixture;
        const auto plan = execution_plan();
        fixture.backend.response_body =
            "[{\"interface\":{\"wireguard\":{\"import\":{\"created\":\"" +
            returned_target +
            "\",\"intersects\":\"\"}}}}]";
        auto prepared = prepare_ndms_native_import(
            plain_wireguard_config());
        const auto& request = prepared.request_identity();
        const auto marker = std::string(request.marker());
        auto receipt = fence_receipt(plan, request);

        const auto result = execute_ndms_native_import_transaction(
            std::move(prepared),
            plan,
            fixture.baseline(),
            std::optional<NdmsNativeAllocatorFenceReceipt>{
                std::move(receipt)},
            fixture.dependencies);

        CHECK(result.status ==
              NdmsNativeImportExecutionStatus::recovery_required);
        CHECK(result.stop ==
              NdmsNativeImportExecutionStop::ambiguous_response);
        REQUIRE(result.response_manifest.has_value());
        CHECK(result.response_manifest->created_evidence ==
              NdmsNativeImportCreatedEvidence::absent);
        REQUIRE(fixture.wal.records.size() == 3U);
        const auto& recorded = fixture.wal.records.back();
        CHECK(recorded.phase ==
              NdmsNativeImportWalPhase::response_recorded);
        CHECK_FALSE(recorded.created_interface.has_value());
        const auto safe = serialize_ndms_native_import_wal(recorded);
        CHECK(safe.find(returned_target) == std::string::npos);
        CHECK(safe.find(kPrivateKey) == std::string::npos);

        NdmsNativeImportRecoveryObservation observation;
        observation.authoritative = true;
        observation.generation_advanced = true;
        observation.protected_catalog_unchanged = true;
        observation.marker_match_count = 1U;
        observation.marker_target = returned_target;
        observation.target_absent_in_baseline = true;
        observation.target_down = true;
        CHECK_FALSE(plan_ndms_native_import_forward_completion(
                        recorded,
                        observation,
                        digest("ndms-rci-full-v1-", 'e'))
                        .actionable());
        CHECK(recorded.marker == marker);
        return classify_ndms_native_import_recovery(
            recorded, observation);
    };

    SUBCASE("another managed slot can only be rolled back by recovery") {
        CHECK(run("Wireguard6") ==
              NdmsNativeImportRecoveryAction::
                  rollback_delete_exact_owned);
    }
    SUBCASE("a protected slot blocks even recovery deletion") {
        CHECK(run("Wireguard4") ==
              NdmsNativeImportRecoveryAction::block_unknown);
    }
}

TEST_CASE("native import executor rejects a stale authoritative baseline") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    const auto stale_baseline = authoritative_baseline(41U, 76U);

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        stale_baseline,
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(result.status == NdmsNativeImportExecutionStatus::blocked);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::baseline_mismatch);
    CHECK(fixture.generations.observe_calls == 1U);
    CHECK(fixture.generations.reserve_calls == 0U);
    CHECK(fixture.wal.calls == 0U);
    CHECK(fixture.backend.calls == 0U);
}

TEST_CASE("native import executor blocks incompatible or protected targets") {
    SUBCASE("protected expected target") {
        Fixture fixture;
        auto plan = execution_plan();
        auto prepared = prepare_ndms_native_import(
            plain_wireguard_config());
        const auto& request = prepared.request_identity();
        auto receipt = fence_receipt(plan, request);
        plan.expected_created_interface = "Wireguard4";

        const auto result = execute_ndms_native_import_transaction(
            std::move(prepared),
            plan,
            fixture.baseline(),
            std::optional<NdmsNativeAllocatorFenceReceipt>{
                std::move(receipt)},
            fixture.dependencies);

        CHECK(result.stop ==
              NdmsNativeImportExecutionStop::expected_target_ineligible);
        CHECK(fixture.generations.observe_calls == 0U);
        CHECK(fixture.wal.calls == 0U);
        CHECK(fixture.backend.calls == 0U);
    }

    SUBCASE("exact create receipt cannot authorize empty-name import") {
        Fixture fixture;
        const auto plan = execution_plan(
            NdmsNativeAllocatorFenceMode::exact_create_if_absent);
        auto prepared = prepare_ndms_native_import(
            plain_wireguard_config());
        const auto& request = prepared.request_identity();
        auto receipt = fence_receipt(plan, request);

        const auto result = execute_ndms_native_import_transaction(
            std::move(prepared),
            plan,
            fixture.baseline(),
            std::optional<NdmsNativeAllocatorFenceReceipt>{
                std::move(receipt)},
            fixture.dependencies);

        CHECK(result.stop ==
              NdmsNativeImportExecutionStop::incompatible_fence_mode);
        CHECK(fixture.generations.observe_calls == 0U);
        CHECK(fixture.wal.calls == 0U);
        CHECK(fixture.backend.calls == 0U);
    }
}

TEST_CASE("response WAL failure cannot authorize forward progress") {
    Fixture fixture;
    const auto plan = execution_plan();
    auto prepared = prepare_ndms_native_import(
        plain_wireguard_config());
    const auto& request = prepared.request_identity();
    auto receipt = fence_receipt(plan, request);
    fixture.wal.fail_on_call = 3U;

    const auto result = execute_ndms_native_import_transaction(
        std::move(prepared),
        plan,
        fixture.baseline(),
        std::optional<NdmsNativeAllocatorFenceReceipt>{
            std::move(receipt)},
        fixture.dependencies);

    CHECK(fixture.backend.calls == 1U);
    CHECK(result.status ==
          NdmsNativeImportExecutionStatus::recovery_required);
    CHECK(result.stop ==
          NdmsNativeImportExecutionStop::response_wal_publish_failed);
    CHECK_FALSE(result.response_wal_published);
    CHECK(result.recovery_action ==
          NdmsNativeImportRecoveryAction::retry_read_only_observation);
}
