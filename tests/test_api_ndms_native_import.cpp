#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_ndms_native_import.hpp"
#include "api/server.hpp"
#include "api/sse_broadcaster.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class ImportAuthDirectory final {
public:
    ImportAuthDirectory() {
        char pattern[] = "/tmp/keen-pbr-native-import-api-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path_ = created;
        auth_path_ = path_ / "auth.json";
        std::ofstream output(auth_path_, std::ios::binary | std::ios::trunc);
        REQUIRE(output);
        output << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
        REQUIRE(output);
    }

    ~ImportAuthDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& auth_path() const noexcept {
        return auth_path_;
    }

private:
    std::filesystem::path path_;
    std::filesystem::path auth_path_;
};

class TrustedLocalConnectionEvaluatorGuard final {
public:
    explicit TrustedLocalConnectionEvaluatorGuard(
        TrustedLocalConnectionEvaluatorForTesting evaluator) {
        set_trusted_local_connection_evaluator_for_testing(
            std::move(evaluator));
    }

    ~TrustedLocalConnectionEvaluatorGuard() {
        reset_trusted_local_connection_evaluator_for_testing();
    }
};

using ImportCallback = std::function<NdmsNativeCooperativeImportResult(
    std::string&&,
    NdmsNativeExternalWriterRaceAcceptance)>;
using ImportRecoveryCallback =
    std::function<NdmsNativeCooperativeImportResumeResult(
        const std::shared_ptr<SensitiveRequestReservation>&)>;

class ImportTestReservation final : public SensitiveRequestReservation {
public:
    explicit ImportTestReservation(std::atomic<bool>& active) noexcept
        : active_(active) {}

    ~ImportTestReservation() noexcept override {
        active_.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool>& active_;
};

class NativeImportApiFixture final {
public:
    explicit NativeImportApiFixture(
        ImportCallback callback = {},
        ImportRecoveryCallback recovery_callback = {})
        : auth_file_("KEEN_PBR_AUTH_FILE",
                     auth_directory_.auth_path().string()),
          trusted_transport_([this](std::string_view,
                                    std::string_view,
                                    bool) {
              return protected_transport_.load(
                  std::memory_order_relaxed);
          }),
          context_(test_support::make_minimal_api_context(
              broadcaster_,
              "/tmp/keen-pbr-native-import-api-config.json")),
          server_(config()) {
        if (callback) {
            context_.run_ndms_native_import_fn =
                [callback = std::move(callback)](
                    std::string&& raw,
                    const NdmsNativeExternalWriterRaceAcceptance
                        acceptance,
                    const std::shared_ptr<SensitiveRequestReservation>&) {
                    return callback(std::move(raw), acceptance);
                };
        }
        if (recovery_callback) {
            context_.resume_ndms_native_import_fn =
                std::move(recovery_callback);
        }
        context_.reserve_ndms_native_import_fn = [this]() {
            return reserve_for_request();
        };
        context_.reserve_ndms_native_import_recovery_fn = [this]() {
            return reserve_for_request();
        };
        register_ndms_native_import_handler(server_, context_);
        server_.start();
        client_ = std::make_unique<httplib::Client>(
            "127.0.0.1", port());
    }

    ~NativeImportApiFixture() {
        server_.stop();
    }

    NativeImportApiFixture(const NativeImportApiFixture&) = delete;
    NativeImportApiFixture& operator=(const NativeImportApiFixture&) = delete;

    httplib::Headers login() {
        const auto response = client_->Post(
            "/api/auth/login",
            R"({"username":"admin","password":"secret"})",
            "application/json");
        REQUIRE(response != nullptr);
        REQUIRE(response->status == 200);
        const auto cookie = response->get_header_value("Set-Cookie");
        const auto separator = cookie.find(';');
        return {{"Cookie", cookie.substr(0U, separator)}};
    }

    void grant_step_up(const httplib::Headers& session) {
        const auto response = client_->Post(
            "/api/auth/step-up",
            session,
            R"({"username":"admin","password":"secret"})",
            "application/json");
        REQUIRE(response != nullptr);
        REQUIRE(response->status == 200);
    }

    httplib::Headers accepted_headers(const httplib::Headers& session) {
        auto headers = session;
        headers.emplace(
            std::string{kNdmsNativeImportRaceAcceptanceHeader},
            std::string{kNdmsNativeImportRaceAcceptanceValue});
        return headers;
    }

    void set_protected_transport(const bool value) {
        protected_transport_.store(value, std::memory_order_relaxed);
    }

    void set_admission(const NdmsNativeMutationAdmissionState value) {
        reservation_available_.store(
            value == NdmsNativeMutationAdmissionState::admitted,
            std::memory_order_release);
    }

    std::size_t reservation_attempts() const noexcept {
        return reservation_attempts_.load(std::memory_order_relaxed);
    }

    bool reservation_active() const noexcept {
        return reservation_active_.load(std::memory_order_acquire);
    }

    httplib::Client& client() noexcept { return *client_; }

    std::unique_ptr<httplib::Client> new_client() const {
        return std::make_unique<httplib::Client>(
            "127.0.0.1", port());
    }

private:
    std::shared_ptr<SensitiveRequestReservation> reserve_for_request() {
        reservation_attempts_.fetch_add(1U, std::memory_order_relaxed);
        if (!reservation_available_.load(std::memory_order_acquire)) {
            return {};
        }
        bool expected = false;
        if (!reservation_active_.compare_exchange_strong(
                expected, true,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return {};
        }
        try {
            return std::make_shared<ImportTestReservation>(
                reservation_active_);
        } catch (...) {
            reservation_active_.store(false, std::memory_order_release);
            throw;
        }
    }

    static int port() {
        return test_support::isolated_api_port(0);
    }

    static ApiConfig config() {
        ApiConfig value;
        value.listen = "127.0.0.1:" + std::to_string(port());
        return value;
    }

    ImportAuthDirectory auth_directory_;
    test_support::EnvironmentVariableGuard auth_file_;
    std::atomic<bool> protected_transport_{true};
    std::atomic<bool> reservation_available_{true};
    std::atomic<bool> reservation_active_{false};
    std::atomic<std::size_t> reservation_attempts_{0U};
    TrustedLocalConnectionEvaluatorGuard trusted_transport_;
    SseBroadcaster broadcaster_;
    ApiContext context_;
    ApiServer server_;
    std::unique_ptr<httplib::Client> client_;
};

NdmsNativeCooperativeImportResult completed_result() {
    NdmsNativeCooperativeImportResult result;
    result.status = NdmsNativeCooperativeImportStatus::completed;
    result.stop = NdmsNativeCooperativeImportStop::none;
    result.external_ndms_writer_race_accepted = true;
    result.request_may_have_been_dispatched = true;
    result.rollback_snapshot_may_be_retained = true;
    result.ownership_published = true;
    result.transaction_id = std::string(32U, 'a');
    result.expected_interface = "Wireguard5";
    result.created_interface = "Wireguard5";
    result.created_kernel_interface = "nwg5";
    result.kind = NdmsNativeTunnelImportKind::wireguard;
    result.delete_wal_readiness = NdmsNativeDeleteWalReadiness::clean;
    result.import_wal_readiness =
        NdmsNativeCooperativeImportWalReadiness::clean;
    return result;
}

NdmsNativeCooperativeImportResumeResult completed_recovery_result() {
    NdmsNativeCooperativeImportResumeResult result;
    result.status = NdmsNativeCooperativeImportResumeStatus::completed;
    result.stop = NdmsNativeCooperativeImportResumeStop::none;
    result.ownership_published = true;
    result.wal_removed = true;
    result.transaction_id = std::string(32U, 'b');
    result.expected_interface = "Wireguard5";
    result.created_interface = "Wireguard5";
    result.created_kernel_interface = "nwg5";
    result.kind = NdmsNativeTunnelImportKind::wireguard;
    result.phase = NdmsNativeImportWalPhase::response_recorded;
    result.delete_wal_readiness = NdmsNativeDeleteWalReadiness::clean;
    result.import_wal_readiness =
        NdmsNativeCooperativeImportWalReadiness::unfinished;
    result.forward_admission_state =
        NdmsNativeImportRecoveryAdmissionState::admitted;
    result.forward_dispatch_state =
        NdmsNativeImportRecoveryDispatchState::completed;
    return result;
}

NdmsNativeCooperativeImportResumeResult no_work_recovery_result() {
    NdmsNativeCooperativeImportResumeResult result;
    result.status = NdmsNativeCooperativeImportResumeStatus::no_work;
    result.stop = NdmsNativeCooperativeImportResumeStop::none;
    result.delete_wal_readiness = NdmsNativeDeleteWalReadiness::clean;
    result.import_wal_readiness =
        NdmsNativeCooperativeImportWalReadiness::clean;
    return result;
}

NdmsNativeCooperativeImportResumeResult blocked_recovery_result() {
    auto result = completed_recovery_result();
    result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
    result.stop =
        NdmsNativeCooperativeImportResumeStop::observation_unstable;
    result.wal_may_require_recovery = true;
    result.ownership_published = false;
    result.wal_removed = false;
    result.created_interface.reset();
    result.created_kernel_interface.reset();
    result.forward_admission_state.reset();
    result.forward_dispatch_state.reset();
    return result;
}

void check_no_store(const httplib::Result& response) {
    REQUIRE(response != nullptr);
    CHECK(response->get_header_value("Cache-Control") == "no-store");
}

} // namespace

TEST_CASE("native import API maps only redacted typed evidence") {
    auto result = completed_result();
    result.status = NdmsNativeCooperativeImportStatus::recovery_required;
    result.stop = NdmsNativeCooperativeImportStop::executor_blocked;
    // These two claims are not delegated to the callback. The import-only
    // HTTP contract always tells the narrower public truth even if a faulty
    // embedder attempts to overclaim either capability.
    result.external_ndms_writer_race_excluded = true;
    result.system_configuration_save_performed = true;
    result.request_may_have_been_dispatched = true;
    result.wal_may_require_recovery = true;
    result.request_error = NdmsNativeTunnelImportErrorCode::invalid_encoding;
    result.direct_observation_failure =
        NdmsNativeDirectObservationFailure::transport_failed;
    result.baseline_error =
        NdmsNativeImportBaselineBuildError::catalog_not_fresh;
    result.executor_stop = NdmsNativeImportExecutionStop::transport_failed;
    result.forward_admission_state =
        NdmsNativeImportRecoveryAdmissionState::lease_busy;
    result.forward_dispatch_state =
        NdmsNativeImportRecoveryDispatchState::step_failed;
    result.forward_failed_step =
        NdmsNativeImportRecoveryStep::publish_ownership;

    const auto response = ndms_native_import_api_response(result);
    CHECK(response.at("status") == "recovery_required");
    CHECK(response.at("stop") == "executor_blocked");
    CHECK(response.at("external_ndms_writer_race_excluded") == false);
    CHECK(response.at("external_ndms_writer_race_accepted") == true);
    CHECK(response.at("system_configuration_save_performed") == false);
    CHECK(response.at("request_may_have_been_dispatched") == true);
    CHECK(response.at("wal_may_require_recovery") == true);
    CHECK(response.at("rollback_snapshot_may_be_retained") == true);
    CHECK(response.at("ownership_published") == true);
    CHECK(response.at("transaction_id") == std::string(32U, 'a'));
    CHECK(response.at("expected_interface") == "Wireguard5");
    CHECK(response.at("created_interface") == "Wireguard5");
    CHECK(response.at("created_kernel_interface") == "nwg5");
    CHECK(response.at("kind") == "wireguard");
    CHECK(response.at("delete_wal_readiness") == "clean");
    CHECK(response.at("import_wal_readiness") == "clean");
    CHECK(response.at("request_error") == "invalid_encoding");
    CHECK(response.at("direct_observation_failure") == "transport_failed");
    CHECK(response.at("baseline_error") == "catalog_not_fresh");
    CHECK(response.at("executor_stop") == "transport_failed");
    CHECK(response.at("forward_admission_state") == "lease_busy");
    CHECK(response.at("forward_dispatch_state") == "step_failed");
    CHECK(response.at("forward_failed_step") == "publish_ownership");

    result.transaction_id = "PrivateKey=must-not-escape";
    result.expected_interface = "Wireguard5/revision/private";
    result.created_interface = "marker-secret";
    result.created_kernel_interface = "nwg5/private";
    const auto refused_strings = ndms_native_import_api_response(result);
    CHECK_FALSE(refused_strings.contains("transaction_id"));
    CHECK_FALSE(refused_strings.contains("expected_interface"));
    CHECK_FALSE(refused_strings.contains("created_interface"));
    CHECK_FALSE(refused_strings.contains("created_kernel_interface"));
    const auto serialized = refused_strings.dump();
    CHECK(serialized.find("PrivateKey") == std::string::npos);
    CHECK(serialized.find("revision/private") == std::string::npos);
    CHECK(serialized.find("marker-secret") == std::string::npos);
    CHECK(serialized.find("nwg5/private") == std::string::npos);

    result.stop = NdmsNativeCooperativeImportStop::
        ownership_target_not_available;
    CHECK(ndms_native_import_api_response(result).at("stop") ==
          "ownership_target_not_available");
    result.stop = NdmsNativeCooperativeImportStop::
        snapshot_target_not_available;
    CHECK(ndms_native_import_api_response(result).at("stop") ==
          "snapshot_target_not_available");
}

TEST_CASE("native import API exposes only a complete proved created identity") {
    auto result = completed_result();
    result.status = NdmsNativeCooperativeImportStatus::recovery_required;
    result.stop = NdmsNativeCooperativeImportStop::executor_blocked;
    result.wal_may_require_recovery = true;

    SUBCASE("paired safe firmware and kernel identities are mapped") {
        const auto response = ndms_native_import_api_response(result);
        CHECK(response.at("created_interface") == "Wireguard5");
        CHECK(response.at("created_kernel_interface") == "nwg5");
    }

    SUBCASE("firmware identity without kernel proof is redacted as a pair") {
        result.created_kernel_interface.reset();
        const auto response = ndms_native_import_api_response(result);
        CHECK_FALSE(response.contains("created_interface"));
        CHECK_FALSE(response.contains("created_kernel_interface"));
    }

    SUBCASE("kernel identity without firmware proof is redacted as a pair") {
        result.created_interface.reset();
        const auto response = ndms_native_import_api_response(result);
        CHECK_FALSE(response.contains("created_interface"));
        CHECK_FALSE(response.contains("created_kernel_interface"));
    }

    SUBCASE("unsafe kernel identity is redacted as a pair") {
        result.created_kernel_interface = "nwg5/private";
        const auto response = ndms_native_import_api_response(result);
        CHECK_FALSE(response.contains("created_interface"));
        CHECK_FALSE(response.contains("created_kernel_interface"));
        CHECK(response.dump().find("nwg5/private") == std::string::npos);
    }

    SUBCASE("overlong kernel identity is redacted as a pair") {
        result.created_kernel_interface = std::string(16U, 'n');
        const auto response = ndms_native_import_api_response(result);
        CHECK_FALSE(response.contains("created_interface"));
        CHECK_FALSE(response.contains("created_kernel_interface"));
    }
}

TEST_CASE("native import rejects incoherent or unknown callback results") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        [&](std::string&&,
            NdmsNativeExternalWriterRaceAcceptance) {
            auto result = completed_result();
            switch (callback_count++) {
            case 0U:
                result.stop =
                    NdmsNativeCooperativeImportStop::unexpected_failure;
                break;
            case 1U:
                result.created_interface = "Wireguard5/private";
                break;
            case 2U:
                result.ownership_published = false;
                break;
            case 3U:
                result.external_ndms_writer_race_accepted = false;
                break;
            case 4U:
                result.wal_may_require_recovery = true;
                break;
            case 5U:
                result.status = static_cast<
                    NdmsNativeCooperativeImportStatus>(255U);
                break;
            case 6U:
                result.kind = static_cast<
                    NdmsNativeTunnelImportKind>(255U);
                break;
            case 7U:
                result.transaction_id = "not-a-transaction";
                break;
            case 8U:
                result.expected_interface = "Wireguard6";
                break;
            case 9U:
                result.kind.reset();
                break;
            case 10U:
                result.delete_wal_readiness =
                    NdmsNativeDeleteWalReadiness::unfinished;
                break;
            case 11U:
                result.import_wal_readiness =
                    NdmsNativeCooperativeImportWalReadiness::unsafe;
                break;
            case 12U:
                result.created_kernel_interface.reset();
                break;
            case 13U:
                result.created_kernel_interface = "nwg5/private";
                break;
            case 14U:
                result.created_kernel_interface = std::string(16U, 'n');
                break;
            case 15U:
                result.created_interface.reset();
                break;
            case 16U:
                result.request_may_have_been_dispatched = false;
                break;
            default:
                result.rollback_snapshot_may_be_retained = false;
                break;
            }
            return result;
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    const auto headers = fixture.accepted_headers(session);

    for (std::size_t index = 0U; index < 18U; ++index) {
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeImportApiPath},
            headers,
            "secret",
            "text/plain");
        check_no_store(response);
        CHECK(response->status == 500);
        CHECK(nlohmann::json::parse(response->body).at("error") ==
              "sensitive_request_failed");
        CHECK(response->body.find("Wireguard5/private") ==
              std::string::npos);
        CHECK(response->body.find("nwg5/private") ==
              std::string::npos);
    }
    CHECK(callback_count == 18U);
}

TEST_CASE("native import authentication and step-up reject before streaming") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        [&](std::string&&,
            NdmsNativeExternalWriterRaceAcceptance) {
            ++callback_count;
            return completed_result();
        });

    reset_sensitive_request_body_stream_count_for_testing();
    const auto unauthenticated = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        "must-not-stream",
        "text/plain");
    check_no_store(unauthenticated);
    CHECK(unauthenticated->status == 401);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(callback_count == 0U);

    const auto session = fixture.login();
    reset_sensitive_request_body_stream_count_for_testing();
    const auto no_step_up = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        fixture.accepted_headers(session),
        "must-not-stream",
        "text/plain");
    check_no_store(no_step_up);
    CHECK(no_step_up->status == 403);
    CHECK(nlohmann::json::parse(no_step_up->body).at("error") ==
          "step_up_required");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(callback_count == 0U);
}

TEST_CASE("native import preflight is bodyless and reports residual risk") {
    NativeImportApiFixture fixture(
        [](std::string&&,
           NdmsNativeExternalWriterRaceAcceptance) {
            return completed_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto accepted = fixture.client().Post(
        std::string{kNdmsNativeImportPreflightApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(accepted);
    REQUIRE(accepted->status == 200);
    const auto body = nlohmann::json::parse(accepted->body);
    CHECK(body.at("admitted") == true);
    CHECK(body.at("owner_risk_acceptance_required") == true);
    CHECK(body.at("external_ndms_writer_race_excluded") == false);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    const auto one_byte = fixture.client().Post(
        std::string{kNdmsNativeImportPreflightApiPath},
        session,
        "x",
        "application/octet-stream");
    check_no_store(one_byte);
    CHECK(one_byte->status == 400);

    const auto too_large = fixture.client().Post(
        std::string{kNdmsNativeImportPreflightApiPath},
        session,
        "xx",
        "application/octet-stream");
    check_no_store(too_large);
    CHECK(too_large->status == 413);
}

TEST_CASE("native import availability content type and consent reject pre-body") {
    {
        NativeImportApiFixture unavailable;
        const auto unavailable_session = unavailable.login();
        unavailable.grant_step_up(unavailable_session);
        reset_sensitive_request_body_stream_count_for_testing();
        const auto no_callback = unavailable.client().Post(
            std::string{kNdmsNativeImportApiPath},
            unavailable.accepted_headers(unavailable_session),
            "must-not-stream",
            "text/plain");
        check_no_store(no_callback);
        CHECK(no_callback->status == 503);
        CHECK(no_callback->get_header_value("Connection") == "close");
        CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

        reset_sensitive_request_body_stream_count_for_testing();
        const auto no_callback_preflight = unavailable.client().Post(
            std::string{kNdmsNativeImportPreflightApiPath},
            unavailable_session,
            "",
            "application/octet-stream");
        check_no_store(no_callback_preflight);
        CHECK(no_callback_preflight->status == 503);
        CHECK(no_callback_preflight->get_header_value("Connection") ==
              "close");
        CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    }

    {
        std::size_t blocked_callback_count = 0U;
        NativeImportApiFixture blocked(
            [&](std::string&&,
                NdmsNativeExternalWriterRaceAcceptance) {
                ++blocked_callback_count;
                return completed_result();
            });
        const auto blocked_session = blocked.login();
        blocked.grant_step_up(blocked_session);
        blocked.set_admission(
            NdmsNativeMutationAdmissionState::blocked);

        reset_sensitive_request_body_stream_count_for_testing();
        const auto dirty_wal = blocked.client().Post(
            std::string{kNdmsNativeImportApiPath},
            blocked.accepted_headers(blocked_session),
            "must-not-stream",
            "text/plain");
        check_no_store(dirty_wal);
        CHECK(dirty_wal->status == 503);
        CHECK(dirty_wal->get_header_value("Connection") == "close");
        CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
        CHECK(blocked_callback_count == 0U);

        reset_sensitive_request_body_stream_count_for_testing();
        const auto dirty_wal_preflight = blocked.client().Post(
            std::string{kNdmsNativeImportPreflightApiPath},
            blocked_session,
            "",
            "application/octet-stream");
        check_no_store(dirty_wal_preflight);
        CHECK(dirty_wal_preflight->status == 503);
        CHECK(dirty_wal_preflight->get_header_value("Connection") ==
              "close");
        CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

        blocked.set_admission(
            NdmsNativeMutationAdmissionState::unavailable);
        const auto unreadable_wal_preflight = blocked.client().Post(
            std::string{kNdmsNativeImportPreflightApiPath},
            blocked_session,
            "",
            "application/octet-stream");
        check_no_store(unreadable_wal_preflight);
        CHECK(unreadable_wal_preflight->status == 503);
        CHECK(blocked_callback_count == 0U);
    }

    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        [&](std::string&&,
            NdmsNativeExternalWriterRaceAcceptance) {
            ++callback_count;
            return completed_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto wrong_type = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        fixture.accepted_headers(session),
        "must-not-stream",
        "application/json");
    check_no_store(wrong_type);
    CHECK(wrong_type->status == 415);
    CHECK(wrong_type->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto missing_consent = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        session,
        "must-not-stream",
        "text/plain");
    check_no_store(missing_consent);
    CHECK(missing_consent->status == 428);
    CHECK(missing_consent->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    auto wrong_consent_headers = session;
    wrong_consent_headers.emplace(
        std::string{kNdmsNativeImportRaceAcceptanceHeader},
        "accepted");
    reset_sensitive_request_body_stream_count_for_testing();
    const auto wrong_consent = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        wrong_consent_headers,
        "must-not-stream",
        "text/plain");
    check_no_store(wrong_consent);
    CHECK(wrong_consent->status == 428);
    CHECK(wrong_consent->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    auto duplicate_headers = fixture.accepted_headers(session);
    duplicate_headers.emplace(
        std::string{kNdmsNativeImportRaceAcceptanceHeader},
        std::string{kNdmsNativeImportRaceAcceptanceValue});
    reset_sensitive_request_body_stream_count_for_testing();
    const auto duplicate_consent = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        duplicate_headers,
        "must-not-stream",
        "text/plain");
    check_no_store(duplicate_consent);
    CHECK(duplicate_consent->status == 428);
    CHECK(duplicate_consent->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(callback_count == 0U);
}

TEST_CASE("native import protected transport rejects before streaming") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        [&](std::string&&,
            NdmsNativeExternalWriterRaceAcceptance) {
            ++callback_count;
            return completed_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    fixture.set_protected_transport(false);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto response = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        fixture.accepted_headers(session),
        "must-not-stream",
        "text/plain");
    check_no_store(response);
    CHECK(response->status == 403);
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "protected_secret_transport_unavailable");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(callback_count == 0U);
}

TEST_CASE("native import consumes at most 512 KiB and invokes once") {
    std::size_t callback_count = 0U;
    std::size_t accepted_bytes = 0U;
    NativeImportApiFixture fixture(
        [&](std::string&& raw,
            const NdmsNativeExternalWriterRaceAcceptance acceptance) {
            ++callback_count;
            accepted_bytes = raw.size();
            CHECK(acceptance ==
                  NdmsNativeExternalWriterRaceAcceptance::owner_accepted);
            return completed_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    const auto headers = fixture.accepted_headers(session);

    const std::string maximum(
        kNdmsNativePreparedImportMaximumInputBytes, 'x');
    const auto accepted = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        headers,
        maximum,
        "Text/Plain; Charset=UTF-8");
    check_no_store(accepted);
    REQUIRE(accepted->status == 200);
    CHECK(callback_count == 1U);
    CHECK(accepted_bytes == maximum.size());
    const auto response = nlohmann::json::parse(accepted->body);
    CHECK(response.at("status") == "completed");
    CHECK(response.at("external_ndms_writer_race_excluded") == false);
    CHECK(response.at("external_ndms_writer_race_accepted") == true);
    CHECK(response.at("system_configuration_save_performed") == false);

    const auto oversized = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        headers,
        std::string(kNdmsNativePreparedImportMaximumInputBytes + 1U, 'x'),
        "text/plain");
    check_no_store(oversized);
    CHECK(oversized->status == 413);
    CHECK(callback_count == 1U);
}

TEST_CASE("native import callback failure is generic and never retried") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        [&](std::string&& raw,
            NdmsNativeExternalWriterRaceAcceptance) ->
            NdmsNativeCooperativeImportResult {
            ++callback_count;
            CHECK(raw == "PRIVATE_TEST_SECRET");
            throw std::runtime_error(
                "PRIVATE_TEST_SECRET must not reach HTTP");
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    const auto response = fixture.client().Post(
        std::string{kNdmsNativeImportApiPath},
        fixture.accepted_headers(session),
        "PRIVATE_TEST_SECRET",
        "text/plain");
    check_no_store(response);
    CHECK(response->status == 500);
    CHECK(callback_count == 1U);
    CHECK(response->body.find("PRIVATE_TEST_SECRET") == std::string::npos);
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "sensitive_request_failed");
}

TEST_CASE("native import reservation excludes a second body stream") {
    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool first_entered = false;
    bool release_first = false;
    std::atomic<std::size_t> callback_count{0U};

    NativeImportApiFixture fixture(
        [&](std::string&&,
            NdmsNativeExternalWriterRaceAcceptance) {
            callback_count.fetch_add(1U, std::memory_order_relaxed);
            std::unique_lock<std::mutex> lock(barrier_mutex);
            first_entered = true;
            barrier_cv.notify_all();
            barrier_cv.wait(lock, [&] { return release_first; });
            return completed_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    const auto headers = fixture.accepted_headers(session);

    reset_sensitive_request_body_stream_count_for_testing();
    int first_status = 0;
    std::thread first_request([&] {
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeImportApiPath},
            headers,
            "FIRST_PRIVATE_KEY",
            "text/plain");
        first_status = response ? response->status : -1;
    });

    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&] { return first_entered; });
    }
    const auto streams_after_first =
        sensitive_request_body_stream_count_for_testing();
    auto second_client = fixture.new_client();
    const auto second = second_client->Post(
        std::string{kNdmsNativeImportApiPath},
        headers,
        "SECOND_MUST_NOT_STREAM",
        "text/plain");
    CHECK(second != nullptr);
    if (second) {
        CHECK(second->status == 503);
        CHECK(second->get_header_value("Connection") == "close");
    }
    CHECK(sensitive_request_body_stream_count_for_testing() ==
          streams_after_first);
    CHECK(callback_count.load(std::memory_order_relaxed) == 1U);

    {
        std::lock_guard<std::mutex> lock(barrier_mutex);
        release_first = true;
    }
    barrier_cv.notify_all();
    first_request.join();
    CHECK(first_status == 200);
}

TEST_CASE("native import recovery maps only coherent redacted evidence") {
    auto result = completed_recovery_result();
    result.phase = NdmsNativeImportWalPhase::ownership_published;
    result.recovery_action =
        NdmsNativeImportRecoveryAction::resume_forward_reconcile;

    const auto response = ndms_native_import_recovery_api_response(result);
    CHECK(response.at("status") == "completed");
    CHECK(response.at("stop") == "none");
    CHECK(response.at("ndms_import_request_dispatched") == false);
    CHECK(response.at("ndms_delete_dispatched") == false);
    CHECK(response.at("system_configuration_save_performed") == false);
    CHECK(response.at("external_ndms_writer_race_excluded") == false);
    CHECK(response.at("wal_may_require_recovery") == false);
    CHECK(response.at("ownership_published") == true);
    CHECK(response.at("wal_removed") == true);
    CHECK(response.at("expected_interface") == "Wireguard5");
    CHECK(response.at("created_interface") == "Wireguard5");
    CHECK(response.at("created_kernel_interface") == "nwg5");
    CHECK(response.at("kind") == "wireguard");
    CHECK(response.at("phase") == "ownership_published");
    CHECK(response.at("delete_wal_readiness") == "clean");
    CHECK(response.at("import_wal_readiness") == "unfinished");
    CHECK(response.at("recovery_action") ==
          "resume_forward_reconcile");
    CHECK(response.at("forward_admission_state") == "admitted");
    CHECK(response.at("forward_dispatch_state") == "completed");
    CHECK_FALSE(response.contains("transaction_id"));
    CHECK(response.dump().find(std::string(32U, 'b')) ==
          std::string::npos);

    const auto no_work = ndms_native_import_recovery_api_response(
        no_work_recovery_result());
    CHECK(no_work.at("status") == "no_work");
    CHECK(no_work.at("delete_wal_readiness") == "clean");
    CHECK(no_work.at("import_wal_readiness") == "clean");
    CHECK_FALSE(no_work.contains("expected_interface"));

    auto observation_failed = blocked_recovery_result();
    observation_failed.stop = NdmsNativeCooperativeImportResumeStop::
        first_observation_failed;
    observation_failed.direct_observation_failure =
        NdmsNativeDirectObservationFailure::transport_failed;
    const auto blocked = ndms_native_import_recovery_api_response(
        observation_failed);
    CHECK(blocked.at("status") == "blocked");
    CHECK(blocked.at("direct_observation_failure") ==
          "transport_failed");
    CHECK_FALSE(blocked.contains("transaction_id"));
}

TEST_CASE("native import recovery rejects unknown or incoherent results") {
    const auto reject = [](auto mutate) {
        auto result = completed_recovery_result();
        mutate(result);
        CHECK_THROWS(
            ndms_native_import_recovery_api_response(result));
    };

    reject([](auto& result) {
        result.status = static_cast<
            NdmsNativeCooperativeImportResumeStatus>(255U);
    });
    reject([](auto& result) {
        result.stop = static_cast<
            NdmsNativeCooperativeImportResumeStop>(255U);
    });
    reject([](auto& result) {
        result.ndms_import_request_dispatched = true;
    });
    reject([](auto& result) { result.ndms_delete_dispatched = true; });
    reject([](auto& result) {
        result.system_configuration_save_performed = true;
    });
    reject([](auto& result) {
        result.external_ndms_writer_race_excluded = true;
    });
    reject([](auto& result) {
        result.transaction_id = "PrivateKey=must-not-escape";
    });
    reject([](auto& result) { result.expected_interface = "Wireguard05"; });
    reject([](auto& result) { result.created_interface = "Wireguard6"; });
    reject([](auto& result) { result.created_kernel_interface.reset(); });
    reject([](auto& result) {
        result.created_kernel_interface = "nwg5/private";
    });
    reject([](auto& result) {
        result.phase = NdmsNativeImportWalPhase::prepared;
    });
    reject([](auto& result) {
        result.import_wal_readiness =
            NdmsNativeCooperativeImportWalReadiness::clean;
    });
    reject([](auto& result) { result.ownership_published = false; });
    reject([](auto& result) { result.wal_removed = false; });
    reject([](auto& result) { result.wal_may_require_recovery = true; });
    reject([](auto& result) {
        result.forward_dispatch_state =
            NdmsNativeImportRecoveryDispatchState::step_failed;
        result.forward_failed_step =
            NdmsNativeImportRecoveryStep::delete_exact_owned_target;
    });
    reject([](auto& result) {
        result.direct_observation_failure =
            NdmsNativeDirectObservationFailure::transport_failed;
    });
    reject([](auto& result) {
        result.recovery_action =
            NdmsNativeImportRecoveryAction::resume_forward_reconcile;
    });

    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::writer_missing;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::
            first_observation_failed;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        result.direct_observation_failure =
            NdmsNativeDirectObservationFailure::transport_failed;
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = blocked_recovery_result();
        result.stop = NdmsNativeCooperativeImportResumeStop::
            first_observation_failed;
        result.direct_observation_failure =
            NdmsNativeDirectObservationFailure::none;
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::
            forward_admission_failed;
        result.phase = NdmsNativeImportWalPhase::prepared;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        result.ownership_published = false;
        result.forward_admission_state =
            NdmsNativeImportRecoveryAdmissionState::lease_busy;
        result.forward_dispatch_state.reset();
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::
            ownership_publish_failed;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        result.ownership_published = false;
        result.forward_dispatch_state =
            NdmsNativeImportRecoveryDispatchState::step_failed;
        result.forward_failed_step =
            NdmsNativeImportRecoveryStep::remove_wal_record;
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = completed_recovery_result();
        result.phase = NdmsNativeImportWalPhase::ownership_published;
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::
            forward_admission_failed;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        result.ownership_published = false;
        result.forward_admission_state =
            NdmsNativeImportRecoveryAdmissionState::lease_busy;
        result.forward_dispatch_state.reset();
        result.recovery_action =
            NdmsNativeImportRecoveryAction::resume_forward_reconcile;
        CHECK_THROWS(ndms_native_import_recovery_api_response(result));
    }

    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::
            forward_admission_failed;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        result.ownership_published = false;
        result.forward_admission_state =
            NdmsNativeImportRecoveryAdmissionState::lease_busy;
        result.forward_dispatch_state.reset();
        CHECK_NOTHROW(ndms_native_import_recovery_api_response(result));
    }
    {
        auto result = completed_recovery_result();
        result.status = NdmsNativeCooperativeImportResumeStatus::blocked;
        result.stop = NdmsNativeCooperativeImportResumeStop::
            ownership_publish_failed;
        result.wal_may_require_recovery = true;
        result.wal_removed = false;
        result.ownership_published = false;
        result.forward_dispatch_state =
            NdmsNativeImportRecoveryDispatchState::step_failed;
        result.forward_failed_step =
            NdmsNativeImportRecoveryStep::publish_ownership;
        CHECK_NOTHROW(ndms_native_import_recovery_api_response(result));
    }

    auto no_work = no_work_recovery_result();
    no_work.wal_may_require_recovery = true;
    CHECK_THROWS(ndms_native_import_recovery_api_response(no_work));

    auto blocked = blocked_recovery_result();
    blocked.stop = NdmsNativeCooperativeImportResumeStop::none;
    CHECK_THROWS(ndms_native_import_recovery_api_response(blocked));
}

TEST_CASE("native import recovery is bodyless and invokes exactly once") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        ImportCallback{},
        [&](const std::shared_ptr<SensitiveRequestReservation>& reservation) {
            ++callback_count;
            CHECK(reservation != nullptr);
            return no_work_recovery_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    const auto accepted = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(accepted);
    REQUIRE(accepted->status == 200);
    CHECK(nlohmann::json::parse(accepted->body).at("status") ==
          "no_work");
    CHECK(callback_count == 1U);
    CHECK_FALSE(fixture.reservation_active());

    const auto one_byte = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "x",
        "application/octet-stream");
    check_no_store(one_byte);
    CHECK(one_byte->status == 400);
    CHECK(callback_count == 1U);
    CHECK_FALSE(fixture.reservation_active());

    const auto too_large = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "xx",
        "application/octet-stream");
    check_no_store(too_large);
    CHECK(too_large->status == 413);
    CHECK(callback_count == 1U);
    CHECK_FALSE(fixture.reservation_active());
}

TEST_CASE("native import recovery guards precede reservation and callback") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        ImportCallback{},
        [&](const std::shared_ptr<SensitiveRequestReservation>&) {
            ++callback_count;
            return no_work_recovery_result();
        });

    const auto unauthenticated = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        "",
        "application/octet-stream");
    check_no_store(unauthenticated);
    CHECK(unauthenticated->status == 401);
    CHECK(fixture.reservation_attempts() == 0U);

    const auto session = fixture.login();
    const auto no_step_up = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(no_step_up);
    CHECK(no_step_up->status == 403);
    CHECK(fixture.reservation_attempts() == 0U);

    fixture.grant_step_up(session);
    fixture.set_protected_transport(false);
    const auto unprotected = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(unprotected);
    CHECK(unprotected->status == 403);
    CHECK(fixture.reservation_attempts() == 0U);
    CHECK(callback_count == 0U);
}

TEST_CASE("native import recovery reservation refusal is pre-body") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        ImportCallback{},
        [&](const std::shared_ptr<SensitiveRequestReservation>&) {
            ++callback_count;
            return no_work_recovery_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    fixture.set_admission(NdmsNativeMutationAdmissionState::blocked);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto response = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "must-not-stream",
        "application/octet-stream");
    check_no_store(response);
    CHECK(response->status == 503);
    CHECK(response->get_header_value("Connection") == "close");
    CHECK(fixture.reservation_attempts() == 1U);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(callback_count == 0U);
}

TEST_CASE("native import recovery reservation excludes a second callback") {
    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool first_entered = false;
    bool release_first = false;
    std::atomic<std::size_t> callback_count{0U};

    NativeImportApiFixture fixture(
        ImportCallback{},
        [&](const std::shared_ptr<SensitiveRequestReservation>&) {
            callback_count.fetch_add(1U, std::memory_order_relaxed);
            std::unique_lock<std::mutex> lock(barrier_mutex);
            first_entered = true;
            barrier_cv.notify_all();
            barrier_cv.wait(lock, [&] { return release_first; });
            return no_work_recovery_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    int first_status = 0;
    std::thread first_request([&] {
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeImportRecoveryApiPath},
            session,
            "",
            "application/octet-stream");
        first_status = response ? response->status : -1;
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&] { return first_entered; });
    }

    auto second_client = fixture.new_client();
    const auto second = second_client->Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "SECOND_MUST_NOT_STREAM",
        "application/octet-stream");
    REQUIRE(second != nullptr);
    CHECK(second->status == 503);
    CHECK(second->get_header_value("Connection") == "close");
    CHECK(callback_count.load(std::memory_order_relaxed) == 1U);

    {
        std::lock_guard<std::mutex> lock(barrier_mutex);
        release_first = true;
    }
    barrier_cv.notify_all();
    first_request.join();
    CHECK(first_status == 200);
    CHECK_FALSE(fixture.reservation_active());
}

TEST_CASE("native import recovery callback failure releases reservation") {
    std::size_t callback_count = 0U;
    NativeImportApiFixture fixture(
        ImportCallback{},
        [&](const std::shared_ptr<SensitiveRequestReservation>&) {
            ++callback_count;
            if (callback_count == 1U) {
                throw std::runtime_error(
                    "PRIVATE_RECOVERY_DETAIL must not reach HTTP");
            }
            return no_work_recovery_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    const auto failed = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(failed);
    CHECK(failed->status == 500);
    CHECK(failed->body.find("PRIVATE_RECOVERY_DETAIL") ==
          std::string::npos);
    CHECK_FALSE(fixture.reservation_active());

    const auto retried_by_owner = fixture.client().Post(
        std::string{kNdmsNativeImportRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(retried_by_owner);
    CHECK(retried_by_owner->status == 200);
    CHECK(callback_count == 2U);
    CHECK_FALSE(fixture.reservation_active());
}

} // namespace keen_pbr3

#endif // WITH_API
