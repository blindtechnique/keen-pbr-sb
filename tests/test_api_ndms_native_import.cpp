#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_ndms_native_import.hpp"
#include "api/server.hpp"
#include "api/sse_broadcaster.hpp"

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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

class NativeImportApiFixture final {
public:
    explicit NativeImportApiFixture(ImportCallback callback = {})
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
        context_.run_ndms_native_import_fn = std::move(callback);
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

    httplib::Client& client() noexcept { return *client_; }

private:
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

} // namespace keen_pbr3

#endif // WITH_API
