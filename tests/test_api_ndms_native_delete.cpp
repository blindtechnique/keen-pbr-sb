#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_ndms_native_delete.hpp"
#include "api/server.hpp"
#include "api/sse_broadcaster.hpp"

#include <atomic>
#include <cstddef>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class DeleteAuthDirectory final {
public:
    DeleteAuthDirectory() {
        char pattern[] = "/tmp/keen-pbr-native-delete-api-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path_ = created;
        auth_path_ = path_ / "auth.json";
        std::ofstream output(auth_path_, std::ios::binary | std::ios::trunc);
        REQUIRE(output);
        output << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
        REQUIRE(output);
    }

    ~DeleteAuthDirectory() {
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

class DeleteTestReservation final : public SensitiveRequestReservation {
public:
    explicit DeleteTestReservation(std::atomic<bool>& active) noexcept
        : active_(active) {}

    ~DeleteTestReservation() noexcept override {
        active_.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool>& active_;
};

using DeleteCallback = std::function<NdmsNativeCooperativeDeleteResult(
    const NdmsNativeCooperativeDeleteRequest&)>;
using ResumeCallback = std::function<NdmsNativeCooperativeDeleteResult(
    const NdmsNativeCooperativeDeleteResumeAcknowledgement&)>;

class NativeDeleteApiFixture final {
public:
    NativeDeleteApiFixture(DeleteCallback delete_callback = {},
                           ResumeCallback resume_callback = {})
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
              "/tmp/keen-pbr-native-delete-api-config.json")),
          server_(config()) {
        if (delete_callback) {
            context_.run_ndms_native_delete_fn =
                [this, callback = std::move(delete_callback)](
                    const NdmsNativeCooperativeDeleteRequest& request,
                    const std::shared_ptr<SensitiveRequestReservation>&
                        reservation) {
                    if (reservation &&
                        reservation_active_.load(
                            std::memory_order_acquire)) {
                        reservation_seen_by_callback_.fetch_add(
                            1U, std::memory_order_relaxed);
                    }
                    return callback(request);
                };
        }
        if (resume_callback) {
            context_.resume_ndms_native_delete_fn =
                [this, callback = std::move(resume_callback)](
                    const NdmsNativeCooperativeDeleteResumeAcknowledgement&
                        acknowledgement,
                    const std::shared_ptr<SensitiveRequestReservation>&
                        reservation) {
                    if (reservation &&
                        reservation_active_.load(
                            std::memory_order_acquire)) {
                        reservation_seen_by_callback_.fetch_add(
                            1U, std::memory_order_relaxed);
                    }
                    return callback(acknowledgement);
                };
        }
        context_.reserve_ndms_native_delete_fn = [this]()
            -> std::shared_ptr<SensitiveRequestReservation> {
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
                return std::make_shared<DeleteTestReservation>(
                    reservation_active_);
            } catch (...) {
                reservation_active_.store(false, std::memory_order_release);
                throw;
            }
        };
        register_ndms_native_delete_handler(server_, context_);
        server_.start();
        client_ = std::make_unique<httplib::Client>("127.0.0.1", port());
    }

    ~NativeDeleteApiFixture() { server_.stop(); }

    NativeDeleteApiFixture(const NativeDeleteApiFixture&) = delete;
    NativeDeleteApiFixture& operator=(const NativeDeleteApiFixture&) = delete;

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

    httplib::Headers acknowledged_headers(
        const httplib::Headers& session) const {
        auto headers = session;
        headers.emplace(
            std::string{kNdmsNativeDeleteRaceAcceptanceHeader},
            std::string{kNdmsNativeDeleteRaceAcceptanceValue});
        headers.emplace(
            std::string{kNdmsNativeDeleteGlobalSaveHeader},
            std::string{kNdmsNativeDeleteGlobalSaveValue});
        return headers;
    }

    void set_protected_transport(const bool value) {
        protected_transport_.store(value, std::memory_order_relaxed);
    }

    void set_reservation_available(const bool value) {
        reservation_available_.store(value, std::memory_order_release);
    }

    std::size_t reservation_attempts() const noexcept {
        return reservation_attempts_.load(std::memory_order_relaxed);
    }

    std::size_t reservation_seen_by_callback() const noexcept {
        return reservation_seen_by_callback_.load(
            std::memory_order_relaxed);
    }

    bool reservation_active() const noexcept {
        return reservation_active_.load(std::memory_order_acquire);
    }

    httplib::Client& client() noexcept { return *client_; }

    std::unique_ptr<httplib::Client> new_client() const {
        return std::make_unique<httplib::Client>("127.0.0.1", port());
    }

private:
    static int port() { return test_support::isolated_api_port(1); }

    static ApiConfig config() {
        ApiConfig value;
        value.listen = "127.0.0.1:" + std::to_string(port());
        return value;
    }

    DeleteAuthDirectory auth_directory_;
    test_support::EnvironmentVariableGuard auth_file_;
    std::atomic<bool> protected_transport_{true};
    std::atomic<bool> reservation_available_{true};
    std::atomic<bool> reservation_active_{false};
    std::atomic<std::size_t> reservation_attempts_{0U};
    std::atomic<std::size_t> reservation_seen_by_callback_{0U};
    TrustedLocalConnectionEvaluatorGuard trusted_transport_;
    SseBroadcaster broadcaster_;
    ApiContext context_;
    ApiServer server_;
    std::unique_ptr<httplib::Client> client_;
};

std::string valid_ownership_revision(const char digit = 'a') {
    return "ndms-native-owner-v3-" + std::string(64U, digit);
}

std::string valid_delete_body(
    const std::string& interface_name = "Wireguard5",
    const std::string& revision = valid_ownership_revision()) {
    return nlohmann::json{
        {"interface_name", interface_name},
        {"expected_ownership_revision", revision},
        {"confirm_label", interface_name},
    }.dump();
}

NdmsNativeCooperativeDeleteResult blocked_result(
    const NdmsNativeCooperativeDeleteStop stop =
        NdmsNativeCooperativeDeleteStop::ownership_changed) {
    NdmsNativeCooperativeDeleteResult result;
    result.status = NdmsNativeCooperativeDeleteStatus::blocked;
    result.stop = stop;
    return result;
}

NdmsNativeCooperativeDeleteResult recovery_result() {
    NdmsNativeCooperativeDeleteResult result;
    result.status = NdmsNativeCooperativeDeleteStatus::recovery_required;
    result.stop =
        NdmsNativeCooperativeDeleteStop::save_reconfirmation_required;
    result.durable_phase = NdmsNativeDeleteWalPhase::save_may_be_inflight;
    result.transaction_id = std::string(32U, 'd');
    result.interface_name = "Wireguard5";
    result.kind = NdmsNativeTunnelImportKind::wireguard;
    result.external_writer_race_accepted = true;
    result.global_save_scope_acknowledged = true;
    return result;
}

NdmsNativeCooperativeDeleteResult terminal_result() {
    auto result = recovery_result();
    result.status = NdmsNativeCooperativeDeleteStatus::
        save_acknowledged_unverified;
    result.stop = NdmsNativeCooperativeDeleteStop::none;
    result.durable_phase = NdmsNativeDeleteWalPhase::cleanup;
    result.ownership_tombstone_durable = true;
    result.rollback_snapshot_retained = true;
    return result;
}

void check_no_store(const httplib::Result& response) {
    REQUIRE(response != nullptr);
    CHECK(response->get_header_value("Cache-Control") == "no-store");
}

} // namespace

TEST_CASE("native delete API maps typed evidence and redacts durable internals") {
    auto result = recovery_result();
    result.stop =
        NdmsNativeCooperativeDeleteStop::runtime_observation_failed;
    result.durable_phase = NdmsNativeDeleteWalPhase::delete_may_be_inflight;
    result.delete_perform_started = true;
    result.request_may_have_been_dispatched = true;
    result.transport_outcome = NdmsNativeExactMutationResponseOutcome::
        acknowledged_needs_observation;
    result.observation_failure =
        NdmsNativeDirectObservationFailure::transport_failed;

    const auto response = ndms_native_delete_api_response(result);
    CHECK(response.size() == 16U);
    CHECK(response.at("status") == "recovery_required");
    CHECK(response.at("stop") == "runtime_observation_failed");
    CHECK(response.at("phase") == "delete_may_be_inflight");
    CHECK(response.at("interface_name") == "Wireguard5");
    CHECK(response.at("kind") == "wireguard");
    CHECK(response.at("external_writer_race_excluded") == false);
    CHECK(response.at("external_writer_race_accepted") == true);
    CHECK(response.at("global_save_scope_acknowledged") == true);
    CHECK(response.at("delete_perform_started") == true);
    CHECK(response.at("save_perform_started") == false);
    CHECK(response.at("request_may_have_been_dispatched") == true);
    CHECK(response.at("system_configuration_save_acknowledged") == false);
    CHECK(response.at("ownership_tombstone_durable") == false);
    CHECK(response.at("rollback_snapshot_retained") == false);
    CHECK(response.at("transport_outcome") ==
          "acknowledged_needs_observation");
    CHECK(response.at("observation_failure") == "transport_failed");
    CHECK_FALSE(response.contains("transaction_id"));
    CHECK_FALSE(response.contains("ownership_revision"));
    CHECK_FALSE(response.contains("marker"));
    CHECK_FALSE(response.contains("snapshot_revision"));
    CHECK_FALSE(response.contains("target_full_revision"));
    CHECK_FALSE(response.contains("catalog_revision"));
    CHECK_FALSE(response.contains("dependency_revision"));
    CHECK(response.dump().find(std::string(32U, 'd')) == std::string::npos);

    const auto cleanup_only = ndms_native_delete_api_response(
        terminal_result());
    CHECK(cleanup_only.size() == 14U);
    CHECK(cleanup_only.at("status") ==
          "save_acknowledged_unverified");
    CHECK(cleanup_only.at("stop") == "none");
    CHECK(cleanup_only.at("phase") == "cleanup");
    CHECK(cleanup_only.at("delete_perform_started") == false);
    CHECK(cleanup_only.at("save_perform_started") == false);
    CHECK(cleanup_only.at("request_may_have_been_dispatched") == false);
    CHECK(cleanup_only.at("system_configuration_save_acknowledged") ==
          false);
    CHECK(cleanup_only.at("ownership_tombstone_durable") == true);
    CHECK(cleanup_only.at("rollback_snapshot_retained") == true);
}

TEST_CASE("native delete API accepts every known typed enum") {
    for (unsigned int value =
             static_cast<unsigned int>(
                 NdmsNativeCooperativeDeleteStop::
                     owner_global_save_not_acknowledged);
         value <= static_cast<unsigned int>(
                      NdmsNativeCooperativeDeleteStop::unexpected_failure);
         ++value) {
        const auto stop =
            static_cast<NdmsNativeCooperativeDeleteStop>(value);
        auto result = blocked_result(stop);
        if (stop ==
                NdmsNativeCooperativeDeleteStop::runtime_observation_failed ||
            stop == NdmsNativeCooperativeDeleteStop::
                        running_config_observation_failed) {
            result = recovery_result();
            result.stop = stop;
            result.observation_failure =
                NdmsNativeDirectObservationFailure::none;
        }
        CHECK_NOTHROW(ndms_native_delete_api_response(result));
    }

    for (unsigned int value =
             static_cast<unsigned int>(NdmsNativeDeleteWalPhase::prepared);
         value <= static_cast<unsigned int>(NdmsNativeDeleteWalPhase::cleanup);
         ++value) {
        auto result = recovery_result();
        result.durable_phase = static_cast<NdmsNativeDeleteWalPhase>(value);
        CHECK_NOTHROW(ndms_native_delete_api_response(result));
    }

    for (const auto kind : {
             NdmsNativeTunnelImportKind::wireguard,
             NdmsNativeTunnelImportKind::amnezia_wireguard}) {
        auto result = recovery_result();
        result.kind = kind;
        CHECK_NOTHROW(ndms_native_delete_api_response(result));
    }

    for (unsigned int value = static_cast<unsigned int>(
             NdmsNativeExactMutationResponseOutcome::guard_rejected);
         value <= static_cast<unsigned int>(
                      NdmsNativeExactMutationResponseOutcome::
                          acknowledged_needs_observation);
         ++value) {
        auto result = recovery_result();
        result.transport_outcome =
            static_cast<NdmsNativeExactMutationResponseOutcome>(value);
        if (*result.transport_outcome !=
                NdmsNativeExactMutationResponseOutcome::guard_rejected &&
            *result.transport_outcome !=
                NdmsNativeExactMutationResponseOutcome::transport_failed) {
            result.delete_perform_started = true;
            result.request_may_have_been_dispatched = true;
        }
        CHECK_NOTHROW(ndms_native_delete_api_response(result));
    }

    for (unsigned int value = static_cast<unsigned int>(
             NdmsNativeDirectObservationFailure::none);
         value <= static_cast<unsigned int>(
                      NdmsNativeDirectObservationFailure::
                          target_evidence_refused);
         ++value) {
        auto result = recovery_result();
        result.stop =
            NdmsNativeCooperativeDeleteStop::runtime_observation_failed;
        result.observation_failure =
            static_cast<NdmsNativeDirectObservationFailure>(value);
        CHECK_NOTHROW(ndms_native_delete_api_response(result));
    }
}

TEST_CASE("native delete API rejects unknown enums and incoherent claims") {
    {
        auto result = blocked_result();
        result.status =
            static_cast<NdmsNativeCooperativeDeleteStatus>(255U);
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = blocked_result();
        result.stop = static_cast<NdmsNativeCooperativeDeleteStop>(255U);
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.durable_phase = static_cast<NdmsNativeDeleteWalPhase>(255U);
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.kind = static_cast<NdmsNativeTunnelImportKind>(255U);
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.transport_outcome =
            static_cast<NdmsNativeExactMutationResponseOutcome>(255U);
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.stop =
            NdmsNativeCooperativeDeleteStop::runtime_observation_failed;
        result.observation_failure =
            static_cast<NdmsNativeDirectObservationFailure>(255U);
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = blocked_result();
        result.external_writer_race_excluded = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = blocked_result();
        result.external_writer_race_accepted = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.kind.reset();
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.interface_name = "Wireguard05";
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.transaction_id = "PRIVATE-TRANSACTION-MUST-NOT-ESCAPE";
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.external_writer_race_accepted = false;
        result.global_save_scope_acknowledged = false;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = blocked_result();
        result.delete_perform_started = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.delete_perform_started = true;
        result.request_may_have_been_dispatched = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.transport_outcome =
            NdmsNativeExactMutationResponseOutcome::transport_failed;
        result.request_may_have_been_dispatched = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.transport_outcome =
            NdmsNativeExactMutationResponseOutcome::transport_failed;
        result.system_configuration_save_acknowledged = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.observation_failure =
            NdmsNativeDirectObservationFailure::transport_failed;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = terminal_result();
        result.durable_phase =
            NdmsNativeDeleteWalPhase::save_acknowledged_unverified;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = terminal_result();
        result.rollback_snapshot_retained = false;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
    {
        auto result = recovery_result();
        result.ownership_tombstone_durable = true;
        CHECK_THROWS(ndms_native_delete_api_response(result));
    }
}

TEST_CASE("native delete remove preserves exact request and returns typed 200") {
    std::size_t callback_count = 0U;
    std::vector<std::string> revisions;
    NativeDeleteApiFixture fixture(
        [&](const NdmsNativeCooperativeDeleteRequest& request) {
            ++callback_count;
            CHECK(request.interface_name == "Wireguard98");
            CHECK(request.global_save_consent ==
                  NdmsNativeOwnerGlobalSaveConsent::
                      acknowledged_all_pending_keenetic_changes);
            CHECK(request.external_writer_race ==
                  NdmsNativeDeleteExternalWriterRaceAcceptance::
                      owner_accepted);
            revisions.push_back(request.expected_ownership_revision);
            if (callback_count == 1U) return blocked_result();
            if (callback_count == 2U) {
                auto result = recovery_result();
                result.interface_name = "Wireguard98";
                return result;
            }
            auto result = terminal_result();
            result.interface_name = "Wireguard98";
            return result;
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    const auto headers = fixture.acknowledged_headers(session);
    const auto revision = valid_ownership_revision('b');

    for (const std::string expected_status : {
             "blocked", "recovery_required",
             "save_acknowledged_unverified"}) {
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeDeleteApiPath},
            headers,
            valid_delete_body("Wireguard98", revision),
            "application/json");
        check_no_store(response);
        REQUIRE(response->status == 200);
        const auto body = nlohmann::json::parse(response->body);
        CHECK(body.at("status") == expected_status);
        CHECK(response->body.find(revision) == std::string::npos);
    }
    CHECK(callback_count == 3U);
    CHECK(revisions == std::vector<std::string>(3U, revision));
    CHECK(fixture.reservation_seen_by_callback() == 3U);
    CHECK_FALSE(fixture.reservation_active());
}

TEST_CASE("native delete rejects malformed request shapes without callback") {
    std::size_t callback_count = 0U;
    NativeDeleteApiFixture fixture(
        [&](const NdmsNativeCooperativeDeleteRequest&) {
            ++callback_count;
            return blocked_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    const auto headers = fixture.acknowledged_headers(session);

    const std::vector<std::string> invalid_bodies{
        "",
        "{",
        "[]",
        R"({"interface_name":"Wireguard5","expected_ownership_revision":"token","confirm_label":"Wireguard5","extra":true})",
        R"({"interface_name":"Wireguard5","confirm_label":"Wireguard5"})",
        R"({"interface_name":5,"expected_ownership_revision":"token","confirm_label":"Wireguard5"})",
        R"({"interface_name":"Wireguard5","expected_ownership_revision":5,"confirm_label":"Wireguard5"})",
        R"({"interface_name":"Wireguard5","expected_ownership_revision":"token","confirm_label":5})",
        R"({"interface_name":"Wireguard5","interface_name":"Wireguard6","expected_ownership_revision":"token","confirm_label":"Wireguard5"})",
        valid_delete_body("Wireguard4"),
        valid_delete_body("Wireguard99"),
        valid_delete_body("Wireguard05"),
        valid_delete_body("wireguard5"),
        valid_delete_body(" Wireguard5"),
        R"({"interface_name":"Wireguard5","expected_ownership_revision":"token","confirm_label":"Wireguard6"})",
        valid_delete_body("Wireguard5", ""),
        valid_delete_body("Wireguard5", std::string(129U, 'a')),
        valid_delete_body("Wireguard5", "opaque revision"),
        valid_delete_body("Wireguard5", "opaque/revision"),
    };

    for (const auto& body : invalid_bodies) {
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeDeleteApiPath},
            headers,
            body,
            "application/json");
        check_no_store(response);
        CHECK(response->status == 400);
        CHECK(nlohmann::json::parse(response->body).at("error") ==
              "sensitive_request_rejected");
    }
    CHECK(callback_count == 0U);
    CHECK(fixture.reservation_seen_by_callback() == 0U);
    CHECK(fixture.reservation_attempts() == invalid_bodies.size());

    const auto oversized = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        headers,
        std::string(kNdmsNativeDeleteRequestMaximumBytes + 1U, 'x'),
        "application/json");
    check_no_store(oversized);
    CHECK(oversized->status == 413);
    CHECK(callback_count == 0U);
}

TEST_CASE("native delete auth transport headers and reservation reject pre-body") {
    std::size_t callback_count = 0U;
    NativeDeleteApiFixture fixture(
        [&](const NdmsNativeCooperativeDeleteRequest&) {
            ++callback_count;
            return blocked_result();
        });

    reset_sensitive_request_body_stream_count_for_testing();
    const auto unauthenticated = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        valid_delete_body(),
        "application/json");
    check_no_store(unauthenticated);
    CHECK(unauthenticated->status == 401);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(fixture.reservation_attempts() == 0U);

    const auto session = fixture.login();
    reset_sensitive_request_body_stream_count_for_testing();
    const auto no_step_up = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body(),
        "application/json");
    check_no_store(no_step_up);
    CHECK(no_step_up->status == 403);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(fixture.reservation_attempts() == 0U);

    fixture.grant_step_up(session);
    fixture.set_protected_transport(false);
    reset_sensitive_request_body_stream_count_for_testing();
    const auto unprotected = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body(),
        "application/json");
    check_no_store(unprotected);
    CHECK(unprotected->status == 403);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(fixture.reservation_attempts() == 0U);
    fixture.set_protected_transport(true);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto wrong_content_type = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body(),
        "application/json; charset=utf-8");
    check_no_store(wrong_content_type);
    CHECK(wrong_content_type->status == 415);
    CHECK(wrong_content_type->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(fixture.reservation_attempts() == 0U);

    const std::vector<httplib::Headers> rejected_headers{
        session,
        httplib::Headers{
            {"Cookie", session.begin()->second},
            {std::string{kNdmsNativeDeleteRaceAcceptanceHeader},
             std::string{kNdmsNativeDeleteRaceAcceptanceValue}}},
        httplib::Headers{
            {"Cookie", session.begin()->second},
            {std::string{kNdmsNativeDeleteGlobalSaveHeader},
             std::string{kNdmsNativeDeleteGlobalSaveValue}}},
        httplib::Headers{
            {"Cookie", session.begin()->second},
            {std::string{kNdmsNativeDeleteRaceAcceptanceHeader}, "accepted"},
            {std::string{kNdmsNativeDeleteGlobalSaveHeader},
             std::string{kNdmsNativeDeleteGlobalSaveValue}}},
    };
    for (const auto& headers : rejected_headers) {
        reset_sensitive_request_body_stream_count_for_testing();
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeDeleteApiPath},
            headers,
            valid_delete_body(),
            "application/json");
        check_no_store(response);
        CHECK(response->status == 428);
        CHECK(response->get_header_value("Connection") == "close");
        CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    }

    auto duplicate = fixture.acknowledged_headers(session);
    duplicate.emplace(
        std::string{kNdmsNativeDeleteGlobalSaveHeader},
        std::string{kNdmsNativeDeleteGlobalSaveValue});
    reset_sensitive_request_body_stream_count_for_testing();
    const auto duplicate_response = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        duplicate,
        valid_delete_body(),
        "application/json");
    check_no_store(duplicate_response);
    CHECK(duplicate_response->status == 428);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    fixture.set_reservation_available(false);
    reset_sensitive_request_body_stream_count_for_testing();
    const auto busy = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body(),
        "application/json");
    check_no_store(busy);
    CHECK(busy->status == 503);
    CHECK(busy->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(callback_count == 0U);
    CHECK(fixture.reservation_attempts() == 1U);
}

TEST_CASE("native delete unavailable callback rejects before body streaming") {
    NativeDeleteApiFixture fixture;
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto remove = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body(),
        "application/json");
    check_no_store(remove);
    CHECK(remove->status == 503);
    CHECK(remove->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    reset_sensitive_request_body_stream_count_for_testing();
    const auto recovery = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(recovery);
    CHECK(recovery->status == 503);
    CHECK(recovery->get_header_value("Connection") == "close");
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);
    CHECK(fixture.reservation_attempts() == 0U);
}

TEST_CASE("native delete recovery uses sole WAL and only fresh paired headers") {
    std::size_t callback_count = 0U;
    std::vector<bool> fresh_acknowledgements;
    NativeDeleteApiFixture fixture(
        [](const NdmsNativeCooperativeDeleteRequest&) {
            return blocked_result();
        },
        [&](const NdmsNativeCooperativeDeleteResumeAcknowledgement& ack) {
            ++callback_count;
            const bool fresh =
                ack.global_save_consent ==
                    NdmsNativeOwnerGlobalSaveConsent::
                        acknowledged_all_pending_keenetic_changes &&
                ack.external_writer_race ==
                    NdmsNativeDeleteExternalWriterRaceAcceptance::
                        owner_accepted;
            fresh_acknowledgements.push_back(fresh);
            return recovery_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    const auto without_fresh = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(without_fresh);
    REQUIRE(without_fresh->status == 200);
    CHECK(nlohmann::json::parse(without_fresh->body).at("status") ==
          "recovery_required");

    const auto with_fresh = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        fixture.acknowledged_headers(session),
        "",
        "application/octet-stream");
    check_no_store(with_fresh);
    REQUIRE(with_fresh->status == 200);
    CHECK(callback_count == 2U);
    CHECK((fresh_acknowledgements == std::vector<bool>{false, true}));
    CHECK(fixture.reservation_seen_by_callback() == 2U);

    auto partial = session;
    partial.emplace(
        std::string{kNdmsNativeDeleteGlobalSaveHeader},
        std::string{kNdmsNativeDeleteGlobalSaveValue});
    reset_sensitive_request_body_stream_count_for_testing();
    const auto partial_response = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        partial,
        "must-not-stream",
        "application/octet-stream");
    check_no_store(partial_response);
    CHECK(partial_response->status == 428);
    CHECK(sensitive_request_body_stream_count_for_testing() == 0U);

    auto wrong = fixture.acknowledged_headers(session);
    wrong.erase(std::string{kNdmsNativeDeleteRaceAcceptanceHeader});
    wrong.emplace(
        std::string{kNdmsNativeDeleteRaceAcceptanceHeader}, "accepted");
    const auto wrong_response = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        wrong,
        "",
        "application/octet-stream");
    check_no_store(wrong_response);
    CHECK(wrong_response->status == 428);

    auto duplicate = fixture.acknowledged_headers(session);
    duplicate.emplace(
        std::string{kNdmsNativeDeleteRaceAcceptanceHeader},
        std::string{kNdmsNativeDeleteRaceAcceptanceValue});
    const auto duplicate_response = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        duplicate,
        "",
        "application/octet-stream");
    check_no_store(duplicate_response);
    CHECK(duplicate_response->status == 428);

    const auto one_byte = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        session,
        "x",
        "application/octet-stream");
    check_no_store(one_byte);
    CHECK(one_byte->status == 400);

    const auto too_large = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        session,
        "xx",
        "application/octet-stream");
    check_no_store(too_large);
    CHECK(too_large->status == 413);
    CHECK(callback_count == 2U);
}

TEST_CASE("native delete callback failures are generic and never retried") {
    std::size_t delete_count = 0U;
    std::size_t resume_count = 0U;
    NativeDeleteApiFixture fixture(
        [&](const NdmsNativeCooperativeDeleteRequest&) ->
            NdmsNativeCooperativeDeleteResult {
            ++delete_count;
            throw std::runtime_error(
                "PRIVATE_DELETE_REVISION_MUST_NOT_ESCAPE");
        },
        [&](const NdmsNativeCooperativeDeleteResumeAcknowledgement&) ->
            NdmsNativeCooperativeDeleteResult {
            ++resume_count;
            auto invalid = terminal_result();
            invalid.ownership_tombstone_durable = false;
            return invalid;
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    const auto remove = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body(),
        "application/json");
    check_no_store(remove);
    CHECK(remove->status == 500);
    CHECK(nlohmann::json::parse(remove->body).at("error") ==
          "sensitive_request_failed");
    CHECK(remove->body.find("PRIVATE_DELETE_REVISION") ==
          std::string::npos);
    CHECK(delete_count == 1U);

    const auto recovery = fixture.client().Post(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        session,
        "",
        "application/octet-stream");
    check_no_store(recovery);
    CHECK(recovery->status == 500);
    CHECK(nlohmann::json::parse(recovery->body).at("error") ==
          "sensitive_request_failed");
    CHECK(resume_count == 1U);
    CHECK_FALSE(fixture.reservation_active());
}

TEST_CASE("native delete reservation excludes a second body stream") {
    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool first_entered = false;
    bool release_first = false;
    std::atomic<std::size_t> callback_count{0U};

    NativeDeleteApiFixture fixture(
        [&](const NdmsNativeCooperativeDeleteRequest&) {
            callback_count.fetch_add(1U, std::memory_order_relaxed);
            std::unique_lock<std::mutex> lock(barrier_mutex);
            first_entered = true;
            barrier_cv.notify_all();
            barrier_cv.wait(lock, [&] { return release_first; });
            return blocked_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);
    const auto headers = fixture.acknowledged_headers(session);

    reset_sensitive_request_body_stream_count_for_testing();
    int first_status = 0;
    std::thread first_request([&] {
        const auto response = fixture.client().Post(
            std::string{kNdmsNativeDeleteApiPath},
            headers,
            valid_delete_body("Wireguard5"),
            "application/json");
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
        std::string{kNdmsNativeDeleteApiPath},
        headers,
        "SECOND_MUST_NOT_STREAM",
        "application/json");
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

TEST_CASE("native delete remove rejects a coherent result for another target") {
    std::size_t callback_count = 0U;
    NativeDeleteApiFixture fixture(
        [&](const NdmsNativeCooperativeDeleteRequest& request) {
            ++callback_count;
            CHECK(request.interface_name == "Wireguard98");
            // This result is internally coherent, but it belongs to the sole
            // durable transaction for a different panel-owned target.
            return terminal_result();
        });
    const auto session = fixture.login();
    fixture.grant_step_up(session);

    const auto response = fixture.client().Post(
        std::string{kNdmsNativeDeleteApiPath},
        fixture.acknowledged_headers(session),
        valid_delete_body("Wireguard98"),
        "application/json");
    check_no_store(response);
    CHECK(response->status == 500);
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "sensitive_request_failed");
    CHECK(response->body.find("Wireguard5") == std::string::npos);
    CHECK(callback_count == 1U);
    CHECK(fixture.reservation_seen_by_callback() == 1U);
    CHECK_FALSE(fixture.reservation_active());
}

} // namespace keen_pbr3

#endif // WITH_API
