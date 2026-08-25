#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_ndms_native_tombstone_forget.hpp"
#include "api/server.hpp"
#include "api/sse_broadcaster.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class ForgetAuthDirectory final {
public:
    ForgetAuthDirectory() {
        char pattern[] = "/tmp/keen-pbr-native-forget-api-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path_ = created;
        auth_path_ = path_ / "auth.json";
        std::ofstream output(auth_path_, std::ios::binary | std::ios::trunc);
        REQUIRE(output);
        output << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
        REQUIRE(output);
    }

    ~ForgetAuthDirectory() {
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

class ForgetTestReservation final : public SensitiveRequestReservation {
public:
    explicit ForgetTestReservation(std::atomic<bool>& active) noexcept
        : active_(active) {}
    ~ForgetTestReservation() noexcept override {
        active_.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool>& active_;
};

NdmsNativeTombstoneForgetResult forgotten_result(
    std::string interface_name = "Wireguard5") {
    NdmsNativeTombstoneForgetResult result;
    result.status = NdmsNativeTombstoneForgetStatus::forgotten;
    result.stop = NdmsNativeTombstoneForgetStop::none;
    result.interface_name = std::move(interface_name);
    result.snapshot_state =
        NdmsNativeTombstoneForgetArtifactState::absent_durable;
    result.tombstone_state =
        NdmsNativeTombstoneForgetArtifactState::absent_durable;
    result.future_reappearance_is_foreign = true;
    return result;
}

NdmsNativeTombstoneForgetResult blocked_result(
    const NdmsNativeTombstoneForgetStop stop =
        NdmsNativeTombstoneForgetStop::ownership_changed) {
    NdmsNativeTombstoneForgetResult result;
    result.stop = stop;
    result.interface_name = "Wireguard5";
    return result;
}

std::string valid_revision() {
    return "ndms-native-owner-tombstone-v1-" + std::string(64U, 'a');
}

std::string valid_body() {
    return nlohmann::json{
        {"interface_name", "Wireguard5"},
        {"expected_ownership_revision", valid_revision()},
        {"confirm_interface_name", "Wireguard5"},
        {"rollback_discard_acknowledgement",
         "permanently_discard_rollback_data"},
        {"foreign_reappearance_acknowledgement",
         "accepted_reappearance_is_foreign"},
    }.dump();
}

using ForgetCallback =
    std::function<NdmsNativeTombstoneForgetResult(
        const NdmsNativeTombstoneForgetRequest&)>;

class NativeForgetApiFixture final {
public:
    explicit NativeForgetApiFixture(
        ForgetCallback callback = [](const auto& request) {
            return forgotten_result(request.interface_name);
        })
        : auth_file_("KEEN_PBR_AUTH_FILE",
                     auth_directory_.auth_path().string()),
          trusted_transport_([](std::string_view,
                                std::string_view,
                                bool) { return true; }),
          context_(test_support::make_minimal_api_context(
              broadcaster_,
              "/tmp/keen-pbr-native-forget-api-config.json")),
          server_(config()),
          callback_(std::move(callback)) {
        context_.reserve_ndms_native_tombstone_forget_fn = [this]() {
            reservation_attempts_.fetch_add(1U, std::memory_order_relaxed);
            bool expected = false;
            if (!reservation_active_.compare_exchange_strong(
                    expected,
                    true,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return std::shared_ptr<SensitiveRequestReservation>{};
            }
            return std::shared_ptr<SensitiveRequestReservation>{
                std::make_shared<ForgetTestReservation>(
                    reservation_active_)};
        };
        context_.run_ndms_native_tombstone_forget_fn =
            [this](
                const NdmsNativeTombstoneForgetRequest& request,
                const std::shared_ptr<SensitiveRequestReservation>&
                    reservation) {
                REQUIRE(reservation != nullptr);
                CHECK(reservation_active_.load(std::memory_order_acquire));
                callback_calls_.fetch_add(1U, std::memory_order_relaxed);
                last_request_ = request;
                return callback_(request);
            };
        register_ndms_native_tombstone_forget_handler(server_, context_);
        server_.start();
        client_ = std::make_unique<httplib::Client>(
            "127.0.0.1", port());
    }

    ~NativeForgetApiFixture() { server_.stop(); }

    httplib::Headers login() {
        const auto response = client_->Post(
            "/api/auth/login",
            R"({"username":"admin","password":"secret"})",
            "application/json");
        REQUIRE(response != nullptr);
        REQUIRE(response->status == 200);
        const auto cookie = response->get_header_value("Set-Cookie");
        return {{"Cookie", cookie.substr(0U, cookie.find(';'))}};
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

    httplib::Client& client() noexcept { return *client_; }
    std::size_t reservation_attempts() const noexcept {
        return reservation_attempts_.load(std::memory_order_relaxed);
    }
    std::size_t callback_calls() const noexcept {
        return callback_calls_.load(std::memory_order_relaxed);
    }
    const NdmsNativeTombstoneForgetRequest& last_request() const noexcept {
        return last_request_;
    }

private:
    static int port() { return test_support::isolated_api_port(2); }
    static ApiConfig config() {
        ApiConfig value;
        value.listen = "127.0.0.1:" + std::to_string(port());
        return value;
    }

    ForgetAuthDirectory auth_directory_;
    test_support::EnvironmentVariableGuard auth_file_;
    TrustedLocalConnectionEvaluatorGuard trusted_transport_;
    std::atomic<bool> reservation_active_{false};
    std::atomic<std::size_t> reservation_attempts_{0U};
    std::atomic<std::size_t> callback_calls_{0U};
    SseBroadcaster broadcaster_;
    ApiContext context_;
    ApiServer server_;
    ForgetCallback callback_;
    NdmsNativeTombstoneForgetRequest last_request_;
    std::unique_ptr<httplib::Client> client_;
};

void check_no_store(const httplib::Result& response) {
    REQUIRE(response != nullptr);
    CHECK(response->get_header_value("Cache-Control") == "no-store");
}

} // namespace

TEST_CASE("native tombstone forget API exposes only coherent redacted facts") {
    const auto response = ndms_native_tombstone_forget_api_response(
        forgotten_result());
    CHECK(response.size() == 8U);
    CHECK(response.at("status") == "forgotten");
    CHECK(response.at("stop") == "none");
    CHECK(response.at("interface_name") == "Wireguard5");
    CHECK(response.at("snapshot_state") == "absent_durable");
    CHECK(response.at("tombstone_state") == "absent_durable");
    CHECK(response.at("router_mutation_attempted") == false);
    CHECK(response.at("system_configuration_save_acknowledged") == false);
    CHECK(response.at("future_reappearance_is_foreign") == true);
    CHECK_FALSE(response.contains("transaction_id"));
    CHECK_FALSE(response.contains("marker"));
    CHECK_FALSE(response.contains("snapshot_revision"));
    CHECK_FALSE(response.contains("kernel_name"));

    auto recovery = blocked_result(NdmsNativeTombstoneForgetStop::writer_lost);
    recovery.status = NdmsNativeTombstoneForgetStatus::recovery_required;
    recovery.snapshot_state =
        NdmsNativeTombstoneForgetArtifactState::absent_durable;
    recovery.tombstone_state =
        NdmsNativeTombstoneForgetArtifactState::retained;
    CHECK_NOTHROW(ndms_native_tombstone_forget_api_response(recovery));

    auto invalid = blocked_result(
        NdmsNativeTombstoneForgetStop::exact_name_not_confirmed);
    CHECK_THROWS(ndms_native_tombstone_forget_api_response(invalid));
    invalid = forgotten_result();
    invalid.future_reappearance_is_foreign = false;
    CHECK_THROWS(ndms_native_tombstone_forget_api_response(invalid));
}

TEST_CASE("native tombstone forget guards and exact body precede execution") {
    NativeForgetApiFixture fixture;

    const auto unauthenticated = fixture.client().Post(
        std::string{kNdmsNativeTombstoneForgetApiPath},
        valid_body(),
        "application/json");
    check_no_store(unauthenticated);
    CHECK(unauthenticated->status == 401);
    CHECK(fixture.reservation_attempts() == 0U);

    const auto session = fixture.login();
    const auto wrong_content_type = fixture.client().Post(
        std::string{kNdmsNativeTombstoneForgetApiPath},
        session,
        valid_body(),
        "text/plain");
    check_no_store(wrong_content_type);
    CHECK(wrong_content_type->status == 415);
    CHECK(fixture.reservation_attempts() == 0U);

    const auto accepted = fixture.client().Post(
        std::string{kNdmsNativeTombstoneForgetApiPath},
        session,
        valid_body(),
        "application/json");
    check_no_store(accepted);
    CHECK(accepted->status == 200);
    CHECK(nlohmann::json::parse(accepted->body).at("status") == "forgotten");
    CHECK(fixture.callback_calls() == 1U);
    CHECK(fixture.last_request().interface_name == "Wireguard5");
    CHECK(fixture.last_request().expected_ownership_revision ==
          valid_revision());
    CHECK(fixture.last_request().exact_name_confirmation ==
          NdmsNativeTombstoneExactNameConfirmation::confirmed);
}

TEST_CASE("native tombstone forget rejects non-exact JSON and result target") {
    {
        NativeForgetApiFixture fixture;
        const auto session = fixture.login();
        fixture.grant_step_up(session);

        const std::vector<std::string> invalid_bodies{
        "{}",
        R"({"interface_name":"Wireguard5","interface_name":"Wireguard6","expected_ownership_revision":"ndms-native-owner-tombstone-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","confirm_interface_name":"Wireguard5","rollback_discard_acknowledgement":"permanently_discard_rollback_data","foreign_reappearance_acknowledgement":"accepted_reappearance_is_foreign"})",
        nlohmann::json{
            {"interface_name", "Wireguard5"},
            {"expected_ownership_revision", valid_revision()},
            {"confirm_interface_name", "Wireguard6"},
            {"rollback_discard_acknowledgement",
             "permanently_discard_rollback_data"},
            {"foreign_reappearance_acknowledgement",
             "accepted_reappearance_is_foreign"},
        }.dump(),
        nlohmann::json{
            {"interface_name", "Wireguard5"},
            {"expected_ownership_revision", "opaque"},
            {"confirm_interface_name", "Wireguard5"},
            {"rollback_discard_acknowledgement", "yes"},
            {"foreign_reappearance_acknowledgement",
             "accepted_reappearance_is_foreign"},
        }.dump(),
        };
        for (const auto& body : invalid_bodies) {
            const auto response = fixture.client().Post(
                std::string{kNdmsNativeTombstoneForgetApiPath},
                session,
                body,
                "application/json");
            check_no_store(response);
            CHECK(response->status == 400);
        }
        CHECK(fixture.callback_calls() == 0U);
    }

    NativeForgetApiFixture mismatch([](const auto&) {
        return forgotten_result("Wireguard6");
    });
    const auto mismatch_session = mismatch.login();
    mismatch.grant_step_up(mismatch_session);
    const auto response = mismatch.client().Post(
        std::string{kNdmsNativeTombstoneForgetApiPath},
        mismatch_session,
        valid_body(),
        "application/json");
    check_no_store(response);
    CHECK(response->status == 500);
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "sensitive_request_failed");
}

} // namespace keen_pbr3

#endif // WITH_API
