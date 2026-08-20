#pragma once

#ifdef WITH_API

#include "../config/config.hpp"
#include "../health/routing_health.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace httplib {
class Request;
class Response;
}

namespace keen_pbr3 {

class ApiError : public std::runtime_error {
public:
    explicit ApiError(std::string message,
                      int status = 500,
                      std::optional<std::string> body = std::nullopt)
        : std::runtime_error(std::move(message))
        , status_(status)
        , body_(std::move(body)) {}

    int status() const noexcept {
        return status_;
    }

    const std::optional<std::string>& body() const noexcept {
        return body_;
    }

private:
    int status_;
    std::optional<std::string> body_;
};

// Move-only storage for a credential-bearing request body.  Sensitive routes
// are streamed into this buffer only after authentication and step-up have
// been admitted.  The bytes are overwritten both when the application takes
// them and when an error path destroys the unread body.
class SensitiveRequestBody final {
public:
    SensitiveRequestBody(const SensitiveRequestBody&) = delete;
    SensitiveRequestBody& operator=(const SensitiveRequestBody&) = delete;
    SensitiveRequestBody(SensitiveRequestBody&& other) noexcept;
    SensitiveRequestBody& operator=(SensitiveRequestBody&& other) noexcept;
    ~SensitiveRequestBody() noexcept;

    std::size_t size() const noexcept;
    bool empty() const noexcept;

    // Materializes the one parser-owned std::string. The streaming buffer is
    // wiped before this returns; the recipient must in turn consume a parser
    // whose contract wipes the returned string on every path.
    std::string take_string_once();

private:
    friend class ApiServer;
    explicit SensitiveRequestBody(std::vector<char> bytes) noexcept;
    void wipe() noexcept;

    std::vector<char> bytes_;
    bool consumed_{false};
};

#ifdef KEEN_PBR3_TESTING
void reset_sensitive_request_body_wipe_count_for_testing() noexcept;
std::size_t sensitive_request_body_wipe_count_for_testing() noexcept;
void reset_sensitive_request_body_stream_count_for_testing() noexcept;
std::size_t sensitive_request_body_stream_count_for_testing() noexcept;
#endif

// HTTP REST API server using cpp-httplib.
// Runs in a background thread and integrates with the Daemon event loop
// for shutdown coordination.
class ApiServer {
public:
    // Construct with listen address from ApiConfig.
    // Does not start listening until start() is called.
    explicit ApiServer(const ApiConfig& config);
    ~ApiServer();

    // Non-copyable, non-movable
    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;
    ApiServer(ApiServer&&) = delete;
    ApiServer& operator=(ApiServer&&) = delete;

    // Register route handlers before calling start().
    using RouteHandler = std::function<std::string()>;
    using BodyRouteHandler = std::function<std::string(const std::string& body)>;
    using SensitiveBodyRouteHandler = std::function<std::string(
        const httplib::Request& request,
        SensitiveRequestBody body)>;
    using SensitivePreBodyAdmission =
        std::function<void(const httplib::Request& request)>;
    using StreamRouteHandler = std::function<void(const httplib::Request&,
                                                  httplib::Response&)>;

    // Register a GET handler that returns a JSON string.
    void get(const std::string& path, RouteHandler handler);

    // Register a POST handler that returns a JSON string.
    void post(const std::string& path, RouteHandler handler);

    // Register a POST handler that receives the request body and returns a JSON string.
    void post(const std::string& path, BodyRouteHandler handler);

    // Register a bounded, no-store POST whose body is read only after the
    // request has passed authentication, step-up and the protected-secret
    // transport check. ContentReader avoids retaining a second req.body copy.
    void post_sensitive(const std::string& path,
                        std::size_t maximum_body_bytes,
                        SensitiveBodyRouteHandler handler);

    // Optional route-specific admission runs after authentication, step-up
    // and protected-transport checks but before ContentReader is entered or a
    // body buffer is allocated. Existing callers use the overload above and
    // retain their previous behavior.
    void post_sensitive(const std::string& path,
                        std::size_t maximum_body_bytes,
                        SensitivePreBodyAdmission pre_body_admission,
                        SensitiveBodyRouteHandler handler);

    // Register a GET handler that streams a non-JSON response.
    void get_stream(const std::string& path, StreamRouteHandler handler);

    // Long-lived authenticated streams register here so a password/provider
    // rotation revokes already-admitted connections together with sessions.
    void on_auth_sessions_revoked(std::function<void()> handler);

    // Captures the request's exact session/loopback admission and returns a
    // cheap probe for long-lived providers. It becomes false on logout,
    // credential publication, mode change, or monotonic session-TTL expiry.
    using StreamAuthorizationProbe = std::function<bool()>;
    StreamAuthorizationProbe make_stream_authorization_probe(
        const httplib::Request& request) const;

    // Register static file serving from frontend_root for non-/api routes.
    // Returns false if static serving could not be configured.
    bool register_static_root(const std::string& frontend_root);

    // Start listening in a background thread.
    void start();

    // Stop the server and join the background thread.
    void stop();

    // Whether the router's own authentication is proven usable in place of the
    // local password, evaluated from the live auth configuration and the
    // firmware policy this server managed to read. Reports only; retires
    // nothing. Empty before the server has any state to judge.
    std::optional<SystemAuthHealthSnapshot> system_auth_health();

    // Returns true if the server is currently listening.
    bool listening() const;

#ifdef KEEN_PBR3_TESTING
    // Models grant expiry between pre-routing admission and serialized
    // publication without changing the production grant TTL.
    void revoke_step_up_grant_for_testing(const std::string& token);

    // Deterministically models a provider publication after pre-routing has
    // admitted a credential request.
    void publish_auth_provider_for_testing(
        const std::string& provider,
        const std::string& keenetic_endpoint = {});

    // Drives one credential poll and reports what it concluded, as the name
    // of an NdmsCredentialChange. The production worker reaches the same code;
    // API pre-routing deliberately does not. This seam keeps revocation
    // deterministic without waiting for the production 30-second cadence.
    std::string poll_router_credentials_for_testing();
#endif

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#ifdef KEEN_PBR3_TESTING
enum class AuthSettingsPublicationStage {
    disk_published,
    runtime_published,
};
using AuthSettingsPublicationHook =
    std::function<void(AuthSettingsPublicationStage)>;
void set_auth_settings_publication_hook_for_testing(
    AuthSettingsPublicationHook hook);
void reset_auth_settings_publication_hook_for_testing();

// Runs after cpp-httplib's pre-routing authentication check but before a
// streaming handler revalidates its session and registers a subscription.
// Tests use this boundary to model a credential rotation racing admission.
using StreamAdmissionHook = std::function<void()>;
void set_stream_admission_hook_for_testing(StreamAdmissionHook hook);
void reset_stream_admission_hook_for_testing();

// Runs after pre-routing accepted /api/auth/settings but before the endpoint's
// serialization mutex. It exposes the revoked-request queueing boundary.
using AuthSettingsAdmissionHook = std::function<void()>;
void set_auth_settings_admission_hook_for_testing(
    AuthSettingsAdmissionHook hook);
void reset_auth_settings_admission_hook_for_testing();

// Runs after credentials were verified against a captured auth generation and
// before session insertion revalidates that generation under the revoke epoch.
using AuthLoginVerifiedHook = std::function<void()>;
void set_auth_login_verified_hook_for_testing(
    AuthLoginVerifiedHook hook);
void reset_auth_login_verified_hook_for_testing();

// Runs at credential-handler entry, after pre-routing attached its admission
// and before the handler snapshots auth or parses the body.
using CredentialHandlerAdmissionHook =
    std::function<void(std::string_view path)>;
void set_credential_handler_admission_hook_for_testing(
    CredentialHandlerAdmissionHook hook);
void reset_credential_handler_admission_hook_for_testing();

// Replaces only the socket/NDMS/route verdict in API integration tests. Pure
// tests cover the production evaluator; handlers use this seam to prove that
// a denial happens before credential body parsing/forwarding. Forwarding
// headers remain a hard production denial before this hook is consulted.
using TrustedLocalConnectionEvaluatorForTesting =
    std::function<bool(std::string_view remote_address,
                       std::string_view local_address,
                       bool require_credential_freshness)>;
void set_trusted_local_connection_evaluator_for_testing(
    TrustedLocalConnectionEvaluatorForTesting evaluator);
void reset_trusted_local_connection_evaluator_for_testing();
#endif

} // namespace keen_pbr3

#endif // WITH_API
