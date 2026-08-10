#pragma once

#ifdef WITH_API

#include "../config/config.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

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
    using StreamRouteHandler = std::function<void(const httplib::Request&,
                                                  httplib::Response&)>;

    // Register a GET handler that returns a JSON string.
    void get(const std::string& path, RouteHandler handler);

    // Register a POST handler that returns a JSON string.
    void post(const std::string& path, RouteHandler handler);

    // Register a POST handler that receives the request body and returns a JSON string.
    void post(const std::string& path, BodyRouteHandler handler);

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

    // Returns true if the server is currently listening.
    bool listening() const;

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
#endif

} // namespace keen_pbr3

#endif // WITH_API
