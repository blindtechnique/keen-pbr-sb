#ifdef WITH_API

#include "server.hpp"

#include "auth_runtime.hpp"
#include "handler_remote_access.hpp"
#include "keenetic_auth.hpp"

#include "../config/config_writer.hpp"
#include "../keenetic/ndms_web_endpoint.hpp"
#include "../log/logger.hpp"
#include "../log/trace.hpp"
#include "../util/traced_mutex.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <httplib.h>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

std::string make_error_json(const std::string& message) {
    return nlohmann::json{{"error", message}}.dump();
}

class ScopedAuthPublicationLatch {
public:
    explicit ScopedAuthPublicationLatch(std::atomic<bool>& latch)
        : latch_(latch) {
        latch_.store(true, std::memory_order_release);
    }

    ~ScopedAuthPublicationLatch() {
        // Before the atomic replacement becomes visible, an exception leaves
        // the old runtime authoritative and the latch may reopen. Afterwards
        // an unexpected failure must stay fail-closed until restart.
        if (!disk_published_) complete();
    }

    void mark_disk_published() noexcept { disk_published_ = true; }

    void complete() noexcept {
        if (!active_) return;
        active_ = false;
        latch_.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool>& latch_;
    bool active_{true};
    bool disk_published_{false};
};

#ifdef KEEN_PBR3_TESTING
std::mutex& auth_settings_publication_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

AuthSettingsPublicationHook& auth_settings_publication_hook() {
    static AuthSettingsPublicationHook hook;
    return hook;
}

std::mutex& stream_admission_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

StreamAdmissionHook& stream_admission_hook() {
    static StreamAdmissionHook hook;
    return hook;
}

std::mutex& auth_settings_admission_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

AuthSettingsAdmissionHook& auth_settings_admission_hook() {
    static AuthSettingsAdmissionHook hook;
    return hook;
}

std::mutex& auth_login_verified_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

AuthLoginVerifiedHook& auth_login_verified_hook() {
    static AuthLoginVerifiedHook hook;
    return hook;
}

void invoke_auth_settings_publication_hook(
    AuthSettingsPublicationStage stage) {
    AuthSettingsPublicationHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            auth_settings_publication_hook_mutex());
        hook = auth_settings_publication_hook();
    }
    if (hook) hook(stage);
}

void invoke_stream_admission_hook() {
    StreamAdmissionHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            stream_admission_hook_mutex());
        hook = stream_admission_hook();
    }
    if (hook) hook();
}

void invoke_auth_settings_admission_hook() {
    AuthSettingsAdmissionHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            auth_settings_admission_hook_mutex());
        hook = auth_settings_admission_hook();
    }
    if (hook) hook();
}

void invoke_auth_login_verified_hook() {
    AuthLoginVerifiedHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            auth_login_verified_hook_mutex());
        hook = auth_login_verified_hook();
    }
    if (hook) hook();
}

void configure_auth_settings_write_fault(
    AtomicFileWriteOptions& options) {
    const char* configured =
        std::getenv("KEEN_PBR_TEST_AUTH_WRITE_FAULT");
    if (configured == nullptr || *configured == '\0') return;
    const std::string requested(configured);
    options.fault_injector = [requested](AtomicFileWriteStage stage) {
        const char* current = "";
        switch (stage) {
            case AtomicFileWriteStage::write: current = "write"; break;
            case AtomicFileWriteStage::file_fsync:
                current = "file_fsync";
                break;
            case AtomicFileWriteStage::rename: current = "rename"; break;
            case AtomicFileWriteStage::directory_fsync:
                current = "directory_fsync";
                break;
        }
        if (requested == current) {
            throw std::runtime_error(
                "injected auth settings atomic write failure");
        }
    };
}
#endif

std::string get_mime_type_for_path(const std::filesystem::path& path) {
    static const std::unordered_map<std::string, std::string> kMimeByExtension{
        {".css", "text/css"},
        {".csv", "text/csv"},
        {".gif", "image/gif"},
        {".htm", "text/html"},
        {".html", "text/html"},
        {".ico", "image/x-icon"},
        {".jpeg", "image/jpeg"},
        {".jpg", "image/jpeg"},
        {".js", "application/javascript"},
        {".json", "application/json"},
        {".map", "application/json"},
        {".mjs", "application/javascript"},
        {".png", "image/png"},
        {".svg", "image/svg+xml"},
        {".txt", "text/plain"},
        {".wasm", "application/wasm"},
        {".webp", "image/webp"},
        {".woff", "font/woff"},
        {".woff2", "font/woff2"},
        {".xml", "application/xml"},
    };

    const auto ext = path.extension().string();
    const auto it = kMimeByExtension.find(ext);
    if (it != kMimeByExtension.end()) {
        return it->second;
    }
    return "application/octet-stream";
}

bool is_hashed_asset(const std::filesystem::path& path) {
    for (const auto& part : path) {
        if (part == "assets") return true;
    }
    return false;
}

bool serve_file_response(httplib::Response& res,
                         const std::filesystem::path& path,
                          const std::filesystem::path& mime_from_path,
                          bool gzip_encoded) {
    res.set_file_content(path.string(), get_mime_type_for_path(mime_from_path));
    if (gzip_encoded) {
        res.set_header("Content-Encoding", "gzip");
        res.set_header("Vary", "Accept-Encoding");
    }
    if (mime_from_path.filename() == "index.html") {
        res.set_header("Cache-Control", "no-cache");
    } else if (is_hashed_asset(mime_from_path)) {
        res.set_header("Cache-Control", "public, max-age=31536000, immutable");
    } else {
        res.set_header("Cache-Control", "public, max-age=3600");
    }
    return true;
}

std::string trim_ascii(std::string value) {
    auto first = value.begin();
    while (first != value.end() && std::isspace(static_cast<unsigned char>(*first)) != 0) {
        ++first;
    }

    auto last = value.end();
    while (last != first && std::isspace(static_cast<unsigned char>(*(last - 1))) != 0) {
        --last;
    }

    return std::string(first, last);
}

bool parse_accept_encoding_token(const std::string& token, std::string& encoding, double& q) {
    q = 1.0;
    const auto semicolon = token.find(';');
    encoding = trim_ascii(token.substr(0, semicolon));
    if (encoding.empty()) {
        return false;
    }

    std::transform(encoding.begin(), encoding.end(), encoding.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (semicolon == std::string::npos) {
        return true;
    }

    size_t cursor = semicolon + 1;
    while (cursor < token.size()) {
        const auto next = token.find(';', cursor);
        const auto param = trim_ascii(token.substr(cursor, next == std::string::npos
                                                              ? std::string::npos
                                                              : next - cursor));
        const auto equals = param.find('=');
        if (equals != std::string::npos) {
            auto name = trim_ascii(param.substr(0, equals));
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            if (name == "q") {
                char* end = nullptr;
                const auto value = trim_ascii(param.substr(equals + 1));
                q = std::strtod(value.c_str(), &end);
                return end != value.c_str() && q >= 0.0;
            }
        }

        if (next == std::string::npos) {
            break;
        }
        cursor = next + 1;
    }

    return true;
}

bool request_accepts_gzip(const httplib::Request& req) {
    const auto header_count = req.get_header_value_count("Accept-Encoding");
    if (header_count == 0) {
        return false;
    }

    std::optional<double> gzip_q;
    std::optional<double> wildcard_q;
    for (size_t header_index = 0; header_index < header_count; ++header_index) {
        const auto header = req.get_header_value("Accept-Encoding", "", header_index);
        size_t cursor = 0;
        while (cursor <= header.size()) {
            const auto next = header.find(',', cursor);
            const auto token = header.substr(cursor, next == std::string::npos
                                                         ? std::string::npos
                                                         : next - cursor);
            std::string encoding;
            double q = 0.0;
            if (parse_accept_encoding_token(token, encoding, q)) {
                if (encoding == "gzip") {
                    gzip_q = q;
                } else if (encoding == "*") {
                    wildcard_q = q;
                }
            }

            if (next == std::string::npos) {
                break;
            }
            cursor = next + 1;
        }
    }

    return gzip_q.value_or(wildcard_q.value_or(0.0)) > 0.0;
}

std::int64_t request_duration_ms(std::chrono::steady_clock::time_point started_at) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
}

void log_request_start(const httplib::Request& req, const char* kind) {
    Logger::instance().trace("http_request_start",
                             "method={} path={} kind={}",
                             req.method,
                             req.path,
                             kind);
}

void log_request_end(const httplib::Request& req,
                     const char* kind,
                     int status,
                     std::chrono::steady_clock::time_point started_at) {
    Logger::instance().trace("http_request_end",
                             "method={} path={} kind={} status={} duration_ms={}",
                             req.method,
                             req.path,
                             kind,
                             status,
                             request_duration_ms(started_at));
}

void log_request_error(const httplib::Request& req,
                       const char* kind,
                       const std::string& error,
                       std::chrono::steady_clock::time_point started_at) {
    Logger::instance().trace("http_request_error",
                             "method={} path={} kind={} duration_ms={} error={}",
                             req.method,
                             req.path,
                             kind,
                             request_duration_ms(started_at),
                             error);
}

bool path_starts_with(const std::filesystem::path& path,
                      const std::filesystem::path& prefix) {
    auto path_it = path.begin();
    auto prefix_it = prefix.begin();

    for (; prefix_it != prefix.end(); ++prefix_it, ++path_it) {
        if (path_it == path.end() || *path_it != *prefix_it) {
            return false;
        }
    }

    return true;
}

bool is_safe_static_relative_path(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory()) {
        return false;
    }

    for (const auto& component : path) {
        if (component == "..") {
            return false;
        }
    }

    return true;
}

bool resolve_static_file_under_root(const std::filesystem::path& root,
                                    const std::filesystem::path& path,
                                    std::filesystem::path& resolved) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        return false;
    }

    ec.clear();
    resolved = std::filesystem::canonical(path, ec);
    if (ec || !path_starts_with(resolved, root)) {
        return false;
    }

    return true;
}

struct WebAuthConfig {
    bool enabled{false};
    bool misconfigured{false};
    bool endpoint_unavailable{false};
    // "local" checks auth.json, "keenetic" asks the router firmware instead.
    std::string provider{"local"};
    std::string keenetic_endpoint;
    std::string keenetic_endpoint_mode{"auto"};
    bool keenetic_endpoint_from_ndms{false};
    std::string username;
    std::string password;
    std::chrono::seconds session_ttl{std::chrono::hours(24 * 7)};

    bool uses_router_account() const { return provider == "keenetic"; }
};

std::optional<KeeneticAuthEndpoint> discover_keenetic_auth_endpoint(
    std::string* error = nullptr) {
    const auto endpoint = discover_ndms_web_endpoint(
        [](const NdmsWebEndpoint& candidate) {
            return probe_keenetic_auth_challenge(candidate.canonical);
        },
        error);
    if (!endpoint) return std::nullopt;
    return parse_keenetic_auth_endpoint(endpoint->canonical, error);
}

WebAuthConfig misconfigured_web_auth(const std::string& message) {
    WebAuthConfig config;
    // A present but unusable auth file must never silently disable
    // authentication. Keep the API closed and leave recovery to the local
    // installer/SSH path.
    config.enabled = true;
    config.misconfigured = true;
    Logger::instance().error("Web authentication is misconfigured: {}", message);
    return config;
}

WebAuthConfig load_web_auth_config() {
    const char* configured = std::getenv("KEEN_PBR_AUTH_FILE");
    const std::filesystem::path path = configured && *configured
        ? configured : "/opt/etc/keen-pbr/auth.json";

    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(path, status_error);
    if (status_error) {
        if (status_error ==
            std::make_error_code(std::errc::no_such_file_or_directory)) {
            return {};
        }
        return misconfigured_web_auth("cannot inspect auth.json");
    }
    if (!std::filesystem::exists(status)) return {};
    if (!std::filesystem::is_regular_file(status)) {
        return misconfigured_web_auth(
            "auth.json is not a regular file");
    }

    std::ifstream input(path);
    if (!input) {
        return misconfigured_web_auth("cannot read auth.json");
    }
    try {
        const auto document = nlohmann::json::parse(input);
        WebAuthConfig config;
        config.enabled = document.value("enabled", false);
        config.provider = document.value("provider", std::string{"local"});
        config.keenetic_endpoint =
            document.value("keenetic_endpoint", std::string{});
        config.keenetic_endpoint_mode =
            document.value("keenetic_endpoint_mode", std::string{"auto"});
        config.username = document.value("username", std::string{});
        config.password = document.value("password", std::string{});
        const auto ttl = document.value("session_ttl_seconds", 604800);
#ifdef KEEN_PBR3_TESTING
        constexpr auto minimum_session_ttl = 1;
#else
        constexpr auto minimum_session_ttl = 300;
#endif
        if (ttl >= minimum_session_ttl && ttl <= 2592000) {
            config.session_ttl = std::chrono::seconds(ttl);
        }
        if (config.provider != "local" &&
            config.provider != "keenetic") {
            if (config.enabled) {
                return misconfigured_web_auth(
                    "auth.json contains an unknown provider");
            }
            config.provider = "local";
        }
        if (config.uses_router_account()) {
            if (config.keenetic_endpoint_mode != "auto" &&
                config.keenetic_endpoint_mode != "manual") {
                if (config.enabled) {
                    return misconfigured_web_auth(
                        "auth.json contains an invalid Keenetic endpoint mode");
                }
                config.keenetic_endpoint_mode = "auto";
            }

            const auto fallback = config.keenetic_endpoint.empty()
                                      ? std::optional<KeeneticAuthEndpoint>{}
                                      : parse_keenetic_auth_endpoint(
                                            config.keenetic_endpoint);
            if (config.keenetic_endpoint_mode == "manual") {
                if (!fallback) {
                    if (config.enabled) {
                        return misconfigured_web_auth(
                            "auth.json contains an invalid manual Keenetic endpoint");
                    }
                    config.keenetic_endpoint.clear();
                } else {
                    config.keenetic_endpoint = fallback->canonical;
                }
            } else if (config.enabled) {
                // Do not block daemon startup on NDMS HTTP probes. A verified
                // last-known-good endpoint is usable immediately; when it is
                // absent or stale, the first rate-limited login refreshes it.
                if (fallback) {
                    config.keenetic_endpoint = fallback->canonical;
                } else {
                    config.keenetic_endpoint.clear();
                    config.endpoint_unavailable = true;
                }
            } else {
                config.keenetic_endpoint =
                    fallback ? fallback->canonical : std::string{};
            }
        }
        if (config.enabled &&
            !config.uses_router_account() &&
            (config.username.empty() || config.password.empty())) {
            return misconfigured_web_auth(
                "local authentication is enabled without credentials");
        }
        return config;
    } catch (const std::exception& error) {
        Logger::instance().error(
            "Failed to parse auth.json: {}", error.what());
        return misconfigured_web_auth("auth.json is invalid");
    }
}

bool constant_time_equal(const std::string& left, const std::string& right) {
    size_t difference = left.size() ^ right.size();
    const size_t length = std::max(left.size(), right.size());
    for (size_t index = 0; index < length; ++index) {
        const unsigned char a = index < left.size() ? static_cast<unsigned char>(left[index]) : 0;
        const unsigned char b = index < right.size() ? static_cast<unsigned char>(right[index]) : 0;
        difference |= a ^ b;
    }
    return difference == 0;
}

std::optional<std::string> random_session_token() {
    std::array<unsigned char, 32> bytes{};
    std::size_t offset = 0;
    bool use_urandom = false;

    while (offset < bytes.size()) {
        const auto received = ::getrandom(
            bytes.data() + offset, bytes.size() - offset, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && errno == ENOSYS) {
            use_urandom = true;
            break;
        }
        return std::nullopt;
    }

    if (use_urandom) {
        const int descriptor =
            ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (descriptor < 0) return std::nullopt;
        offset = 0;
        while (offset < bytes.size()) {
            const auto received = ::read(
                descriptor, bytes.data() + offset,
                bytes.size() - offset);
            if (received > 0) {
                offset += static_cast<std::size_t>(received);
                continue;
            }
            if (received < 0 && errno == EINTR) continue;
            (void)::close(descriptor);
            return std::nullopt;
        }
        if (::close(descriptor) != 0) return std::nullopt;
    }

    static constexpr char hex[] = "0123456789abcdef";
    std::string token(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        token[index * 2] = hex[bytes[index] >> 4U];
        token[index * 2 + 1] = hex[bytes[index] & 0x0fU];
    }
    return token;
}

std::string cookie_value(const httplib::Request& request, const std::string& name) {
    const auto cookie = request.get_header_value("Cookie");
    size_t cursor = 0;
    while (cursor < cookie.size()) {
        const auto end = cookie.find(';', cursor);
        auto item = trim_ascii(cookie.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor));
        const auto separator = item.find('=');
        if (separator != std::string::npos && item.substr(0, separator) == name) {
            return item.substr(separator + 1);
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    return {};
}

bool is_loopback_address(const std::string& address) {
    return address == "127.0.0.1" || address == "::1" || address == "::ffff:127.0.0.1";
}

bool valid_local_transport_manager_request(const httplib::Request& request) {
    if (request.path != "/api/runtime/outbounds" || !is_loopback_address(request.remote_addr)) {
        return false;
    }

    const auto authorization = request.get_header_value("Authorization");
    constexpr const char* prefix = "Bearer ";
    if (authorization.rfind(prefix, 0) != 0) {
        return false;
    }

    const char* configured = std::getenv("KEEN_PBR_TRANSPORT_CONFIG");
    const std::filesystem::path path = configured && *configured
        ? configured : "/opt/etc/keen-pbr/transports.json";
    std::ifstream input(path);
    if (!input) {
        return false;
    }
    try {
        const auto document = nlohmann::json::parse(input);
        const auto expected = document.value("api_key", std::string{});
        const auto provided = authorization.substr(std::char_traits<char>::length(prefix));
        return !expected.empty() && constant_time_equal(provided, expected);
    } catch (const std::exception&) {
        return false;
    }
}

bool is_sensitive_backup_path(const std::string& path) {
    return path == "/api/backup" || path.rfind("/api/backup/", 0) == 0;
}

} // namespace

#ifdef KEEN_PBR3_TESTING
void set_auth_settings_publication_hook_for_testing(
    AuthSettingsPublicationHook hook) {
    const std::lock_guard<std::mutex> lock(
        auth_settings_publication_hook_mutex());
    auth_settings_publication_hook() = std::move(hook);
}

void reset_auth_settings_publication_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        auth_settings_publication_hook_mutex());
    auth_settings_publication_hook() = {};
}

void set_stream_admission_hook_for_testing(
    StreamAdmissionHook hook) {
    const std::lock_guard<std::mutex> lock(
        stream_admission_hook_mutex());
    stream_admission_hook() = std::move(hook);
}

void reset_stream_admission_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        stream_admission_hook_mutex());
    stream_admission_hook() = {};
}

void set_auth_settings_admission_hook_for_testing(
    AuthSettingsAdmissionHook hook) {
    const std::lock_guard<std::mutex> lock(
        auth_settings_admission_hook_mutex());
    auth_settings_admission_hook() = std::move(hook);
}

void reset_auth_settings_admission_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        auth_settings_admission_hook_mutex());
    auth_settings_admission_hook() = {};
}

void set_auth_login_verified_hook_for_testing(
    AuthLoginVerifiedHook hook) {
    const std::lock_guard<std::mutex> lock(
        auth_login_verified_hook_mutex());
    auth_login_verified_hook() = std::move(hook);
}

void reset_auth_login_verified_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        auth_login_verified_hook_mutex());
    auth_login_verified_hook() = {};
}
#endif

struct ApiServer::Impl {
    httplib::Server server;
    std::string host;
    int port;
    std::thread listen_thread;
    std::atomic<bool> is_listening{false};
    std::atomic<bool> listen_failed{false};
    std::atomic<bool> listen_finished{false};
    TracedMutex state_mutex;
    std::condition_variable_any startup_cv;
    std::string listen_error_message;
    std::mutex auth_update_mutex;
    std::mutex auth_endpoint_discovery_mutex;
    std::mutex auth_mutex;
    std::mutex auth_revocation_mutex;
    std::vector<std::function<void()>> auth_revocation_handlers;
    std::atomic<bool> auth_publication_in_progress{false};
    std::chrono::steady_clock::time_point auth_endpoint_retry_after{};
    WebAuthConfig auth;
    std::uint64_t auth_generation{0};
    AuthSessionRegistry sessions;
    AuthLoginRateLimiter login_rate_limiter;

    WebAuthConfig auth_snapshot() {
        std::lock_guard lock(auth_mutex);
        return auth;
    }

    std::pair<WebAuthConfig, std::uint64_t>
    auth_snapshot_with_generation() {
        std::lock_guard lock(auth_mutex);
        return {auth, auth_generation};
    }

    void advance_auth_generation_locked() noexcept {
        if (++auth_generation == 0U) ++auth_generation;
    }

    void replace_auth(WebAuthConfig replacement) {
        std::lock_guard lock(auth_mutex);
        auth = std::move(replacement);
        advance_auth_generation_locked();
    }

    void close_authenticated_streams_locked() noexcept {
        for (auto& handler : auth_revocation_handlers) {
            try {
                if (handler) handler();
            } catch (const std::exception& error) {
                try {
                    Logger::instance().info(
                        "An authenticated stream will be retired by its "
                        "transport after an auth revocation callback failed: {}",
                        error.what());
                } catch (...) {
                    // Session invalidation below is the security boundary;
                    // an optional diagnostic sink cannot abort it.
                }
            } catch (...) {
                try {
                    Logger::instance().info(
                        "An authenticated stream will be retired by its "
                        "transport after an auth revocation callback failed");
                } catch (...) {
                }
            }
        }
    }

    void revoke_auth_sessions() {
        // This is the session/SSE epoch boundary. A stream admission takes the
        // same lock, revalidates its cookie and registers the subscription
        // before releasing it. Therefore it is either part of this cohort and
        // closed below, or observes the cleared registry and is rejected.
        std::lock_guard epoch_lock(auth_revocation_mutex);
        close_authenticated_streams_locked();
        sessions.clear();
    }

    bool revoke_auth_session(const std::string& token) {
        // Logout is unauthenticated as an endpoint so clients can always
        // discard a stale cookie. Only a currently valid token is authority
        // to retire streams; otherwise this would be a global SSE DoS.
        std::lock_guard epoch_lock(auth_revocation_mutex);
        if (token.empty() || !sessions.contains(token)) return false;
        // Broadcasters currently revoke the active authenticated cohort. This
        // is conservative for another administrator: their stream reconnects
        // with its still-valid cookie, while the logged-out stream cannot leak
        // queued frames or outlive the session.
        close_authenticated_streams_locked();
        sessions.erase(token);
        return true;
    }

    std::optional<std::pair<WebAuthConfig, std::uint64_t>>
    refresh_keenetic_endpoint_from_ndms(
        const std::string& failed_endpoint) {
        // Only one request may query RCI at a time. Requests queued behind a
        // successful refresh reuse that result; failed discovery has a short
        // backoff so an unauthenticated client cannot occupy all HTTP workers.
        std::lock_guard discovery_lock(auth_endpoint_discovery_mutex);
        {
            const auto current = auth_snapshot_with_generation();
            if (!current.first.endpoint_unavailable &&
                current.first.keenetic_endpoint != failed_endpoint) {
                return current;
            }
        }
        const auto now = std::chrono::steady_clock::now();
        if (now < auth_endpoint_retry_after) return std::nullopt;

        const auto endpoint = discover_keenetic_auth_endpoint();
        if (!endpoint) {
            auth_endpoint_retry_after = now + std::chrono::seconds(10);
            return std::nullopt;
        }

        std::lock_guard auth_lock(auth_mutex);
        if (!auth.uses_router_account() ||
            auth.keenetic_endpoint_mode != "auto") {
            return std::nullopt;
        }
        auth.keenetic_endpoint = endpoint->canonical;
        auth.keenetic_endpoint_from_ndms = true;
        auth.endpoint_unavailable = false;
        auth_endpoint_retry_after = {};
        advance_auth_generation_locked();
        return std::pair{auth, auth_generation};
    }
};

ApiServer::ApiServer(const ApiConfig& config) : impl_(std::make_unique<Impl>()) {
    // The daemon runs on memory-constrained routers. Reject oversized bodies
    // before cpp-httplib buffers them and bound slow/stalled clients. Backup
    // restore applies a stricter aggregate limit in its own handler.
    impl_->server.set_payload_max_length(16U * 1024U * 1024U);
    impl_->server.set_default_headers({
        {"X-Content-Type-Options", "nosniff"},
        {"X-Frame-Options", "SAMEORIGIN"},
        {"Referrer-Policy", "no-referrer"},
        {"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
    });
    impl_->server.set_read_timeout(15);
    impl_->server.set_write_timeout(30);
    impl_->server.set_keep_alive_timeout(20);

    // Parse "host:port" from config.listen
    const std::string listen = config.listen.value_or("0.0.0.0:12121");
    auto colon = listen.rfind(':');
    if (colon == std::string::npos) {
        throw ApiError("Invalid listen address: " + listen +
                       " (expected host:port)");
    }

    impl_->host = listen.substr(0, colon);
    std::string port_str = listen.substr(colon + 1);

    try {
        impl_->port = std::stoi(port_str);
    } catch (const std::exception&) {
        throw ApiError("Invalid port in listen address: " + port_str);
    }

    if (impl_->port <= 0 || impl_->port > 65535) {
        throw ApiError("Port out of range: " + port_str);
    }

    impl_->replace_auth(load_web_auth_config());
    impl_->server.Get("/api/auth/status", [state = impl_.get()](const httplib::Request& req,
                                                                  httplib::Response& res) {
        auto auth = state->auth_snapshot();
        const bool loopback_request =
            is_loopback_address(req.remote_addr);
        bool authenticated = !auth.enabled && loopback_request;
        if (auth.enabled) {
            const auto token = cookie_value(req, "keen_pbr_session");
            authenticated = state->sessions.contains(token);
        }
        nlohmann::json response{
            {"enabled", auth.enabled},
            {"provider", auth.provider},
            {"authenticated", authenticated},
        };
        if (!auth.enabled) {
            response["no_auth_scope"] = "loopback_only";
            response["network_api_blocked"] = !loopback_request;
        }
        if (auth.misconfigured) {
            response["error"] = "auth_misconfigured";
        } else if (auth.endpoint_unavailable) {
            response["error"] = "auth_endpoint_unavailable";
        } else if (authenticated && auth.uses_router_account()) {
            response["keenetic_endpoint"] =
                auth.keenetic_endpoint;
            response["keenetic_endpoint_mode"] =
                auth.keenetic_endpoint_mode;
            response["keenetic_endpoint_source"] =
                auth.keenetic_endpoint_from_ndms ? "ndms" : "fallback";
        }
        res.set_header("Cache-Control", "no-store");
        res.set_content(response.dump(), "application/json");
    });
    impl_->server.Post("/api/auth/login", [state = impl_.get()](const httplib::Request& req,
                                                                   httplib::Response& res) {
        auto auth_state = state->auth_snapshot_with_generation();
        auto auth = std::move(auth_state.first);
        auto auth_generation = auth_state.second;
        res.set_header("Cache-Control", "no-store");
        if (auth.misconfigured) {
            res.status = 503;
            res.set_content(
                R"({"error":"auth_misconfigured"})",
                "application/json");
            return;
        }
        if (!auth.enabled) {
            res.set_content(R"({"authenticated":true})", "application/json");
            return;
        }
        if (!state->login_rate_limiter.allow(req.remote_addr)) {
            res.status = 429;
            res.set_header("Retry-After", "60");
            res.set_content(
                R"({"error":"too many login attempts"})",
                "application/json");
            return;
        }
        try {
            const auto body = nlohmann::json::parse(req.body);
            const auto username = body.value("username", std::string{});
            const auto password = body.value("password", std::string{});

            if (auth.uses_router_account()) {
                if (auth.endpoint_unavailable &&
                    auth.keenetic_endpoint_mode == "auto") {
                    const auto refreshed =
                        state->refresh_keenetic_endpoint_from_ndms(
                            auth.keenetic_endpoint);
                    if (refreshed) {
                        auth = refreshed->first;
                        auth_generation = refreshed->second;
                    }
                }
                if (auth.endpoint_unavailable) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":"auth_endpoint_unavailable"})",
                        "application/json");
                    return;
                }
                auto verdict = verify_keenetic_credentials(
                    auth.keenetic_endpoint, username, password);
                if (!verdict.authenticated &&
                    !verdict.endpoint_verified &&
                    auth.keenetic_endpoint_mode == "auto") {
                    // LAN address or the firmware HTTP port may have changed
                    // after this daemon started. Refresh only on an actual
                    // connection failure; wrong passwords never fan out into
                    // additional RCI calls.
                    const auto refreshed =
                        state->refresh_keenetic_endpoint_from_ndms(
                            auth.keenetic_endpoint);
                    if (refreshed) {
                        auth = refreshed->first;
                        auth_generation = refreshed->second;
                        verdict = verify_keenetic_credentials(
                            auth.keenetic_endpoint,
                            username,
                            password);
                    }
                }
                if (!verdict.authenticated) {
                    state->login_rate_limiter.record_failure(req.remote_addr);
                    // A router that cannot be reached is an outage, not a typo.
                    res.status = verdict.reachable ? 401 : 503;
                    res.set_content(
                        nlohmann::json{{"error", verdict.error.empty()
                                                     ? "invalid credentials"
                                                     : verdict.error}}
                            .dump(),
                        "application/json");
                    return;
                }
            } else if (!constant_time_equal(username, auth.username) ||
                       !constant_time_equal(password, auth.password)) {
                state->login_rate_limiter.record_failure(req.remote_addr);
                res.status = 401;
                res.set_content(R"({"error":"invalid credentials"})", "application/json");
                return;
            }
#ifdef KEEN_PBR3_TESTING
            invoke_auth_login_verified_hook();
#endif
            const auto token = random_session_token();
            if (!token) {
                Logger::instance().error(
                    "Cannot obtain secure entropy for a web session");
                res.status = 503;
                res.set_content(
                    R"({"error":"secure session creation failed"})",
                    "application/json");
                return;
            }
            std::chrono::seconds session_ttl;
            {
                // Verification may involve NDM/network I/O and deliberately
                // happens without the epoch. Session publication does not:
                // the exact captured auth generation is revalidated while
                // rotation/logout cannot cross this insertion boundary.
                const std::lock_guard epoch_lock(
                    state->auth_revocation_mutex);
                const std::lock_guard auth_lock(state->auth_mutex);
                if (state->auth_generation != auth_generation ||
                    !state->auth.enabled || state->auth.misconfigured ||
                    state->auth.provider != auth.provider) {
                    res.status = 409;
                    res.set_content(
                        R"({"error":"authentication settings changed; retry login"})",
                        "application/json");
                    return;
                }
                session_ttl = state->auth.session_ttl;
                if (!state->sessions.insert(*token, session_ttl)) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":"session limit reached"})",
                        "application/json");
                    return;
                }
            }
            state->login_rate_limiter.record_success(req.remote_addr);
            res.set_header("Set-Cookie", "keen_pbr_session=" + *token +
                           "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                           std::to_string(session_ttl.count()));
            res.set_content(R"({"authenticated":true})", "application/json");
        } catch (const std::exception&) {
            state->login_rate_limiter.record_failure(req.remote_addr);
            res.status = 400;
            res.set_content(R"({"error":"invalid login request"})", "application/json");
        }
    });
    // Switching the login mode from the interface: writing auth.json by hand on
    // the router was the only way before.
    impl_->server.Post("/api/auth/settings", [state = impl_.get()](const httplib::Request& req,
                                                                    httplib::Response& res) {
        try {
#ifdef KEEN_PBR3_TESTING
            invoke_auth_settings_admission_hook();
#endif
            // Keep the file replacement, reload and in-memory replacement in
            // one order when two administrators save at the same time.
            std::lock_guard update_lock(state->auth_update_mutex);
            const auto current_auth = state->auth_snapshot();
            if (current_auth.enabled) {
                // A second settings request can pass pre-routing with the old
                // cookie, then wait here while the first rotation clears that
                // session. Revalidate after serialization so revoked
                // authority cannot publish another credential set.
                const std::lock_guard epoch_lock(
                    state->auth_revocation_mutex);
                if (!state->sessions.contains(cookie_value(
                        req, "keen_pbr_session"))) {
                    res.status = 401;
                    res.set_header("Cache-Control", "no-store");
                    res.set_content(
                        R"({"error":"authentication required"})",
                        "application/json");
                    return;
                }
            }
            const auto body = nlohmann::json::parse(req.body);
            const auto provider = body.value("provider", std::string{"local"});
            if (provider != "local" && provider != "keenetic") {
                res.status = 400;
                res.set_content(R"({"error":"unknown provider"})", "application/json");
                return;
            }

            nlohmann::json document;
            const bool requested_enabled = body.value("enabled", true);
            document["enabled"] = requested_enabled;
            document["provider"] = provider;
            document["session_ttl_seconds"] =
                static_cast<long long>(
                    current_auth.session_ttl.count());

            if (provider == "keenetic") {
                const auto endpoint_mode = body.contains(
                                                   "keenetic_endpoint_mode")
                                               ? body.value(
                                                     "keenetic_endpoint_mode",
                                                     std::string{"auto"})
                                               : current_auth.uses_router_account()
                                                     ? current_auth
                                                           .keenetic_endpoint_mode
                                                     : std::string{"auto"};
                if (endpoint_mode != "auto" &&
                    endpoint_mode != "manual") {
                    res.status = 400;
                    res.set_content(
                        R"({"error":"invalid Keenetic endpoint mode"})",
                        "application/json");
                    return;
                }
                const auto endpoint_text = body.contains("keenetic_endpoint")
                                               ? body.value(
                                                     "keenetic_endpoint",
                                                     std::string{})
                                               : current_auth.uses_router_account()
                                                     ? current_auth
                                                           .keenetic_endpoint
                                                     : std::string{};
                const auto fallback =
                    endpoint_text.empty()
                        ? std::optional<KeeneticAuthEndpoint>{}
                        : parse_keenetic_auth_endpoint(endpoint_text);
                if (!endpoint_text.empty() && !fallback) {
                    res.status = 400;
                    res.set_content(
                        R"({"error":"invalid Keenetic endpoint"})",
                        "application/json");
                    return;
                }
                std::optional<KeeneticAuthEndpoint> endpoint;
                if (!requested_enabled) {
                    endpoint = fallback;
                } else if (endpoint_mode == "manual") {
                    endpoint = fallback;
                    if (!endpoint) {
                        res.status = 400;
                        res.set_content(
                            R"({"error":"manual Keenetic endpoint is required"})",
                            "application/json");
                        return;
                    }
                } else {
                    endpoint = discover_keenetic_auth_endpoint();
                    if (!endpoint) endpoint = fallback;
                }
                const auto username = body.value("username", std::string{});
                const auto password = body.value("password", std::string{});
                if (requested_enabled) {
                    if (!endpoint ||
                        !probe_keenetic_auth_challenge(endpoint->canonical)) {
                        res.status = 503;
                        res.set_content(
                            R"({"error":"auth_endpoint_unavailable"})",
                            "application/json");
                        return;
                    }
                    const bool switching_to_router =
                        !current_auth.enabled ||
                        !current_auth.uses_router_account();
                    const bool credentials_supplied =
                        !username.empty() || !password.empty();
                    if (switching_to_router && !credentials_supplied) {
                        res.status = 400;
                        res.set_content(
                            R"({"error":"router credentials are required before enabling authentication"})",
                            "application/json");
                        return;
                    }
                    if (credentials_supplied) {
                        if (username.empty() || password.empty()) {
                            res.status = 400;
                            res.set_content(
                                R"({"error":"username and password are required"})",
                                "application/json");
                            return;
                        }
                        const auto verdict =
                            verify_keenetic_credentials(
                                endpoint->canonical, username, password);
                        if (!verdict.authenticated) {
                            res.status = verdict.reachable ? 401 : 503;
                            res.set_content(
                                nlohmann::json{{"error", verdict.error}}.dump(),
                                "application/json");
                            return;
                        }
                    }
                }
                document["keenetic_endpoint_mode"] = endpoint_mode;
                // Persist an explicit manual fallback, or the successfully
                // discovered endpoint as a last-known-good value for a future
                // transient RCI outage.
                if (fallback) {
                    document["keenetic_endpoint"] =
                        fallback->canonical;
                } else if (endpoint) {
                    document["keenetic_endpoint"] =
                        endpoint->canonical;
                }
            } else {
                const auto username = body.value("username", std::string{});
                const auto password = body.value("password", std::string{});
                if (document["enabled"].get<bool>() &&
                    (username.empty() || password.empty())) {
                    res.status = 400;
                    res.set_content(R"({"error":"username and password are required"})",
                                    "application/json");
                    return;
                }
                document["username"] = username;
                document["password"] = password;
            }

            auto remote_access_security_boundary =
                acquire_remote_access_security_boundary();
            if (!requested_enabled) {
                if (remote_access_blocks_auth_disable(
                        remote_access_security_boundary)) {
                    res.status = 409;
                    res.set_content(
                        R"({"error":"remote_access_enabled"})",
                        "application/json");
                    return;
                }
            }

            ScopedAuthPublicationLatch auth_publication(
                state->auth_publication_in_progress);

            const char* configured = std::getenv("KEEN_PBR_AUTH_FILE");
            const std::filesystem::path path = configured && *configured
                ? configured : "/opt/etc/keen-pbr/auth.json";
            AtomicFileWriteOptions write_options;
            write_options.default_file_mode = 0600;
            write_options.file_mode = static_cast<mode_t>(0600);
            bool auth_settings_committed = false;
            bool auth_settings_durable = true;
            write_options.committed_result = &auth_settings_committed;
#ifdef KEEN_PBR3_TESTING
            configure_auth_settings_write_fault(write_options);
#endif
            try {
                write_file_atomically(
                    path.string(),
                    document.dump() + "\n",
                    write_options);
            } catch (const AtomicFileWriteError& error) {
                if (auth_settings_committed || error.committed()) {
                    // The file visible to future requests is already the new
                    // one. Reload it below even though directory fsync failed;
                    // otherwise authentication on disk and in memory diverge.
                    // Record that fact before logging: formatting or a log
                    // sink may throw, and the publication latch must remain
                    // fail-closed after the rename under every exception.
                    auth_publication.mark_disk_published();
                    auth_settings_durable = false;
                    Logger::instance().warn(
                        "auth.json was published but directory sync failed: {}",
                        error.what());
                } else {
                    Logger::instance().error(
                        "Cannot write auth.json atomically: {}",
                        error.what());
                    res.status = 500;
                    res.set_content(
                        R"({"error":"cannot write auth.json"})",
                        "application/json");
                    return;
                }
            } catch (const std::exception& error) {
                if (auth_settings_committed) {
                    auth_publication.mark_disk_published();
                    auth_settings_durable = false;
                    Logger::instance().warn(
                        "auth.json was published before an unexpected "
                        "write completion failure: {}",
                        error.what());
                } else {
                    Logger::instance().error(
                        "Cannot write auth.json atomically: {}",
                        error.what());
                    res.status = 500;
                    res.set_content(
                        R"({"error":"cannot write auth.json"})",
                        "application/json");
                    return;
                }
            }

            auth_publication.mark_disk_published();
#ifdef KEEN_PBR3_TESTING
            invoke_auth_settings_publication_hook(
                AuthSettingsPublicationStage::disk_published);
#endif
            const auto replacement = load_web_auth_config();
            if (replacement.misconfigured) {
                // The file on disk is now authoritative. Never keep an older
                // disabled/insecure in-memory mode after a failed reload.
                state->replace_auth(replacement);
#ifdef KEEN_PBR3_TESTING
                invoke_auth_settings_publication_hook(
                    AuthSettingsPublicationStage::runtime_published);
#endif
                state->revoke_auth_sessions();
                auth_publication.complete();
                res.status = 500;
                res.set_content(
                    R"({"error":"auth_misconfigured"})",
                    "application/json");
                return;
            }
            const bool auth_disable_staged =
                !requested_enabled && current_auth.enabled;
            if (!auth_disable_staged) {
                state->replace_auth(replacement);
            }
#ifdef KEEN_PBR3_TESTING
            invoke_auth_settings_publication_hook(
                AuthSettingsPublicationStage::runtime_published);
#endif
            // Existing sessions belong to the previous mode. Disabling an
            // active runtime is deliberately staged until restart: firewall
            // removal cannot retire an already-established keep-alive/SSE
            // connection, so this process continues requiring credentials.
            state->revoke_auth_sessions();
            auth_publication.complete();
            std::optional<RemoteAccessReconcileResult>
                remote_access_reconcile;
            if (requested_enabled) {
                // Authentication is authoritative before this admission. No
                // firewall command runs on the HTTP worker: the zero-delay
                // hint is owned by the daemon control loop, including the
                // recovery from an earlier auth-disabled degraded state.
                remote_access_reconcile.emplace(
                    defer_remote_access_reconcile_after_auth_enable(
                        remote_access_security_boundary));
            }
            nlohmann::json response{
                {"saved", true},
                {"durable", auth_settings_durable},
            };
            if (remote_access_reconcile &&
                !remote_access_reconcile->apply.applied) {
                response["remote_access_pending"] =
                    remote_access_reconcile->status.recovery_owned;
                response["remote_access_generation"] =
                    remote_access_reconcile->status.desired_generation;
            }
            if (auth_disable_staged) {
                response["restart_required"] = true;
                response["runtime_auth_enabled"] = true;
                response["restart_detail"] =
                    "authentication remains enabled until service restart "
                    "so existing connections cannot become unauthenticated; "
                    "after restart no-auth API access is loopback-only";
                response["warning"] = response["restart_detail"];
            }
            if (!auth_settings_durable) {
                const std::string durability_warning =
                    "authentication settings are visible but directory "
                    "durability could not be confirmed";
                if (response.contains("warning")) {
                    response["warning"] =
                        response["warning"].get<std::string>() + "; " +
                        durability_warning;
                } else {
                    response["warning"] = durability_warning;
                }
            }
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& error) {
            res.status = 400;
            res.set_content(nlohmann::json{{"error", error.what()}}.dump(),
                            "application/json");
        }
    });

    impl_->server.Post("/api/auth/logout", [state = impl_.get()](const httplib::Request& req,
                                                                    httplib::Response& res) {
        const auto token = cookie_value(req, "keen_pbr_session");
        (void)state->revoke_auth_session(token);
        res.set_header("Set-Cookie", "keen_pbr_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
        res.set_header("Cache-Control", "no-store");
        res.set_content(R"({"authenticated":false})", "application/json");
    });
    impl_->server.set_pre_routing_handler([state = impl_.get()](const httplib::Request& req,
                                                                   httplib::Response& res) {
        // Backup payloads contain credentials and complete routing state.
        // Set this before authentication so both successful responses and
        // rejected requests are excluded from browser and intermediary caches.
        if (is_sensitive_backup_path(req.path)) {
            res.set_header("Cache-Control", "no-store");
        }

        if (valid_local_transport_manager_request(req)) {
            return httplib::Server::HandlerResponse::Unhandled;
        }
        const bool api_request = req.path.rfind("/api/", 0) == 0;
        if (api_request &&
            state->auth_publication_in_progress.load(
                std::memory_order_acquire)) {
            // auth.json and the middleware snapshot are deliberately
            // published as one application-layer state. Reject instead of
            // serving the older (possibly disabled) snapshot in the gap.
            res.status = 503;
            res.set_header("Cache-Control", "no-store");
            res.set_header("Retry-After", "1");
            res.set_content(
                R"({"error":"authentication settings are being published"})",
                "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        const auto auth = state->auth_snapshot();
        const bool loopback_request =
            is_loopback_address(req.remote_addr);
        if (api_request && !auth.enabled && !loopback_request &&
            req.path != "/api/auth/status") {
            const bool cleanup_unverified =
                remote_access_runtime_blocks_unauthenticated_request(false);
            // Even exact chain removal cannot retire a WAN TCP keep-alive
            // established earlier. Therefore an auth-disabled runtime is a
            // loopback recovery mode, never unauthenticated network access.
            res.status = cleanup_unverified ? 503 : 403;
            res.set_header("Cache-Control", "no-store");
            if (cleanup_unverified) res.set_header("Retry-After", "1");
            res.set_content(
                cleanup_unverified
                    ? R"({"error":"remote access cleanup is not verified"})"
                    : R"({"error":"authentication is disabled; no-auth API access is loopback-only"})",
                "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        if (!auth.enabled || !api_request ||
            req.path == "/api/auth/status" || req.path == "/api/auth/login" ||
            req.path == "/api/auth/logout") {
            return httplib::Server::HandlerResponse::Unhandled;
        }
        const auto token = cookie_value(req, "keen_pbr_session");
        const bool valid = state->sessions.contains(token);
        if (valid) return httplib::Server::HandlerResponse::Unhandled;
        res.status = 401;
        res.set_content(R"({"error":"authentication required"})", "application/json");
        return httplib::Server::HandlerResponse::Handled;
    });
}

ApiServer::~ApiServer() {
    stop();
}

void ApiServer::get(const std::string& path, RouteHandler handler) {
    impl_->server.Get(path, [h = std::move(handler)](const httplib::Request& req,
                                                      httplib::Response& res) {
        const auto trace_id = allocate_trace_id();
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        log_request_start(req, "api");
        try {
            std::string body = h();
            res.set_content(body, "application/json");
            log_request_end(req, "api", res.status == 0 ? 200 : res.status, started_at);
        } catch (const ApiError& e) {
            res.status = e.status();
            res.set_content(e.body().value_or(make_error_json(e.what())), "application/json");
            log_request_error(req, "api", e.what(), started_at);
            log_request_end(req, "api", res.status, started_at);
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(make_error_json(e.what()), "application/json");
            log_request_error(req, "api", e.what(), started_at);
            log_request_end(req, "api", res.status, started_at);
        }
    });
}

void ApiServer::post(const std::string& path, RouteHandler handler) {
    impl_->server.Post(path, [h = std::move(handler)](const httplib::Request& req,
                                                       httplib::Response& res) {
        const auto trace_id = allocate_trace_id();
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        log_request_start(req, "api");
        try {
            std::string body = h();
            res.set_content(body, "application/json");
            log_request_end(req, "api", res.status == 0 ? 200 : res.status, started_at);
        } catch (const ApiError& e) {
            res.status = e.status();
            res.set_content(e.body().value_or(make_error_json(e.what())), "application/json");
            log_request_error(req, "api", e.what(), started_at);
            log_request_end(req, "api", res.status, started_at);
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(make_error_json(e.what()), "application/json");
            log_request_error(req, "api", e.what(), started_at);
            log_request_end(req, "api", res.status, started_at);
        }
    });
}

void ApiServer::post(const std::string& path, BodyRouteHandler handler) {
    impl_->server.Post(path, [h = std::move(handler)](const httplib::Request& req,
                                                       httplib::Response& res) {
        const auto trace_id = allocate_trace_id();
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        log_request_start(req, "api");
        try {
            std::string result = h(req.body);
            res.set_content(result, "application/json");
            log_request_end(req, "api", res.status == 0 ? 200 : res.status, started_at);
        } catch (const ApiError& e) {
            res.status = e.status();
            res.set_content(e.body().value_or(make_error_json(e.what())), "application/json");
            log_request_error(req, "api", e.what(), started_at);
            log_request_end(req, "api", res.status, started_at);
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(make_error_json(e.what()), "application/json");
            log_request_error(req, "api", e.what(), started_at);
            log_request_end(req, "api", res.status, started_at);
        }
    });
}

void ApiServer::get_stream(const std::string& path, StreamRouteHandler handler) {
    impl_->server.Get(path, [state = impl_.get(), h = std::move(handler)](
                                const httplib::Request& req,
                                httplib::Response& res) {
        const auto trace_id = allocate_trace_id();
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        log_request_start(req, "stream");
        try {
            const bool protected_api_stream =
                req.path.rfind("/api/", 0) == 0 &&
                !valid_local_transport_manager_request(req);
            std::unique_lock<std::mutex> auth_epoch_lock;
            if (protected_api_stream) {
#ifdef KEEN_PBR3_TESTING
                // The normal middleware check has already succeeded. Pause
                // here to prove a credential rotation cannot slip between
                // that check and subscription registration.
                invoke_stream_admission_hook();
#endif
                auth_epoch_lock = std::unique_lock<std::mutex>(
                    state->auth_revocation_mutex);
                if (state->auth_publication_in_progress.load(
                        std::memory_order_acquire)) {
                    res.status = 503;
                    res.set_header("Cache-Control", "no-store");
                    res.set_header("Retry-After", "1");
                    res.set_content(
                        R"({"error":"authentication settings are being published"})",
                        "application/json");
                    log_request_end(
                        req, "stream", res.status, started_at);
                    return;
                }

                const auto auth = state->auth_snapshot();
                if (auth.enabled &&
                    !state->sessions.contains(cookie_value(
                        req, "keen_pbr_session"))) {
                    res.status = 401;
                    res.set_header("Cache-Control", "no-store");
                    res.set_content(
                        R"({"error":"authentication required"})",
                        "application/json");
                    log_request_end(
                        req, "stream", res.status, started_at);
                    return;
                }
                if (!auth.enabled &&
                    !is_loopback_address(req.remote_addr)) {
                    const bool cleanup_unverified =
                        remote_access_runtime_blocks_unauthenticated_request(
                            false);
                    res.status = cleanup_unverified ? 503 : 403;
                    res.set_header("Cache-Control", "no-store");
                    if (cleanup_unverified) {
                        res.set_header("Retry-After", "1");
                    }
                    res.set_content(
                        cleanup_unverified
                            ? R"({"error":"remote access cleanup is not verified"})"
                            : R"({"error":"authentication is disabled; no-auth API access is loopback-only"})",
                        "application/json");
                    log_request_end(
                        req, "stream", res.status, started_at);
                    return;
                }
            }
            // Keep the epoch lock through the handler's synchronous
            // subscribe()/provider registration. It is released before any
            // content-provider loop starts.
            h(req, res);
            if (auth_epoch_lock.owns_lock()) auth_epoch_lock.unlock();
            log_request_end(req, "stream", res.status == 0 ? 200 : res.status, started_at);
        } catch (const std::exception& e) {
            if (!res.status) {
                res.status = 500;
            }
            if (res.body.empty()) {
                res.set_content(make_error_json(e.what()), "application/json");
            }
            log_request_error(req, "stream", e.what(), started_at);
            log_request_end(req, "stream", res.status, started_at);
        }
    });
}

void ApiServer::on_auth_sessions_revoked(
    std::function<void()> handler) {
    if (!handler) return;
    std::lock_guard lock(impl_->auth_revocation_mutex);
    impl_->auth_revocation_handlers.push_back(std::move(handler));
}

ApiServer::StreamAuthorizationProbe
ApiServer::make_stream_authorization_probe(
    const httplib::Request& request) const {
    const auto token = cookie_value(request, "keen_pbr_session");
    const bool loopback_request =
        is_loopback_address(request.remote_addr);
    return [state = impl_.get(), token, loopback_request]() {
        const std::lock_guard epoch_lock(
            state->auth_revocation_mutex);
        if (state->auth_publication_in_progress.load(
                std::memory_order_acquire)) {
            return false;
        }
        const auto auth = state->auth_snapshot();
        if (auth.enabled) return state->sessions.contains(token);
        return loopback_request;
    };
}

bool ApiServer::register_static_root(const std::string& frontend_root) {
    namespace fs = std::filesystem;

    std::error_code ec;
    const fs::path root = fs::weakly_canonical(fs::path(frontend_root), ec);
    if (ec || !fs::is_directory(root)) {
        return false;
    }

    impl_->server.Get(R"(/(.*))", [root](const httplib::Request& req,
                                          httplib::Response& res) {
        const auto trace_id = allocate_trace_id();
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        log_request_start(req, "static");

        auto finish = [&req, &res, started_at]() {
            log_request_end(req, "static", res.status == 0 ? 200 : res.status, started_at);
        };

        const bool accepts_gzip = request_accepts_gzip(req);

        auto serve_index = [&res, &root, accepts_gzip]() -> bool {
            const fs::path index_path = root / "index.html";
            auto index_gzip_path = index_path;
            index_gzip_path += ".gz";

            fs::path resolved_index_gzip;
            if (accepts_gzip &&
                resolve_static_file_under_root(root, index_gzip_path, resolved_index_gzip)) {
                return serve_file_response(res, resolved_index_gzip, index_path, true);
            }

            fs::path resolved_index;
            if (resolve_static_file_under_root(root, index_path, resolved_index)) {
                return serve_file_response(res, resolved_index, index_path, false);
            }

            return false;
        };

        const bool is_api_route = req.path == "/api" || req.path.rfind("/api/", 0) == 0;
        if (is_api_route) {
            res.status = 404;
            res.set_content(make_error_json("not found"), "application/json");
            finish();
            return;
        }

        const fs::path relative = (req.path == "/"
                                       ? fs::path("index.html")
                                       : fs::path(req.path).relative_path())
                                      .lexically_normal();

        if (!is_safe_static_relative_path(relative)) {
            res.status = 400;
            res.set_content(make_error_json("invalid path"), "application/json");
            finish();
            return;
        }

        std::error_code ec;
        const fs::path requested = fs::absolute(root / relative, ec).lexically_normal();
        if (ec || !path_starts_with(requested, root)) {
            res.status = 400;
            res.set_content(make_error_json("invalid path"), "application/json");
            finish();
            return;
        }

        fs::path requested_gzip = requested;
        requested_gzip += ".gz";

        fs::path resolved_gzip;
        if (accepts_gzip && resolve_static_file_under_root(root, requested_gzip, resolved_gzip)) {
            if (serve_file_response(res, resolved_gzip, requested, true)) {
                finish();
                return;
            }
            res.status = 500;
            res.set_content(make_error_json("failed to read static file"), "application/json");
            finish();
            return;
        }

        fs::path resolved_requested;
        if (resolve_static_file_under_root(root, requested, resolved_requested)) {
            if (serve_file_response(res, resolved_requested, requested, false)) {
                finish();
                return;
            }
            res.status = 500;
            res.set_content(make_error_json("failed to read static file"), "application/json");
            finish();
            return;
        }

        if (serve_index()) {
            finish();
            return;
        }

        res.status = 404;
        res.set_content(make_error_json("not found"), "application/json");
        finish();
    });

    return true;
}

void ApiServer::start() {
    if (impl_->is_listening.load(std::memory_order_acquire) && impl_->server.is_running()) {
        return;
    }

    impl_->listen_failed.store(false, std::memory_order_release);
    impl_->listen_finished.store(false, std::memory_order_release);
    {
        KPBR_LOCK_GUARD(impl_->state_mutex);
        impl_->listen_error_message.clear();
    }

    impl_->listen_thread = std::thread([this]() {
        std::string error_message;
        bool listen_ok = false;

        try {
            listen_ok = impl_->server.listen(impl_->host, impl_->port);
            if (!listen_ok) {
                error_message = "listen() returned false";
                const int listen_errno = errno;
                if (listen_errno != 0) {
                    error_message += ": ";
                    error_message += std::strerror(listen_errno);
                }
                impl_->listen_failed.store(true, std::memory_order_release);
            }
        } catch (const std::exception& e) {
            error_message = e.what();
            impl_->listen_failed.store(true, std::memory_order_release);
        } catch (...) {
            error_message = "Unknown listen thread error";
            impl_->listen_failed.store(true, std::memory_order_release);
        }

        impl_->is_listening.store(listen_ok, std::memory_order_release);
        impl_->listen_finished.store(true, std::memory_order_release);
        {
            KPBR_UNIQUE_LOCK(lock, impl_->state_mutex);
            if (!error_message.empty()) {
                impl_->listen_error_message = std::move(error_message);
            }
        }
        impl_->startup_cv.notify_all();
    });

    {
        constexpr auto startup_timeout = std::chrono::seconds(3);
        constexpr auto poll_interval = std::chrono::milliseconds(50);
        const auto deadline = std::chrono::steady_clock::now() + startup_timeout;
        KPBR_UNIQUE_LOCK(lock, impl_->state_mutex);
        while (!impl_->server.is_running() &&
               !impl_->listen_failed.load(std::memory_order_acquire) &&
               !impl_->listen_finished.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            impl_->startup_cv.wait_for(lock, poll_interval);
        }
    }

    if (impl_->server.is_running()) {
        impl_->is_listening.store(true, std::memory_order_release);
        return;
    }

    std::string diagnostic;
    {
        KPBR_LOCK_GUARD(impl_->state_mutex);
        diagnostic = impl_->listen_error_message;
    }
    if (diagnostic.empty()) {
        diagnostic = impl_->listen_finished.load(std::memory_order_acquire)
            ? "listen thread exited before server became running"
            : "startup timed out after 3s";
    }

    stop();
    throw ApiError("Failed to start API server on " + impl_->host + ":" +
                   std::to_string(impl_->port) + " (" + diagnostic + ")");
}

void ApiServer::stop() {
    if (impl_ && impl_->server.is_running()) {
        impl_->server.stop();
    }
    if (impl_ && impl_->listen_thread.joinable()) {
        impl_->listen_thread.join();
    }
    if (impl_) {
        impl_->is_listening.store(false, std::memory_order_release);
    }
}

bool ApiServer::listening() const {
    return impl_->is_listening.load(std::memory_order_acquire) && impl_->server.is_running();
}

} // namespace keen_pbr3

#endif // WITH_API
