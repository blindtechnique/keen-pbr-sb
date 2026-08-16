#ifdef WITH_API

#include "server.hpp"

#include "auth_runtime.hpp"
#include "handler_remote_access.hpp"
#include "keenetic_auth.hpp"
#include "local_password_hash.hpp"
#include "trusted_local_connection.hpp"

#include "../config/config_writer.hpp"
#include "step_up.hpp"
#include "system_auth_capability.hpp"
#include "../keenetic/ndms_lockout_policy.hpp"
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

std::mutex& credential_handler_admission_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

CredentialHandlerAdmissionHook& credential_handler_admission_hook() {
    static CredentialHandlerAdmissionHook hook;
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

void invoke_credential_handler_admission_hook(
    const std::string_view path) {
    CredentialHandlerAdmissionHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            credential_handler_admission_hook_mutex());
        hook = credential_handler_admission_hook();
    }
    if (hook) hook(path);
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

// Long enough that health polling never becomes a probe loop, short enough
// that a firmware whose web service just came back is noticed while the
// operator is still looking at the page.
constexpr std::chrono::seconds kChallengeProbeTtl{60};

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
    // The firmware's brute-force policy, read once alongside endpoint
    // discovery. Empty means the read failed, which keeps the conservative
    // default rather than lifting the limit.
    std::optional<NdmsLockoutPolicy> firmware_lockout;

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

#ifdef KEEN_PBR3_TESTING
std::mutex& trusted_local_connection_evaluator_mutex() {
    static std::mutex mutex;
    return mutex;
}

TrustedLocalConnectionEvaluatorForTesting&
trusted_local_connection_evaluator() {
    static TrustedLocalConnectionEvaluatorForTesting evaluator;
    return evaluator;
}

std::optional<bool> invoke_trusted_local_connection_evaluator(
    const std::string_view remote_address,
    const std::string_view local_address,
    const bool require_credential_freshness) {
    TrustedLocalConnectionEvaluatorForTesting evaluator;
    {
        const std::lock_guard<std::mutex> lock(
            trusted_local_connection_evaluator_mutex());
        evaluator = trusted_local_connection_evaluator();
    }
    if (!evaluator) return std::nullopt;
    return evaluator(
        remote_address, local_address, require_credential_freshness);
}
#endif

bool has_forwarding_identity_headers(const httplib::Request& request) {
    // There is no configured trusted reverse-proxy boundary. cpp-httplib's
    // remote/local addresses therefore come from the accepted socket, and a
    // request carrying proxy identity hints is denied for the secret-import
    // locality capability instead of trying to interpret any of them.
    static constexpr std::array<const char*, 5> names{
        "Forwarded",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Real-IP",
    };
    return std::any_of(
        names.begin(), names.end(),
        [&](const char* name) { return request.has_header(name); });
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

struct AuthSettingsAdmission {
    bool authenticated_session{false};
    bool no_auth_loopback_recovery{false};
};

constexpr const char* kAuthSettingsAdmissionKey =
    "keen-pbr.auth-settings-admission";

struct CredentialAuthAdmission {
    std::uint64_t auth_generation{0U};
    std::string provider;
    bool auth_enabled{false};
    bool protected_secret_transport{false};
    bool https_reverse_proxy{false};
    bool authenticated_session{false};
};

constexpr const char* kCredentialAuthAdmissionKey =
    "keen-pbr.credential-auth-admission";

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

void set_credential_handler_admission_hook_for_testing(
    CredentialHandlerAdmissionHook hook) {
    const std::lock_guard<std::mutex> lock(
        credential_handler_admission_hook_mutex());
    credential_handler_admission_hook() = std::move(hook);
}

void reset_credential_handler_admission_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        credential_handler_admission_hook_mutex());
    credential_handler_admission_hook() = {};
}

void set_trusted_local_connection_evaluator_for_testing(
    TrustedLocalConnectionEvaluatorForTesting evaluator) {
    const std::lock_guard<std::mutex> lock(
        trusted_local_connection_evaluator_mutex());
    trusted_local_connection_evaluator() = std::move(evaluator);
}

void reset_trusted_local_connection_evaluator_for_testing() {
    const std::lock_guard<std::mutex> lock(
        trusted_local_connection_evaluator_mutex());
    trusted_local_connection_evaluator() = {};
}
#endif

struct ApiServer::Impl {
    httplib::Server server;
    std::unique_ptr<TrustedLocalConnectionCache>
        trusted_local_connection_cache;
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
    std::mutex lockout_policy_mutex;
    std::chrono::steady_clock::time_point lockout_policy_retry_after{};
    std::mutex challenge_probe_mutex;
    std::string challenge_probe_endpoint;
    bool challenge_probe_result{false};
    std::chrono::steady_clock::time_point challenge_probe_expires{};
    std::mutex auth_mutex;
    std::mutex auth_revocation_mutex;
    std::vector<std::function<void()>> auth_revocation_handlers;
    std::atomic<bool> auth_publication_in_progress{false};
    std::chrono::steady_clock::time_point auth_endpoint_retry_after{};
    WebAuthConfig auth;
    std::uint64_t auth_generation{0};
    AuthSessionRegistry sessions;
    // Short-lived grants keyed by the session token. Same shape as a session,
    // deliberately: a step-up is a session that expires in minutes.
    AuthSessionRegistry step_up_grants{kStepUpGrantCapacity};
    AuthLoginRateLimiter login_rate_limiter;
    // Sized from the firmware defaults measured on a live Keenetic. Reading
    // the router's actual policy over RCI is a separate slice; until then the
    // conservative default is the documented one, and the capability report
    // stays honest about not having read it.
    AuthForwardBudget firmware_forward_budget{
        auth_forward_capacity_for(kNdmsDefaultLockoutThreshold),
        kNdmsDefaultLockoutObservation};

    TrustedLocalConnectionDecision evaluate_trusted_local_connection(
        const httplib::Request& request,
        const bool require_credential_freshness) {
        if (has_forwarding_identity_headers(request)) return {};
#ifdef KEEN_PBR3_TESTING
        if (const auto overridden =
                invoke_trusted_local_connection_evaluator(
                    request.remote_addr,
                    request.local_addr,
                    require_credential_freshness)) {
            return TrustedLocalConnectionDecision{
                *overridden, *overridden ? 1U : 0U,
                *overridden ? std::chrono::seconds{1}
                            : std::chrono::seconds{}};
        }
#endif
        return trusted_local_connection_cache != nullptr
                   ? trusted_local_connection_cache->evaluate(
                         request.remote_addr,
                         request.local_addr,
                         false,
                         require_credential_freshness)
                   : TrustedLocalConnectionDecision{};
    }

    struct ProtectedSecretTransportDecision {
        bool protected_transport{false};
        bool https_reverse_proxy{false};
    };

    ProtectedSecretTransportDecision evaluate_protected_secret_transport(
        const httplib::Request& request,
        const bool require_credential_freshness) {
        const auto local = evaluate_trusted_local_connection(
            request, require_credential_freshness);
        if (local.trusted) return {true, false};

        // KeenDNS terminates browser HTTPS on the router and forwards the
        // request to this plaintext listener. Proxy headers alone grant
        // nothing: a single browser Origin must say HTTPS, and the accepted
        // TCP peer itself must be an address owned by this router kernel.
        const bool unambiguous_headers =
            request.get_header_value_count("Origin") == 1U &&
            request.get_header_value_count("Sec-Fetch-Site") <= 1U &&
            request.get_header_value_count("X-Forwarded-Proto") <= 1U;
        const auto interfaces = system_trusted_local_interface_addresses();
        const bool trusted_proxy = unambiguous_headers &&
            trusted_router_https_proxy_connection_is_proven(
                request.remote_addr,
                request.local_addr,
                request.get_header_value("Origin"),
                request.get_header_value("Sec-Fetch-Site"),
                request.get_header_value("X-Forwarded-Proto"),
                interfaces);
        return {trusted_proxy, trusted_proxy};
    }

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
        apply_forward_budget(replacement);
        {
            std::lock_guard lock(auth_mutex);
            auth = std::move(replacement);
            advance_auth_generation_locked();
        }
        // A locality proof must not cross an authentication publication.
        // Network-only changes are bounded by the cache TTL; auth changes are
        // synchronously invalidated here.
        if (trusted_local_connection_cache) {
            trusted_local_connection_cache->invalidate();
        }
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
        step_up_grants.clear();
    }

    bool revoke_auth_session(const std::string& token) {
        // Logout is unauthenticated as an endpoint so clients can always
        // discard a stale cookie. Only a currently valid token is authority
        // to retire streams; otherwise this would be a global SSE DoS.
        std::lock_guard epoch_lock(auth_revocation_mutex);
        if (token.empty()) return false;
        if (!sessions.contains(token)) {
            step_up_grants.erase(token);
            return false;
        }
        // Broadcasters currently revoke the active authenticated cohort. This
        // is conservative for another administrator: their stream reconnects
        // with its still-valid cookie, while the logged-out stream cannot leak
        // queued frames or outlive the session.
        close_authenticated_streams_locked();
        sessions.erase(token);
        step_up_grants.erase(token);
        return true;
    }

    // The firmware's own policy is authoritative whenever we managed to read
    // it. The measured defaults stand in when we did not, and the capability
    // report is what tells an operator which of the two happened - the budget
    // itself must never widen just because a read failed.
    struct CredentialOutcome {
        bool ok{false};
        int status{401};
        long long retry_after_seconds{0};
        std::string body{R"({"error":"invalid credentials"})"};
        KeeneticAuthResult keenetic;
    };

    CredentialOutcome forward_keenetic_credentials(
        const std::string& endpoint,
        const std::string& username,
        const std::string& password) {
        CredentialOutcome outcome;
        // Policy refresh happens before admission. reconfigure() shares the
        // budget mutex with Permit, so it cannot resize a live forwarding
        // attempt underneath it.
        refresh_firmware_lockout_policy();
        auto permit = firmware_forward_budget.reserve_forward();
        if (!permit) {
            outcome.status = 429;
            outcome.retry_after_seconds =
                kNdmsDefaultLockoutObservation.count();
            outcome.body = R"({"error":"too many login attempts"})";
            return outcome;
        }

        outcome.keenetic = verify_keenetic_credentials(
            endpoint, username, password);
        if (outcome.keenetic.endpoint_verified &&
            !outcome.keenetic.authenticated) {
            permit->record_forwarded_failure();
        }
        if (!outcome.keenetic.authenticated) {
            outcome.status = outcome.keenetic.reachable ? 401 : 503;
            outcome.body = nlohmann::json{
                {"error", outcome.keenetic.error.empty()
                              ? "invalid credentials"
                              : outcome.keenetic.error}}
                               .dump();
            return outcome;
        }

        outcome.ok = true;
        return outcome;
    }

    // The single credential check, shared by login and by step-up.
    //
    // Sharing it is not tidiness. A second verification path would be a second
    // way to spend the firmware's lockout budget, and a budget with two
    // spenders that only one of them counts is not a budget - step-up would
    // have become the way around the very protection it sits behind.
    CredentialOutcome verify_credentials(
        WebAuthConfig& auth,
        std::uint64_t& auth_generation_snapshot,
        const std::string& username,
        const std::string& password,
        AuthLoginRateLimiter::Permit& login_attempt) {
        CredentialOutcome outcome;

        if (auth.uses_router_account()) {
            if (auth.endpoint_unavailable &&
                auth.keenetic_endpoint_mode == "auto") {
                const auto refreshed =
                    refresh_keenetic_endpoint_from_ndms(auth.keenetic_endpoint);
                if (refreshed) {
                    auth = refreshed->first;
                    auth_generation_snapshot = refreshed->second;
                }
            }
            if (auth.endpoint_unavailable) {
                login_attempt.release();
                outcome.status = 503;
                outcome.body = R"({"error":"auth_endpoint_unavailable"})";
                return outcome;
            }
            outcome = forward_keenetic_credentials(
                auth.keenetic_endpoint, username, password);
            if (!outcome.ok && outcome.status != 429 &&
                !outcome.keenetic.endpoint_verified &&
                auth.keenetic_endpoint_mode == "auto") {
                // LAN address or the firmware HTTP port may have changed after
                // this daemon started. Refresh only on an actual connection
                // failure; wrong passwords never fan out into additional RCI
                // calls.
                const auto refreshed =
                    refresh_keenetic_endpoint_from_ndms(auth.keenetic_endpoint);
                if (refreshed) {
                    auth = refreshed->first;
                    auth_generation_snapshot = refreshed->second;
                    outcome = forward_keenetic_credentials(
                        auth.keenetic_endpoint, username, password);
                }
            }
            if (!outcome.ok) {
                // An unreachable endpoint did not test a credential. Release
                // that reservation without penalizing the source; invalid or
                // budget-exhausting attempts remain failures.
                if (outcome.status == 503) {
                    login_attempt.release();
                } else {
                    login_attempt.record_failure();
                }
                return outcome;
            }
        } else {
            // Derived first and unconditionally, so a wrong username costs the
            // same time as a wrong password. The login limiter already bounds
            // how often anyone can spend it.
            const auto verdict =
                verify_local_password(auth.password, password);
            if (verdict == LocalPasswordVerdict::unusable) {
                Logger::instance().error(
                    "The local credential in auth.json announces a derived key "
                    "and is not one; no password can match it until it is set "
                    "again");
            }
            const bool accepted =
                constant_time_equal(username, auth.username) &&
                (verdict == LocalPasswordVerdict::matched ||
                 verdict ==
                     LocalPasswordVerdict::matched_legacy_plaintext);
            if (!accepted) {
                login_attempt.record_failure();
                outcome.status = 401;
                return outcome;
            }
            if (verdict ==
                LocalPasswordVerdict::matched_legacy_plaintext) {
                // Accepted, because refusing would lock the operator out of
                // their own router. Said out loud, because a credential kept
                // in cleartext is not a resting state.
                Logger::instance().warn(
                    "The local password is still stored in cleartext; saving "
                    "it again in the authentication settings replaces it with "
                    "a derived key");
            }
        }

        login_attempt.record_success();
        outcome.ok = true;
        return outcome;
    }

    // Whether the endpoint actually serves the Keenetic challenge, cached so a
    // health poll cannot turn into a probe per request.
    //
    // No credentials are sent: probe_keenetic_auth_challenge only asks whether
    // the realm and challenge headers come back. A failed probe is cached too,
    // and for the same interval - retrying on every health request would turn
    // an unreachable endpoint into a burst of connection attempts.
    bool keenetic_challenge_observed(const std::string& endpoint) {
        if (endpoint.empty()) return false;

        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(challenge_probe_mutex);
        if (challenge_probe_endpoint == endpoint &&
            now < challenge_probe_expires) {
            return challenge_probe_result;
        }
        challenge_probe_endpoint = endpoint;
        challenge_probe_result = probe_keenetic_auth_challenge(endpoint);
        challenge_probe_expires = now + kChallengeProbeTtl;
        return challenge_probe_result;
    }

    // Reads the firmware policy at most once per retry interval, on the login
    // path rather than at startup. The daemon deliberately does not block
    // booting on NDMS probes, and a login is the first moment the answer
    // actually matters. Held across the read on purpose: concurrent logins
    // should queue behind one RCI call, not stampede it.
    void refresh_firmware_lockout_policy() {
        std::lock_guard lock(lockout_policy_mutex);
        {
            std::lock_guard auth_lock(auth_mutex);
            if (auth.firmware_lockout) return;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now < lockout_policy_retry_after) return;

        std::string error;
        const auto policy = fetch_ndms_lockout_policy(&error);
        if (!policy) {
            // Keep the conservative default and try again later. A failed read
            // must never be the reason the budget widens.
            lockout_policy_retry_after = now + std::chrono::seconds(60);
            Logger::instance().warn(
                "Falling back to the default KeeneticOS lockout policy: {}",
                error);
            return;
        }
        lockout_policy_retry_after = {};
        {
            std::lock_guard auth_lock(auth_mutex);
            auth.firmware_lockout = policy;
        }
        firmware_forward_budget.reconfigure(
            auth_forward_capacity_for(policy->threshold),
            policy->observation_window);
    }

    void apply_forward_budget(const WebAuthConfig& config) {
        const auto threshold = config.firmware_lockout
                                   ? config.firmware_lockout->threshold
                                   : kNdmsDefaultLockoutThreshold;
        const auto window = config.firmware_lockout
                                ? config.firmware_lockout->observation_window
                                : kNdmsDefaultLockoutObservation;
        firmware_forward_budget.reconfigure(
            auth_forward_capacity_for(threshold), window);
    }

    SystemAuthCapability system_auth_switch_capability(
        const std::string& endpoint,
        const bool challenge_observed) {
        // The local password is replacement authority. Do not discard it on
        // the strength of a reachable /auth endpoint alone: unless the live
        // firmware lockout policy is known, we cannot prove that forwarding
        // WebUI failures will not lock the router administrator out.
        refresh_firmware_lockout_policy();
        const auto current = auth_snapshot();

        SystemAuthCapabilityInputs inputs;
        inputs.endpoint_resolved = !endpoint.empty();
        inputs.endpoint_is_loopback = endpoint_is_loopback(endpoint);
        inputs.challenge_observed = challenge_observed;
        inputs.firmware_lockout = current.firmware_lockout;
        inputs.local_limiter.max_failures =
            static_cast<std::uint32_t>(kAuthLoginMaxFailures);
        inputs.local_limiter.window = kAuthLoginWindow;
        inputs.local_limiter.lockout = kAuthLoginLockout;
        inputs.local_limiter.global_forward_cap =
            firmware_forward_budget.capacity();
        return evaluate_system_auth_capability(inputs);
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
    // Remote-access firewall removal cannot revoke a TCP connection which was
    // accepted while the WAN rule still existed. In particular, such a
    // connection must never survive a later switch to the Keenetic provider
    // and carry router credentials over plaintext WAN HTTP. One request per
    // HTTP connection makes the firewall proof an actual request boundary.
    // Long-lived SSE responses remain one request and are separately revoked
    // by the authentication epoch.
    impl_->server.set_keep_alive_max_count(1);
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
    impl_->trusted_local_connection_cache =
        std::make_unique<TrustedLocalConnectionCache>(
            []() -> std::optional<TrustedLocalConnectionSnapshot> {
                // Fixed-loopback RCI supplies the private/non-global NDMS
                // classification; the challenge probe proves this exact
                // numeric address is the router's management service. One
                // verified address is intentionally sufficient for the MVP.
                const auto endpoint = discover_keenetic_auth_endpoint();
                if (!endpoint) return std::nullopt;
                auto interfaces =
                    system_trusted_local_interface_addresses();
                if (interfaces.empty()) return std::nullopt;
                return TrustedLocalConnectionSnapshot{
                    {endpoint->host},
                    std::move(interfaces),
                };
            });
    impl_->server.Get("/api/auth/status", [state = impl_.get()](const httplib::Request& req,
                                                                  httplib::Response& res) {
        const auto auth = state->auth_snapshot();
        const bool loopback_request =
            is_loopback_address(req.remote_addr);
        bool authenticated = !auth.enabled && loopback_request;
        if (auth.enabled) {
            const auto token = cookie_value(req, "keen_pbr_session");
            authenticated = state->sessions.contains(token);
        }
        const bool credential_transport_preflight =
            req.has_param("credential_transport") &&
            req.get_param_value("credential_transport") == "1";
        TrustedLocalConnectionDecision local_decision;
        if (auth.enabled &&
            (authenticated || auth.uses_router_account()) &&
            state->trusted_local_connection_cache != nullptr) {
            local_decision =
                state->evaluate_trusted_local_connection(
                    req, credential_transport_preflight);
        }
        nlohmann::json response{
            {"enabled", auth.enabled},
            {"provider", auth.provider},
            {"authenticated", authenticated},
            {"trusted_local_connection", local_decision.trusted},
        };
        if (local_decision.trusted) {
            // String encoding avoids JavaScript integer truncation. The
            // remaining lifetime lets the browser expire the UI capability
            // even if the next no-store status refresh fails.
            response["trusted_local_connection_generation"] =
                std::to_string(local_decision.evidence_generation);
            response["trusted_local_connection_valid_for_seconds"] =
                local_decision.valid_for.count();
        }
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
    // Reauthentication on top of an existing session, for the operations that
    // install software or change how the router is reached. Never reachable
    // without a session: the pre-routing guard runs first, so an unauthenticated
    // caller cannot use this to probe credentials.
    impl_->server.Post("/api/auth/step-up", [state = impl_.get()](const httplib::Request& req,
                                                                     httplib::Response& res) {
#ifdef KEEN_PBR3_TESTING
        invoke_credential_handler_admission_hook(req.path);
#endif
        auto auth_state = state->auth_snapshot_with_generation();
        auto auth = std::move(auth_state.first);
        auto auth_generation = auth_state.second;
        res.set_header("Cache-Control", "no-store");
        const auto* admission =
            res.user_data.get<CredentialAuthAdmission>(
                kCredentialAuthAdmissionKey);
        if (auth.uses_router_account() &&
            (admission == nullptr ||
             !admission->protected_secret_transport)) {
            res.status = 403;
            res.set_content(
                R"({"error":"protected_secret_transport_unavailable"})",
                "application/json");
            return;
        }
        if (state->auth_publication_in_progress.load(
                std::memory_order_acquire)) {
            res.status = 503;
            res.set_header("Retry-After", "1");
            res.set_content(
                R"({"error":"authentication settings are being published"})",
                "application/json");
            return;
        }
        if (admission == nullptr ||
            admission->auth_generation != auth_generation ||
            admission->provider != auth.provider ||
            admission->auth_enabled != auth.enabled) {
            res.status = 409;
            res.set_content(
                R"({"error":"authentication settings changed; retry step-up"})",
                "application/json");
            return;
        }
        if (auth.misconfigured) {
            res.status = 503;
            res.set_content(
                R"({"error":"auth_misconfigured"})", "application/json");
            return;
        }
        if (!auth.enabled) {
            // There is no session to step up from, and the privileged routes
            // are already open. Refusing here would only invent a control the
            // deployment does not have.
            res.set_content(R"({"granted":true})", "application/json");
            return;
        }
        if (!admission->authenticated_session) {
            res.status = 401;
            res.set_content(
                R"({"error":"authentication required"})",
                "application/json");
            return;
        }
        const auto session = cookie_value(req, "keen_pbr_session");
        if (!state->sessions.contains(session)) {
            res.status = 401;
            res.set_content(
                R"({"error":"authentication required"})", "application/json");
            return;
        }
        auto login_attempt =
            state->login_rate_limiter.reserve_attempt(req.remote_addr);
        if (!login_attempt) {
            res.status = 429;
            res.set_header("Retry-After", "60");
            res.set_content(
                R"({"error":"too many login attempts"})", "application/json");
            return;
        }
        // Keenetic transport locality was already enforced by pre-routing,
        // before cpp-httplib admitted req.body. Repeating the RTM/NDMS proof
        // here would add network work without narrowing the accepted request.
        try {
            const auto body = nlohmann::json::parse(req.body);
            const auto username = body.value("username", std::string{});
            const auto password = body.value("password", std::string{});

            const auto outcome = state->verify_credentials(
                auth, auth_generation, username, password, *login_attempt);
            if (!outcome.ok) {
                res.status = outcome.status;
                if (outcome.retry_after_seconds > 0) {
                    res.set_header(
                        "Retry-After",
                        std::to_string(outcome.retry_after_seconds));
                }
                res.set_content(outcome.body, "application/json");
                return;
            }
            {
                // Credential verification may perform NDM/network I/O, so it
                // deliberately happens without the epoch. Publication does
                // not: rotation/logout cannot cross the generation, session
                // revalidation and grant insertion boundary.
                const std::lock_guard epoch_lock(
                    state->auth_revocation_mutex);
                const std::lock_guard auth_lock(state->auth_mutex);
                if (state->auth_generation != auth_generation ||
                    !state->auth.enabled || state->auth.misconfigured ||
                    state->auth.provider != auth.provider) {
                    res.status = 409;
                    res.set_content(
                        R"({"error":"authentication settings changed; retry step-up"})",
                        "application/json");
                    return;
                }
                if (!state->sessions.contains(session)) {
                    res.status = 401;
                    res.set_content(
                        R"({"error":"authentication required"})",
                        "application/json");
                    return;
                }
                // Keyed by the session, so the grant dies with it. A grant
                // that outlived its session would be a credential of its own.
                if (!state->step_up_grants.insert(
                        session, kStepUpGrantTtl)) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":"step-up grant limit reached"})",
                        "application/json");
                    return;
                }
            }
            res.set_content(
                nlohmann::json{
                    {"granted", true},
                    {"expires_in_seconds", kStepUpGrantTtl.count()}}
                    .dump(),
                "application/json");
        } catch (const std::exception&) {
            login_attempt->record_failure();
            res.status = 400;
            res.set_content(
                R"({"error":"invalid step-up request"})", "application/json");
        }
    });
    impl_->server.Post("/api/auth/login", [state = impl_.get()](const httplib::Request& req,
                                                                   httplib::Response& res) {
#ifdef KEEN_PBR3_TESTING
        invoke_credential_handler_admission_hook(req.path);
#endif
        auto auth_state = state->auth_snapshot_with_generation();
        auto auth = std::move(auth_state.first);
        auto auth_generation = auth_state.second;
        res.set_header("Cache-Control", "no-store");
        const auto* admission =
            res.user_data.get<CredentialAuthAdmission>(
                kCredentialAuthAdmissionKey);
        if (auth.uses_router_account() &&
            (admission == nullptr ||
             !admission->protected_secret_transport)) {
            res.status = 403;
            res.set_content(
                R"({"error":"protected_secret_transport_unavailable"})",
                "application/json");
            return;
        }
        if (state->auth_publication_in_progress.load(
                std::memory_order_acquire)) {
            res.status = 503;
            res.set_header("Retry-After", "1");
            res.set_content(
                R"({"error":"authentication settings are being published"})",
                "application/json");
            return;
        }
        if (admission == nullptr ||
            admission->auth_generation != auth_generation ||
            admission->provider != auth.provider ||
            admission->auth_enabled != auth.enabled) {
            res.status = 409;
            res.set_content(
                R"({"error":"authentication settings changed; retry login"})",
                "application/json");
            return;
        }
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
        auto login_attempt =
            state->login_rate_limiter.reserve_attempt(req.remote_addr);
        if (!login_attempt) {
            res.status = 429;
            res.set_header("Retry-After", "60");
            res.set_content(
                R"({"error":"too many login attempts"})",
                "application/json");
            return;
        }
        // Keenetic transport locality was already enforced by pre-routing,
        // before cpp-httplib admitted req.body. The handler retains the rate
        // limiter and credential verifier; it must not redo router discovery.
        try {
            const auto body = nlohmann::json::parse(req.body);
            const auto username = body.value("username", std::string{});
            const auto password = body.value("password", std::string{});

            const auto outcome = state->verify_credentials(
                auth, auth_generation, username, password, *login_attempt);
            if (!outcome.ok) {
                res.status = outcome.status;
                if (outcome.retry_after_seconds > 0) {
                    res.set_header(
                        "Retry-After",
                        std::to_string(outcome.retry_after_seconds));
                }
                res.set_content(outcome.body, "application/json");
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
            auto cookie = "keen_pbr_session=" + *token +
                          "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                          std::to_string(session_ttl.count());
            if (admission->https_reverse_proxy) cookie += "; Secure";
            res.set_header("Set-Cookie", cookie);
            res.set_content(R"({"authenticated":true})", "application/json");
        } catch (const std::exception&) {
            login_attempt->record_failure();
            res.status = 400;
            res.set_content(R"({"error":"invalid login request"})", "application/json");
        }
    });
    // Switching the login mode from the interface: writing auth.json by hand on
    // the router was the only way before.
    impl_->server.Post("/api/auth/settings", [state = impl_.get()](const httplib::Request& req,
                                                                    httplib::Response& res) {
        try {
            const auto* admission =
                res.user_data.get<AuthSettingsAdmission>(
                    kAuthSettingsAdmissionKey);
            if (admission == nullptr) {
                res.status = 403;
                res.set_header("Cache-Control", "no-store");
                res.set_content(
                    R"({"error":"authentication admission unavailable"})",
                    "application/json");
                return;
            }
#ifdef KEEN_PBR3_TESTING
            invoke_auth_settings_admission_hook();
#endif
            // Keep the file replacement, reload and in-memory replacement in
            // one order when two administrators save at the same time.
            std::lock_guard update_lock(state->auth_update_mutex);
            const auto current_auth = state->auth_snapshot();
            // Queueing behind another publication can outlive the five-second
            // credential evidence admitted by pre-routing. Revalidate the
            // same accepted socket after serialization and before parsing,
            // forwarding or publishing anything from the settings body.
            const bool recovery_loopback =
                admission->no_auth_loopback_recovery &&
                !current_auth.enabled &&
                is_loopback_address(req.remote_addr) &&
                is_loopback_address(req.local_addr);
            if (!recovery_loopback &&
                !state->evaluate_trusted_local_connection(req, true).trusted) {
                res.status = 403;
                res.set_header("Cache-Control", "no-store");
                res.set_content(
                    R"({"error":"protected_secret_transport_unavailable"})",
                    "application/json");
                return;
            }
            if (admission->authenticated_session) {
                // A second settings request can pass pre-routing with the old
                // cookie, then wait here while the first rotation clears that
                // session. Revalidate after serialization so revoked
                // authority cannot publish another credential set.
                const std::lock_guard epoch_lock(
                    state->auth_revocation_mutex);
                if (!state->sessions.contains(
                        cookie_value(req, "keen_pbr_session"))) {
                    res.status = 401;
                    res.set_header("Cache-Control", "no-store");
                    res.set_content(
                        R"({"error":"authentication required"})",
                        "application/json");
                    return;
                }
                if (!state->step_up_grants.contains(
                        cookie_value(req, "keen_pbr_session"))) {
                    res.status = 403;
                    res.set_header("Cache-Control", "no-store");
                    res.set_content(
                        R"({"error":"step_up_required"})",
                        "application/json");
                    return;
                }
            } else if (!recovery_loopback) {
                res.status = 401;
                res.set_header("Cache-Control", "no-store");
                res.set_content(
                    R"({"error":"authentication required"})",
                    "application/json");
                return;
            }
            const auto body = nlohmann::json::parse(req.body);
            const auto provider = body.value("provider", std::string{"local"});
            if (provider != "local" && provider != "keenetic") {
                res.status = 400;
                res.set_content(R"({"error":"unknown provider"})", "application/json");
                return;
            }
            const bool requested_enabled = body.value("enabled", true);

            // Provider publication and remote desired-state publication share
            // one fence. Keep it across endpoint/credential verification and
            // the atomic auth publication: otherwise a remote-enable POST can
            // slip between this check and auth.json and expose the router
            // administrator password over plaintext WAN HTTP.
            auto remote_access_security_boundary =
                acquire_remote_access_security_boundary();
            if (requested_enabled && provider == "keenetic" &&
                remote_access_blocks_keenetic_auth(
                    remote_access_security_boundary)) {
                res.status = 409;
                res.set_header("Cache-Control", "no-store");
                res.set_content(
                    R"({"error":"remote_access_incompatible_with_keenetic_auth"})",
                    "application/json");
                return;
            }

            nlohmann::json document;
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
                const bool switching_to_router =
                    !current_auth.enabled ||
                    !current_auth.uses_router_account();
                if (!requested_enabled && switching_to_router) {
                    // A disabled provider cannot be verified. Accepting this
                    // would erase the last working local credential before
                    // its replacement had proved either capability or login.
                    res.status = 409;
                    res.set_content(
                        R"({"error":"system_auth_requires_enabled_verification"})",
                        "application/json");
                    return;
                }
                if (requested_enabled) {
                    if (!endpoint ||
                        !probe_keenetic_auth_challenge(endpoint->canonical)) {
                        res.status = 503;
                        res.set_content(
                            R"({"error":"auth_endpoint_unavailable"})",
                            "application/json");
                        return;
                    }
                    if (switching_to_router) {
                        const auto capability =
                            state->system_auth_switch_capability(
                                endpoint->canonical, true);
                        if (!capability.may_replace_local_password) {
                            res.status = 503;
                            res.set_header("Cache-Control", "no-store");
                            res.set_content(
                                nlohmann::json{
                                    {"error",
                                     "system_auth_capability_not_usable"},
                                    {"capability_state",
                                     system_auth_capability_state_name(
                                         capability.state)},
                                    {"detail", capability.detail},
                                }
                                    .dump(),
                                "application/json");
                            return;
                        }
                    }
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
                        auto login_attempt =
                            state->login_rate_limiter.reserve_attempt(
                                req.remote_addr);
                        if (!login_attempt) {
                            res.status = 429;
                            res.set_header("Retry-After", "60");
                            res.set_content(
                                R"({"error":"too many login attempts"})",
                                "application/json");
                            return;
                        }
                        const auto credential_outcome =
                            state->forward_keenetic_credentials(
                                endpoint->canonical, username, password);
                        if (!credential_outcome.ok) {
                            if (credential_outcome.status == 503) {
                                login_attempt->release();
                            } else {
                                login_attempt->record_failure();
                            }
                            res.status = credential_outcome.status;
                            if (credential_outcome.retry_after_seconds > 0) {
                                res.set_header(
                                    "Retry-After",
                                    std::to_string(
                                        credential_outcome
                                            .retry_after_seconds));
                            }
                            res.set_content(
                                credential_outcome.body,
                                "application/json");
                            return;
                        }
                        login_attempt->record_success();
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
                if (password.empty()) {
                    // Only reachable while authentication is disabled: an
                    // enabled provider without credentials was refused above.
                    // There is nothing to derive a key from.
                    document["password"] = std::string{};
                } else {
                    const auto salt = random_session_token();
                    const std::string derived =
                        salt ? encode_local_password_hash(
                                   password,
                                   *salt,
                                   kLocalPasswordHashIterations)
                             : std::string{};
                    if (derived.empty()) {
                        // Without entropy there is no salt, and without a salt
                        // the only thing left to store is the password itself.
                        // Refuse instead: a failure the operator can retry is
                        // better than a silent downgrade to cleartext.
                        res.status = 500;
                        res.set_content(
                            R"({"error":"cannot_derive_password_key"})",
                            "application/json");
                        return;
                    }
                    document["password"] = derived;
                }
            }

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
        } catch (const nlohmann::json::exception&) {
            // Parser/type diagnostics can include fragments near the failure.
            // Authentication settings may contain both the panel password and
            // Keenetic credentials, so expose only a stable redacted error.
            res.status = 400;
            res.set_content(
                R"({"error":"invalid authentication settings request"})",
                "application/json");
        } catch (const std::exception& error) {
            res.status = 400;
            res.set_content(nlohmann::json{{"error", error.what()}}.dump(),
                            "application/json");
        }
    });
    impl_->server.Post(
        "/api/auth/settings/step-up-preflight",
        [state = impl_.get()](const httplib::Request& req,
                             httplib::Response& res) {
            res.set_header("Cache-Control", "no-store");
            const auto auth = state->auth_snapshot();
            if (!auth.enabled) {
                res.set_content(R"({"granted":true})", "application/json");
                return;
            }
            const auto token = cookie_value(req, "keen_pbr_session");
            if (!state->sessions.contains(token)) {
                res.status = 401;
                res.set_content(
                    R"({"error":"authentication required"})",
                    "application/json");
                return;
            }
            if (!state->step_up_grants.contains(token)) {
                res.status = 403;
                res.set_content(
                    R"({"error":"step_up_required"})",
                    "application/json");
                return;
            }
            res.set_content(R"({"granted":true})", "application/json");
        });

    impl_->server.Post("/api/auth/logout", [state = impl_.get()](const httplib::Request& req,
                                                                    httplib::Response& res) {
        const auto token = cookie_value(req, "keen_pbr_session");
        (void)state->revoke_auth_session(token);
        auto cookie = std::string{
            "keen_pbr_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"};
        if (state->evaluate_protected_secret_transport(req, false)
                .https_reverse_proxy) {
            cookie += "; Secure";
        }
        res.set_header("Set-Cookie", cookie);
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

        const bool no_store_auth_path =
            req.path == "/api/auth/status" ||
            req.path == "/api/auth/login" ||
            req.path == "/api/auth/step-up" ||
            req.path == "/api/auth/settings" ||
            req.path == "/api/auth/settings/step-up-preflight" ||
            req.path == "/api/auth/logout";
        if (no_store_auth_path) {
            // This classification is independent of the eventual auth
            // verdict. A 401/403/503 response at any early boundary must not
            // leave authentication/session metadata in a browser or proxy
            // cache.
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
        const auto auth_state = state->auth_snapshot_with_generation();
        const auto& auth = auth_state.first;
        const auto auth_generation = auth_state.second;
        const bool loopback_request =
            is_loopback_address(req.remote_addr);
        const bool credential_handler_request =
            req.method == "POST" &&
            (req.path == "/api/auth/login" ||
             req.path == "/api/auth/step-up");
        if (credential_handler_request) {
            res.user_data.set(
                kCredentialAuthAdmissionKey,
                CredentialAuthAdmission{
                    auth_generation, auth.provider, auth.enabled, false,
                    false, false});
        }
        const auto reject_unprotected_secret_transport = [&]() {
            res.status = 403;
            res.set_header("Cache-Control", "no-store");
            res.set_header("Connection", "close");
            res.set_content(
                R"({"error":"protected_secret_transport_unavailable"})",
                "application/json");
            return httplib::Server::HandlerResponse::Handled;
        };
        if (auth.enabled && auth.uses_router_account() &&
            req.method == "POST" && req.path == "/api/auth/login") {
            auto login_attempt =
                state->login_rate_limiter.reserve_attempt(req.remote_addr);
            if (!login_attempt) {
                res.status = 429;
                res.set_header("Retry-After", "60");
                res.set_content(
                    R"({"error":"too many login attempts"})",
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            const auto transport =
                state->evaluate_protected_secret_transport(req, true);
            if (!transport.protected_transport) {
                login_attempt->record_failure();
                // This runs after headers but before cpp-httplib reads
                // req.body. Router credentials must never enter daemon memory
                // from WAN or an unattested proxy connection, even when a
                // stale firewall rule still reaches this listener.
                return reject_unprotected_secret_transport();
            }
            res.user_data.set(
                kCredentialAuthAdmissionKey,
                CredentialAuthAdmission{
                    auth_generation, auth.provider, auth.enabled, true,
                    transport.https_reverse_proxy, false});
            // The handler owns the attempt that measures credential validity.
            // Releasing here avoids charging one browser submission twice.
            login_attempt->release();
        }
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
        if (!auth.enabled && req.method == "POST" &&
            req.path == "/api/auth/settings" && loopback_request &&
            is_loopback_address(req.local_addr)) {
            res.user_data.set(
                kAuthSettingsAdmissionKey,
                AuthSettingsAdmission{false, true});
        }
        if (!auth.enabled || !api_request ||
            req.path == "/api/auth/status" || req.path == "/api/auth/login" ||
            req.path == "/api/auth/logout") {
            return httplib::Server::HandlerResponse::Unhandled;
        }
        const auto token = cookie_value(req, "keen_pbr_session");
        const bool valid = state->sessions.contains(token);
        if (valid) {
            // Enforced here rather than in each privileged handler. A guard
            // every handler has to remember to call is a guard that a new
            // handler will not have.
            if (requires_step_up(req.method, req.path) &&
                !state->step_up_grants.contains(token)) {
                res.status = 403;
                res.set_content(
                    R"({"error":"step_up_required"})", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            const bool credential_route =
                req.method == "POST" &&
                ((auth.uses_router_account() &&
                  req.path == "/api/auth/step-up") ||
                 req.path == "/api/auth/settings" ||
                 req.path ==
                     "/api/auth/settings/step-up-preflight");
            if (credential_route) {
                auto login_attempt =
                    state->login_rate_limiter.reserve_attempt(req.remote_addr);
                if (!login_attempt) {
                    res.status = 429;
                    res.set_header("Retry-After", "60");
                    res.set_content(
                        R"({"error":"too many login attempts"})",
                        "application/json");
                    return httplib::Server::HandlerResponse::Handled;
                }
                const bool router_step_up =
                    auth.uses_router_account() &&
                    req.path == "/api/auth/step-up";
                const auto transport = router_step_up
                    ? state->evaluate_protected_secret_transport(req, true)
                    : Impl::ProtectedSecretTransportDecision{
                          state->evaluate_trusted_local_connection(req, true)
                              .trusted,
                          false};
                if (!transport.protected_transport) {
                    login_attempt->record_failure();
                    // The settings body can switch from local to Keenetic
                    // auth, so its provider cannot safely be discovered by
                    // parsing first. Gate the whole route before body input.
                    return reject_unprotected_secret_transport();
                }
                login_attempt->release();
                if (req.path == "/api/auth/step-up") {
                    res.user_data.set(
                        kCredentialAuthAdmissionKey,
                        CredentialAuthAdmission{
                            auth_generation, auth.provider, auth.enabled,
                            true, transport.https_reverse_proxy, true});
                }
            } else if (req.method == "POST" &&
                       req.path == "/api/auth/step-up") {
                res.user_data.set(
                    kCredentialAuthAdmissionKey,
                    CredentialAuthAdmission{
                        auth_generation, auth.provider, auth.enabled, false,
                        false, true});
            }
            if (req.method == "POST" &&
                req.path == "/api/auth/settings") {
                res.user_data.set(
                    kAuthSettingsAdmissionKey,
                    AuthSettingsAdmission{true, false});
            }
            return httplib::Server::HandlerResponse::Unhandled;
        }
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
    impl_->server.Post(path, [state = impl_.get(), h = std::move(handler)](
                                 const httplib::Request& req,
                                 httplib::Response& res) {
        const auto trace_id = allocate_trace_id();
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        log_request_start(req, "api");
        try {
            // Action-multiplexed routes cannot be classified by pre-routing:
            // cpp-httplib deliberately invokes it before reading req.body.
            // Their bodies are not credential-bearing, so parse only the
            // bounded action after authenticated admission and enforce the
            // grant before the application handler can mutate anything.
            if (path_dispatches_on_action(req.path)) {
                std::string action;
                try {
                    const auto document = nlohmann::json::parse(req.body);
                    if (document.is_object()) {
                        const auto found = document.find("action");
                        if (found != document.end() && found->is_string()) {
                            action = found->get<std::string>();
                        }
                    }
                } catch (const std::exception&) {
                    // The application handler owns malformed JSON errors. An
                    // absent action has no privileged action-specific bypass.
                }
                if (requires_step_up(req.method, req.path, action)) {
                    const auto auth = state->auth_snapshot();
                    if (auth.enabled) {
                        const auto token =
                            cookie_value(req, "keen_pbr_session");
                        if (!state->sessions.contains(token)) {
                            res.status = 401;
                            res.set_content(
                                R"({"error":"authentication required"})",
                                "application/json");
                            log_request_end(
                                req, "api", res.status, started_at);
                            return;
                        }
                        if (!state->step_up_grants.contains(token)) {
                            res.status = 403;
                            res.set_content(
                                R"({"error":"step_up_required"})",
                                "application/json");
                            log_request_end(
                                req, "api", res.status, started_at);
                            return;
                        }
                    }
                }
            }
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

std::optional<SystemAuthHealthSnapshot> ApiServer::system_auth_health() {
    if (!impl_) return std::nullopt;
    const auto auth = impl_->auth_snapshot();

    SystemAuthEndpointState endpoint_state;
    endpoint_state.endpoint = auth.keenetic_endpoint;
    endpoint_state.endpoint_unavailable = auth.endpoint_unavailable;

    SystemAuthLimiterBudget limiter;
    limiter.max_failures = static_cast<std::uint32_t>(kAuthLoginMaxFailures);
    limiter.window = kAuthLoginWindow;
    limiter.lockout = kAuthLoginLockout;
    limiter.global_forward_cap = impl_->firmware_forward_budget.capacity();

    const auto inputs = build_system_auth_inputs(
        endpoint_state, auth.firmware_lockout, limiter,
        [this](const std::string& endpoint) {
            return impl_->keenetic_challenge_observed(endpoint);
        });

    const auto capability = evaluate_system_auth_capability(inputs);

    SystemAuthHealthSnapshot snapshot;
    snapshot.state = system_auth_capability_state_name(capability.state);
    snapshot.detail = capability.detail;
    snapshot.forwarded_failures_per_window =
        static_cast<std::int64_t>(capability.forwarded_failures_per_window);
    return snapshot;
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

#ifdef KEEN_PBR3_TESTING
void ApiServer::revoke_step_up_grant_for_testing(const std::string& token) {
    impl_->step_up_grants.erase(token);
}

void ApiServer::publish_auth_provider_for_testing(
    const std::string& provider,
    const std::string& keenetic_endpoint) {
    auto replacement = impl_->auth_snapshot();
    replacement.enabled = true;
    replacement.misconfigured = false;
    replacement.provider = provider;
    if (provider == "keenetic") {
        replacement.keenetic_endpoint = keenetic_endpoint;
        replacement.keenetic_endpoint_mode = "manual";
        replacement.endpoint_unavailable = false;
    }
    impl_->replace_auth(std::move(replacement));
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
