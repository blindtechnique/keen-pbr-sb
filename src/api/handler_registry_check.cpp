#ifdef WITH_API

#include "handler_registry_check.hpp"

#include "../config/config.hpp"
#include "../config/config_writer.hpp"
#include "../config/subscription_fetch_policy.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

// The public instance of cheburcheck. Its code is not vendored - only the
// verdict is shown, and the service is credited in the panel.
constexpr const char* kServiceUrl = "https://cheburcheck.ru/api/v1/check?target=";
constexpr const char* kServiceName = "cheburcheck.ru";
constexpr const char* kConsentFileName = "registry-consent.json";

// The registry moves in days, not seconds, and the service publishes neither
// terms nor a rate limit. An hour of caching keeps a panel that is left open
// from turning one operator's curiosity into a stream of requests.
constexpr auto kCacheTtl = std::chrono::minutes(60);
constexpr std::size_t kCacheCap = 32;

// Long enough for a DoH round trip on a bad link, short enough that the panel
// does not look hung.
constexpr auto kTimeout = std::chrono::seconds(12);
constexpr std::size_t kMaxResponseBytes = 256U * 1024U;
constexpr std::size_t kMaxConsentBytes = 4096U;
constexpr std::size_t kMaxArrayItems = 32U;
constexpr std::size_t kMaxShortValueBytes = 512U;

struct CachedVerdict {
    nlohmann::json payload;
    std::chrono::steady_clock::time_point stored_at;
};

std::mutex& cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, CachedVerdict>& cache() {
    static std::map<std::string, CachedVerdict> entries;
    return entries;
}

// Serialises consent changes with outbound lookups. Once disabling consent
// returns, no older request can still start sending its target outside the
// router. It also bounds the unversioned third-party dependency to one
// in-flight request instead of tying up many HTTP workers at once.
std::mutex& consent_and_lookup_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::filesystem::path consent_path(const ApiContext& ctx) {
    return std::filesystem::path(ctx.config_path).parent_path() /
           kConsentFileName;
}

bool private_consent_metadata(const struct stat& metadata) {
    return S_ISREG(metadata.st_mode) && metadata.st_nlink == 1 &&
           metadata.st_uid == ::geteuid() &&
           metadata.st_gid == ::getegid() &&
           (metadata.st_mode & 07777) == 0600 && metadata.st_size >= 0 &&
           static_cast<std::uint64_t>(metadata.st_size) <= kMaxConsentBytes;
}

bool same_consent_identity(const struct stat& before,
                           const struct stat& after) {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

RegistryConsentState load_consent(const std::filesystem::path& path) {
    const int fd = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        return errno == ENOENT ? RegistryConsentState::absent
                               : RegistryConsentState::unreadable;
    }
    bool fd_open = true;
    const auto close_fd = [&]() {
        if (!fd_open) return;
        (void)::close(fd);
        fd_open = false;
    };
    try {
        struct stat metadata {};
        if (::fstat(fd, &metadata) != 0 ||
            !private_consent_metadata(metadata)) {
            close_fd();
            return RegistryConsentState::unreadable;
        }
        std::string body;
        body.reserve(static_cast<std::size_t>(metadata.st_size));
        char buffer[512];
        while (true) {
            const auto count = ::read(fd, buffer, sizeof(buffer));
            if (count < 0) {
                if (errno == EINTR) continue;
                close_fd();
                return RegistryConsentState::unreadable;
            }
            if (count == 0) break;
            if (body.size() + static_cast<std::size_t>(count) >
                kMaxConsentBytes) {
                close_fd();
                return RegistryConsentState::unreadable;
            }
            body.append(buffer, static_cast<std::size_t>(count));
        }
        struct stat after {};
        if (::fstat(fd, &after) != 0 || !private_consent_metadata(after) ||
            !same_consent_identity(metadata, after)) {
            close_fd();
            return RegistryConsentState::unreadable;
        }
        close_fd();
        const auto stored = nlohmann::json::parse(body);
        if (!stored.is_object() || stored.size() != 1U ||
            !stored.contains("enabled") ||
            !stored.at("enabled").is_boolean()) {
            return RegistryConsentState::unreadable;
        }
        return stored.at("enabled").get<bool>()
                   ? RegistryConsentState::enabled
                   : RegistryConsentState::disabled;
    } catch (const std::exception&) {
        close_fd();
        return RegistryConsentState::unreadable;
    }
}

bool save_consent(const std::filesystem::path& path, bool enabled) {
    bool committed = false;
    AtomicFileWriteOptions options;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    options.owner = ::geteuid();
    options.group = ::getegid();
    options.committed_result = &committed;
    const auto expected = enabled ? RegistryConsentState::enabled
                                  : RegistryConsentState::disabled;
    try {
        write_file_atomically(
            path.string(),
            nlohmann::json{{"enabled", enabled}}.dump(2) + "\n",
            options);
        if (load_consent(path) != expected) {
            throw std::runtime_error(
                "Published registry consent did not pass private-file validation");
        }
        return true;
    } catch (const AtomicFileWriteError& error) {
        if (!committed && !error.committed()) throw;
        if (load_consent(path) != expected) {
            throw std::runtime_error(
                "Published registry consent did not pass private-file validation");
        }
        Logger::instance().warn(
            "Registry consent was published but directory sync failed: {}",
            error.what());
        return false;
    }
}

std::string trim_lower(std::string value) {
    const auto not_space = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    for (auto& character : value) {
        character = static_cast<char>(
            std::tolower(static_cast<unsigned char>(character)));
    }
    return value;
}

// Only what can appear in a hostname or an IP literal is sent. This is not
// cosmetic: the target is pasted by a person and lands in a URL, so anything
// that could carry a query separator or a control character is refused rather
// than escaped.
bool is_sendable_target(const std::string& target) {
    if (target.empty() || target.size() > 253U) return false;
    for (const unsigned char character : target) {
        const bool allowed =
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '-' || character == ':';
        if (!allowed) return false;
    }
    return true;
}

// Only the fields the panel shows are carried through. A response is data from
// a service we do not control, so it is copied field by field rather than
// forwarded whole.
nlohmann::json summarise(const nlohmann::json& raw) {
    nlohmann::json summary;
    summary["checked"] = true;
    summary["service"] = kServiceName;
    summary["blocked"] = raw.value("blocked", false);

    const auto rkn = raw.find("rkn_domain");
    if (rkn != raw.end() && rkn->is_string()) {
        auto value = rkn->get<std::string>();
        if (value.size() <= kMaxShortValueBytes) {
            summary["rkn_domain"] = std::move(value);
        }
    }

    const auto subnets = raw.find("blocked_subnets");
    auto blocked_subnets = nlohmann::json::array();
    if (subnets != raw.end() && subnets->is_array()) {
        for (const auto& subnet : *subnets) {
            if (blocked_subnets.size() >= kMaxArrayItems) break;
            if (!subnet.is_string()) continue;
            auto value = subnet.get<std::string>();
            if (value.size() <= kMaxShortValueBytes) {
                blocked_subnets.push_back(std::move(value));
            }
        }
    }
    summary["blocked_subnets"] = std::move(blocked_subnets);

    const auto ips = raw.find("ips");
    auto addresses = nlohmann::json::array();
    if (ips != raw.end() && ips->is_array()) {
        for (const auto& ip : *ips) {
            if (addresses.size() >= kMaxArrayItems) break;
            if (!ip.is_string()) continue;
            auto value = ip.get<std::string>();
            if (value.size() <= kMaxShortValueBytes) {
                addresses.push_back(std::move(value));
            }
        }
    }
    summary["ips"] = std::move(addresses);

    // A blocked subnet on a shared CDN is the case where "the domain is not in
    // the registry" and "it still fails" are both true, so the provider names
    // are worth showing.
    const auto cdn = raw.find("cdn_providers");
    auto providers = nlohmann::json::array();
    if (cdn != raw.end() && cdn->is_object()) {
        for (const auto& item : cdn->items()) {
            if (providers.size() >= kMaxArrayItems) break;
            if (item.key().size() <= kMaxShortValueBytes) {
                providers.push_back(item.key());
            }
        }
    }
    summary["cdn_providers"] = std::move(providers);

    const auto geo = raw.find("geo");
    if (geo != raw.end() && geo->is_object()) {
        const auto organisation = geo->find("organisation");
        if (organisation != geo->end() && organisation->is_string()) {
            auto value = organisation->get<std::string>();
            if (value.size() <= kMaxShortValueBytes) {
                summary["organisation"] = std::move(value);
            }
        }
    }
    return summary;
}

nlohmann::json not_checked(const std::string& reason) {
    nlohmann::json response;
    response["checked"] = false;
    response["service"] = kServiceName;
    response["reason"] = reason;
    return response;
}

std::string fetch_default(const std::string& target, uint32_t fwmark) {
    HttpClient client;
    client.set_timeout(kTimeout);
    client.set_max_response_size(kMaxResponseBytes);
    HttpRequestOptions options;
    options.fwmark = fwmark;
    options.destination_filter = [](const std::string& address) {
        return subscription_destination_permitted(address) ==
               SubscriptionDestinationVerdict::allowed;
    };
    // This endpoint is fixed by the application. A redirect is neither needed
    // nor authority to disclose the target to another host.
    options.max_redirects = 0;
    return client.download(kServiceUrl + target, options);
}

uint32_t mark_for_detour(const Config& config, const std::string& tag) {
    if (tag.empty() || !config.outbounds) return 0;
    try {
        const auto marks = allocate_outbound_marks(
            config.fwmark.value_or(FwmarkConfig{}), *config.outbounds);
        const auto found = marks.find(tag);
        return found == marks.end() ? 0U : found->second;
    } catch (const std::exception&) {
        return 0;
    }
}

void register_handler(ApiServer& server,
                      ApiContext& ctx,
                      RegistryFetcher fetcher,
                      RegistryConsentReader read_consent,
                      RegistryConsentWriter write_consent) {
    if (!read_consent) {
        const auto path = consent_path(ctx);
        read_consent = [path]() { return load_consent(path); };
    }
    if (!write_consent) {
        const auto path = consent_path(ctx);
        write_consent = [path](bool enabled) {
            return save_consent(path, enabled);
        };
    }

    server.get(
        "/api/routing/registry-consent",
        [read_consent]() -> std::string {
            std::lock_guard<std::mutex> lock(consent_and_lookup_mutex());
            const auto state = read_consent();
            if (state == RegistryConsentState::unreadable) {
                throw ApiError("Registry consent state is unavailable", 503);
            }
            return nlohmann::json{
                {"enabled", state == RegistryConsentState::enabled},
                {"durable", true},
            }.dump();
        });

    server.post(
        "/api/routing/registry-consent",
        [write_consent](const std::string& body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(body);
            } catch (const std::exception&) {
                throw ApiError("Invalid request body", 400);
            }
            if (!request.is_object() || request.size() != 1U ||
                !request.contains("enabled") ||
                !request.at("enabled").is_boolean()) {
                throw ApiError(
                    "Request must contain exactly one boolean enabled field",
                    400);
            }
            const bool enabled = request.at("enabled").get<bool>();
            std::lock_guard<std::mutex> lock(consent_and_lookup_mutex());
            const bool durable = write_consent(enabled);
            if (!enabled) {
                std::lock_guard<std::mutex> cache_lock(cache_mutex());
                cache().clear();
            }
            return nlohmann::json{
                {"enabled", enabled},
                {"durable", durable},
            }.dump();
        });

    server.post(
        "/api/routing/registry-check",
        [&ctx, fetcher, read_consent](const std::string& body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(body);
            } catch (const std::exception&) {
                nlohmann::json payload = {{"error", "Invalid request body"}};
                throw ApiError("Invalid request body", 400, payload.dump());
            }

            const auto target =
                trim_lower(request.value("target", std::string{}));
            if (!is_sendable_target(target)) {
                nlohmann::json payload = {
                    {"error", "target must be a domain name or IP address"}};
                throw ApiError("Invalid target", 400, payload.dump());
            }

            // Keep the gate held through the outbound call: once a disable
            // request returns, an older lookup cannot still disclose its
            // target. The same lock admits at most one third-party call.
            std::lock_guard<std::mutex> consent_lock(
                consent_and_lookup_mutex());
            const auto config = ctx.get_visible_config();
            const auto consent = read_consent();
            if (consent == RegistryConsentState::unreadable) {
                throw ApiError("Registry consent state is unavailable", 503);
            }
            if (consent != RegistryConsentState::enabled) {
                auto response = not_checked("registry_lookup_disabled");
                response["target"] = target;
                return response.dump();
            }

            {
                std::lock_guard<std::mutex> lock(cache_mutex());
                const auto found = cache().find(target);
                if (found != cache().end() &&
                    std::chrono::steady_clock::now() - found->second.stored_at <
                        kCacheTtl) {
                    auto cached = found->second.payload;
                    cached["cached"] = true;
                    return cached.dump();
                }
            }

            const auto detour = request.value("detour", std::string{});
            const auto mark =
                detour.empty() ? 0U : mark_for_detour(config, detour);

            std::string raw_body;
            try {
                raw_body = fetcher ? fetcher(target)
                                   : fetch_default(target, mark);
            } catch (const std::exception& error) {
                // A lookup that did not happen is reported as "not checked",
                // never as "not blocked": the panel must not turn a failed
                // request into a clean bill of health.
                Logger::instance().info(
                    "Registry check for '{}' did not complete: {}",
                    target,
                    error.what());
                auto response = not_checked("lookup_failed");
                response["target"] = target;
                response["error"] =
                    std::string(error.what()).substr(0, kMaxShortValueBytes);
                return response.dump();
            }

            nlohmann::json parsed;
            try {
                parsed = nlohmann::json::parse(raw_body);
            } catch (const std::exception&) {
                auto response = not_checked("unreadable_response");
                response["target"] = target;
                return response.dump();
            }
            if (!parsed.is_object()) {
                auto response = not_checked("unreadable_response");
                response["target"] = target;
                return response.dump();
            }

            auto summary = summarise(parsed);
            summary["target"] = target;
            {
                std::lock_guard<std::mutex> lock(cache_mutex());
                if (cache().size() >= kCacheCap) cache().clear();
                cache()[target] =
                    CachedVerdict{summary, std::chrono::steady_clock::now()};
            }
            summary["cached"] = false;
            return summary.dump();
        });
}

} // namespace

void register_registry_check_handler(ApiServer& server, ApiContext& ctx) {
    register_handler(server, ctx, {}, {}, {});
}

void register_registry_check_handler_for_test(ApiServer& server,
                                              ApiContext& ctx,
                                              RegistryFetcher fetcher,
                                              RegistryConsentReader read_consent,
                                              RegistryConsentWriter write_consent) {
    register_handler(
        server,
        ctx,
        std::move(fetcher),
        std::move(read_consent),
        std::move(write_consent));
}

void clear_registry_check_cache_for_testing() {
    std::lock_guard<std::mutex> lock(cache_mutex());
    cache().clear();
}

#ifdef KEEN_PBR3_TESTING
RegistryConsentState load_registry_consent_file_for_test(
    const std::string& path) {
    return load_consent(path);
}

bool save_registry_consent_file_for_test(const std::string& path,
                                         bool enabled) {
    return save_consent(path, enabled);
}
#endif

} // namespace keen_pbr3

#endif
