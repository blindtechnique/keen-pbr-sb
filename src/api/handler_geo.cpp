#ifdef WITH_API

#include "handler_geo.hpp"

#include "../http/http_client.hpp"
#include "../log/logger.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <fstream>
#include <limits>
#include <mutex>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <vector>

namespace keen_pbr3 {

namespace {

// ipwho.is отвечает без ключа и без регистрации, по HTTPS. Имена он не
// разрешает — только адреса, поэтому хост мы приводим к адресу сами.
constexpr const char* kLookupPrefix = "https://ipwho.is/";

constexpr const char* kCachePath = "/opt/var/cache/keen-pbr/geo.json";

// Сервер не переезжает из страны в страну, так что месяц — разумный срок.
// Смысл кэша не в скорости, а в том, чтобы адреса пользователя уходили
// наружу один раз, а не при каждом открытии страницы.
constexpr auto kMaxAge = std::chrono::hours(24 * 30);

// Верхняя граница на один запрос. Страница просит всё разом, но незнакомых
// адресов там обычно единицы; ограничение защищает от того, чтобы конфиг на
// три десятка транспортов подвесил ответ на полторы минуты.
constexpr size_t kLookupsPerRequest = 6;
constexpr size_t kMaxCacheEntries = 256;
constexpr size_t kMaxConcurrentLookups = 12;

constexpr auto kLookupTimeout = std::chrono::seconds(4);

std::mutex& geo_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::set<std::string>& in_flight() {
    static std::set<std::string> hosts;
    return hosts;
}

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

nlohmann::json& cache() {
    static nlohmann::json data = [] {
        std::ifstream file(kCachePath);
        if (!file) {
            return nlohmann::json::object();
        }
        try {
            auto parsed = nlohmann::json::parse(file);
            return parsed.is_object() ? parsed : nlohmann::json::object();
        } catch (const std::exception&) {
            // Испорченный кэш — не повод падать: он наполнится заново.
            return nlohmann::json::object();
        }
    }();
    return data;
}

void save_cache() {
    ::mkdir("/opt/var/cache", 0755);
    ::mkdir("/opt/var/cache/keen-pbr", 0755);
    const std::string temporary = std::string(kCachePath) + ".tmp";
    {
        std::ofstream file(temporary, std::ios::trunc);
        if (!file) {
            return;
        }
        file << cache().dump();
    }
    ::rename(temporary.c_str(), kCachePath);
}

bool cache_entry_is_fresh(const nlohmann::json& entry) {
    if (!entry.is_object()) return false;
    const auto age = now_seconds() - entry.value("checked_at", int64_t{0});
    return age >= 0 &&
           age < std::chrono::duration_cast<std::chrono::seconds>(kMaxAge).count();
}

void prune_cache() {
    while (cache().size() > kMaxCacheEntries) {
        auto oldest = cache().end();
        int64_t oldest_time = std::numeric_limits<int64_t>::max();
        for (auto it = cache().begin(); it != cache().end(); ++it) {
            const auto checked_at = it->value("checked_at", int64_t{0});
            if (checked_at < oldest_time) {
                oldest = it;
                oldest_time = checked_at;
            }
        }
        if (oldest == cache().end()) break;
        cache().erase(oldest);
    }
}

bool looks_like_address(const std::string& host) {
    in_addr ipv4{};
    in6_addr ipv6{};
    return inet_pton(AF_INET, host.c_str(), &ipv4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &ipv6) == 1;
}

// Имя сервера приводится к адресу штатным резолвером: у ipwho.is своего
// разрешения имён нет, а адрес нам и так известен ядру, раз туннель работает.
std::string resolve_address(const std::string& host) {
    if (looks_like_address(host)) {
        return host;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result) {
        return {};
    }

    char text[INET6_ADDRSTRLEN] = {};
    const void* address = nullptr;
    if (result->ai_family == AF_INET) {
        address = &reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;
    } else if (result->ai_family == AF_INET6) {
        address = &reinterpret_cast<sockaddr_in6*>(result->ai_addr)->sin6_addr;
    }

    std::string resolved;
    if (address && ::inet_ntop(result->ai_family, address, text, sizeof(text))) {
        resolved = text;
    }
    ::freeaddrinfo(result);
    return resolved;
}

// Пустой результат означает «не выяснили», а не «нет страны»: и то и другое
// на экране выглядит одинаково — просто ничего не показываем.
nlohmann::json look_up(const std::string& host) {
    const auto address = resolve_address(host);
    if (address.empty()) {
        return {};
    }

    try {
        HttpClient client;
        client.set_timeout(kLookupTimeout);
        client.set_max_response_size(64U * 1024U);
        const auto body = nlohmann::json::parse(client.download(kLookupPrefix + address));
        if (!body.is_object() || !body.value("success", false)) {
            return {};
        }

        nlohmann::json entry;
        entry["country"] = body.value("country", std::string{});
        entry["country_code"] = body.value("country_code", std::string{});
        if (body.contains("flag") && body["flag"].is_object()) {
            entry["emoji"] = body["flag"].value("emoji", std::string{});
        }
        if (entry.value("country", std::string{}).empty()) {
            return {};
        }
        entry["checked_at"] = now_seconds();
        return entry;
    } catch (const std::exception& error) {
        Logger::instance().verbose("Could not find out where {} is: {}", host, error.what());
        return {};
    }
}

void look_up_in_background(std::vector<std::string> hosts) {
    std::thread([hosts = std::move(hosts)]() {
        std::vector<std::pair<std::string, nlohmann::json>> results;
        results.reserve(hosts.size());
        for (const auto& host : hosts) {
            auto entry = look_up(host);
            // Cache failures too. Otherwise a missing DNS record or an offline
            // GeoIP service is contacted on every page opening.
            if (entry.is_null() || entry.empty()) {
                entry = nlohmann::json{{"checked_at", now_seconds()}};
            }
            results.emplace_back(host, std::move(entry));
        }

        std::lock_guard<std::mutex> lock(geo_mutex());
        for (auto& [host, entry] : results) {
            cache()[host] = std::move(entry);
            in_flight().erase(host);
        }
        prune_cache();
        save_cache();
    }).detach();
}

} // namespace

void register_geo_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.post("/api/system/geo", [](const std::string& body) -> std::string {
        std::vector<std::string> hosts;
        bool allow_external_lookup = false;
        try {
            const auto request = nlohmann::json::parse(body);
            allow_external_lookup = request.value("allow_external_lookup", false);
            if (request.contains("hosts") && request["hosts"].is_array()) {
                for (const auto& host : request["hosts"]) {
                    if (host.is_string()) {
                        const auto value = host.get<std::string>();
                        if (!value.empty() && value.size() <= 253 &&
                            hosts.size() < kMaxCacheEntries) {
                            hosts.push_back(value);
                        }
                    }
                }
            }
        } catch (const std::exception&) {
            return nlohmann::json{{"error", "invalid_request"}}.dump();
        }

        nlohmann::json found = nlohmann::json::object();
        std::vector<std::string> scheduled;
        bool pending = false;
        {
            std::lock_guard<std::mutex> lock(geo_mutex());
            for (const auto& host : hosts) {
                if (found.contains(host)) continue;
                const auto cached = cache().find(host);
                if (cached != cache().end() && cache_entry_is_fresh(*cached)) {
                    if (!cached->value("country", std::string{}).empty()) {
                        found[host] = *cached;
                    }
                    continue;
                }
                if (!allow_external_lookup) continue;
                pending = true;
                if (scheduled.size() < kLookupsPerRequest &&
                    in_flight().size() < kMaxConcurrentLookups &&
                    in_flight().insert(host).second) {
                    scheduled.push_back(host);
                }
            }
        }

        if (!scheduled.empty()) look_up_in_background(std::move(scheduled));

        return nlohmann::json{{"locations", found}, {"pending", pending}}.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
