#ifdef WITH_API

#include "handler_geo.hpp"

#include "../http/http_client.hpp"
#include "../log/logger.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <fstream>
#include <mutex>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
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

constexpr auto kLookupTimeout = std::chrono::seconds(4);

std::mutex& geo_mutex() {
    static std::mutex mutex;
    return mutex;
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

} // namespace

void register_geo_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.post("/api/system/geo", [](const std::string& body) -> std::string {
        std::vector<std::string> hosts;
        try {
            const auto request = nlohmann::json::parse(body);
            if (request.contains("hosts") && request["hosts"].is_array()) {
                for (const auto& host : request["hosts"]) {
                    if (host.is_string() && !host.get<std::string>().empty()) {
                        hosts.push_back(host.get<std::string>());
                    }
                }
            }
        } catch (const std::exception&) {
            return nlohmann::json{{"error", "invalid_request"}}.dump();
        }

        std::lock_guard<std::mutex> lock(geo_mutex());
        nlohmann::json found = nlohmann::json::object();
        size_t looked_up = 0;
        bool changed = false;

        for (const auto& host : hosts) {
            if (found.contains(host)) {
                continue;
            }

            const auto cached = cache().find(host);
            if (cached != cache().end() && cached->is_object()) {
                const auto age = now_seconds() - cached->value("checked_at", int64_t{0});
                if (age < std::chrono::duration_cast<std::chrono::seconds>(kMaxAge).count()) {
                    found[host] = *cached;
                    continue;
                }
            }

            if (looked_up >= kLookupsPerRequest) {
                continue;
            }
            ++looked_up;

            auto entry = look_up(host);
            if (entry.is_null() || entry.empty()) {
                continue;
            }
            cache()[host] = entry;
            found[host] = entry;
            changed = true;
        }

        if (changed) {
            save_cache();
        }

        return nlohmann::json{{"locations", found}}.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
