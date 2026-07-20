#ifdef WITH_API

#include "handler_ndms_names.hpp"

#include "../http/http_client.hpp"

#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciInterfaces = "http://127.0.0.1:79/rci/show/interface";
// The pages that need this poll every few seconds; the firmware's web server
// is single-threaded and answers this particular call slowly.
constexpr auto kCacheTtl = std::chrono::seconds(30);

std::mutex& cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::optional<bool> boolean_field(const nlohmann::json& entry,
                                  const char* key,
                                  const char* truthy_word) {
    const auto found = entry.find(key);
    if (found == entry.end()) {
        return std::nullopt;
    }
    if (found->is_boolean()) {
        return found->get<bool>();
    }
    if (found->is_string()) {
        return found->get<std::string>() == truthy_word;
    }
    return std::nullopt;
}

// NDMS keeps the user's own label in "description"; when it is empty the
// firmware falls back to the interface id, and so do we.
nlohmann::json build_names() {
    nlohmann::json names = nlohmann::json::object();

    nlohmann::json interfaces;
    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(3));
        client.set_max_response_size(2U * 1024U * 1024U);
        interfaces = nlohmann::json::parse(client.download(kRciInterfaces));
    } catch (const std::exception&) {
        // No firmware API here: OpenWrt builds and the developer machine both
        // land in this branch, and an empty map simply means "no nicer names".
        return names;
    }

    if (!interfaces.is_object()) {
        return names;
    }

    for (const auto& [id, entry] : interfaces.items()) {
        if (!entry.is_object()) {
            continue;
        }

        // The kernel name is what keen-pbr stores in its outbounds; without it
        // there is nothing to match against, so such entries are skipped.
        const auto kernel_name = trim(entry.value("interface-name", std::string{}));
        if (kernel_name.empty()) {
            continue;
        }

        const auto description = trim(entry.value("description", std::string{}));

        nlohmann::json info;
        info["label"] = description.empty() ? id : description;
        info["id"] = id;
        info["type"] = entry.value("type", std::string{});
        // NDMS answers with "yes"/"up" on some firmwares and with a real bool
        // on others. Anything else is left out rather than forced: a surprise
        // type here used to throw out of the whole request.
        if (const auto flag = boolean_field(entry, "connected", "yes")) {
            info["connected"] = *flag;
        }
        if (const auto flag = boolean_field(entry, "link", "up")) {
            info["link"] = *flag;
        }

        names[kernel_name] = info;
    }

    return names;
}

} // namespace

void register_ndms_names_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.get("/api/system/interface-names", []() -> std::string {
        static nlohmann::json cached = nlohmann::json::object();
        static std::chrono::steady_clock::time_point fetched_at{};
        static bool fetched_once = false;

        std::lock_guard<std::mutex> lock(cache_mutex());
        const auto now = std::chrono::steady_clock::now();
        // The emptiness of the answer must be cached too. Where there is no
        // firmware API the map is always empty, and treating that as "not
        // cached yet" meant a three-second HTTP attempt on every single
        // request of a page that polls.
        if (!fetched_once || now - fetched_at > kCacheTtl) {
            cached = build_names();
            fetched_at = now;
            fetched_once = true;
        }

        nlohmann::json response;
        response["names"] = cached;
        response["available"] = !cached.empty();
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
