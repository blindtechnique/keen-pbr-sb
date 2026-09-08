#pragma once
#include "../crypto/sha256.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

namespace keen_pbr3 {
// Pure projection: source metadata and the router clock are authoritative.
// Stable IDs let dismissals work across browsers without a second event journal.
inline nlohmann::json subscription_notices(const nlohmann::json& sources, std::int64_t now) {
    auto notices = nlohmann::json::array();
    if (!sources.is_array()) return notices;
    for (const auto& source : sources) {
        if (!source.is_object() || notices.size() >= 256) continue;
        const auto id = source.value("id", std::string{});
        if (id.empty()) continue;
        const auto name = source.value("name", std::string{});
        const auto add = [&](const std::string& kind, const std::string& cycle,
                             nlohmann::json details = nlohmann::json::object()) {
            details["id"] = "subscription:" + Sha256::hex(id + ":" + kind + ":" + cycle);
            details["subscription_id"] = id;
            details["name"] = name;
            details["kind"] = kind;
            if (notices.size() < 256) notices.push_back(std::move(details));
        };
        const auto expiry = source.value("expires_at", std::int64_t{0});
        const auto pending = source.value("pending_new_servers_count", 0);
        if (pending > 0) {
            const auto revision = source.find("pending_servers_revision");
            add("new_servers", revision == source.end() ? "0" : revision->dump(), {{"count", pending}});
        }
        if (source.contains("total_bytes") && source.contains("upload_bytes") &&
            source.contains("download_bytes")) {
            // Long double prevents unsigned counter addition overflow.
            const auto total = source.at("total_bytes").get<long double>();
            const auto used = source.at("upload_bytes").get<long double>() +
                              source.at("download_bytes").get<long double>();
            if (total > 0 && used >= 0 && used >= total * 0.9L) {
                const auto cycle = source.at("total_bytes").dump() + ":" + std::to_string(expiry) +
                    ":" + std::to_string(source.value("usage_cycle", std::int64_t{0}));
                add(used >= total ? "traffic_exhausted" : "traffic_low", cycle,
                    {{"remaining_percent", static_cast<int>(std::ceil(
                        std::max(0.0L, (total - used) * 100 / total)))}});
            }
        }
        if (expiry > 0 && now > 0 && expiry - now <= 7 * 86400) {
            const auto days = expiry <= now ? 0 : (expiry - now + 86399) / 86400;
            add(expiry <= now ? "expired" : "expires_soon",
                std::to_string(expiry) + (days <= 1 ? ":1" : days <= 3 ? ":3" : ":7"), {{"days", days}});
        }
        const auto sync_error = source.value("last_sync_error", std::string{});
        if (!sync_error.empty()) add("sync_failed", sync_error);
    }
    return notices;
}
}
