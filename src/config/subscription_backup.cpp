#include "subscription_backup.hpp"
#include "subscription_import_plan.hpp"
#include "subscription_store.hpp"
#include "../util/display_name.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>

namespace keen_pbr3 {
namespace {
using json = nlohmann::json;
constexpr std::size_t kMaximumStoreBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaximumSources = 64U;
constexpr std::size_t kMaximumEntries = 512U;
constexpr std::uint64_t kMaximumExactInteger = 9007199254740991ULL;

[[noreturn]] void invalid() {
    throw std::invalid_argument("invalid subscription backup");
}

bool identifier(const std::string& value, std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
        });
}

bool fingerprint(const std::string& value) {
    return value.size() == 64U &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        });
}

bool candidate_key(const std::string& value) {
    return value.size() == 70U &&
        (value.compare(0, 6, "named:") == 0 || value.compare(0, 6, "exact:") == 0) &&
        fingerprint(value.substr(6));
}

const std::string& string_field(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string()) invalid();
    return object.at(key).get_ref<const std::string&>();
}

std::uint64_t unsigned_integer(const json& value, std::uint64_t maximum) {
    if (!value.is_number_integer()) invalid();
    if (value.is_number_unsigned()) {
        const auto number = value.get<std::uint64_t>();
        if (number > maximum) invalid();
        return number;
    }
    const auto number = value.get<std::int64_t>();
    if (number < 0 || static_cast<std::uint64_t>(number) > maximum) invalid();
    return static_cast<std::uint64_t>(number);
}

std::set<std::string> string_set(const json& value, bool keys) {
    if (!value.is_array() || value.size() > kMaximumEntries) invalid();
    std::set<std::string> result;
    for (const auto& item : value) {
        if (!item.is_string()) invalid();
        const auto& text = item.get_ref<const std::string&>();
        if (!(keys ? candidate_key(text) : identifier(text, 128U)) ||
            !result.insert(text).second) invalid();
    }
    return result;
}

void validate_inventory_item(const json& item, bool binding) {
    if (!item.is_object()) invalid();
    const auto& key = string_field(item, "key");
    const auto& digest = string_field(item, "fingerprint");
    if (!candidate_key(key) || !fingerprint(digest) ||
        !item.contains("stable") || !item.at("stable").is_boolean()) invalid();
    const auto stable = item.at("stable").get<bool>();
    if (stable != (key.compare(0, 6, "named:") == 0) ||
        (!stable && key != "exact:" + digest)) invalid();
    if (binding && !identifier(string_field(item, "tag"), 128U)) invalid();
}

void validate_record(const json& record) {
    if (!record.is_object()) invalid();
    // The store preserves metadata extensions. Validate every known field but
    // retain opaque future fields, still bounded by the whole private file.
    if (!identifier(string_field(record, "id"), 128U)) invalid();
    const auto& url = string_field(record, "url");
    if (url.size() > 4096U || classify_subscription_url(url) != SubscriptionUrlVerdict::allowed)
        invalid();
    const auto host = subscription_source_host(url);
    if (record.contains("source_host") && string_field(record, "source_host") != host)
        invalid();
    for (const char* field : {"name", "provider_name"}) {
        if (!record.contains(field)) continue;
        const auto& name = string_field(record, field);
        // save() uses the URL host before a provider or custom name is known.
        if (!display_name::is_valid(name, false) &&
            !(std::string(field) == "name" && name == host && host.size() <= 253U)) invalid();
    }
    if (record.contains("name_is_custom") && !record.at("name_is_custom").is_boolean())
        invalid();
    if (record.contains("refresh_interval_seconds")) {
        const auto interval = unsigned_integer(record.at("refresh_interval_seconds"), 604800U);
        if (!valid_subscription_refresh_interval(static_cast<std::int64_t>(interval))) invalid();
    }
    for (const char* field : {"checked_at", "updated_at", "expires_at"})
        if (record.contains(field)) (void)unsigned_integer(record.at(field), 253402300799ULL);
    for (const char* field : {"upload_bytes", "download_bytes", "total_bytes", "usage_cycle",
                             "pending_servers_revision"})
        if (record.contains(field)) (void)unsigned_integer(record.at(field), kMaximumExactInteger);
    for (const char* field : {"node_count", "pending_new_servers_count"})
        if (record.contains(field)) (void)unsigned_integer(record.at(field), kMaximumEntries);
    if (record.contains("error")) {
        const auto& error = string_field(record, "error");
        if (error != "invalid_document" && error != "fetch_failed") invalid();
    }
    if (record.contains("last_sync_error")) {
        static const std::set<std::string> errors{"", "apply_failed", "transport_unavailable",
            "ambiguous_binding", "transport_changed", "apply_unavailable"};
        if (!errors.count(string_field(record, "last_sync_error"))) invalid();
    }
    const auto tags = record.contains("transport_tags")
        ? string_set(record.at("transport_tags"), false) : std::set<std::string>{};
    for (const char* field : {"_bindings", "_inventory"}) {
        if (!record.contains(field)) continue;
        const auto& items = record.at(field);
        if (!items.is_array() || items.size() > kMaximumEntries) invalid();
        const bool bindings = std::string(field) == "_bindings";
        std::set<std::string> unique;
        for (const auto& item : items) {
            validate_inventory_item(item, bindings);
            const auto& identity = string_field(item, bindings ? "tag" : "key");
            if (!unique.insert(identity).second || (bindings && !tags.count(identity))) invalid();
        }
    }
    for (const char* field : {"_known_candidates", "_pending_candidates"})
        if (record.contains(field)) (void)string_set(record.at(field), true);
}

std::map<std::string, std::string> transport_fingerprints(const json& config) {
    std::map<std::string, std::string> result;
    if (config.is_null()) return result;
    if (!config.is_array() && (!config.is_object() || !config.contains("transports") ||
        !config.at("transports").is_array())) invalid();
    const auto& specs = config.is_array() ? config : config.at("transports");
    std::set<std::string> tags;
    for (const auto& spec : specs) {
        if (!spec.is_object()) invalid();
        const auto& tag = string_field(spec, "tag");
        const auto& type = string_field(spec, "type");
        if (!identifier(tag, 128U) || !tags.insert(tag).second) invalid();
        if (spec.contains("link") && !spec.at("link").is_string()) invalid();
        if (type != "sing-box" || !spec.contains("link")) continue;
        const auto digest = subscription_link_fingerprint(string_field(spec, "link"));
        if (!digest.empty()) result.emplace(tag, digest);
    }
    return result;
}
} // namespace

json validated_subscription_backup(const json& records) {
    try {
        if (!records.is_array() || records.size() > kMaximumSources ||
            records.dump().size() > kMaximumStoreBytes) invalid();
        std::set<std::string> ids;
        std::set<std::string> urls;
        for (const auto& record : records) {
            validate_record(record);
            if (!ids.insert(string_field(record, "id")).second ||
                !urls.insert(string_field(record, "url")).second) invalid();
        }
        return records;
    } catch (...) { invalid(); }
}

json reconcile_subscription_backup(const json& records, const json& transports_config) {
    try {
        auto result = validated_subscription_backup(records);
        const auto transports = transport_fingerprints(transports_config);
        for (auto& source : result) {
            const auto original_bindings = source.value("_bindings", json::array());
            auto bindings = json::array();
            auto linked = json::array();
            for (const auto& tag_value : source.value("transport_tags", json::array())) {
                const auto& tag = tag_value.get_ref<const std::string&>();
                const auto transport = transports.find(tag);
                if (transport == transports.end()) continue;
                const auto existing = std::find_if(original_bindings.begin(), original_bindings.end(),
                    [&](const auto& binding) { return binding.at("tag") == tag; });
                if (existing != original_bindings.end()) {
                    // A reused tag never inherits the previous source, even if
                    // the new transport matches another provider inventory row.
                    if (existing->at("fingerprint") != transport->second) continue;
                    linked.push_back(tag);
                    bindings.push_back(*existing);
                    continue;
                }
                // Legacy records lack binding fingerprints. Only a unique
                // saved inventory match can establish identity without I/O.
                json matched;
                bool ambiguous = false;
                for (const auto& item : source.value("_inventory", json::array())) {
                    if (item.at("fingerprint") != transport->second) continue;
                    if (!matched.is_null()) { ambiguous = true; break; }
                    matched = item;
                }
                if (matched.is_null() || ambiguous) continue;
                matched["tag"] = tag;
                linked.push_back(tag);
                bindings.push_back(std::move(matched));
            }
            source["transport_tags"] = std::move(linked);
            if (source.contains("_bindings") || !bindings.empty())
                source["_bindings"] = std::move(bindings);
        }
        return validated_subscription_backup(result);
    } catch (...) { invalid(); }
}

} // namespace keen_pbr3
