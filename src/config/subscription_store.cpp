#include "subscription_store.hpp"
#include "config_writer.hpp"
#include "../crypto/sha256.hpp"
#include "../util/display_name.hpp"
#include "../util/base64.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

namespace keen_pbr3 {
namespace {
using json = nlohmann::json;
constexpr std::size_t kMaximumStoreBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaximumSubscriptions = 64U;
std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1U);
}
void check_name(const std::string& name) {
    if (!display_name::is_valid(name, false))
        throw std::invalid_argument("invalid subscription name");
}
json& require_record(json& records, const std::string& id) {
    for (auto& record : records) {
        if (record.value("id", "") == id) return record;
    }
    throw std::out_of_range("subscription not found");
}
std::int64_t refresh_interval(const json& record) {
    const auto value = record.value("refresh_interval_seconds", subscription_default_refresh_interval);
    return valid_subscription_refresh_interval(value)
        ? value : subscription_default_refresh_interval;
}

void merge_bindings(json& record, const json& additions) {
    auto bindings = record.value("_bindings", json::array());
    auto known = record.value("_known_candidates", std::set<std::string>{});
    for (const auto& addition : additions) {
        const auto tag = addition.at("tag").get<std::string>();
        auto found = std::find_if(bindings.begin(), bindings.end(), [&](const auto& binding) {
            return binding.value("tag", "") == tag;
        });
        if (found == bindings.end()) bindings.push_back(addition);
        else *found = addition;
        known.insert(addition.at("key").get<std::string>());
    }
    if (bindings.size() > 512U) throw std::runtime_error("subscription binding limit reached");
    record["_bindings"] = std::move(bindings);
    // Do not mark a legacy source initialized until its first real inventory.
    if (record.contains("_inventory")) record["_known_candidates"] = known;
}

bool detach_transport_tags(json& record, const std::set<std::string>& tags) {
    bool changed = false;
    for (const char* field : {"transport_tags", "_bindings"}) {
        auto found = record.find(field);
        if (found == record.end()) continue;
        auto& entries = *found;
        const auto previous_size = entries.size();
        const bool bindings = std::string(field) == "_bindings";
        entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const auto& entry) {
            const auto tag = bindings ? entry.value("tag", std::string{})
                                      : entry.template get<std::string>();
            return tags.count(tag) != 0;
        }), entries.end());
        changed = changed || entries.size() != previous_size;
    }
    // Keep known candidates: a user-deleted VPN is not a new provider server.
    return changed;
}

void reconcile_inventory(json& record, bool initialized) {
    const auto inventory = record.value("_inventory", json::array());
    if (inventory.size() > 512U) throw std::runtime_error("subscription inventory limit reached");
    std::set<std::string> current;
    for (const auto& item : inventory) current.insert(item.at("key").get<std::string>());
    auto known = record.value("_known_candidates", std::set<std::string>{});
    if (!initialized) known = current;
    for (const auto& binding : record.value("_bindings", json::array()))
        known.insert(binding.at("key").get<std::string>());
    // Keep the baseline bounded by the current provider inventory. A removed
    // server which later returns is proposed again, never recreated silently.
    for (auto it = known.begin(); it != known.end();)
        if (current.count(*it) == 0) it = known.erase(it); else ++it;
    std::set<std::string> pending;
    std::set_difference(current.begin(), current.end(), known.begin(), known.end(),
                        std::inserter(pending, pending.end()));
    const auto previous = record.value("_pending_candidates", std::set<std::string>{});
    auto revision = record.value("pending_servers_revision", std::int64_t{0});
    if (previous != pending) ++revision;
    record["_known_candidates"] = known;
    record["_pending_candidates"] = pending;
    record["pending_new_servers_count"] = pending.size();
    record["pending_servers_revision"] = revision;
}

void merge_metadata(json& record, const json& metadata) {
    const bool initialized = record.contains("_inventory");
    const bool stale = metadata.contains("checked_at") && record.contains("checked_at") &&
        metadata.at("checked_at").get<std::int64_t>() < record.at("checked_at").get<std::int64_t>();
    if (stale) {
        if (metadata.contains("_binding_updates")) merge_bindings(record, metadata.at("_binding_updates"));
        if (initialized) reconcile_inventory(record, true);
        return;
    }
    if (!metadata.contains("error") && metadata.contains("upload_bytes") &&
        metadata.contains("download_bytes") && record.contains("upload_bytes") &&
        record.contains("download_bytes")) {
        const auto previous_usage = record.at("upload_bytes").get<std::uint64_t>() +
            record.at("download_bytes").get<std::uint64_t>();
        const auto current_usage = metadata.at("upload_bytes").get<std::uint64_t>() +
            metadata.at("download_bytes").get<std::uint64_t>();
        if (current_usage < previous_usage)
            record["usage_cycle"] = record.value("usage_cycle", std::int64_t{0}) + 1;
    }
    const bool custom_name = record.value("name_is_custom",
        record.value("name", "") != record.value("source_host", "") &&
        record.value("name", "") != record.value("provider_name", ""));
    if (!custom_name && metadata.contains("provider_name"))
        record["name"] = metadata.at("provider_name");
    // An unsuccessful refresh keeps the last successful limits and counters.
    // A successful response without the header clears old limits: unknown is
    // not unlimited, nor should the old provider limits look freshly verified.
    if (!metadata.contains("error")) {
        for (const char* key : {"upload_bytes", "download_bytes", "total_bytes",
                                "expires_at", "node_count", "updated_at", "error"})
            record.erase(key);
    }
    for (auto it = metadata.begin(); it != metadata.end(); ++it)
        if (it.key() != "_binding_updates") record[it.key()] = it.value();
    if (metadata.contains("_binding_updates"))
        merge_bindings(record, metadata.at("_binding_updates"));
    if (record.contains("_inventory")) reconcile_inventory(record, initialized);
}
} // namespace

std::string parse_subscription_title(const std::string& header) {
    auto title = trim(header);
    if (title.size() > 1024U) return {};
    if (title.compare(0, 7, "base64:") == 0) {
        try { title = trim(base64_decode(title.substr(7))); }
        catch (...) { return {}; }
    }
    return display_name::is_valid(title, false) ? title : std::string{};
}

nlohmann::json parse_subscription_userinfo(const std::string& header) {
    json result = json::object();
    const std::map<std::string, std::string> fields{
        {"upload", "upload_bytes"}, {"download", "download_bytes"},
        {"total", "total_bytes"}, {"expire", "expires_at"}};
    std::set<std::string> seen;
    std::stringstream input(header);
    std::string part;
    while (std::getline(input, part, ';')) {
        const auto equals = part.find('=');
        if (equals == std::string::npos) continue;
        const auto found = fields.find(trim(part.substr(0, equals)));
        if (found == fields.end()) continue;
        const auto& key = found->second;
        if (!seen.insert(key).second) { result.erase(key); continue; }
        const auto text = trim(part.substr(equals + 1U));
        if (text.empty()) continue;
        // JSON numbers cross JavaScript; keep counters exactly representable.
        constexpr std::uint64_t maximum = 9007199254740991ULL;
        std::uint64_t value = 0U;
        bool valid = true;
        for (const char ch : text) {
            if (ch < '0' || ch > '9' || value > (maximum - (ch - '0')) / 10U) {
                valid = false; break;
            }
            value = value * 10U + static_cast<unsigned>(ch - '0');
        }
        // Providers conventionally use zero for an unspecified total/expiry.
        if (valid && (key != "expires_at" || value <= 253402300799ULL) &&
            (value != 0U || key == "upload_bytes" || key == "download_bytes"))
            result[key] = value;
    }
    return result;
}

std::string subscription_source_host(const std::string& url) {
    const auto start = url.find("://");
    if (start == std::string::npos) return {};
    return url.substr(start + 3U, url.find_first_of("/?#", start + 3U) - start - 3U);
}

nlohmann::json public_subscription(nlohmann::json record) {
    record.erase("url");
    record.erase("name_is_custom");
    record.erase("provider_name");
    for (const char* key : {"_inventory", "_bindings", "_known_candidates", "_pending_candidates"})
        record.erase(key);
    const auto interval = refresh_interval(record);
    record["refresh_interval_seconds"] = interval;
    record["pending_new_servers_count"] = record.value("pending_new_servers_count", 0);
    record["pending_servers_revision"] = std::to_string(record.value("pending_servers_revision", std::int64_t{0}));
    record["usage_cycle"] = record.value("usage_cycle", 0);
    if (interval > 0)
        record["next_check_at"] = record.value("checked_at", std::int64_t{0}) + interval;
    else record.erase("next_check_at");
    if (record.value("last_sync_error", "").empty()) record.erase("last_sync_error");
    return record;
}

bool valid_subscription_refresh_interval(std::int64_t interval) noexcept {
    return interval == 0 || (interval >= 3600 && interval <= 604800);
}

nlohmann::json SubscriptionStore::read() const {
    std::error_code error;
    const auto size = std::filesystem::file_size(path_, error);
    if (error == std::errc::no_such_file_or_directory) return json::array();
    if (error || size > kMaximumStoreBytes)
        throw std::runtime_error("cannot read subscription metadata");
    try {
        std::ifstream input(path_);
        auto records = json::parse(input);
        if (!records.is_array() || records.size() > kMaximumSubscriptions)
            throw std::runtime_error("invalid subscription metadata");
        for (const auto& record : records) {
            if (!record.is_object() || !record.contains("id") ||
                !record.at("id").is_string() || !record.contains("url") ||
                !record.at("url").is_string())
                throw std::runtime_error("invalid subscription metadata");
        }
        return records;
    } catch (...) { throw std::runtime_error("cannot read subscription metadata"); }
}

void SubscriptionStore::write(const nlohmann::json& records) const {
    const auto body = records.dump();
    if (body.size() > kMaximumStoreBytes || records.size() > kMaximumSubscriptions)
        throw std::runtime_error("subscription metadata limit reached");
    AtomicFileWriteOptions options;
    options.file_mode = 0600;
    write_file_atomically(path_, body, options);
}

nlohmann::json SubscriptionStore::list() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    for (auto& record : records) record = public_subscription(std::move(record));
    return records;
}

nlohmann::json SubscriptionStore::find(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    return require_record(records, id);
}

nlohmann::json SubscriptionStore::save(
    const std::string& url, const std::string& name, const nlohmann::json& metadata,
    const std::vector<std::string>& tags, const nlohmann::json& bindings) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto it = std::find_if(records.begin(), records.end(), [&](const auto& record) {
        return record.value("url", "") == url;
    });
    if (it == records.end()) {
        records.push_back({{"id", "sub-" + Sha256::hex(url).substr(0, 24)}, {"url", url},
                           {"name", subscription_source_host(url)}, {"name_is_custom", false},
                           {"source_host", subscription_source_host(url)},
                           {"refresh_interval_seconds", subscription_default_refresh_interval},
                           {"transport_tags", json::array()}});
        it = std::prev(records.end());
    }
    if (!name.empty()) {
        check_name(name);
        (*it)["name"] = name;
        (*it)["name_is_custom"] = true;
    }
    auto linked = (*it).value("transport_tags", std::vector<std::string>{});
    for (const auto& tag : tags)
        if (std::find(linked.begin(), linked.end(), tag) == linked.end()) linked.push_back(tag);
    (*it)["transport_tags"] = linked;
    merge_bindings(*it, bindings);
    merge_metadata(*it, metadata);
    const auto result = public_subscription(*it);
    write(records);
    return result;
}

nlohmann::json SubscriptionStore::refresh(const std::string& id, const nlohmann::json& metadata,
                                         const std::vector<std::string>& confirmed_absent_tags) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto& record = require_record(records, id);
    merge_metadata(record, metadata);
    if (!confirmed_absent_tags.empty())
        detach_transport_tags(record, {confirmed_absent_tags.begin(), confirmed_absent_tags.end()});
    const auto result = public_subscription(record);
    write(records);
    return result;
}

bool SubscriptionStore::detach_transport(const std::string& tag) {
    if (tag.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    bool changed = false;
    for (auto& record : records)
        changed = detach_transport_tags(record, {tag}) || changed;
    if (changed) write(records);
    return changed;
}

nlohmann::json SubscriptionStore::rename(const std::string& id, const std::string& name) {
    check_name(name);
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto& record = require_record(records, id);
    record["name"] = name;
    record["name_is_custom"] = true;
    const auto result = public_subscription(record);
    write(records);
    return result;
}

nlohmann::json SubscriptionStore::set_refresh_interval(const std::string& id, std::int64_t interval) {
    if (!valid_subscription_refresh_interval(interval))
        throw std::invalid_argument("invalid subscription refresh interval");
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto& record = require_record(records, id);
    record["refresh_interval_seconds"] = interval;
    const auto result = public_subscription(record);
    write(records);
    return result;
}

std::optional<nlohmann::json> SubscriptionStore::due(std::int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto records = read();
    std::optional<json> selected;
    std::int64_t selected_due = std::numeric_limits<std::int64_t>::max();
    for (const auto& record : records) {
        const auto interval = refresh_interval(record);
        if (interval == 0) continue;
        const auto checked = record.value("checked_at", std::int64_t{0});
        const auto next = checked == 0 ? 0 : checked + interval;
        if (next <= now && next < selected_due) {
            selected = record;
            selected_due = next;
        }
    }
    return selected;
}

void SubscriptionStore::erase(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    records.erase(std::remove_if(records.begin(), records.end(), [&](const auto& record) {
        return record.value("id", "") == id;
    }), records.end());
    write(records);
}
} // namespace keen_pbr3
