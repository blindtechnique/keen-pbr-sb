#include "subscription_store.hpp"
#include "config_writer.hpp"
#include "../crypto/sha256.hpp"
#include "../util/display_name.hpp"

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
constexpr std::size_t kMaximumStoreBytes = 512U * 1024U;
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
void merge_metadata(json& record, const json& metadata) {
    // An unsuccessful refresh keeps the last successful limits and counters.
    // A successful response without the header clears old limits: unknown is
    // not unlimited, nor should the old provider limits look freshly verified.
    if (!metadata.contains("error")) {
        for (const char* key : {"upload_bytes", "download_bytes", "total_bytes",
                                "expires_at", "node_count", "updated_at", "error"})
            record.erase(key);
    }
    for (auto it = metadata.begin(); it != metadata.end(); ++it)
        record[it.key()] = it.value();
}
} // namespace

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
    return record;
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
    const std::vector<std::string>& tags) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto it = std::find_if(records.begin(), records.end(), [&](const auto& record) {
        return record.value("url", "") == url;
    });
    if (it == records.end()) {
        records.push_back({{"id", "sub-" + Sha256::hex(url).substr(0, 24)}, {"url", url},
                           {"name", subscription_source_host(url)},
                           {"source_host", subscription_source_host(url)},
                           {"transport_tags", json::array()}});
        it = std::prev(records.end());
    }
    if (!name.empty()) { check_name(name); (*it)["name"] = name; }
    auto linked = (*it).value("transport_tags", std::vector<std::string>{});
    for (const auto& tag : tags)
        if (std::find(linked.begin(), linked.end(), tag) == linked.end()) linked.push_back(tag);
    (*it)["transport_tags"] = linked;
    merge_metadata(*it, metadata);
    const auto result = public_subscription(*it);
    write(records);
    return result;
}

nlohmann::json SubscriptionStore::refresh(const std::string& id, const nlohmann::json& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto& record = require_record(records, id);
    merge_metadata(record, metadata);
    const auto result = public_subscription(record);
    write(records);
    return result;
}

nlohmann::json SubscriptionStore::rename(const std::string& id, const std::string& name) {
    check_name(name);
    std::lock_guard<std::mutex> lock(mutex_);
    auto records = read();
    auto& record = require_record(records, id);
    record["name"] = name;
    const auto result = public_subscription(record);
    write(records);
    return result;
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
