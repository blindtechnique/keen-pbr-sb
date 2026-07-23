#include "cache_manager.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

static std::string current_time_iso() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&time_t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

CacheDownloadResult download_failed(std::string message,
                                    std::optional<long> http_status_code = std::nullopt) {
    CacheDownloadResult result;
    result.status = CacheDownloadStatus::Failed;
    result.error_message = std::move(message);
    result.http_status_code = http_status_code;
    return result;
}

std::string clean_download_error_message(const std::exception& error) {
    constexpr std::string_view prefix = "HTTP request failed: ";
    std::string message = error.what();
    if (message.rfind(prefix, 0) == 0) {
        message.erase(0, prefix.size());
    }
    return message;
}

bool is_sing_box_rule_set_url(const std::string& url) {
    const auto end = url.find_first_of("?#");
    std::string path = url.substr(0, end);
    std::transform(path.begin(), path.end(), path.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return path.size() >= 4 && path.compare(path.size() - 4, 4, ".srs") == 0;
}

std::vector<std::string> sing_box_candidates() {
    std::vector<std::string> candidates;
    if (const char* configured = std::getenv("KEEN_PBR_SING_BOX"); configured && *configured) {
        candidates.emplace_back(configured);
    }
    try {
        std::ifstream config("/opt/etc/keen-pbr/transports.json");
        if (config) {
            auto parsed = nlohmann::json::parse(config);
            const auto binary = parsed.value("sing_box_binary", std::string{});
            if (!binary.empty()) candidates.push_back(binary);
        }
    } catch (const std::exception&) {
        // Fall through to standard paths when the optional companion config is absent or invalid.
    }
    candidates.emplace_back("/opt/bin/sing-box");
    candidates.emplace_back("/usr/bin/sing-box");
    candidates.emplace_back("sing-box");
    return candidates;
}

void collect_srs_entries(const nlohmann::json& rule,
                         std::set<std::string>& entries,
                         size_t& unsupported) {
    if (!rule.is_object()) return;
    if (rule.value("invert", false)) {
        ++unsupported;
        return;
    }
    const auto collect = [&](const char* field, const std::string& prefix = {}) {
        const auto it = rule.find(field);
        if (it == rule.end() || !it->is_array()) return;
        for (const auto& value : *it) {
            if (value.is_string() && !value.get_ref<const std::string&>().empty()) {
                entries.insert(prefix + value.get_ref<const std::string&>());
            }
        }
    };
    collect("domain");
    collect("domain_suffix", "*.");
    collect("ip_cidr");

    for (const char* field : {"domain_keyword", "domain_regex", "source_ip_cidr"}) {
        const auto it = rule.find(field);
        if (it != rule.end() && it->is_array() && !it->empty()) unsupported += it->size();
    }
    const auto nested = rule.find("rules");
    if (nested != rule.end() && nested->is_array()) {
        for (const auto& child : *nested) collect_srs_entries(child, entries, unsupported);
    }
}

std::optional<std::string> decompile_srs(const std::filesystem::path& input,
                                         const std::filesystem::path& json_output,
                                         const std::filesystem::path& text_output) {
    bool decompiled = false;
    for (const auto& binary : sing_box_candidates()) {
        if (binary.find('/') != std::string::npos && !std::filesystem::exists(binary)) continue;
        if (safe_exec({binary, "rule-set", "decompile", "--output", json_output.string(), input.string()},
                      /*suppress_output=*/true) == 0) {
            decompiled = true;
            break;
        }
    }
    if (!decompiled) {
        return "sing-box rule-set decompile failed; install sing-box 1.10+ or set KEEN_PBR_SING_BOX";
    }

    try {
        std::ifstream source(json_output);
        if (!source) return "sing-box did not create decompiled rule-set JSON";
        const auto document = nlohmann::json::parse(source);
        const auto rules = document.find("rules");
        if (rules == document.end() || !rules->is_array()) return "decompiled SRS has no rules array";

        std::set<std::string> entries;
        size_t unsupported = 0;
        for (const auto& rule : *rules) collect_srs_entries(rule, entries, unsupported);
        if (entries.empty()) {
            return unsupported > 0
                ? "SRS contains only unsupported keyword, regex, source or inverted rules"
                : "SRS contains no domain, domain_suffix or ip_cidr entries";
        }

        std::ofstream target(text_output);
        if (!target) return "failed to create converted SRS cache file";
        for (const auto& entry : entries) target << entry << '\n';
        if (!target) return "failed to write converted SRS cache file";
    } catch (const std::exception& error) {
        return std::string("failed to convert decompiled SRS: ") + error.what();
    }
    return std::nullopt;
}

} // namespace

CacheManager::CacheManager(const std::filesystem::path& cache_dir,
                           size_t max_file_size_bytes)
    : cache_dir_(cache_dir)
    , max_file_size_bytes_(max_file_size_bytes) {
    http_client_.set_max_response_size(max_file_size_bytes);
}

void CacheManager::ensure_dir() {
    std::filesystem::create_directories(cache_dir_);
}

void CacheManager::set_max_file_size(size_t bytes) {
    max_file_size_bytes_ = bytes;
    http_client_.set_max_response_size(bytes);
}

CacheDownloadResult CacheManager::download(const std::string& name,
                                           const std::string& url,
                                           const CacheDownloadOptions& options) {
    CacheMetadata existing = load_metadata(name);

    ConditionalDownloadResult result;
    try {
        result = http_client_.download_conditional(
            url,
            existing.etag.value_or(""),
            existing.last_modified.value_or(""),
            HttpRequestOptions{options.fwmark});
    } catch (const HttpError& e) {
        if (e.status_code() > 0) {
            return download_failed("HTTP " + std::to_string(e.status_code()), e.status_code());
        }
        return download_failed(clean_download_error_message(e));
    } catch (const std::exception& e) {
        return download_failed(e.what());
    }

    if (result.not_modified) {
        CacheDownloadResult not_modified;
        not_modified.status = CacheDownloadStatus::NotModified;
        return not_modified;
    }

    std::filesystem::path final_path = cache_path(name);
    std::filesystem::path final_meta = meta_path(name);
    std::filesystem::path tmp_path = cache_dir_ / (name + ".txt.tmp");
    std::filesystem::path tmp_meta = cache_dir_ / (name + ".meta.json.tmp");
    std::filesystem::path tmp_srs = cache_dir_ / (name + ".srs.tmp");
    std::filesystem::path tmp_srs_json = cache_dir_ / (name + ".srs.json.tmp");
    const bool srs = is_sing_box_rule_set_url(url);

    {
        std::ofstream ofs(srs ? tmp_srs : tmp_path, std::ios::binary);
        if (!ofs) return download_failed("failed to open temporary cache file for writing");
        ofs << result.body;
        if (!ofs) {
            std::filesystem::remove(tmp_path);
            std::filesystem::remove(tmp_srs);
            return download_failed("failed to write temporary cache file");
        }
    }

    if (srs) {
        const auto conversion_error = decompile_srs(tmp_srs, tmp_srs_json, tmp_path);
        std::filesystem::remove(tmp_srs);
        std::filesystem::remove(tmp_srs_json);
        if (conversion_error.has_value()) {
            std::filesystem::remove(tmp_path);
            return download_failed(*conversion_error);
        }
    }

    CacheMetadata meta;
    meta.etag = result.etag;
    meta.last_modified = result.last_modified;
    meta.url = url;
    meta.download_time = current_time_iso();

    {
        std::ofstream ofs(tmp_meta);
        if (!ofs) {
            std::filesystem::remove(tmp_path);
            std::filesystem::remove(tmp_srs);
            std::filesystem::remove(tmp_srs_json);
            return download_failed("failed to open temporary cache metadata for writing");
        }
        ofs << nlohmann::json(meta).dump(2) << '\n';
        if (!ofs) {
            std::filesystem::remove(tmp_path);
            std::filesystem::remove(tmp_meta);
            return download_failed("failed to write temporary cache metadata");
        }
    }

    // Rename body first: on crash here, old meta triggers a re-download (safe).
    // Rename meta second: once both succeed the cache is fully consistent.
    try {
        std::filesystem::rename(tmp_path, final_path);
        std::filesystem::rename(tmp_meta, final_meta);
    } catch (const std::exception& e) {
        std::filesystem::remove(tmp_path);
        std::filesystem::remove(tmp_meta);
        return download_failed(e.what());
    }

    CacheDownloadResult updated;
    updated.status = CacheDownloadStatus::Updated;
    return updated;
}

bool CacheManager::has_cache(const std::string& name) const {
    return std::filesystem::exists(cache_path(name));
}

std::filesystem::path CacheManager::cache_path(const std::string& name) const {
    return cache_dir_ / (name + ".txt");
}

std::filesystem::path CacheManager::meta_path(const std::string& name) const {
    return cache_dir_ / (name + ".meta.json");
}

CacheMetadata CacheManager::load_metadata(const std::string& name) const {
    std::ifstream ifs(meta_path(name));
    if (!ifs.is_open()) return {};
    try {
        return nlohmann::json::parse(ifs).get<CacheMetadata>();
    } catch (const nlohmann::json::exception&) {
        return {};
    }
}

void CacheManager::save_metadata(const std::string& name, const CacheMetadata& meta) {
    const std::filesystem::path final_meta = meta_path(name);
    const std::filesystem::path tmp_meta = cache_dir_ / (name + ".meta.json.tmp");

    {
        std::ofstream ofs(tmp_meta);
        if (!ofs) {
            return;
        }
        ofs << nlohmann::json(meta).dump(2) << '\n';
        if (!ofs) {
            std::filesystem::remove(tmp_meta);
            return;
        }
    }

    std::filesystem::rename(tmp_meta, final_meta);
}

} // namespace keen_pbr3
