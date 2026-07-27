#include "cache_manager.hpp"
#include "../config/list_parser.hpp"
#include "../lists/srs_decoder.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string_view>
#include <utility>

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
                                    std::optional<long> http_status_code = std::nullopt,
                                    bool retryable = false) {
    CacheDownloadResult result;
    result.status = CacheDownloadStatus::Failed;
    result.error_message = std::move(message);
    result.http_status_code = http_status_code;
    result.retryable = retryable;
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

bool is_srs_rule_set_url(const std::string& url) {
    const auto end = url.find_first_of("?#");
    std::string path = url.substr(0, end);
    std::transform(path.begin(), path.end(), path.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return path.size() >= 4 && path.compare(path.size() - 4, 4, ".srs") == 0;
}

std::size_t saturating_multiply(std::size_t value, std::size_t multiplier) {
    if (value > std::numeric_limits<std::size_t>::max() / multiplier) {
        return std::numeric_limits<std::size_t>::max();
    }
    return value * multiplier;
}

bool is_usable_converted_cache(const std::filesystem::path& path,
                               std::size_t max_file_size_bytes) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return false;
    }
    const auto file_size = std::filesystem::file_size(path, error);
    if (error || file_size > max_file_size_bytes) {
        return false;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }

    EntryCounter entries;
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() > 4096U) {
            return false;
        }
        const auto first = std::find_if_not(
            line.begin(), line.end(),
            [](unsigned char value) { return std::isspace(value) != 0; });
        const auto last = std::find_if_not(
            line.rbegin(), line.rend(),
            [](unsigned char value) { return std::isspace(value) != 0; })
                              .base();
        if (first == line.end() || first >= last || *first == '#') {
            continue;
        }
        const std::string_view value(
            &*first, static_cast<std::size_t>(last - first));
        if (!ListParser::classify_entry(value, entries)) {
            return false;
        }
    }
    return input.eof();
}

SrsDecodeLimits srs_decode_limits(std::size_t max_file_size_bytes) {
    constexpr std::size_t kRouterTrieNodeCap = 1000000U;
    SrsDecodeLimits limits;
    limits.max_compressed_bytes =
        std::max<std::size_t>(1U, std::min(limits.max_compressed_bytes,
                                           max_file_size_bytes));
    limits.max_decompressed_bytes =
        std::max<std::size_t>(
            1U,
            std::min(limits.max_decompressed_bytes,
                     saturating_multiply(max_file_size_bytes, 4U)));
    limits.max_total_string_bytes =
        std::min(limits.max_total_string_bytes, limits.max_decompressed_bytes);
    limits.max_trie_labels =
        std::min({limits.max_trie_labels,
                  limits.max_decompressed_bytes,
                  kRouterTrieNodeCap - 1U});
    limits.max_trie_nodes =
        std::min({limits.max_trie_nodes,
                  limits.max_trie_labels + 1U,
                  kRouterTrieNodeCap});
    limits.max_output_string_bytes =
        std::min(limits.max_output_string_bytes, max_file_size_bytes);
    limits.max_output_entries =
        std::min(limits.max_output_entries,
                 std::max<std::size_t>(1U, max_file_size_bytes / 32U));
    return limits;
}

std::optional<std::string> decode_srs_native(
    const std::filesystem::path& input,
    const std::filesystem::path& text_output,
    std::size_t max_output_bytes,
    std::string& warning_message) {
    try {
        auto decoded = decode_srs_file(input, srs_decode_limits(max_output_bytes));

        std::ofstream target(text_output, std::ios::binary);
        if (!target) {
            return "failed to create converted SRS cache file";
        }

        std::size_t output_bytes = 0;
        std::size_t output_entries = 0;
        std::size_t exact_domains_mapped = 0;
        std::size_t invalid_domains_skipped = 0;
        const auto write_entry = [&](std::string_view prefix,
                                     std::string_view value)
            -> std::optional<std::string> {
            const std::size_t line_bytes = prefix.size() + value.size() + 1U;
            if (line_bytes > max_output_bytes - output_bytes) {
                return "converted SRS list exceeds configured file size limit";
            }
            target << prefix << value << '\n';
            if (!target) {
                return "failed to write converted SRS cache file";
            }
            output_bytes += line_bytes;
            ++output_entries;
            return std::nullopt;
        };

        for (const auto& domain : decoded.domains) {
            if (domain.rfind("*.", 0) == 0 || (!domain.empty() && domain.front() == '.')) {
                ++invalid_domains_skipped;
                continue;
            }
            const auto normalized = ListParser::normalize_domain(domain);
            if (!normalized.has_value()) {
                ++invalid_domains_skipped;
                continue;
            }
            if (const auto error = write_entry({}, *normalized); error.has_value()) {
                return error;
            }
            ++exact_domains_mapped;
        }
        for (const auto& suffix : decoded.domain_suffixes) {
            if (suffix.rfind("*.", 0) == 0 || (!suffix.empty() && suffix.front() == '.')) {
                ++invalid_domains_skipped;
                continue;
            }
            const auto normalized = ListParser::normalize_domain(suffix);
            if (!normalized.has_value()) {
                ++invalid_domains_skipped;
                continue;
            }
            if (const auto error = write_entry("*.", *normalized); error.has_value()) {
                return error;
            }
        }
        for (const auto& cidr : decoded.ip_cidrs) {
            if (const auto error = write_entry({}, cidr); error.has_value()) {
                return error;
            }
        }

        if (output_entries == 0U &&
            (decoded.skipped_rules != 0U ||
             decoded.unsupported_fields != 0U ||
             invalid_domains_skipped != 0U)) {
            return "SRS contains no safely representable domain, domain suffix or IP/CIDR entries";
        }

        std::vector<std::string> warning_parts;
        if (exact_domains_mapped != 0U) {
            warning_parts.push_back(
                "mapped " + std::to_string(exact_domains_mapped) +
                " exact domain(s) to keen-pbr root-and-subdomain semantics");
        }
        if (decoded.unsupported_fields != 0U) {
            warning_parts.push_back(
                "skipped " + std::to_string(decoded.unsupported_fields) +
                " unsupported condition(s)");
        }
        if (decoded.skipped_rules != 0U) {
            auto part =
                "skipped " + std::to_string(decoded.skipped_rules) + " rule(s)";
            if (decoded.inverted_rules != 0U) {
                part += ", including " + std::to_string(decoded.inverted_rules) +
                        " inverted rule(s)";
            }
            warning_parts.push_back(std::move(part));
        }
        if (invalid_domains_skipped != 0U) {
            warning_parts.push_back(
                "skipped " + std::to_string(invalid_domains_skipped) +
                " invalid domain value(s)");
        }
        if (!warning_parts.empty()) {
            std::ostringstream warning;
            warning << "SRS import is lossy: ";
            for (std::size_t index = 0; index < warning_parts.size(); ++index) {
                if (index != 0U) {
                    warning << "; ";
                }
                warning << warning_parts[index];
            }
            warning_message = warning.str();
        }
        return std::nullopt;
    } catch (const SrsDecodeError& error) {
        if (error.kind() == SrsDecodeErrorKind::UnsupportedVersion) {
            return std::string(error.what()) +
                   "; update keen-pbr-sb to add support before importing this file";
        }
        return error.what();
    } catch (const std::exception& error) {
        return std::string("failed to decode SRS: ") + error.what();
    }
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

void CacheManager::record_refresh_failure(
    const std::string& name,
    const std::string& url,
    const std::string& error_message,
    const std::optional<std::string>& detour) {
    CacheMetadata metadata = load_metadata(name);
    metadata.last_refresh_attempt = current_time_iso();
    metadata.last_refresh_error = error_message;
    metadata.last_refresh_url = url;
    metadata.last_refresh_detour = detour;
    save_metadata(name, metadata);
}

CacheDownloadResult CacheManager::download(const std::string& name,
                                           const std::string& url,
                                           const CacheDownloadOptions& options) {
    const bool srs = is_srs_rule_set_url(url);
    CacheMetadata existing = load_metadata(name);
    const bool same_source =
        existing.url.has_value() && *existing.url == url;
    const bool current_srs_revision =
        !srs ||
        (existing.srs_decoder_revision.has_value() &&
         *existing.srs_decoder_revision == kSrsDecoderRevision);
    std::error_code cache_error;
    const bool cached_body_exists =
        std::filesystem::is_regular_file(cache_path(name), cache_error);
    const bool use_conditionals =
        same_source && current_srs_revision && cached_body_exists;
    const auto failed_attempt =
        [this, &name, &url, &options](
            std::string message,
            std::optional<long> http_status_code = std::nullopt,
            bool retryable = false) {
            auto result =
                download_failed(
                    std::move(message), http_status_code, retryable);
            try {
                record_refresh_failure(
                    name, url, result.error_message, options.detour);
            } catch (...) {
                // Refresh status is diagnostic metadata. Never replace the
                // original download error or make a usable cache unavailable
                // merely because that status could not be persisted.
            }
            return result;
        };

    ConditionalDownloadResult result;
    try {
        result = http_client_.download_conditional(
            url,
            use_conditionals ? existing.etag.value_or("") : "",
            use_conditionals ? existing.last_modified.value_or("") : "",
            HttpRequestOptions{options.fwmark});
    } catch (const HttpError& e) {
        if (e.status_code() > 0) {
            return failed_attempt(
                "HTTP " + std::to_string(e.status_code()),
                e.status_code(),
                true);
        }
        return failed_attempt(
            clean_download_error_message(e), std::nullopt, true);
    } catch (const std::exception& e) {
        return failed_attempt(e.what(), std::nullopt, true);
    }

    if (result.not_modified && !use_conditionals) {
        return failed_attempt(
            "HTTP 304 received without a matching local cache validator",
            304);
    }
    if (result.not_modified) {
        const std::string successful_at = current_time_iso();
        existing.download_time = successful_at;
        existing.last_refresh_attempt = successful_at;
        existing.last_refresh_error.reset();
        existing.last_refresh_url = url;
        existing.last_refresh_detour = options.detour;
        try {
            save_metadata(name, existing);
        } catch (const std::exception& error) {
            return failed_attempt(
                std::string("failed to persist cache metadata: ") +
                error.what());
        }

        CacheDownloadResult not_modified;
        not_modified.status = CacheDownloadStatus::NotModified;
        return not_modified;
    }

    std::filesystem::path final_path = cache_path(name);
    std::filesystem::path final_meta = meta_path(name);
    std::filesystem::path tmp_path = cache_dir_ / (name + ".txt.tmp");
    std::filesystem::path tmp_meta = cache_dir_ / (name + ".meta.json.tmp");
    std::filesystem::path tmp_srs = cache_dir_ / (name + ".srs.tmp");
    std::string conversion_warning;

    {
        std::ofstream ofs(srs ? tmp_srs : tmp_path, std::ios::binary);
        if (!ofs) {
            return failed_attempt(
                "failed to open temporary cache file for writing");
        }
        ofs << result.body;
        if (!ofs) {
            std::filesystem::remove(tmp_path);
            std::filesystem::remove(tmp_srs);
            return failed_attempt(
                "failed to write temporary cache file");
        }
    }

    if (srs) {
        std::string{}.swap(result.body);
        auto conversion_error =
            decode_srs_native(tmp_srs,
                              tmp_path,
                              max_file_size_bytes_,
                              conversion_warning);
        std::filesystem::remove(tmp_srs);
        if (conversion_error.has_value()) {
            std::filesystem::remove(tmp_path);
            return failed_attempt(*conversion_error);
        }
    }

    const std::string successful_at = current_time_iso();
    CacheMetadata meta;
    meta.etag = result.etag;
    meta.last_modified = result.last_modified;
    meta.url = url;
    meta.download_time = successful_at;
    meta.last_refresh_attempt = successful_at;
    meta.last_refresh_url = url;
    meta.last_refresh_detour = options.detour;
    if (srs) {
        meta.srs_decoder_revision = kSrsDecoderRevision;
    }

    {
        std::ofstream ofs(tmp_meta);
        if (!ofs) {
            std::filesystem::remove(tmp_path);
            std::filesystem::remove(tmp_srs);
            return failed_attempt(
                "failed to open temporary cache metadata for writing");
        }
        ofs << nlohmann::json(meta).dump(2) << '\n';
        if (!ofs) {
            std::filesystem::remove(tmp_path);
            std::filesystem::remove(tmp_meta);
            return failed_attempt(
                "failed to write temporary cache metadata");
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
        return failed_attempt(e.what());
    }

    CacheDownloadResult updated;
    updated.status = CacheDownloadStatus::Updated;
    if (srs) {
        updated.warning_message = std::move(conversion_warning);
    }
    return updated;
}

bool CacheManager::has_cache(const std::string& name) const {
    return std::filesystem::exists(cache_path(name));
}

bool CacheManager::has_current_cache(const std::string& name,
                                     const std::string& url) const {
    if (!has_cache(name)) {
        return false;
    }

    const CacheMetadata metadata = load_metadata(name);
    if (!metadata.url.has_value() || *metadata.url != url) {
        return false;
    }

    return !is_srs_rule_set_url(url) ||
           (metadata.srs_decoder_revision.has_value() &&
            *metadata.srs_decoder_revision == kSrsDecoderRevision);
}

bool CacheManager::has_usable_same_source_cache(
    const std::string& name,
    const std::string& url) const {
    const CacheMetadata metadata = load_metadata(name);
    if (!metadata.url.has_value() || *metadata.url != url) {
        return false;
    }
    return is_usable_converted_cache(
        cache_path(name), max_file_size_bytes_);
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
