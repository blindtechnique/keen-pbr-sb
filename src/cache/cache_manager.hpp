#pragma once

#include "../api/generated/api_types.hpp"
#include "../config/config.hpp"
#include "../http/http_client.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Use generated CacheMetadata from the API schema
using CacheMetadata = api::CacheMetadata;

struct CacheDownloadOptions {
    uint32_t fwmark{0};
    std::optional<std::string> detour;
};

enum class CacheDownloadStatus {
    Updated,
    NotModified,
    Failed,
};

struct CacheDownloadResult {
    CacheDownloadStatus status{CacheDownloadStatus::Failed};
    std::string error_message;
    std::string warning_message;
    std::optional<long> http_status_code;
    bool retryable{false};

    bool updated() const {
        return status == CacheDownloadStatus::Updated;
    }

    bool not_modified() const {
        return status == CacheDownloadStatus::NotModified;
    }

    bool failed() const {
        return status == CacheDownloadStatus::Failed;
    }
};

class CacheManager {
public:
    explicit CacheManager(const std::filesystem::path& cache_dir,
                          size_t max_file_size_bytes = kDefaultMaxFileSizeBytes);

    // Create cache directory if it doesn't exist.
    void ensure_dir();

    // Set maximum allowed size for downloaded remote content.
    void set_max_file_size(size_t bytes);

    size_t max_file_size() const noexcept { return max_file_size_bytes_; }

    // Download a list from URL using conditional requests (ETag/If-Modified-Since).
    // On failure, does not overwrite existing cache.
    CacheDownloadResult download(const std::string& name,
                                 const std::string& url,
                                 const CacheDownloadOptions& options = {});

    // Persist a refresh failure detected before an HTTP request can be made
    // (for example, when every explicitly configured detour has no fwmark).
    // Existing cache contents and the last successful download timestamp are
    // preserved.
    void record_refresh_failure(
        const std::string& name,
        const std::string& url,
        const std::string& error_message,
        const std::optional<std::string>& detour = std::nullopt);

    // Check if a cached file exists for the given list name.
    bool has_cache(const std::string& name) const;

    // Check that the cached body belongs to the current source and, for
    // compiled SRS lists, was produced by the current decoder revision.
    bool has_current_cache(const std::string& name, const std::string& url) const;

    // Check whether an older converted cache can be used safely when refreshing
    // the exact same source fails. This validates the bounded text body but
    // does not claim that it was produced by the current SRS decoder.
    bool has_usable_same_source_cache(const std::string& name,
                                      const std::string& url) const;

    // Path to the cached list file: <cache_dir>/<name>.txt
    std::filesystem::path cache_path(const std::string& name) const;

    // Path to the metadata file: <cache_dir>/<name>.meta.json
    std::filesystem::path meta_path(const std::string& name) const;

    // Load metadata from .meta.json file. Returns empty metadata if file doesn't exist.
    CacheMetadata load_metadata(const std::string& name) const;

    // Save metadata to .meta.json file.
    void save_metadata(const std::string& name, const CacheMetadata& meta);

private:
    std::filesystem::path cache_dir_;
    size_t max_file_size_bytes_;
    HttpClient http_client_;
};

} // namespace keen_pbr3
