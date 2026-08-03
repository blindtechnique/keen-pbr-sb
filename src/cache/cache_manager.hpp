#pragma once

#include "../api/generated/api_types.hpp"
#include "../config/config.hpp"
#include "../http/http_client.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

#ifdef KEEN_PBR3_TESTING
enum class AtomicFileWriteStage;
#endif

// Use generated CacheMetadata from the API schema
using CacheMetadata = api::CacheMetadata;
using CacheCommitCallback =
    std::function<void(const std::function<void()>&)>;

struct CacheDownloadOptions {
    uint32_t fwmark{0};
    std::optional<std::string> detour;
    HttpCancellationToken cancellation;
    CacheCommitCallback commit;
#ifdef KEEN_PBR3_TESTING
    // Deterministic cache-metadata fault seam. Production builds do not carry
    // this field; tests use it to exercise the rename/directory-fsync boundary.
    std::function<void(AtomicFileWriteStage)> metadata_fault_injector;
    // Observes the point immediately before failed refresh metadata is
    // persisted. Tests use it to assert that an uncommitted immutable body no
    // longer consumes the space needed by that metadata write.
    std::function<void()> before_failure_metadata_persist;
#endif
};

enum class CacheDownloadStatus {
    Updated,
    NotModified,
    Cancelled,
    Failed,
};

struct CacheDownloadResult {
    CacheDownloadStatus status{CacheDownloadStatus::Failed};
    std::string error_message;
    // Successful, non-actionable conversion detail which belongs in the journal
    // but is not a service incident (for example, a safely ignored SRS
    // condition while all representable destinations were retained).
    std::string diagnostic_message;
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

    bool cancelled() const {
        return status == CacheDownloadStatus::Cancelled;
    }
};

class CacheManager {
public:
    explicit CacheManager(const std::filesystem::path& cache_dir,
                          size_t max_file_size_bytes = kDefaultMaxFileSizeBytes,
                          std::shared_ptr<HttpTransport> transport =
                              default_http_transport());

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

    // Resolve the verified current generation named by metadata, falling back
    // to its verified previous generation and then to a legacy <name>.txt
    // cache only when generation pointers have not been introduced yet.
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
