#pragma once

#include "../api/generated/api_types.hpp"
#include "../config/config.hpp"
#include "../http/http_client.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

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

// An immutable, verified cache body together with an opaque lease that keeps
// the named generation alive against GC by the CacheManager which captured it.
// The handle is cheap to copy: bodies are never copied and copies share one
// lease.
class CacheGenerationHandle {
public:
    CacheGenerationHandle() = default;

    const std::filesystem::path& path() const noexcept { return path_; }
    const api::CacheGeneration& generation() const noexcept {
        return generation_;
    }

private:
    CacheGenerationHandle(std::filesystem::path path,
                          api::CacheGeneration generation,
                          std::shared_ptr<const void> lease);

    std::filesystem::path path_;
    api::CacheGeneration generation_;
    std::shared_ptr<const void> lease_;

    friend class CacheManager;
};

// A point-in-time view of the URL-cache generations for a set of configured
// lists. Missing bodies are recorded explicitly, so a cache created after the
// snapshot cannot appear halfway through the same resolver transaction.
class ListCacheGenerationSnapshot {
public:
    bool contains(const std::string& name) const;
    const CacheGenerationHandle* find(const std::string& name) const;
    // One stable string per pinned list: its generation digest, or empty for
    // a list the snapshot knows but has no cached body for. Two snapshots
    // with equal fingerprints pin identical bytes for every list, which is
    // what a set-reusing firewall refresh needs to know without reading any.
    std::map<std::string, std::string> fingerprints() const;

private:
    std::map<std::string, std::optional<CacheGenerationHandle>> entries_;

    friend class CacheManager;
};

struct CacheGenerationPinState;

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

    // Capture verified immutable bodies for the supplied list names and pin
    // them until the returned snapshot and all of its copies are released.
    // The lease coordinates only with this CacheManager instance. The daemon
    // must capture through the single-writer ListService CacheManager rather
    // than create another manager for the same directory. The immutable
    // snapshot can then cross asynchronous resolver phases without carrying a
    // daemon lock between threads.
    std::shared_ptr<const ListCacheGenerationSnapshot> capture_generation(
        const std::vector<std::string>& names) const;

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
    std::shared_ptr<CacheGenerationPinState> generation_pin_state_;
};

} // namespace keen_pbr3
