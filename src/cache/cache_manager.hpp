#pragma once

#include "../api/generated/api_types.hpp"
#include "../config/config.hpp"
#include "../http/http_client.hpp"
#include "../lists/list_shrink_guard.hpp"

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
using CacheShrinkAcceptance =
    decltype(api::ListRefreshRequest{}.accept_shrink)::value_type;
using CacheShrinkRejection =
    decltype(CacheMetadata{}.last_refresh_shrink_rejection)::value_type;
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
    // Request-scoped controls. Force only bypasses HTTP validators; accepting
    // a shrink applies to the exact previously shown body pair, not later
    // scheduled downloads or a changed source response.
    bool force_refresh{false};
    ListShrinkPolicy shrink_policy;
    std::optional<CacheShrinkAcceptance> accept_shrink;
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
    std::optional<CacheShrinkRejection> shrink_rejection;

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
    // Captured with the body under the existing publication mutex, never
    // looked up again in live metadata when a pinned generation is streamed.
    const std::optional<std::string>& source_url() const noexcept {
        return source_url_;
    }
    const std::string& source_format() const noexcept { return source_format_; }
    const std::optional<std::int64_t>& source_decoder_revision() const noexcept {
        return source_decoder_revision_;
    }
    // Structured bodies are usable only for the captured explicit format and
    // current decoder revision. Legacy text/SRS source matching stays intact.
    bool matches_source(const std::string& url,
                        const std::string& source_format = "text") const;

private:
    CacheGenerationHandle(std::filesystem::path path,
                          api::CacheGeneration generation,
                          std::optional<std::string> source_url,
                          std::string source_format,
                          std::optional<std::int64_t> source_decoder_revision,
                          std::shared_ptr<const void> lease);

    std::filesystem::path path_;
    api::CacheGeneration generation_;
    std::optional<std::string> source_url_;
    std::string source_format_{"text"};
    std::optional<std::int64_t> source_decoder_revision_;
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
    // One stable digest of source identity and body digest per pinned list,
    // or empty when its body is missing. Equal fingerprints mean identical
    // bytes from the same URL, format and decoder: matching bytes from a
    // replacement source may now be usable where the old source was ignored.
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

    // Download a list using conditional requests for the same URL/format/
    // decoder. Explicit JSON/YAML is normalized before publication; failure
    // never overwrites the existing cache or publishes a decoded prefix.
    CacheDownloadResult download(const std::string& name,
                                 const std::string& url,
                                 const CacheDownloadOptions& options = {},
                                 const std::string& source_format = "text");

    // Persist a refresh failure detected before an HTTP request can be made
    // (for example, when every explicitly configured detour has no fwmark).
    // Existing cache contents and the last successful download timestamp are
    // preserved.
    void record_refresh_failure(
        const std::string& name,
        const std::string& url,
        const std::string& error_message,
        const std::optional<std::string>& detour = std::nullopt,
        const std::optional<CacheShrinkRejection>& shrink_rejection = std::nullopt);

    // Check if a cached file exists for the given list name.
    bool has_cache(const std::string& name) const;

    // Check the source format and current structured/SRS decoder revision as
    // well as the URL. Legacy metadata without a format remains plain text.
    bool has_current_cache(const std::string& name, const std::string& url,
                           const std::string& source_format = "text") const;

    // Check whether an older converted cache can be used safely when refreshing
    // the exact same source fails. This validates the bounded text body but
    // does not claim that it was produced by the current SRS decoder. Explicit
    // structured formats still require their current decoder revision.
    bool has_usable_same_source_cache(const std::string& name,
                                      const std::string& url,
                                      const std::string& source_format = "text") const;

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
