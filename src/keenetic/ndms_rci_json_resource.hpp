#pragma once

#include "ndms_cache_status.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// Full RCI documents can contain credentials and tunnel keys. Keep their
// bytes behind one immutable handle and wipe the retained allocation when the
// last consumer releases a generation. Raw documents must never be logged,
// serialized into diagnostics or exposed through the API.
class NdmsSensitiveJsonDocument final {
public:
    explicit NdmsSensitiveJsonDocument(std::string body);
    ~NdmsSensitiveJsonDocument();

    NdmsSensitiveJsonDocument(const NdmsSensitiveJsonDocument&) = delete;
    NdmsSensitiveJsonDocument& operator=(
        const NdmsSensitiveJsonDocument&) = delete;
    NdmsSensitiveJsonDocument(NdmsSensitiveJsonDocument&&) = delete;
    NdmsSensitiveJsonDocument& operator=(
        NdmsSensitiveJsonDocument&&) = delete;

    std::string_view body() const noexcept;

private:
    std::string body_;
};

enum class NdmsRciJsonFailure : std::uint8_t {
    none,
    transport_failed,
    response_too_large,
    malformed_response,
};

enum class NdmsRciJsonShape : std::uint8_t {
    object,
    running_config,
};

struct NdmsRciJsonSnapshot {
    std::shared_ptr<const NdmsSensitiveJsonDocument> document;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
    bool changed{false};
    std::optional<std::chrono::steady_clock::time_point> observed_at;
    std::uint64_t content_generation{0};
    std::uint64_t observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
    NdmsRciJsonFailure failure{NdmsRciJsonFailure::none};
};

// Shared state machine for passive, process-local RCI resources. Network I/O
// and validation run outside mutex_; peek() is strictly cache-only. Failed or
// superseded observations never replace the exact last-known-good document.
class NdmsRciJsonResource {
public:
    using Clock = std::chrono::steady_clock;
    using FetchFn = std::function<std::string()>;
    using NowFn = std::function<Clock::time_point()>;

    explicit NdmsRciJsonResource(
        FetchFn fetch_fn,
        NdmsRciJsonShape shape,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    NdmsRciJsonSnapshot get();
    NdmsRciJsonSnapshot force_refresh();
    NdmsRciJsonSnapshot peek() const;
    void invalidate();

private:
    NdmsRciJsonSnapshot get_impl(bool force_refresh);
    NdmsRciJsonSnapshot snapshot_locked(
        bool refreshed = false,
        bool changed = false) const;

    FetchFn fetch_fn_;
    NowFn now_fn_;
    NdmsRciJsonShape shape_;
    Clock::duration cache_ttl_;
    Clock::duration failure_retry_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::shared_ptr<const NdmsSensitiveJsonDocument> document_;
    std::string content_digest_;
    NdmsCatalogCacheStatus status_{NdmsCatalogCacheStatus::unavailable};
    Clock::time_point refresh_after_{};
    Clock::time_point forced_refresh_after_{};
    std::optional<Clock::time_point> observed_at_;
    bool refresh_attempted_{false};
    bool refresh_in_progress_{false};
    bool last_refresh_accepted_{false};
    bool last_refresh_changed_{false};
    std::uint64_t refresh_generation_{0};
    std::uint64_t content_generation_{0};
    std::uint64_t observation_generation_{0};
    std::uint64_t invalidation_epoch_{0};
    std::uint64_t observation_epoch_{0};
    std::uint64_t last_completed_refresh_epoch_{0};
    NdmsRciJsonFailure last_failure_{NdmsRciJsonFailure::none};
};

} // namespace keen_pbr3
