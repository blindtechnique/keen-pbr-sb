#pragma once

#include "ndms_catalog_cache.hpp"

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

// The full running-config document can contain credentials and tunnel keys.
// Keep its bytes behind one immutable handle and wipe the retained allocation
// when the last consumer releases a generation. The body must never be logged,
// serialized into diagnostics or exposed through the API.
class NdmsSensitiveRunningConfigDocument final {
public:
    explicit NdmsSensitiveRunningConfigDocument(std::string body);
    ~NdmsSensitiveRunningConfigDocument();

    NdmsSensitiveRunningConfigDocument(
        const NdmsSensitiveRunningConfigDocument&) = delete;
    NdmsSensitiveRunningConfigDocument& operator=(
        const NdmsSensitiveRunningConfigDocument&) = delete;
    NdmsSensitiveRunningConfigDocument(
        NdmsSensitiveRunningConfigDocument&&) = delete;
    NdmsSensitiveRunningConfigDocument& operator=(
        NdmsSensitiveRunningConfigDocument&&) = delete;

    std::string_view body() const noexcept;

private:
    std::string body_;
};

enum class NdmsRunningConfigFailure : std::uint8_t {
    none,
    transport_failed,
    response_too_large,
    malformed_response,
};

struct NdmsRunningConfigSnapshot {
    std::shared_ptr<const NdmsSensitiveRunningConfigDocument> document;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    // True only when this call completed and accepted an RCI observation.
    bool refreshed{false};
    // True only when accepted bytes differ from the retained generation.
    bool changed{false};
    std::optional<std::chrono::steady_clock::time_point> observed_at;
    // Content identity. A successful observation of identical bytes keeps the
    // same generation while advancing observation_generation/observed_at.
    std::uint64_t content_generation{0};
    // Advances for every accepted current-epoch RCI observation, including a
    // semantic no-op. This is distinct from both content identity and the
    // topology/invalidation epoch.
    std::uint64_t observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
    NdmsRunningConfigFailure failure{NdmsRunningConfigFailure::none};
};

// Sole process-local owner of GET /rci/show/running-config. Network I/O and
// validation run outside mutex_; peek() is strictly cache-only. Failed or
// superseded observations never replace the last known-good sensitive body.
class NdmsRunningConfigResource {
public:
    using Clock = std::chrono::steady_clock;
    using FetchFn = std::function<std::string()>;
    using NowFn = std::function<Clock::time_point()>;

    explicit NdmsRunningConfigResource(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    NdmsRunningConfigSnapshot get();
    NdmsRunningConfigSnapshot force_refresh();
    NdmsRunningConfigSnapshot peek() const;
    void invalidate();

private:
    NdmsRunningConfigSnapshot get_impl(bool force_refresh);
    NdmsRunningConfigSnapshot snapshot_locked(
        bool refreshed = false,
        bool changed = false) const;

    FetchFn fetch_fn_;
    NowFn now_fn_;
    Clock::duration cache_ttl_;
    Clock::duration failure_retry_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::shared_ptr<const NdmsSensitiveRunningConfigDocument> document_;
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
    NdmsRunningConfigFailure last_failure_{
        NdmsRunningConfigFailure::none};
};

NdmsRunningConfigResource& shared_ndms_running_config_resource();

} // namespace keen_pbr3
