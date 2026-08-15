#include "ndms_catalog_cache.hpp"

#include "../http/http_client.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciInterfaces =
    "http://127.0.0.1:79/rci/show/interface";
constexpr auto kCacheTtl = std::chrono::seconds(30);
constexpr auto kFailureRetry = std::chrono::seconds(5);

NdmsInterfaceCatalog unavailable_catalog() {
    return parse_ndms_interface_catalog(nlohmann::json{});
}

bool is_rci_error_object(const nlohmann::json& response) {
    if (response.find("error") != response.end()) return true;

    const auto status = response.find("status");
    if (status == response.end() || !status->is_string()) return false;
    auto value = status->get<std::string>();
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value == "error" || value == "failed";
}

NdmsInterfaceCatalog parse_catalog_response(const std::string& response_body) {
    const auto response = nlohmann::json::parse(response_body);
    if (!response.is_object()) {
        throw std::runtime_error("NDMS RCI response is not an object");
    }
    if (response.empty()) {
        throw std::runtime_error("NDMS RCI response is empty");
    }
    if (is_rci_error_object(response)) {
        throw std::runtime_error("NDMS RCI returned an error object");
    }

    auto catalog = parse_ndms_interface_catalog(response);
    if (!catalog.firmware_available) {
        throw std::runtime_error("NDMS RCI response is unavailable");
    }
    return catalog;
}

} // namespace

NdmsCatalogCache::NdmsCatalogCache(FetchFn fetch_fn,
                                   Clock::duration cache_ttl,
                                   Clock::duration failure_retry,
                                   NowFn now_fn)
    : fetch_fn_(std::move(fetch_fn)),
      now_fn_(std::move(now_fn)),
      cache_ttl_(cache_ttl),
      failure_retry_(failure_retry) {
    if (!fetch_fn_) {
        throw std::invalid_argument("NDMS catalog fetch function is required");
    }
    if (!now_fn_) {
        now_fn_ = [] {
            return Clock::now();
        };
    }
}

NdmsCatalogSnapshot NdmsCatalogCache::snapshot_locked(
    bool refreshed) const {
    if (catalog_) {
        auto effective_status = status_;
        if (!refreshed &&
            effective_status == NdmsCatalogCacheStatus::fresh &&
            now_fn_() >= refresh_after_) {
            effective_status = NdmsCatalogCacheStatus::stale;
        }
        return {
            *catalog_,
            effective_status,
            refreshed,
            catalog_observed_at_,
            accepted_observation_generation_,
            accepted_observation_epoch_,
            invalidation_epoch_,
        };
    }
    return {
        unavailable_catalog(),
        NdmsCatalogCacheStatus::unavailable,
        refreshed,
        std::nullopt,
        accepted_observation_generation_,
        accepted_observation_epoch_,
        invalidation_epoch_,
    };
}

NdmsCatalogSnapshot NdmsCatalogCache::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_locked();
}

NdmsCatalogSnapshot NdmsCatalogCache::get() {
    return get_impl(false);
}

NdmsCatalogSnapshot NdmsCatalogCache::force_refresh() {
    return get_impl(true);
}

void NdmsCatalogCache::invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++invalidation_epoch_;
    if (invalidation_epoch_ == 0U) {
        // Zero is the initial epoch. Do not make a wrapped process-local
        // counter indistinguishable from a never-invalidated cache.
        ++invalidation_epoch_;
    }
    if (catalog_) {
        status_ = NdmsCatalogCacheStatus::stale;
    } else {
        status_ = NdmsCatalogCacheStatus::unavailable;
    }
    refresh_after_ = Clock::time_point{};
    forced_refresh_after_ = Clock::time_point{};
}

NdmsCatalogSnapshot NdmsCatalogCache::get_impl(bool force_refresh) {
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
        const auto now = now_fn_();
        if (refresh_attempted_ &&
            ((!force_refresh && now < refresh_after_) ||
             (force_refresh && now < forced_refresh_after_))) {
            return snapshot_locked();
        }

        if (refresh_in_progress_) {
            const auto observed_generation = refresh_generation_;
            refresh_finished_.wait(
                lock,
                [this, observed_generation] {
                    return refresh_generation_ != observed_generation;
                });
            // An interface event can invalidate the cache while an older
            // request is in flight. A forced caller that arrived for that
            // event must not mistake the rejected pre-event generation for
            // its requested observation. Re-evaluate and become the next
            // single-flight fetcher. A same-epoch transport failure is still
            // returned normally and remains retry-throttled.
            if (force_refresh &&
                last_completed_refresh_epoch_ != invalidation_epoch_) {
                continue;
            }
            return snapshot_locked(last_refresh_accepted_);
        }

        refresh_in_progress_ = true;
        const auto fetch_invalidation_epoch = invalidation_epoch_;
        lock.unlock();

        std::optional<NdmsInterfaceCatalog> fetched_catalog;
        try {
            // Network I/O and parsing stay outside mutex_ so cache-only
            // readers do not serialize behind the loopback request.
            fetched_catalog = parse_catalog_response(fetch_fn_());
        } catch (...) {
            // Older firmware, transient RCI failures and malformed responses
            // all preserve the last successfully parsed catalog.
        }
        const auto completed_at = now_fn_();

        lock.lock();
        refresh_attempted_ = true;
        const bool refresh_epoch_is_current =
            fetch_invalidation_epoch == invalidation_epoch_;
        const bool refresh_accepted =
            fetched_catalog.has_value() &&
            refresh_epoch_is_current;
        if (refresh_accepted) {
            catalog_ = std::move(*fetched_catalog);
            // The instant this catalog was read, kept so a consumer can turn
            // the firmware's relative counters into durations. Same clock as
            // the TTL deadlines, read once so the two cannot disagree.
            catalog_observed_at_ = completed_at;
            ++accepted_observation_generation_;
            if (accepted_observation_generation_ == 0U) {
                // Reserve zero for "no accepted observation". Reaching this
                // branch would require 2^64 accepted RCI reads in one daemon
                // process, but keeping the sentinel invariant is free.
                ++accepted_observation_generation_;
            }
            accepted_observation_epoch_ = fetch_invalidation_epoch;
            status_ = NdmsCatalogCacheStatus::fresh;
            refresh_after_ = completed_at + cache_ttl_;
        } else {
            status_ = catalog_ ? NdmsCatalogCacheStatus::stale
                               : NdmsCatalogCacheStatus::unavailable;
            // A response or transport failure from an older topology epoch
            // cannot regain authority and must not throttle the replacement
            // observation requested by invalidate().
            refresh_after_ = refresh_epoch_is_current
                ? completed_at + failure_retry_
                : Clock::time_point{};
        }
        // A successful regular TTL refresh must not suppress the first
        // interface-event refresh: kernel renumbering can happen immediately
        // afterwards. Failed requests and explicit refreshes are both
        // throttled.
        if (!refresh_epoch_is_current) {
            forced_refresh_after_ = Clock::time_point{};
        } else if (force_refresh || !fetched_catalog) {
            forced_refresh_after_ = completed_at + failure_retry_;
        }
        refresh_in_progress_ = false;
        last_refresh_accepted_ = refresh_accepted;
        last_completed_refresh_epoch_ = fetch_invalidation_epoch;
        ++refresh_generation_;
        auto result = snapshot_locked(refresh_accepted);
        lock.unlock();
        refresh_finished_.notify_all();
        return result;
    }
}

NdmsCatalogCache& shared_ndms_catalog_cache() {
    static NdmsCatalogCache cache(
        [] {
            HttpClient client;
            client.set_timeout(std::chrono::seconds(3));
            client.set_max_response_size(2U * 1024U * 1024U);
            return client.download(kRciInterfaces);
        },
        kCacheTtl,
        kFailureRetry);
    return cache;
}

} // namespace keen_pbr3
