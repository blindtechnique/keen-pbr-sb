#include "ndms_vpn_server_service_cache.hpp"

#include "../http/http_client.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr const char* kRciRunningConfig =
    "http://127.0.0.1:79/rci/show/running-config";
constexpr auto kCacheTtl = std::chrono::seconds(30);
constexpr auto kFailureRetry = std::chrono::seconds(5);

NdmsVpnServerServiceCatalog unavailable_catalog() {
    return {};
}

NdmsVpnServerServiceCatalog parse_catalog_response(
    const std::string& response_body) {
    const auto response = nlohmann::json::parse(response_body);
    if (!response.is_object() || response.empty() ||
        response.find("error") != response.end()) {
        throw std::runtime_error(
            "NDMS running-config response is unavailable");
    }
    auto catalog = parse_ndms_vpn_server_service_catalog(response);
    if (!catalog.firmware_available) {
        throw std::runtime_error(
            "NDMS VPN service inventory is unavailable");
    }
    return catalog;
}

} // namespace

NdmsVpnServerServiceCache::NdmsVpnServerServiceCache(
    FetchFn fetch_fn,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : fetch_fn_(std::move(fetch_fn)),
      now_fn_(std::move(now_fn)),
      cache_ttl_(cache_ttl),
      failure_retry_(failure_retry) {
    if (!fetch_fn_) {
        throw std::invalid_argument(
            "NDMS VPN service fetch function is required");
    }
    if (!now_fn_) {
        now_fn_ = [] {
            return Clock::now();
        };
    }
}

NdmsVpnServerServiceSnapshot
NdmsVpnServerServiceCache::snapshot_locked(bool refreshed) const {
    if (catalog_) {
        auto effective_status = status_;
        if (!refreshed &&
            effective_status == NdmsCatalogCacheStatus::fresh &&
            now_fn_() >= refresh_after_) {
            effective_status = NdmsCatalogCacheStatus::stale;
        }
        return {*catalog_, effective_status, refreshed};
    }
    return {
        unavailable_catalog(),
        NdmsCatalogCacheStatus::unavailable,
        refreshed,
    };
}

NdmsVpnServerServiceSnapshot NdmsVpnServerServiceCache::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_locked();
}

NdmsVpnServerServiceSnapshot NdmsVpnServerServiceCache::get() {
    return get_impl(false);
}

NdmsVpnServerServiceSnapshot
NdmsVpnServerServiceCache::force_refresh() {
    return get_impl(true);
}

void NdmsVpnServerServiceCache::invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++invalidation_epoch_;
    status_ = catalog_ ? NdmsCatalogCacheStatus::stale
                       : NdmsCatalogCacheStatus::unavailable;
    refresh_after_ = Clock::time_point{};
    forced_refresh_after_ = Clock::time_point{};
}

NdmsVpnServerServiceSnapshot
NdmsVpnServerServiceCache::get_impl(bool force_refresh) {
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
            if (force_refresh &&
                last_completed_refresh_epoch_ != invalidation_epoch_) {
                continue;
            }
            return snapshot_locked(last_refresh_accepted_);
        }

        refresh_in_progress_ = true;
        const auto fetch_invalidation_epoch = invalidation_epoch_;
        lock.unlock();

        std::optional<NdmsVpnServerServiceCatalog> fetched_catalog;
        try {
            fetched_catalog = parse_catalog_response(fetch_fn_());
        } catch (...) {
            // A failed or unsupported observation must not replace the last
            // strictly parsed inventory.
        }
        const auto completed_at = now_fn_();

        lock.lock();
        refresh_attempted_ = true;
        const bool refresh_epoch_is_current =
            fetch_invalidation_epoch == invalidation_epoch_;
        const bool refresh_accepted =
            fetched_catalog.has_value() && refresh_epoch_is_current;
        if (refresh_accepted) {
            catalog_ = std::move(*fetched_catalog);
            status_ = NdmsCatalogCacheStatus::fresh;
            refresh_after_ = completed_at + cache_ttl_;
        } else {
            status_ = catalog_ ? NdmsCatalogCacheStatus::stale
                               : NdmsCatalogCacheStatus::unavailable;
            refresh_after_ = refresh_epoch_is_current
                ? completed_at + failure_retry_
                : Clock::time_point{};
        }
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

NdmsVpnServerServiceCache& shared_ndms_vpn_server_service_cache() {
    static NdmsVpnServerServiceCache cache(
        [] {
            HttpClient client;
            client.set_timeout(std::chrono::seconds(3));
            client.set_max_response_size(2U * 1024U * 1024U);
            return client.download(kRciRunningConfig);
        },
        kCacheTtl,
        kFailureRetry);
    return cache;
}

} // namespace keen_pbr3
