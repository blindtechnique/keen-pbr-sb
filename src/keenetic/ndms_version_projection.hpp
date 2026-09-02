#pragma once

#include "ndms_version_resource.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct NdmsRouterVersionFacts {
    std::string model;
    std::string vendor;
    std::string hw_id;
    std::string region;
    std::string arch;
    std::string title;
    std::string release;
    std::string sandbox;
    std::string firmware_date;
};

struct NdmsRouterVersionFactsSnapshot {
    std::optional<NdmsRouterVersionFacts> facts;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
    bool changed{false};
    std::optional<std::chrono::steady_clock::time_point> observed_at;
    std::uint64_t source_content_generation{0};
    std::uint64_t source_observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
};

struct NdmsFirmwareVersionSnapshot {
    // nullopt is an accepted current projection for an authoritative version
    // object which contains no human-readable title/release/version field.
    std::optional<std::string> version;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
    bool changed{false};
    std::optional<std::chrono::steady_clock::time_point> observed_at;
    std::uint64_t source_content_generation{0};
    std::uint64_t source_observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
};

class NdmsRouterVersionFactsCache {
public:
    using Clock = NdmsVersionResource::Clock;
    using FetchFn = NdmsVersionResource::FetchFn;
    using NowFn = NdmsVersionResource::NowFn;

    explicit NdmsRouterVersionFactsCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(30),
        NowFn now_fn = {});
    explicit NdmsRouterVersionFactsCache(NdmsVersionResource& resource);

    NdmsRouterVersionFactsSnapshot get();
    NdmsRouterVersionFactsSnapshot force_refresh();
    NdmsRouterVersionFactsSnapshot peek() const;
    void invalidate();

private:
    NdmsRouterVersionFactsSnapshot project(const NdmsVersionSnapshot& raw) const;
    NdmsRouterVersionFactsSnapshot snapshot_locked(
        const NdmsVersionSnapshot& raw, bool refreshed = false,
        bool changed = false) const;

    std::unique_ptr<NdmsVersionResource> owned_resource_;
    NdmsVersionResource* resource_{nullptr};
    mutable std::mutex mutex_;
    mutable std::optional<NdmsRouterVersionFacts> facts_;
    mutable std::optional<Clock::time_point> source_observed_at_;
    mutable std::uint64_t source_content_generation_{0};
    mutable std::uint64_t source_observation_generation_{0};
    mutable std::uint64_t source_observation_epoch_{0};
    mutable std::uint64_t attempted_content_generation_{0};
};

class NdmsFirmwareVersionCache {
public:
    using Clock = NdmsVersionResource::Clock;
    using FetchFn = NdmsVersionResource::FetchFn;
    using NowFn = NdmsVersionResource::NowFn;

    explicit NdmsFirmwareVersionCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(30),
        NowFn now_fn = {});
    explicit NdmsFirmwareVersionCache(NdmsVersionResource& resource);

    NdmsFirmwareVersionSnapshot get();
    NdmsFirmwareVersionSnapshot force_refresh();
    NdmsFirmwareVersionSnapshot peek() const;
    void invalidate();

private:
    NdmsFirmwareVersionSnapshot project(const NdmsVersionSnapshot& raw) const;
    NdmsFirmwareVersionSnapshot snapshot_locked(
        const NdmsVersionSnapshot& raw, bool refreshed = false,
        bool changed = false) const;

    std::unique_ptr<NdmsVersionResource> owned_resource_;
    NdmsVersionResource* resource_{nullptr};
    mutable std::mutex mutex_;
    mutable bool has_projection_{false};
    mutable std::optional<std::string> version_;
    mutable std::optional<Clock::time_point> source_observed_at_;
    mutable std::uint64_t source_content_generation_{0};
    mutable std::uint64_t source_observation_generation_{0};
    mutable std::uint64_t source_observation_epoch_{0};
    mutable std::uint64_t attempted_content_generation_{0};
};

NdmsRouterVersionFactsCache& shared_ndms_router_version_facts_cache();
NdmsFirmwareVersionCache& shared_ndms_firmware_version_cache();

} // namespace keen_pbr3
