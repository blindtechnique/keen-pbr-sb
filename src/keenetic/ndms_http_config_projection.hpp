#pragma once

#include "ndms_http_config_resource.hpp"
#include "ndms_http_service_config.hpp"
#include "ndms_lockout_policy.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

namespace keen_pbr3 {

struct NdmsHttpServiceConfigSnapshot {
    std::optional<NdmsHttpServiceConfig> config;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
    bool changed{false};
    std::optional<std::chrono::steady_clock::time_point> observed_at;
    std::uint64_t source_content_generation{0};
    std::uint64_t source_observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
};

struct NdmsLockoutPolicySnapshot {
    // nullopt can be an accepted current typed result: the firmware document
    // may legitimately contain no usable policy. source_content_generation
    // distinguishes that from a projection which has never been accepted.
    std::optional<NdmsLockoutPolicy> policy;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
    bool changed{false};
    std::optional<std::chrono::steady_clock::time_point> observed_at;
    std::uint64_t source_content_generation{0};
    std::uint64_t source_observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
};

// Independent typed projections over one shared raw document. A malformed
// service port does not hide a current lockout policy, and an absent policy
// does not make a valid management port unavailable.
class NdmsHttpServiceConfigCache {
public:
    using Clock = NdmsHttpConfigResource::Clock;
    using FetchFn = NdmsHttpConfigResource::FetchFn;
    using NowFn = NdmsHttpConfigResource::NowFn;

    explicit NdmsHttpServiceConfigCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});
    explicit NdmsHttpServiceConfigCache(NdmsHttpConfigResource& resource);

    NdmsHttpServiceConfigSnapshot get();
    NdmsHttpServiceConfigSnapshot force_refresh();
    NdmsHttpServiceConfigSnapshot peek() const;
    void invalidate();

private:
    NdmsHttpServiceConfigSnapshot project(
        const NdmsHttpConfigSnapshot& raw) const;
    NdmsHttpServiceConfigSnapshot snapshot_locked(
        const NdmsHttpConfigSnapshot& raw,
        bool refreshed = false,
        bool changed = false) const;

    std::unique_ptr<NdmsHttpConfigResource> owned_resource_;
    NdmsHttpConfigResource* resource_{nullptr};
    mutable std::mutex mutex_;
    mutable std::optional<NdmsHttpServiceConfig> config_;
    mutable std::optional<Clock::time_point> source_observed_at_;
    mutable std::uint64_t source_content_generation_{0};
    mutable std::uint64_t source_observation_generation_{0};
    mutable std::uint64_t source_observation_epoch_{0};
    mutable std::uint64_t attempted_content_generation_{0};
};

class NdmsLockoutPolicyCache {
public:
    using Clock = NdmsHttpConfigResource::Clock;
    using FetchFn = NdmsHttpConfigResource::FetchFn;
    using NowFn = NdmsHttpConfigResource::NowFn;

    explicit NdmsLockoutPolicyCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});
    explicit NdmsLockoutPolicyCache(NdmsHttpConfigResource& resource);

    NdmsLockoutPolicySnapshot get();
    NdmsLockoutPolicySnapshot force_refresh();
    NdmsLockoutPolicySnapshot peek() const;
    void invalidate();

private:
    NdmsLockoutPolicySnapshot project(
        const NdmsHttpConfigSnapshot& raw) const;
    NdmsLockoutPolicySnapshot snapshot_locked(
        const NdmsHttpConfigSnapshot& raw,
        bool refreshed = false,
        bool changed = false) const;

    std::unique_ptr<NdmsHttpConfigResource> owned_resource_;
    NdmsHttpConfigResource* resource_{nullptr};
    mutable std::mutex mutex_;
    mutable bool has_projection_{false};
    mutable std::optional<NdmsLockoutPolicy> policy_;
    mutable std::optional<Clock::time_point> source_observed_at_;
    mutable std::uint64_t source_content_generation_{0};
    mutable std::uint64_t source_observation_generation_{0};
    mutable std::uint64_t source_observation_epoch_{0};
    mutable std::uint64_t attempted_content_generation_{0};
};

NdmsHttpServiceConfigCache& shared_ndms_http_service_config_cache();
NdmsLockoutPolicyCache& shared_ndms_lockout_policy_cache();

} // namespace keen_pbr3
