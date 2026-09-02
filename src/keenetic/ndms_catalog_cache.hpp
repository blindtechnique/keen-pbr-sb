#pragma once

#include "ndms_interface_inventory.hpp"
#include "ndms_interface_resource.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct NdmsCatalogSnapshot {
    NdmsInterfaceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    // True only when this call observed a completed refresh generation
    // instead of receiving a TTL/throttle cache hit or peek. Authority is
    // represented by status=fresh: a recently verified cache hit remains
    // authoritative even though this particular call did not perform I/O.
    bool refreshed{false};
    // Steady instant this catalog was actually read from the firmware.
    //
    // Every live counter it carries is a "for the last N seconds" duration, so
    // it is only convertible into an instant together with this stamp - and a
    // snapshot served from cache can be a whole TTL older than the moment a
    // caller consumes it. Steady rather than wall on purpose: it is used to
    // derive durations, and this router has no battery-backed RTC, so the wall
    // clock steps once NTP catches up.
    std::optional<std::chrono::steady_clock::time_point> observed_at;

    // Monotonic process-local identity of the last catalog accepted from
    // firmware. It advances only when a parsed response belongs to the
    // current invalidation epoch. Cache hits, failed refreshes and rejected
    // pre-invalidation completions retain the previous value. Zero means no
    // catalog has ever been accepted by this cache instance.
    std::uint64_t observation_generation{0};

    // Topology epoch in which the retained catalog was accepted, and the
    // cache's current topology epoch respectively. After invalidate(), a
    // retained last-known-good catalog intentionally has
    // observation_epoch < invalidation_epoch until a replacement observation
    // is accepted. These are safe process-local counters, not firmware
    // revisions and not mutation authorization.
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
};

// Typed, non-secret projection of the shared passive show/interface resource.
// The daemon and API consume this projection; native VPN mutation evidence
// deliberately keeps its separate exact operation-local observation path.
class NdmsCatalogCache {
public:
    using Clock = NdmsInterfaceResource::Clock;
    using FetchFn = NdmsInterfaceResource::FetchFn;
    using NowFn = NdmsInterfaceResource::NowFn;

    // Compatibility/test constructor. The owned raw resource still supplies
    // the same single-flight, invalidation-epoch and LKG contract as the
    // production shared resource.
    explicit NdmsCatalogCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    explicit NdmsCatalogCache(NdmsInterfaceResource& resource);

    NdmsCatalogSnapshot get();
    // Requests a fresh RCI observation even while the regular TTL is valid.
    // Repeated forced refreshes are still throttled by the raw resource's
    // failure retry and concurrent callers share one in-flight request.
    NdmsCatalogSnapshot force_refresh();
    // Invalidates raw catalog authority without performing I/O. Interface
    // events call this before cache-only reconciliation; the next forced
    // refresh is allowed immediately by the shared resource.
    void invalidate();
    NdmsCatalogSnapshot peek() const;

private:
    NdmsCatalogSnapshot project(const NdmsInterfaceSnapshot& raw) const;
    NdmsCatalogSnapshot snapshot_locked(
        const NdmsInterfaceSnapshot& raw,
        bool refreshed = false) const;

    std::unique_ptr<NdmsInterfaceResource> owned_resource_;
    NdmsInterfaceResource* resource_{nullptr};

    mutable std::mutex mutex_;
    mutable std::optional<NdmsInterfaceCatalog> catalog_;
    mutable std::optional<Clock::time_point> source_observed_at_;
    mutable std::uint64_t source_content_generation_{0};
    mutable std::uint64_t source_observation_generation_{0};
    mutable std::uint64_t source_observation_epoch_{0};
    mutable std::uint64_t attempted_content_generation_{0};
};

// Shared by the daemon runtime and API projections. All passive consumers use
// the same raw show/interface owner and therefore cannot start duplicate RCI
// polling loops.
NdmsCatalogCache& shared_ndms_catalog_cache();

} // namespace keen_pbr3
