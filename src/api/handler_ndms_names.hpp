#pragma once

#ifdef WITH_API

#include "../keenetic/ndms_interface_inventory.hpp"
#include "handlers.hpp"
#include "server.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NdmsCatalogCacheStatus : std::uint8_t {
    fresh,
    stale,
    unavailable,
};

struct NdmsCatalogSnapshot {
    NdmsInterfaceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
};

// Thread-safe, single-flight cache for the loopback NDMS request. Failed
// refreshes never replace the most recent catalog that parsed successfully.
class NdmsCatalogCache {
public:
    using Clock = std::chrono::steady_clock;
    using FetchFn = std::function<std::string()>;
    using NowFn = std::function<Clock::time_point()>;

    explicit NdmsCatalogCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    NdmsCatalogSnapshot get();

private:
    NdmsCatalogSnapshot snapshot_locked() const;

    FetchFn fetch_fn_;
    NowFn now_fn_;
    Clock::duration cache_ttl_;
    Clock::duration failure_retry_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::optional<NdmsInterfaceCatalog> catalog_;
    NdmsCatalogCacheStatus status_{NdmsCatalogCacheStatus::unavailable};
    Clock::time_point refresh_after_{};
    bool refresh_attempted_{false};
    bool refresh_in_progress_{false};
    std::uint64_t refresh_generation_{0};
};

// Human names for interfaces, taken from the router's own configuration.
//
// keen-pbr works in kernel interface names - nwg2, ppp0, eth3 - because that
// is what routing needs. The person who set the router up named the same
// things differently in NDMS: "sddvpn.mooo.com AWG2", "Провайдер", "Гостевая
// сеть". Showing our names where theirs exist is the single largest source of
// confusion in the interface, and the firmware already knows the mapping.
void register_ndms_names_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
void register_ndms_names_handler_for_tests(ApiServer& server,
                                           NdmsCatalogCache& cache,
                                           std::vector<std::string>
                                               runtime_interface_names = {});
#endif

} // namespace keen_pbr3

#endif
