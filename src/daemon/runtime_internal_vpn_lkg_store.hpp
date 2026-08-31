#pragma once

#include "internal_vpn_runtime_resolution.hpp"

#include "../util/traced_mutex.hpp"

#include <vector>

namespace keen_pbr3 {

// Exact pair used by cold-boot publication. Preparing the pair is fallible;
// exchanging it with the active cache only swaps already allocated vectors.
// The operation owner remains responsible for deciding when that exchange is
// admitted and for exchanging the same value back on rollback.
struct RuntimeInternalVpnLkgPublication final {
    std::vector<InternalVpnServer> servers;
    std::vector<InternalVpnRuntimeTarget> service_targets;
};

// Thread-safe storage for the two verified include-only native-VPN caches.
// This class does not add an admission gate, journal or recovery policy. It
// only owns the state and preserves the existing merge/publication semantics.
class RuntimeInternalVpnLkgStore final {
public:
    std::vector<InternalVpnServer> snapshot_servers() const;
    std::vector<InternalVpnRuntimeTarget>
    snapshot_service_targets() const;

    // These operations are intentionally fallible. Callers retain their
    // existing logging/noexcept policy around allocation or lock failures.
    void update_servers(
        const InternalVpnRuntimeResolution& resolution);
    void update_service_targets(
        const InternalVpnServiceRuntimeResolution& resolution);

    // Copy the current exact pair and apply both eligible resolution deltas
    // while holding the same lock used by the previous Daemon implementation.
    RuntimeInternalVpnLkgPublication prepare_publication(
        const InternalVpnRuntimeResolution& server_resolution,
        const InternalVpnServiceRuntimeResolution& service_resolution) const;

    // Exchange an already prepared pair with the active pair. This is not
    // noexcept because acquiring the traced mutex can fail; callers that run
    // inside a noexcept publication callback must retain their existing try /
    // catch boundary.
    void exchange(RuntimeInternalVpnLkgPublication& publication);

private:
    mutable TracedMutex mutex_;
    std::vector<InternalVpnServer> servers_ GUARDED_BY(mutex_);
    std::vector<InternalVpnRuntimeTarget>
        service_targets_ GUARDED_BY(mutex_);
};

} // namespace keen_pbr3
