#pragma once

#include "../api/generated/api_types.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/netlink.hpp"
#include "../routing/urltest_manager.hpp"
#include "../runtime/runtime_state_machine.hpp"
#include "../util/traced_mutex.hpp"

#include <vector>
#include <map>
#include <string>
#include <cstdint>
#include <optional>

namespace keen_pbr3 {

struct RuntimeStateSnapshot {
    FirewallState firewall_state;
    std::vector<RouteSpec> route_specs;
    std::vector<RuleSpec> policy_rule_specs;
    std::map<std::string, UrltestState> urltest_states;
    std::string resolver_config_hash;
    std::string resolver_config_hash_actual;
    std::optional<std::int64_t> resolver_config_hash_actual_ts;
    std::optional<api::ResolverConfigSyncState> resolver_config_sync_state;
    api::ResolverConfigProbeStatus resolver_config_probe_status{api::ResolverConfigProbeStatus::UNKNOWN};
    api::ResolverLiveStatus resolver_live_status{api::ResolverLiveStatus::UNKNOWN};
    std::optional<std::int64_t> resolver_last_probe_ts;
    std::optional<std::int64_t> apply_started_ts;
    bool routing_runtime_active{true};
    RuntimeState runtime_state{RuntimeState::starting};
    std::string runtime_state_reason;
};

class RuntimeStateStore {
public:
    RuntimeStateSnapshot snapshot() const;
    // Replaces everything the store holds EXCEPT routing_runtime_active,
    // which the store owns outright and carries forward. A publish rebuilds
    // the whole snapshot from the daemon's fields, so honouring the incoming
    // value would let any of the ~25 publish sites reset a flag it never
    // meant to touch - and the default is `true`, so the reset direction is
    // "routing is fine", which is the answer that must never be invented.
    void publish(RuntimeStateSnapshot snapshot);

    // Whether routing is live, as its own read and its own write.
    //
    // This one field used to be answered twice: the daemon kept a plain
    // `bool routing_runtime_active_` and the published snapshot was built
    // from it, so between a write to the field and the next publish the API
    // and the panel answered with the previous value - "the panel says one
    // thing, the runtime does another". There is now one place to hold it.
    //
    // Separate accessors rather than snapshot()/publish() because both hot
    // paths want only this bool: snapshot() copies the route and rule
    // vectors and the urltest map, which is a lot of work per event for one
    // flag, and publish() would need the whole snapshot rebuilt to change it.
    bool routing_runtime_active() const;
    void set_routing_runtime_active(bool active);

private:
    mutable TracedSharedMutex mutex_;
    RuntimeStateSnapshot snapshot_ GUARDED_BY(mutex_);
};

} // namespace keen_pbr3
