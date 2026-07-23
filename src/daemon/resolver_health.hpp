#pragma once

#include "../api/generated/api_types.hpp"
#include "../dns/dns_txt_client.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

struct ResolverActualState {
    api::ResolverLiveStatus live_status{api::ResolverLiveStatus::UNKNOWN};
    std::optional<std::int64_t> last_probe_ts;
    std::string actual_hash;
    std::optional<std::int64_t> actual_ts;
};

ResolverActualState build_resolver_actual_state(
    bool routing_runtime_active,
    bool resolver_configured,
    const std::optional<ResolverConfigHashProbeResult>& probe_result,
    std::optional<std::int64_t> probe_completed_ts);

std::optional<api::ResolverConfigSyncState> classify_resolver_config_sync_state(
    const std::optional<std::int64_t>& actual_ts,
    const std::optional<std::int64_t>& apply_started_ts,
    std::int64_t now_ts,
    bool hash_equal);

bool resolver_reload_required(std::string_view expected_hash,
                              std::string_view actual_hash,
                              api::ResolverLiveStatus live_status);

} // namespace keen_pbr3
