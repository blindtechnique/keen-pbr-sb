#pragma once

#include <cstdint>

namespace keen_pbr3 {

inline constexpr const char* dns_query_log_path =
    "/tmp/dnsmasq-keen-pbr-queries.log";
inline constexpr std::uintmax_t maximum_dns_query_log_size =
    2U * 1024U * 1024U;

enum class DnsQueryLogMaintenanceState {
    unavailable,
    within_limit,
    truncated,
    truncate_failed,
};

struct DnsQueryLogMaintenanceResult {
    DnsQueryLogMaintenanceState state{
        DnsQueryLogMaintenanceState::unavailable};
    std::uintmax_t observed_size{0U};
    int error_number{0};
};

// Bounds the dnsmasq observation stream by truncating its existing inode.
// This is safe for dnsmasq's live O_APPEND descriptor and never creates a
// missing path. An unavailable best-effort log is non-fatal to the daemon.
DnsQueryLogMaintenanceResult maintain_dns_query_log(
    const char* path = dns_query_log_path,
    std::uintmax_t maximum_size = maximum_dns_query_log_size) noexcept;

} // namespace keen_pbr3
