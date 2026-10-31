#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Observations only: never consumed by VPN health or routing selection.
struct InterceptionHealth {
    bool dns_requested{false}, l7_requested{false};
    std::string dns_state{"unknown"}, l7_state{"unknown"};
    std::string dns_detail, l7_detail;
    std::vector<std::string> interfaces;
    std::string nfqueue{"not_run"}, nflog{"not_run"}, fail_open{"not_run"};
    uint64_t dns_packets{0}, dns_matched{0}, l7_packets{0}, l7_matched{0};
    uint64_t set_errors{0}, dns_hold_timeouts{0}, queue_overruns{0}, log_overruns{0};
};

} // namespace keen_pbr3
