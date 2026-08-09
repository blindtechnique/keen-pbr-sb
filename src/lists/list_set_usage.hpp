#pragma once

#include "../config/config.hpp"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

class ListStreamer;

struct ListSetUsage {
    static constexpr std::size_t kMaxTrackedStaticDestinations = 256U;

    bool has_static_entries{false};
    bool has_domain_entries{false};
    bool has_static_ipv4_entries{false};
    bool has_static_ipv6_entries{false};
    uint32_t dynamic_timeout{0};
    // A bounded sample of static destination selectors supports immediate,
    // targeted retirement when traffic changes from direct to managed. The
    // global conntrack table is never flushed.
    std::vector<std::string> static_destinations;
    bool static_destinations_truncated{false};
};

struct AppliedListContentState {
    std::map<std::string, std::vector<std::string>> static_destinations;
    // Domain-derived addresses live only in dynamic firewall sets. Keep this
    // fact so conntrack retirement can report its intentionally partial
    // coverage without pretending that those destinations were inspected.
    std::set<std::string> domain_entry_lists;
    std::set<std::string> truncated_static_destination_lists;
};

// Analyze a list's fully streamed content to determine which firewall sets are needed.
ListSetUsage analyze_list_set_usage(const std::string& list_name,
                                    const ListConfig& config,
                                    ListStreamer& list_streamer);

} // namespace keen_pbr3
