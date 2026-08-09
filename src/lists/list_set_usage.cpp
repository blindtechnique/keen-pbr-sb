#include "list_set_usage.hpp"

#include "list_entry_visitor.hpp"
#include "list_streamer.hpp"

namespace keen_pbr3 {

ListSetUsage analyze_list_set_usage(const std::string& list_name,
                                    const ListConfig& config,
                                    ListStreamer& list_streamer) {
    ListSetUsage usage;
    FunctionalVisitor analyzer(
        [&usage](EntryType type, std::string_view entry) {
            if (type == EntryType::Domain) {
                usage.has_domain_entries = true;
                return;
            }
            usage.has_static_entries = true;
            if (entry.find(':') == std::string_view::npos) {
                usage.has_static_ipv4_entries = true;
            } else {
                usage.has_static_ipv6_entries = true;
            }
            if (usage.static_destinations.size() <
                ListSetUsage::kMaxTrackedStaticDestinations) {
                usage.static_destinations.emplace_back(entry);
            } else {
                usage.static_destinations_truncated = true;
            }
        });
    list_streamer.stream_list(list_name, config, analyzer);

    const int64_t ttl_ms = config.ttl_ms.value_or(0);
    if (ttl_ms >= 1000) {
        usage.dynamic_timeout = static_cast<uint32_t>(ttl_ms / 1000);
    }

    return usage;
}

} // namespace keen_pbr3
