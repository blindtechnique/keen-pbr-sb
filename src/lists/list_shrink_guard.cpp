#include "list_shrink_guard.hpp"

#include "../config/list_parser.hpp"
#include "../lists/list_entry_visitor.hpp"
#include "../util/format_compat.hpp"

namespace keen_pbr3 {

ListEntryCounts count_list_entries(std::istream& input) {
    ListEntryCounts counts;
    FunctionalVisitor visitor([&counts](EntryType type, std::string_view) {
        switch (type) {
            case EntryType::Domain:
                ++counts.domains;
                break;
            case EntryType::Cidr:
                ++counts.cidrs;
                break;
            case EntryType::Ip:
                ++counts.ips;
                break;
        }
    });
    ListParser::stream_parse(input, visitor);
    return counts;
}

ListShrinkDecision decide_list_shrink(const ListEntryCounts& previous,
                                      const ListEntryCounts& candidate,
                                      const ListShrinkPolicy& policy) {
    ListShrinkDecision decision;

    const auto had = previous.total();
    const auto has = candidate.total();

    // A first download, or a cache whose counts were never recorded. There is
    // nothing to shrink from, and refusing here would mean a list could never
    // arrive at all.
    if (had <= 0) return decision;

    decision.retained_fraction =
        static_cast<double>(has) / static_cast<double>(had);

    // Small sources move a lot in relative terms and mean nothing by it.
    if (had < policy.min_previous_entries) return decision;

    if (has == 0) {
        decision.verdict = ListShrinkVerdict::refuse;
        decision.reason = keen_pbr3::format(
            "the update decoded no entries at all while the cached list has "
            "{}; keeping the cached list",
            had);
        return decision;
    }

    if (decision.retained_fraction < policy.min_retained_fraction) {
        decision.verdict = ListShrinkVerdict::refuse;
        decision.reason = keen_pbr3::format(
            "the update decoded {} entries against {} cached, keeping {}% - "
            "below the {}% this source is allowed to lose; keeping the cached "
            "list",
            has,
            had,
            static_cast<int>(decision.retained_fraction * 100.0),
            static_cast<int>(policy.min_retained_fraction * 100.0));
        return decision;
    }

    return decision;
}

}  // namespace keen_pbr3
