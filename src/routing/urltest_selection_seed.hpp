#pragma once

#include "../config/config.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Produce a structurally valid URLTEST cursor before the first probe completes.
// A retained cursor remains authoritative while it is still configured and
// marked. A missing or stale cursor falls back deterministically to the first
// configured and marked child in the same stable group-weight/declaration order
// used by URLTEST.
inline std::map<std::string, std::string>
normalize_and_seed_urltest_selections(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& current) {
    std::map<std::string, std::string> normalized;

    for (const auto& outbound :
         config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::URLTEST) {
            continue;
        }

        const auto groups = outbound.outbound_groups.value_or(
            std::vector<OutboundGroup>{});
        const auto is_configured_and_marked_child =
            [&groups, &outbound_marks](const std::string& child_tag) {
                return outbound_marks.find(child_tag) !=
                           outbound_marks.end() &&
                       std::any_of(
                           groups.begin(),
                           groups.end(),
                           [&child_tag](const OutboundGroup& group) {
                               return std::find(group.outbounds.begin(),
                                                group.outbounds.end(),
                                                child_tag) !=
                                      group.outbounds.end();
                           });
            };

        const auto retained = current.find(outbound.tag);
        if (retained != current.end() &&
            is_configured_and_marked_child(retained->second)) {
            normalized.emplace(outbound.tag, retained->second);
            continue;
        }

        struct GroupRef {
            std::size_t index;
            std::uint32_t weight;
        };
        std::vector<GroupRef> ordered_groups;
        ordered_groups.reserve(groups.size());
        for (std::size_t index = 0; index < groups.size(); ++index) {
            ordered_groups.push_back(GroupRef{
                index,
                static_cast<std::uint32_t>(
                    groups[index].weight.value_or(1)),
            });
        }
        std::stable_sort(
            ordered_groups.begin(),
            ordered_groups.end(),
            [](const GroupRef& left, const GroupRef& right) {
                return left.weight < right.weight;
            });

        bool seeded = false;
        for (const auto& group_ref : ordered_groups) {
            for (const auto& child_tag :
                 groups[group_ref.index].outbounds) {
                if (outbound_marks.find(child_tag) ==
                    outbound_marks.end()) {
                    continue;
                }
                normalized.emplace(outbound.tag, child_tag);
                seeded = true;
                break;
            }
            if (seeded) {
                break;
            }
        }
    }

    return normalized;
}

} // namespace keen_pbr3
