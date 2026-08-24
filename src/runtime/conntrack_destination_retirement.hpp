#pragma once

#include "../lists/list_set_usage.hpp"

#include <algorithm>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct ConntrackDestinationRetirementPlan {
    std::set<std::string> current_list_names;
    std::vector<std::string> current_destination_selectors;
};

struct ConntrackDestinationRetirementCoverage {
    std::vector<std::string> destination_selectors;
    // Dynamic DNS-derived members are not available through ListStreamer, and
    // bounded static tracking deliberately retains only its first selectors.
    // Callers expose this as quiet diagnostics; neither limitation justifies a
    // global conntrack flush.
    std::set<std::string> domain_backed_list_names;
    std::set<std::string> truncated_static_list_names;

    bool partial() const noexcept {
        return !domain_backed_list_names.empty() ||
               !truncated_static_list_names.empty();
    }
};

namespace runtime_recovery_detail {

inline std::string_view trim_ascii_whitespace(
    std::string_view value) noexcept {
    constexpr std::string_view whitespace{" \t\r\n"};
    const auto first = value.find_first_not_of(whitespace);
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1U);
}

inline bool is_global_destination_selector(
    std::string_view selector) noexcept {
    selector = trim_ascii_whitespace(selector);
    const auto slash = selector.rfind('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    return trim_ascii_whitespace(selector.substr(slash + 1U)) == "0";
}

inline bool contains_global_destination_selector(
    const ConntrackDestinationRetirementCoverage& coverage) noexcept {
    return std::any_of(
        coverage.destination_selectors.begin(),
        coverage.destination_selectors.end(),
        [](const std::string& selector) {
            return is_global_destination_selector(selector);
        });
}

} // namespace runtime_recovery_detail

inline ConntrackDestinationRetirementPlan
destination_retirement_plan_for_lists(
    const std::set<std::string>& list_names) {
    ConntrackDestinationRetirementPlan plan;
    plan.current_list_names = list_names;
    return plan;
}

inline ConntrackDestinationRetirementCoverage
merge_conntrack_destination_retirement_coverage(
    ConntrackDestinationRetirementCoverage left,
    const ConntrackDestinationRetirementCoverage& right) {
    left.destination_selectors.insert(
        left.destination_selectors.end(),
        right.destination_selectors.begin(),
        right.destination_selectors.end());
    left.domain_backed_list_names.insert(
        right.domain_backed_list_names.begin(),
        right.domain_backed_list_names.end());
    left.truncated_static_list_names.insert(
        right.truncated_static_list_names.begin(),
        right.truncated_static_list_names.end());
    return left;
}

inline ConntrackDestinationRetirementCoverage
collect_conntrack_destination_retirement_coverage(
    const ConntrackDestinationRetirementPlan& plan,
    const AppliedListContentState& content_state) {
    ConntrackDestinationRetirementCoverage coverage;
    coverage.destination_selectors = plan.current_destination_selectors;
    for (const auto& list_name : plan.current_list_names) {
        const auto static_destinations =
            content_state.static_destinations.find(list_name);
        if (static_destinations != content_state.static_destinations.end()) {
            coverage.destination_selectors.insert(
                coverage.destination_selectors.end(),
                static_destinations->second.begin(),
                static_destinations->second.end());
        }
        if (content_state.domain_entry_lists.count(list_name) != 0U) {
            coverage.domain_backed_list_names.insert(list_name);
        }
        if (content_state.truncated_static_destination_lists.count(list_name) !=
            0U) {
            coverage.truncated_static_list_names.insert(list_name);
        }
    }
    return coverage;
}

} // namespace keen_pbr3
