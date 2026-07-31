#pragma once

#include "config.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct ListDeleteTarget {
    std::string list_id;
    std::optional<std::string> replacement_list_id;
};

struct ListDeletePlanSummary {
    std::vector<std::string> deleted_lists;
    std::size_t rebound_references{0};
    std::size_t removed_route_rules{0};
    std::size_t updated_route_rules{0};
    std::size_t removed_dns_rules{0};
    std::size_t updated_dns_rules{0};
};

struct ListDeletePlan {
    Config config;
    ListDeletePlanSummary summary;
};

// Builds a complete, validation-ready candidate without mutating the source
// configuration. It never persists, applies, or restarts the runtime.
ListDeletePlan plan_list_delete(
    const Config& source,
    const std::vector<ListDeleteTarget>& targets);

} // namespace keen_pbr3
