#pragma once

#include "config.hpp"

#include <set>
#include <string>

namespace keen_pbr3 {

// Pure cleanup for a confirmed outbound deletion. Uses the same empty-group
// cascade as dependency analysis; unrelated fields and absent optionals stay
// unchanged. System outbounds and already absent targets are not deleted.
Config remove_outbound_dependencies(
    const Config& config, const std::set<std::string>& requested_tags);

struct InterfaceOutboundDeletePlan {
    Config config;
    std::set<std::string> tags;
    bool used_by_group{false};
};

// Plan each active/draft snapshot separately: the same tag may point to a
// different interface in the draft. Native deletion keeps group membership
// as an explicit user edit instead of silently changing a working group.
InterfaceOutboundDeletePlan plan_native_interface_outbound_delete(
    const Config& config, const std::string& kernel_interface);

} // namespace keen_pbr3
