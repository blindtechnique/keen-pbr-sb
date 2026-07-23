#pragma once

#include "config.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

enum class DependencyEntityKind {
    List,
    Outbound,
    DnsServer,
};

enum class DependencyRelation {
    UsesList,
    RoutesTo,
    DetoursVia,
    ContainsMember,
    UsesDnsServer,
    FallbackTo,
};

enum class DependencyConsequence {
    Modify,
    Delete,
    Disconnect,
};

enum class DependencyDependentKind {
    RoutingRule,
    DnsRule,
    DnsServer,
    OutboundGroup,
    List,
    DnsFallback,
};

struct DependencyTarget {
    DependencyEntityKind kind;
    std::string id;
    bool cascaded{false};
};

struct DependencyReference {
    DependencyTarget target;
    DependencyDependentKind dependent_kind;
    std::string dependent_id;
    DependencyRelation relation;
    DependencyConsequence consequence;
    std::string path;
    std::string href;
};

struct DependencyAnalysis {
    std::vector<DependencyTarget> targets;
    std::vector<DependencyReference> references;
    bool safe_to_delete{true};
};

DependencyAnalysis analyze_dependencies(
    const Config& config,
    const std::vector<DependencyTarget>& requested_targets);

} // namespace keen_pbr3
