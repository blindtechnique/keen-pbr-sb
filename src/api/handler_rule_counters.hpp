#pragma once

#ifdef WITH_API
#include "handlers.hpp"
#include "routing_firewall_evidence_view.hpp"

namespace keen_pbr3 {

// Supplied config and realized rules belong to the same control-loop capture.
// This report deliberately has no flow totals, rates, deltas or reset action.
api::RuleCountersResponse build_rule_counters_response(
    const Config& applied, bool unapplied_draft,
    const RoutingFirewallEvidenceLookup& lookup);

void register_rule_counters_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3
#endif
