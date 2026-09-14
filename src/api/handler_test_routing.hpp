#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"
#ifdef KEEN_PBR3_TESTING
#include "../nfqws/list_match.hpp"
#endif

#include <cstddef>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// POST /api/routing/test
// Body: { "target": "<ip-or-domain>" }
// Returns JSON with expected/actual outbound per resolved IP.
void register_test_routing_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
// Runs only after the request owns the single nfqws scan slot and before it
// inspects configuration or list metadata. Tests hold the first request here
// to prove a concurrent request returns busy without entering the scan.
using NfqwsCoverageScanHook = std::function<void()>;
void set_nfqws_coverage_scan_hook_for_testing(NfqwsCoverageScanHook hook);
void reset_nfqws_coverage_scan_hook_for_testing();

// The production reader accepts direct children of the fixed lists root only.
// This seam proves a configurable nested parent cannot be a symlink escape.
bool nfqws_list_path_confined_for_testing(const std::string& path);

// Returns the conservative resident-cache charge for a list accepted by the
// production bounds. nullopt means no partial parse can enter the cache.
std::optional<std::size_t> nfqws_cached_list_footprint_for_testing(
    const std::string& contents);

// Production profile evaluation/serialization with an in-memory list reader;
// tests do not create nfqws files in /opt or change running services.
api::RoutingTestNfqws nfqws_profile_coverage_for_testing(
    const TestRoutingResult& result,
    const std::vector<nfqws::ProfileReference>& profiles,
    const nfqws::ListLoader& load);
#endif

} // namespace keen_pbr3

#endif // WITH_API
