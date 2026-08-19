#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <functional>
#include <string>

namespace keen_pbr3 {

// POST /api/routing/registry-check - asks a third-party service whether a
// domain is on Russia's blocking registry.
//
// This is the one place in the daemon that talks to a service we do not
// control, so it is gated on ui_preferences.registry_lookup_enabled - the
// daemon's own setting, not a flag the request may assert. A browser cannot
// authorise the lookup by asking for it, and the consent outlives the browser
// that gave it.
//
// The answer is about the registry, not about this router - whether the domain
// actually fails here is what the routing test and the reachability probes are
// for, and the two are deliberately reported separately.
void register_registry_check_handler(ApiServer& server, ApiContext& ctx);

// Replaces the HTTPS call for tests. Receives the target and returns the raw
// response body; throwing signals a failed lookup.
using RegistryFetcher = std::function<std::string(const std::string& target)>;

void register_registry_check_handler_for_test(ApiServer& server,
                                              ApiContext& ctx,
                                              RegistryFetcher fetcher);

// Drops the cached verdicts. Tests need it because the cache deliberately
// outlives a single request.
void clear_registry_check_cache_for_testing();

} // namespace keen_pbr3

#endif
