#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

// Opens the web interface to the outside world.
//
// The API already listens on every address; what keeps it private is the
// firmware's firewall. So this adds a deliberate hole for one TCP port on the
// WAN interface, and nothing else. It refuses to open when login is disabled -
// publishing an unauthenticated control panel to the internet is not a choice
// worth offering behind a single switch.
void register_remote_access_handler(ApiServer& server, ApiContext& ctx);

// Re-applies the stored rules. Called at startup and after firewall rebuilds,
// because the firmware wipes rules it does not own on network events.
void apply_remote_access_rules();

} // namespace keen_pbr3

#endif
