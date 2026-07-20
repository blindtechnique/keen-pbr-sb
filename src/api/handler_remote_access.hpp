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

// Re-applies the stored rules. Called at startup and after every firewall
// rebuild: the firmware reapplies its own firewall on network events and wipes
// rules it does not own, so applying once at startup was not enough.
//
// listen_address is the panel's own bind address. A panel bound to loopback
// cannot be published no matter what the firewall says, and that failure is
// invisible from the outside - it looks exactly like a blocked port.
void apply_remote_access_rules(const std::string& listen_address = {});

// True when the configured bind address can accept connections from outside.
bool listen_address_is_reachable(const std::string& listen_address);

} // namespace keen_pbr3

#endif
