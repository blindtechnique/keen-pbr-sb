#pragma once

#ifdef WITH_API

#include "handlers.hpp"

namespace keen_pbr3 {

// GET /api/tunnel-probe - what the nfqws2-to-tunnel automation last did.
//
// Reads a small store of its own rather than the API context: the pass runs on
// a worker thread and has nothing else to ask the daemon for, and threading one
// more function through the context would couple this to wiring it does not
// need.
void register_tunnel_probe_handler(ApiServer& server);

}  // namespace keen_pbr3

#endif  // WITH_API
