#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {
void register_logs_handler(ApiServer& server, ApiContext& ctx);

// Applies logging preferences stored on the router. Called at startup, after
// the sink exists but before the daemon does any real work.
void apply_stored_log_settings();
}

#endif
