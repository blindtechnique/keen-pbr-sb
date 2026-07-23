#pragma once

#ifdef WITH_API
#include "handlers.hpp"
namespace keen_pbr3 {
void register_connections_handler(ApiServer& server, ApiContext& ctx);
// Marks the cached /proc snapshot stale after a kernel conntrack event. Cursor
// snapshots remain immutable; only the next first-page query is refreshed.
void invalidate_connections_snapshot();
}
#endif
