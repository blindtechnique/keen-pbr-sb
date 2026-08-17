#pragma once

#ifdef WITH_API

#include "server.hpp"

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif

namespace keen_pbr3 {
void register_logs_handler(ApiServer& server);

// Applies logging preferences stored on the router. Called at startup, after
// the sink exists but before the daemon does any real work.
void apply_stored_log_settings();

#ifdef KEEN_PBR3_TESTING
enum class LogSettingsTestStage { request_ready, after_read };
using LogSettingsTestHook = std::function<void(LogSettingsTestStage)>;
void set_log_settings_test_hook(LogSettingsTestHook hook);
#endif
}

#endif
