#pragma once

#ifdef WITH_API

#include "server.hpp"

#include <functional>

namespace keen_pbr3 {
class StatusStream;
// These are the exact callbacks registered below. Keeping their construction
// separate lets focused tests exercise persistence and SSE without starting
// unrelated authentication or router discovery providers.
struct NotificationHandlers {
    ApiServer::RouteHandler get;
    ApiServer::BodyRouteHandler dismiss;
};
NotificationHandlers make_notification_handlers(
    StatusStream* status_stream, const std::string& config_path,
    std::function<nlohmann::json()> subscription_sources = {});

void register_logs_handler(
    ApiServer& server,
    StatusStream* status_stream = nullptr,
    const std::string& config_path = "/opt/etc/keen-pbr/config.json",
    std::function<nlohmann::json()> subscription_sources = {});

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
