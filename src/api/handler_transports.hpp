#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#ifdef KEEN_PBR3_TESTING
#include "handler_config.hpp"
#endif

namespace keen_pbr3 {

void register_transports_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
void register_transports_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options = {});
#endif

} // namespace keen_pbr3

#endif // WITH_API
