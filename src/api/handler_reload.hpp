#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

using ServiceProcessRestartExecutor =
    std::function<int(const std::vector<std::string>&)>;
std::string request_service_process_restart(const ServiceProcessRestartExecutor& execute);
void register_reload_handler(ApiServer& server, ApiContext& ctx,
                             ServiceProcessRestartExecutor execute_process_restart = {});

} // namespace keen_pbr3

#endif // WITH_API
