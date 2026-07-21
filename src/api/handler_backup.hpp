#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <nlohmann/json_fwd.hpp>
#include <string>

namespace keen_pbr3 {

void register_backup_handler(ApiServer& server, ApiContext& ctx);
std::string create_full_rollback_backup(const ApiContext& ctx);

} // namespace keen_pbr3

#endif
