#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <nlohmann/json_fwd.hpp>
#include <string>

namespace keen_pbr3 {

void register_backup_handler(ApiServer& server, ApiContext& ctx);
std::string create_full_rollback_backup(const ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
void restore_backup_bundle_for_test(const ApiContext& ctx,
                                    const nlohmann::json& backup);
#endif

} // namespace keen_pbr3

#endif
