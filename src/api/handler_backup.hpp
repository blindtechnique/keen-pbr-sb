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
nlohmann::json create_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& groups);
nlohmann::json create_nfqws_backup_section_for_test(
    const nlohmann::json& groups,
    const std::string& nfqws_root,
    const std::string& strategies_root);
void validate_confined_restore_target_for_test(
    const std::string& root,
    const std::string& target);
void restore_backup_bundle_for_test(const ApiContext& ctx,
                                    const nlohmann::json& backup);
#endif

} // namespace keen_pbr3

#endif
