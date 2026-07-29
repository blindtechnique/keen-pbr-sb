#pragma once

#ifdef WITH_API

#include "handler_config.hpp"
#include "handlers.hpp"
#include "server.hpp"

#include <nlohmann/json.hpp>

#include <functional>

namespace keen_pbr3 {

using CatalogSnapshotProvider = std::function<nlohmann::json()>;

void register_catalog_setup_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
void register_catalog_setup_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    CatalogSnapshotProvider catalog_snapshot_provider,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options = {});
#endif

} // namespace keen_pbr3

#endif // WITH_API
