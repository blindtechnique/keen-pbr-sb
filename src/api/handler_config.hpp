#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#ifdef KEEN_PBR3_TESTING
#include <filesystem>
#include <functional>
#include <string>
#endif

namespace keen_pbr3 {

void register_config_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
using ConfigFileWriterForTest =
    std::function<void(const std::string&, const std::string&)>;

enum class ConfigSaveFaultStage {
    wal_started,
    generation_reserved,
    config_written,
    files_committed,
    apply_returned,
    core_applied,
    wal_committed,
};

struct ConfigSaveTestOptions {
    // Empty means a private sibling of the test config file. Production never
    // consults this option and always uses the fixed recovery state root.
    std::filesystem::path recovery_state_root;
    std::function<void(ConfigSaveFaultStage)> fault_injector;
};

void register_config_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options = {});
#endif

} // namespace keen_pbr3

#endif // WITH_API
