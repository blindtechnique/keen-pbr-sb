#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <functional>
#include <optional>
#include <string>
#include <utility>

#ifdef KEEN_PBR3_TESTING
#include <filesystem>
#endif

namespace keen_pbr3 {

void register_config_handler(ApiServer& server, ApiContext& ctx);

// A conditional transport mutation was rejected before it changed durable
// state. The shared commit coordinator must close its prepared WAL without
// restoring the transport snapshot: another writer may already own the newer
// durable bytes.
class ConfigCommitNoMutationConflict final : public ApiError {
public:
    explicit ConfigCommitNoMutationConflict(
        std::string message,
        int status = 409,
        std::optional<std::string> body = std::nullopt)
        : ApiError(
              std::move(message),
              status,
              std::move(body)) {}
};

// Optional transport-manager leg owned by the same durable config-save WAL.
//
// The caller validates the transport before the journal is started.  mutate()
// performs the conditional durable mutation and returns the exact revision
// loaded by transport-manager.  verify_revision() proves runtime registration
// of that revision.  restore_revision() runs after the exact files have been
// restored but before the rollback marker is removed, so a failed restart
// leaves the WAL available for startup recovery.
struct ConfigCommitTransportEffect {
    std::string config_path;
    // Revision observed by the transport manager before validation. It must
    // equal the exact durable snapshot revision before the WAL may start.
    std::string base_revision;
    std::function<std::string()> mutate;
    std::function<void(const std::string&)> verify_revision;
    std::function<void(const std::string&)> restore_revision;
};

struct PreparedConfigCommit {
    Config config;
    std::string serialized;
    std::optional<ConfigCommitTransportEffect> transport;
    std::string success_status{"ok"};
    std::string success_message{"Config saved and applied"};
};

using PrepareConfigCommit =
    std::function<PreparedConfigCommit()>;

// Runs validation, exact file snapshots, the single config-save WAL, optional
// transport-manager mutation/readiness, and core apply under one maintenance
// lease.  This is the only cross-layer commit path used by both /api/config/save
// and composite transport creation.
std::string commit_prepared_config(
    ApiContext& ctx,
    std::string maintenance_operation,
    PrepareConfigCommit prepare);

std::string serialize_config_for_persistence(
    const Config& config);

#ifdef KEEN_PBR3_TESTING
using ConfigFileWriterForTest =
    std::function<void(const std::string&, const std::string&)>;

enum class ConfigSaveFaultStage {
    wal_started,
    generation_reserved,
    transport_mutated,
    config_written,
    files_committed,
    transports_ready,
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

std::string commit_prepared_config_for_test(
    ApiContext& ctx,
    std::string maintenance_operation,
    PrepareConfigCommit prepare,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options = {});

void register_config_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options = {});
#endif

} // namespace keen_pbr3

#endif // WITH_API
