#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <cstddef>
#include <functional>
#include <nlohmann/json_fwd.hpp>
#include <string>

namespace keen_pbr3 {

enum class AtomicFileWriteStage;

void register_backup_handler(ApiServer& server, ApiContext& ctx);
std::string create_full_rollback_backup(const ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
enum class RestoreServiceReadinessForTest {
    starting,
    ready,
    failed,
};

struct BackupRestoreRootsForTest {
    std::string nfqws;
    std::string strategies;
};

struct BackupRestoreHooksForTest {
    std::function<void(const std::string&, AtomicFileWriteStage)>
        atomic_write_fault;
    std::function<void(std::size_t, const std::string&)>
        before_forward_write;
    std::function<void()> after_forward_runtime_apply;
    std::function<void(const std::string&)>
        before_forward_service_restart;
    std::function<void(std::size_t, const std::string&)>
        before_rollback_write;
    std::function<RestoreServiceReadinessForTest(const std::string&)>
        probe_service_readiness;
    std::function<RestoreServiceReadinessForTest(const std::string&)>
        probe_transport_config_revision;
    std::function<void()> wait_before_service_probe;
};

nlohmann::json create_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& groups);
using BackupSnapshotReaderForTest = std::function<nlohmann::json(
    const ApiContext&, const nlohmann::json&)>;
void register_backup_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    BackupSnapshotReaderForTest backup_snapshot_reader);
nlohmann::json create_nfqws_backup_section_for_test(
    const nlohmann::json& groups,
    const std::string& nfqws_root,
    const std::string& strategies_root);
void validate_confined_restore_target_for_test(
    const std::string& root,
    const std::string& target);
void restore_backup_bundle_for_test(const ApiContext& ctx,
                                    const nlohmann::json& backup);
void restore_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const BackupRestoreRootsForTest& roots);
void restore_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const BackupRestoreHooksForTest& hooks);
void restore_backup_with_rollback_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const std::string& rollback_path);
void restore_backup_with_rollback_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const std::string& rollback_path,
    const BackupRestoreHooksForTest& hooks);
void restore_persistent_rollback_for_test(
    const ApiContext& ctx,
    const std::string& rollback_path,
    const BackupRestoreHooksForTest& hooks = {});
void restore_persistent_rollback_for_test(
    const ApiContext& ctx,
    const std::string& rollback_path,
    const BackupRestoreRootsForTest& roots,
    const BackupRestoreHooksForTest& hooks = {});
void create_full_rollback_backup_for_test(
    const ApiContext& ctx,
    const std::string& rollback_path,
    const BackupRestoreRootsForTest& roots);
bool rollback_backup_available_for_test(const std::string& rollback_path);
#endif

} // namespace keen_pbr3

#endif
