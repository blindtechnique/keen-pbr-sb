#ifdef WITH_API

#include "handler_config.hpp"
#include "maintenance_api.hpp"
#include "generated/api_types.hpp"

#include "../backup/persistent_snapshot.hpp"
#include "../backup/recovery_coordinator.hpp"
#include "../backup/restore_transaction.hpp"
#include "../config/config.hpp"
#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"
#include "../log/logger.hpp"
#include "../setup/catalog_setup_planner.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <exception>
#include <filesystem>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <sys/random.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

constexpr const char* kRecoveryStateRoot =
    "/opt/var/lib/keen-pbr/recovery";

bool is_lowercase_sha256_digest(const std::string& value) {
    return value.size() == 64U &&
           std::all_of(
               value.begin(),
               value.end(),
               [](const char ch) {
                   return (ch >= '0' && ch <= '9') ||
                          (ch >= 'a' && ch <= 'f');
               });
}

enum class ConfigSaveCheckpoint {
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

struct ConfigSaveRuntimeOptions {
    fs::path recovery_state_root{kRecoveryStateRoot};
#ifdef KEEN_PBR3_TESTING
    std::function<void(ConfigSaveFaultStage)> fault_injector;
#endif
};

void fill_from_urandom(
    unsigned char* output,
    std::size_t size) {
    const int fd = ::open(
        "/dev/urandom",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "Cannot open /dev/urandom");
    }

    std::size_t offset = 0;
    try {
        while (offset < size) {
            const auto count = ::read(
                fd, output + offset, size - offset);
            if (count < 0) {
                if (errno == EINTR) continue;
                throw std::system_error(
                    errno,
                    std::generic_category(),
                    "Cannot read /dev/urandom");
            }
            if (count == 0) {
                throw std::runtime_error(
                    "Unexpected end of /dev/urandom");
            }
            offset += static_cast<std::size_t>(count);
        }
    } catch (...) {
        (void)::close(fd);
        throw;
    }
    // A read-only entropy descriptor has no data to flush. In particular,
    // close(2) returning EINTR must not invalidate already obtained entropy.
    (void)::close(fd);
}

std::string secure_transaction_id() {
    std::array<unsigned char, 16> random_bytes{};
    std::size_t offset = 0;
    while (offset < random_bytes.size()) {
        const auto count = ::getrandom(
            random_bytes.data() + offset,
            random_bytes.size() - offset,
            0);
        if (count < 0) {
            if (errno == EINTR) continue;
            // Old Keenetic/Entware kernels may not expose getrandom(2).
            // /dev/urandom is the only fallback; time, PID and rand() are
            // deliberately never used for a durable transaction identity.
            fill_from_urandom(
                random_bytes.data(), random_bytes.size());
            offset = random_bytes.size();
            break;
        }
        if (count == 0) {
            fill_from_urandom(
                random_bytes.data(), random_bytes.size());
            offset = random_bytes.size();
            break;
        }
        offset += static_cast<std::size_t>(count);
    }

    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(random_bytes.size() * 2U);
    for (const auto byte : random_bytes) {
        result.push_back(hex[(byte >> 4U) & 0x0fU]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
}

backup::PersistentLayout config_save_layout(
    const std::string& config_path,
    bool includes_transports = false) {
    backup::PersistentLayout layout;
    layout.config = config_path;
    layout.transports =
        fs::path(config_path).parent_path() /
        (includes_transports
             ? "transports.json"
             : ".keen-pbr-unused-transports.json");
    return layout;
}

#ifdef KEEN_PBR3_TESTING
void inject_config_save_fault(
    const ConfigSaveRuntimeOptions& options,
    ConfigSaveCheckpoint stage) {
    if (options.fault_injector) {
        options.fault_injector(
            static_cast<ConfigSaveFaultStage>(stage));
    }
}
#else
void inject_config_save_fault(
    const ConfigSaveRuntimeOptions&,
    ConfigSaveCheckpoint) {}
#endif

bool restore_exact_config_snapshot(
    const ConfigSaveRuntimeOptions& options,
    const backup::PersistentLayout& persistent_layout,
    const std::function<void()>& before_completion,
    std::string& failure) noexcept {
    try {
        backup::RecoveryCoordinator coordinator(
            {
                options.recovery_state_root,
                persistent_layout,
            },
            backup::RecoveryCoordinatorHooks{
                before_completion
                    ? [before_completion](
                          RestoreTransactionOperation,
                          const RestoreJournalEntry&) {
                          before_completion();
                      }
                    : std::function<void(
                          RestoreTransactionOperation,
                          const RestoreJournalEntry&)>{},
            });
        const auto result = coordinator.recover();
        if (result.outcome !=
                backup::RecoveryOutcome::rollback_completed ||
            result.operation !=
                backup::RecoveryOperation::config_save) {
            failure =
                "Recovery journal did not prove an exact config rollback";
            return false;
        }
        return true;
    } catch (const std::exception& error) {
        failure = error.what();
    } catch (...) {
        failure = "Unknown exact config recovery failure";
    }
    return false;
}

void mark_config_save_unknown_best_effort(
    const ConfigSaveRuntimeOptions& options,
    const RestoreTransaction& transaction) noexcept {
    // The operation-local marker blocks direct access to the stale rollback
    // payload. The global marker blocks RecoveryCoordinator before it can
    // inspect or apply any operation journal. Both are attempted independently
    // so one filesystem failure cannot suppress the other safety barrier.
    try {
        RestoreJournal(transaction.state_directory())
            .mark_unknown();
    } catch (...) {
    }
    try {
        RestoreJournal(options.recovery_state_root)
            .mark_unknown();
    } catch (...) {
    }
}

bool restore_exact_config_snapshot(
    const ConfigSaveRuntimeOptions& options,
    const backup::PersistentLayout& persistent_layout,
    std::string& failure) noexcept {
    return restore_exact_config_snapshot(
        options,
        persistent_layout,
        {},
        failure);
}

bool stop_routing_best_effort(ApiContext& ctx) noexcept {
    try {
        ctx.emergency_quiesce_runtime();
        return true;
    } catch (const std::exception& error) {
        Logger::instance().error(
            "Cannot quiesce routing after unsafe config save: {}",
            error.what());
    } catch (...) {
        Logger::instance().error(
            "Cannot quiesce routing after unsafe config save: unknown error");
    }
    return false;
}

[[noreturn]] void throw_recovery_required(
    ApiContext& ctx,
    const std::string& reason,
    bool applied,
    bool rolled_back,
    const std::string& recovery_error = {}) {
    const bool runtime_quiesced =
        stop_routing_best_effort(ctx);
    nlohmann::json payload = {
        {"error", reason},
        {"saved", false},
        {"applied", applied},
        {"rolled_back", rolled_back},
        {"recovery_required", true},
        {"runtime_quiesced", runtime_quiesced},
    };
    if (!recovery_error.empty()) {
        payload["recovery_error"] = recovery_error;
    }
    throw ApiError(
        "Persistent recovery required",
        503,
        payload.dump());
}

void fail_lifecycle_best_effort(
    ApiContext& ctx,
    const LifecycleOperationSnapshot& lifecycle,
    const std::string& error) noexcept {
    if (!ctx.lifecycle_operations) return;
    try {
        ctx.lifecycle_operations->fail_stage(
            lifecycle.id, "commit_and_apply", error);
        ctx.lifecycle_operations->finish(
            lifecycle.id, error);
    } catch (const std::exception& bookkeeping_error) {
        Logger::instance().error(
            "Cannot publish config-save failure: {}",
            bookkeeping_error.what());
    } catch (...) {
        Logger::instance().error(
            "Cannot publish config-save failure: unknown error");
    }
}

nlohmann::json make_validation_error_json(const ConfigValidationError& error) {
    nlohmann::json issues = nlohmann::json::array();
    for (const auto& issue : error.issues()) {
        issues.push_back({
            {"path", issue.path},
            {"message", issue.message},
        });
    }

    return {
        {"error", error.what()},
        {"validation_errors", std::move(issues)},
    };
}

Config normalize_config_for_api_response(Config config) {
    if (!config.daemon.has_value()) {
        config.daemon = DaemonConfig{};
    }

    config.daemon->skip_marked_packets =
        config.daemon->skip_marked_packets.value_or(true);
    config.daemon->clear_dynamic_sets_on_apply =
        config.daemon->clear_dynamic_sets_on_apply.value_or(true);
    config.daemon->ipv6_enabled =
        config.daemon->ipv6_enabled.value_or(true);

    return config;
}

std::string serialize_config_pretty(const Config& config) {
    nlohmann::json json = config;
    std::function<bool(nlohmann::json&)> prune_json = [&](nlohmann::json& value) -> bool {
        if (value.is_object()) {
            for (auto it = value.begin(); it != value.end();) {
                if (prune_json(it.value())) {
                    it = value.erase(it);
                } else {
                    ++it;
                }
            }
            return value.empty();
        }

        if (value.is_array()) {
            for (auto& item : value) {
                (void)prune_json(item);
            }
            return false;
        }

        return value.is_null();
    };

    (void)prune_json(json);
    return json.dump(1, '\t') + "\n";
}

class ConfigOperationGuard final {
public:
    explicit ConfigOperationGuard(ApiContext& context)
        : context_(context) {
        context_.begin_save_operation();
        active_ = true;
    }

    ~ConfigOperationGuard() noexcept {
        if (!active_) return;
        try {
            context_.finish_config_operation();
        } catch (const std::exception& error) {
            Logger::instance().error(
                "Cannot release config save operation: {}", error.what());
        } catch (...) {
            Logger::instance().error(
                "Cannot release config save operation: unknown error");
        }
    }

    ConfigOperationGuard(const ConfigOperationGuard&) = delete;
    ConfigOperationGuard& operator=(const ConfigOperationGuard&) = delete;

    void finish() {
        if (!active_) return;
        context_.finish_config_operation();
        active_ = false;
    }

private:
    ApiContext& context_;
    bool active_{false};
};

} // namespace

std::string serialize_config_for_persistence(
    const Config& config) {
    return serialize_config_pretty(config);
}

namespace {

std::string commit_prepared_config_impl(
    ApiContext& ctx,
    std::string maintenance_operation,
    PrepareConfigCommit prepare,
    const std::function<void(
        const std::string&,
        const std::string&)>& write_config_file,
    const ConfigSaveRuntimeOptions& runtime_options) {
    try {
        auto maintenance =
            ctx.acquire_maintenance_lease(
                std::move(maintenance_operation));
        ConfigOperationGuard config_operation(ctx);
        auto prepared = prepare();

        LifecycleOperationSnapshot lifecycle;
        if (ctx.lifecycle_operations) {
            if (const auto active =
                    ctx.lifecycle_operations->begin(
                        LifecycleOperationType::ApplyConfig,
                        {
                            {"validate_config",
                             "Validate configuration"},
                            {"commit_and_apply",
                             "Commit and apply configuration"},
                        },
                        lifecycle)) {
                throw ApiError(
                    "A lifecycle operation is already active",
                    409,
                    nlohmann::json{
                        {"error",
                         "A lifecycle operation is already active"},
                        {"active_operation_id", *active}}
                        .dump());
            }
            ctx.lifecycle_operations->start_stage(
                lifecycle.id, "validate_config");
        }

        try {
            ctx.validate_candidate_config(prepared.config);
            if (ctx.lifecycle_operations) {
                ctx.lifecycle_operations->succeed_stage(
                    lifecycle.id, "validate_config");
                ctx.lifecycle_operations->start_stage(
                    lifecycle.id, "commit_and_apply");
            }
        } catch (const ConfigValidationError& error) {
            if (ctx.lifecycle_operations) {
                ctx.lifecycle_operations->fail_stage(
                    lifecycle.id,
                    "validate_config",
                    error.what());
                ctx.lifecycle_operations->finish(
                    lifecycle.id, error.what());
            }
            auto payload =
                make_validation_error_json(error);
            payload["saved"] = false;
            payload["applied"] = false;
            payload["rolled_back"] = false;
            throw ApiError(
                "Dry-run apply check failed",
                400,
                payload.dump());
        } catch (const std::exception& error) {
            if (ctx.lifecycle_operations) {
                ctx.lifecycle_operations->fail_stage(
                    lifecycle.id,
                    "validate_config",
                    error.what());
                ctx.lifecycle_operations->finish(
                    lifecycle.id, error.what());
            }
            throw ApiError(
                "Dry-run apply check failed",
                500,
                nlohmann::json{
                    {"error",
                     std::string(
                         "Dry-run apply check failed: ") +
                         error.what()},
                    {"saved", false},
                    {"applied", false},
                    {"rolled_back", false},
                }
                    .dump());
        }

        const bool includes_transports =
            prepared.transport.has_value();
        backup::PersistentLayout persistent_layout;
        std::unique_ptr<RestoreTransaction> transaction;
        std::string rollback_payload;
        std::optional<std::string>
            previous_transport_revision;
        try {
            persistent_layout = config_save_layout(
                ctx.config_path, includes_transports);

            std::vector<backup::FileReplacement>
                replacements;
            backup::FileReplacement config_replacement;
            config_replacement.path = ctx.config_path;
            config_replacement.content =
                prepared.serialized;
            config_replacement.max_content_bytes =
                backup::kMaxSnapshotBytes;
            replacements.push_back(
                std::move(config_replacement));

            if (prepared.transport.has_value()) {
                const auto configured_transport_path =
                    fs::path(
                        prepared.transport->config_path)
                        .lexically_normal();
                if (configured_transport_path !=
                    persistent_layout.transports
                        .lexically_normal()) {
                    throw std::runtime_error(
                        "Transport transaction target does "
                        "not match the managed transports "
                        "configuration");
                }
                backup::FileReplacement
                    transport_snapshot;
                transport_snapshot.path =
                    persistent_layout.transports;
                // The transport manager owns the forward
                // bytes. This replacement exists only to
                // capture an exact rollback entry.
                transport_snapshot.content.clear();
                transport_snapshot.max_content_bytes =
                    backup::kMaxSnapshotBytes;
                replacements.push_back(
                    std::move(transport_snapshot));
            }

            const auto mutations =
                backup::snapshot_replacements(
                    persistent_layout,
                    std::move(replacements));
            rollback_payload =
                backup::make_operation_snapshot(
                    mutations)
                    .dump();
            if (includes_transports) {
                const auto transport_snapshot =
                    std::find_if(
                        mutations.begin(),
                        mutations.end(),
                        [](const backup::FileMutation&
                               mutation) {
                            return mutation.kind ==
                                   backup::
                                       PersistentTargetKind::
                                           transports;
                        });
                if (transport_snapshot ==
                        mutations.end() ||
                    !transport_snapshot->before.existed) {
                    throw ApiError(
                        "Current transport configuration "
                        "is unavailable for rollback",
                        500);
                }
                previous_transport_revision =
                    Sha256::hex(
                        transport_snapshot->before.content);
                if (prepared.transport->base_revision.empty() ||
                    prepared.transport->base_revision !=
                        *previous_transport_revision) {
                    throw ApiError(
                        "Transport manager state does not "
                        "match the durable transport "
                        "configuration",
                        409,
                        nlohmann::json{
                            {"error",
                             "Transport manager state does "
                             "not match the durable "
                             "transport configuration"},
                            {"manager_revision",
                             prepared.transport
                                 ->base_revision},
                            {"durable_revision",
                             *previous_transport_revision},
                            {"saved", false},
                            {"applied", false},
                            {"rolled_back", false},
                        }
                            .dump());
                }
            }

            transaction =
                std::make_unique<RestoreTransaction>(
                    runtime_options.recovery_state_root,
                    RestoreTransactionOperation::
                        config_save);
        } catch (...) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Cannot prepare configuration recovery "
                "snapshot");
            throw;
        }

        std::vector<RestoreJournalEffect> effects{
            RestoreJournalEffect::files,
        };
        if (includes_transports) {
            effects.push_back(
                RestoreJournalEffect::
                    transport_manager);
        }
        effects.push_back(RestoreJournalEffect::core);
        try {
            transaction->begin(
                secure_transaction_id(),
                rollback_payload,
                std::move(effects));
        } catch (const std::exception& error) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Cannot start configuration recovery "
                "journal");
            throw_recovery_required(
                ctx,
                std::string(
                    "Cannot start the durable "
                    "configuration recovery journal: ") +
                    error.what(),
                false,
                false);
        } catch (...) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Cannot start configuration recovery "
                "journal");
            throw_recovery_required(
                ctx,
                "Cannot start the durable configuration "
                "recovery journal",
                false,
                false);
        }

        std::optional<std::string>
            committed_transport_revision;
        const auto rollback_transport =
            [&prepared,
             &previous_transport_revision]() {
                if (!prepared.transport.has_value() ||
                    !previous_transport_revision
                         .has_value()) {
                    return;
                }
                prepared.transport->restore_revision(
                    *previous_transport_revision);
            };

        try {
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::wal_started);
            (void)maintenance->reserve(
                maintenance->base_generation());
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::
                    generation_reserved);

            if (prepared.transport.has_value()) {
                committed_transport_revision =
                    prepared.transport->mutate();
                if (committed_transport_revision->empty()) {
                    throw std::runtime_error(
                        "Transport manager did not return "
                        "the committed configuration "
                        "revision");
                }
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::
                        transport_mutated);
            }

            write_config_file(
                ctx.config_path, prepared.serialized);
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::config_written);

            transaction->files_committed();
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::files_committed);

            if (prepared.transport.has_value()) {
                prepared.transport->verify_revision(
                    *committed_transport_revision);
                transaction->transports_ready();
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::
                        transports_ready);
            }
        } catch (
            const ConfigCommitNoMutationConflict&) {
            // The CAS contract proves that this operation
            // changed neither the transport file nor
            // manager state. Restoring our older snapshot
            // here would clobber the concurrent winner.
            try {
                transaction->complete_rollback();
            } catch (const std::exception& error) {
                mark_config_save_unknown_best_effort(
                    runtime_options, *transaction);
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Cannot close the prepared "
                    "configuration recovery journal");
                throw_recovery_required(
                    ctx,
                    std::string(
                        "Transport configuration changed "
                        "before this operation mutated "
                        "state, but its recovery journal "
                        "could not be closed: ") +
                        error.what(),
                    false,
                    false);
            } catch (...) {
                mark_config_save_unknown_best_effort(
                    runtime_options, *transaction);
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Cannot close the prepared "
                    "configuration recovery journal");
                throw_recovery_required(
                    ctx,
                    "Transport configuration changed "
                    "before this operation mutated state, "
                    "but its recovery journal could not "
                    "be closed",
                    false,
                    false);
            }
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Transport configuration changed");
            throw;
        } catch (...) {
            const auto original_failure =
                std::current_exception();
            std::string recovery_error;
            if (!restore_exact_config_snapshot(
                    runtime_options,
                    persistent_layout,
                    rollback_transport,
                    recovery_error)) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration file recovery failed");
                throw_recovery_required(
                    ctx,
                    "Configuration write failed and exact "
                    "recovery could not be proven",
                    false,
                    false,
                    recovery_error);
            }
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration write failed");
            std::rethrow_exception(original_failure);
        }

        ConfigApplyResult apply_result;
        try {
            apply_result =
                ctx.enqueue_apply_validated_config(
                    prepared.config,
                    prepared.serialized);
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::apply_returned);
        } catch (const ApiError&) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration runtime apply was "
                "interrupted");
            throw_recovery_required(
                ctx,
                "Configuration runtime apply was "
                "interrupted; runtime state is unknown",
                false,
                false);
        } catch (const std::exception& error) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration runtime apply was "
                "interrupted");
            throw_recovery_required(
                ctx,
                std::string(
                    "Configuration runtime apply was "
                    "interrupted: ") +
                    error.what(),
                false,
                false);
        } catch (...) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration runtime apply was "
                "interrupted");
            throw_recovery_required(
                ctx,
                "Configuration runtime apply was "
                "interrupted; runtime state is unknown",
                false,
                false);
        }

        if (!apply_result.error.empty() ||
            !apply_result.applied) {
            if (!apply_result.rolled_back &&
                !apply_result.runtime_unchanged) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration runtime rollback was "
                    "not proven");
                throw_recovery_required(
                    ctx,
                    apply_result.error.empty()
                        ? "Configuration was not applied "
                          "and runtime rollback was not "
                          "proven"
                        : std::string(
                              "Commit/apply failed: ") +
                              apply_result.error,
                    apply_result.applied,
                    false);
            }

            std::string recovery_error;
            if (!restore_exact_config_snapshot(
                    runtime_options,
                    persistent_layout,
                    rollback_transport,
                    recovery_error)) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration file recovery failed");
                throw_recovery_required(
                    ctx,
                    "Runtime rolled back, but exact "
                    "persistent recovery could not be "
                    "proven",
                    apply_result.applied,
                    true,
                    recovery_error);
            }

            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration commit or apply failed");
            throw ApiError(
                "Commit/apply failed",
                500,
                nlohmann::json{
                    {"error",
                     apply_result.error.empty()
                         ? "Configuration was not applied"
                         : std::string(
                               "Commit/apply failed: ") +
                               apply_result.error},
                    {"saved", false},
                    {"applied", apply_result.applied},
                    {"rolled_back", apply_result.rolled_back},
                    {"runtime_unchanged",
                     apply_result.runtime_unchanged},
                    {"file_rolled_back", true},
                    {"recovery_required", false},
                }
                    .dump());
        }

        try {
            maintenance->verify_held();
            transaction->core_applied();
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::core_applied);
            transaction->commit();
        } catch (const std::exception& error) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration recovery journal commit "
                "failed");
            throw_recovery_required(
                ctx,
                std::string(
                    "Configuration applied, but its "
                    "recovery journal could not be "
                    "committed: ") +
                    error.what(),
                true,
                false);
        } catch (...) {
            fail_lifecycle_best_effort(
                ctx,
                lifecycle,
                "Configuration recovery journal commit "
                "failed");
            throw_recovery_required(
                ctx,
                "Configuration applied, but its recovery "
                "journal could not be committed",
                true,
                false);
        }

        inject_config_save_fault(
            runtime_options,
            ConfigSaveCheckpoint::wal_committed);

        nlohmann::json response = {
            {"status", prepared.success_status},
            {"message", prepared.success_message},
            {"saved", true},
            {"applied", true},
            {"rolled_back", apply_result.rolled_back},
            {"config_revision",
             Sha256::hex(prepared.serialized)},
        };
        if (committed_transport_revision.has_value()) {
            response["transport_revision"] =
                *committed_transport_revision;
        }
        if (apply_result.apply_started_ts.has_value()) {
            response["apply_started_ts"] =
                *apply_result.apply_started_ts;
        }
        if (ctx.lifecycle_operations) {
            ctx.lifecycle_operations->succeed_stage(
                lifecycle.id, "commit_and_apply");
            ctx.lifecycle_operations->finish(lifecycle.id);
        }
        config_operation.finish();
        return response.dump();
    } catch (const MaintenanceLockError& error) {
        throw_maintenance_api_error(error);
    }
}

} // namespace

std::string commit_prepared_config(
    ApiContext& ctx,
    std::string maintenance_operation,
    PrepareConfigCommit prepare) {
    return commit_prepared_config_impl(
        ctx,
        std::move(maintenance_operation),
        std::move(prepare),
        [](const std::string& path,
           const std::string& body) {
            write_config_atomically(path, body);
        },
        ConfigSaveRuntimeOptions{});
}

#ifdef KEEN_PBR3_TESTING
std::string commit_prepared_config_for_test(
    ApiContext& ctx,
    std::string maintenance_operation,
    PrepareConfigCommit prepare,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options) {
    ConfigSaveRuntimeOptions runtime_options;
    runtime_options.recovery_state_root =
        options.recovery_state_root.empty()
            ? fs::path(ctx.config_path).parent_path() /
                  ".keen-pbr-recovery"
            : std::move(options.recovery_state_root);
    runtime_options.fault_injector =
        std::move(options.fault_injector);
    return commit_prepared_config_impl(
        ctx,
        std::move(maintenance_operation),
        std::move(prepare),
        std::move(write_config_file),
        std::move(runtime_options));
}
#endif

static void register_config_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    std::function<void(const std::string&, const std::string&)>
        write_config_file,
    ConfigSaveRuntimeOptions runtime_options) {
    // GET /api/config - return current config and whether it is staged in memory
    server.get("/api/config", [&ctx]() -> std::string {
        const auto visible_snapshot =
            ctx.get_visible_config_state();
        const Config visible_config =
            normalize_config_for_api_response(
                visible_snapshot.config);
        const auto list_refresh_state = ctx.get_list_refresh_state_map(visible_config);
        nlohmann::json response = {
            {"config", nlohmann::json(visible_config)},
            {"is_draft", visible_snapshot.is_draft},
            {"revision", visible_snapshot.revision},
            {"list_refresh_state", nlohmann::json(list_refresh_state)},
        };
        return response.dump();
    });

    const auto parse_validated_candidate =
        [](const std::string& body) -> Config {
        Config staged;
        try {
            staged = parse_config(body);
            validate_config(staged);
        } catch (const ConfigValidationError& e) {
            throw ApiError(e.what(), 400, make_validation_error_json(e).dump());
        } catch (const ConfigError& e) {
            nlohmann::json payload = {
                {"error", e.what()},
                {"validation_errors", nlohmann::json::array({
                    {{"path", "$"}, {"message", e.what()}},
                })},
            };
            throw ApiError(e.what(), 400, payload.dump());
        }
        return staged;
    };

    // POST /api/config - validate and stage in memory only
    server.post(
        "/api/config",
        [&ctx, parse_validated_candidate](
            const std::string& body) -> std::string {
        Config staged = parse_validated_candidate(body);
        std::string formatted_config = serialize_config_pretty(staged);
        ConfigOperationGuard config_operation(ctx);
        ctx.stage_config(std::move(staged), std::move(formatted_config));
        config_operation.finish();

        api::ConfigUpdateResponse resp;
        resp.status = api::ConfigUpdateResponseStatus::OK;
        resp.message = "Config staged in memory";
        return nlohmann::json(resp).dump();
    });

    // The simple list dialog uses a narrower, backend-authoritative contract
    // than the advanced editor. It cannot stage a route-only configuration:
    // the candidate must contain one dedicated route rule and one compatible
    // DNS rule for the new list.
    server.post(
        "/api/setup/list/stage",
        [&ctx, parse_validated_candidate](
            const std::string& body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(body);
            } catch (const nlohmann::json::exception& error) {
                throw ApiError(
                    std::string("Invalid JSON request: ") + error.what(),
                    400);
            }
            if (!request.is_object() ||
                !request.contains("config") ||
                !request.at("config").is_object() ||
                !request.contains("list_id") ||
                !request.at("list_id").is_string() ||
                request.at("list_id").get_ref<const std::string&>().empty() ||
                !request.contains("base_revision") ||
                !request.at("base_revision").is_string() ||
                !is_lowercase_sha256_digest(
                    request.at("base_revision").get_ref<
                        const std::string&>())) {
                throw ApiError(
                    "Recommended list setup requires config, list_id, and "
                    "a lowercase SHA-256 base_revision",
                    400,
                    nlohmann::json{
                        {"error",
                         "Recommended list setup requires config, list_id, "
                         "and a lowercase SHA-256 base_revision"},
                        {"reason", "recommended_list_setup_invalid"},
                    }
                        .dump());
            }

            Config staged = parse_validated_candidate(
                request.at("config").dump());
            try {
                setup::validate_recommended_list_setup(
                    staged,
                    request.at("list_id").get<std::string>());
            } catch (const std::invalid_argument& error) {
                throw ApiError(
                    error.what(),
                    400,
                    nlohmann::json{
                        {"error", error.what()},
                        {"reason", "recommended_list_setup_invalid"},
                    }
                        .dump());
            }

            std::string formatted_config =
                serialize_config_pretty(staged);
            ConfigOperationGuard config_operation(ctx);
            const std::string requested_base_revision =
                request.at("base_revision").get<std::string>();
            if (!ctx.stage_config_if_visible_revision(
                    requested_base_revision,
                    std::move(staged),
                    std::move(formatted_config))) {
                const VisibleConfigSnapshot current =
                    ctx.get_visible_config_snapshot();
                const std::string message =
                    "The visible configuration changed after this list "
                    "setup was opened";
                throw ApiError(
                    message,
                    409,
                    nlohmann::json{
                        {"error", message},
                        {"reason", "base_revision_mismatch"},
                        {"base_revision", requested_base_revision},
                        {"current_base_revision", current.revision},
                        {"draft_preserved", current.is_draft},
                        {"staged", false},
                    }
                        .dump());
            }
            config_operation.finish();

            api::ConfigUpdateResponse response;
            response.status = api::ConfigUpdateResponseStatus::OK;
            response.message =
                "Recommended list setup staged in memory";
            return nlohmann::json(response).dump();
        });

    // POST /api/config/save - persist the staged candidate through the shared
    // durable commit coordinator used by composite transport creation.
    server.post(
        "/api/config/save",
        [&ctx,
         write_config_file = std::move(write_config_file),
         runtime_options = std::move(runtime_options)]()
            -> std::string {
            return commit_prepared_config_impl(
                ctx,
                "config-save",
                [&ctx]() -> PreparedConfigCommit {
                    const auto staged_snapshot =
                        ctx.get_staged_config_cas_snapshot();
                    if (!staged_snapshot.has_value()) {
                        throw ApiError(
                            "No staged config to save", 400);
                    }
                    if (!staged_snapshot->base_revision.empty() &&
                        staged_snapshot->base_revision !=
                            staged_snapshot->active_revision) {
                        const std::string message =
                            "The active configuration changed after this "
                            "draft was created";
                        throw ApiError(
                            message,
                            409,
                            nlohmann::json{
                                {"error", message},
                                {"reason",
                                 "draft_base_revision_mismatch"},
                                {"base_revision",
                                 staged_snapshot->base_revision},
                                {"active_revision",
                                 staged_snapshot->active_revision},
                                {"draft_preserved", true},
                                {"saved", false},
                                {"applied", false},
                            }
                                .dump());
                    }
                    PreparedConfigCommit prepared;
                    prepared.config = staged_snapshot->config;
                    prepared.serialized =
                        staged_snapshot->serialized;
                    return prepared;
                },
                write_config_file,
                runtime_options);
        });
}

void register_config_handler(ApiServer& server, ApiContext& ctx) {
    register_config_handler_impl(
        server,
        ctx,
        [](const std::string& path, const std::string& body) {
            write_config_atomically(path, body);
        },
        ConfigSaveRuntimeOptions{});
}

#ifdef KEEN_PBR3_TESTING
void register_config_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options) {
    ConfigSaveRuntimeOptions runtime_options;
    runtime_options.recovery_state_root =
        options.recovery_state_root.empty()
            ? fs::path(ctx.config_path).parent_path() /
                  ".keen-pbr-recovery"
            : std::move(options.recovery_state_root);
    runtime_options.fault_injector =
        std::move(options.fault_injector);
    register_config_handler_impl(
        server,
        ctx,
        std::move(write_config_file),
        std::move(runtime_options));
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
