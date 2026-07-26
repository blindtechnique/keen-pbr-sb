#ifdef WITH_API

#include "handler_config.hpp"
#include "maintenance_api.hpp"
#include "generated/api_types.hpp"

#include "../backup/persistent_snapshot.hpp"
#include "../backup/recovery_coordinator.hpp"
#include "../backup/restore_transaction.hpp"
#include "../config/config.hpp"
#include "../config/config_writer.hpp"
#include "../log/logger.hpp"
#include <nlohmann/json.hpp>

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

enum class ConfigSaveCheckpoint {
    wal_started,
    generation_reserved,
    config_written,
    files_committed,
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
    const std::string& config_path) {
    backup::PersistentLayout layout;
    layout.config = config_path;
    // Operation snapshots identify the file as "config"; the other roots are
    // intentionally inert for this one-file transaction.
    layout.transports =
        fs::path(config_path).parent_path() /
        ".keen-pbr-unused-transports.json";
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
    std::string& failure) noexcept {
    try {
        backup::RecoveryCoordinator coordinator({
            options.recovery_state_root,
            persistent_layout,
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

static void register_config_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    std::function<void(const std::string&, const std::string&)>
        write_config_file,
    ConfigSaveRuntimeOptions runtime_options) {
    // GET /api/config - return current config and whether it is staged in memory
    server.get("/api/config", [&ctx]() -> std::string {
        const Config visible_config =
            normalize_config_for_api_response(ctx.get_visible_config());
        const bool is_draft = ctx.config_is_draft();
        const auto list_refresh_state = ctx.get_list_refresh_state_map(visible_config);
        nlohmann::json response = {
            {"config", nlohmann::json(visible_config)},
            {"is_draft", is_draft},
            {"list_refresh_state", nlohmann::json(list_refresh_state)},
        };
        return response.dump();
    });

    // POST /api/config - validate and stage in memory only
    server.post("/api/config", [&ctx](const std::string& body) -> std::string {
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

        std::string formatted_config = serialize_config_pretty(staged);
        ctx.stage_config(std::move(staged), std::move(formatted_config));

        api::ConfigUpdateResponse resp;
        resp.status = api::ConfigUpdateResponseStatus::OK;
        resp.message = "Config staged in memory";
        return nlohmann::json(resp).dump();
    });

    // POST /api/config/save - dry-run check, persist staged config, apply immediately
    server.post(
        "/api/config/save",
        [&ctx,
         write_config_file = std::move(write_config_file),
         runtime_options = std::move(runtime_options)]()
            -> std::string {
          try {
            auto maintenance =
                ctx.acquire_maintenance_lease("config-save");
            ConfigOperationGuard config_operation(ctx);

            const auto staged_snapshot =
                ctx.get_staged_config_snapshot();

            if (!staged_snapshot.has_value()) {
                throw ApiError("No staged config to save", 400);
            }

            LifecycleOperationSnapshot lifecycle;
            if (ctx.lifecycle_operations) {
                if (const auto active = ctx.lifecycle_operations->begin(
                        LifecycleOperationType::ApplyConfig,
                        {{"validate_config", "Validate configuration"},
                        {"commit_and_apply",
                          "Commit and apply configuration"}},
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

            // Phase 1: validation + dry-run apply check.
            try {
                ctx.validate_candidate_config(staged_snapshot->first);
                if (ctx.lifecycle_operations) {
                    ctx.lifecycle_operations->succeed_stage(
                        lifecycle.id, "validate_config");
                    ctx.lifecycle_operations->start_stage(
                        lifecycle.id, "commit_and_apply");
                }
            } catch (const ConfigValidationError& e) {
                if (ctx.lifecycle_operations) {
                    ctx.lifecycle_operations->fail_stage(
                        lifecycle.id, "validate_config", e.what());
                    ctx.lifecycle_operations->finish(lifecycle.id, e.what());
                }
                nlohmann::json error_payload =
                    make_validation_error_json(e);
                error_payload["saved"] = false;
                error_payload["applied"] = false;
                error_payload["rolled_back"] = false;
                throw ApiError(
                    "Dry-run apply check failed",
                    400,
                    error_payload.dump());
            } catch (const std::exception& e) {
                if (ctx.lifecycle_operations) {
                    ctx.lifecycle_operations->fail_stage(
                        lifecycle.id, "validate_config", e.what());
                    ctx.lifecycle_operations->finish(lifecycle.id, e.what());
                }
                nlohmann::json error_payload = {
                    {"error",
                     std::string("Dry-run apply check failed: ") + e.what()},
                    {"saved", false},
                    {"applied", false},
                    {"rolled_back", false},
                };
                throw ApiError(
                    "Dry-run apply check failed",
                    500,
                    error_payload.dump());
            }

            // Phase 2: exact persistent snapshot + crash journal + apply.
            //
            // RestoreTransaction is the sole owner of on-disk rollback. The
            // runtime apply result is the sole source of truth about whether
            // the old runtime was restored. Mixing a manual file rollback
            // with an unknown runtime would make the next boot unsafe.
            backup::PersistentLayout persistent_layout;
            std::unique_ptr<RestoreTransaction> transaction;
            std::string rollback_payload;
            try {
                persistent_layout =
                    config_save_layout(ctx.config_path);
                backup::FileReplacement replacement;
                replacement.path = ctx.config_path;
                replacement.content = staged_snapshot->second;
                replacement.max_content_bytes =
                    backup::kMaxSnapshotBytes;
                const auto mutations =
                    backup::snapshot_replacements(
                        persistent_layout,
                        {std::move(replacement)});
                rollback_payload =
                    backup::make_operation_snapshot(
                        mutations)
                        .dump();

                transaction =
                    std::make_unique<RestoreTransaction>(
                        runtime_options.recovery_state_root,
                        RestoreTransactionOperation::config_save);
            } catch (...) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Cannot prepare configuration recovery snapshot");
                throw;
            }

            try {
                transaction->begin(
                    secure_transaction_id(),
                    rollback_payload,
                    {
                        RestoreJournalEffect::files,
                        RestoreJournalEffect::core,
                    });
            } catch (const std::exception& error) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Cannot start configuration recovery journal");
                throw_recovery_required(
                    ctx,
                    std::string(
                        "Cannot start the durable configuration recovery "
                        "journal: ") +
                        error.what(),
                    false,
                    false);
            } catch (...) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Cannot start configuration recovery journal");
                throw_recovery_required(
                    ctx,
                    "Cannot start the durable configuration recovery journal",
                    false,
                    false);
            }

            // Failures before runtime apply can be recovered immediately and
            // proven exactly from the immutable operation snapshot.
            try {
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::wal_started);
                (void)maintenance->reserve(
                    maintenance->base_generation());
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::generation_reserved);

                write_config_file(
                    ctx.config_path, staged_snapshot->second);
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::config_written);

                transaction->files_committed();
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::files_committed);
            } catch (...) {
                const auto original_failure =
                    std::current_exception();
                std::string recovery_error;
                if (!restore_exact_config_snapshot(
                        runtime_options,
                        persistent_layout,
                        recovery_error)) {
                    fail_lifecycle_best_effort(
                        ctx,
                        lifecycle,
                        "Configuration file recovery failed");
                    throw_recovery_required(
                        ctx,
                        "Configuration write failed and exact recovery "
                        "could not be proven",
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
                        staged_snapshot->first,
                        staged_snapshot->second);
                inject_config_save_fault(
                    runtime_options,
                    ConfigSaveCheckpoint::apply_returned);
            } catch (const ApiError&) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration runtime apply was interrupted");
                throw_recovery_required(
                    ctx,
                    "Configuration runtime apply was interrupted; "
                    "runtime state is unknown",
                    false,
                    false);
            } catch (const std::exception& error) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration runtime apply was interrupted");
                throw_recovery_required(
                    ctx,
                    std::string(
                        "Configuration runtime apply was interrupted: ") +
                        error.what(),
                    false,
                    false);
            } catch (...) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration runtime apply was interrupted");
                throw_recovery_required(
                    ctx,
                    "Configuration runtime apply was interrupted; "
                    "runtime state is unknown",
                    false,
                    false);
            }

            if (!apply_result.error.empty() ||
                !apply_result.applied) {
                if (!apply_result.rolled_back) {
                    fail_lifecycle_best_effort(
                        ctx,
                        lifecycle,
                        "Configuration runtime rollback was not proven");
                    throw_recovery_required(
                        ctx,
                        apply_result.error.empty()
                            ? "Configuration was not applied and runtime "
                              "rollback was not proven"
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
                        recovery_error)) {
                    fail_lifecycle_best_effort(
                        ctx,
                        lifecycle,
                        "Configuration file recovery failed");
                    throw_recovery_required(
                        ctx,
                        "Runtime rolled back, but exact config-file "
                        "recovery could not be proven",
                        apply_result.applied,
                        true,
                        recovery_error);
                }

                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration commit or apply failed");
                nlohmann::json error_payload = {
                    {"error",
                     apply_result.error.empty()
                         ? "Configuration was not applied"
                         : std::string("Commit/apply failed: ") +
                               apply_result.error},
                    {"saved", false},
                    {"applied", apply_result.applied},
                    {"rolled_back", true},
                    {"file_rolled_back", true},
                    {"recovery_required", false},
                };
                throw ApiError(
                    "Commit/apply failed",
                    500,
                    error_payload.dump());
            }

            // After a successful runtime apply, any failure before the durable
            // WAL commit has an unknown cross-layer state. Never roll back
            // only the file; quiesce routing and leave the journal active for
            // startup recovery.
            try {
                // reserve() proves ownership before the file mutation. The
                // runtime apply may take long enough for a dead guardian to
                // be reaped and a competing updater to acquire the lock, so
                // prove ownership again at the durable cross-layer boundary.
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
                    "Configuration recovery journal commit failed");
                throw_recovery_required(
                    ctx,
                    std::string(
                        "Configuration applied, but its recovery journal "
                        "could not be committed: ") +
                        error.what(),
                    true,
                    false);
            } catch (...) {
                fail_lifecycle_best_effort(
                    ctx,
                    lifecycle,
                    "Configuration recovery journal commit failed");
                throw_recovery_required(
                    ctx,
                    "Configuration applied, but its recovery journal "
                    "could not be committed",
                    true,
                    false);
            }

            // This is the durable cross-layer commit point. Nothing below may
            // trigger a file rollback, even if lifecycle publication or HTTP
            // response bookkeeping fails.
            inject_config_save_fault(
                runtime_options,
                ConfigSaveCheckpoint::wal_committed);

            nlohmann::json response = {
                {"status", "ok"},
                {"message", "Config saved and applied"},
                {"saved", true},
                {"applied", true},
                {"rolled_back", apply_result.rolled_back},
            };
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
