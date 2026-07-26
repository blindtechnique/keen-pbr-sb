#ifdef WITH_API

#include "handler_backup.hpp"
#include "maintenance_api.hpp"

#include "../backup/persistent_snapshot.hpp"
#include "generated/api_types.hpp"
#include "../config/config.hpp"
#include "../crypto/sha256.hpp"
#include "../log/logger.hpp"
#include "../util/base64.hpp"
#include "../util/safe_exec.hpp"

#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <httplib.h>
#include <iterator>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;
namespace persistent = backup;
constexpr std::size_t kMaxBackupBytes =
    persistent::kMaxSnapshotBytes;
constexpr std::size_t kMaxBackupFileBytes =
    persistent::kMaxManagedFileBytes;
constexpr std::size_t kMaxBackupFiles =
    persistent::kMaxManagedFiles;
constexpr const char* kRollbackPath = "/opt/etc/keen-pbr/rollback-backup.json";
constexpr const char* kBase64Encoding = "base64";
constexpr const char* kBackupFormat = "keen-pbr-sb-backup";
constexpr const char* kRollbackFormat =
    persistent::kPersistentSnapshotFormat;
constexpr int kBackupSchema = 1;
constexpr std::size_t kServiceReadinessAttempts = 20U;
constexpr auto kServiceReadinessDelay = std::chrono::milliseconds(250);
constexpr auto kServiceReadinessTimeout = std::chrono::seconds(5);
constexpr auto kServiceProbeTimeout = std::chrono::milliseconds(200);
constexpr auto kServiceProbeKillGrace = std::chrono::milliseconds(50);

enum class ServiceReadiness {
    starting,
    ready,
    failed,
};

struct RestoreExecutionHooks {
    std::function<void(const fs::path&, AtomicFileWriteStage)>
        atomic_write_fault;
    std::function<void(std::size_t, const fs::path&)>
        before_forward_write;
    std::function<void()> after_forward_runtime_apply;
    std::function<void(const std::string&)>
        before_forward_service_restart;
    std::function<void(std::size_t, const fs::path&)>
        before_rollback_write;
    std::function<ServiceReadiness(const std::string&)>
        probe_service_readiness;
    std::function<ServiceReadiness(const std::string&)>
        probe_transport_config_revision;
    std::function<void()> wait_before_service_probe;
};

persistent::FileApplyHooks file_apply_hooks(
    const RestoreExecutionHooks& hooks) {
    persistent::FileApplyHooks result;
    result.atomic_write_fault = hooks.atomic_write_fault;
    result.before_forward_write =
        hooks.before_forward_write;
    result.before_rollback_write =
        hooks.before_rollback_write;
    return result;
}

[[noreturn]] void throw_persistent_snapshot_api_error(
    const persistent::PersistentSnapshotError& error) {
    switch (error.kind()) {
    case persistent::PersistentSnapshotErrorKind::invalid_document:
        throw ApiError(error.what(), 400);
    case persistent::PersistentSnapshotErrorKind::limit_exceeded:
        throw ApiError(error.what(), 413);
    case persistent::PersistentSnapshotErrorKind::unsafe_local_state:
    case persistent::PersistentSnapshotErrorKind::io_failure:
    case persistent::PersistentSnapshotErrorKind::internal:
        throw ApiError(error.what(), 500);
    }
    throw ApiError(error.what(), 500);
}

template <typename Callable>
decltype(auto) with_persistent_snapshot_errors(
    Callable&& callable) {
    try {
        return std::forward<Callable>(callable)();
    } catch (
        const persistent::PersistentSnapshotError& error) {
        throw_persistent_snapshot_api_error(error);
    }
}

std::string read_text(const fs::path& path) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxBackupBytes) throw ApiError("backup source is missing or too large", 400);
    std::ifstream input(path, std::ios::binary);
    if (!input) throw ApiError("cannot read backup source", 500);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

using FileReplacement = persistent::FileReplacement;
using FileMutationPlan = persistent::FileMutationPlan;

void reject_nul_path(const std::string& value,
                     const char* error_message) {
    if (value.find('\0') != std::string::npos) {
        throw ApiError(error_message, 400);
    }
}

void validate_confined_restore_target(const fs::path& root,
                                      const fs::path& target) {
    persistent::validate_confined_target(root, target);
}

std::string exception_message(std::exception_ptr error) {
    if (!error) return "unknown restore failure";
    try {
        std::rethrow_exception(error);
    } catch (const std::exception& exception) {
        return exception.what();
    } catch (...) {
        return "unknown restore failure";
    }
}

int restart_restore_service(const ApiContext& ctx,
                            const std::string& init_script) {
    if (ctx.restart_restore_service_fn) {
        return ctx.restart_restore_service_fn(init_script);
    }
    return safe_exec({init_script, "restart"}, true);
}

ServiceReadiness probe_restore_service(
    const ApiContext& ctx,
    const RestoreExecutionHooks& hooks,
    const std::string& init_script,
    std::chrono::milliseconds timeout) {
    if (hooks.probe_service_readiness) {
        return hooks.probe_service_readiness(init_script);
    }
    // Unit-test and embedding callbacks historically model a complete,
    // synchronous restart. Preserve that contract unless the caller supplied
    // an explicit readiness probe.
    if (ctx.restart_restore_service_fn) return ServiceReadiness::ready;
    const int status = safe_exec_with_timeouts(
        {init_script, "check"},
        true,
        {
            std::max(std::chrono::milliseconds(1), timeout),
            kServiceProbeKillGrace,
        });
    if (status == 0) return ServiceReadiness::ready;
    if (status == -1 || status == 126 || status == 127) {
        return ServiceReadiness::failed;
    }
    return ServiceReadiness::starting;
}

ServiceReadiness probe_transport_config_revision(
    const ApiContext& ctx,
    const RestoreExecutionHooks& hooks,
    const std::string& expected_revision) {
    if (hooks.probe_transport_config_revision) {
        return hooks.probe_transport_config_revision(
            expected_revision);
    }
    // Unit-test restart callbacks model a complete synchronous restart. Tests
    // that need to assert revision hand-off provide the explicit hook above.
    if (ctx.restart_restore_service_fn) return ServiceReadiness::ready;

    try {
        const auto transports_path =
            fs::path(ctx.config_path).parent_path() /
            "transports.json";
        const auto config =
            nlohmann::json::parse(read_text(transports_path));
        const auto listen =
            config.value("listen", std::string("127.0.0.1:12122"));
        const auto separator = listen.rfind(':');
        if (separator == std::string::npos) {
            return ServiceReadiness::failed;
        }
        const auto host = listen.substr(0, separator);
        if (host != "127.0.0.1" && host != "localhost") {
            return ServiceReadiness::failed;
        }
        const int port = std::stoi(listen.substr(separator + 1));
        if (port <= 0 || port > 65535) {
            return ServiceReadiness::failed;
        }

        httplib::Client client(host, port);
        client.set_connection_timeout(0, 200000);
        client.set_read_timeout(0, 200000);
        const auto response = client.Get("/healthz");
        if (!response || response->status < 200 ||
            response->status >= 300) {
            return ServiceReadiness::starting;
        }
        const auto health =
            nlohmann::json::parse(response->body);
        if (!health.is_object() ||
            health.value("status", std::string{}) != "ok") {
            return ServiceReadiness::failed;
        }
        if (!health.contains("config_revision") ||
            !health.at("config_revision").is_string()) {
            return ServiceReadiness::starting;
        }
        return health.at("config_revision").get_ref<
                       const std::string&>() == expected_revision
                   ? ServiceReadiness::ready
                   : ServiceReadiness::starting;
    } catch (const std::exception&) {
        // The manager may not have bound its socket yet. The bounded readiness
        // loop decides whether this is transient or a failed restart.
        return ServiceReadiness::starting;
    }
}

void wait_for_restore_service_ready(
    const ApiContext& ctx,
    const RestoreExecutionHooks& hooks,
    const std::string& init_script,
    const std::optional<std::string>&
        expected_transport_revision = std::nullopt) {
    const auto deadline =
        std::chrono::steady_clock::now() + kServiceReadinessTimeout;
    for (std::size_t attempt = 0;
         attempt < kServiceReadinessAttempts;
         ++attempt) {
        const auto before_probe = std::chrono::steady_clock::now();
        if (before_probe >= deadline) break;
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - before_probe);
        const auto state =
            probe_restore_service(
                ctx,
                hooks,
                init_script,
                std::min(kServiceProbeTimeout, remaining));
        if (state == ServiceReadiness::ready) {
            if (!expected_transport_revision.has_value()) return;
            const auto revision_state =
                probe_transport_config_revision(
                    ctx,
                    hooks,
                    *expected_transport_revision);
            if (revision_state == ServiceReadiness::ready) return;
            if (revision_state == ServiceReadiness::failed) {
                throw ApiError(
                    "transport manager rejected the restored configuration",
                    500);
            }
        }
        if (state == ServiceReadiness::failed) {
            throw ApiError(
                "service stopped immediately after restart: " +
                    init_script,
                500);
        }
        if (attempt + 1U == kServiceReadinessAttempts) break;
        const auto after_probe = std::chrono::steady_clock::now();
        if (after_probe >= deadline) break;
        if (hooks.wait_before_service_probe) {
            hooks.wait_before_service_probe();
        } else {
            std::this_thread::sleep_for(std::min(
                kServiceReadinessDelay,
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - after_probe)));
        }
    }
    throw ApiError(
        "service did not become ready before timeout: " + init_script,
        500);
}

bool selected(const nlohmann::json& groups, const char* name) {
    if (!groups.is_object())
        throw ApiError("invalid backup groups", 400);
    const auto value = groups.find(name);
    if (value == groups.end()) return false;
    if (!value->is_boolean())
        throw ApiError("invalid backup group selection", 400);
    return value->get<bool>();
}

using NfqwsBackupGroup = persistent::NfqwsFileGroup;
using NfqwsSelection = persistent::NfqwsSelection;

NfqwsSelection nfqws_selection(const nlohmann::json& groups) {
    const bool has_split_selection =
        groups.contains("nfqws_config") || groups.contains("nfqws_lists");
    if (has_split_selection) {
        return {
            selected(groups, "nfqws_config"),
            selected(groups, "nfqws_lists"),
        };
    }

    const bool legacy_selected = selected(groups, "nfqws");
    return {legacy_selected, legacy_selected};
}

std::optional<NfqwsSelection> declared_nfqws_selection(
    const nlohmann::json& backup) {
    if (!backup.contains("groups")) return std::nullopt;
    if (!backup.at("groups").is_object()) {
        throw ApiError("invalid backup groups", 400);
    }
    const auto& groups = backup.at("groups");
    if (!groups.contains("nfqws") &&
        !groups.contains("nfqws_config") &&
        !groups.contains("nfqws_lists")) {
        return std::nullopt;
    }
    return nfqws_selection(groups);
}

bool has_unsafe_path_component(const fs::path& path) {
    return std::any_of(
        path.begin(), path.end(), [](const fs::path& component) {
            return component == ".." || component == ".";
        });
}

void add_nfqws_tree(nlohmann::json& files,
                    const fs::path& root,
                    const std::string& prefix,
                    const NfqwsSelection& selection,
                    std::size_t& total_bytes,
                    std::size_t& file_count) {
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return;
    for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
        if (ec || entry.is_symlink(ec) || !entry.is_regular_file(ec)) continue;
        const auto relative = fs::relative(entry.path(), root, ec);
        if (ec || relative.empty()) continue;
        const fs::path backup_path = fs::path(prefix) / relative;
        const auto group =
            persistent::classify_nfqws_path(backup_path);
        if (!group.has_value() || !selection.includes(*group)) continue;
        const auto file_size = entry.file_size(ec);
        if (ec) continue;
        if (file_size > kMaxBackupFileBytes)
            throw ApiError("backup contains a file larger than the per-file limit", 413);
        if (file_count >= kMaxBackupFiles ||
            file_size >
                static_cast<std::uintmax_t>(
                    kMaxBackupBytes - total_bytes))
            throw ApiError("backup content exceeds the aggregate limit", 413);
        ++file_count;
        const auto value = read_text(entry.path());
        if (value.size() > kMaxBackupFileBytes ||
            value.size() > kMaxBackupBytes - total_bytes) {
            throw ApiError(
                "backup content exceeds the aggregate limit", 413);
        }
        total_bytes += value.size();
        files[backup_path.generic_string()] = {
            {"encoding", kBase64Encoding},
            {"data", base64_encode(value)},
        };
    }
}

nlohmann::json collect_nfqws_files(const nlohmann::json& groups,
                                   const fs::path& nfqws_root,
                                   const fs::path& strategies_root) {
    const auto selection = nfqws_selection(groups);
    nlohmann::json files = nlohmann::json::object();
    if (!selection.any()) return files;

    std::size_t total_bytes = 0;
    std::size_t file_count = 0;
    add_nfqws_tree(files, nfqws_root, "nfqws2", selection, total_bytes,
                   file_count);
    add_nfqws_tree(files, strategies_root, "strategies", selection,
                   total_bytes, file_count);
    return files;
}

std::string decode_backup_file(const nlohmann::json& value) {
    if (value.is_string()) return value.get<std::string>();
    if (!value.is_object() || value.size() != 2U ||
        !value.contains("encoding") ||
        !value.at("encoding").is_string() ||
        value.at("encoding").get_ref<const std::string&>() != kBase64Encoding ||
        !value.contains("data") || !value.at("data").is_string()) {
        throw ApiError("invalid nfqws backup file", 400);
    }

    const auto& encoded = value.at("data").get_ref<const std::string&>();
    constexpr std::size_t kMaxEncodedFileBytes = ((kMaxBackupFileBytes + 2U) / 3U) * 4U;
    if (encoded.size() > kMaxEncodedFileBytes)
        throw ApiError("invalid nfqws backup file", 400);
    try {
        return base64_decode(encoded);
    } catch (const std::invalid_argument&) {
        throw ApiError("invalid nfqws backup file", 400);
    }
}

nlohmann::json read_persisted_config(const ApiContext& ctx) {
    try {
        const auto content = read_text(ctx.config_path);
        auto config = parse_config(content);
        validate_config(config);
        return nlohmann::json(config);
    } catch (const ApiError&) {
        throw;
    } catch (const std::exception& error) {
        throw ApiError(
            std::string("persisted configuration is invalid: ") +
                error.what(),
            500);
    }
}

nlohmann::json make_backup(const ApiContext& ctx, const nlohmann::json& groups) {
    // Backup is a recovery artifact. It must describe the active persisted
    // state, never an unsaved UI draft returned by get_visible_config().
    const nlohmann::json source = read_persisted_config(ctx);
    nlohmann::json data = nlohmann::json::object();
    if (selected(groups, "general")) {
        auto general = source;
        for (const char* key : {"outbounds", "dns", "lists", "route"}) general.erase(key);
        data["general"] = std::move(general);
    }
    if (selected(groups, "transports")) {
        const auto path = fs::path(ctx.config_path).parent_path() / "transports.json";
        std::error_code ec;
        if (fs::is_regular_file(path, ec)) data["transports"] = nlohmann::json::parse(read_text(path));
    }
    if (selected(groups, "outbounds")) {
        data["outbounds"] =
            source.contains("outbounds") && source.at("outbounds").is_array()
                ? source.at("outbounds")
                : nlohmann::json::array();
    }
    if (selected(groups, "dns")) {
        data["dns"] =
            source.contains("dns") && source.at("dns").is_object()
                ? source.at("dns")
                : nlohmann::json::object();
    }
    if (selected(groups, "routing")) {
        data["lists"] =
            source.contains("lists") && source.at("lists").is_object()
                ? source.at("lists")
                : nlohmann::json::object();
        data["route"] =
            source.contains("route") && source.at("route").is_object()
                ? source.at("route")
                : nlohmann::json::object();
    }
    if (nfqws_selection(groups).any()) {
        data["nfqws"] = collect_nfqws_files(
            groups,
            "/opt/etc/nfqws2",
            "/opt/etc/keen-pbr/nfqws-strategies");
    }
    nlohmann::json backup = {{"format", kBackupFormat}, {"schema", kBackupSchema},
            {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
            {"groups", groups}, {"data", std::move(data)}};
    if (backup.dump().size() > kMaxBackupBytes)
        throw ApiError("backup exceeds the aggregate limit", 413);
    return backup;
}

nlohmann::json all_groups() {
    return {{"general", true}, {"transports", true}, {"outbounds", true},
            {"dns", true}, {"routing", true}, {"nfqws_config", true},
            {"nfqws_lists", true}};
}

void validate_bundle(const nlohmann::json& backup) {
    if (!backup.is_object() || !backup.contains("format") ||
        !backup.at("format").is_string() ||
        backup.at("format").get_ref<const std::string&>() !=
            kBackupFormat ||
        !backup.contains("schema") ||
        !backup.at("schema").is_number_integer() ||
        backup.at("schema").get<int>() != kBackupSchema ||
        !backup.contains("data") || !backup.at("data").is_object()) {
        throw ApiError("invalid keen-pbr-sb backup", 400);
    }
    if (backup.dump().size() > kMaxBackupBytes)
        throw ApiError("backup exceeds the aggregate limit", 413);
    const auto& data = backup.at("data");
    static const std::set<std::string> kAllowedSections{
        "general", "transports", "outbounds", "dns",
        "lists", "route", "nfqws",
    };
    for (const auto& item : data.items()) {
        if (kAllowedSections.find(item.key()) == kAllowedSections.end()) {
            throw ApiError(
                "unknown backup data section: " + item.key(), 400);
        }
    }
    if (data.contains("general") && !data.at("general").is_object())
        throw ApiError("invalid general backup section", 400);
    if (data.contains("general")) {
        for (const char* reserved :
             {"outbounds", "dns", "lists", "route"}) {
            if (data.at("general").contains(reserved)) {
                throw ApiError(
                    std::string("reserved key in general backup section: ") +
                        reserved,
                    400);
            }
        }
    }
    if (data.contains("transports") &&
        !data.at("transports").is_object() && !data.at("transports").is_array())
        throw ApiError("invalid transports backup section", 400);
    if (data.contains("outbounds") && !data.at("outbounds").is_array())
        throw ApiError("invalid outbounds backup section", 400);
    for (const char* key : {"dns", "lists", "route"}) {
        if (data.contains(key) && !data.at(key).is_object())
            throw ApiError(std::string("invalid ") + key + " backup section", 400);
    }
    if (data.contains("nfqws")) {
        if (!data.at("nfqws").is_object() || data.at("nfqws").size() > kMaxBackupFiles)
            throw ApiError("invalid nfqws backup section", 400);
        const auto declared_selection =
            declared_nfqws_selection(backup);
        std::size_t total_bytes = 0;
        for (const auto& item : data.at("nfqws").items()) {
            reject_nul_path(item.key(), "invalid nfqws path in backup");
            const auto content = decode_backup_file(item.value());
            if (content.size() > kMaxBackupFileBytes)
                throw ApiError("invalid nfqws backup file", 400);
            if (content.size() > kMaxBackupBytes - total_bytes)
                throw ApiError("nfqws backup section is too large", 413);
            total_bytes += content.size();
            const fs::path relative(item.key());
            if (relative.is_absolute() || relative.empty() ||
                has_unsafe_path_component(relative))
                throw ApiError("invalid nfqws path in backup", 400);
            const auto group =
                persistent::classify_nfqws_path(relative);
            if (!group.has_value())
                throw ApiError("unsupported nfqws file in backup", 400);
            if (declared_selection.has_value() &&
                !declared_selection->includes(*group)) {
                throw ApiError(
                    "nfqws backup file does not match selected group", 400);
            }
        }
    }
}

using RestoreRoots = persistent::PersistentLayout;
using PersistentTargetKind =
    persistent::PersistentTargetKind;

RestoreRoots persistent_layout(
    const ApiContext& ctx,
    RestoreRoots roots = {}) {
    roots.config = ctx.config_path;
    roots.transports =
        fs::path(ctx.config_path).parent_path() /
        "transports.json";
    return roots;
}

struct PreparedRestore {
    FileMutationPlan mutations;
    std::optional<Config> next_config;
    std::string next_config_json;
    std::optional<Config> previous_config;
    std::string previous_config_json;
    bool restart_transports{false};
    bool restart_nfqws{false};
    std::optional<std::string> next_transport_revision;
    std::optional<std::string> previous_transport_revision;
};

PreparedRestore prepare_persistent_rollback_restore(
    const ApiContext& ctx,
    const nlohmann::json& rollback,
    const RestoreRoots& roots = {}) {
    if (ctx.config_is_draft()) {
        throw ApiError(
            "Backup restore is unavailable while a draft config is staged",
            409);
    }

    auto mutations = persistent::prepare_persistent_restore(
        persistent_layout(ctx, roots), rollback);
    PreparedRestore prepared;

    for (const auto& mutation : mutations) {
        if (mutation.kind == PersistentTargetKind::config) {
            if (mutation.replacement.remove) {
                throw ApiError(
                    "rollback snapshot cannot remove configuration", 400);
            }
            try {
                prepared.next_config_json =
                    mutation.replacement.content;
                prepared.next_config =
                    parse_config(prepared.next_config_json);
                validate_config(*prepared.next_config);
                ctx.validate_candidate_config(*prepared.next_config);
            } catch (const std::exception& error) {
                throw ApiError(
                    std::string(
                        "rollback configuration is invalid: ") +
                        error.what(),
                    400);
            }
            if (!mutation.before.existed) {
                throw ApiError(
                    "current configuration is unavailable for rollback",
                    500);
            }
            try {
                prepared.previous_config_json =
                    mutation.before.content;
                prepared.previous_config =
                    parse_config(prepared.previous_config_json);
                validate_config(*prepared.previous_config);
            } catch (const std::exception& error) {
                throw ApiError(
                    std::string(
                        "current configuration cannot be used for rollback: ") +
                        error.what(),
                    500);
            }
        } else if (
            mutation.kind ==
            PersistentTargetKind::transports) {
            prepared.restart_transports = true;
            if (!mutation.replacement.remove) {
                prepared.next_transport_revision =
                    Sha256::hex(
                        mutation.replacement.content);
            }
            if (mutation.before.existed) {
                prepared.previous_transport_revision =
                    Sha256::hex(mutation.before.content);
            }
        } else {
            prepared.restart_nfqws = true;
        }
    }
    prepared.mutations = std::move(mutations);
    return prepared;
}

PreparedRestore prepare_restore_bundle(const ApiContext& ctx,
                                       const nlohmann::json& backup,
                                       const RestoreRoots& roots) {
    if (ctx.config_is_draft()) {
        throw ApiError(
            "Backup restore is unavailable while a draft config is staged",
            409);
    }
    validate_bundle(backup);
    const auto& data = backup.at("data");
    PreparedRestore prepared;
    const auto layout = persistent_layout(ctx, roots);
    std::vector<FileReplacement> replacements;

    bool config_changed = false;
    for (const char* key :
         {"general", "outbounds", "dns", "lists", "route"}) {
        if (data.contains(key)) {
            config_changed = true;
            break;
        }
    }

    if (config_changed) {
        nlohmann::json merged = read_persisted_config(ctx);
        if (data.contains("general")) {
            for (const auto& item : data.at("general").items()) {
                merged[item.key()] = item.value();
            }
        }
        for (const char* key : {"outbounds", "dns", "lists", "route"}) {
            if (data.contains(key)) {
                merged[key] = data.at(key);
            }
        }

        prepared.next_config_json = merged.dump(1, '\t') + "\n";
        try {
            prepared.next_config =
                parse_config(prepared.next_config_json);
            validate_config(*prepared.next_config);
            ctx.validate_candidate_config(*prepared.next_config);
        } catch (const std::exception& error) {
            throw ApiError(
                std::string("backup configuration is invalid: ") +
                    error.what(),
                400);
        }

        FileReplacement replacement;
        replacement.path = layout.config;
        replacement.content = prepared.next_config_json;
        replacement.max_content_bytes = kMaxBackupBytes;
        replacements.push_back(std::move(replacement));
    }

    if (data.contains("transports")) {
        const auto transports_content =
            data.at("transports").dump(1, '\t') + "\n";
        prepared.next_transport_revision =
            Sha256::hex(transports_content);
        FileReplacement replacement;
        replacement.path = layout.transports;
        replacement.content = transports_content;
        replacement.mode_override =
            static_cast<mode_t>(0600);
        replacement.created_directory_mode =
            static_cast<mode_t>(0700);
        replacement.max_content_bytes = kMaxBackupBytes;
        replacements.push_back(std::move(replacement));
        prepared.restart_transports = true;
    }

    if (data.contains("nfqws")) {
        const auto exact_selection =
            declared_nfqws_selection(backup);
        std::set<std::string> restored_targets;
        std::size_t restored_bytes = 0;
        for (const auto& item : data.at("nfqws").items()) {
            const auto resolved =
                persistent::resolve_persistent_target(
                    layout, item.key());
            if (!resolved.confinement_root.has_value()) {
                throw ApiError("invalid nfqws path in backup", 400);
            }
            auto content = decode_backup_file(item.value());
            if (content.size() > kMaxBackupFileBytes ||
                content.size() >
                    kMaxBackupBytes - restored_bytes) {
                throw ApiError(
                    "nfqws backup section is too large", 413);
            }
            restored_bytes += content.size();
            if (restored_targets.size() >= kMaxBackupFiles ||
                !restored_targets.insert(item.key()).second) {
                throw ApiError(
                    "nfqws restore contains too many or duplicate files",
                    413);
            }
            FileReplacement replacement;
            replacement.path = resolved.path;
            replacement.content = std::move(content);
            replacement.ensure_world_readable = true;
            replacement.confinement_root =
                resolved.confinement_root;
            replacement.created_directory_mode =
                static_cast<mode_t>(0700);
            replacement.max_content_bytes =
                kMaxBackupFileBytes;
            replacements.push_back(std::move(replacement));
        }
        if (exact_selection.has_value()) {
            for (const auto& target :
                 persistent::current_nfqws_targets(
                     layout, *exact_selection)) {
                if (restored_targets.find(target) !=
                    restored_targets.end()) {
                    continue;
                }
                if (restored_targets.size() >= kMaxBackupFiles) {
                    throw ApiError(
                        "nfqws restore contains too many files", 413);
                }
                restored_targets.insert(target);
                const auto resolved =
                    persistent::resolve_persistent_target(
                        layout, target);
                FileReplacement tombstone;
                tombstone.path = resolved.path;
                tombstone.confinement_root =
                    resolved.confinement_root;
                tombstone.created_directory_mode = 0700;
                tombstone.remove = true;
                tombstone.max_content_bytes =
                    kMaxBackupFileBytes;
                replacements.push_back(
                    std::move(tombstone));
            }
        }
        prepared.restart_nfqws = true;
    }

    if (replacements.empty() &&
        !data.contains("nfqws")) {
        throw ApiError("backup contains no restorable data", 400);
    }

    // Snapshot every target during preflight. Besides preparing rollback, this
    // rejects symlinks, non-regular targets and unreadable files before the
    // persistent rollback point is replaced.
    prepared.mutations = persistent::snapshot_replacements(
        layout, std::move(replacements));
    for (const auto& mutation : prepared.mutations) {
        if (prepared.restart_transports &&
            mutation.kind ==
                PersistentTargetKind::transports &&
            mutation.before.existed) {
            prepared.previous_transport_revision =
                Sha256::hex(mutation.before.content);
        }
    }

    if (config_changed) {
        const auto config_snapshot = std::find_if(
            prepared.mutations.begin(),
            prepared.mutations.end(),
            [](const persistent::FileMutation& mutation) {
                return mutation.kind ==
                       PersistentTargetKind::config;
            });
        if (config_snapshot == prepared.mutations.end() ||
            !config_snapshot->before.existed) {
            throw ApiError("current configuration is unavailable for rollback",
                           500);
        }
        try {
            prepared.previous_config_json =
                config_snapshot->before.content;
            prepared.previous_config =
                parse_config(prepared.previous_config_json);
            validate_config(*prepared.previous_config);
        } catch (const std::exception& error) {
            throw ApiError(
                std::string("current configuration cannot be used for rollback: ") +
                    error.what(),
                500);
        }
    }

    return prepared;
}

void apply_prepared_restore(
    const ApiContext& ctx,
    const PreparedRestore& prepared,
    const RestoreExecutionHooks& hooks = {}) {
    bool runtime_apply_attempted = false;
    bool transport_restart_attempted = false;
    bool nfqws_restart_attempted = false;
    persistent::FileMutationTransaction file_transaction(
        prepared.mutations, file_apply_hooks(hooks));
    try {
        file_transaction.apply();

        if (prepared.restart_transports) {
            constexpr const char* kTransportManager =
                "/opt/etc/init.d/S79transport-manager";
            if (hooks.before_forward_service_restart) {
                hooks.before_forward_service_restart(kTransportManager);
            }
            transport_restart_attempted = true;
            if (restart_restore_service(ctx, kTransportManager) != 0) {
                throw ApiError("transport manager restart failed", 500);
            }
            wait_for_restore_service_ready(
                ctx,
                hooks,
                kTransportManager,
                prepared.next_transport_revision);
        }
        if (prepared.next_config.has_value()) {
            runtime_apply_attempted = true;
            const auto result =
                ctx.enqueue_apply_validated_config(
                    *prepared.next_config,
                    prepared.next_config_json);
            if (!result.error.empty()) {
                throw ApiError("restore apply failed: " + result.error, 500);
            }
            if (hooks.after_forward_runtime_apply) {
                hooks.after_forward_runtime_apply();
            }
        }
        if (prepared.restart_nfqws) {
            constexpr const char* kNfqws = "/opt/etc/init.d/S51nfqws2";
            if (hooks.before_forward_service_restart) {
                hooks.before_forward_service_restart(kNfqws);
            }
            nfqws_restart_attempted = true;
            if (restart_restore_service(ctx, kNfqws) != 0) {
                throw ApiError("nfqws2 restart failed", 500);
            }
            wait_for_restore_service_ready(ctx, hooks, kNfqws);
        }
    } catch (...) {
        const auto original_error = std::current_exception();
        auto rollback_errors = file_transaction.rollback();

        // Runtime routing may refer to managed interfaces. Restore and verify
        // the transport-manager generation before applying the old core
        // configuration, mirroring the forward dependency order.
        if (transport_restart_attempted) {
            try {
                constexpr const char* kTransportManager =
                    "/opt/etc/init.d/S79transport-manager";
                if (restart_restore_service(ctx, kTransportManager) != 0) {
                    throw ApiError(
                        "transport manager rollback restart failed", 500);
                }
                wait_for_restore_service_ready(
                    ctx,
                    hooks,
                    kTransportManager,
                    prepared.previous_transport_revision);
            } catch (const std::exception& error) {
                rollback_errors.push_back(
                    std::string("transport manager rollback restart failed: ") +
                    error.what());
            }
        }
        if (runtime_apply_attempted &&
            prepared.previous_config.has_value()) {
            try {
                const auto result = ctx.enqueue_apply_validated_config(
                    *prepared.previous_config,
                    prepared.previous_config_json);
                if (!result.error.empty()) {
                    rollback_errors.push_back(
                        "runtime rollback failed: " + result.error);
                }
            } catch (const std::exception& error) {
                rollback_errors.push_back(
                    std::string("runtime rollback failed: ") + error.what());
            }
        }
        if (nfqws_restart_attempted) {
            try {
                constexpr const char* kNfqws =
                    "/opt/etc/init.d/S51nfqws2";
                if (restart_restore_service(ctx, kNfqws) != 0) {
                    throw ApiError(
                        "nfqws2 rollback restart failed", 500);
                }
                wait_for_restore_service_ready(
                    ctx, hooks, kNfqws);
            } catch (const std::exception& error) {
                rollback_errors.push_back(
                    std::string("nfqws2 rollback restart failed: ") +
                    error.what());
            }
        }

        if (!rollback_errors.empty()) {
            std::ostringstream message;
            message << exception_message(original_error)
                    << "; rollback was incomplete:";
            for (const auto& error : rollback_errors) {
                message << " " << error << ";";
            }
            Logger::instance().error("{}", message.str());
            throw ApiError(message.str(), 500);
        }
        try {
            std::rethrow_exception(original_error);
        } catch (const ApiError&) {
            throw;
        } catch (const std::exception& error) {
            throw ApiError(
                std::string("backup restore failed: ") + error.what(), 500);
        } catch (...) {
            throw ApiError("backup restore failed: unknown error", 500);
        }
    }
}

void restore_bundle(const ApiContext& ctx,
                    const nlohmann::json& backup,
                    const RestoreRoots& roots = {},
                    const RestoreExecutionHooks& hooks = {}) {
    with_persistent_snapshot_errors([&] {
        const auto prepared =
            prepare_restore_bundle(ctx, backup, roots);
        apply_prepared_restore(ctx, prepared, hooks);
    });
}

std::string write_persistent_rollback_snapshot_at(
    const nlohmann::json& snapshot,
    const fs::path& path,
    const RestoreExecutionHooks& hooks = {}) {
    return with_persistent_snapshot_errors([&] {
        return persistent::save_snapshot(
            snapshot, path, file_apply_hooks(hooks));
    });
}

std::string create_full_rollback_backup_at(
    const ApiContext& ctx,
    const fs::path& path,
    const RestoreExecutionHooks& hooks = {},
    const RestoreRoots& roots = {}) {
    return with_persistent_snapshot_errors([&] {
        return write_persistent_rollback_snapshot_at(
            persistent::make_full_snapshot(
                persistent_layout(ctx, roots)),
            path,
            hooks);
    });
}

void restore_with_rollback(const ApiContext& ctx,
                           const nlohmann::json& backup,
                           const fs::path& rollback_path,
                           const RestoreExecutionHooks& hooks = {}) {
    with_persistent_snapshot_errors([&] {
        // Nothing below this line may discover a malformed archive. Preparing
        // the complete plan first keeps a previously known-good rollback intact
        // when the new import cannot be applied.
        const RestoreRoots roots;
        const auto prepared =
            prepare_restore_bundle(ctx, backup, roots);
        write_persistent_rollback_snapshot_at(
            persistent::make_operation_snapshot(
                prepared.mutations),
            rollback_path,
            hooks);
        apply_prepared_restore(ctx, prepared, hooks);
    });
}

void restore_persistent_rollback(
    const ApiContext& ctx,
    const nlohmann::json& rollback,
    const RestoreExecutionHooks& hooks = {},
    const RestoreRoots& roots = {}) {
    with_persistent_snapshot_errors([&] {
        const auto prepared =
            prepare_persistent_rollback_restore(
                ctx, rollback, roots);
        apply_prepared_restore(ctx, prepared, hooks);
    });
}

nlohmann::json read_rollback_document_at(const fs::path& path) {
    return with_persistent_snapshot_errors([&] {
        return persistent::load_snapshot(path);
    });
}

bool rollback_backup_available_at(const fs::path& path) {
    try {
        const auto rollback = read_rollback_document_at(path);
        if (rollback.is_object() &&
            rollback.value("format", std::string{}) ==
                kRollbackFormat) {
            (void)persistent::parse_persistent_snapshot(
                rollback);
        } else {
            // Keep the one-release upgrade path visible to the UI as well as
            // to POST /api/backup/rollback.
            validate_bundle(rollback);
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

std::string create_full_rollback_backup(const ApiContext& ctx) {
    return create_full_rollback_backup_at(ctx, kRollbackPath);
}

#ifdef KEEN_PBR3_TESTING
static RestoreRoots restore_roots_for_test(
    const BackupRestoreRootsForTest& roots) {
    RestoreRoots layout;
    layout.nfqws = fs::path(roots.nfqws);
    layout.strategies = fs::path(roots.strategies);
    return layout;
}

static RestoreExecutionHooks adapt_test_hooks(
    const BackupRestoreHooksForTest& hooks) {
    RestoreExecutionHooks adapted;
    if (hooks.atomic_write_fault) {
        adapted.atomic_write_fault =
            [callback = hooks.atomic_write_fault](
                const fs::path& path,
                AtomicFileWriteStage stage) {
                callback(path.string(), stage);
            };
    }
    if (hooks.before_forward_write) {
        adapted.before_forward_write =
            [callback = hooks.before_forward_write](
                std::size_t index, const fs::path& path) {
                callback(index, path.string());
            };
    }
    adapted.after_forward_runtime_apply =
        hooks.after_forward_runtime_apply;
    adapted.before_forward_service_restart =
        hooks.before_forward_service_restart;
    if (hooks.before_rollback_write) {
        adapted.before_rollback_write =
            [callback = hooks.before_rollback_write](
                std::size_t index, const fs::path& path) {
                callback(index, path.string());
            };
    }
    if (hooks.probe_service_readiness) {
        adapted.probe_service_readiness =
            [callback = hooks.probe_service_readiness](
                const std::string& service) {
                switch (callback(service)) {
                case RestoreServiceReadinessForTest::starting:
                    return ServiceReadiness::starting;
                case RestoreServiceReadinessForTest::ready:
                    return ServiceReadiness::ready;
                case RestoreServiceReadinessForTest::failed:
                    return ServiceReadiness::failed;
                }
                return ServiceReadiness::failed;
            };
    }
    if (hooks.probe_transport_config_revision) {
        adapted.probe_transport_config_revision =
            [callback =
                 hooks.probe_transport_config_revision](
                const std::string& expected_revision) {
                switch (callback(expected_revision)) {
                case RestoreServiceReadinessForTest::starting:
                    return ServiceReadiness::starting;
                case RestoreServiceReadinessForTest::ready:
                    return ServiceReadiness::ready;
                case RestoreServiceReadinessForTest::failed:
                    return ServiceReadiness::failed;
                }
                return ServiceReadiness::failed;
            };
    }
    adapted.wait_before_service_probe =
        hooks.wait_before_service_probe;
    return adapted;
}

nlohmann::json create_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& groups) {
    return make_backup(ctx, groups);
}

nlohmann::json create_nfqws_backup_section_for_test(
    const nlohmann::json& groups,
    const std::string& nfqws_root,
    const std::string& strategies_root) {
    return collect_nfqws_files(groups, nfqws_root, strategies_root);
}

void validate_confined_restore_target_for_test(
    const std::string& root,
    const std::string& target) {
    with_persistent_snapshot_errors([&] {
        validate_confined_restore_target(root, target);
    });
}

void restore_backup_bundle_for_test(const ApiContext& ctx,
                                    const nlohmann::json& backup) {
    restore_bundle(ctx, backup);
}

void restore_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const BackupRestoreRootsForTest& roots) {
    restore_bundle(ctx,
                   backup,
                   restore_roots_for_test(roots));
}

void restore_backup_bundle_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const BackupRestoreHooksForTest& hooks) {
    restore_bundle(ctx, backup, {}, adapt_test_hooks(hooks));
}

void restore_backup_with_rollback_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const std::string& rollback_path) {
    restore_with_rollback(ctx, backup, rollback_path);
}

void restore_backup_with_rollback_for_test(
    const ApiContext& ctx,
    const nlohmann::json& backup,
    const std::string& rollback_path,
    const BackupRestoreHooksForTest& hooks) {
    restore_with_rollback(
        ctx, backup, rollback_path, adapt_test_hooks(hooks));
}

void restore_persistent_rollback_for_test(
    const ApiContext& ctx,
    const std::string& rollback_path,
    const BackupRestoreHooksForTest& hooks) {
    const auto rollback =
        read_rollback_document_at(rollback_path);
    restore_persistent_rollback(
        ctx, rollback, adapt_test_hooks(hooks));
}

void restore_persistent_rollback_for_test(
    const ApiContext& ctx,
    const std::string& rollback_path,
    const BackupRestoreRootsForTest& roots,
    const BackupRestoreHooksForTest& hooks) {
    const auto rollback =
        read_rollback_document_at(rollback_path);
    restore_persistent_rollback(
        ctx,
        rollback,
        adapt_test_hooks(hooks),
        restore_roots_for_test(roots));
}

void create_full_rollback_backup_for_test(
    const ApiContext& ctx,
    const std::string& rollback_path,
    const BackupRestoreRootsForTest& roots) {
    (void)create_full_rollback_backup_at(
        ctx,
        rollback_path,
        {},
        restore_roots_for_test(roots));
}

bool rollback_backup_available_for_test(
    const std::string& rollback_path) {
    return rollback_backup_available_at(rollback_path);
}
#endif

using BackupSnapshotReader = std::function<nlohmann::json(
    const ApiContext&, const nlohmann::json&)>;

static void register_backup_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    BackupSnapshotReader backup_snapshot_reader) {
    server.post("/api/backup", [
        &ctx,
        backup_snapshot_reader =
            std::move(backup_snapshot_reader)
    ](const std::string& body) -> std::string {
        if (body.size() > kMaxBackupBytes) throw ApiError("backup request is too large", 413);
        nlohmann::json request;
        try { request = nlohmann::json::parse(body); }
        catch (...) { throw ApiError("invalid backup request", 400); }
        try {
            auto maintenance =
                ctx.acquire_maintenance_lease("backup-read");
            return backup_snapshot_reader(
                       ctx,
                       request.value(
                           "groups", nlohmann::json::object()))
                .dump();
        } catch (const MaintenanceLockError& error) {
            throw_maintenance_api_error(error);
        }
    });
    server.post("/api/backup/restore", [&ctx](const std::string& body) -> std::string {
        if (body.size() > kMaxBackupBytes) throw ApiError("backup is too large", 413);
        nlohmann::json backup;
        try { backup = nlohmann::json::parse(body); }
        catch (...) { throw ApiError("invalid backup JSON", 400); }
        ctx.begin_save_operation();
        try {
            restore_with_rollback(ctx, backup, kRollbackPath);
            ctx.finish_config_operation();
            return R"({"ok":true})";
        } catch (...) {
            ctx.finish_config_operation();
            throw;
        }
    });
    server.get("/api/backup/rollback", []() -> std::string {
        return nlohmann::json{
            {"available", rollback_backup_available_at(kRollbackPath)},
        }.dump();
    });
    server.post("/api/backup/rollback", [&ctx]() -> std::string {
        ctx.begin_save_operation();
        try {
            const auto rollback =
                read_rollback_document_at(kRollbackPath);
            if (rollback.is_object() &&
                rollback.value("format", std::string{}) ==
                    kRollbackFormat) {
                restore_persistent_rollback(ctx, rollback);
            } else {
                // One-release compatibility path for rollback artifacts
                // produced before the exact snapshot format existed.
                validate_bundle(rollback);
                restore_bundle(ctx, rollback);
            }
            ctx.finish_config_operation();
            return R"({"ok":true})";
        } catch (...) {
            ctx.finish_config_operation();
            throw;
        }
    });
}

void register_backup_handler(ApiServer& server, ApiContext& ctx) {
    register_backup_handler_impl(
        server,
        ctx,
        [](const ApiContext& context,
           const nlohmann::json& groups) {
            return make_backup(context, groups);
        });
}

#ifdef KEEN_PBR3_TESTING
void register_backup_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    BackupSnapshotReaderForTest backup_snapshot_reader) {
    register_backup_handler_impl(
        server, ctx, std::move(backup_snapshot_reader));
}
#endif

} // namespace keen_pbr3

#endif
