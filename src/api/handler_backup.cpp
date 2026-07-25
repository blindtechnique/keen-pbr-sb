#ifdef WITH_API

#include "handler_backup.hpp"

#include "generated/api_types.hpp"
#include "../config/config.hpp"
#include "../log/logger.hpp"
#include "../util/base64.hpp"
#include "../util/safe_exec.hpp"

#include <cerrno>
#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;
constexpr std::size_t kMaxBackupBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaxBackupFileBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaxBackupFiles = 512U;
constexpr const char* kRollbackPath = "/opt/etc/keen-pbr/rollback-backup.json";
constexpr const char* kBase64Encoding = "base64";

std::string read_text(const fs::path& path) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxBackupBytes) throw ApiError("backup source is missing or too large", 400);
    std::ifstream input(path, std::ios::binary);
    if (!input) throw ApiError("cannot read backup source", 500);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_atomic(const fs::path& path, const std::string& content,
                  bool ensure_world_readable = false,
                  std::optional<mode_t> mode_override = std::nullopt,
                  std::optional<uid_t> owner_override = std::nullopt,
                  std::optional<gid_t> group_override = std::nullopt) {
    if (content.size() > kMaxBackupFileBytes && path != kRollbackPath &&
        path.filename() != "config.json" && path.filename() != "transports.json")
        throw ApiError("backup file is too large", 413);
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) throw ApiError("cannot create backup directory", 500);
    struct stat previous{};
    const bool had_previous = ::stat(path.c_str(), &previous) == 0;
    auto temporary = path;
    temporary += ".keen-pbr-sb.tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output || !(output << content)) throw ApiError("cannot write backup file", 500);
    output.close();
    if (!output) throw ApiError("cannot flush backup file", 500);
    mode_t mode = mode_override.value_or(
        had_previous ? (previous.st_mode & 0777) : 0644);
    if (ensure_world_readable) mode |= 0444;
    const uid_t owner = owner_override.value_or(
        had_previous ? previous.st_uid : geteuid());
    const gid_t group = group_override.value_or(
        had_previous ? previous.st_gid : getegid());
    if (::chmod(temporary.c_str(), mode) != 0 ||
        ::chown(temporary.c_str(), owner, group) != 0) {
        fs::remove(temporary, ec);
        throw ApiError("cannot preserve backup file metadata", 500);
    }
    const int temp_fd = ::open(temporary.c_str(), O_RDONLY | O_CLOEXEC);
    if (temp_fd < 0 || ::fsync(temp_fd) != 0) {
        if (temp_fd >= 0) ::close(temp_fd);
        fs::remove(temporary, ec);
        throw ApiError("cannot sync backup file", 500);
    }
    ::close(temp_fd);
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        fs::remove(temporary, ec);
        throw ApiError("cannot replace backup file", 500);
    }
    const int directory_fd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd >= 0) {
        (void)::fsync(directory_fd);
        ::close(directory_fd);
    }
}

struct FileReplacement {
    fs::path path;
    std::string content;
    bool ensure_world_readable{false};
    std::optional<fs::path> confinement_root;
};

struct FileSnapshot {
    fs::path path;
    std::optional<fs::path> confinement_root;
    bool existed{false};
    std::string content;
    mode_t mode{0600};
    uid_t owner{0};
    gid_t group{0};
};

bool unsafe_relative_path(const fs::path& path) {
    return path.empty() || path.is_absolute() ||
           std::any_of(
               path.begin(), path.end(), [](const fs::path& component) {
                   return component == ".." || component == ".";
               });
}

void validate_confined_restore_target(const fs::path& root,
                                      const fs::path& target) {
    const auto normalized_root = root.lexically_normal();
    const auto normalized_target = target.lexically_normal();
    if (!normalized_root.is_absolute() || !normalized_target.is_absolute()) {
        throw ApiError("nfqws restore path must be absolute", 400);
    }

    const auto relative = normalized_target.lexically_relative(normalized_root);
    if (unsafe_relative_path(relative)) {
        throw ApiError("nfqws restore path escapes its root", 400);
    }

    auto inspect = [&](const fs::path& path, bool require_directory,
                       bool allow_missing) {
        struct stat metadata {};
        if (::lstat(path.c_str(), &metadata) != 0) {
            if (errno == ENOENT && allow_missing) return false;
            throw ApiError("cannot inspect nfqws restore path " +
                               path.string(),
                           500);
        }
        if (S_ISLNK(metadata.st_mode)) {
            throw ApiError("nfqws restore path contains a symbolic link", 400);
        }
        if (require_directory && !S_ISDIR(metadata.st_mode)) {
            throw ApiError(
                "nfqws restore parent is not a directory", 400);
        }
        if (!require_directory && !S_ISREG(metadata.st_mode)) {
            throw ApiError("nfqws restore target is not a regular file", 400);
        }
        return true;
    };

    bool parent_missing = !inspect(normalized_root, true, true);
    fs::path current = normalized_root;
    for (auto component = relative.begin(); component != relative.end();
         ++component) {
        current /= *component;
        const bool is_target = std::next(component) == relative.end();
        if (parent_missing) continue;
        const bool exists = inspect(current, !is_target, true);
        if (!exists) parent_missing = true;
    }
}

FileSnapshot capture_file(
    const fs::path& path,
    const std::optional<fs::path>& confinement_root = std::nullopt) {
    if (confinement_root.has_value()) {
        validate_confined_restore_target(*confinement_root, path);
    }
    FileSnapshot snapshot;
    snapshot.path = path;
    snapshot.confinement_root = confinement_root;

    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0) {
        if (errno == ENOENT) return snapshot;
        throw ApiError("cannot inspect restore target " + path.string(), 500);
    }
    if (!S_ISREG(metadata.st_mode)) {
        throw ApiError("restore target is not a regular file: " + path.string(),
                       500);
    }

    snapshot.existed = true;
    snapshot.content = read_text(path);
    snapshot.mode = metadata.st_mode & 0777;
    snapshot.owner = metadata.st_uid;
    snapshot.group = metadata.st_gid;
    return snapshot;
}

void sync_parent_directory(const fs::path& path) {
    const int directory_fd =
        ::open(path.parent_path().c_str(),
               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd >= 0) {
        (void)::fsync(directory_fd);
        ::close(directory_fd);
    }
}

void restore_snapshot(const FileSnapshot& snapshot) {
    if (snapshot.confinement_root.has_value()) {
        validate_confined_restore_target(
            *snapshot.confinement_root, snapshot.path);
    }
    if (snapshot.existed) {
        write_atomic(snapshot.path,
                     snapshot.content,
                     false,
                     snapshot.mode,
                     snapshot.owner,
                     snapshot.group);
        return;
    }

    std::error_code ec;
    const bool removed = fs::remove(snapshot.path, ec);
    if (ec) {
        throw ApiError("cannot remove newly restored file " +
                           snapshot.path.string(),
                       500);
    }
    if (removed) sync_parent_directory(snapshot.path);
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

bool selected(const nlohmann::json& groups, const char* name) {
    if (!groups.is_object())
        throw ApiError("invalid backup groups", 400);
    const auto value = groups.find(name);
    if (value == groups.end()) return false;
    if (!value->is_boolean())
        throw ApiError("invalid backup group selection", 400);
    return value->get<bool>();
}

enum class NfqwsBackupGroup {
    config,
    lists,
};

struct NfqwsSelection {
    bool config{false};
    bool lists{false};

    bool includes(NfqwsBackupGroup group) const {
        return group == NfqwsBackupGroup::config ? config : lists;
    }

    bool any() const {
        return config || lists;
    }
};

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

bool has_unsafe_path_component(const fs::path& path) {
    return std::any_of(
        path.begin(), path.end(), [](const fs::path& component) {
            return component == ".." || component == ".";
        });
}

std::optional<NfqwsBackupGroup> classify_nfqws_path(
    const fs::path& relative) {
    if (relative.is_absolute() || relative.empty() ||
        has_unsafe_path_component(relative)) {
        return std::nullopt;
    }

    const auto first = *relative.begin();
    const auto extension = relative.extension().string();
    const auto filename = relative.filename().string();
    const bool compressed_lua =
        filename.size() >= 7 &&
        filename.substr(filename.size() - 7) == ".lua.gz";

    if (first == "strategies") {
        return extension == ".conf"
                   ? std::optional{NfqwsBackupGroup::config}
                   : std::nullopt;
    }
    if (first != "nfqws2") return std::nullopt;
    if (extension == ".list") return NfqwsBackupGroup::lists;
    if (extension == ".conf" || extension == ".lua" || compressed_lua)
        return NfqwsBackupGroup::config;
    return std::nullopt;
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
        const auto group = classify_nfqws_path(backup_path);
        if (!group.has_value() || !selection.includes(*group)) continue;
        const auto file_size = entry.file_size(ec);
        if (ec) continue;
        if (file_size > kMaxBackupFileBytes)
            throw ApiError("backup contains a file larger than the per-file limit", 413);
        if (++file_count > kMaxBackupFiles || total_bytes + file_size > kMaxBackupBytes)
            throw ApiError("backup content exceeds the aggregate limit", 413);
        const auto value = read_text(entry.path());
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
    if (!value.is_object() || !value.contains("encoding") ||
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

nlohmann::json make_backup(const ApiContext& ctx, const nlohmann::json& groups) {
    const nlohmann::json source = ctx.get_visible_config();
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
    if (selected(groups, "outbounds")) data["outbounds"] = source.value("outbounds", nlohmann::json::array());
    if (selected(groups, "dns")) data["dns"] = source.value("dns", nlohmann::json::object());
    if (selected(groups, "routing")) {
        data["lists"] = source.value("lists", nlohmann::json::object());
        data["route"] = source.value("route", nlohmann::json::object());
    }
    if (nfqws_selection(groups).any()) {
        data["nfqws"] = collect_nfqws_files(
            groups,
            "/opt/etc/nfqws2",
            "/opt/etc/keen-pbr/nfqws-strategies");
    }
    nlohmann::json backup = {{"format", "keen-pbr-sb-backup"}, {"schema", 1},
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
    if (!backup.is_object() || backup.value("format", "") != "keen-pbr-sb-backup" ||
        backup.value("schema", 0) != 1 || !backup.contains("data") || !backup["data"].is_object())
        throw ApiError("invalid keen-pbr-sb backup", 400);
    if (backup.dump().size() > kMaxBackupBytes)
        throw ApiError("backup exceeds the aggregate limit", 413);
    const auto& data = backup.at("data");
    if (data.contains("general") && !data.at("general").is_object())
        throw ApiError("invalid general backup section", 400);
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
        std::optional<NfqwsSelection> declared_selection;
        if (backup.contains("groups")) {
            if (!backup.at("groups").is_object())
                throw ApiError("invalid backup groups", 400);
            const auto& groups = backup.at("groups");
            if (groups.contains("nfqws_config") ||
                groups.contains("nfqws_lists")) {
                declared_selection = nfqws_selection(groups);
            }
        }
        std::size_t total_bytes = 0;
        for (const auto& item : data.at("nfqws").items()) {
            const auto content = decode_backup_file(item.value());
            if (content.size() > kMaxBackupFileBytes)
                throw ApiError("invalid nfqws backup file", 400);
            total_bytes += content.size();
            const fs::path relative(item.key());
            if (relative.is_absolute() || relative.empty() ||
                has_unsafe_path_component(relative))
                throw ApiError("invalid nfqws path in backup", 400);
            const auto group = classify_nfqws_path(relative);
            if (!group.has_value())
                throw ApiError("unsupported nfqws file in backup", 400);
            if (declared_selection.has_value() &&
                !declared_selection->includes(*group)) {
                throw ApiError(
                    "nfqws backup file does not match selected group", 400);
            }
        }
        if (total_bytes > kMaxBackupBytes)
            throw ApiError("nfqws backup section is too large", 413);
    }
}

void restore_bundle(const ApiContext& ctx, const nlohmann::json& backup) {
    validate_bundle(backup);
    const auto& data = backup.at("data");
    nlohmann::json merged = ctx.get_visible_config();
    bool config_changed = false;
    if (data.contains("general")) {
        for (const auto& item : data.at("general").items()) merged[item.key()] = item.value();
        config_changed = true;
    }
    for (const char* key : {"outbounds", "dns", "lists", "route"}) {
        if (data.contains(key)) {
            merged[key] = data.at(key);
            config_changed = true;
        }
    }

    const auto formatted = merged.dump(1, '\t') + "\n";
    Config parsed;
    if (config_changed) {
        try {
            parsed = parse_config(formatted);
            validate_config(parsed);
            ctx.validate_candidate_config(parsed);
        } catch (const std::exception& error) {
            throw ApiError(
                std::string("backup configuration is invalid: ") +
                    error.what(),
                400);
        }
    }

    std::vector<FileReplacement> replacements;
    if (config_changed) {
        replacements.push_back({ctx.config_path, formatted, false});
    }
    if (data.contains("transports")) {
        replacements.push_back({
            fs::path(ctx.config_path).parent_path() / "transports.json",
            data.at("transports").dump(1, '\t') + "\n",
            false,
        });
    }
    if (data.contains("nfqws")) {
        for (const auto& item : data.at("nfqws").items()) {
            const fs::path relative(item.key());
            const auto first = *relative.begin();
            const fs::path root = first == "nfqws2" ? "/opt/etc/nfqws2" :
                                  first == "strategies" ? "/opt/etc/keen-pbr/nfqws-strategies" : fs::path{};
            if (root.empty()) throw ApiError("invalid nfqws path in backup", 400);
            auto tail = relative;
            tail = tail.lexically_relative(first);
            replacements.push_back({
                root / tail,
                decode_backup_file(item.value()),
                true,
                root,
            });
        }
    }

    std::vector<FileSnapshot> snapshots;
    snapshots.reserve(replacements.size());
    for (const auto& replacement : replacements) {
        snapshots.push_back(capture_file(
            replacement.path, replacement.confinement_root));
    }

    std::optional<Config> previous_config;
    std::string previous_config_json;
    if (config_changed) {
        const auto config_snapshot = std::find_if(
            snapshots.begin(),
            snapshots.end(),
            [&ctx](const FileSnapshot& snapshot) {
                return snapshot.path == fs::path(ctx.config_path);
            });
        if (config_snapshot == snapshots.end() || !config_snapshot->existed) {
            throw ApiError("current configuration is unavailable for rollback",
                           500);
        }
        try {
            previous_config_json = config_snapshot->content;
            previous_config = parse_config(previous_config_json);
            validate_config(*previous_config);
        } catch (const std::exception& error) {
            throw ApiError(
                std::string("current configuration cannot be used for rollback: ") +
                    error.what(),
                500);
        }
    }

    try {
        for (const auto& replacement : replacements) {
            if (replacement.confinement_root.has_value()) {
                validate_confined_restore_target(
                    *replacement.confinement_root, replacement.path);
            }
            write_atomic(replacement.path,
                         replacement.content,
                         replacement.ensure_world_readable);
        }

        if (config_changed) {
            const auto result =
                ctx.enqueue_apply_validated_config(parsed, formatted);
            if (!result.error.empty()) {
                throw ApiError("restore apply failed: " + result.error, 500);
            }
        }
        if (data.contains("transports") &&
            safe_exec({"/opt/etc/init.d/S79transport-manager", "restart"},
                      true) != 0) {
            throw ApiError("transport manager restart failed", 500);
        }
        if (data.contains("nfqws") &&
            safe_exec({"/opt/etc/init.d/S51nfqws2", "restart"}, true) != 0) {
            throw ApiError("nfqws2 restart failed", 500);
        }
    } catch (...) {
        const auto original_error = std::current_exception();
        std::vector<std::string> rollback_errors;

        for (auto snapshot = snapshots.rbegin();
             snapshot != snapshots.rend();
             ++snapshot) {
            try {
                restore_snapshot(*snapshot);
            } catch (const std::exception& error) {
                rollback_errors.push_back(error.what());
            }
        }

        if (previous_config.has_value()) {
            try {
                const auto result = ctx.enqueue_apply_validated_config(
                    *previous_config, previous_config_json);
                if (!result.error.empty()) {
                    rollback_errors.push_back(
                        "runtime rollback failed: " + result.error);
                }
            } catch (const std::exception& error) {
                rollback_errors.push_back(
                    std::string("runtime rollback failed: ") + error.what());
            }
        }
        if (data.contains("transports") &&
            safe_exec({"/opt/etc/init.d/S79transport-manager", "restart"},
                      true) != 0) {
            rollback_errors.push_back(
                "transport manager rollback restart failed");
        }
        if (data.contains("nfqws") &&
            safe_exec({"/opt/etc/init.d/S51nfqws2", "restart"}, true) != 0) {
            rollback_errors.push_back("nfqws2 rollback restart failed");
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
        std::rethrow_exception(original_error);
    }
}

} // namespace

std::string create_full_rollback_backup(const ApiContext& ctx) {
    const auto payload = make_backup(ctx, all_groups()).dump(1, '\t') + "\n";
    write_atomic(kRollbackPath, payload, false, static_cast<mode_t>(0600));
    return payload;
}

#ifdef KEEN_PBR3_TESTING
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
    validate_confined_restore_target(root, target);
}

void restore_backup_bundle_for_test(const ApiContext& ctx,
                                    const nlohmann::json& backup) {
    restore_bundle(ctx, backup);
}
#endif

void register_backup_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/backup", [&ctx](const std::string& body) -> std::string {
        if (body.size() > kMaxBackupBytes) throw ApiError("backup request is too large", 413);
        nlohmann::json request;
        try { request = nlohmann::json::parse(body); }
        catch (...) { throw ApiError("invalid backup request", 400); }
        return make_backup(ctx, request.value("groups", nlohmann::json::object())).dump();
    });
    server.post("/api/backup/restore", [&ctx](const std::string& body) -> std::string {
        if (body.size() > kMaxBackupBytes) throw ApiError("backup is too large", 413);
        nlohmann::json backup;
        try { backup = nlohmann::json::parse(body); }
        catch (...) { throw ApiError("invalid backup JSON", 400); }
        ctx.begin_save_operation();
        try {
            create_full_rollback_backup(ctx);
            restore_bundle(ctx, backup);
            ctx.finish_config_operation();
            return R"({"ok":true})";
        } catch (...) {
            ctx.finish_config_operation();
            throw;
        }
    });
    server.get("/api/backup/rollback", []() -> std::string {
        std::error_code ec;
        return nlohmann::json{{"available", fs::is_regular_file(kRollbackPath, ec)}}.dump();
    });
    server.post("/api/backup/rollback", [&ctx]() -> std::string {
        ctx.begin_save_operation();
        try {
            const auto backup = nlohmann::json::parse(read_text(kRollbackPath));
            restore_bundle(ctx, backup);
            ctx.finish_config_operation();
            return R"({"ok":true})";
        } catch (...) {
            ctx.finish_config_operation();
            throw;
        }
    });
}

} // namespace keen_pbr3

#endif
