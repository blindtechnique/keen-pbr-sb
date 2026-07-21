#ifdef WITH_API

#include "handler_backup.hpp"

#include "generated/api_types.hpp"
#include "../config/config.hpp"
#include "../log/logger.hpp"
#include "../util/safe_exec.hpp"

#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
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

std::string read_text(const fs::path& path) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxBackupBytes) throw ApiError("backup source is missing or too large", 400);
    std::ifstream input(path, std::ios::binary);
    if (!input) throw ApiError("cannot read backup source", 500);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_atomic(const fs::path& path, const std::string& content,
                  bool ensure_world_readable = false) {
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
    mode_t mode = had_previous ? (previous.st_mode & 0777) : 0644;
    if (ensure_world_readable) mode |= 0444;
    if (::chmod(temporary.c_str(), mode) != 0 ||
        (had_previous && ::chown(temporary.c_str(), previous.st_uid, previous.st_gid) != 0)) {
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

bool selected(const nlohmann::json& groups, const char* name) {
    return groups.value(name, false);
}

void add_tree(nlohmann::json& files, const fs::path& root, const std::string& prefix,
              std::size_t& total_bytes, std::size_t& file_count) {
    static const std::set<std::string> allowed_extensions{".conf", ".list", ".lua"};
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return;
    for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
        if (ec || entry.is_symlink(ec) || !entry.is_regular_file(ec)) continue;
        const auto filename = entry.path().filename().string();
        const bool compressed_lua = filename.size() >= 7 &&
                                    filename.substr(filename.size() - 7) == ".lua.gz";
        if (!compressed_lua && !allowed_extensions.count(entry.path().extension().string())) continue;
        const auto file_size = entry.file_size(ec);
        if (ec) continue;
        if (file_size > kMaxBackupFileBytes)
            throw ApiError("backup contains a file larger than the per-file limit", 413);
        if (++file_count > kMaxBackupFiles || total_bytes + file_size > kMaxBackupBytes)
            throw ApiError("backup content exceeds the aggregate limit", 413);
        const auto relative = fs::relative(entry.path(), root, ec);
        if (ec || relative.empty()) continue;
        const auto value = read_text(entry.path());
        total_bytes += value.size();
        files[prefix + "/" + relative.generic_string()] = value;
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
    if (selected(groups, "nfqws")) {
        nlohmann::json files = nlohmann::json::object();
        std::size_t total_bytes = 0;
        std::size_t file_count = 0;
        add_tree(files, "/opt/etc/nfqws2", "nfqws2", total_bytes, file_count);
        add_tree(files, "/opt/etc/keen-pbr/nfqws-strategies", "strategies",
                 total_bytes, file_count);
        data["nfqws"] = std::move(files);
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
            {"dns", true}, {"routing", true}, {"nfqws", true}};
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
        std::size_t total_bytes = 0;
        for (const auto& item : data.at("nfqws").items()) {
            if (!item.value().is_string() || item.value().get_ref<const std::string&>().size() > kMaxBackupFileBytes)
                throw ApiError("invalid nfqws backup file", 400);
            total_bytes += item.value().get_ref<const std::string&>().size();
            const fs::path relative(item.key());
            if (relative.is_absolute() || relative.empty() ||
                std::any_of(relative.begin(), relative.end(), [](const fs::path& part) {
                    return part == ".." || part == ".";
                }))
                throw ApiError("invalid nfqws path in backup", 400);
            const auto first = *relative.begin();
            const auto extension = relative.extension().string();
            const auto filename = relative.filename().string();
            const bool allowed = first == "nfqws2"
                ? (extension == ".conf" || extension == ".list" || extension == ".lua" ||
                   (filename.size() >= 7 && filename.substr(filename.size() - 7) == ".lua.gz"))
                : first == "strategies" && extension == ".conf";
            if (!allowed) throw ApiError("unsupported nfqws file in backup", 400);
        }
        if (total_bytes > kMaxBackupBytes)
            throw ApiError("nfqws backup section is too large", 413);
    }
}

void restore_bundle(const ApiContext& ctx, const nlohmann::json& backup) {
    validate_bundle(backup);
    const auto& data = backup.at("data");
    nlohmann::json merged = ctx.get_visible_config();
    if (data.contains("general")) {
        for (const auto& item : data.at("general").items()) merged[item.key()] = item.value();
    }
    for (const char* key : {"outbounds", "dns", "lists", "route"})
        if (data.contains(key)) merged[key] = data.at(key);

    const auto formatted = merged.dump(1, '\t') + "\n";
    Config parsed;
    try {
        parsed = parse_config(formatted);
        validate_config(parsed);
        ctx.validate_candidate_config(parsed);
    } catch (const std::exception& error) {
        throw ApiError(std::string("backup configuration is invalid: ") + error.what(), 400);
    }

    const auto previous_config = read_text(ctx.config_path);
    if (data.contains("transports")) {
        write_atomic(fs::path(ctx.config_path).parent_path() / "transports.json",
                     data.at("transports").dump(1, '\t') + "\n");
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
            write_atomic(root / tail, item.value().get<std::string>(), true);
        }
    }

    write_atomic(ctx.config_path, formatted);
    const auto result = ctx.enqueue_apply_validated_config(std::move(parsed), formatted);
    if (!result.error.empty()) {
        write_atomic(ctx.config_path, previous_config);
        throw ApiError("restore apply failed: " + result.error, 500);
    }
    if (data.contains("transports") &&
        safe_exec({"/opt/etc/init.d/S79transport-manager", "restart"}, true) != 0)
        throw ApiError("transport manager restart failed", 500);
    if (data.contains("nfqws") &&
        safe_exec({"/opt/etc/init.d/S51nfqws2", "restart"}, true) != 0)
        throw ApiError("nfqws2 restart failed", 500);
}

} // namespace

std::string create_full_rollback_backup(const ApiContext& ctx) {
    const auto payload = make_backup(ctx, all_groups()).dump(1, '\t') + "\n";
    write_atomic(kRollbackPath, payload);
    return payload;
}

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
        std::optional<nlohmann::json> automatic_rollback;
        try {
            automatic_rollback = nlohmann::json::parse(create_full_rollback_backup(ctx));
            restore_bundle(ctx, backup);
            ctx.finish_config_operation();
            return R"({"ok":true})";
        } catch (...) {
            if (automatic_rollback.has_value()) {
                try {
                    restore_bundle(ctx, *automatic_rollback);
                } catch (const std::exception& rollback_error) {
                    Logger::instance().error("Automatic backup rollback failed: {}",
                                             rollback_error.what());
                }
            }
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
