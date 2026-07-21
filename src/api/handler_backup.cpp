#ifdef WITH_API

#include "handler_backup.hpp"

#include "generated/api_types.hpp"
#include "../config/config.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;
constexpr std::size_t kMaxBackupBytes = 12U * 1024U * 1024U;
constexpr const char* kRollbackPath = "/opt/etc/keen-pbr/rollback-backup.json";

std::string read_text(const fs::path& path) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxBackupBytes) throw ApiError("backup source is missing or too large", 400);
    std::ifstream input(path, std::ios::binary);
    if (!input) throw ApiError("cannot read backup source", 500);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_atomic(const fs::path& path, const std::string& content) {
    if (content.size() > kMaxBackupBytes) throw ApiError("backup is too large", 413);
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) throw ApiError("cannot create backup directory", 500);
    auto temporary = path;
    temporary += ".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output || !(output << content)) throw ApiError("cannot write backup file", 500);
    output.close();
    fs::rename(temporary, path, ec);
    if (ec) {
        fs::remove(path, ec);
        ec.clear();
        fs::rename(temporary, path, ec);
    }
    if (ec) throw ApiError("cannot replace backup file", 500);
}

bool selected(const nlohmann::json& groups, const char* name) {
    return groups.value(name, false);
}

void add_tree(nlohmann::json& files, const fs::path& root, const std::string& prefix) {
    static const std::set<std::string> allowed_extensions{".conf", ".list", ".lua"};
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return;
    for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
        if (ec || !entry.is_regular_file(ec)) continue;
        if (!allowed_extensions.count(entry.path().extension().string())) continue;
        const auto relative = fs::relative(entry.path(), root, ec);
        if (ec || relative.empty()) continue;
        const auto value = read_text(entry.path());
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
        add_tree(files, "/opt/etc/nfqws2", "nfqws2");
        add_tree(files, "/opt/etc/keen-pbr/nfqws-strategies", "strategies");
        data["nfqws"] = std::move(files);
    }
    return {{"format", "keen-pbr-sb-backup"}, {"schema", 1},
            {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
            {"groups", groups}, {"data", std::move(data)}};
}

nlohmann::json all_groups() {
    return {{"general", true}, {"transports", true}, {"outbounds", true},
            {"dns", true}, {"routing", true}, {"nfqws", true}};
}

void validate_bundle(const nlohmann::json& backup) {
    if (!backup.is_object() || backup.value("format", "") != "keen-pbr-sb-backup" ||
        backup.value("schema", 0) != 1 || !backup.contains("data") || !backup["data"].is_object())
        throw ApiError("invalid keen-pbr-sb backup", 400);
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

    if (data.contains("transports")) {
        write_atomic(fs::path(ctx.config_path).parent_path() / "transports.json",
                     data.at("transports").dump(1, '\t') + "\n");
    }
    if (data.contains("nfqws")) {
        for (const auto& item : data.at("nfqws").items()) {
            const fs::path relative(item.key());
            if (relative.is_absolute() || item.key().find("..") != std::string::npos || !item.value().is_string())
                throw ApiError("invalid nfqws path in backup", 400);
            const auto first = *relative.begin();
            const fs::path root = first == "nfqws2" ? "/opt/etc/nfqws2" :
                                  first == "strategies" ? "/opt/etc/keen-pbr/nfqws-strategies" : fs::path{};
            if (root.empty()) throw ApiError("invalid nfqws path in backup", 400);
            auto tail = relative;
            tail = tail.lexically_relative(first);
            write_atomic(root / tail, item.value().get<std::string>());
        }
    }

    write_atomic(ctx.config_path, formatted);
    const auto result = ctx.enqueue_apply_validated_config(std::move(parsed), formatted);
    if (!result.error.empty()) throw ApiError("restore apply failed: " + result.error, 500);
    if (data.contains("transports"))
        (void)std::system("/opt/etc/init.d/S79transport-manager restart >/dev/null 2>&1");
    if (data.contains("nfqws"))
        (void)std::system("/opt/etc/init.d/S51nfqws2 restart >/dev/null 2>&1");
}

} // namespace

std::string create_full_rollback_backup(const ApiContext& ctx) {
    const auto payload = make_backup(ctx, all_groups()).dump(1, '\t') + "\n";
    write_atomic(kRollbackPath, payload);
    return payload;
}

void register_backup_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/backup", [&ctx](const std::string& body) -> std::string {
        nlohmann::json request;
        try { request = nlohmann::json::parse(body); }
        catch (...) { throw ApiError("invalid backup request", 400); }
        return make_backup(ctx, request.value("groups", nlohmann::json::object())).dump();
    });
    server.post("/api/backup/restore", [&ctx](const std::string& body) -> std::string {
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
