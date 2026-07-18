#ifdef WITH_API

#include "handler_nfqws.hpp"

#include "../http/http_client.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <vector>
#include <zlib.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;
constexpr const char* kBinary = "/opt/usr/bin/nfqws2";
constexpr const char* kInit = "/opt/etc/init.d/S51nfqws2";
constexpr const char* kConfigDir = "/opt/etc/nfqws2";
constexpr const char* kListsDir = "/opt/etc/nfqws2/lists";
constexpr const char* kLuaDir = "/opt/etc/nfqws2/lua";
constexpr const char* kLogDir = "/opt/var/log";
constexpr const char* kBuiltinStrategies = "/opt/usr/share/keen-pbr/nfqws-strategies";
constexpr const char* kUserStrategies = "/opt/etc/keen-pbr/nfqws-strategies";

bool valid_name(const std::string& value, bool allow_spaces = false) {
    if (value.empty() || value.size() > 80 || value == "." || value == "..") return false;
    return std::all_of(value.begin(), value.end(), [allow_spaces](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' ||
               ch == '(' || ch == ')' || (allow_spaces && ch == ' ');
    });
}

std::string read_file(const fs::path& path, std::size_t limit = 2U * 1024U * 1024U) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > limit) throw ApiError("nfqws file is missing or too large", 400);
    if (path.extension() == ".gz") {
        gzFile input = gzopen(path.c_str(), "rb");
        if (!input) throw ApiError("failed to read compressed nfqws file", 500);
        std::array<char, 16U * 1024U> buffer{};
        std::string content;
        int count = 0;
        while ((count = gzread(input, buffer.data(), static_cast<unsigned int>(buffer.size()))) > 0) {
            if (content.size() + static_cast<std::size_t>(count) > limit) {
                gzclose(input);
                throw ApiError("compressed nfqws file is too large", 413);
            }
            content.append(buffer.data(), static_cast<std::size_t>(count));
        }
        const auto close_status = gzclose(input);
        if (count < 0 || close_status != Z_OK)
            throw ApiError("failed to decompress nfqws file", 500);
        return content;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw ApiError("failed to read nfqws file", 500);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_file_atomic(const fs::path& path, const std::string& content) {
    if (content.size() > 2U * 1024U * 1024U) throw ApiError("nfqws file is too large", 413);
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) throw ApiError("failed to create nfqws directory", 500);
    // keen-pbr can run with a restrictive umask, while nfqws2 drops privileges
    // to nobody. Preserve an existing file's ownership/mode and make new
    // editable nfqws files world-readable so the service can reopen them.
    ::chmod(path.parent_path().c_str(), 0755);
    struct stat previous{};
    const bool had_previous = ::stat(path.c_str(), &previous) == 0;
    auto temporary = path;
    temporary += ".keen-pbr-sb.tmp";
    if (path.extension() == ".gz") {
        gzFile output = gzopen(temporary.c_str(), "wb9");
        if (!output) throw ApiError("failed to write compressed nfqws file", 500);
        const auto written = gzwrite(output, content.data(), static_cast<unsigned int>(content.size()));
        const auto close_status = gzclose(output);
        if (written != static_cast<int>(content.size()) || close_status != Z_OK) {
            fs::remove(temporary, ec);
            throw ApiError("failed to compress nfqws file", 500);
        }
    } else {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output || !(output << content)) throw ApiError("failed to write nfqws file", 500);
    }
    const mode_t mode = had_previous ? ((previous.st_mode & 0777) | 0444) : 0644;
    if (::chmod(temporary.c_str(), mode) != 0) {
        fs::remove(temporary, ec);
        throw ApiError("failed to set nfqws file permissions", 500);
    }
    if (had_previous && ::chown(temporary.c_str(), previous.st_uid, previous.st_gid) != 0) {
        fs::remove(temporary, ec);
        throw ApiError("failed to preserve nfqws file ownership", 500);
    }
    fs::rename(temporary, path, ec);
    if (ec) {
        fs::remove(path, ec);
        ec.clear();
        fs::rename(temporary, path, ec);
    }
    if (ec) throw ApiError("failed to replace nfqws file", 500);
}

bool natural_less(const std::string& lhs, const std::string& rhs) {
    std::size_t left = 0;
    std::size_t right = 0;
    while (left < lhs.size() && right < rhs.size()) {
        const auto lch = static_cast<unsigned char>(lhs[left]);
        const auto rch = static_cast<unsigned char>(rhs[right]);
        if (std::isdigit(lch) && std::isdigit(rch)) {
            std::size_t lend = left;
            std::size_t rend = right;
            while (lend < lhs.size() && std::isdigit(static_cast<unsigned char>(lhs[lend]))) ++lend;
            while (rend < rhs.size() && std::isdigit(static_cast<unsigned char>(rhs[rend]))) ++rend;
            auto lsignificant = left;
            auto rsignificant = right;
            while (lsignificant + 1 < lend && lhs[lsignificant] == '0') ++lsignificant;
            while (rsignificant + 1 < rend && rhs[rsignificant] == '0') ++rsignificant;
            const auto ldigits = lend - lsignificant;
            const auto rdigits = rend - rsignificant;
            if (ldigits != rdigits) return ldigits < rdigits;
            const auto numeric_compare = lhs.compare(lsignificant, ldigits, rhs, rsignificant, rdigits);
            if (numeric_compare != 0) return numeric_compare < 0;
            left = lend;
            right = rend;
            continue;
        }
        const auto lower_left = static_cast<unsigned char>(std::tolower(lch));
        const auto lower_right = static_cast<unsigned char>(std::tolower(rch));
        if (lower_left != lower_right) return lower_left < lower_right;
        ++left;
        ++right;
    }
    return lhs.size() < rhs.size();
}

std::pair<fs::path, std::string> file_path(const std::string& category,
                                           const std::string& name) {
    if (!valid_name(name)) throw ApiError("invalid nfqws filename", 400);
    if (category == "config" && name.size() >= 5 && name.substr(name.size() - 5) == ".conf")
        return {fs::path(kConfigDir) / name, "config"};
    if (category == "list" && name.size() >= 5 && name.substr(name.size() - 5) == ".list")
        return {fs::path(kListsDir) / name, "list"};
    if (category == "lua" &&
        ((name.size() >= 4 && name.substr(name.size() - 4) == ".lua") ||
         (name.size() >= 7 && name.substr(name.size() - 7) == ".lua.gz")))
        return {fs::path(kLuaDir) / name, "lua"};
    if (category == "log" && name.size() >= 4 && name.substr(name.size() - 4) == ".log" && name.rfind("nfqws", 0) == 0)
        return {fs::path(kLogDir) / name, "log"};
    throw ApiError("unsupported nfqws file", 400);
}

std::string run_command(const std::string& command, int& status) {
    std::array<char, 1024> buffer{};
    std::string output;
    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (!pipe) throw ApiError("failed to run nfqws command", 500);
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        if (output.size() < 128U * 1024U) output += buffer.data();
    }
    status = pclose(pipe);
    return output;
}

std::string installed_version() {
    int status = 0;
    auto output = run_command("/opt/bin/opkg status nfqws2-keenetic | awk -F': ' '/^Version:/ {print $2; exit}'", status);
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
    return output;
}

void append_files(nlohmann::json& files, const fs::path& directory,
                  const std::string& category, const std::string& suffix,
                  bool removable) {
    std::error_code ec;
    if (!fs::is_directory(directory, ec)) return;
    for (const auto& entry : fs::directory_iterator(directory, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const auto name = entry.path().filename().string();
        if (name.size() < suffix.size() || name.substr(name.size() - suffix.size()) != suffix) continue;
        if (category == "log" && name.rfind("nfqws", 0) != 0) continue;
        files.push_back({{"name", name}, {"category", category},
                         {"removable", removable}, {"size", entry.file_size(ec)}});
    }
}

std::set<std::string> deleted_strategies() {
    std::set<std::string> result;
    std::error_code ec;
    const auto directory = fs::path(kUserStrategies) / ".deleted";
    if (!fs::is_directory(directory, ec)) return result;
    for (const auto& entry : fs::directory_iterator(directory, ec))
        if (entry.is_regular_file(ec)) result.insert(entry.path().filename().string());
    return result;
}

nlohmann::json list_strategies() {
    nlohmann::json result = nlohmann::json::array();
    const auto deleted = deleted_strategies();
    std::set<std::string> names;
    std::error_code ec;
    if (fs::is_directory(kBuiltinStrategies, ec)) {
        for (const auto& entry : fs::directory_iterator(kBuiltinStrategies, ec)) {
            if (!entry.is_directory(ec)) continue;
            const auto name = entry.path().filename().string();
            const auto config = entry.path() / "nfqws2.conf";
            if (!valid_name(name, true) || deleted.count(name) || !fs::is_regular_file(config, ec)) continue;
            const auto override_path = fs::path(kUserStrategies) / (name + ".conf");
            const bool overridden = fs::is_regular_file(override_path, ec);
            result.push_back({{"name", name}, {"builtin", true}, {"overridden", overridden},
                              {"content", read_file(overridden ? override_path : config)}});
            names.insert(name);
        }
    }
    if (fs::is_directory(kUserStrategies, ec)) {
        for (const auto& entry : fs::directory_iterator(kUserStrategies, ec)) {
            if (!entry.is_regular_file(ec) || entry.path().extension() != ".conf") continue;
            const auto name = entry.path().stem().string();
            if (!valid_name(name, true) || names.count(name) || deleted.count(name)) continue;
            result.push_back({{"name", name}, {"builtin", false}, {"overridden", false},
                              {"content", read_file(entry.path())}});
        }
    }
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        return natural_less(lhs.at("name").template get<std::string>(),
                            rhs.at("name").template get<std::string>());
    });
    return result;
}

fs::path strategy_source(const std::string& name) {
    if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
    std::error_code ec;
    const auto custom = fs::path(kUserStrategies) / (name + ".conf");
    if (fs::is_regular_file(custom, ec)) return custom;
    const auto builtin = fs::path(kBuiltinStrategies) / name / "nfqws2.conf";
    if (fs::is_regular_file(builtin, ec)) return builtin;
    throw ApiError("nfqws strategy not found", 404);
}

} // namespace

void register_nfqws_handler(ApiServer& server, ApiContext&) {
    server.get("/api/nfqws", []() -> std::string {
        std::error_code ec;
        const bool installed = fs::is_regular_file(kBinary, ec);
        bool running = false;
        if (installed && fs::is_regular_file(kInit, ec)) {
            int status = 0;
            const auto output = run_command(std::string(kInit) + " status", status);
            running = output.find("is running") != std::string::npos;
        }
        nlohmann::json files = nlohmann::json::array();
        append_files(files, kConfigDir, "config", ".conf", false);
        append_files(files, kListsDir, "list", ".list", true);
        append_files(files, kLuaDir, "lua", ".lua", true);
        append_files(files, kLuaDir, "lua", ".lua.gz", true);
        append_files(files, kLogDir, "log", ".log", false);
        auto strategies = list_strategies();
        std::string active_strategy;
        const auto active_config = fs::path(kConfigDir) / "nfqws2.conf";
        if (fs::is_regular_file(active_config, ec)) {
            const auto active_content = read_file(active_config);
            for (const auto& strategy : strategies) {
                if (strategy.value("content", std::string{}) == active_content) {
                    active_strategy = strategy.value("name", std::string{});
                    break;
                }
            }
        }
        return nlohmann::json{{"installed", installed}, {"running", running},
                              {"version", installed ? installed_version() : ""},
                              {"files", files}, {"strategies", strategies},
                              {"active_strategy", active_strategy}}
            .dump();
    });

    server.post("/api/nfqws", [](const std::string& body) -> std::string {
        nlohmann::json request;
        try { request = nlohmann::json::parse(body); }
        catch (const nlohmann::json::exception&) { throw ApiError("invalid nfqws request", 400); }
        const auto action = request.value("action", std::string{});

        if (action == "read_file") {
            const auto [path, category] = file_path(request.value("category", ""), request.value("name", ""));
            auto content = read_file(path);
            if (category == "log") {
                std::vector<std::string> lines;
                std::string line;
                std::istringstream input(content);
                while (std::getline(input, line)) lines.push_back(line);
                std::reverse(lines.begin(), lines.end());
                content.clear();
                for (const auto& item : lines) content += item + "\n";
            }
            return nlohmann::json{{"content", content}}.dump();
        }
        if (action == "save_file" || action == "create_file") {
            const auto [path, category] = file_path(request.value("category", ""), request.value("name", ""));
            if (action == "create_file" && fs::exists(path)) throw ApiError("nfqws file already exists", 409);
            if (category == "log" && action == "create_file") throw ApiError("cannot create a log", 400);
            write_file_atomic(path, request.value("content", std::string{}));
            return R"({"ok":true})";
        }
        if (action == "delete_file") {
            const auto [path, category] = file_path(request.value("category", ""), request.value("name", ""));
            if (category == "config" || category == "log") throw ApiError("this nfqws file cannot be deleted", 400);
            std::error_code ec2;
            if (!fs::remove(path, ec2)) throw ApiError("failed to delete nfqws file", 500);
            return R"({"ok":true})";
        }
        if (action == "clear_log") {
            const auto [path, category] = file_path("log", request.value("name", ""));
            if (category != "log") throw ApiError("only nfqws logs can be cleared", 400);
            write_file_atomic(path, "");
            return R"({"ok":true})";
        }
        if (action == "service") {
            const auto command = request.value("command", std::string{});
            if (command != "start" && command != "stop" && command != "restart" && command != "reload")
                throw ApiError("unsupported nfqws service command", 400);
            if (!fs::exists(kInit)) throw ApiError("nfqws2 is not installed", 409);
            int status = 0;
            const auto output = run_command(std::string(kInit) + " " + command, status);
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status}}.dump();
        }
        if (action == "upgrade") {
            int status = 0;
            const auto output = run_command("/opt/bin/opkg update && /opt/bin/opkg upgrade nfqws2-keenetic", status);
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status}}.dump();
        }
        if (action == "save_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            write_file_atomic(fs::path(kUserStrategies) / (name + ".conf"), request.value("content", std::string{}));
            std::error_code ec2;
            fs::remove(fs::path(kUserStrategies) / ".deleted" / name, ec2);
            return R"({"ok":true})";
        }
        if (action == "apply_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            const auto content = request.contains("content") && request["content"].is_string()
                                     ? request["content"].get<std::string>()
                                     : read_file(strategy_source(name));
            write_file_atomic(fs::path(kConfigDir) / "nfqws2.conf", content);
            if (!fs::exists(kInit)) throw ApiError("nfqws2 is not installed", 409);
            int status = 0;
            const auto output = run_command(std::string(kInit) + " restart", status);
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status}}.dump();
        }
        if (action == "delete_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            std::error_code ec2;
            fs::remove(fs::path(kUserStrategies) / (name + ".conf"), ec2);
            write_file_atomic(fs::path(kUserStrategies) / ".deleted" / name, "deleted\n");
            return R"({"ok":true})";
        }
        if (action == "import_lists") {
            if (!request.contains("files") || !request["files"].is_object()) throw ApiError("nfqws list bundle is invalid", 400);
            for (const auto& item : request["files"].items()) {
                const auto [path, category] = file_path("list", item.key());
                if (!item.value().is_string()) throw ApiError("nfqws list content must be text", 400);
                write_file_atomic(path, item.value().get<std::string>());
            }
            return R"({"ok":true})";
        }
        if (action == "check_url") {
            const auto url = request.value("url", std::string{});
            if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) throw ApiError("invalid URL", 400);
            HttpClient client;
            client.set_timeout(std::chrono::seconds(10));
            client.set_max_response_size(50U * 1024U);
            try { client.download(url); return R"({"ok":true,"reachable":true})"; }
            catch (const std::exception&) { return R"({"ok":true,"reachable":false})"; }
        }
        throw ApiError("unsupported nfqws action", 400);
    });
}

} // namespace keen_pbr3

#endif
