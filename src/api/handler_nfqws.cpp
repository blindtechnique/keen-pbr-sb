#ifdef WITH_API

#include "handler_nfqws.hpp"
#include "handler_backup.hpp"

#include "../http/http_client.hpp"
#include "../util/network_routes.hpp"
#include "../util/nfqws_config.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <httplib.h>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <signal.h>
#include <sstream>
#include <string>
#include <thread>
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
constexpr const char* kPidfile = "/opt/var/run/nfqws2.pid";
constexpr const char* kConfigDir = "/opt/etc/nfqws2";
constexpr const char* kListsDir = "/opt/etc/nfqws2/lists";
constexpr const char* kLuaDir = "/opt/etc/nfqws2/lua";
constexpr const char* kLogDir = "/opt/var/log";
constexpr const char* kBuiltinStrategies = "/opt/usr/share/keen-pbr/nfqws-strategies";
constexpr const char* kUserStrategies = "/opt/etc/keen-pbr/nfqws-strategies";

std::string read_file(const fs::path& path, std::size_t limit = 2U * 1024U * 1024U);
void write_file_atomic(const fs::path& path, const std::string& content);

std::string render_wan_interfaces(const std::string& content) {
    return nfqws_config_with_isp_interfaces(content, default_route_interfaces());
}

bool builtin_strategy(const std::string& name) {
    std::error_code ec;
    return fs::is_regular_file(fs::path(kBuiltinStrategies) / name / "nfqws2.conf", ec);
}

bool generated_default_strategy(const std::string& name) {
    return name.rfind("default (", 0) == 0;
}

bool automatic_wan_strategy(const std::string& name) {
    std::error_code ec;
    const bool overridden =
        fs::is_regular_file(fs::path(kUserStrategies) / (name + ".conf"), ec);
    return generated_default_strategy(name) || (builtin_strategy(name) && !overridden);
}

std::string dated_default_name() {
    const auto now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    char date[16]{};
    std::strftime(date, sizeof(date), "%Y.%m.%d", &local);
    return std::string("default (") + date + ')';
}

std::array<fs::path, 5> nfqws_config_candidates() {
    return {
        fs::path(kConfigDir) / "nfqws2.conf",
        fs::path(kConfigDir) / "nfqws2.conf-opkg",
        fs::path(kConfigDir) / "nfqws2.conf.opkg",
        fs::path(kConfigDir) / "nfqws2.conf-opkg-new",
        fs::path(kConfigDir) / "nfqws2.conf.opkg-dist",
    };
}

std::map<std::string, std::string> read_candidate_configs() {
    std::map<std::string, std::string> result;
    std::error_code ec;
    for (const auto& candidate : nfqws_config_candidates()) {
        if (fs::is_regular_file(candidate, ec)) result[candidate.string()] = read_file(candidate);
    }
    return result;
}

std::string save_updated_default_strategy(
    const std::string& previous,
    const std::map<std::string, std::string>& candidates_before_upgrade) {
    const auto old_semantics = nfqws_config_without_ipv6_toggle(previous);
    std::error_code ec;
    for (const auto& candidate : nfqws_config_candidates()) {
        if (!fs::is_regular_file(candidate, ec)) continue;
        const auto updated = read_file(candidate);
        const auto previous_candidate = candidates_before_upgrade.find(candidate.string());
        if (previous_candidate != candidates_before_upgrade.end() &&
            previous_candidate->second == updated) {
            continue;
        }
        if (nfqws_config_without_ipv6_toggle(updated) == old_semantics) continue;

        const auto base = dated_default_name();
        for (unsigned int suffix = 1; suffix < 100; ++suffix) {
            const auto name = suffix == 1 ? base : base + " " + std::to_string(suffix);
            const auto destination = fs::path(kUserStrategies) / (name + ".conf");
            if (fs::is_regular_file(destination, ec)) {
                if (nfqws_config_without_ipv6_toggle(read_file(destination)) ==
                    nfqws_config_without_ipv6_toggle(updated)) {
                    return name;
                }
                continue;
            }
            write_file_atomic(destination, updated);
            return name;
        }
        throw ApiError("too many nfqws default strategies for this date", 409);
    }
    return {};
}

bool valid_name(const std::string& value, bool allow_spaces = false) {
    if (value.empty() || value.size() > 80 || value == "." || value == "..") return false;
    return std::all_of(value.begin(), value.end(), [allow_spaces](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' ||
               ch == '(' || ch == ')' || (allow_spaces && ch == ' ');
    });
}

std::string read_file(const fs::path& path, std::size_t limit) {
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

std::array<unsigned long, 3> semantic_version(const std::string& value) {
    std::array<unsigned long, 3> result{};
    auto cursor = value.find_first_of("0123456789");
    for (std::size_t index = 0; index < result.size() && cursor != std::string::npos; ++index) {
        const auto end = value.find_first_not_of("0123456789", cursor);
        try {
            result[index] = std::stoul(value.substr(cursor, end - cursor));
        } catch (const std::exception&) {
            return {};
        }
        if (index + 1 == result.size() || end == std::string::npos || value[end] != '.') break;
        cursor = end + 1;
    }
    return result;
}

bool newer_version(const std::string& latest, const std::string& current) {
    return semantic_version(latest) > semantic_version(current);
}

nlohmann::json nfqws_update_status(bool force = false) {
    static std::mutex mutex;
    static nlohmann::json cached;
    static std::chrono::steady_clock::time_point checked_at{};
    constexpr auto kCacheLifetime = std::chrono::minutes(30);

    const std::lock_guard lock(mutex);
    const auto now = std::chrono::steady_clock::now();
    if (!force && !cached.empty() && now - checked_at < kCacheLifetime) return cached;

    HttpClient client;
    client.set_timeout(std::chrono::seconds(10));
    client.set_max_response_size(256U * 1024U);
    const auto release = nlohmann::json::parse(client.download(
        "https://api.github.com/repos/nfqws/nfqws2-keenetic/releases/latest"));
    const auto current = installed_version();
    const auto latest = release.value("tag_name", std::string{});
    if (latest.empty()) throw ApiError("nfqws2 release does not contain a version", 502);

    cached = nlohmann::json{{"ok", true},
                            {"current", current},
                            {"latest", latest},
                            {"available", newer_version(latest, current)},
                            {"release_url", release.value("html_url", std::string{})}};
    checked_at = now;
    return cached;
}

std::mutex& nfqws_operation_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::vector<pid_t> nfqws_processes() {
    std::vector<pid_t> result;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/proc", ec)) {
        if (!entry.is_directory(ec)) continue;
        const auto name = entry.path().filename().string();
        if (name.empty() || !std::all_of(name.begin(), name.end(), [](unsigned char ch) {
                return std::isdigit(ch);
            }))
            continue;

        std::ifstream comm(entry.path() / "comm");
        std::string process_name;
        std::getline(comm, process_name);
        if (process_name != "nfqws2" && process_name != "nfqws") continue;

        try {
            result.push_back(static_cast<pid_t>(std::stol(name)));
        } catch (const std::exception&) {
        }
    }
    return result;
}

// nfqws2.conf carries the queue the daemon binds to. Hardcoding 300 makes the
// health check and the start/restart verification report failure whenever the
// user changes NFQUEUE_NUM from the web interface, so read it back instead.
int configured_nfqueue_num() {
    constexpr int kDefaultQueue = 300;
    std::ifstream input(fs::path(kConfigDir) / "nfqws2.conf");
    std::string line;
    while (std::getline(input, line)) {
        const auto key = line.find("NFQUEUE_NUM");
        if (key == std::string::npos) continue;
        if (line.find_first_not_of(" \t") != key) continue; // skip comments
        const auto eq = line.find('=', key);
        if (eq == std::string::npos) continue;

        std::string value = line.substr(eq + 1);
        value.erase(0, value.find_first_not_of(" \t\"'"));
        const auto end = value.find_first_not_of("0123456789");
        if (end != std::string::npos) value.erase(end);
        if (value.empty()) continue;
        try {
            const int parsed = std::stoi(value);
            if (parsed >= 0 && parsed <= 65535) return parsed;
        } catch (const std::exception&) {
        }
    }
    return kDefaultQueue;
}

bool nfqueue_active(int queue_number) {
    std::ifstream input("/proc/net/netfilter/nfnetlink_queue");
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        int current_queue = -1;
        if (fields >> current_queue && current_queue == queue_number) return true;
    }
    return false;
}

// nfqws2 1.0.2 can leave an empty PID file even though the daemon and its
// NFQUEUE socket are alive. Its init script then treats the empty string as a
// number, fails to stop the old daemon and starts a second process which cannot
// bind queue 300. Repair the file only immediately before an explicit service
// command and only when there is exactly one unambiguous daemon process.
void repair_nfqws_pidfile() {
    const auto processes = nfqws_processes();
    if (processes.size() != 1) return;

    std::ofstream output(kPidfile, std::ios::trunc);
    if (output) output << processes.front() << '\n';
}

bool wait_for_nfqws_exit(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        if (nfqws_processes().empty() && !nfqueue_active(configured_nfqueue_num())) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (std::chrono::steady_clock::now() < deadline);
    return nfqws_processes().empty() && !nfqueue_active(configured_nfqueue_num());
}

std::string run_nfqws_service_command(const std::string& command, int& status) {
    if (command == "reload") {
        repair_nfqws_pidfile();
        return run_command(std::string(kInit) + " reload", status);
    }

    if (command == "start") {
        auto output = run_command(std::string(kInit) + " start", status);
        for (int attempt = 0;
             attempt < 30 && (nfqws_processes().empty() || !nfqueue_active(configured_nfqueue_num()));
             ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        repair_nfqws_pidfile();
        status = status == 0 && !nfqws_processes().empty() && nfqueue_active(configured_nfqueue_num()) ? 0 : 1;
        return output;
    }

    repair_nfqws_pidfile();
    int stop_status = 0;
    auto output = run_command(std::string(kInit) + " stop", stop_status);
    if (!wait_for_nfqws_exit(std::chrono::seconds(3))) {
        output += "nfqws2 did not stop in time; terminating the stale process.\n";
        for (const auto pid : nfqws_processes()) ::kill(pid, SIGKILL);
        wait_for_nfqws_exit(std::chrono::seconds(2));
    }

    if (command == "stop") {
        status = nfqws_processes().empty() && !nfqueue_active(configured_nfqueue_num()) ? 0 : 1;
        return output;
    }

    int start_status = 0;
    output += run_command(std::string(kInit) + " start", start_status);
    for (int attempt = 0;
         attempt < 30 && (nfqws_processes().empty() || !nfqueue_active(configured_nfqueue_num()));
         ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    repair_nfqws_pidfile();
    status = start_status == 0 && !nfqws_processes().empty() && nfqueue_active(configured_nfqueue_num()) ? 0 : 1;
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

void register_nfqws_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/nfqws", []() -> std::string {
        std::error_code ec;
        const bool installed = fs::is_regular_file(kBinary, ec);
        const bool process_running = installed && !nfqws_processes().empty();
        const bool queue_active = installed && nfqueue_active(configured_nfqueue_num());
        const bool running = process_running && queue_active;
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
                const auto name = strategy.value("name", std::string{});
                auto expected = strategy.value("content", std::string{});
                if (automatic_wan_strategy(name)) expected = render_wan_interfaces(expected);
                if (expected == active_content) {
                    active_strategy = strategy.value("name", std::string{});
                    break;
                }
            }
        }
        return nlohmann::json{{"installed", installed}, {"running", running},
                              {"process_running", process_running},
                              {"queue_active", queue_active},
                              {"version", installed ? installed_version() : ""},
                              {"files", files}, {"strategies", strategies},
                              {"active_strategy", active_strategy}}
            .dump();
    });

    server.post("/api/nfqws", [&ctx](const std::string& body) -> std::string {
        nlohmann::json request;
        try { request = nlohmann::json::parse(body); }
        catch (const nlohmann::json::exception&) { throw ApiError("invalid nfqws request", 400); }
        const auto action = request.value("action", std::string{});

        if (action == "check_update") {
            return nfqws_update_status(request.value("force", false)).dump();
        }

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
            const std::lock_guard lock(nfqws_operation_mutex());
            write_file_atomic(path, request.value("content", std::string{}));
            return R"({"ok":true})";
        }
        if (action == "delete_file") {
            const auto [path, category] = file_path(request.value("category", ""), request.value("name", ""));
            if (category == "config" || category == "log") throw ApiError("this nfqws file cannot be deleted", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            std::error_code ec2;
            if (!fs::remove(path, ec2)) throw ApiError("failed to delete nfqws file", 500);
            return R"({"ok":true})";
        }
        if (action == "clear_log") {
            const auto [path, category] = file_path("log", request.value("name", ""));
            if (category != "log") throw ApiError("only nfqws logs can be cleared", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            write_file_atomic(path, "");
            return R"({"ok":true})";
        }
        if (action == "service") {
            const auto command = request.value("command", std::string{});
            if (command != "start" && command != "stop" && command != "restart" && command != "reload")
                throw ApiError("unsupported nfqws service command", 400);
            if (!fs::exists(kInit)) throw ApiError("nfqws2 is not installed", 409);
            const std::lock_guard lock(nfqws_operation_mutex());
            int status = 0;
            const auto output = run_nfqws_service_command(command, status);
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status}}.dump();
        }
        if (action == "upgrade") {
            const std::lock_guard lock(nfqws_operation_mutex());
            std::error_code ec2;
            const auto active_config = fs::path(kConfigDir) / "nfqws2.conf";
            const auto previous = fs::is_regular_file(active_config, ec2)
                                      ? read_file(active_config)
                                      : std::string{};
            const auto candidates_before_upgrade = read_candidate_configs();
            // This is the same validated rollback bundle used by the main
            // keen-pbr-sb updater. It includes all nfqws2 configuration,
            // lists, Lua files and user strategies before opkg touches them.
            create_full_rollback_backup(ctx);
            int status = 0;
            auto output = std::string("Rollback backup created.\n") +
                          run_command("/opt/bin/opkg update && /opt/bin/opkg upgrade nfqws2-keenetic", status);
            const auto created = status == 0
                                     ? save_updated_default_strategy(previous, candidates_before_upgrade)
                                     : std::string{};
            if (status == 0) {
                output += "\nInstalled nfqws2 version: " + installed_version() + "\n";
            }
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status},
                                  {"strategy_created", created}}.dump();
        }
        if (action == "save_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            write_file_atomic(fs::path(kUserStrategies) / (name + ".conf"), request.value("content", std::string{}));
            std::error_code ec2;
            fs::remove(fs::path(kUserStrategies) / ".deleted" / name, ec2);
            return R"({"ok":true})";
        }
        if (action == "apply_strategy") {
            const std::lock_guard lock(nfqws_operation_mutex());
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            auto content = request.contains("content") && request["content"].is_string()
                               ? request["content"].get<std::string>()
                               : read_file(strategy_source(name));
            if (automatic_wan_strategy(name)) content = render_wan_interfaces(content);
            write_file_atomic(fs::path(kConfigDir) / "nfqws2.conf", content);
            if (!fs::exists(kInit)) throw ApiError("nfqws2 is not installed", 409);
            int status = 0;
            const auto output = run_nfqws_service_command("restart", status);
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status}}.dump();
        }
        if (action == "save_files") {
            if (!request.contains("files") || !request["files"].is_array())
                throw ApiError("nfqws files payload is invalid", 400);
            if (request["files"].empty() || request["files"].size() > 256)
                throw ApiError("nfqws files payload is empty or too large", 400);

            struct PendingFile {
                fs::path path;
                std::string content;
            };
            std::vector<PendingFile> pending;
            std::set<std::string> unique;
            std::size_t total_size = 0;
            for (const auto& item : request["files"]) {
                if (!item.is_object() || !item.contains("content") || !item["content"].is_string())
                    throw ApiError("nfqws file entry is invalid", 400);
                const auto category = item.value("category", std::string{});
                const auto name = item.value("name", std::string{});
                if (category != "list" && category != "lua")
                    throw ApiError("only nfqws lists and Lua files can be batch-saved", 400);
                const auto [path, resolved_category] = file_path(category, name);
                if (resolved_category != category || !unique.insert(category + '/' + name).second)
                    throw ApiError("duplicate or mismatched nfqws file", 400);
                auto content = item["content"].get<std::string>();
                total_size += content.size();
                if (content.size() > 2U * 1024U * 1024U || total_size > 8U * 1024U * 1024U)
                    throw ApiError("nfqws files payload is too large", 413);
                pending.push_back({path, std::move(content)});
            }

            const std::lock_guard lock(nfqws_operation_mutex());
            for (const auto& item : pending) write_file_atomic(item.path, item.content);
            std::string output = "Saved " + std::to_string(pending.size()) + " nfqws file(s).\n";
            int status = 0;
            if (request.value("restart", false)) {
                output += run_nfqws_service_command("restart", status);
            }
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status},
                                  {"saved", pending.size()}}.dump();
        }
        if (action == "delete_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            std::error_code ec2;
            fs::remove(fs::path(kUserStrategies) / (name + ".conf"), ec2);
            write_file_atomic(fs::path(kUserStrategies) / ".deleted" / name, "deleted\n");
            return R"({"ok":true})";
        }
        if (action == "import_lists") {
            if (!request.contains("files") || !request["files"].is_object()) throw ApiError("nfqws list bundle is invalid", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            for (const auto& item : request["files"].items()) {
                const auto [path, category] = file_path("list", item.key());
                if (!item.value().is_string()) throw ApiError("nfqws list content must be text", 400);
                write_file_atomic(path, item.value().get<std::string>());
            }
            return R"({"ok":true})";
        }
        if (action == "import_bundle") {
            if (!request.contains("files") || !request["files"].is_object())
                throw ApiError("nfqws bundle is invalid", 400);

            struct PendingFile {
                fs::path path;
                std::string content;
            };
            std::vector<PendingFile> pending;
            std::size_t total_size = 0;
            for (const auto& category : {"config", "list"}) {
                const auto category_it = request["files"].find(category);
                if (category_it == request["files"].end()) continue;
                if (!category_it->is_object()) throw ApiError("nfqws bundle category is invalid", 400);
                for (const auto& item : category_it->items()) {
                    if (!item.value().is_string()) throw ApiError("nfqws bundle content must be text", 400);
                    const auto [path, resolved_category] = file_path(category, item.key());
                    if (resolved_category != category) throw ApiError("nfqws bundle category mismatch", 400);
                    auto content = item.value().get<std::string>();
                    if (content.size() > 2U * 1024U * 1024U)
                        throw ApiError("nfqws bundle file is too large", 413);
                    total_size += content.size();
                    if (total_size > 8U * 1024U * 1024U || pending.size() >= 256)
                        throw ApiError("nfqws bundle is too large", 413);
                    pending.push_back({path, std::move(content)});
                }
            }
            if (pending.empty()) throw ApiError("nfqws bundle is empty", 400);
            // Validate the entire bundle before the first write. Each file is
            // then replaced atomically by write_file_atomic().
            const std::lock_guard lock(nfqws_operation_mutex());
            for (const auto& item : pending) write_file_atomic(item.path, item.content);
            return R"({"ok":true})";
        }
        if (action == "check_url") {
            const auto url = request.value("url", std::string{});
            if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) throw ApiError("invalid URL", 400);
            HttpClient client;
            client.set_timeout(std::chrono::seconds(10));
            // 50 KB used to be the cap here, and almost every real page is
            // larger, so the download threw on the size limit and a perfectly
            // reachable site was reported unreachable.
            client.set_max_response_size(4U * 1024U * 1024U);
            nlohmann::json response;
            response["ok"] = true;
            try {
                client.download(url);
                response["reachable"] = true;
            } catch (const std::exception& e) {
                // The reason matters: a name that does not resolve, a refused
                // connection and a TLS handshake cut short are three different
                // problems, and only the last is what nfqws2 exists to fix.
                response["reachable"] = false;
                response["error"] = e.what();
            }
            return response.dump();
        }
        throw ApiError("unsupported nfqws action", 400);
    });
}

} // namespace keen_pbr3

#endif
