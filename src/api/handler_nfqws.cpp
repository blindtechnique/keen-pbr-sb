#ifdef WITH_API

#include "handler_nfqws.hpp"
#include "handler_backup.hpp"
#include "maintenance_api.hpp"
#include "../update/component_capture.hpp"
#include "../update/component_transaction_journal.hpp"
#include "../update/package_footprint.hpp"
#include "../update/rescue_integrity.hpp"
#include "../util/nfqws_config_migration.hpp"
#include "../util/nfqws_runtime_state.hpp"

#include "../http/http_client.hpp"
#include "../util/network_routes.hpp"
#include "../util/nfqws_config.hpp"
#include "../util/nfqws_file_writer.hpp"
#include "../util/nfqws_rotator_state.hpp"
#include "../util/nfqws_strategy_assets.hpp"
#include "../util/nfqws_validator.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <httplib.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <signal.h>
#include <sstream>
#include <string>
#include <thread>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>
#include <zlib.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;
constexpr const char* kBinary = "/opt/usr/bin/nfqws2";
constexpr const char* kInit = "/opt/etc/init.d/S51nfqws2";
constexpr const char* kPidfile = "/opt/var/run/nfqws2.pid";
constexpr const char* kConfigDir = "/opt/etc/nfqws2";
constexpr const char* kOpkgPackageFileList =
    "/opt/lib/opkg/info/nfqws2-keenetic.list";
constexpr const char* kNfqwsJournal =
    "/opt/var/lib/keen-pbr/nfqws-transaction.json";
constexpr const char* kNfqwsCapture =
    "/opt/var/lib/keen-pbr/nfqws-restore-point";
constexpr const char* kListsDir = "/opt/etc/nfqws2/lists";
constexpr const char* kLuaDir = "/opt/etc/nfqws2/lua";
constexpr const char* kLogDir = "/opt/var/log";
constexpr const char* kBuiltinStrategies = "/opt/usr/share/keen-pbr/nfqws-strategies";
constexpr const char* kBuiltinBlobs = "/opt/usr/share/keen-pbr/nfqws-blobs";
constexpr const char* kPackagedRotatorReporter =
    "/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua";
constexpr const char* kLiveRotatorReporter =
    "/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua";
constexpr const char* kRotatorStateDirectory =
    "/var/run/keen-pbr-nfqws";
constexpr const char* kUserStrategies = "/opt/etc/keen-pbr/nfqws-strategies";
constexpr const char* kDurabilityWarning =
    "Warning: the nfqws file is visible, but directory durability could not "
    "be confirmed. Runtime reconciliation continued.";

struct ApplyStrategyHooks {
    std::function<bool()> installed;
    std::function<std::vector<ConfigValidationIssue>(
        const std::string&, const std::string&)>
        validate;
    std::function<NfqwsStrategyAssetSync(const std::string&)> provision;
    std::function<NfqwsFileWriteResult(const std::string&)> write_active;
    std::function<std::string(int&)> restart;
};

std::string read_file(const fs::path& path, std::size_t limit = 2U * 1024U * 1024U);

NfqwsFileWriteResult save_nfqws_file(
    const fs::path& path,
    const std::string& content,
    AtomicFileWriteOptions options = {}) {
    try {
        return write_nfqws_file_atomically(
            path, content, std::move(options));
    } catch (const std::length_error& error) {
        throw ApiError(error.what(), 413);
    } catch (const AtomicFileWriteError& error) {
        if (error.committed()) return {false};
        throw ApiError(
            "failed to write nfqws file", 500);
    } catch (const std::exception& error) {
        throw ApiError(error.what(), 500);
    }
}

void merge_durability(bool& durable, const NfqwsFileWriteResult& result) {
    durable = durable && result.durable;
}

void append_durability_warning(std::string& output, bool durable) {
    if (durable) return;
    if (!output.empty() && output.back() != '\n') output += '\n';
    output += kDurabilityWarning;
    output += '\n';
}

nlohmann::json successful_write_response(bool durable) {
    nlohmann::json response{{"ok", true}, {"durable", durable}};
    if (!durable) response["warning"] = kDurabilityWarning;
    return response;
}

[[noreturn]] void throw_candidate_invalid(
    const std::vector<ConfigValidationIssue>& issues) {
    nlohmann::json rendered = nlohmann::json::array();
    for (const auto& issue : issues) {
        rendered.push_back({{"path", issue.path}, {"message", issue.message}});
    }
    const nlohmann::json body{
        {"error", "The nfqws2 strategy candidate is invalid"},
        {"validation_errors", std::move(rendered)},
        {"saved", false},
        {"applied", false},
    };
    throw ApiError(
        "The nfqws2 strategy candidate is invalid", 400, body.dump());
}

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
    const std::map<std::string, std::string>& candidates_before_upgrade,
    bool& durable) {
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
            merge_durability(
                durable, save_nfqws_file(destination, updated));
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
    const auto current = installed_version();
    if (current.empty()) {
        cached = nlohmann::json{{"ok", true},
                                {"installed", false},
                                {"current", ""},
                                {"latest", ""},
                                {"available", false},
                                {"release_url", ""}};
        checked_at = now;
        return cached;
    }
    if (!force && !cached.empty() && cached.value("installed", false) &&
        cached.value("current", std::string{}) == current &&
        now - checked_at < kCacheLifetime) {
        return cached;
    }

    HttpClient client;
    client.set_timeout(std::chrono::seconds(10));
    client.set_max_response_size(256U * 1024U);
    const auto release = nlohmann::json::parse(client.download(
        "https://api.github.com/repos/nfqws/nfqws2-keenetic/releases/latest"));
    const auto latest = release.value("tag_name", std::string{});
    if (latest.empty()) throw ApiError("nfqws2 release does not contain a version", 502);

    cached = nlohmann::json{{"ok", true},
                            {"installed", true},
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

// Every path whose bytes decide whether nfqws2 still works, which is not the
// same set opkg tracks.
//
// Measured on a live router: opkg's list names eight files that do not exist -
// the package is `Architecture: all`, ships a binary per architecture, and its
// postinst deletes the staging directory after picking one - while the binary
// that actually runs, /opt/usr/bin/nfqws2, is absent from the list entirely
// because the postinst creates it with `cp`.
//
// So opkg's record is the starting point, never the answer. The two paths this
// project already knows about are added explicitly; the listed ones are
// observed as they are, without deciding which absences were intended.
std::vector<std::string> nfqws_package_paths() {
    std::vector<std::string> paths =
        read_opkg_file_list(kOpkgPackageFileList);
    paths.emplace_back(kBinary);
    paths.emplace_back(kInit);
    return paths;
}

std::vector<pid_t> nfqws_processes();

// What the live processes are actually executing.
//
// /proc/<pid>/exe still hashes after the file it points at has been replaced,
// which is the only way to tell a process running the new binary from one
// running the bytes that used to be there.
NfqwsRuntimeObservation observe_nfqws_runtime() {
    NfqwsRuntimeObservation observation;
    const auto pids = nfqws_processes();
    if (pids.empty()) return observation;
    observation.process_present = true;
    observation.image_consistent = true;
    for (const auto pid : pids) {
        const auto image = fs::path("/proc") / std::to_string(pid) / "exe";
        const auto digest = rescue_integrity::sha256_file(image);
        if (!digest) {
            observation.image_consistent = false;
            break;
        }
        if (observation.image_sha256.empty()) {
            observation.image_sha256 = *digest;
        } else if (observation.image_sha256 != *digest) {
            // Two live processes on different images is not a state to average
            // out; it is one to report as unestablished.
            observation.image_consistent = false;
            break;
        }
    }
    return observation;
}

std::string installed_binary_digest(const PackageFootprint& footprint) {
    for (const auto& state : footprint.files) {
        if (state.path == kBinary) return state.sha256;
    }
    return {};
}

void describe_runtime_outcome(std::string& output,
                              NfqwsRuntimeOutcome outcome) {
    output += "nfqws2 runtime: ";
    output += nfqws_runtime_outcome_name(outcome);
    output += "\n";
    if (outcome == NfqwsRuntimeOutcome::stopped_by_upgrade) {
        output +=
            "nfqws2 was running before the upgrade and is not running now. "
            "The init script refuses to start when it rejects the active "
            "configuration, which is the usual reason after a configuration "
            "migration.\n";
    } else if (outcome == NfqwsRuntimeOutcome::running_stale) {
        output +=
            "nfqws2 is running an image that is not the installed binary; "
            "restart the service to pick up the new one.\n";
    }
}

// Verifying the restore point hashes every captured file. The nfqws page polls
// this status, so doing it per request would spend hundreds of kilobytes of
// hashing a few seconds apart to answer a question whose answer changes only
// when we change it.
//
// Cached with a short life rather than invalidated by hand: our own mutations
// are not the only way a store goes bad, and a cache that only we can clear
// would keep reporting `usable` after something outside this process damaged
// it. Thirty seconds bounds how long that lie can live.
//
// `force` is for our own mutations, which know the answer changed. Without it
// an operator who has just created a restore point watches a disabled button
// for half a minute and concludes it did not work.
ComponentCaptureState cached_restore_point_state(bool force = false) {
    static std::mutex mutex;
    static std::optional<ComponentCaptureState> cached;
    static std::chrono::steady_clock::time_point checked_at{};
    constexpr auto kTtl = std::chrono::seconds{30};

    const std::lock_guard lock(mutex);
    const auto now = std::chrono::steady_clock::now();
    if (!force && cached && now - checked_at < kTtl) return *cached;
    cached = verify_component_capture(kNfqwsCapture);
    checked_at = now;
    return *cached;
}

// One place that names a step, so a phase cannot be broadcast under a name the
// page does not know. Never throws: a component operation must not fail
// because nobody was listening to its progress.
void publish_transaction_step(const ApiContext& ctx,
                              std::string_view operation,
                              std::string_view step,
                              bool active,
                              const std::string& detail = {}) noexcept {
    if (ctx.status_stream == nullptr) return;
    try {
        ctx.status_stream->publish_component_transaction(nlohmann::json{
            {"component", "nfqws2-keenetic"},
            {"operation", std::string(operation)},
            {"step", std::string(step)},
            {"active", active},
            {"detail", detail}});
    } catch (...) {
    }
}

// Guarantees the stream is told the operation ended, on every path out.
//
// Without this, a throw between the first step and the last leaves every open
// page showing progress for an operation that stopped minutes ago - and the
// paths that throw here are refusals and failures, exactly when an operator is
// watching.
class TransactionProgress {
public:
    TransactionProgress(const ApiContext& ctx, std::string operation)
        : ctx_(ctx), operation_(std::move(operation)) {}

    ~TransactionProgress() {
        if (!finished_)
            publish_transaction_step(ctx_, operation_, "finished", false,
                                     "aborted");
    }

    TransactionProgress(const TransactionProgress&) = delete;
    TransactionProgress& operator=(const TransactionProgress&) = delete;

    void step(std::string_view name) const {
        publish_transaction_step(ctx_, operation_, name, true);
    }

    void finish(const std::string& detail) {
        publish_transaction_step(ctx_, operation_, "finished", false, detail);
        finished_ = true;
    }

private:
    const ApiContext& ctx_;
    std::string operation_;
    bool finished_{false};
};

NfqwsConfigObservation observe_nfqws_config() {
    NfqwsConfigObservation observation;
    const auto active = fs::path(kConfigDir) / "nfqws2.conf";
    const auto displaced = fs::path(kConfigDir) / "nfqws2.conf-old";
    std::error_code ec;
    if (fs::is_regular_file(active, ec)) {
        observation.active_present = true;
        if (const auto digest = rescue_integrity::sha256_file(active))
            observation.active_sha256 = *digest;
    }
    if (fs::is_regular_file(displaced, ec)) {
        observation.displaced_present = true;
        if (const auto digest = rescue_integrity::sha256_file(displaced))
            observation.displaced_sha256 = *digest;
    }
    return observation;
}

void describe_config_outcome(std::string& output,
                             NfqwsConfigOutcome outcome) {
    if (outcome != NfqwsConfigOutcome::replaced_by_package &&
        outcome != NfqwsConfigOutcome::lost) {
        return;
    }
    if (outcome == NfqwsConfigOutcome::lost) {
        output += "\nThe active nfqws2 configuration is gone after the "
                  "upgrade.\n";
        return;
    }
    // The whole point of this slice. Upstream's preinst is allowed to migrate
    // its own configuration; what it may not do is take the operator's
    // settings away without anybody saying where they went.
    output += "\nThe package replaced the active nfqws2 configuration with "
              "its defaults (CONFIG_VERSION migration). Your previous "
              "configuration is at ";
    output += (fs::path(kConfigDir) / "nfqws2.conf-old").string();
    output += ", and the rollback backup taken before this upgrade also "
              "contains it.\n";
}

void describe_package_change(std::string& output,
                             PackageBinaryOutcome outcome,
                             const PackageFootprintDiff& diff) {
    output += "\nnfqws2 binary: ";
    output += package_binary_outcome_name(outcome);
    output += "\n";
    if (outcome == PackageBinaryOutcome::missing_after) {
        output +=
            "The nfqws2 binary is gone after the upgrade; the service has "
            "nothing to run.\n";
    }
    output += "Package files changed: " + std::to_string(diff.changed.size()) +
              ", added: " + std::to_string(diff.added.size()) +
              ", removed: " + std::to_string(diff.removed.size());
    if (!diff.indeterminate.empty()) {
        // Surfaced rather than folded into "changed": a file we could not read
        // is a gap in the observation, and calling it a change would make
        // every permission error look like the upgrade doing work.
        output += ", unreadable: " +
                  std::to_string(diff.indeterminate.size());
    }
    output += "\n";
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

// Runs the nfqws2 init script under a deadline.
//
// The generic run_command() above uses popen/pclose, and pclose waits for the
// child with no deadline at all. A hung init script therefore blocked the HTTP
// worker forever - while holding nfqws_operation_mutex, so every subsequent
// nfqws request piled up behind it and the whole section of the UI froze with
// no way back short of restarting the daemon.
//
// safe_exec_capture takes argv rather than a shell string, which this path
// does not need anyway: the arguments are a fixed script path and a fixed
// verb, neither of which is caller-controlled.
std::string run_nfqws_init_script(const std::string& action, int& status) {
    constexpr size_t kMaxOutputBytes = 128U * 1024U;
    // Generous on purpose. Stopping nfqws2 can legitimately take seconds while
    // connections drain, and a deadline that fires during ordinary work would
    // be worse than the hang it guards against.
    constexpr auto kInitScriptTimeout = std::chrono::seconds{60};

    auto result = safe_exec_capture(
        {std::string(kInit), action},
        /*suppress_stderr=*/false,
        kMaxOutputBytes,
        /*capture_stderr=*/true,
        /*drain_after_limit=*/true,
        SafeExecFailureLog::Enabled,
        SafeExecTimeouts{kInitScriptTimeout, std::chrono::seconds{2}});

    auto output = std::move(result.stdout_output);
    status = result.exit_code;
    if (result.timed_out) {
        output += "nfqws2 init script timed out and was terminated.\n";
        // A killed script is never a success, whatever exit status the kill
        // happened to produce.
        if (status == 0) status = 1;
    }
    if (result.truncated) {
        output += "(output truncated)\n";
    }
    return output;
}

std::string run_nfqws_service_command(const std::string& command, int& status) {
    if (command == "reload") {
        repair_nfqws_pidfile();
        return run_nfqws_init_script("reload", status);
    }

    if (command == "start") {
        auto output = run_nfqws_init_script("start", status);
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
    auto output = run_nfqws_init_script("stop", stop_status);
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
    output += run_nfqws_init_script("start", start_status);
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

NfqwsFileWriteResult provision_rotator_reporter(
    const std::string& content) {
    if (!nfqws_config_has_owned_rotator_telemetry(content)) return {};
    const auto packaged =
        read_file(kPackagedRotatorReporter, kMaxNfqwsFileSize);
    std::error_code ec;
    const auto status = fs::symlink_status(kLiveRotatorReporter, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        throw ApiError("failed to inspect durable nfqws rotator reporter", 500);
    }
    if (!ec && fs::exists(status)) {
        if (fs::is_symlink(status) || !fs::is_regular_file(status)) {
            throw ApiError("durable nfqws rotator reporter path is unsafe", 500);
        }
    }
    return save_nfqws_file(kLiveRotatorReporter, packaged);
}

NfqwsStrategyAssetSync provision_strategy_assets(
    const std::string& name, const std::string& content, bool& durable) {
    merge_durability(durable, provision_rotator_reporter(content));
    if (!builtin_strategy(name)) return {};
    const auto strategy_directory = fs::path(kBuiltinStrategies) / name;
    try {
        return sync_nfqws_strategy_assets(
            strategy_directory / "required-blobs.txt",
            kBuiltinBlobs,
            fs::path(kConfigDir) / "blobs");
    } catch (const std::exception& error) {
        throw ApiError(
            std::string("failed to provision nfqws strategy blobs: ") +
                error.what(),
            500);
    }
}

std::map<std::string, std::string> strategy_asset_validation_paths(
    const std::string& name, const std::string& content) {
    std::map<std::string, std::string> result;
    if (nfqws_config_has_owned_rotator_telemetry(content)) {
        std::error_code reporter_error;
        if (!fs::is_regular_file(kPackagedRotatorReporter, reporter_error) ||
            reporter_error) {
            throw ApiError(
                "packaged nfqws rotator reporter is unavailable", 500);
        }
        result.emplace(
            fs::path(kLiveRotatorReporter).lexically_normal().string(),
            fs::path(kPackagedRotatorReporter).lexically_normal().string());
    }
    if (!builtin_strategy(name)) return result;
    const auto strategy_directory = fs::path(kBuiltinStrategies) / name;
    try {
        for (const auto& asset : inspect_nfqws_strategy_assets(
                 strategy_directory / "required-blobs.txt",
                 kBuiltinBlobs,
                 fs::path(kConfigDir) / "blobs")) {
            result.emplace(asset.destination.lexically_normal().string(),
                           asset.verification_path.lexically_normal().string());
        }
    } catch (const std::exception& error) {
        throw ApiError(
            std::string("failed to inspect nfqws strategy blobs: ") +
                error.what(),
            500);
    }
    return result;
}

std::optional<std::uint64_t> nfqws_process_age_seconds(
    const NfqwsProcessGeneration& generation) {
    const long ticks_per_second = ::sysconf(_SC_CLK_TCK);
    if (ticks_per_second <= 0) return std::nullopt;
    struct timespec uptime {};
#ifdef CLOCK_BOOTTIME
    constexpr clockid_t uptime_clock = CLOCK_BOOTTIME;
#else
    constexpr clockid_t uptime_clock = CLOCK_MONOTONIC;
#endif
    if (::clock_gettime(uptime_clock, &uptime) != 0 || uptime.tv_sec < 0) {
        return std::nullopt;
    }
    const auto ticks = static_cast<std::uint64_t>(uptime.tv_sec) *
                           static_cast<std::uint64_t>(ticks_per_second) +
                       static_cast<std::uint64_t>(uptime.tv_nsec) *
                           static_cast<std::uint64_t>(ticks_per_second) /
                           1000000000ULL;
    if (generation.start_ticks > ticks) return std::nullopt;
    return (ticks - generation.start_ticks) /
           static_cast<std::uint64_t>(ticks_per_second);
}

nlohmann::json rotator_histogram_json(
    const std::map<std::uint32_t, std::uint64_t>& histogram) {
    nlohmann::json rendered = nlohmann::json::array();
    for (const auto& [value, targets] : histogram) {
        rendered.push_back({{"value", value}, {"targets", targets}});
    }
    return rendered;
}

nlohmann::json nfqws_rotator_state_json(
    const std::string& active_content,
    const std::vector<pid_t>& processes) {
    NfqwsRotatorStateSelection selection;
    selection.reporter_expected =
        nfqws_config_has_owned_rotator_telemetry(active_content);
    selection.now_unix = static_cast<std::int64_t>(std::time(nullptr));

    if (selection.reporter_expected && processes.size() == 1U) {
        const auto generation = read_nfqws_process_generation(
            static_cast<std::int64_t>(processes.front()));
        if (generation.has_value()) {
            const auto age = nfqws_process_age_seconds(*generation);
            if (age.has_value()) {
                selection.process_generation = generation;
                selection.process_age_seconds = *age;
                selection.snapshot_candidates =
                    read_nfqws_rotator_snapshot_candidates(
                        kRotatorStateDirectory);
            }
        }
    }

    const auto state = select_nfqws_rotator_state(selection);
    nlohmann::json rendered{
        {"schema", 1},
        {"status", nfqws_rotator_state_status_name(state.status)},
        {"observed_at", nullptr},
        {"truncated", false},
        {"pools", nlohmann::json::object()},
    };
    if (!state.snapshot.has_value()) return rendered;

    rendered["observed_at"] = state.snapshot->observed_at_unix;
    rendered["truncated"] = state.snapshot->truncated;
    const bool exact = state.status == NfqwsRotatorStateStatus::ready &&
                       !state.snapshot->truncated;
    for (const auto& pool : state.snapshot->pools) {
        nlohmann::json pool_json{
            {"tracked_targets", pool.tracked_targets},
            {"active_slot", nullptr},
            {"slot_count", nullptr},
            {"pending_failures", nullptr},
            {"max_pending_failures", nullptr},
            {"active_slot_histogram",
             rotator_histogram_json(pool.slot_histogram)},
            {"slot_count_histogram",
             rotator_histogram_json(pool.slot_count_histogram)},
            {"pending_failure_histogram",
             rotator_histogram_json(pool.pending_failure_histogram)},
        };
        if (exact) {
            if (const auto value = pool.unanimous_slot()) {
                pool_json["active_slot"] = *value;
            }
            if (const auto value = pool.unanimous_slot_count()) {
                pool_json["slot_count"] = *value;
            }
            if (const auto value = pool.unanimous_pending_failures()) {
                pool_json["pending_failures"] = *value;
            }
            pool_json["max_pending_failures"] =
                pool.max_pending_failures();
        }
        rendered["pools"][pool.key] = std::move(pool_json);
    }
    return rendered;
}

std::optional<NfqwsBinaryIdentity> read_nfqws_binary_identity(
    const std::string& path) {
    struct stat metadata {};
    if (::stat(path.c_str(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        return std::nullopt;
    }
    return NfqwsBinaryIdentity{
        static_cast<std::uint64_t>(metadata.st_dev),
        static_cast<std::uint64_t>(metadata.st_ino),
        static_cast<std::uint64_t>(metadata.st_size),
        static_cast<std::int64_t>(metadata.st_mtim.tv_sec),
        static_cast<std::int64_t>(metadata.st_mtim.tv_nsec),
        static_cast<std::int64_t>(metadata.st_ctim.tv_sec),
        static_cast<std::int64_t>(metadata.st_ctim.tv_nsec),
    };
}

NfqwsDryRunCapabilityCache& dry_run_capability_cache() {
    static NfqwsDryRunCapabilityCache cache;
    return cache;
}

std::optional<std::string> probe_nfqws_help(const std::string& binary) {
    const auto result = safe_exec_capture(
        {binary, "--help"},
        /*suppress_stderr=*/false,
        /*max_bytes=*/256U * 1024U,
        /*capture_stderr=*/true,
        /*drain_after_limit=*/false,
        SafeExecFailureLog::Suppressed,
        SafeExecTimeouts{std::chrono::seconds{5}, std::chrono::seconds{1}});
    if (result.timed_out || result.exit_code < 0 || result.exit_code == 127) {
        return std::nullopt;
    }
    return result.stdout_output;
}

[[noreturn]] void throw_candidate_verification_unavailable(
    const std::string& reason) {
    const nlohmann::json body{
        {"error", "The nfqws2 strategy candidate could not be verified"},
        {"detail", reason},
        {"saved", false},
        {"applied", false},
    };
    throw ApiError(
        "The nfqws2 strategy candidate could not be verified", 503,
        body.dump());
}

std::string last_nonempty_line(const std::string& text) {
    std::istringstream input(text);
    std::string line;
    std::string result;
    while (std::getline(input, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' ||
                line.back() == '\t')) {
            line.pop_back();
        }
        if (!line.empty()) result = std::move(line);
    }
    return result;
}

void validate_candidate_or_throw(const std::string& name,
                                 const std::string& content) {
    const auto packaged_assets =
        strategy_asset_validation_paths(name, content);
    const NfqwsPathResolver resolve_path =
        [packaged_assets](const std::string& path)
        -> std::optional<std::string> {
        const auto normalized = fs::path(path).lexically_normal().string();
        const auto packaged = packaged_assets.find(normalized);
        if (packaged != packaged_assets.end()) return packaged->second;
        std::error_code ec;
        if (fs::is_regular_file(fs::path(path), ec) && !ec) return path;
        return std::nullopt;
    };

    auto issues = validate_nfqws_candidate(content, resolve_path);
    if (!issues.empty()) throw_candidate_invalid(issues);

    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto before = read_nfqws_binary_identity(kBinary);
        if (!before.has_value()) {
            throw_candidate_verification_unavailable(
                "the installed nfqws2 binary identity is unavailable; nothing was changed");
        }
        const auto capability = dry_run_capability_cache().detect(
            kBinary, read_nfqws_binary_identity, probe_nfqws_help);
        const auto after_probe = read_nfqws_binary_identity(kBinary);
        if (!after_probe.has_value() || *after_probe != *before) continue;
        if (capability == NfqwsDryRunCapability::unavailable) {
            throw_candidate_verification_unavailable(
                "the nfqws2 capability probe did not complete; nothing was changed");
        }
        if (capability == NfqwsDryRunCapability::unsupported) return;

        auto args = build_nfqws_dry_run_args(
            content, configured_nfqueue_num(), resolve_path);
        args.insert(args.begin(), kBinary);
        const auto verified = safe_exec_capture(
            args,
            /*suppress_stderr=*/false,
            /*max_bytes=*/64U * 1024U,
            /*capture_stderr=*/true,
            /*drain_after_limit=*/false,
            SafeExecFailureLog::Suppressed,
            SafeExecTimeouts{std::chrono::seconds{15},
                             std::chrono::seconds{1}});
        const auto after_run = read_nfqws_binary_identity(kBinary);
        if (!after_run.has_value() || *after_run != *before) continue;
        if (verified.timed_out || verified.exit_code < 0) {
            throw_candidate_verification_unavailable(
                "nfqws2 --dry-run did not complete; nothing was changed");
        }
        if (verified.exit_code == 0) return;

        auto reason = last_nonempty_line(verified.stdout_output);
        if (reason.empty()) {
            reason = "nfqws2 rejected the candidate (exit code " +
                     std::to_string(verified.exit_code) + ')';
        }
        issues.push_back(
            {"NFQWS_ARGS", "nfqws2 --dry-run: " + reason});
        throw_candidate_invalid(issues);
    }
    throw_candidate_verification_unavailable(
        "the nfqws2 binary changed during validation; nothing was changed");
}

} // namespace

void register_nfqws_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    std::optional<ApplyStrategyHooks> apply_hooks) {
    server.get("/api/nfqws", []() -> std::string {
        std::error_code ec;
        const bool installed = fs::is_regular_file(kBinary, ec);
        const auto processes =
            installed ? nfqws_processes() : std::vector<pid_t>{};
        const bool process_running = !processes.empty();
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
        std::string active_content;
        const auto active_config = fs::path(kConfigDir) / "nfqws2.conf";
        if (fs::is_regular_file(active_config, ec)) {
            active_content = read_file(active_config);
            const auto active_identity =
                nfqws_config_strategy_identity(active_content);
            for (const auto& strategy : strategies) {
                const auto name = strategy.value("name", std::string{});
                auto expected = strategy.value("content", std::string{});
                if (automatic_wan_strategy(name)) expected = render_wan_interfaces(expected);
                if (nfqws_config_strategy_identity(expected) ==
                    active_identity) {
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
                              {"active_strategy", active_strategy},
                              {"rotator_state", nfqws_rotator_state_json(
                                                    active_content,
                                                    processes)},
                              // Surfaced here rather than only on the next
                              // attempt. A reboot in the middle of a package
                              // operation leaves a record nobody reads until
                              // an operator tries to upgrade again, and the
                              // moment to learn that something was interrupted
                              // is before deciding what to do next.
                              {"transaction_state",
                               component_transaction_state_name(
                                   read_component_transaction(kNfqwsJournal)
                                       .state)},
                              {"restore_point",
                               component_capture_state_name(
                                   cached_restore_point_state())}}
            .dump();
    });

    server.post("/api/nfqws", [&ctx, apply_hooks](const std::string& body) -> std::string {
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
            if (category == "log" && action == "create_file") throw ApiError("cannot create a log", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            const bool create_only = action == "create_file";
            if (create_only && fs::exists(path)) {
                throw ApiError("nfqws file already exists", 409);
            }
            AtomicFileWriteOptions write_options;
            write_options.replace_existing = !create_only;
            const auto saved = save_nfqws_file(
                path,
                request.value("content", std::string{}),
                write_options);
            return successful_write_response(saved.durable).dump();
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
            const auto saved = save_nfqws_file(path, "");
            return successful_write_response(saved.durable).dump();
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
            // The only nfqws action that mutates installed packages, and until
            // now the only package mutation in the process that took no
            // cross-process lease. An in-process mutex bounds nothing outside
            // this daemon: `opkg upgrade nfqws2-keenetic` could run while
            // S80 was stopping the service for its own lifecycle operation,
            // while keen-pbr's self-update was replacing its own package, or
            // while rescue recovery was restoring configuration.
            //
            // Acquired before the in-process mutex, not after. Config save and
            // transports take the lease first and then do their work; taking
            // them in the other order here would give two lock orders in one
            // process, which is how a deadlock is built.
            //
            // Acquired before create_full_rollback_backup as well: a refusal
            // must cost the operator nothing. If somebody else holds the
            // lease, this writes no snapshot and runs no opkg.
            std::unique_ptr<MaintenanceLease> maintenance;
            try {
                maintenance = ctx.acquire_maintenance_lease("nfqws-upgrade");
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
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
            // Refuse on top of an unfinished transaction. The previous run
            // did not report an end, so what is installed is unknown, and
            // running a package manager over an unknown state is how one
            // interrupted upgrade becomes an unrecoverable one.
            const auto journal = read_component_transaction(kNfqwsJournal);
            if (journal.state != ComponentTransactionState::none) {
                throw ApiError(
                    std::string("a previous nfqws2 package operation did not "
                                "finish (") +
                        component_transaction_state_name(journal.state) +
                        "); inspect the component before upgrading again",
                    409);
            }
            TransactionProgress progress(ctx, "upgrade");
            progress.step("backup");
            create_full_rollback_backup(ctx);
            const auto footprint_before =
                observe_package_footprint(nfqws_package_paths());
            const auto config_before = observe_nfqws_config();
            const auto runtime_before = observe_nfqws_runtime();

            ComponentTransactionRecord record;
            record.component = "nfqws2-keenetic";
            record.operation = "upgrade";
            // `started`, not `mutating`: nothing on this router has been
            // touched yet, and the capture below only reads. An interruption
            // between here and opkg leaves the component exactly as it was,
            // and recording it as "the package manager may have run" would
            // make a harmless interruption look like a dangerous one - the
            // same overstatement the rest of this work exists to remove.
            record.phase = ComponentTransactionPhase::started;
            record.started_at = static_cast<std::int64_t>(std::time(nullptr));
            record.binary_sha256 = installed_binary_digest(footprint_before);
            record.config_sha256 = config_before.active_sha256;
            record.runtime_was_running = runtime_before.process_present;
            write_component_transaction(kNfqwsJournal, record);

            // Taken before opkg, because these bytes stop existing the moment
            // it runs and cannot be reconstructed afterwards.
            std::string output = "Rollback backup created.\n";
            progress.step("capture");
            const auto capture =
                capture_component_files(footprint_before, kNfqwsCapture);
            cached_restore_point_state(/*force=*/true);
            output += capture.complete
                          ? std::string("Component restore point captured (") +
                                std::to_string(capture.captured) +
                                " files).\n"
                          : std::string("Component restore point is "
                                        "incomplete; ") +
                                std::to_string(capture.failed.size()) +
                                " file(s) could not be captured, so there is "
                                "nothing complete to restore from.\n";

            // Promoted immediately before the package manager runs, and not a
            // line earlier: from here on anything on disk may have changed.
            record.phase = ComponentTransactionPhase::mutating;
            write_component_transaction(kNfqwsJournal, record);
            progress.step("install");
            int status = 0;
            output += run_command("/opt/bin/opkg update && /opt/bin/opkg upgrade nfqws2-keenetic", status);
            progress.step("verify");
            record.phase = ComponentTransactionPhase::verifying;
            write_component_transaction(kNfqwsJournal, record);
            const auto footprint_after =
                observe_package_footprint(nfqws_package_paths());
            const auto binary_outcome = judge_package_binary(
                footprint_before, footprint_after, kBinary);
            const auto footprint_diff =
                diff_package_footprint(footprint_before, footprint_after);
            const auto config_outcome =
                judge_nfqws_config(config_before, observe_nfqws_config());
            const auto runtime_outcome = judge_nfqws_runtime(
                runtime_before, observe_nfqws_runtime(),
                installed_binary_digest(footprint_after));
            describe_package_change(output, binary_outcome, footprint_diff);
            describe_runtime_outcome(output, runtime_outcome);
            describe_config_outcome(output, config_outcome);
            bool durable = true;
            const auto created = status == 0
                                     ? save_updated_default_strategy(
                                           previous,
                                           candidates_before_upgrade,
                                           durable)
                                     : std::string{};
            if (status == 0) {
                output += "\nInstalled nfqws2 version: " + installed_version() + "\n";
            }
            append_durability_warning(output, durable);
            // A binary that vanished is not a successful upgrade, whatever
            // opkg's exit code says. The service has nothing left to run, and
            // reporting that as ok would hand the operator a green tick over a
            // dead component.
            const bool binary_lost =
                binary_outcome == PackageBinaryOutcome::missing_after;
            // Automatic rollback, armed only for the outcomes that mean the
            // component is broken.
            //
            // Not armed for `replaced_by_package`: that migration is upstream's
            // own and the upgrade worked. Reverting a successful upgrade
            // because the package migrated its configuration would be keen-pbr
            // fighting the package on the operator's behalf without being
            // asked, and the previous slice already made the migration visible.
            //
            // Not armed for `unknown` either. A check that could not be made
            // is not a failure, and replacing a working component on the
            // strength of an unreadable /proc entry would be a rollback that
            // causes the outage it exists to prevent.
            const bool component_broken =
                binary_lost || nfqws_runtime_is_failure(runtime_outcome);
            bool rolled_back = false;
            if (component_broken && capture.complete) {
                progress.step("rollback");
                output +=
                    "\nThe upgrade left the component broken; restoring the "
                    "captured bytes.\n";
                if (record.runtime_was_running) {
                    int stop_status = 0;
                    output += run_nfqws_service_command("stop", stop_status);
                }
                const auto restored =
                    restore_component_files(kNfqwsCapture);
                rolled_back = restored.complete;
                output += restored.complete
                              ? "Restored " +
                                    std::to_string(restored.restored) +
                                    " files.\n"
                              : "Restore did not complete: " +
                                    (restored.refused.empty()
                                         ? std::to_string(
                                               restored.failed.size()) +
                                               " file(s) failed"
                                         : restored.refused) +
                                    ".\n";
                if (record.runtime_was_running) {
                    int start_status = 0;
                    output += run_nfqws_service_command("start", start_status);
                }
            } else if (component_broken) {
                // Said plainly rather than left to be inferred from silence.
                output +=
                    "\nThe upgrade left the component broken and there is no "
                    "complete restore point to return to.\n";
            }
            // Cleared only here, after every check has run. A record that
            // survives is reported rather than ignored: the next upgrade must
            // see it, and a removal that silently failed would let it through.
            if (!clear_component_transaction(kNfqwsJournal)) {
                output +=
                    "\nThe transaction record could not be removed; the next "
                    "upgrade will refuse until it is cleared.\n";
            }
            // A rolled-back upgrade is still not a successful upgrade. The
            // operator asked for a new version and does not have one; that the
            // component survived is the recovery working, not the request.
            // Published before returning, so a page that never sees the HTTP
            // response - a closed tab, a dropped connection - still learns the
            // operation ended rather than showing progress forever.
            progress.finish(component_broken
                                ? (rolled_back ? "rolled_back" : "broken")
                                : std::string{});
            return nlohmann::json{{"ok", status == 0 && !component_broken},
                                  {"rolled_back", rolled_back},
                                  {"output", output}, {"status", status},
                                  {"strategy_created", created},
                                  {"durable", durable},
                                  {"binary_outcome",
                                   package_binary_outcome_name(binary_outcome)},
                                  {"config_outcome",
                                   nfqws_config_outcome_name(config_outcome)},
                                  {"runtime_outcome",
                                   nfqws_runtime_outcome_name(runtime_outcome)},
                                  {"warning", durable ? "" : kDurabilityWarning}}.dump();
        }
        if (action == "capture_restore_point") {
            // No step-up. This installs nothing; it copies files this daemon
            // already reads into a private store of ours. Asking for a
            // password to take a safety net discourages taking one, and the
            // action an attacker wants is the restore, which is guarded.
            //
            // The lease is still required: capturing while opkg is midway
            // through replacing files would store a mixture of two versions
            // and call it a restore point.
            std::unique_ptr<MaintenanceLease> maintenance;
            try {
                maintenance =
                    ctx.acquire_maintenance_lease("nfqws-capture-restore-point");
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
            const std::lock_guard lock(nfqws_operation_mutex());

            const auto journal = read_component_transaction(kNfqwsJournal);
            if (journal.state != ComponentTransactionState::none) {
                throw ApiError(
                    "a previous nfqws2 package operation did not finish; what "
                    "is installed is unknown, so it must not be captured as a "
                    "restore point",
                    409);
            }

            const auto captured = capture_component_files(
                observe_package_footprint(nfqws_package_paths()),
                kNfqwsCapture);
            const auto state = cached_restore_point_state(/*force=*/true);
            std::string output =
                "Captured files: " + std::to_string(captured.captured) + "\n";
            for (const auto& failure : captured.failed) {
                output += "Could not capture: " + failure + "\n";
            }
            // The verdict comes from re-reading the store, not from the write
            // having returned. What matters is whether a restore could use it.
            output += "Restore point: ";
            output += component_capture_state_name(state);
            output += "\n";
            return nlohmann::json{
                {"ok", captured.complete &&
                           state == ComponentCaptureState::usable},
                {"output", output},
                {"captured", captured.captured},
                {"failed", captured.failed.size()},
                {"restore_point", component_capture_state_name(state)}}
                .dump();
        }
        if (action == "restore_component") {
            // Same lease as the upgrade: this replaces installed binaries, so
            // it must not run beside a lifecycle operation or the keen-pbr
            // updater any more than an upgrade may.
            std::unique_ptr<MaintenanceLease> maintenance;
            try {
                maintenance =
                    ctx.acquire_maintenance_lease("nfqws-restore-component");
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
            const std::lock_guard lock(nfqws_operation_mutex());

            const auto capture_state =
                verify_component_capture(kNfqwsCapture);
            if (capture_state != ComponentCaptureState::usable) {
                // Refused before anything stops, so a component that is
                // working keeps working when there is nothing to restore.
                throw ApiError(
                    std::string("no usable nfqws2 restore point (") +
                        component_capture_state_name(capture_state) + ")",
                    409);
            }

            ComponentTransactionRecord record;
            record.component = "nfqws2-keenetic";
            record.operation = "restore-component";
            record.phase = ComponentTransactionPhase::mutating;
            record.started_at = static_cast<std::int64_t>(std::time(nullptr));
            record.runtime_was_running =
                observe_nfqws_runtime().process_present;
            write_component_transaction(kNfqwsJournal, record);

            TransactionProgress progress(ctx, "restore");
            std::string output;
            int service_status = 0;
            if (record.runtime_was_running) {
                progress.step("stop");
                output += run_nfqws_service_command("stop", service_status);
            }
            progress.step("restore");
            const auto restored = restore_component_files(kNfqwsCapture);
            output += "\nRestored files: " +
                      std::to_string(restored.restored) + "\n";
            for (const auto& failure : restored.failed) {
                output += "Could not restore: " + failure + "\n";
            }
            if (record.runtime_was_running) {
                progress.step("start");
                int start_status = 0;
                output += run_nfqws_service_command("start", start_status);
            }
            progress.finish(restored.complete ? std::string{} : "incomplete");
            // Only what was captured came back. Files the newer package added
            // are still there, and saying so is the difference between a
            // restore and a claim of one.
            output +=
                "Files added by the newer package were not removed; this "
                "restores the captured bytes, not the exact former state.\n";
            if (!clear_component_transaction(kNfqwsJournal)) {
                output +=
                    "The transaction record could not be removed; the next "
                    "package operation will refuse until it is cleared.\n";
            }
            return nlohmann::json{{"ok", restored.complete},
                                  {"output", output},
                                  {"restored", restored.restored},
                                  {"failed", restored.failed.size()}}
                .dump();
        }
        if (action == "save_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            const auto saved = save_nfqws_file(
                fs::path(kUserStrategies) / (name + ".conf"),
                request.value("content", std::string{}));
            std::error_code ec2;
            fs::remove(fs::path(kUserStrategies) / ".deleted" / name, ec2);
            return successful_write_response(saved.durable).dump();
        }
        if (action == "apply_strategy") {
            const std::lock_guard lock(nfqws_operation_mutex());
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            const bool installed = apply_hooks.has_value()
                                       ? apply_hooks->installed()
                                       : fs::exists(kBinary) && fs::exists(kInit);
            if (!installed)
                throw ApiError("nfqws2 is not installed", 409);
            auto content = request.contains("content") && request["content"].is_string()
                               ? request["content"].get<std::string>()
                               : read_file(strategy_source(name));
            if (automatic_wan_strategy(name)) content = render_wan_interfaces(content);
            if (content.size() > kMaxNfqwsFileSize) {
                throw ApiError("nfqws file is too large", 413);
            }

            // This is the no-mutation boundary.  Both the structural parser
            // and, when supported, the exact engine dry-run finish before blob
            // provisioning, config replacement, or service restart.
            if (apply_hooks.has_value()) {
                const auto issues = apply_hooks->validate(name, content);
                if (!issues.empty()) throw_candidate_invalid(issues);
            } else {
                validate_candidate_or_throw(name, content);
            }

            bool durable = true;
            const auto assets = apply_hooks.has_value()
                                    ? apply_hooks->provision(name)
                                    : provision_strategy_assets(
                                          name, content, durable);
            const auto saved = apply_hooks.has_value()
                                   ? apply_hooks->write_active(content)
                                   : save_nfqws_file(
                                         fs::path(kConfigDir) / "nfqws2.conf",
                                         content);
            merge_durability(durable, saved);
            int status = 0;
            auto output = apply_hooks.has_value()
                              ? apply_hooks->restart(status)
                              : run_nfqws_service_command("restart", status);
            if (!assets.installed.empty()) {
                std::ostringstream details;
                details << "Installed missing strategy blobs:";
                for (const auto& item : assets.installed) details << ' ' << item;
                details << "\n";
                output = details.str() + output;
            }
            append_durability_warning(output, durable);
            return nlohmann::json{{"ok", status == 0},
                                  {"output", output},
                                  {"status", status},
                                  {"durable", durable},
                                  {"warning", durable
                                                  ? ""
                                                  : kDurabilityWarning},
                                  {"installed_blobs", assets.installed},
                                  {"preserved_blobs", assets.preserved}}
                .dump();
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
            bool durable = true;
            for (const auto& item : pending) {
                merge_durability(
                    durable, save_nfqws_file(item.path, item.content));
            }
            std::string output = "Saved " + std::to_string(pending.size()) + " nfqws file(s).\n";
            int status = 0;
            if (request.value("restart", false)) {
                output += run_nfqws_service_command("restart", status);
            }
            append_durability_warning(output, durable);
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status},
                                  {"saved", pending.size()},
                                  {"durable", durable},
                                  {"warning", durable ? "" : kDurabilityWarning}}.dump();
        }
        if (action == "delete_strategy") {
            const auto name = request.value("name", std::string{});
            if (!valid_name(name, true)) throw ApiError("invalid strategy name", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            std::error_code ec2;
            fs::remove(fs::path(kUserStrategies) / (name + ".conf"), ec2);
            const auto saved = save_nfqws_file(
                fs::path(kUserStrategies) / ".deleted" / name,
                "deleted\n");
            return successful_write_response(saved.durable).dump();
        }
        if (action == "import_lists") {
            if (!request.contains("files") || !request["files"].is_object()) throw ApiError("nfqws list bundle is invalid", 400);
            const std::lock_guard lock(nfqws_operation_mutex());
            bool durable = true;
            for (const auto& item : request["files"].items()) {
                const auto [path, category] = file_path("list", item.key());
                if (!item.value().is_string()) throw ApiError("nfqws list content must be text", 400);
                merge_durability(
                    durable,
                    save_nfqws_file(
                        path, item.value().get<std::string>()));
            }
            return successful_write_response(durable).dump();
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
            // then replaced atomically by save_nfqws_file().
            const std::lock_guard lock(nfqws_operation_mutex());
            bool durable = true;
            for (const auto& item : pending) {
                merge_durability(
                    durable, save_nfqws_file(item.path, item.content));
            }
            return successful_write_response(durable).dump();
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

void register_nfqws_handler(ApiServer& server, ApiContext& ctx) {
    register_nfqws_handler_impl(server, ctx, std::nullopt);
}

#ifdef KEEN_PBR3_TESTING
void register_nfqws_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    NfqwsApplyStrategyTestHooks hooks) {
    ApplyStrategyHooks internal;
    internal.installed = std::move(hooks.installed);
    internal.validate = std::move(hooks.validate);
    internal.provision = std::move(hooks.provision);
    internal.write_active = std::move(hooks.write_active);
    internal.restart = std::move(hooks.restart);
    register_nfqws_handler_impl(server, ctx, std::move(internal));
}
#endif

} // namespace keen_pbr3

#endif
