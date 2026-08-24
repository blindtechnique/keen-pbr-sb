#ifdef WITH_API

#include "handler_nfqws.hpp"
#include "handler_backup.hpp"
#include "maintenance_api.hpp"
#include "../update/component_capture.hpp"
#include "../update/component_package_transaction.hpp"
#include "../update/component_transaction_journal.hpp"
#include "../update/package_footprint.hpp"
#include "../update/rescue_integrity.hpp"
#include "../crypto/sha256.hpp"
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
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
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
// Where a scripted install renames the init script to while the package's
// postinst runs (same directory, so the rename is atomic; dot-prefixed, so
// the init sequence never globs it). Only scripted installs create this
// name, which is what lets boot recovery restore it on filesystem evidence
// alone.
constexpr const char* kInitHeld = "/opt/etc/init.d/.S51nfqws2.kpbr-held";
constexpr const char* kPidfile = "/opt/var/run/nfqws2.pid";
constexpr const char* kConfigDir = "/opt/etc/nfqws2";
constexpr const char* kOpkgPackageFileList =
    "/opt/lib/opkg/info/nfqws2-keenetic.list";
constexpr const char* kNfqwsJournal =
    "/opt/var/lib/keen-pbr/nfqws-transaction.json";
constexpr const char* kNfqwsCapture =
    "/opt/var/lib/keen-pbr/nfqws-restore-point";
// Exact IPKs for the component, beside the other keen-pbr state. The feed
// serves only its latest version, so the installed version's bytes are kept
// here from the moment they can be had: once the feed moves on they cannot
// be fetched again, and a rollback that cannot reinstall them is file-level
// only.
constexpr const char* kComponentStoreRoot = "/opt/var/lib/keen-pbr/components";
constexpr const char* kNfqwsPackage = "nfqws2-keenetic";
// opkg's copy of the feed index, rewritten by `opkg update`. It names the
// exact file, size and SHA-256 the feed serves, which is what a downloaded
// IPK is checked against before it is allowed anywhere near opkg install.
constexpr const char* kNfqwsFeedList = "/opt/var/opkg-lists/nfqws2-keenetic";
constexpr const char* kNfqwsUpgradeLimitationExact =
    "Runs opkg under the shared maintenance lease with the target IPK "
    "verified against the feed index and an exact copy of the installed "
    "version retained for reinstall; an interrupted transaction is recovered "
    "at the next daemon start from its journal. The upstream maintainer "
    "script may still start the service before verification.";
constexpr const char* kNfqwsUpgradeLimitationInexact =
    "Runs opkg under the shared maintenance lease with the target IPK "
    "verified against the feed index, but no exact copy of the installed "
    "version is retained (the feed no longer serves it), so a failed or "
    "interrupted upgrade restores captured files without exact opkg "
    "metadata and stays blocked until the package state is repaired.";
// Where the last boot-time recovery wrote its decision and outcome, so the
// status page can say what happened after a reboot. Written by the daemon's
// startup task, read on every status poll; absent until the first run that
// found a journal.
constexpr const char* kNfqwsBootRecoveryRecord =
    "/opt/var/lib/keen-pbr/nfqws-boot-recovery.json";
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

std::atomic<std::uint64_t>& nfqws_transaction_generation() noexcept {
    static std::atomic<std::uint64_t> generation{0};
    return generation;
}

struct NfqwsTransactionSnapshot {
    std::uint64_t generation{0};
    ComponentTransactionStatus transaction;
    bool stable{false};
};

NfqwsTransactionSnapshot read_nfqws_transaction_snapshot() {
    const auto before =
        nfqws_transaction_generation().load(std::memory_order_acquire);
    auto transaction = read_component_transaction(kNfqwsJournal);
    const auto after =
        nfqws_transaction_generation().load(std::memory_order_acquire);
    return NfqwsTransactionSnapshot{
        after, std::move(transaction), before == after};
}

bool nfqws_snapshot_is_clean(
    const NfqwsTransactionSnapshot& snapshot) noexcept {
    // Odd is the publication window between the generation bump and the
    // durable journal write/clear. The path may still look absent in that
    // window, but absence is not a clean snapshot until the writer closes the
    // seqlock with the next (even) generation.
    return snapshot.stable && (snapshot.generation % 2U) == 0U &&
           snapshot.transaction.state == ComponentTransactionState::none;
}

bool nfqws_snapshot_allows_optimistic_publish(
    const NfqwsTransactionSnapshot& initial,
    const NfqwsTransactionSnapshot& current) noexcept {
    return nfqws_snapshot_is_clean(initial) &&
           nfqws_snapshot_is_clean(current) &&
           initial.generation == current.generation;
}

void write_nfqws_transaction(
    const ComponentTransactionRecord& record) {
    // Advance before publishing the journal. A reader that straddles this
    // boundary either sees the durable record or a changed generation and
    // must withhold every optimistic version/update claim.
    nfqws_transaction_generation().fetch_add(1, std::memory_order_acq_rel);
    try {
        write_component_transaction(kNfqwsJournal, record);
    } catch (...) {
        nfqws_transaction_generation().fetch_add(
            1, std::memory_order_release);
        throw;
    }
    nfqws_transaction_generation().fetch_add(1, std::memory_order_release);
}

bool clear_nfqws_transaction() {
    // A failed clear is still a state transition attempt. Increment first so
    // a concurrent reader cannot publish evidence collected on the other side
    // of it; the retained journal remains the durable fail-closed authority.
    nfqws_transaction_generation().fetch_add(1, std::memory_order_acq_rel);
    const bool cleared = clear_component_transaction(kNfqwsJournal);
    nfqws_transaction_generation().fetch_add(1, std::memory_order_release);
    return cleared;
}

const char* nfqws_snapshot_state_name(
    const NfqwsTransactionSnapshot& snapshot) noexcept {
    return snapshot.stable
               ? component_transaction_state_name(snapshot.transaction.state)
               : "changed_during_read";
}

class NfqwsNetfilterRefreshGuard final {
public:
    explicit NfqwsNetfilterRefreshGuard(ApiContext& context,
                                        bool armed = true) noexcept
        : context_(context), armed_(armed) {}

    ~NfqwsNetfilterRefreshGuard() noexcept {
        if (!armed_) return;
        try {
            (void)context_.request_netfilter_runtime_refresh();
        } catch (...) {
            // The service/config mutation is already visible.  An exception
            // from an embedder callback must not mask its real result; the
            // production callback is itself fail-closed and non-throwing.
        }
    }

    NfqwsNetfilterRefreshGuard(const NfqwsNetfilterRefreshGuard&) = delete;
    NfqwsNetfilterRefreshGuard& operator=(
        const NfqwsNetfilterRefreshGuard&) = delete;

    bool request_now() noexcept {
        if (!armed_) return false;
        armed_ = false;
        try {
            return context_.request_netfilter_runtime_refresh();
        } catch (...) {
            return false;
        }
    }

private:
    ApiContext& context_;
    bool armed_{true};
};

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

std::string installed_version() {
    constexpr size_t kMaxStatusBytes = 64U * 1024U;
    const auto result = safe_exec_capture(
        {"/opt/bin/opkg", "status", "nfqws2-keenetic"},
        /*suppress_stderr=*/false,
        kMaxStatusBytes,
        /*capture_stderr=*/true,
        /*drain_after_limit=*/true,
        SafeExecFailureLog::DiagnosticOnly,
        SafeExecTimeouts{std::chrono::seconds{30}, std::chrono::seconds{2}});
    if (result.timed_out) {
        throw ApiError("timed out while reading the installed nfqws2 version",
                       504);
    }
    if (result.exit_code != 0 || result.truncated) return {};

    std::istringstream lines(result.stdout_output);
    std::string line;
    constexpr std::string_view prefix{"Version: "};
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind(prefix, 0) == 0) {
            return line.substr(prefix.size());
        }
    }
    return {};
}

struct BoundedOpkgUpgradeResult {
    std::string output;
    int status{-1};
    bool timed_out{false};
    bool termination_uncertain{false};
    // opkg install was issued against a verified candidate. Everything
    // before that (feed refresh, download, verification, retention of the
    // installed version's own IPK) leaves the installed component untouched.
    bool upgrade_started{false};
    // The feed serves nothing newer; no install was attempted.
    bool up_to_date{false};
    // An exact copy of the version that was installed when this began is in
    // the store, so a failed install can reinstall it rather than only
    // restore captured files.
    bool previous_exact{false};
    std::string target_version;
    // The install ran scripted: the package's own maintainer scripts were
    // run by the transaction with the init script held aside, so nothing
    // started the service and the caller owns the start. False means the
    // scripts could not be laid out and the plain opkg install ran instead,
    // with its usual autostart.
    bool scripted{false};
    // Meaningful only when scripted: every scripted step passed. A false
    // here already forced a non-zero status.
    bool scripted_ok{false};
    // False only when the init script is still held aside under its
    // kpbr-held name; boot recovery restores it by that name.
    bool init_restored{true};
};

// The third argument is the child's working directory, empty to inherit.
// `opkg download` writes into it; see ComponentCommandRunner for why this is
// a chdir and not a shell `cd` on KeeneticOS.
using NfqwsExecCapture = std::function<ExecCaptureResult(
    const std::vector<std::string>&, SafeExecTimeouts,
    const std::filesystem::path&)>;

struct NfqwsPackagePaths {
    fs::path store_root{kComponentStoreRoot};
    fs::path feed_list{kNfqwsFeedList};
    ScriptedInstallPaths scripted{fs::path{kInit}, fs::path{kInitHeld},
                                  fs::path{"/opt/etc/opkg.conf"},
                                  fs::path{"/"}, "/opt/bin/sh",
                                  "/opt/bin/tar"};
};

ComponentPackageOptions nfqws_package_options(const NfqwsPackagePaths& paths) {
    // Updating feed metadata and running maintainer scripts can both be slow on
    // flash-backed routers, so this is deliberately much longer than the
    // ordinary command deadline. It is still finite: the maintenance lease and
    // nfqws mutex must never be held forever by a wedged opkg or descendant.
    ComponentPackageOptions options;
    options.package = kNfqwsPackage;
    options.feed_list = paths.feed_list;
    options.timeouts =
        SafeExecTimeouts{std::chrono::minutes{10}, std::chrono::seconds{5}};
    options.scripted = paths.scripted;
    return options;
}

std::string nfqws_package_command_label(const std::vector<std::string>& argv) {
    std::string label = "opkg";
    for (std::size_t index = 1; index < argv.size(); ++index) {
        if (argv[index].empty() || argv[index].front() == '/') continue;
        label += ' ';
        label += argv[index];
    }
    return label;
}

// Package commands run with a pinned PATH. opkg spawns its downloader by
// name from PATH, and this router carries two wgets: /opt/bin/wget is the
// wget-ssl the feeds need, /opt/usr/bin/wget is a busybox applet link that
// cannot speak HTTPS at all. Which one a child sees would otherwise depend
// on who started the daemon - the boot init puts /opt/bin first, an
// operator's ssh shell puts /opt/usr/bin first - and a daemon restarted by
// hand would fail every feed refresh with "not an http or ftp url". The
// maintainer scripts a scripted install runs resolve their tools (sed, cp,
// route, ip) from the same pinned order.
constexpr const char* kNfqwsPackageCommandPath =
    "/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:"
    "/usr/sbin:/usr/bin:/sbin:/bin";

ExecCaptureResult run_nfqws_package_command(
    const std::vector<std::string>& argv, SafeExecTimeouts timeouts,
    const std::filesystem::path& working_directory) {
    return safe_exec_capture(
        argv,
        /*suppress_stderr=*/false,
        64U * 1024U,
        /*capture_stderr=*/true,
        /*drain_after_limit=*/true,
        SafeExecFailureLog::Enabled,
        timeouts,
        /*child_environment=*/{{"PATH", kNfqwsPackageCommandPath}},
        working_directory.string());
}

// Called once the target is verified and staged, immediately before opkg
// install: the last moment at which nothing has been mutated and the first
// at which the transaction knows which versions it is moving between.
// Returning false refuses the install - used when the journal that would
// describe the mutation could not be written, because a mutation nobody can
// later read about is the one this whole path exists to prevent.
using NfqwsPreparedHook =
    std::function<bool(const BoundedOpkgUpgradeResult&)>;

// Every package command passes through this, so the operator log carries
// each command's output with the same truncation, deadline and termination
// annotations whichever step ran it. The referenced fields belong to the
// caller's combined result (upgrade or install - the same contract).
ExecCaptureResult run_annotated_package_command(
    const NfqwsExecCapture& execute,
    const std::vector<std::string>& argv,
    SafeExecTimeouts timeouts,
    const std::filesystem::path& cwd,
    std::string& output,
    int& status,
    bool& timed_out,
    bool& termination_uncertain) {
    constexpr size_t kMaxOutputPerCommand = 64U * 1024U;
    auto result = execute(argv, timeouts, cwd);
    const auto label = nfqws_package_command_label(argv);
    output += result.stdout_output;
    if (!output.empty() && output.back() != '\n') {
        output += '\n';
    }
    if (result.truncated) {
        output += label + " output was truncated after " +
                  std::to_string(kMaxOutputPerCommand) + " bytes.\n";
    }
    if (result.timed_out) {
        timed_out = true;
        output += label +
                  " exceeded the 10 minute deadline; the "
                  "package-manager outcome is unknown.\n";
    }
    if (result.termination_uncertain) {
        termination_uncertain = true;
        output += label +
                  " could not be proven fully terminated. No component "
                  "inspection or captured-file recovery may run while a "
                  "package-manager descendant could still be mutating it.\n";
    }
    status = result.exit_code;
    if ((result.timed_out || result.termination_uncertain) && status == 0) {
        status = -1;
    }
    return result;
}

// The one mutation step every install-shaped flow shares: the scripted
// install (the package's scripts run by the transaction, service start
// suppressed) with an honest fallback to the plain opkg install when the
// scripts cannot be laid out - the plain install is exactly yesterday's
// behavior, autostart included, and a package whose archive this code
// cannot open must still be installable. The distinction is reported so
// the caller knows who owns the start.
void run_scripted_or_plain_install(ComponentPackageTransaction& transaction,
                                   bool upgrade,
                                   std::string& output,
                                   bool& mutation_started,
                                   bool& scripted,
                                   bool& scripted_ok,
                                   bool& init_restored,
                                   int& status,
                                   // The caller's combined command flags,
                                   // updated live by its annotated runner
                                   // while the scripted attempt runs.
                                   const bool& timed_out,
                                   const bool& termination_uncertain,
                                   const ScriptedServiceStop& stop_service =
                                       {}) {
    const auto append = [&output](const std::string& text) {
        if (text.empty()) return;
        if (!output.empty() && output.back() != '\n') output += '\n';
        output += text;
        if (output.back() != '\n') output += '\n';
    };
    try {
        ScriptedInstallReport report;
        transaction.scripted_install_candidate(upgrade, report,
                                               stop_service);
        append(report.notes);
        if (!report.scripts_extracted) {
            if (timed_out || termination_uncertain) {
                // The extraction did not fail - it did not finish, or its
                // process tree could not be proven dead. Starting a second
                // package manager on top of that is exactly what the
                // termination rules everywhere else refuse.
                append("The script extraction did not finish cleanly; not "
                       "falling back to a plain install on top of an "
                       "unproven process tree.");
                if (status == 0) status = -1;
                return;
            }
            // Nothing has run and nothing was mutated; the plain install
            // still works the way it always has.
            append("Falling back to a plain opkg install; the package's own "
                   "scripts will run, its service start included.");
            mutation_started = true;
            (void)transaction.install_candidate();
            return;
        }
        scripted = true;
        scripted_ok = scripted_install_succeeded(report);
        init_restored = report.init_restored;
        // A preinst that ran may already have moved component files around
        // even when the package manager itself never started; recovery must
        // treat that as a mutation.
        mutation_started = report.preinst_ran || report.mutation_started;
        if (!scripted_ok && status == 0) status = 1;
    } catch (const ComponentPackageRefused& refused) {
        mutation_started = false;
        append(std::string("opkg install was not run: ") + refused.what() +
               ".");
        if (status == 0) status = 1;
    }
}

BoundedOpkgUpgradeResult run_bounded_nfqws_opkg_upgrade(
    const NfqwsExecCapture& execute,
    const std::string& installed_version,
    const NfqwsPackagePaths& paths = {},
    const NfqwsPreparedHook& on_prepared = {},
    const ScriptedServiceStop& stop_service = {}) {
    BoundedOpkgUpgradeResult combined;
    const auto run_annotated = [&](const std::vector<std::string>& argv,
                                   SafeExecTimeouts timeouts,
                                   const std::filesystem::path& cwd) {
        return run_annotated_package_command(
            execute, argv, timeouts, cwd, combined.output, combined.status,
            combined.timed_out, combined.termination_uncertain);
    };

    ComponentIpkStore store(paths.store_root, kNfqwsPackage);
    ComponentPackageTransaction transaction(
        nfqws_package_options(paths), store, run_annotated);

    const auto preparation = transaction.prepare(installed_version);
    combined.output += preparation.output;
    combined.previous_exact = preparation.previous_exact;
    if (preparation.target) {
        combined.target_version = preparation.target->version;
    }
    if (!preparation.error.empty()) {
        // Nothing installed was touched. The status is still a failure: the
        // operator asked for an upgrade and is not getting one.
        if (combined.status == 0) combined.status = 1;
        return combined;
    }
    if (preparation.up_to_date) {
        combined.up_to_date = true;
        combined.status = 0;
        return combined;
    }
    if (!preparation.candidate_verified) {
        combined.output +=
            "No verified target package was staged; opkg install was not "
            "run.\n";
        if (combined.status == 0) combined.status = 1;
        return combined;
    }

    if (on_prepared && !on_prepared(combined)) {
        combined.output +=
            "The transaction journal could not record the prepared install; "
            "opkg install was not run.\n";
        if (combined.status == 0) combined.status = 1;
        return combined;
    }
    run_scripted_or_plain_install(
        transaction, /*upgrade=*/true, combined.output,
        combined.upgrade_started, combined.scripted, combined.scripted_ok,
        combined.init_restored, combined.status, combined.timed_out,
        combined.termination_uncertain, stop_service);
    return combined;
}

BoundedOpkgUpgradeResult run_bounded_nfqws_opkg_upgrade(
    const std::string& installed_version,
    const NfqwsPreparedHook& on_prepared,
    const ScriptedServiceStop& stop_service = {}) {
    return run_bounded_nfqws_opkg_upgrade(run_nfqws_package_command,
                                          installed_version, {}, on_prepared,
                                          stop_service);
}

// The official feed definition, exactly as the shell installer writes it.
// A conf already present with other content is the operator's mirror choice
// and is never touched.
constexpr const char* kNfqwsFeedConf = "/opt/etc/opkg/nfqws2-keenetic.conf";
constexpr const char* kNfqwsFeedConfContent =
    "src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all\n";

struct BoundedOpkgInstallResult {
    std::string output;
    int status{-1};
    bool timed_out{false};
    bool termination_uncertain{false};
    // opkg install nfqws2-keenetic was issued. Everything before it -
    // HTTPS prerequisites, the feed definition, feed refreshes, the
    // download and its verification - is system state, not the component.
    bool install_started{false};
    std::string target_version;
    bool feed_conf_written{false};
    // Same trio as the upgrade result: scripted says the transaction ran
    // the package's scripts itself with the service start suppressed, so
    // the caller owns the start.
    bool scripted{false};
    bool scripted_ok{false};
    bool init_restored{true};
};

// A fresh installation, prepared the way install.sh's configure_nfqws2
// does and executed the way the guarded upgrade does. The order of the
// preparation is load-bearing and copied from the shell installer: with the
// plain Entware wget still installed, a present HTTPS feed definition makes
// `opkg update` fail as a whole - which is exactly the state an interrupted
// earlier install leaves behind. So a canonical conf is removed first,
// HTTPS prerequisites go in, the conf is written back, and only then is the
// feed read. The package itself is then fetched with `opkg download`,
// verified against the feed index's size and SHA-256, installed from the
// verified file, and that file is retained as the exact copy of the
// installed version from day one.
BoundedOpkgInstallResult run_bounded_nfqws_opkg_install(
    const NfqwsExecCapture& execute,
    const NfqwsPackagePaths& paths = {},
    const fs::path& feed_conf = kNfqwsFeedConf,
    const NfqwsPreparedHook& on_prepared = {}) {
    BoundedOpkgInstallResult combined;
    const auto run_annotated = [&](const std::vector<std::string>& argv,
                                   SafeExecTimeouts timeouts,
                                   const std::filesystem::path& cwd) {
        return run_annotated_package_command(
            execute, argv, timeouts, cwd, combined.output, combined.status,
            combined.timed_out, combined.termination_uncertain);
    };
    const auto note = [&](const std::string& line) {
        if (!combined.output.empty() && combined.output.back() != '\n') {
            combined.output += '\n';
        }
        combined.output += line;
        combined.output += '\n';
    };
    const auto command_failed = [&] {
        return combined.status != 0 || combined.timed_out ||
               combined.termination_uncertain;
    };
    const auto options = nfqws_package_options(paths);

    // 1. The feed definition, canonical copies first (see above).
    std::error_code conf_error;
    const auto conf_status = fs::symlink_status(feed_conf, conf_error);
    bool conf_present = !conf_error && fs::exists(conf_status);
    if (conf_present && !fs::is_regular_file(conf_status)) {
        // A symlink or anything else non-regular is somebody's deliberate
        // arrangement: it stays active for opkg and is not this action's
        // to rewrite or remove. If it points at an HTTPS feed on a router
        // without wget-ssl, the update below fails and says so.
        note("The nfqws2 feed definition is not a regular file; it is left "
             "as it is.");
    } else if (conf_present) {
        std::ifstream input(feed_conf, std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
        const std::string canonical(kNfqwsFeedConfContent);
        const bool conf_is_ours =
            body == canonical ||
            body == canonical.substr(0, canonical.size() - 1);
        if (conf_is_ours) {
            fs::remove(feed_conf, conf_error);
            if (conf_error) {
                combined.status = -1;
                note("The canonical nfqws2 feed definition could not be "
                     "removed before the HTTPS prerequisites (" +
                     conf_error.message() +
                     "); with the plain wget still possible, refreshing "
                     "feeds over it would fail as a whole, so nothing was "
                     "attempted.");
                return combined;
            }
            conf_present = false;
        } else {
            note("An nfqws2 feed definition with custom content is already "
                 "present and is left as it is.");
        }
    }

    // 2. HTTPS prerequisites, against the stock Entware feeds.
    (void)run_annotated({options.opkg, "update"}, options.timeouts, {});
    if (command_failed()) {
        note("The Entware package lists could not be refreshed; nothing "
             "was installed.");
        return combined;
    }
    (void)run_annotated({options.opkg, "install", "ca-certificates",
                         "wget-ssl"},
                        options.timeouts, {});
    if (command_failed()) {
        note("The HTTPS prerequisites (ca-certificates, wget-ssl) could not "
             "be installed; nothing else was touched.");
        return combined;
    }
    // Best effort, exactly like the shell installer: a router without
    // wget-nossl fails this and that is fine. What is not fine is a remove
    // that timed out or cannot be proven terminated - no more package
    // manager on top of that.
    (void)run_annotated({options.opkg, "remove", "wget-nossl"},
                        options.timeouts, {});
    if (combined.timed_out || combined.termination_uncertain) {
        note("The wget-nossl removal did not finish cleanly; stopping "
             "before the package manager is asked to do more.");
        if (combined.status == 0) combined.status = -1;
        return combined;
    }
    combined.status = 0;

    // 3. The feed definition itself, durably.
    if (!conf_present) {
        try {
            AtomicFileWriteOptions write_options;
            write_options.create_parent_directories = true;
            write_options.file_mode = 0644;
            write_file_atomically(feed_conf.string(), kNfqwsFeedConfContent,
                                  write_options);
            combined.feed_conf_written = true;
        } catch (const std::exception& error) {
            combined.status = -1;
            note(std::string("The nfqws2 feed definition could not be "
                             "written: ") +
                 error.what());
            return combined;
        }
    }

    // 4. The verified path the upgrade uses, with nothing installed yet:
    // prepare refreshes the feed again, downloads the one listed IPK,
    // verifies it against the index and stages it as the candidate.
    ComponentIpkStore store(paths.store_root, kNfqwsPackage);
    ComponentPackageTransaction transaction(options, store, run_annotated);
    const auto preparation = transaction.prepare(std::string{});
    combined.output += preparation.output;
    if (preparation.target) {
        combined.target_version = preparation.target->version;
    }
    if (!preparation.error.empty()) {
        if (combined.status == 0) combined.status = 1;
        return combined;
    }
    if (!preparation.candidate_verified) {
        note("No verified package was staged; opkg install was not run.");
        if (combined.status == 0) combined.status = 1;
        return combined;
    }

    if (on_prepared) {
        BoundedOpkgUpgradeResult prepared_view;
        prepared_view.target_version = combined.target_version;
        if (!on_prepared(prepared_view)) {
            note("The transaction journal could not record the prepared "
                 "install; opkg install was not run.");
            if (combined.status == 0) combined.status = 1;
            return combined;
        }
    }
    run_scripted_or_plain_install(
        transaction, /*upgrade=*/false, combined.output,
        combined.install_started, combined.scripted, combined.scripted_ok,
        combined.init_restored, combined.status, combined.timed_out,
        combined.termination_uncertain);
    return combined;
}

// Reinstalls the exact IPK of the version that was installed before a
// failed upgrade, which restores opkg's own record of the package and
// every file the package owns. Returns true only when the scripts ran to
// the end and the package database names that version again; the caller
// still restores captured files and verifies the runtime afterwards. The
// reinstall runs scripted - the package's maintainer scripts executed by
// the transaction with the init script held aside - so the rollback owns
// the service start instead of racing the package's own.
bool reinstall_exact_previous_nfqws_package(
    const std::string& expected_version,
    const std::function<std::string()>& read_installed_version,
    std::string& output,
    const NfqwsExecCapture& execute = run_nfqws_package_command,
    const NfqwsPackagePaths& paths = {}) {
    if (expected_version.empty()) {
        output += "The pre-upgrade version was not known; the exact package "
                  "was not reinstalled.\n";
        return false;
    }
    ComponentIpkStore store(paths.store_root, kNfqwsPackage);
    int annotated_status = 0;
    bool annotated_timed_out = false;
    bool annotated_uncertain = false;
    const auto run_annotated = [&](const std::vector<std::string>& argv,
                                   SafeExecTimeouts timeouts,
                                   const std::filesystem::path& cwd) {
        return run_annotated_package_command(
            execute, argv, timeouts, cwd, output, annotated_status,
            annotated_timed_out, annotated_uncertain);
    };
    ComponentPackageTransaction transaction(
        nfqws_package_options(paths), store, run_annotated);
    bool scripted_failed = false;
    try {
        ScriptedInstallReport report;
        transaction.scripted_reinstall_current(expected_version, report);
        if (!report.notes.empty()) {
            if (!output.empty() && output.back() != '\n') output += '\n';
            output += report.notes;
        }
        if (!report.scripts_extracted) {
            if (annotated_timed_out || annotated_uncertain) {
                output += "The script extraction did not finish cleanly; "
                          "not falling back to a plain reinstall on top of "
                          "an unproven process tree.\n";
                return false;
            }
            output += "Falling back to a plain opkg reinstall; the "
                      "package's own scripts will run, its service start "
                      "included.\n";
            (void)transaction.reinstall_current(expected_version);
        } else {
            scripted_failed = !scripted_install_succeeded(report);
        }
    } catch (const ComponentPackageRefused& refused) {
        output += std::string("The exact previous package was not "
                              "reinstalled: ") +
                  refused.what() + ".\n";
        return false;
    }
    if (scripted_failed || annotated_status != 0 || annotated_timed_out ||
        annotated_uncertain) {
        output += "Reinstalling the exact previous package " +
                  expected_version + " did not succeed.\n";
        return false;
    }
    std::string now_installed;
    try {
        now_installed = read_installed_version();
    } catch (const std::exception& error) {
        output += std::string("The reinstalled version could not be read: ") +
                  error.what() + "\n";
        return false;
    }
    if (now_installed != expected_version) {
        output += "opkg reports version '" + now_installed +
                  "' after reinstalling " + expected_version +
                  "; the package state is not proven restored.\n";
        return false;
    }
    output += "Exact previous package " + expected_version +
              " reinstalled; opkg metadata restored.\n";
    return true;
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

#ifdef KEEN_PBR3_TESTING
// The published package_metadata_verified is decided by
// nfqws_snapshot_allows_optimistic_publish, which compares the snapshot taken
// before the slow reads with the one taken after. This single-state form is
// the same rule stated over one snapshot, and exists so the suite can pin what
// an abandoned transaction means without staging two of them. Guarding it
// keeps the -Werror build from carrying a function no shipped path calls.
bool nfqws_package_metadata_verified(
    ComponentTransactionState transaction_state) noexcept {
    return transaction_state == ComponentTransactionState::none;
}
#endif

bool should_clear_nfqws_upgrade_journal(
    bool component_broken,
    bool package_mutation_started,
    bool rolled_back,
    bool termination_uncertain,
    bool exact_rollback_verified = false) noexcept {
    // An uncertain mutator cannot authorize any finalization.
    if (termination_uncertain) return false;
    // A rollback that reinstalled the exact previous IPK, with opkg naming
    // that version again and the captured files and runtime restored, has
    // put the package back where it was. The upgrade still failed, but the
    // component is a known quantity and the journal has nothing left to
    // guard.
    if (rolled_back && exact_rollback_verified) return true;
    // A file-only rollback after opkg started cannot reconcile the package
    // database. The durable record is then the marker that suppresses
    // version and update claims until manual package repair.
    return !component_broken && !(package_mutation_started && rolled_back);
}

struct CapturedRestoreFinalization {
    bool ok{false};
    bool clear_journal{false};
    bool package_metadata_verified{false};
    const char* terminal_state{"incomplete"};
};

CapturedRestoreFinalization finalize_captured_file_restore(
    bool files_restored) noexcept {
    // Even a byte- and runtime-complete restore is not an exact package
    // rollback: opkg metadata and newly introduced paths remain untouched.
    return CapturedRestoreFinalization{
        false,
        false,
        false,
        files_restored ? "metadata_unverified" : "incomplete"};
}

nlohmann::json nfqws_update_status(bool force = false) {
    static std::mutex mutex;
    static nlohmann::json cached;
    static std::chrono::steady_clock::time_point checked_at{};
    constexpr auto kCacheLifetime = std::chrono::minutes(30);

    const auto initial_snapshot = read_nfqws_transaction_snapshot();
    auto blocked_status = [](const NfqwsTransactionSnapshot& snapshot) {
        std::error_code installed_error;
        return nlohmann::json{
            {"ok", true},
            {"installed", fs::is_regular_file(kBinary, installed_error)},
            {"current", ""},
            {"latest", ""},
            {"available", false},
            {"release_url", ""},
            {"package_metadata_verified", false},
            {"blocked_reason", "nfqws_package_metadata_unverified"},
            {"transaction_state",
             nfqws_snapshot_state_name(snapshot)}};
    };
    if (!nfqws_snapshot_is_clean(initial_snapshot)) {
        return blocked_status(initial_snapshot);
    }

    const std::lock_guard lock(mutex);
    const auto now = std::chrono::steady_clock::now();
    auto publish_optimistic = [&](nlohmann::json candidate,
                                  bool replace_cache) {
        // Revalidate after every version read and remote fetch, immediately
        // before cache publication/return. A mutation that appeared and even
        // finished during this request changes the in-process generation, so
        // none->none cannot turn a stale observation into an "up to date"
        // claim. An active/retained journal is independently fail-closed.
        const auto current_snapshot = read_nfqws_transaction_snapshot();
        if (!nfqws_snapshot_allows_optimistic_publish(
                initial_snapshot, current_snapshot)) {
            return blocked_status(current_snapshot);
        }
        if (replace_cache) {
            cached = candidate;
            checked_at = now;
        }
        return candidate;
    };
    const auto current = installed_version();
    if (current.empty()) {
        return publish_optimistic(
            nlohmann::json{{"ok", true},
                           {"installed", false},
                           {"current", ""},
                           {"latest", ""},
                           {"available", false},
                           {"release_url", ""},
                           {"package_metadata_verified", true},
                           {"blocked_reason", ""},
                           {"transaction_state", "none"}},
            /*replace_cache=*/true);
    }
    if (!force && !cached.empty() && cached.value("installed", false) &&
        cached.value("current", std::string{}) == current &&
        now - checked_at < kCacheLifetime) {
        return publish_optimistic(cached, /*replace_cache=*/false);
    }

    HttpClient client;
    client.set_timeout(std::chrono::seconds(10));
    client.set_max_response_size(256U * 1024U);
    const auto release = nlohmann::json::parse(client.download(
        "https://api.github.com/repos/nfqws/nfqws2-keenetic/releases/latest"));
    const auto latest = release.value("tag_name", std::string{});
    if (latest.empty()) throw ApiError("nfqws2 release does not contain a version", 502);

    return publish_optimistic(
        nlohmann::json{
            {"ok", true},
            {"installed", true},
            {"current", current},
            {"latest", latest},
            {"available", newer_version(latest, current)},
            {"release_url", release.value("html_url", std::string{})},
            {"package_metadata_verified", true},
            {"blocked_reason", ""},
            {"transaction_state", "none"}},
        /*replace_cache=*/true);
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
PackagePathList nfqws_package_paths() {
    auto result = read_opkg_file_list_bounded(kOpkgPackageFileList);
    if (!result.complete) return result;
    if (std::any_of(result.paths.begin(), result.paths.end(),
                    [](const std::string& path) {
                        return path.rfind("/opt/", 0) != 0;
                    })) {
        result.complete = false;
        result.error = "nfqws2 package record contains a path outside /opt";
        result.paths.clear();
        return result;
    }
    if (result.paths.size() > kComponentMaxPathCount - 2U) {
        result.complete = false;
        result.error = "nfqws2 package footprint exceeds the path-count limit";
        result.paths.clear();
        return result;
    }
    result.paths.emplace_back(kBinary);
    result.paths.emplace_back(kInit);
    std::sort(result.paths.begin(), result.paths.end());
    result.paths.erase(std::unique(result.paths.begin(), result.paths.end()),
                       result.paths.end());
    return result;
}

PackageFootprint require_nfqws_footprint() {
    const auto paths = nfqws_package_paths();
    if (!paths.complete) {
        throw ApiError("cannot establish the nfqws2 package footprint: " +
                           paths.error,
                       409);
    }
    auto footprint = observe_package_footprint(paths.paths);
    if (!footprint.complete) {
        throw ApiError(
            "cannot establish a complete, bounded nfqws2 package footprint",
            409);
    }
    return footprint;
}

struct PostUpgradeFootprintAssessment {
    PackageFootprint footprint;
    PackageFootprintDiff diff;
    PackageBinaryOutcome binary_outcome{
        PackageBinaryOutcome::indeterminate};
    bool recovery_required{true};
    std::string error;
};

PostUpgradeFootprintAssessment assess_post_upgrade_footprint(
    const PackageFootprint& before,
    const std::function<PackageFootprint()>& observe_after) {
    PostUpgradeFootprintAssessment assessment;
    try {
        assessment.footprint = observe_after();
        if (!assessment.footprint.complete) {
            assessment.error =
                "post-upgrade package footprint is incomplete";
            return assessment;
        }
        assessment.binary_outcome = judge_package_binary(
            before, assessment.footprint, kBinary);
        assessment.diff =
            diff_package_footprint(before, assessment.footprint);
        assessment.recovery_required = false;
    } catch (const std::exception& error) {
        assessment.error = error.what();
    } catch (...) {
        assessment.error = "unknown package-footprint observation failure";
    }
    return assessment;
}

// Whether the store holds the exact IPK of `installed_version`. Hashing the
// retained file costs one pass over a few megabytes, and the nfqws page polls
// status, so the answer is cached briefly - the same bargain as
// cached_restore_point_state, for the same reason. `force` is for our own
// mutations of the store.
bool cached_exact_previous_ipk(const std::string& installed_version,
                               bool force = false) {
    static std::mutex mutex;
    static std::optional<std::pair<std::string, bool>> cached;
    static std::chrono::steady_clock::time_point checked_at{};
    constexpr auto kTtl = std::chrono::seconds{30};

    if (installed_version.empty()) return false;
    const std::lock_guard lock(mutex);
    const auto now = std::chrono::steady_clock::now();
    if (!force && cached && cached->first == installed_version &&
        now - checked_at < kTtl) {
        return cached->second;
    }
    bool exact = false;
    try {
        const ComponentIpkStore store(kComponentStoreRoot, kNfqwsPackage);
        const auto current = store.inspect(IpkSlot::current);
        exact = current.state == IpkSlotState::usable &&
                current.retained->version == installed_version;
    } catch (...) {
        exact = false;
    }
    cached = std::make_pair(installed_version, exact);
    checked_at = now;
    return exact;
}

std::optional<nlohmann::json> read_nfqws_boot_recovery_record();

nlohmann::json nfqws_upgrade_capability(
    bool package_metadata_verified,
    bool exact_previous_ipk,
    const ComponentTransactionStatus* journal) {
    // What the last boot-time recovery decided and did, when one ran. The
    // page cannot tell "nothing ran" from "ran and had to keep the journal"
    // by the journal alone; this is the difference. Published only when the
    // record demonstrably talks about the journal being shown: either no
    // journal remains (the record describes the run that cleared it), or
    // the identities match. A record about some earlier journal next to a
    // fresh interruption - or next to one this daemon has not looked at
    // yet - would claim an examination that never happened.
    nlohmann::json boot_recovery_last = nullptr;
    if (const auto record = read_nfqws_boot_recovery_record()) {
        const bool describes_shown_journal =
            journal == nullptr ||
            journal->state == ComponentTransactionState::none ||
            (journal->record &&
             journal->record->started_at != 0 &&
             record->value("journal_started_at", std::int64_t{0}) ==
                 journal->record->started_at &&
             record->value("journal_operation", std::string{}) ==
                 journal->record->operation);
        if (describes_shown_journal) {
            boot_recovery_last = nlohmann::json{
                {"at", record->value("at", std::int64_t{0})},
                {"outcome", record->value("outcome", std::string{})},
                {"plan", record->value("plan", std::string{})},
                {"reason", record->value("reason", std::string{})},
                {"journal_cleared", record->value("journal_cleared", false)},
            };
        }
    }
    return nlohmann::json{
        {"available", package_metadata_verified},
        {"mode", "guarded_opkg"},
        // The installed version's own IPK is in the store, so a failed
        // upgrade reinstalls it instead of only restoring captured files.
        {"exact_previous_ipk", exact_previous_ipk},
        // The upgrade path refuses any target whose size or SHA-256 differs
        // from the feed index, and installs from the verified file.
        {"verified_target_ipk", true},
        {"exact_opkg_metadata_rollback", exact_previous_ipk},
        // The daemon's startup task reads the journal and acts on it; see
        // run_nfqws_boot_recovery.
        {"boot_recovery", true},
        {"boot_recovery_last", boot_recovery_last},
        {"package_metadata_verified", package_metadata_verified},
        {"blocked_reason",
         package_metadata_verified
             ? ""
             : "nfqws_package_metadata_unverified"},
        {"limitation", exact_previous_ipk
                           ? kNfqwsUpgradeLimitationExact
                           : kNfqwsUpgradeLimitationInexact},
    };
}

std::vector<pid_t> nfqws_processes();

std::optional<std::string> hash_nfqws_process_image(pid_t pid) {
    // /proc/<pid>/exe is intentionally a kernel-owned symlink. The generic
    // integrity helper rejects every symlink (correct for restore inputs), so
    // using it here made every live process image unverifiable. Follow only
    // this fixed /proc shape and keep the read under the component file bound.
    const auto image = fs::path("/proc") / std::to_string(pid) / "exe";
    std::ifstream input(image, std::ios::binary);
    if (!input) return std::nullopt;
    Sha256 hasher;
    std::array<char, 64U * 1024U> buffer{};
    std::uintmax_t total = 0;
    while (input) {
        input.read(buffer.data(),
                   static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            total += static_cast<std::uintmax_t>(count);
            if (total > kComponentMaxFileBytes) return std::nullopt;
            hasher.update(buffer.data(), static_cast<std::size_t>(count));
        }
    }
    if (!input.eof()) return std::nullopt;
    return hasher.hex_digest();
}

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
        const auto digest = hash_nfqws_process_image(pid);
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

bool nfqws_fully_stopped() {
    return nfqws_processes().empty() &&
           !nfqueue_active(configured_nfqueue_num());
}

bool nfqws_running_installed_image() {
    const auto installed = rescue_integrity::sha256_file(kBinary);
    const auto runtime = observe_nfqws_runtime();
    return installed && runtime.process_present && runtime.image_consistent &&
           runtime.image_sha256 == *installed &&
           nfqueue_active(configured_nfqueue_num());
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
// An older popen/pclose path waited for the child with no deadline at all. A
// hung init script therefore blocked the HTTP worker forever - while holding
// nfqws_operation_mutex, so every subsequent nfqws request piled up behind it
// and the whole section of the UI froze with no way back short of restarting
// the daemon.
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

struct PostMutationGuardResult {
    bool operation_completed{false};
    bool component_broken{true};
    bool recovery_attempted{false};
    bool rolled_back{false};
    std::string operation_error;
    std::string recovery_error;
};

PostMutationGuardResult guard_nfqws_post_mutation(
    const std::function<bool()>& operation,
    const std::function<bool()>& recover,
    const std::function<bool()>& recovery_allowed) {
    PostMutationGuardResult result;
    try {
        result.component_broken = operation();
        result.operation_completed = true;
    } catch (const std::exception& error) {
        result.operation_error = error.what();
    } catch (...) {
        result.operation_error = "unknown post-mutation failure";
    }

    if (!result.component_broken) return result;

    // A timed-out process tree may have escaped its retained process group.
    // In that case touching the same files is not recovery: it is a concurrent
    // mutation racing an untrusted maintainer script. Leave both the component
    // and journal alone until an operator can prove the mutator is gone.
    try {
        if (!recovery_allowed()) return result;
    } catch (const std::exception& error) {
        result.recovery_error = error.what();
        return result;
    } catch (...) {
        result.recovery_error = "unknown recovery-admission failure";
        return result;
    }

    result.recovery_attempted = true;
    try {
        result.rolled_back = recover();
    } catch (const std::exception& error) {
        result.recovery_error = error.what();
    } catch (...) {
        result.recovery_error = "unknown captured-file recovery failure";
    }
    return result;
}

// Best-effort recovery for every failure after opkg is allowed to start. This
// function deliberately does not clear the transaction journal: its caller may
// do that only after both captured bytes and the pre-upgrade runtime state are
// verified. Any exception is caught by guard_nfqws_post_mutation(), so an
// uncertain recovery keeps the durable journal and blocks another upgrade.
bool restore_nfqws_capture_after_failed_upgrade(
    const ComponentTransactionRecord& record,
    TransactionProgress& progress,
    std::string& output,
    const std::string& version_before,
    bool exact_previous_available,
    bool& package_metadata_restored) {
    package_metadata_restored = false;
    const auto capture_state = verify_component_capture(kNfqwsCapture);
    if (capture_state != ComponentCaptureState::usable) {
        output +=
            "\nThe upgrade left the component broken and there is no usable "
            "restore point to return to (";
        output += component_capture_state_name(capture_state);
        output += ").\n";
        return false;
    }

    progress.step("rollback");
    // The exact IPK first, while the service may still be whatever opkg
    // left: the reinstall runs the package's maintainer scripts (scripted,
    // with the service start suppressed), and the captured files must land
    // after those, not before. Only then are the bytes the operator
    // actually had written back over the package's defaults.
    if (exact_previous_available) {
        output += "\nThe upgrade did not finish safely; reinstalling the "
                  "exact previous package.\n";
        package_metadata_restored = reinstall_exact_previous_nfqws_package(
            version_before, [] { return installed_version(); }, output);
    }
    output +=
        package_metadata_restored
            ? "Restoring the captured bytes over the reinstalled package.\n"
            : "\nThe upgrade did not finish safely; restoring the captured "
              "bytes.\n";
    if (!nfqws_fully_stopped()) {
        int stop_status = 0;
        output += run_nfqws_service_command("stop", stop_status);
    }
    if (!nfqws_fully_stopped()) {
        output +=
            "nfqws2 could not be verified stopped; captured files were not "
            "written and the transaction record was retained.\n";
        return false;
    }

    const auto restored = restore_component_files(kNfqwsCapture);
    output += restored.complete
                  ? "Restored " + std::to_string(restored.restored) +
                        " files.\n"
                  : "Restore did not complete: " +
                        (restored.refused.empty()
                             ? std::to_string(restored.failed.size()) +
                                   " file(s) failed"
                             : restored.refused) +
                        ".\n";
    if (!restored.complete) return false;

    bool runtime_restored = false;
    if (record.runtime_was_running) {
        int start_status = 0;
        output += run_nfqws_service_command("start", start_status);
        runtime_restored =
            start_status == 0 && nfqws_running_installed_image();
    } else {
        runtime_restored = nfqws_fully_stopped();
    }
    if (!runtime_restored) {
        output +=
            "The captured files were restored, but the pre-upgrade runtime "
            "state could not be verified; the transaction record was retained.\n";
    }
    return runtime_restored;
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
            const auto packaged_content = read_file(config);
            const auto content =
                overridden ? read_file(override_path) : packaged_content;
            // Applying a built-in creates an override that may differ only by
            // the generated WAN list or our owned telemetry arguments. Keep
            // that exact semantic copy canonical, but never let a copied
            // marker hide a real user edit as an approved profile.
            bool canonical = true;
            if (overridden) {
                const auto expected = render_wan_interfaces(packaged_content);
                canonical = nfqws_config_matches_packaged_strategy(
                    content, packaged_content, expected);
            }
            result.push_back({{"name", name}, {"builtin", true}, {"overridden", overridden},
                              {"canonical", canonical}, {"content", content}});
            names.insert(name);
        }
    }
    if (fs::is_directory(kUserStrategies, ec)) {
        for (const auto& entry : fs::directory_iterator(kUserStrategies, ec)) {
            if (!entry.is_regular_file(ec) || entry.path().extension() != ".conf") continue;
            const auto name = entry.path().stem().string();
            if (!valid_name(name, true) || names.count(name) || deleted.count(name)) continue;
            result.push_back({{"name", name}, {"builtin", false}, {"overridden", false},
                              {"canonical", false},
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


// ---------------------------------------------------------------------------
// Boot-time recovery of an interrupted package transaction.
//
// A reboot in the middle of `opkg install` leaves the journal, the exact-IPK
// store, the restore point and whatever opkg managed to write. Nothing used
// to look at them: the next boot brought up whatever was on disk and the web
// page said "a previous operation did not finish" until an operator repaired
// the package by hand. decide_component_boot_recovery turns that evidence
// into one plan; this runs the plan with the same helpers the interactive
// rollback uses, under the same maintenance lease, in the same lock order.
// ---------------------------------------------------------------------------

std::optional<nlohmann::json> read_nfqws_boot_recovery_record() {
    constexpr std::size_t kMaxRecordBytes = 16U * 1024U;
    std::error_code error;
    const auto path = fs::path(kNfqwsBootRecoveryRecord);
    if (!fs::is_regular_file(fs::symlink_status(path, error)) || error) {
        return std::nullopt;
    }
    const auto size = fs::file_size(path, error);
    if (error || size > kMaxRecordBytes) return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    std::string body((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    try {
        auto parsed = nlohmann::json::parse(body);
        if (!parsed.is_object()) return std::nullopt;
        return parsed;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void write_nfqws_boot_recovery_record(
    const NfqwsBootRecoveryResult& result) noexcept {
    constexpr std::size_t kMaxOutputBytes = 4U * 1024U;
    try {
        std::string output = result.output;
        if (output.size() > kMaxOutputBytes) {
            output = "...\n" + output.substr(output.size() - kMaxOutputBytes);
        }
        const nlohmann::json body{
            {"at", static_cast<std::int64_t>(std::time(nullptr))},
            {"outcome", nfqws_boot_recovery_outcome_name(result.outcome)},
            {"plan", result.plan},
            {"reason", result.reason},
            {"journal_cleared", result.journal_cleared},
            // The answered journal's identity, so the next start can tell
            // "same journal, already answered" from a new interruption, and
            // the status page can tell whether this record describes the
            // journal it is showing.
            {"journal_started_at", result.journal_started_at},
            {"journal_operation", result.journal_operation},
            {"output", output},
        };
        AtomicFileWriteOptions options;
        options.create_parent_directories = true;
        options.default_file_mode = 0600;
        options.file_mode = static_cast<mode_t>(0600);
        write_file_atomically(kNfqwsBootRecoveryRecord, body.dump(2) + "\n",
                              options);
    } catch (...) {
        // The record is for the status page; losing it loses a sentence,
        // not the recovery.
    }
}

// The orchestration proper. Every input and effect is a hook so the mapping
// from plan to action, the lease handling and what gets recorded can be
// exercised without a router; production (below) binds the real helpers.
NfqwsBootRecoveryResult run_nfqws_boot_recovery_with(
    const NfqwsBootRecoveryHooks& hooks) {
    NfqwsBootRecoveryResult result;
    const auto finish = [&](NfqwsBootRecoveryOutcome outcome) {
        result.outcome = outcome;
        if (hooks.record_result) hooks.record_result(result);
        return result;
    };
    const auto note = [&](const std::string& line) {
        if (!result.output.empty() && result.output.back() != '\n') {
            result.output += '\n';
        }
        result.output += line;
        result.output += '\n';
    };

    // A free look first: no journal means no lease, no log, nothing. The
    // one thing that overrides the early returns is a held-aside init
    // script - physical evidence that a scripted install's hold was never
    // undone. That evidence forces the run through to the lease and the
    // heal, whatever the journal says; the gates are then re-applied under
    // the lease so a healed run still executes no already-answered plan.
    const bool held_evidence =
        hooks.init_script_held && hooks.init_script_held();
    {
        const auto glance = hooks.read_journal();
        if ((glance.state == ComponentTransactionState::none ||
             glance.state == ComponentTransactionState::in_flight) &&
            !held_evidence) {
            result.plan = component_boot_recovery_action_name(
                ComponentBootRecoveryAction::none);
            result.outcome = NfqwsBootRecoveryOutcome::nothing_to_do;
            return result;
        }
        // A journal that stays on disk after an answer (journal_retained,
        // failed) would otherwise be answered again at every daemon start -
        // and a reinstall plan re-derived from it would downgrade whatever
        // the operator has repaired by hand since. One journal gets one
        // answer; the durable record's identity says whether this is the
        // same journal.
        if (glance.record && hooks.read_last_answer && !held_evidence) {
            const auto answered = hooks.read_last_answer();
            if (answered && answered->journal_started_at != 0 &&
                answered->journal_started_at == glance.record->started_at &&
                answered->journal_operation == glance.record->operation) {
                result.plan = component_boot_recovery_action_name(
                    ComponentBootRecoveryAction::none);
                result.reason =
                    "this journal was already answered at a previous start "
                    "(outcome " + answered->outcome + "); it stays until the "
                    "package state is repaired and acknowledged";
                result.outcome = NfqwsBootRecoveryOutcome::nothing_to_do;
                // Deliberately not recorded: the matching record must keep
                // describing the run that actually acted.
                return result;
            }
        }
    }

    // Lease first, then the in-process mutex: the order every nfqws
    // mutation uses. Busy is not an error here - S80 may still hold the
    // lease while it finishes our own start - so it is reported for a
    // retry rather than recorded as a result.
    std::unique_ptr<MaintenanceLease> lease;
    try {
        lease = hooks.acquire_lease();
    } catch (const MaintenanceLockError& error) {
        if (error.kind() == MaintenanceLockErrorKind::busy) {
            lease.reset();
        } else {
            note(std::string("The maintenance lease could not be taken: ") +
                 error.what());
            result.plan = "none";
            result.reason = "maintenance lease unavailable";
            return finish(NfqwsBootRecoveryOutcome::failed);
        }
    }
    if (!lease) {
        result.outcome = NfqwsBootRecoveryOutcome::lease_busy;
        return result;
    }
    const std::lock_guard lock(nfqws_operation_mutex());

    // First, under the lease: if a scripted install crashed while the init
    // script was held aside, put it back before anything decides or runs a
    // plan - the plans stop and start the service through that script.
    if (hooks.heal_init_script) {
        const auto healed = hooks.heal_init_script();
        if (!healed.empty()) note(healed);
    }

    // Everything is re-read under the lease: the glance above may have
    // raced an operator's repair.
    ComponentBootRecoveryEvidence evidence;
    evidence.journal = hooks.read_journal();
    evidence.previous_ipk = hooks.inspect_current_ipk();
    evidence.capture = hooks.capture_state();
    evidence.installed_version = hooks.installed_version();
    evidence.installed_binary_sha256 = hooks.installed_binary_sha256();
    if (evidence.journal.record) {
        result.journal_started_at = evidence.journal.record->started_at;
        result.journal_operation = evidence.journal.record->operation;
    }
    // The gates the held evidence bypassed above, re-applied under the
    // lease: the heal has run, and a healed boot still must not execute a
    // plan for a journal that is absent or already answered. Neither
    // return is recorded - there is no unanswered journal to record
    // against, and the answered record must keep describing the run that
    // actually acted.
    if (held_evidence) {
        if (evidence.journal.state == ComponentTransactionState::none ||
            evidence.journal.state == ComponentTransactionState::in_flight) {
            result.plan = component_boot_recovery_action_name(
                ComponentBootRecoveryAction::none);
            result.reason = "the held init script was the only evidence";
            result.outcome = NfqwsBootRecoveryOutcome::nothing_to_do;
            return result;
        }
        if (evidence.journal.record && hooks.read_last_answer) {
            const auto answered = hooks.read_last_answer();
            if (answered && answered->journal_started_at != 0 &&
                answered->journal_started_at ==
                    evidence.journal.record->started_at &&
                answered->journal_operation ==
                    evidence.journal.record->operation) {
                result.plan = component_boot_recovery_action_name(
                    ComponentBootRecoveryAction::none);
                result.reason =
                    "this journal was already answered at a previous start "
                    "(outcome " + answered->outcome + "); the held init "
                    "script has been dealt with above and the journal stays "
                    "until the package state is repaired and acknowledged";
                result.outcome = NfqwsBootRecoveryOutcome::nothing_to_do;
                return result;
            }
        }
    }
    const auto plan = decide_component_boot_recovery(evidence);
    result.plan = component_boot_recovery_action_name(plan.action);
    result.reason = plan.reason;
    note("Boot recovery plan: " + result.plan + " (" + plan.reason + ").");

    switch (plan.action) {
    case ComponentBootRecoveryAction::none:
        return finish(NfqwsBootRecoveryOutcome::nothing_to_do);

    case ComponentBootRecoveryAction::clear_journal:
        if (hooks.clear_journal()) {
            result.journal_cleared = true;
            note("Transaction journal cleared.");
            return finish(NfqwsBootRecoveryOutcome::recovered);
        }
        note("The transaction journal could not be removed; it stays as "
             "the marker of an unfinished operation.");
        return finish(NfqwsBootRecoveryOutcome::failed);

    case ComponentBootRecoveryAction::manual:
        note("Nothing on disk can put the component back; the journal "
             "stays and web upgrades remain blocked until the package is "
             "repaired by hand.");
        return finish(NfqwsBootRecoveryOutcome::journal_retained);

    case ComponentBootRecoveryAction::restore_files:
    case ComponentBootRecoveryAction::reinstall_previous:
    case ComponentBootRecoveryAction::restore_files_inexact:
        break;
    }

    const auto& record = *evidence.journal.record;
    NfqwsBootRecoveryStepResult step;
    try {
        step = hooks.execute_restore(plan, record, result.output);
    } catch (const std::exception& error) {
        note(std::string("Recovery step failed: ") + error.what());
        step = NfqwsBootRecoveryStepResult{};
    } catch (...) {
        note("Recovery step failed with an unknown error.");
        step = NfqwsBootRecoveryStepResult{};
    }
    const bool exact_required =
        plan.action == ComponentBootRecoveryAction::reinstall_previous;
    const bool succeeded =
        step.rolled_back && (!exact_required || step.package_metadata_restored);
    if (!succeeded) {
        note(exact_required && step.rolled_back
                 ? "Captured files and runtime were restored, but the exact "
                   "previous package was not reinstalled; package metadata "
                   "stays unverified."
                 : "The component could not be restored; the journal stays.");
        return finish(NfqwsBootRecoveryOutcome::failed);
    }
    if (exact_required && hooks.discard_candidate) hooks.discard_candidate();
    if (!plan.clear_journal_on_success) {
        note("Captured files and runtime restored, but without the exact "
             "previous package opkg metadata stays unverified; the journal "
             "stays until the package is repaired.");
        return finish(NfqwsBootRecoveryOutcome::journal_retained);
    }
    if (!hooks.clear_journal()) {
        note("The component is restored, but the transaction journal could "
             "not be removed.");
        return finish(NfqwsBootRecoveryOutcome::failed);
    }
    result.journal_cleared = true;
    note("Component restored to version " + record.previous_version +
         "; transaction journal cleared.");
    return finish(NfqwsBootRecoveryOutcome::recovered);
}

NfqwsBootRecoveryHooks production_nfqws_boot_recovery_hooks(ApiContext& ctx) {
    NfqwsBootRecoveryHooks hooks;
    hooks.read_journal = [] {
        return read_component_transaction(kNfqwsJournal);
    };
    hooks.read_last_answer =
        []() -> std::optional<NfqwsBootRecoveryLastAnswer> {
        const auto record = read_nfqws_boot_recovery_record();
        if (!record) return std::nullopt;
        NfqwsBootRecoveryLastAnswer answer;
        answer.journal_started_at =
            record->value("journal_started_at", std::int64_t{0});
        answer.journal_operation =
            record->value("journal_operation", std::string{});
        answer.outcome = record->value("outcome", std::string{});
        return answer;
    };
    hooks.acquire_lease = [&ctx]() -> std::unique_ptr<MaintenanceLease> {
        return ctx.acquire_maintenance_lease("nfqws-boot-recovery");
    };
    hooks.init_script_held = []() -> bool {
        std::error_code held_error;
        const auto held_status = fs::symlink_status(kInitHeld, held_error);
        return !held_error && fs::exists(held_status);
    };
    hooks.heal_init_script = []() -> std::string {
        std::error_code held_error;
        const auto held_status = fs::symlink_status(kInitHeld, held_error);
        if (held_error || !fs::exists(held_status)) return {};
        std::error_code init_error;
        const auto init_status = fs::symlink_status(kInit, init_error);
        if (init_error &&
            init_status.type() != fs::file_type::not_found) {
            // Absence is the restore case below (libstdc++ reports it as
            // not_found with ENOENT in the error code); only a stat that
            // failed some other way leaves the state unknown.
            return std::string("The nfqws2 init script could not be "
                               "inspected (") +
                   init_error.message() +
                   "); its held-aside copy was left untouched.";
        }
        if (fs::exists(init_status)) {
            if (!fs::is_regular_file(init_status) &&
                !fs::is_symlink(init_status)) {
                // Something that is not a script occupies the init path -
                // which is exactly how a restore rename fails and leaves
                // the held copy behind. Deleting the copy here would
                // destroy the one thing that can still put the script
                // back; the operator has to clear the path first.
                return std::string("The nfqws2 init script path is occupied "
                                   "by something that is not a script while "
                                   "a held-aside copy exists; neither was "
                                   "touched - clear ") +
                       kInit + " and the next start restores the script.";
            }
            // The real script is in place, so the held name is a leftover
            // whose window has passed; keeping it would make the next hold
            // silently overwrite evidence.
            std::error_code remove_error;
            fs::remove(kInitHeld, remove_error);
            return remove_error
                       ? std::string("A stale held copy of the nfqws2 init "
                                     "script could not be removed: ") +
                             remove_error.message()
                       : std::string("Removed a stale held copy of the "
                                     "nfqws2 init script.");
        }
        // No init script at its place. Putting the held copy back is right
        // only while the package is still installed; a held copy that
        // outlived its package (opkg removes only registered paths) would
        // otherwise be resurrected as a boot-time start script for a binary
        // that no longer exists.
        std::error_code list_error;
        if (!fs::is_regular_file(kOpkgPackageFileList, list_error)) {
            std::error_code remove_error;
            fs::remove(kInitHeld, remove_error);
            return remove_error
                       ? std::string("The held init script copy of a "
                                     "removed package could not be "
                                     "deleted: ") +
                             remove_error.message()
                       : std::string("Removed the held init script copy of "
                                     "a package that is no longer "
                                     "installed.");
        }
        std::error_code rename_error;
        fs::rename(kInitHeld, kInit, rename_error);
        return rename_error
                   ? std::string("The nfqws2 init script is held aside at ") +
                         kInitHeld + " and could not be restored: " +
                         rename_error.message()
                   : std::string("Restored the nfqws2 init script from its "
                                 "held-aside copy: a scripted install was "
                                 "interrupted while its postinst ran.");
    };
    hooks.inspect_current_ipk = []() -> IpkSlotInspection {
        try {
            const ComponentIpkStore store(kComponentStoreRoot, kNfqwsPackage);
            return store.inspect(IpkSlot::current);
        } catch (...) {
            IpkSlotInspection inspection;
            inspection.state = IpkSlotState::corrupt;
            inspection.detail = "the component store could not be inspected";
            return inspection;
        }
    };
    hooks.capture_state = [] {
        return verify_component_capture(kNfqwsCapture);
    };
    hooks.installed_version = []() -> std::string {
        try {
            return installed_version();
        } catch (...) {
            return {};
        }
    };
    hooks.installed_binary_sha256 = []() -> std::string {
        return rescue_integrity::sha256_file(kBinary).value_or(std::string{});
    };
    // The progress stream must finish with the run's real outcome, which is
    // known only after the journal-clear decision - not inside the restore
    // step, whose local success ("files came back") is exactly what the
    // outcomes journal_retained and failed exist to qualify. The slot hands
    // the open progress from the step to the final record.
    auto progress_slot =
        std::make_shared<std::unique_ptr<TransactionProgress>>();
    hooks.execute_restore = [&ctx, progress_slot](
                                const ComponentBootRecoveryPlan& plan,
                                const ComponentTransactionRecord& record,
                                std::string& output) {
        NfqwsBootRecoveryStepResult step;
        *progress_slot =
            std::make_unique<TransactionProgress>(ctx, "boot-recovery");
        // Stopping, restoring and starting nfqws2 changes its netfilter
        // footprint and possibly its process image: ask the control loop to
        // reconcile PPE/netfilter state afterwards, as the interactive path
        // does at its own mutation boundary.
        NfqwsNetfilterRefreshGuard refresh_guard(ctx);
        try {
            step.rolled_back = restore_nfqws_capture_after_failed_upgrade(
                record, **progress_slot, output, record.previous_version,
                plan.action == ComponentBootRecoveryAction::reinstall_previous,
                step.package_metadata_restored);
        } catch (const std::exception& error) {
            output += std::string("\nBoot recovery step failed: ") +
                      error.what() + "\n";
            step.rolled_back = false;
        }
        (void)cached_restore_point_state(/*force=*/true);
        return step;
    };
    hooks.clear_journal = [] { return clear_nfqws_transaction(); };
    hooks.discard_candidate = [] {
        try {
            ComponentIpkStore store(kComponentStoreRoot, kNfqwsPackage);
            store.discard(IpkSlot::candidate);
        } catch (...) {
        }
    };
    hooks.record_result = [progress_slot](
                              const NfqwsBootRecoveryResult& result) {
        if (*progress_slot) {
            (*progress_slot)
                ->finish(nfqws_boot_recovery_outcome_name(result.outcome));
            progress_slot->reset();
        }
        write_nfqws_boot_recovery_record(result);
    };
    return hooks;
}
} // namespace

const char* nfqws_boot_recovery_outcome_name(
    NfqwsBootRecoveryOutcome outcome) noexcept {
    switch (outcome) {
    case NfqwsBootRecoveryOutcome::nothing_to_do: return "nothing_to_do";
    case NfqwsBootRecoveryOutcome::lease_busy: return "lease_busy";
    case NfqwsBootRecoveryOutcome::recovered: return "recovered";
    case NfqwsBootRecoveryOutcome::journal_retained: return "journal_retained";
    case NfqwsBootRecoveryOutcome::failed: return "failed";
    }
    return "unknown";
}

NfqwsBootRecoveryResult run_nfqws_boot_recovery(ApiContext& ctx) noexcept {
    try {
        return run_nfqws_boot_recovery_with(
            production_nfqws_boot_recovery_hooks(ctx));
    } catch (const std::exception& error) {
        NfqwsBootRecoveryResult result;
        result.outcome = NfqwsBootRecoveryOutcome::failed;
        result.plan = "none";
        result.reason = "boot recovery threw";
        result.output = std::string("Boot recovery failed: ") + error.what();
        write_nfqws_boot_recovery_record(result);
        return result;
    } catch (...) {
        NfqwsBootRecoveryResult result;
        result.outcome = NfqwsBootRecoveryOutcome::failed;
        result.plan = "none";
        result.reason = "boot recovery threw";
        result.output = "Boot recovery failed with an unknown error";
        write_nfqws_boot_recovery_record(result);
        return result;
    }
}

void register_nfqws_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    std::optional<ApplyStrategyHooks> apply_hooks) {
    server.get("/api/nfqws", []() -> std::string {
        std::error_code ec;
        const bool installed = fs::is_regular_file(kBinary, ec);
        const auto initial_snapshot = read_nfqws_transaction_snapshot();
        const bool initially_metadata_verified =
            nfqws_snapshot_is_clean(initial_snapshot);
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
        std::string version;
        if (installed && initially_metadata_verified) {
            version = installed_version();
        }
        const auto rotator_state =
            nfqws_rotator_state_json(active_content, processes);
        const auto restore_point_state = cached_restore_point_state();
        // `installed_version`, directory walks and runtime inspection above
        // all take time. Revalidate directly before publication so a package
        // transaction that started or completed during the read cannot leave
        // an optimistic version/capability response behind.
        const auto current_snapshot = read_nfqws_transaction_snapshot();
        const bool package_metadata_verified =
            nfqws_snapshot_allows_optimistic_publish(
                initial_snapshot, current_snapshot);
        if (!package_metadata_verified) version.clear();
        const auto& published_snapshot = package_metadata_verified
                                             ? initial_snapshot
                                             : current_snapshot;
        return nlohmann::json{
                   {"installed", installed},
                   {"running", running},
                   {"process_running", process_running},
                   {"queue_active", queue_active},
                   {"version", version},
                   {"package_metadata_verified", package_metadata_verified},
                   {"files", files},
                   {"strategies", strategies},
                   {"active_strategy", active_strategy},
                   {"rotator_state", rotator_state},
                   // Surfaced here rather than only on the next attempt. A
                   // reboot or a concurrent package operation makes the
                   // package version unverified before another mutation is
                   // considered.
                   {"transaction_state",
                    nfqws_snapshot_state_name(published_snapshot)},
                   {"restore_point",
                    component_capture_state_name(
                        restore_point_state)},
                   {"upgrade_capability",
                    nfqws_upgrade_capability(
                        package_metadata_verified,
                        cached_exact_previous_ipk(version),
                        &published_snapshot.transaction)},
                   {"restore_capability",
                    nlohmann::json{
                        {"available",
                         restore_point_state == ComponentCaptureState::usable},
                        {"exact_package_state", false},
                        {"limitation",
                         "Restores captured files only; it does not restore "
                         "opkg metadata or remove files introduced later."}}}}
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
            const bool active_config =
                path == fs::path(kConfigDir) / "nfqws2.conf";
            // Saving the active file does not restart nfqws2.  It can
            // therefore make the durable configuration disagree with the
            // live process argv.  Reconcile immediately so PPE is removed on
            // that mismatch instead of retaining a graph derived from stale
            // selectors until an unrelated firewall event.
            NfqwsNetfilterRefreshGuard refresh_guard(ctx, active_config);
            AtomicFileWriteOptions write_options;
            write_options.replace_existing = !create_only;
            const auto saved = save_nfqws_file(
                path,
                request.value("content", std::string{}),
                write_options);
            auto response = successful_write_response(saved.durable);
            response["firewall_reconcile_pending"] =
                active_config ? refresh_guard.request_now() : false;
            return response.dump();
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
            NfqwsNetfilterRefreshGuard refresh_guard(ctx);
            int status = 0;
            const auto output = run_nfqws_service_command(command, status);
            // A terminal service action may change both the live queue and
            // the process argv from which PPE derives its active port
            // contract.  Request the existing coalesced control-loop writer;
            // never execute firewall commands on this HTTP worker.
            const bool firewall_reconcile_pending =
                refresh_guard.request_now();
            return nlohmann::json{{"ok", status == 0},
                                  {"output", output},
                                  {"status", status},
                                  {"firewall_reconcile_pending",
                                   firewall_reconcile_pending}}
                .dump();
        }
        if (action == "install") {
            // A fresh installation for a router that does not have the
            // package: the same lease, the same lock order and the same
            // verified download path as the upgrade. What it does not have
            // is a pre-mutation world to capture - nothing is installed -
            // so the honest rollback of a failed fresh install is removal,
            // back to the nothing that was there.
            std::unique_ptr<MaintenanceLease> maintenance;
            try {
                maintenance = ctx.acquire_maintenance_lease("nfqws-install");
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
            const std::lock_guard lock(nfqws_operation_mutex());
            std::error_code presence_error;
            if (fs::is_regular_file(kBinary, presence_error) ||
                fs::is_regular_file(kOpkgPackageFileList, presence_error)) {
                // The opkg file list alone also refuses: it means opkg
                // still holds a record of this package, and installing over
                // a record is the package manager's decision to make
                // through upgrade, not this action's.
                throw ApiError(
                    "nfqws2 is already installed, or opkg still holds its "
                    "package record; use the upgrade action, or repair the "
                    "package record manually",
                    409);
            }
            const auto journal = read_component_transaction(kNfqwsJournal);
            if (journal.state != ComponentTransactionState::none) {
                throw ApiError(
                    std::string("a previous nfqws2 package operation did not "
                                "finish (") +
                        component_transaction_state_name(journal.state) +
                        "); inspect the component before installing",
                    409);
            }
            TransactionProgress progress(ctx, "install");
            ComponentTransactionRecord record;
            record.component = kNfqwsPackage;
            record.operation = "install";
            record.phase = ComponentTransactionPhase::started;
            record.started_at = static_cast<std::int64_t>(std::time(nullptr));
            record.owner_is_operation_process = false;
            write_nfqws_transaction(record);

            // The install ends with the service started - by this action
            // after verification when the install ran scripted, by the
            // package's own postinst on the plain fallback - so the
            // firewall graph must be reconciled whatever happens past this
            // point.
            NfqwsNetfilterRefreshGuard refresh_guard(ctx);
            progress.step("install");
            const auto result = run_bounded_nfqws_opkg_install(
                run_nfqws_package_command, {}, kNfqwsFeedConf,
                [&](const BoundedOpkgUpgradeResult& prepared) {
                    // Verified and staged; nothing mutated yet. The journal
                    // must say "mutating" durably before opkg install may
                    // run - a mutation nobody can later read about is what
                    // this path exists to prevent.
                    record.target_version = prepared.target_version;
                    record.phase = ComponentTransactionPhase::mutating;
                    try {
                        write_nfqws_transaction(record);
                    } catch (...) {
                        return false;
                    }
                    return true;
                });
            std::string output = result.output;
            bool journal_cleared = false;

            if (result.termination_uncertain) {
                output +=
                    "\nThe package-manager process tree could not be proven "
                    "stopped. The durable transaction record was retained; "
                    "stop/inspect the process tree and repair the package "
                    "state manually.\n";
                progress.finish("termination_uncertain");
                return nlohmann::json{{"ok", false},
                                      {"output", output},
                                      {"installed", false},
                                      {"journal_cleared", false}}
                    .dump();
            }
            if (!result.install_started) {
                // Prerequisites or verification refused; the component was
                // never touched and the journal has nothing to guard.
                journal_cleared = clear_nfqws_transaction();
                if (!journal_cleared) {
                    output += "\nThe transaction record could not be "
                              "cleared; the next package operation will "
                              "refuse until it is inspected.\n";
                }
                progress.finish("failed");
                return nlohmann::json{{"ok", false},
                                      {"output", output},
                                      {"installed", false},
                                      {"journal_cleared", journal_cleared}}
                    .dump();
            }

            progress.step("verify");
            record.phase = ComponentTransactionPhase::verifying;
            try {
                write_nfqws_transaction(record);
            } catch (const std::exception& error) {
                output += std::string("\nThe verifying phase could not be "
                                      "journaled: ") +
                          error.what() + "\n";
            }
            std::string installed_now;
            try {
                installed_now = installed_version();
            } catch (...) {
            }
            const bool component_broken =
                result.status != 0 || installed_now.empty() ||
                (!result.target_version.empty() &&
                 installed_now != result.target_version);

            if (!component_broken) {
                record.phase = ComponentTransactionPhase::verified;
                try {
                    write_nfqws_transaction(record);
                } catch (const std::exception& error) {
                    output += std::string("\nThe verified phase could not "
                                          "be journaled: ") +
                              error.what() + "\n";
                }
                // A scripted install suppressed the package's own start; a
                // fresh install ends with the service running, so start it
                // now that the package is verified. A start that fails does
                // not un-install a verified package - the package's own
                // postinst ignores its start's outcome the same way - it is
                // reported and left to the operator, with the component
                // installed and stopped.
                if (result.scripted) {
                    progress.step("start");
                    int start_status = 0;
                    output += "\nStarting nfqws2 under the transaction (the "
                              "package's own start was suppressed).\n";
                    output += run_nfqws_service_command("start",
                                                        start_status);
                    output += start_status == 0
                                  ? "nfqws2 started.\n"
                                  : "nfqws2 did not start cleanly; check "
                                    "its configuration and logs.\n";
                }
                // The file just installed becomes the exact copy of the
                // installed version - retention from day one, while the
                // feed still serves these bytes.
                try {
                    ComponentIpkStore store(kComponentStoreRoot,
                                            kNfqwsPackage);
                    store.promote_candidate();
                    output += "Exact copy of " + installed_now +
                              " retained for future rollback.\n";
                } catch (const std::exception& error) {
                    output += std::string("The installed package's exact "
                                          "copy could not be retained: ") +
                              error.what() + "\n";
                }
                (void)cached_exact_previous_ipk(installed_now,
                                                /*force=*/true);
                journal_cleared = clear_nfqws_transaction();
                output +=
                    "\nInstalled nfqws2 version: " + installed_now + "\n";
                if (!journal_cleared) {
                    output += "The transaction record could not be cleared; "
                              "package operations stay blocked until it is "
                              "inspected.\n";
                }
                progress.finish(journal_cleared ? "completed"
                                                : "journal_retained");
                return nlohmann::json{{"ok", journal_cleared},
                                      {"output", output},
                                      {"installed", true},
                                      {"installed_version", installed_now},
                                      {"journal_cleared", journal_cleared}}
                    .dump();
            }

            // The rollback of a fresh install is removal: the pre-install
            // state was "not installed", and that is a state this router is
            // known to work in. Its own step name, because the page's
            // "rollback" wording talks about restoring saved files, and
            // nothing is being restored here.
            progress.step("remove");
            output += "\nThe installation did not verify; removing the "
                      "package to return to the pre-install state.\n";
            int remove_status = -1;
            bool remove_timed_out = false;
            bool remove_uncertain = false;
            (void)run_annotated_package_command(
                run_nfqws_package_command,
                {nfqws_package_options({}).opkg, "remove", kNfqwsPackage},
                nfqws_package_options({}).timeouts, {}, output,
                remove_status, remove_timed_out, remove_uncertain);
            bool removed = false;
            if (!remove_uncertain && !remove_timed_out) {
                std::string after;
                try {
                    after = installed_version();
                } catch (...) {
                }
                // The proof is the post-state, not opkg's exit code: a
                // remove of a package opkg never registered answers
                // non-zero while the state may still be clean. All three
                // traces must be gone - the status entry, the binary, and
                // opkg's file list, which is written during unpack and is
                // exactly what a crashed install leaves behind. A leftover
                // list would make every retry refuse as "already
                // installed", so "removed" must not be claimed over it.
                std::error_code trace_error;
                removed = after.empty() &&
                          !fs::is_regular_file(kBinary, trace_error) &&
                          !fs::is_regular_file(kOpkgPackageFileList,
                                               trace_error);
            }
            try {
                ComponentIpkStore store(kComponentStoreRoot, kNfqwsPackage);
                store.discard(IpkSlot::candidate);
            } catch (...) {
            }
            if (removed) {
                // opkg removes only registered paths; the held-aside init
                // script copy a failed scripted install can leave is ours
                // to clean. It must not survive the journal below: with no
                // journal, boot recovery would later read a stale held name
                // as evidence of an interrupted install that never was.
                std::error_code held_error;
                if (fs::remove(kInitHeld, held_error)) {
                    output += "Removed the held-aside init script copy the "
                              "failed scripted install left behind.\n";
                }
                journal_cleared = clear_nfqws_transaction();
                output += journal_cleared
                              ? "Removed; the router is back to the "
                                "pre-install state.\n"
                              : "Removed, but the transaction record could "
                                "not be cleared; it stays until inspected.\n";
            } else {
                output += "The package could not be verified removed; the "
                          "transaction record was retained for manual "
                          "repair.\n";
            }
            progress.finish(removed && journal_cleared ? "rolled_back"
                                                       : "failed");
            return nlohmann::json{{"ok", false},
                                  {"output", output},
                                  {"installed", !removed},
                                  {"journal_cleared", journal_cleared}}
                .dump();
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
            const auto footprint_before = require_nfqws_footprint();
            const auto config_before = observe_nfqws_config();
            const auto runtime_before = observe_nfqws_runtime();
            // What opkg says is installed right now. This is the version an
            // exact rollback must reinstall, and the version whose IPK is
            // retained while the feed still serves it. Read before the
            // journal exists: a timeout here refuses the upgrade with
            // nothing written and nothing touched.
            const auto version_before = installed_version();

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
            record.previous_version = version_before;
            // Known now, not only after the download: a crash during the
            // feed refresh must leave a journal that lets recovery consult
            // the store rather than fall through to a file-only restore.
            // Preparation cannot change it - retaining the installed
            // version and staging a newer one are mutually exclusive.
            record.exact_previous_ipk =
                cached_exact_previous_ipk(version_before, /*force=*/true);
            record.owner_is_operation_process = false;
            write_nfqws_transaction(record);

            // Taken before opkg, because these bytes stop existing the moment
            // it runs and cannot be reconstructed afterwards.
            std::string output = "Rollback backup created.\n";
            progress.step("capture");
            const auto capture =
                capture_component_files(footprint_before, kNfqwsCapture);
            const auto capture_state =
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
            if (!capture.complete ||
                capture_state != ComponentCaptureState::usable) {
                const bool journal_cleared =
                    clear_nfqws_transaction();
                progress.finish("capture_incomplete");
                throw ApiError(
                    journal_cleared
                        ? "nfqws2 upgrade refused: no complete usable "
                          "pre-mutation capture"
                        : "nfqws2 upgrade refused: capture is incomplete and "
                          "the transaction journal could not be cleared",
                    409);
            }

            // Promoted immediately before the package manager runs, and not a
            // line earlier: from here on anything on disk may have changed.
            record.phase = ComponentTransactionPhase::mutating;
            write_nfqws_transaction(record);
            progress.step("install");
            // opkg may stop/start nfqws2 and replace the process image or its
            // NFQUEUE contract. Arm only at the mutation boundary: every exit
            // after this point asks the existing control-loop writer to
            // reconcile PPE/netfilter state, while preflight refusals remain
            // free of firewall side effects.
            NfqwsNetfilterRefreshGuard refresh_guard(ctx);
            int status = -1;
            bool durable = true;
            PackageBinaryOutcome binary_outcome =
                PackageBinaryOutcome::indeterminate;
            bool footprint_verified = false;
            std::string config_outcome_name = "unknown";
            std::string runtime_outcome_name = "unknown";
            std::string created;
            bool package_mutation_started = false;
            bool package_command_returned = false;
            bool termination_uncertain = false;
            bool recovery_safe = false;
            bool previous_exact = false;
            bool package_metadata_restored = false;
            std::string target_version;

            // This is the single exception boundary after the durable journal
            // says opkg may mutate the component. Every command, observation,
            // description and post-upgrade config write is inside it. A throw
            // therefore becomes the same captured-file recovery decision as a
            // non-zero opkg exit or a failed runtime check, rather than escaping
            // with a mutated package and only the firewall guard left to run.
            const auto post_mutation = guard_nfqws_post_mutation(
                [&]() {
                    const auto opkg = run_bounded_nfqws_opkg_upgrade(
                        version_before,
                        [&](const BoundedOpkgUpgradeResult& prepared) {
                            // Still nothing mutated. Record which versions
                            // the install is about to move between and
                            // whether the previous one is held byte-exact,
                            // so a reboot from here on leaves a journal a
                            // recovery can act on rather than guess from.
                            record.target_version = prepared.target_version;
                            record.exact_previous_ipk = prepared.previous_exact;
                            try {
                                write_nfqws_transaction(record);
                            } catch (const std::exception& error) {
                                output += std::string(
                                              "Journal write failed: ") +
                                          error.what() + "\n";
                                return false;
                            }
                            return true;
                        },
                        // The scripted flow suppresses every stop the
                        // package's own scripts used to perform, so the
                        // transaction stops the service itself - in the old
                        // prerm's slot, with the stragglers-killing verified
                        // stop - and the controlled start below brings it
                        // back on the new binary.
                        [&](std::string& notes) {
                            if (!runtime_before.process_present) {
                                return true;
                            }
                            notes += "Stopping nfqws2 under the transaction "
                                     "before its files are replaced.\n";
                            int stop_status = 0;
                            notes += run_nfqws_service_command("stop",
                                                               stop_status);
                            return stop_status == 0;
                        });
                    package_command_returned = true;
                    package_mutation_started = opkg.upgrade_started;
                    termination_uncertain = opkg.termination_uncertain;
                    previous_exact = opkg.previous_exact;
                    target_version = opkg.target_version;
                    status = opkg.status;
                    output += opkg.output;
                    // The store may have gained the installed version's
                    // own IPK during preparation; the status page should
                    // not keep saying otherwise for half a minute.
                    (void)cached_exact_previous_ipk(version_before,
                                                    /*force=*/true);

                    if (termination_uncertain) {
                        output +=
                            "\nThe package-manager process tree could not be "
                            "proven stopped. Post-upgrade inspection and "
                            "captured-file recovery were deliberately skipped "
                            "so they cannot race a live mutator. The durable "
                            "transaction record was retained; stop/inspect "
                            "the process tree and repair the package state "
                            "manually.\n";
                        return true;
                    }

                    // A failed `opkg update` changed feed metadata at most; it
                    // never reached the installed nfqws2 package. Once its
                    // process group is proven gone, there are no component
                    // bytes to inspect or restore and the journal may be
                    // cleared normally. The non-zero status still makes the
                    // requested upgrade fail.
                    if (!package_mutation_started) {
                        output +=
                            opkg.up_to_date
                                ? "\nNothing to install; the installed "
                                  "component was not mutated.\n"
                                : "\nopkg install was not started; the "
                                  "installed component was not mutated and "
                                  "no captured-file recovery was needed.\n";
                        return false;
                    }

                    // From here onward the executor has returned with a
                    // quiesced process group. Observation failures may safely
                    // enter the single captured-file recovery funnel.
                    recovery_safe = true;

                    // A scripted install suppressed the package's own start,
                    // so the transaction restores the pre-upgrade runtime
                    // state itself before judging it: a service that was
                    // running keeps running, on the new binary, started
                    // under the same lease that installed it. A start that
                    // does not come up is left to the runtime verdict below,
                    // which routes it into the captured-file recovery.
                    if (opkg.scripted && opkg.scripted_ok && status == 0 &&
                        runtime_before.process_present) {
                        progress.step("start");
                        int start_status = 0;
                        output += "\nStarting nfqws2 under the transaction "
                                  "(the package's own start was "
                                  "suppressed).\n";
                        output +=
                            run_nfqws_service_command("start", start_status);
                        if (start_status != 0) {
                            output += "The controlled start did not verify; "
                                      "the runtime check below decides.\n";
                        }
                    }

                    progress.step("verify");
                    record.phase = ComponentTransactionPhase::verifying;
                    write_nfqws_transaction(record);
                    const auto footprint_assessment =
                        assess_post_upgrade_footprint(
                            footprint_before,
                            [] { return require_nfqws_footprint(); });
                    binary_outcome = footprint_assessment.binary_outcome;
                    footprint_verified =
                        !footprint_assessment.recovery_required;
                    const auto config_outcome = judge_nfqws_config(
                        config_before, observe_nfqws_config());
                    config_outcome_name =
                        nfqws_config_outcome_name(config_outcome);
                    const auto runtime_after = observe_nfqws_runtime();
                    const auto runtime_outcome = judge_nfqws_runtime(
                        runtime_before, runtime_after,
                        footprint_assessment.recovery_required
                            ? std::string{}
                            : installed_binary_digest(
                                  footprint_assessment.footprint));
                    runtime_outcome_name =
                        nfqws_runtime_outcome_name(runtime_outcome);
                    if (footprint_assessment.recovery_required) {
                        output +=
                            "\nThe package footprint could not be established "
                            "after opkg; treating the component as broken and "
                            "attempting the captured-file restore";
                        if (!footprint_assessment.error.empty()) {
                            output += ": " + footprint_assessment.error;
                        }
                        output += ".\n";
                    } else {
                        describe_package_change(
                            output,
                            binary_outcome,
                            footprint_assessment.diff);
                    }
                    describe_runtime_outcome(output, runtime_outcome);
                    describe_config_outcome(output, config_outcome);

                    const bool binary_unverified =
                        binary_outcome != PackageBinaryOutcome::replaced &&
                        binary_outcome != PackageBinaryOutcome::unchanged;
                    const bool config_broken =
                        config_outcome == NfqwsConfigOutcome::lost ||
                        config_outcome ==
                            NfqwsConfigOutcome::replaced_by_package;
                    const bool runtime_state_changed =
                        runtime_before.process_present !=
                        runtime_after.process_present;
                    bool component_broken =
                        status != 0 ||
                        footprint_assessment.recovery_required ||
                        binary_unverified || config_broken ||
                        runtime_state_changed ||
                        nfqws_runtime_is_failure(runtime_outcome);
                    if (status == 0 && !component_broken) {
                        const auto version = installed_version();
                        if (version.empty()) {
                            component_broken = true;
                            output +=
                                "\nThe installed nfqws2 version could not be "
                                "verified; attempting the captured-file "
                                "restore.\n";
                        } else if (!target_version.empty() &&
                                   version != target_version) {
                            // opkg returned success but the package database
                            // does not name the file that was installed.
                            // That is not an upgrade that can be trusted.
                            component_broken = true;
                            output +=
                                "\nopkg reports version " + version +
                                " after installing " + target_version +
                                "; attempting the captured-file restore.\n";
                        } else {
                            output +=
                                "\nInstalled nfqws2 version: " + version +
                                "\n";
                        }
                    }
                    if (!component_broken) {
                        // Everything that could be checked has passed.
                        // Say so durably before the bookkeeping below: a
                        // crash between promotion and the journal's removal
                        // would otherwise read, at boot, as an unfinished
                        // mutation whose exact previous package is gone
                        // from `current` - and recovery would restore the
                        // old files over a verified new package.
                        record.phase = ComponentTransactionPhase::verified;
                        try {
                            write_nfqws_transaction(record);
                        } catch (const std::exception& error) {
                            // Not a reason to undo a verified upgrade. The
                            // journal stays at `verifying`; the ordinary
                            // clear below still removes it.
                            output += std::string("The verified phase could "
                                                  "not be journaled: ") +
                                      error.what() + "\n";
                        }
                        // The candidate is proven installed: it is now the
                        // exact copy of the installed version, and what was
                        // installed before becomes the exact copy of the
                        // previous one. A store failure here does not undo a
                        // verified upgrade; the next status read simply finds
                        // no exact copy and says so.
                        try {
                            ComponentIpkStore store(kComponentStoreRoot,
                                                    kNfqwsPackage);
                            store.promote_candidate();
                            output += "Exact copy of " + target_version +
                                      " retained for future rollback.\n";
                        } catch (const std::exception& error) {
                            output +=
                                std::string("The installed package's exact "
                                            "copy could not be retained: ") +
                                error.what() + "\n";
                        }
                        (void)cached_exact_previous_ipk(target_version,
                                                        /*force=*/true);
                    }
                    if (!component_broken) {
                        created = save_updated_default_strategy(
                            previous, candidates_before_upgrade, durable);
                        append_durability_warning(output, durable);
                    }
                    return component_broken;
                },
                [&]() {
                    return restore_nfqws_capture_after_failed_upgrade(
                        record, progress, output, version_before,
                        previous_exact, package_metadata_restored);
                },
                [&]() { return recovery_safe; });

            const bool component_broken = post_mutation.component_broken;
            const bool rolled_back = post_mutation.rolled_back;
            if (!post_mutation.operation_error.empty()) {
                if (status == 0) status = 1;
                output += "\nA post-mutation nfqws2 step failed: " +
                          post_mutation.operation_error + ".\n";
                if (post_mutation.recovery_attempted) {
                    output +=
                        "The failure was routed through captured-file "
                        "recovery.\n";
                }
            }
            if (!post_mutation.recovery_error.empty()) {
                output +=
                    "Captured-file recovery itself failed or became uncertain: " +
                    post_mutation.recovery_error + ".\n";
            }
            const bool recovery_blocked =
                component_broken && !post_mutation.recovery_attempted;
            if (recovery_blocked && !termination_uncertain) {
                output +=
                    "Captured-file recovery was not attempted because the "
                    "package-manager execution did not return enough evidence "
                    "to prove that mutation had stopped. The transaction "
                    "record was retained for manual recovery.\n";
            }
            const bool exact_rollback_verified =
                rolled_back && package_metadata_restored;
            const bool package_metadata_unverified =
                package_mutation_started && rolled_back &&
                !exact_rollback_verified;
            if (package_metadata_unverified) {
                output +=
                    "\nThe captured files and runtime were restored, but opkg "
                    "metadata and files introduced by the package were not. "
                    "The transaction remains degraded and web upgrades stay "
                    "blocked until the package state is repaired manually.\n";
            } else if (exact_rollback_verified) {
                output +=
                    "\nThe exact previous package, its captured files and "
                    "the runtime were restored; the component is back to "
                    "version " + version_before + ".\n";
                // Leftover candidate bytes are no longer a target for
                // anything; the next upgrade verifies a fresh download.
                try {
                    ComponentIpkStore store(kComponentStoreRoot,
                                            kNfqwsPackage);
                    store.discard(IpkSlot::candidate);
                } catch (...) {
                }
            }
            bool journal_cleared = false;
            if (should_clear_nfqws_upgrade_journal(
                    component_broken,
                    package_mutation_started,
                    rolled_back,
                    termination_uncertain,
                    exact_rollback_verified)) {
                journal_cleared =
                    clear_nfqws_transaction();
            }
            if (!journal_cleared) {
                output +=
                    "\nThe transaction record was retained because the "
                    "operation, rollback, runtime verification or journal "
                    "clear did not finish.\n";
            }
            // A rolled-back upgrade is still not a successful upgrade. The
            // operator asked for a new version and does not have one; that the
            // component survived is the recovery working, not the request.
            // Published before returning, so a page that never sees the HTTP
            // response - a closed tab, a dropped connection - still learns the
            // operation ended rather than showing progress forever.
            progress.finish(!journal_cleared
                                ? termination_uncertain
                                      ? "termination_uncertain"
                                      : package_metadata_unverified
                                            ? "metadata_unverified"
                                            : "journal_retained"
                                : component_broken
                                      ? (rolled_back ? "rolled_back" : "broken")
                                      : std::string{});
            const bool firewall_reconcile_pending =
                refresh_guard.request_now();
            return nlohmann::json{{"ok", status == 0 && !component_broken &&
                                          journal_cleared},
                                  {"rolled_back", rolled_back},
                                  {"journal_retained", !journal_cleared},
                                  {"package_mutation_started",
                                   package_mutation_started},
                                  {"package_command_returned",
                                   package_command_returned},
                                  {"package_metadata_verified",
                                   journal_cleared &&
                                       !package_metadata_unverified},
                                  {"termination_uncertain",
                                   termination_uncertain},
                                  {"recovery_attempted",
                                   post_mutation.recovery_attempted},
                                  {"recovery_blocked_reason",
                                   termination_uncertain
                                       ? "package_manager_termination_uncertain"
                                       : recovery_blocked
                                             ? "package_manager_quiescence_unverified"
                                             : ""},
                                  {"output", output}, {"status", status},
                                  {"strategy_created", created},
                                  {"durable", durable},
                                  {"binary_outcome",
                                   package_binary_outcome_name(binary_outcome)},
                                  {"footprint_verified", footprint_verified},
                                  {"config_outcome", config_outcome_name},
                                  {"runtime_outcome", runtime_outcome_name},
                                  {"firewall_reconcile_pending",
                                   firewall_reconcile_pending},
                                  {"warning", durable ? "" : kDurabilityWarning}}.dump();
        }
        if (action == "capture_restore_point") {
            // The snapshot contains configuration and lists as well as the
            // binary. It is private and never returned, but replacing a known
            // recovery point still changes the future downgrade target, so
            // this action is step-up protected alongside restore.
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
                require_nfqws_footprint(), kNfqwsCapture);
            const auto state = cached_restore_point_state(/*force=*/true);
            std::string output =
                "Captured files: " + std::to_string(captured.captured) + "\n";
            for (const auto& failure : captured.failed) {
                output += "Could not capture: " + failure + "\n";
            }
            // The exact IPK belongs to the restore point as much as the
            // files do, and unlike the files it has an expiry: the feed
            // serves only its latest version. Fetch it now, while "now" is
            // still in time. A feed that cannot be reached leaves the file
            // capture exactly as valid as it was; only the IPK is missing,
            // and the result says so.
            bool exact_previous_ipk = false;
            const auto retained_version = installed_version();
            if (retained_version.empty()) {
                output += "The installed version could not be read; no exact "
                          "package copy was retained.\n";
            } else {
                ComponentIpkStore store(kComponentStoreRoot, kNfqwsPackage);
                ComponentPackageTransaction transaction(
                    nfqws_package_options(NfqwsPackagePaths{}), store,
                    run_nfqws_package_command);
                const auto retention =
                    transaction.retain_installed(retained_version);
                output += retention.output;
                exact_previous_ipk = retention.previous_exact;
                (void)cached_exact_previous_ipk(retained_version,
                                                /*force=*/true);
            }
            // The verdict comes from re-reading the store, not from the write
            // having returned. What matters is whether a restore could use it.
            output += "Restore point: ";
            output += component_capture_state_name(state);
            output += "\n";
            if (!captured.complete &&
                state == ComponentCaptureState::usable) {
                output +=
                    "The new capture was not published; the previous usable "
                    "restore point was retained.\n";
            }
            return nlohmann::json{
                {"ok", captured.complete &&
                           state == ComponentCaptureState::usable},
                {"output", output},
                {"captured", captured.captured},
                {"failed", captured.failed.size()},
                // Manual restore still writes files only; the exact IPK is
                // used by the upgrade path's rollback.
                {"exact_package_state", false},
                {"exact_previous_ipk", exact_previous_ipk},
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

            const auto journal = read_component_transaction(kNfqwsJournal);
            if (journal.state != ComponentTransactionState::none) {
                throw ApiError(
                    "a previous nfqws2 package operation did not finish; "
                    "inspect or recover it before restoring again",
                    409);
            }
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

            const auto runtime_before = observe_nfqws_runtime();
            const bool queue_before =
                nfqueue_active(configured_nfqueue_num());
            if (runtime_before.process_present != queue_before) {
                throw ApiError(
                    "nfqws2 runtime is neither fully running nor fully "
                    "stopped; restore refused before changing files",
                    409);
            }

            ComponentTransactionRecord record;
            record.component = "nfqws2-keenetic";
            record.operation = "restore-component";
            record.phase = ComponentTransactionPhase::mutating;
            record.started_at = static_cast<std::int64_t>(std::time(nullptr));
            record.runtime_was_running = runtime_before.process_present;
            // The handler is a scope inside the long-lived daemon, not a
            // process. If it throws or its connection dies, the daemon PID
            // surviving must not keep this record classified as in-flight.
            record.owner_is_operation_process = false;
            write_nfqws_transaction(record);

            TransactionProgress progress(ctx, "restore");
            NfqwsNetfilterRefreshGuard refresh_guard(ctx);
            std::string output;
            if (record.runtime_was_running) {
                progress.step("stop");
                int stop_status = 0;
                output += run_nfqws_service_command("stop", stop_status);
                if (!nfqws_fully_stopped()) {
                    output +=
                        "nfqws2 could not be verified stopped; no captured "
                        "file was written. The transaction record was kept.\n";
                    progress.finish("stop_failed");
                    const bool firewall_reconcile_pending =
                        refresh_guard.request_now();
                    return nlohmann::json{
                        {"ok", false},
                        {"output", output},
                        {"restored", 0},
                        {"failed", 0},
                        {"runtime_verified", false},
                        {"journal_retained", true},
                        {"exact_package_state", false},
                        {"firewall_reconcile_pending",
                         firewall_reconcile_pending}}
                        .dump();
                }
            }
            progress.step("restore");
            const auto restored = restore_component_files(kNfqwsCapture);
            output += "\nRestored files: " +
                      std::to_string(restored.restored) + "\n";
            for (const auto& failure : restored.failed) {
                output += "Could not restore: " + failure + "\n";
            }
            bool runtime_verified = false;
            if (restored.complete && record.runtime_was_running) {
                progress.step("start");
                int start_status = 0;
                output += run_nfqws_service_command("start", start_status);
                runtime_verified =
                    start_status == 0 && nfqws_running_installed_image();
                if (!runtime_verified) {
                    output +=
                        "nfqws2 did not restart on the restored binary with "
                        "its configured NFQUEUE.\n";
                }
            } else if (restored.complete) {
                runtime_verified = nfqws_fully_stopped();
                if (!runtime_verified) {
                    output +=
                        "nfqws2 was stopped before restore but is not fully "
                        "stopped afterwards.\n";
                }
            } else if (record.runtime_was_running &&
                       restored.restored == 0U &&
                       !restored.refused.empty()) {
                // The restore source changed between the preflight check and
                // the restore call, so no destination was touched. Put the
                // original running state back, but retain the journal because
                // the requested restore itself did not complete.
                progress.step("start");
                int start_status = 0;
                output += run_nfqws_service_command("start", start_status);
                runtime_verified =
                    start_status == 0 && nfqws_running_installed_image();
            }
            // Only what was captured came back. Files the newer package added
            // are still there, and saying so is the difference between a
            // restore and a claim of one.
            output +=
                "Files added by the newer package were not removed; this "
                "restores the captured bytes, not the exact former state.\n";
            const bool files_restored =
                restored.complete && runtime_verified;
            // A captured-file restore is intentionally not an opkg
            // transaction: it neither rewinds the package database nor
            // removes paths introduced after the capture. Even when every
            // captured byte and the runtime are verified, clearing this
            // journal would make GET/check_update trust a newer opkg version
            // for an older restored binary and could turn the next upgrade
            // into a false no-op. Keep an explicit degraded state until a
            // real package-manager repair reconciles both worlds.
            const auto finalization =
                finalize_captured_file_restore(files_restored);
            const bool journal_cleared = finalization.clear_journal;
            if (files_restored) {
                output +=
                    "The captured bytes and runtime were restored, but opkg "
                    "metadata remains unverified. The transaction record was "
                    "kept and web upgrades remain blocked until manual package "
                    "repair.\n";
            } else {
                output +=
                    "The transaction record was kept because restoration or "
                    "runtime verification did not finish exactly; the next "
                    "package operation will refuse.\n";
            }
            const bool ok = finalization.ok;
            progress.finish(finalization.terminal_state);
            const bool firewall_reconcile_pending =
                refresh_guard.request_now();
            return nlohmann::json{{"ok", ok},
                                  {"output", output},
                                  {"restored", restored.restored},
                                  {"failed", restored.failed.size()},
                                  {"runtime_verified", runtime_verified},
                                  {"journal_retained", !journal_cleared},
                                  {"package_metadata_verified",
                                   finalization.package_metadata_verified},
                                  {"files_restored", files_restored},
                                  {"exact_package_state", false},
                                  {"firewall_reconcile_pending",
                                   firewall_reconcile_pending}}
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

            NfqwsNetfilterRefreshGuard refresh_guard(ctx);
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
            const bool firewall_reconcile_pending =
                refresh_guard.request_now();
            return nlohmann::json{{"ok", status == 0},
                                  {"output", output},
                                  {"status", status},
                                  {"durable", durable},
                                  {"warning", durable
                                                  ? ""
                                                  : kDurabilityWarning},
                                  {"installed_blobs", assets.installed},
                                  {"preserved_blobs", assets.preserved},
                                  {"firewall_reconcile_pending",
                                   firewall_reconcile_pending}}
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
            const bool restart_requested = request.value("restart", false);
            NfqwsNetfilterRefreshGuard refresh_guard(
                ctx, restart_requested);
            if (restart_requested) {
                output += run_nfqws_service_command("restart", status);
            }
            append_durability_warning(output, durable);
            const bool firewall_reconcile_pending =
                restart_requested
                    ? refresh_guard.request_now()
                    : false;
            return nlohmann::json{{"ok", status == 0}, {"output", output}, {"status", status},
                                  {"saved", pending.size()},
                                  {"durable", durable},
                                  {"warning", durable ? "" : kDurabilityWarning},
                                  {"firewall_reconcile_pending",
                                   firewall_reconcile_pending}}.dump();
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
            const auto active_config = fs::path(kConfigDir) / "nfqws2.conf";
            const bool replaces_active_config = std::any_of(
                pending.begin(), pending.end(),
                [&active_config](const PendingFile& item) {
                    return item.path == active_config;
                });
            // Import, like save_file, can replace the active durable config
            // without restarting nfqws2. Reconcile the existing control-loop
            // owner so a file/cmdline mismatch removes a stale PPE graph.
            NfqwsNetfilterRefreshGuard refresh_guard(
                ctx, replaces_active_config);
            bool durable = true;
            for (const auto& item : pending) {
                merge_durability(
                    durable, save_nfqws_file(item.path, item.content));
            }
            auto response = successful_write_response(durable);
            response["firewall_reconcile_pending"] =
                replaces_active_config ? refresh_guard.request_now() : false;
            return response.dump();
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
NfqwsBootRecoveryResult run_nfqws_boot_recovery_for_testing(
    const NfqwsBootRecoveryHooks& hooks) {
    return run_nfqws_boot_recovery_with(hooks);
}

NfqwsPostUpgradeFootprintAssessment
assess_nfqws_post_upgrade_footprint_for_testing(
    const PackageFootprint& before,
    std::function<PackageFootprint()> observe_after) {
    const auto assessment =
        assess_post_upgrade_footprint(before, observe_after);
    return NfqwsPostUpgradeFootprintAssessment{
        assessment.footprint,
        assessment.diff,
        assessment.binary_outcome,
        assessment.recovery_required,
        assessment.error,
    };
}

NfqwsBoundedOpkgTestResult run_nfqws_bounded_opkg_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts,
        const std::filesystem::path&)> execute,
    const std::string& installed_version,
    const std::string& store_root,
    const std::string& feed_list,
    const ScriptedInstallPaths& scripted,
    std::function<bool(std::string&)> stop_service) {
    NfqwsPackagePaths paths;
    paths.store_root = store_root;
    paths.feed_list = feed_list;
    paths.scripted = scripted;
    const auto result = run_bounded_nfqws_opkg_upgrade(
        execute, installed_version, paths, {}, stop_service);
    return NfqwsBoundedOpkgTestResult{
        result.output,
        result.status,
        result.timed_out,
        result.termination_uncertain,
        result.upgrade_started,
        result.up_to_date,
        result.previous_exact,
        result.target_version,
        result.scripted,
        result.scripted_ok,
        result.init_restored,
    };
}

NfqwsInstallTestResult run_nfqws_install_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts,
        const std::filesystem::path&)> execute,
    const std::string& store_root,
    const std::string& feed_list,
    const std::string& feed_conf,
    std::function<bool(const std::string& target_version)> on_prepared,
    const ScriptedInstallPaths& scripted) {
    NfqwsPackagePaths paths;
    paths.store_root = store_root;
    paths.feed_list = feed_list;
    paths.scripted = scripted;
    NfqwsPreparedHook hook;
    if (on_prepared) {
        hook = [&on_prepared](const BoundedOpkgUpgradeResult& prepared) {
            return on_prepared(prepared.target_version);
        };
    }
    const auto result =
        run_bounded_nfqws_opkg_install(execute, paths, feed_conf, hook);
    return NfqwsInstallTestResult{
        result.output,
        result.status,
        result.timed_out,
        result.termination_uncertain,
        result.install_started,
        result.target_version,
        result.feed_conf_written,
        result.scripted,
        result.scripted_ok,
        result.init_restored,
    };
}

bool reinstall_exact_previous_nfqws_package_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts,
        const std::filesystem::path&)> execute,
    const std::string& expected_version,
    std::function<std::string()> read_installed_version,
    const std::string& store_root,
    std::string& output,
    const ScriptedInstallPaths& scripted) {
    NfqwsPackagePaths paths;
    paths.store_root = store_root;
    paths.scripted = scripted;
    return reinstall_exact_previous_nfqws_package(
        expected_version, read_installed_version, output, execute, paths);
}

NfqwsPostMutationGuardTestResult guard_nfqws_post_mutation_for_testing(
    std::function<bool()> operation,
    std::function<bool()> recover,
    bool recovery_allowed) {
    const auto result =
        guard_nfqws_post_mutation(
            operation,
            recover,
            [recovery_allowed] { return recovery_allowed; });
    return NfqwsPostMutationGuardTestResult{
        result.operation_completed,
        result.component_broken,
        result.recovery_attempted,
        result.rolled_back,
        result.operation_error,
        result.recovery_error,
    };
}

bool should_clear_nfqws_upgrade_journal_for_testing(
    bool component_broken,
    bool package_mutation_started,
    bool rolled_back,
    bool termination_uncertain,
    bool exact_rollback_verified) {
    return should_clear_nfqws_upgrade_journal(
        component_broken,
        package_mutation_started,
        rolled_back,
        termination_uncertain,
        exact_rollback_verified);
}

bool nfqws_package_metadata_verified_for_testing(
    bool transaction_present) {
    return nfqws_package_metadata_verified(
        transaction_present ? ComponentTransactionState::abandoned
                            : ComponentTransactionState::none);
}

NfqwsCapturedRestoreFinalizationTestResult
finalize_nfqws_captured_file_restore_for_testing(bool files_restored) {
    const auto finalization =
        finalize_captured_file_restore(files_restored);
    return NfqwsCapturedRestoreFinalizationTestResult{
        finalization.ok,
        finalization.clear_journal,
        finalization.package_metadata_verified,
        finalization.terminal_state,
    };
}

bool nfqws_optimistic_publish_survives_mutation_for_testing(
    bool mutation_between_reads) {
    const auto before_generation =
        nfqws_transaction_generation().load(std::memory_order_acquire);
    NfqwsTransactionSnapshot initial{
        before_generation, ComponentTransactionStatus{}, true};
    if (mutation_between_reads) {
        // Each production mutation opens and closes this same two-step
        // generation. Advancing by one completed mutation models a journal
        // that appeared and disappeared between two otherwise-clean reads,
        // without writing the fixed /opt test path.
        nfqws_transaction_generation().fetch_add(
            2, std::memory_order_acq_rel);
    }
    NfqwsTransactionSnapshot current{
        nfqws_transaction_generation().load(std::memory_order_acquire),
        ComponentTransactionStatus{},
        true};
    return nfqws_snapshot_allows_optimistic_publish(initial, current);
}

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
