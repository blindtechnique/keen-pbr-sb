#ifdef WITH_API

#include "handler_remote_access.hpp"

#include "../config/config_writer.hpp"
#include "../log/logger.hpp"
#include "../util/network_routes.hpp"
#include "../util/safe_exec.hpp"

#include <cstdlib>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr const char* kSettingsPath = "/opt/etc/keen-pbr/remote-access.json";
constexpr const char* kAuthPath = "/opt/etc/keen-pbr/auth.json";
constexpr const char* kChain = "KeenPbrRemote";
// The panel itself always listens here; a different external port is published
// with a REDIRECT rather than by moving the listener.
constexpr int kInternalPort = 12121;
constexpr int kDefaultPort = 12121;
constexpr unsigned int kReconcileAttempts = 3U;
constexpr unsigned int kMaximumDuplicateRules = 16U;

std::mutex& settings_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::string settings_path() {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured =
            std::getenv("KEEN_PBR_TEST_REMOTE_SETTINGS_FILE")) {
        if (*configured != '\0') return configured;
    }
#endif
    return kSettingsPath;
}

std::string auth_path() {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured =
            std::getenv("KEEN_PBR_TEST_REMOTE_AUTH_FILE")) {
        if (*configured != '\0') return configured;
    }
#endif
    return kAuthPath;
}

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return {};
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

nlohmann::json load_settings() {
    nlohmann::json settings;
    settings["enabled"] = false;
    settings["port"] = kDefaultPort;

    try {
        const auto raw = read_file(settings_path());
        if (raw.empty()) return settings;
        const auto stored = nlohmann::json::parse(raw);
        if (stored.contains("enabled") && stored["enabled"].is_boolean()) {
            settings["enabled"] = stored["enabled"].get<bool>();
        }
        if (stored.contains("port") && stored["port"].is_number_integer()) {
            settings["port"] = stored["port"].get<int>();
        }
    } catch (const std::exception&) {
        // A damaged file must not leave the panel exposed: fall back to closed.
    }
    return settings;
}

// Returns false only when rename(2) published the new settings but the
// directory fsync failed. In that case callers must still reconcile runtime
// state with the visible file; reporting a plain write failure would leave the
// firewall and the authoritative settings out of sync until restart.
bool save_settings(const nlohmann::json& settings) {
    bool committed = false;
    AtomicFileWriteOptions options;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    options.committed_result = &committed;
    try {
        write_file_atomically(
            settings_path(), settings.dump(2) + "\n", options);
        return true;
    } catch (const AtomicFileWriteError& error) {
        if (!committed && !error.committed()) throw;
        Logger::instance().warn(
            "Remote-access settings were published but directory sync "
            "failed: {}",
            error.what());
        return false;
    }
}

#ifdef KEEN_PBR3_TESTING
RemoteAccessCommandRunner& command_runner_for_testing() {
    static RemoteAccessCommandRunner runner;
    return runner;
}
#endif

int run_command(const std::vector<std::string>& command) {
#ifdef KEEN_PBR3_TESTING
    if (command_runner_for_testing()) {
        return command_runner_for_testing()(command);
    }
#endif
    return safe_exec(command, true);
}

std::string primary_wan_interface() {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured = std::getenv("KEEN_PBR_TEST_REMOTE_WAN")) {
        if (*configured != '\0') return configured;
    }
#endif
    return primary_default_route_interface();
}

// Login must be on before anything is published. Reading auth.json directly
// keeps this independent of whichever provider is configured.
bool login_required() {
    try {
        const auto raw = read_file(auth_path());
        if (raw.empty()) return false;
        const auto parsed = nlohmann::json::parse(raw);
        return parsed.value("enabled", false);
    } catch (const std::exception&) {
        return false;
    }
}

// True when the kernel actually has an interface by this name.
//
// iptables accepts "-i" for names that do not exist, on the assumption the
// interface will appear later. That turned a wrong name into a rule which is
// present, looks right in -S output, and never matches anything.
bool kernel_interface_exists(const std::string& name) {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured = std::getenv("KEEN_PBR_TEST_REMOTE_WAN")) {
        if (*configured != '\0' && name == configured) return true;
    }
#endif
    std::ifstream dev("/proc/net/dev");
    if (!dev.is_open()) {
        return true; // Cannot check; do not block on our own inability to tell.
    }
    std::string line;
    while (std::getline(dev, line)) {
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const auto begin = line.find_first_not_of(" \t");
        if (begin == std::string::npos || begin >= colon) {
            continue;
        }
        if (line.substr(begin, colon - begin) == name) {
            return true;
        }
    }
    return false;
}

enum class RuleState { present, absent, unknown };

std::vector<std::string> iptables_command(
    const std::string& table,
    std::vector<std::string> arguments) {
    std::vector<std::string> command{"iptables"};
    if (!table.empty()) {
        command.push_back("-t");
        command.push_back(table);
    }
    command.insert(
        command.end(), arguments.begin(), arguments.end());
    return command;
}

RuleState inspect_rule(const std::string& table,
                       const std::string& chain,
                       const std::vector<std::string>& rule) {
    std::vector<std::string> arguments{"-C", chain};
    arguments.insert(arguments.end(), rule.begin(), rule.end());
    const int status = run_command(
        iptables_command(table, std::move(arguments)));
    if (status == 0) return RuleState::present;
    if (status == 1) return RuleState::absent;
    return RuleState::unknown;
}

RuleState inspect_chain(const std::string& table) {
    const int status = run_command(
        iptables_command(table, {"-S", kChain}));
    if (status == 0) return RuleState::present;
    if (status == 1) return RuleState::absent;
    return RuleState::unknown;
}

bool delete_all_matching_rules(
    const std::string& table,
    const std::string& chain,
    const std::vector<std::string>& rule) {
    for (unsigned int duplicate = 0;
         duplicate < kMaximumDuplicateRules;
         ++duplicate) {
        const auto state = inspect_rule(table, chain, rule);
        if (state == RuleState::absent) return true;
        if (state == RuleState::unknown) return false;

        std::vector<std::string> arguments{"-D", chain};
        arguments.insert(arguments.end(), rule.begin(), rule.end());
        if (run_command(
                iptables_command(table, std::move(arguments))) != 0) {
            return false;
        }
    }
    return inspect_rule(table, chain, rule) == RuleState::absent;
}

bool remove_chain(const std::string& table,
                  const std::string& parent_chain) {
    const auto initial_state = inspect_chain(table);
    if (initial_state == RuleState::absent) return true;
    if (initial_state == RuleState::unknown) return false;

    const std::vector<std::string> jump{"-j", kChain};
    bool success = delete_all_matching_rules(
        table, parent_chain, jump);
    if (run_command(
            iptables_command(table, {"-F", kChain})) != 0) {
        success = false;
    }
    if (run_command(
            iptables_command(table, {"-X", kChain})) != 0) {
        success = false;
    }

    // A deleted user chain cannot still be referenced by a parent rule, so
    // proving the chain absent also proves all jumps to it are gone without
    // asking iptables to resolve a now-nonexistent target.
    return success && inspect_chain(table) == RuleState::absent;
}

bool remove_rules_once() {
    // Attempt both tables even if the first one is damaged. Leaving the NAT
    // half behind after the filter half fails is not a safe disabled state.
    const bool filter_removed = remove_chain({}, "INPUT");
    const bool nat_removed = remove_chain("nat", "PREROUTING");
    return filter_removed && nat_removed;
}

bool remove_rules_with_retry() {
    for (unsigned int attempt = 0; attempt < kReconcileAttempts; ++attempt) {
        if (remove_rules_once()) return true;
    }
    return false;
}

bool run_required(const std::string& table,
                  std::vector<std::string> arguments) {
    return run_command(
               iptables_command(table, std::move(arguments))) == 0;
}

bool install_rules_once(const std::string& wan, int port) {
    if (!remove_rules_once()) return false;

    const auto internal_port = std::to_string(kInternalPort);
    const auto external_port = std::to_string(port);
    const std::vector<std::string> input_jump{"-j", kChain};
    const std::vector<std::string> internal_accept{
        "-i", wan, "-p", "tcp", "--dport", internal_port,
        "-j", "ACCEPT"};

    if (!run_required({}, {"-N", kChain}) ||
        !run_required({}, {"-I", "INPUT", "1", "-j", kChain}) ||
        !run_required({}, {"-A", kChain, "-i", wan, "-p", "tcp",
                           "--dport", internal_port, "-j", "ACCEPT"})) {
        return false;
    }

    if (port != kInternalPort) {
        if (!run_required("nat", {"-N", kChain}) ||
            !run_required(
                "nat", {"-I", "PREROUTING", "1", "-j", kChain}) ||
            !run_required(
                "nat", {"-A", kChain, "-i", wan, "-p", "tcp",
                         "--dport", external_port, "-j", "REDIRECT",
                         "--to-ports", internal_port}) ||
            !run_required(
                {}, {"-A", kChain, "-i", wan, "-p", "tcp",
                     "--dport", external_port, "-j", "ACCEPT"})) {
            return false;
        }
    }

    if (inspect_chain({}) != RuleState::present ||
        inspect_rule({}, "INPUT", input_jump) != RuleState::present ||
        inspect_rule({}, kChain, internal_accept) != RuleState::present) {
        return false;
    }

    if (port == kInternalPort) {
        return inspect_chain("nat") == RuleState::absent;
    }

    const std::vector<std::string> external_accept{
        "-i", wan, "-p", "tcp", "--dport", external_port,
        "-j", "ACCEPT"};
    const std::vector<std::string> redirect{
        "-i", wan, "-p", "tcp", "--dport", external_port,
        "-j", "REDIRECT", "--to-ports", internal_port};
    return inspect_chain("nat") == RuleState::present &&
           inspect_rule("nat", "PREROUTING", input_jump) ==
               RuleState::present &&
           inspect_rule("nat", kChain, redirect) == RuleState::present &&
           inspect_rule({}, kChain, external_accept) == RuleState::present;
}

bool install_rules_with_retry(const std::string& wan, int port) {
    for (unsigned int attempt = 0; attempt < kReconcileAttempts; ++attempt) {
        if (install_rules_once(wan, port)) return true;
    }
    return false;
}

RemoteAccessApplyResult close_with_error(std::string error) {
    if (!remove_rules_with_retry()) {
        error +=
            "; the closed firewall state could not be verified after bounded retries";
    }
    return {false, std::move(error)};
}

RemoteAccessApplyResult reconcile_remote_access_rules_locked(
    const nlohmann::json& settings,
    const std::string& listen_address) {
    if (!settings.value("enabled", false)) {
        if (remove_rules_with_retry()) return {true, {}};
        return {
            false,
            "remote access is disabled, but owned firewall rules could not "
            "be removed and verified",
        };
    }
    if (!login_required()) {
        return close_with_error(
            "remote access requires web-interface authentication");
    }
    if (!listen_address_is_reachable(listen_address)) {
        return close_with_error(
            "the panel listener is loopback-only and cannot accept remote access");
    }

    const auto wan = primary_wan_interface();
    if (wan.empty()) {
        return close_with_error(
            "no default-route interface is available for remote access");
    }
    if (!kernel_interface_exists(wan)) {
        return close_with_error(
            "the default-route interface '" + wan +
            "' is not a live kernel interface");
    }

    const int port = settings.value("port", kDefaultPort);
    if (port < 1 || port > 65535) {
        return close_with_error(
            "the stored remote-access port is outside 1..65535");
    }
    if (!install_rules_with_retry(wan, port)) {
        return close_with_error(
            "remote-access firewall rules could not be installed and verified");
    }

    Logger::instance().info(
        "Remote access is OPEN: the web interface is reachable from the internet on {}:{}",
        wan,
        port);
    return {true, {}};
}

} // namespace

bool listen_address_is_reachable(const std::string& listen_address) {
    if (listen_address.empty()) {
        // Nothing to check against; assume the caller knows better than we do.
        return true;
    }
    const auto colon = listen_address.rfind(':');
    const auto host = colon == std::string::npos ? listen_address
                                                 : listen_address.substr(0, colon);
    return host != "127.0.0.1" && host != "localhost" && host != "::1";
}

RemoteAccessApplyResult apply_remote_access_rules(
    const std::string& listen_address) {
    const std::lock_guard<std::mutex> lock(settings_mutex());
    const auto result = reconcile_remote_access_rules_locked(
        load_settings(), listen_address);
    if (!result.applied) {
        Logger::instance().error(
            "Cannot reconcile remote-access firewall state: {}",
            result.error);
    }
    return result;
}

bool remove_remote_access_rules() {
    const std::lock_guard<std::mutex> lock(settings_mutex());
    if (remove_rules_with_retry()) return true;
    Logger::instance().error(
        "Cannot remove and verify remote-access firewall rules");
    return false;
}

void register_remote_access_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/system/remote-access", [&ctx]() -> std::string {
        const auto config = ctx.get_visible_config();
        const auto listen = config.api.has_value()
                                ? config.api->listen.value_or(std::string{})
                                : std::string{};

        std::lock_guard<std::mutex> lock(settings_mutex());
        auto settings = load_settings();
        settings["login_required"] = login_required();
        settings["internal_port"] = kInternalPort;
        settings["listen"] = listen;
        settings["listen_reachable"] = listen_address_is_reachable(listen);
        return settings.dump();
    });

    server.post("/api/system/remote-access", [&ctx](const std::string& body) -> std::string {
        nlohmann::json response;
        try {
            const auto request = nlohmann::json::parse(body);
            const bool enabled = request.value("enabled", false);
            const int port = request.value("port", kDefaultPort);

            if (port < 1 || port > 65535) {
                response["error"] = "port must be between 1 and 65535";
                return response.dump();
            }

            const auto config = ctx.get_visible_config();
            const auto listen = config.api.has_value()
                                    ? config.api->listen.value_or(std::string{})
                                    : std::string{};
            // Persisting the desired state and reconciling the firewall form
            // one local transaction. A concurrent request must not overwrite
            // the file between this request's save and its runtime apply.
            const std::lock_guard<std::mutex> lock(settings_mutex());
            // Refusing here rather than warning later: the whole point of the
            // check is that the panel never reaches the internet unprotected.
            if (enabled && !login_required()) {
                response["error"] = "login_disabled";
                return response.dump();
            }
            if (enabled && !listen_address_is_reachable(listen)) {
                response["error"] = "listen_loopback";
                response["listen"] = listen;
                return response.dump();
            }

            nlohmann::json settings;
            settings["enabled"] = enabled;
            settings["port"] = port;
            bool settings_durable = false;
            try {
                settings_durable = save_settings(settings);
            } catch (const std::exception& error) {
                Logger::instance().error(
                    "Cannot write remote-access.json atomically: {}",
                    error.what());
                response["error"] = "cannot write remote-access.json";
                return response.dump();
            }

            const auto apply_result =
                reconcile_remote_access_rules_locked(settings, listen);
            if (!apply_result.applied) {
                Logger::instance().error(
                    "Remote-access settings were saved, but the firewall "
                    "state was not applied: {}",
                    apply_result.error);
                response["error"] =
                    "cannot apply remote-access firewall rules";
                response["detail"] = apply_result.error;
                response["degraded"] = true;
                response["durable"] = settings_durable;
                response["settings"] = settings;
                return response.dump();
            }
            response["ok"] = true;
            response["durable"] = settings_durable;
            if (!settings_durable) {
                response["warning"] =
                    "remote-access settings are visible but directory "
                    "durability could not be confirmed";
            }
            response["settings"] = settings;
        } catch (const std::exception& e) {
            response["error"] = e.what();
        }
        return response.dump();
    });
}

#ifdef KEEN_PBR3_TESTING
void set_remote_access_command_runner_for_testing(
    RemoteAccessCommandRunner runner) {
    const std::lock_guard<std::mutex> lock(settings_mutex());
    command_runner_for_testing() = std::move(runner);
}

void reset_remote_access_command_runner_for_testing() {
    const std::lock_guard<std::mutex> lock(settings_mutex());
    command_runner_for_testing() = {};
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
