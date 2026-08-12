#ifdef WITH_API

#include "handler_remote_access.hpp"

#include "../config/config_writer.hpp"
#include "../log/logger.hpp"
#include "../util/network_routes.hpp"
#include "../util/safe_exec.hpp"

#include <cstdlib>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr const char* kSettingsPath = "/opt/etc/keen-pbr/remote-access.json";
constexpr const char* kAuthPath = "/opt/etc/keen-pbr/auth.json";
constexpr const char* kChain = "KeenPbrRemote";
// The panel itself listens here. A different external port cannot be offered
// safely with a plain REDIRECT: INPUT sees the translated destination, so a
// rule accepting the translated packet also accepts direct WAN :12121. Until
// original-destination matching is capability-probed and verified, only the
// actual listener port is admissible.
constexpr int kInternalPort = 12121;
constexpr int kDefaultPort = 12121;
constexpr unsigned int kMaximumDuplicateRules = 16U;
// A reconcile attempt contains several commands. A long wait on every command
// would block the control loop for tens of seconds during an NDM storm; one
// second is enough to absorb ordinary lock hand-off and the coordinator owns
// the longer recovery backoff.
constexpr int kXtablesWaitSeconds = 1;
constexpr SafeExecTimeouts kRemoteCommandTimeouts{
    std::chrono::seconds{2},
    std::chrono::milliseconds{500},
};
constexpr std::array<std::chrono::milliseconds, 6> kRetryDelays{
    std::chrono::seconds{1},
    std::chrono::seconds{2},
    std::chrono::seconds{4},
    std::chrono::seconds{8},
    std::chrono::seconds{15},
    std::chrono::seconds{30},
};
constexpr auto kMaintenanceRetryDelay = std::chrono::seconds{60};

struct DesiredRemoteAccessState {
    bool enabled{false};
    int port{kDefaultPort};
    std::string listen_address;
};

struct ReconcileCommandContext {
    RemoteAccessReconcilePhase phase{RemoteAccessReconcilePhase::idle};
    int exit_code{0};
};

struct ReconcileAttemptOutcome {
    bool success{false};
    bool transient{false};
    RemoteAccessRuntimeState success_state{RemoteAccessRuntimeState::closed};
    std::string interface;
    RemoteAccessReconcilePhase phase{RemoteAccessReconcilePhase::idle};
    int exit_code{0};
    std::string error;
};

enum class IncidentNotificationKind {
    none,
    raised,
    cleared,
};

struct RemoteAccessCoordinator {
    std::mutex mutex;
    RemoteAccessRuntimeStatus status;
    std::uint64_t next_generation{0};
    bool in_flight{false};
    bool rerun_requested{false};
    std::uint64_t next_incident_notification_token{0};
    std::uint64_t pending_incident_notification_token{0};
    std::uint64_t pending_incident_notification_generation{0};
    IncidentNotificationKind pending_incident_notification_kind{
        IncidentNotificationKind::none};
    bool incident_announced{false};
};

RemoteAccessCoordinator& coordinator() {
    static RemoteAccessCoordinator value;
    return value;
}

bool runtime_status_is_verified_closed(
    const RemoteAccessRuntimeStatus& status) noexcept {
    return status.desired_generation != 0U &&
           status.applied_generation == status.desired_generation &&
           !status.desired_enabled &&
           status.state == RemoteAccessRuntimeState::closed;
}

std::mutex& incident_publication_mutex() {
    static std::mutex mutex;
    return mutex;
}

#ifdef KEEN_PBR3_TESTING
std::mutex& incident_publish_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

RemoteAccessIncidentPublishHook& incident_publish_hook_for_testing() {
    static RemoteAccessIncidentPublishHook hook;
    return hook;
}

std::mutex& desired_admission_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

RemoteAccessDesiredAdmissionHook& desired_admission_hook_for_testing() {
    static RemoteAccessDesiredAdmissionHook hook;
    return hook;
}

std::mutex& security_fence_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

RemoteAccessSecurityFenceHook& security_fence_hook_for_testing() {
    static RemoteAccessSecurityFenceHook hook;
    return hook;
}

void invoke_security_fence_hook_for_testing(
    RemoteAccessSecurityFenceStage stage) {
    RemoteAccessSecurityFenceHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            security_fence_hook_mutex());
        hook = security_fence_hook_for_testing();
    }
    if (hook) hook(stage);
}
#endif

struct RetrySchedulerRegistration {
    std::mutex invocation_mutex;
    std::atomic<bool> active{true};
    // A registration replaced by a new scheduler forwards an already-captured
    // hint to the replacement. A registration fenced for shutdown drops it.
    std::atomic<bool> redispatch_when_inactive{false};
    RemoteAccessRetryScheduler callback;
};

struct RetrySchedulerRegistry {
    std::mutex mutex;
    std::shared_ptr<RetrySchedulerRegistration> registration;
    std::optional<RemoteAccessRetryHint> pending;
};

RetrySchedulerRegistry& retry_scheduler_registry() {
    static RetrySchedulerRegistry value;
    return value;
}

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
    // The reconciler and HTTP middleware must read the same production auth
    // authority. The test-only override remains first so isolated firewall
    // tests never depend on a process-wide middleware fixture.
    if (const char* configured = std::getenv("KEEN_PBR_AUTH_FILE")) {
        if (*configured != '\0') return configured;
    }
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

int run_command(
    const std::vector<std::string>& command,
    SafeExecFailureLog failure_log =
        SafeExecFailureLog::DiagnosticOnly) {
#ifdef KEEN_PBR3_TESTING
    if (command_runner_for_testing()) {
        return command_runner_for_testing()(command);
    }
#endif
    return safe_exec_with_timeouts(
        command,
        /*suppress_output=*/true,
        kRemoteCommandTimeouts,
        {},
        failure_log);
}

std::mutex& remote_access_security_boundary_mutex() {
    static std::mutex mutex;
    return mutex;
}

enum class XtablesWaitMode { unknown, timeout, flag, none };

std::mutex& xtables_wait_mutex() {
    static std::mutex mutex;
    return mutex;
}

XtablesWaitMode& xtables_wait_mode_storage() {
    static XtablesWaitMode mode{XtablesWaitMode::unknown};
    return mode;
}

XtablesWaitMode detect_xtables_wait_mode(
    ReconcileCommandContext& context,
    SafeExecFailureLog failure_log =
        SafeExecFailureLog::DiagnosticOnly) {
    std::lock_guard<std::mutex> lock(xtables_wait_mutex());
    auto& cached = xtables_wait_mode_storage();
    if (cached != XtablesWaitMode::unknown) return cached;

#ifdef KEEN_PBR3_TESTING
    if (const char* configured =
            std::getenv("KEEN_PBR_TEST_REMOTE_XTABLES_WAIT")) {
        const std::string value(configured);
        if (value == "timeout") return cached = XtablesWaitMode::timeout;
        if (value == "flag") return cached = XtablesWaitMode::flag;
        if (value == "none") return cached = XtablesWaitMode::none;
    }
#endif

    context.phase = RemoteAccessReconcilePhase::detect_xtables_wait;
    const int timeout_status = run_command(
        {"iptables", "-w", std::to_string(kXtablesWaitSeconds),
         "-S", "INPUT"},
        failure_log);
    if (timeout_status == 0 || timeout_status == 1) {
        return cached = XtablesWaitMode::timeout;
    }
    // Exit 2 is the legacy iptables syntax-error result. Operational failures
    // (including lock timeout/exec failure) must be retried rather than used
    // as authority to silently downgrade locking.
    if (timeout_status != 2) {
        context.exit_code = timeout_status;
        return XtablesWaitMode::unknown;
    }

    const int flag_status =
        run_command(
            {"iptables", "-w", "-S", "INPUT"}, failure_log);
    if (flag_status == 0 || flag_status == 1) {
        return cached = XtablesWaitMode::flag;
    }
    if (flag_status != 2) {
        context.exit_code = flag_status;
        return XtablesWaitMode::unknown;
    }
    return cached = XtablesWaitMode::none;
}

std::string primary_wan_interface() {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured = std::getenv("KEEN_PBR_TEST_REMOTE_WAN")) {
        if (*configured != '\0') return configured;
    }
#endif
    return primary_default_route_interface();
}

struct RemoteAuthState {
    bool readable{false};
    bool enabled{false};
    std::string provider{"local"};
};

// Reading auth.json directly keeps firewall admission on the same durable
// authority as the middleware, including during daemon startup.
RemoteAuthState load_remote_auth_state() {
    RemoteAuthState state;
    try {
        const auto raw = read_file(auth_path());
        if (raw.empty()) return state;
        const auto parsed = nlohmann::json::parse(raw);
        if (!parsed.is_object() || !parsed.contains("enabled") ||
            !parsed["enabled"].is_boolean()) {
            return state;
        }
        state.enabled = parsed["enabled"].get<bool>();
        state.provider = parsed.value("provider", std::string{"local"});
        if (state.provider != "local" && state.provider != "keenetic") {
            return RemoteAuthState{};
        }
        state.readable = true;
        return state;
    } catch (const std::exception&) {
        return state;
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
    std::vector<std::string> arguments,
    XtablesWaitMode wait_mode) {
    std::vector<std::string> command{"iptables"};
    if (wait_mode == XtablesWaitMode::timeout) {
        command.push_back("-w");
        command.push_back(std::to_string(kXtablesWaitSeconds));
    } else if (wait_mode == XtablesWaitMode::flag) {
        command.push_back("-w");
    }
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
                       const std::vector<std::string>& rule,
                       XtablesWaitMode wait_mode,
                       ReconcileCommandContext& context,
                       RemoteAccessReconcilePhase phase,
                       SafeExecFailureLog failure_log =
                           SafeExecFailureLog::DiagnosticOnly) {
    std::vector<std::string> arguments{"-C", chain};
    arguments.insert(arguments.end(), rule.begin(), rule.end());
    context.phase = phase;
    const int status = run_command(iptables_command(
        table, std::move(arguments), wait_mode), failure_log);
    context.exit_code = status;
    if (status == 0) return RuleState::present;
    if (status == 1) return RuleState::absent;
    return RuleState::unknown;
}

RuleState inspect_chain(const std::string& table,
                        XtablesWaitMode wait_mode,
                        ReconcileCommandContext& context,
                        RemoteAccessReconcilePhase phase,
                        SafeExecFailureLog failure_log =
                            SafeExecFailureLog::DiagnosticOnly) {
    context.phase = phase;
    const int status = run_command(iptables_command(
        table, {"-S", kChain}, wait_mode), failure_log);
    context.exit_code = status;
    if (status == 0) return RuleState::present;
    if (status == 1) return RuleState::absent;
    return RuleState::unknown;
}

bool delete_all_matching_rules(
    const std::string& table,
    const std::string& chain,
    const std::vector<std::string>& rule,
    XtablesWaitMode wait_mode,
    ReconcileCommandContext& context,
    RemoteAccessReconcilePhase phase,
    SafeExecFailureLog failure_log) {
    for (unsigned int duplicate = 0;
         duplicate < kMaximumDuplicateRules;
         ++duplicate) {
        const auto state = inspect_rule(
            table, chain, rule, wait_mode, context, phase, failure_log);
        if (state == RuleState::absent) return true;
        if (state == RuleState::unknown) return false;

        std::vector<std::string> arguments{"-D", chain};
        arguments.insert(arguments.end(), rule.begin(), rule.end());
        context.phase = phase;
        context.exit_code = run_command(iptables_command(
            table, std::move(arguments), wait_mode), failure_log);
        if (context.exit_code != 0) {
            return false;
        }
    }
    return inspect_rule(
               table, chain, rule, wait_mode, context, phase,
               failure_log) ==
           RuleState::absent;
}

bool remove_chain(const std::string& table,
                  const std::string& parent_chain,
                  XtablesWaitMode wait_mode,
                  ReconcileCommandContext& context,
                  RemoteAccessReconcilePhase phase,
                  SafeExecFailureLog failure_log) {
    const auto initial_state = inspect_chain(
        table, wait_mode, context, phase, failure_log);
    if (initial_state == RuleState::absent) return true;
    if (initial_state == RuleState::unknown) return false;

    const std::vector<std::string> jump{"-j", kChain};
    bool success = delete_all_matching_rules(
        table, parent_chain, jump, wait_mode, context, phase,
        failure_log);
    auto first_failure = context;
    context.phase = phase;
    context.exit_code = run_command(iptables_command(
        table, {"-F", kChain}, wait_mode), failure_log);
    if (context.exit_code != 0) {
        if (success) first_failure = context;
        success = false;
    }
    context.exit_code = run_command(iptables_command(
        table, {"-X", kChain}, wait_mode), failure_log);
    if (context.exit_code != 0) {
        if (success) first_failure = context;
        success = false;
    }

    if (!success) {
        context = first_failure;
        return false;
    }

    // A deleted user chain cannot still be referenced by a parent rule, so
    // proving the chain absent also proves all jumps to it are gone without
    // asking iptables to resolve a now-nonexistent target.
    return success &&
           inspect_chain(
               table, wait_mode, context, phase, failure_log) ==
               RuleState::absent;
}

bool remove_rules_once(XtablesWaitMode wait_mode,
                       ReconcileCommandContext& context,
                       SafeExecFailureLog failure_log =
                           SafeExecFailureLog::DiagnosticOnly) {
    // Attempt both tables even if the first one is damaged. Leaving the NAT
    // half behind after the filter half fails is not a safe disabled state.
    const bool filter_removed = remove_chain(
        {}, "INPUT", wait_mode, context,
        RemoteAccessReconcilePhase::remove_filter, failure_log);
    const auto filter_context = context;
    const bool nat_removed = remove_chain(
        "nat", "PREROUTING", wait_mode, context,
        RemoteAccessReconcilePhase::remove_nat, failure_log);
    const auto nat_context = context;
    if (!filter_removed) context = filter_context;
    else if (!nat_removed) context = nat_context;
    return filter_removed && nat_removed;
}

bool run_required(const std::string& table,
                  std::vector<std::string> arguments,
                  XtablesWaitMode wait_mode,
                  ReconcileCommandContext& context,
                  RemoteAccessReconcilePhase phase) {
    context.phase = phase;
    context.exit_code = run_command(iptables_command(
        table, std::move(arguments), wait_mode));
    return context.exit_code == 0;
}

bool install_rules_once(const std::string& wan,
                        int port,
                        XtablesWaitMode wait_mode,
                        ReconcileCommandContext& context) {
    if (!remove_rules_once(wait_mode, context)) return false;
    if (port != kInternalPort) return false;

    const auto internal_port = std::to_string(kInternalPort);
    const std::vector<std::string> input_jump{"-j", kChain};
    const std::vector<std::string> internal_accept{
        "-i", wan, "-p", "tcp", "--dport", internal_port,
        "-j", "ACCEPT"};

    if (!run_required({}, {"-N", kChain}, wait_mode, context,
                      RemoteAccessReconcilePhase::install_filter) ||
        !run_required({}, {"-I", "INPUT", "1", "-j", kChain},
                      wait_mode, context,
                      RemoteAccessReconcilePhase::install_filter) ||
        !run_required({}, {"-A", kChain, "-i", wan, "-p", "tcp",
                           "--dport", internal_port, "-j", "ACCEPT"},
                      wait_mode, context,
                      RemoteAccessReconcilePhase::install_filter)) {
        return false;
    }

    if (inspect_chain({}, wait_mode, context,
                      RemoteAccessReconcilePhase::verify_filter) !=
            RuleState::present ||
        inspect_rule({}, "INPUT", input_jump, wait_mode, context,
                     RemoteAccessReconcilePhase::verify_filter) !=
            RuleState::present ||
        inspect_rule({}, kChain, internal_accept, wait_mode, context,
                     RemoteAccessReconcilePhase::verify_filter) !=
            RuleState::present) {
        return false;
    }

    return inspect_chain("nat", wait_mode, context,
                         RemoteAccessReconcilePhase::verify_nat) ==
           RuleState::absent;
}

std::string command_failure_detail(
    const std::string& message,
    const ReconcileCommandContext& context) {
    return message + " (phase=" +
           remote_access_reconcile_phase_name(context.phase) +
           ", exit=" + std::to_string(context.exit_code) + ")";
}

ReconcileAttemptOutcome close_with_error(
    std::string error,
    bool transient,
    XtablesWaitMode wait_mode,
    ReconcileCommandContext& context) {
    const auto original_failure = context;
    if (!remove_rules_once(wait_mode, context)) {
        error += "; " + command_failure_detail(
            "the closed firewall state could not be verified", context);
        transient = true;
    } else {
        // Cleanup is a safety action, not the cause. Preserve the exact phase
        // that made the generation fail when fail-closed verification itself
        // succeeded.
        context = original_failure;
    }
    return {
        false,
        transient,
        RemoteAccessRuntimeState::closed,
        {},
        context.phase,
        context.exit_code,
        std::move(error),
    };
}

ReconcileAttemptOutcome reconcile_remote_access_rules_once(
    const DesiredRemoteAccessState& desired) {
    ReconcileCommandContext context;
    const auto wait_mode = detect_xtables_wait_mode(context);
    if (wait_mode == XtablesWaitMode::unknown) {
        return {
            false,
            true,
            RemoteAccessRuntimeState::closed,
            {},
            context.phase,
            context.exit_code,
            command_failure_detail(
                "cannot determine a safe xtables wait mode", context),
        };
    }

    if (!desired.enabled) {
        if (remove_rules_once(wait_mode, context)) {
            return {
                true,
                false,
                RemoteAccessRuntimeState::closed,
                {},
                RemoteAccessReconcilePhase::idle,
                0,
                {},
            };
        }
        return close_with_error(
            command_failure_detail(
                "remote access is disabled, but owned firewall rules could "
                "not be removed and verified",
                context),
            true,
            wait_mode,
            context);
    }

    context.phase = RemoteAccessReconcilePhase::prerequisites;
    const auto auth = load_remote_auth_state();
    if (!auth.readable || !auth.enabled) {
        return close_with_error(
            "remote access requires web-interface authentication",
            false,
            wait_mode,
            context);
    }
    if (auth.provider == "keenetic") {
        return close_with_error(
            "remote access is unavailable with the Keenetic authentication "
            "provider because router credentials would traverse plaintext "
            "WAN HTTP",
            false,
            wait_mode,
            context);
    }
    if (!listen_address_is_reachable(desired.listen_address)) {
        return close_with_error(
            "the panel listener is loopback-only and cannot accept remote access",
            false,
            wait_mode,
            context);
    }

    context.phase = RemoteAccessReconcilePhase::discover_default_route;
    const auto wan = primary_wan_interface();
    if (wan.empty()) {
        return close_with_error(
            "no default-route interface is available for remote access",
            true,
            wait_mode,
            context);
    }
    context.phase = RemoteAccessReconcilePhase::verify_interface;
    if (!kernel_interface_exists(wan)) {
        return close_with_error(
            "the default-route interface '" + wan +
            "' is not a live kernel interface",
            true,
            wait_mode,
            context);
    }

    if (desired.port < 1 || desired.port > 65535) {
        return close_with_error(
            "the stored remote-access port is outside 1..65535",
            false,
            wait_mode,
            context);
    }
    if (desired.port != kInternalPort) {
        return close_with_error(
            "custom external ports are unavailable until translated traffic "
            "can be distinguished from direct WAN access to port 12121",
            false,
            wait_mode,
            context);
    }
    if (!install_rules_once(
            wan, desired.port, wait_mode, context)) {
        return close_with_error(
            command_failure_detail(
                "remote-access firewall rules could not be installed and "
                "verified",
                context),
            true,
            wait_mode,
            context);
    }

    Logger::instance().info(
        "Remote access is OPEN: the web interface is reachable from the internet on {}:{}",
        wan,
        desired.port);
    return {
        true,
        false,
        RemoteAccessRuntimeState::applied,
        wan,
        RemoteAccessReconcilePhase::idle,
        0,
        {},
    };
}

DesiredRemoteAccessState load_desired_state(
    const std::string& listen_address) {
    const auto settings = load_settings();
    return {
        settings.value("enabled", false),
        settings.value("port", kDefaultPort),
        listen_address,
    };
}

struct RemoteAccessReconcileClaim {
    std::uint64_t generation{0};
    DesiredRemoteAccessState desired;
};

RemoteAccessReconcileResult coordinator_snapshot_locked(
    const RemoteAccessCoordinator& value) {
    RemoteAccessReconcileResult result;
    result.status = value.status;
    return result;
}

void invalidate_incident_notification_locked(
    RemoteAccessCoordinator& value) noexcept {
    value.pending_incident_notification_token = 0;
    value.pending_incident_notification_generation = 0;
    value.pending_incident_notification_kind =
        IncidentNotificationKind::none;
}

void queue_incident_notification_locked(
    RemoteAccessCoordinator& value,
    RemoteAccessReconcileResult& result,
    IncidentNotificationKind kind) {
    auto token = ++value.next_incident_notification_token;
    if (token == 0U) token = ++value.next_incident_notification_token;
    value.pending_incident_notification_token = token;
    value.pending_incident_notification_generation =
        value.status.desired_generation;
    value.pending_incident_notification_kind = kind;
    result.incident_notification_token = token;
    result.incident_raised = kind == IncidentNotificationKind::raised;
    result.incident_cleared = kind == IncidentNotificationKind::cleared;
}

void reset_incident_for_new_desired_locked(
    RemoteAccessCoordinator& value) noexcept {
    // A notification not yet claimed belongs to the superseded desired
    // generation and must never escape afterwards.  The bell is an event log,
    // not a persistent latch, so a new desired state starts with clean runtime
    // truth rather than inheriting the previous generation's incident.
    invalidate_incident_notification_locked(value);
    value.incident_announced = false;
    value.status.incident_active = false;
}

// Admit a new desired generation without claiming its iptables writer. This
// is the only path used by the HTTP worker: the zero-delay hint crosses the
// daemon bridge and retry_remote_access_reconcile() claims the writer on the
// control loop. If a control-loop attempt is already in flight, its stale
// completion owns the one trailing hint for this newer generation.
RemoteAccessReconcileResult defer_new_generation(
    const DesiredRemoteAccessState& desired) {
#ifdef KEEN_PBR3_TESTING
    RemoteAccessDesiredAdmissionHook admission_hook;
    {
        const std::lock_guard<std::mutex> lock(
            desired_admission_hook_mutex());
        admission_hook = desired_admission_hook_for_testing();
    }
    if (admission_hook) admission_hook();
#endif
    // Serialize desired-generation replacement with notification
    // claim+publication.  Either the old transition is fully published first,
    // or this generation invalidates its token before it can be claimed.
    const std::lock_guard<std::mutex> publication_lock(
        incident_publication_mutex());
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    RemoteAccessReconcileResult result;
    const auto generation = ++value.next_generation;
    value.status.desired_generation = generation;
    value.status.desired_enabled = desired.enabled;
    value.status.desired_port = desired.port;
    value.status.state = RemoteAccessRuntimeState::pending;
    value.status.phase = RemoteAccessReconcilePhase::idle;
    value.status.command_exit_code = 0;
    value.status.attempt = 0;
    value.status.interface.clear();
    value.status.error.clear();
    value.status.recovery_owned = true;
    value.status.maintenance = false;
    reset_incident_for_new_desired_locked(value);
    result.apply = {
        false,
        "remote-access firewall reconciliation is queued",
    };

    if (value.in_flight) {
        value.rerun_requested = true;
        result.coalesced = true;
    } else {
        value.rerun_requested = false;
        result.retry = {
            true,
            generation,
            std::chrono::milliseconds{0},
            false,
        };
    }
    result.status = value.status;
    return result;
}

std::optional<RemoteAccessReconcileClaim> begin_refresh_generation(
    const DesiredRemoteAccessState& desired,
    RemoteAccessReconcileResult& immediate_result) {
    const std::lock_guard<std::mutex> publication_lock(
        incident_publication_mutex());
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    const bool desired_changed =
        value.status.desired_generation == 0U ||
        value.status.desired_enabled != desired.enabled ||
        value.status.desired_port != desired.port;
    if (desired_changed) {
        value.status.desired_generation = ++value.next_generation;
        value.status.desired_enabled = desired.enabled;
        value.status.desired_port = desired.port;
        value.status.phase = RemoteAccessReconcilePhase::idle;
        value.status.command_exit_code = 0;
        value.status.attempt = 0;
        value.status.interface.clear();
        value.status.error.clear();
        reset_incident_for_new_desired_locked(value);
    }

    const auto generation = value.status.desired_generation;
    value.status.state = RemoteAccessRuntimeState::pending;
    value.status.recovery_owned = true;
    value.status.maintenance = false;

    if (value.in_flight) {
        value.rerun_requested = true;
        immediate_result = coordinator_snapshot_locked(value);
        immediate_result.coalesced = true;
        return std::nullopt;
    }

    value.in_flight = true;
    value.rerun_requested = false;
    return RemoteAccessReconcileClaim{generation, desired};
}

std::optional<RemoteAccessReconcileClaim> begin_retry_generation(
    std::uint64_t expected_generation,
    const DesiredRemoteAccessState& desired,
    RemoteAccessReconcileResult& immediate_result) {
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    if (expected_generation != value.status.desired_generation ||
        value.status.state == RemoteAccessRuntimeState::applied ||
        value.status.state == RemoteAccessRuntimeState::closed ||
        desired.enabled != value.status.desired_enabled ||
        desired.port != value.status.desired_port) {
        immediate_result = coordinator_snapshot_locked(value);
        immediate_result.stale = true;
        return std::nullopt;
    }
    if (value.in_flight) {
        value.rerun_requested = true;
        immediate_result = coordinator_snapshot_locked(value);
        immediate_result.coalesced = true;
        return std::nullopt;
    }
    value.status.recovery_owned = true;
    value.in_flight = true;
    value.rerun_requested = false;
    return RemoteAccessReconcileClaim{expected_generation, desired};
}

RemoteAccessReconcileResult complete_generation(
    const RemoteAccessReconcileClaim& claim,
    ReconcileAttemptOutcome outcome) {
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    RemoteAccessReconcileResult result;
    const bool incident_was_active = value.status.incident_active;
    value.in_flight = false;
    const bool same_generation_rerun =
        claim.generation == value.status.desired_generation &&
        value.rerun_requested;

    if (claim.generation != value.status.desired_generation) {
        value.rerun_requested = false;
        value.status.state = RemoteAccessRuntimeState::pending;
        value.status.recovery_owned = true;
        value.status.maintenance = false;
        result.apply = {
            false,
            "remote-access desired state changed during reconciliation; "
            "the current generation is queued",
        };
        result.retry = {
            true,
            value.status.desired_generation,
            std::chrono::milliseconds{0},
            false,
        };
        result.status = value.status;
        result.stale = true;
        return result;
    }
    value.rerun_requested = false;

    value.status.interface = std::move(outcome.interface);
    if (outcome.success) {
        if (same_generation_rerun) {
            // A runtime observation arrived while this proof was executing.
            // The successful attempt cannot close an older incident or claim
            // finality across that observation; one immediate same-generation
            // pass verifies the post-event state on the control loop.
            value.status.state = RemoteAccessRuntimeState::pending;
            value.status.recovery_owned = true;
            value.status.maintenance = false;
            if (!incident_was_active) {
                value.status.phase = RemoteAccessReconcilePhase::idle;
                value.status.command_exit_code = 0;
                value.status.error.clear();
            }
            result.apply = {
                false,
                "remote-access runtime changed during verification; "
                "one trailing pass is queued",
            };
            result.retry = {
                true,
                claim.generation,
                std::chrono::milliseconds{0},
                false,
            };
            result.status = value.status;
            result.stale = true;
            return result;
        }
        value.status.state = outcome.success_state;
        value.status.applied_generation = claim.generation;
        value.status.attempt = 0;
        value.status.phase = RemoteAccessReconcilePhase::idle;
        value.status.command_exit_code = 0;
        value.status.error.clear();
        value.status.incident_active = false;
        value.status.recovery_owned = false;
        value.status.maintenance = false;
        result.apply = {true, {}};
        if (incident_was_active) {
            if (value.incident_announced) {
                queue_incident_notification_locked(
                    value, result, IncidentNotificationKind::cleared);
            } else {
                invalidate_incident_notification_locked(value);
            }
        }
        result.status = value.status;
        return result;
    }

    value.status.phase = outcome.phase;
    value.status.command_exit_code = outcome.exit_code;
    value.status.error = std::move(outcome.error);
    result.apply = {false, value.status.error};
    // A same-generation refresh which coalesced during a failed attempt does
    // not discard that failure. Counting it is what lets a sustained NDM or
    // interface storm reach the bounded incident threshold instead of keeping
    // attempt zero forever. The ordinary backoff hint below owns the retry.
    if (!outcome.transient) {
        value.status.state = RemoteAccessRuntimeState::degraded;
        value.status.incident_active = true;
        value.status.recovery_owned = false;
        value.status.maintenance = false;
        if (!incident_was_active) {
            if (value.incident_announced) {
                // A previously announced incident became active again before
                // its queued clear was published.  Keep the existing bell and
                // cancel only that exact clear transition.
                invalidate_incident_notification_locked(value);
            } else {
                queue_incident_notification_locked(
                    value, result, IncidentNotificationKind::raised);
            }
        }
        result.status = value.status;
        return result;
    }

    ++value.status.attempt;
    if (value.status.attempt <= kRetryDelays.size()) {
        value.status.state = RemoteAccessRuntimeState::pending;
        value.status.incident_active = incident_was_active;
        value.status.recovery_owned = true;
        value.status.maintenance = false;
        result.retry = {
            true,
            claim.generation,
            kRetryDelays[value.status.attempt - 1U],
            false,
        };
    } else {
        value.status.state = RemoteAccessRuntimeState::degraded;
        value.status.incident_active = true;
        value.status.recovery_owned = true;
        value.status.maintenance = true;
        if (!incident_was_active) {
            if (value.incident_announced) {
                invalidate_incident_notification_locked(value);
            } else {
                queue_incident_notification_locked(
                    value, result, IncidentNotificationKind::raised);
            }
        }
        result.retry = {
            true,
            claim.generation,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                kMaintenanceRetryDelay),
            true,
        };
    }
    result.status = value.status;
    return result;
}

RemoteAccessReconcileResult execute_claim(
    const RemoteAccessReconcileClaim& claim) {
    try {
#ifdef KEEN_PBR3_TESTING
        invoke_security_fence_hook_for_testing(
            RemoteAccessSecurityFenceStage::waiting);
#endif
        // Authentication's durable-file and in-memory publication is one
        // security boundary with the firewall writer. In particular, a
        // reconciler must not observe auth.json enabled while HTTP middleware
        // still serves the previous disabled snapshot.
        [[maybe_unused]] auto security_boundary =
            acquire_remote_access_security_boundary();
#ifdef KEEN_PBR3_TESTING
        invoke_security_fence_hook_for_testing(
            RemoteAccessSecurityFenceStage::acquired);
#endif
        bool generation_is_current = false;
        {
            auto& value = coordinator();
            const std::lock_guard<std::mutex> lock(value.mutex);
            generation_is_current =
                claim.generation == value.status.desired_generation;
        }
        if (!generation_is_current) {
            // The auth/remote publisher which owned the fence superseded this
            // claim while it waited. Completing it queues the current
            // generation without executing stale firewall commands.
            return complete_generation(claim, {});
        }
        return complete_generation(
            claim, reconcile_remote_access_rules_once(claim.desired));
    } catch (const std::exception& error) {
        return complete_generation(
            claim,
            ReconcileAttemptOutcome{
                false,
                true,
                RemoteAccessRuntimeState::closed,
                {},
                RemoteAccessReconcilePhase::internal,
                -1,
                std::string("remote-access reconciliation raised an "
                            "unexpected exception: ") + error.what(),
            });
    } catch (...) {
        return complete_generation(
            claim,
            ReconcileAttemptOutcome{
                false,
                true,
                RemoteAccessRuntimeState::closed,
                {},
                RemoteAccessReconcilePhase::internal,
                -1,
                "remote-access reconciliation raised an unknown exception",
            });
    }
}

void retain_retry_hint(RemoteAccessRetryHint hint) {
    auto& registry = retry_scheduler_registry();
    const std::lock_guard<std::mutex> lock(registry.mutex);
    if (!registry.pending ||
        hint.generation >= registry.pending->generation) {
        registry.pending = std::move(hint);
    }
}

void publish_retry_hint(const RemoteAccessRetryHint& hint);

void invoke_retry_scheduler(
    const std::shared_ptr<RetrySchedulerRegistration>& registration,
    const RemoteAccessRetryHint& hint) {
    if (!registration) {
        retain_retry_hint(hint);
        return;
    }
    try {
        const std::lock_guard<std::mutex> invocation_lock(
            registration->invocation_mutex);
        if (!registration->active.load(std::memory_order_acquire)) {
            if (registration->redispatch_when_inactive.load(
                    std::memory_order_acquire)) {
                publish_retry_hint(hint);
            }
            return;
        }
        if (!registration->callback) {
            retain_retry_hint(hint);
            return;
        }
        // Production callback wiring must only enqueue a control-loop task.
        // It is deliberately invoked without coordinator/registry locks so a
        // deterministic test callback may re-enter the reconciler.
        registration->callback(hint);
    } catch (const std::exception& error) {
        if (!registration->active.load(std::memory_order_acquire)) return;
        Logger::instance().info(
            "Remote-access recovery generation {} remains pending because "
            "scheduler dispatch was deferred: {}",
            hint.generation,
            error.what());
        retain_retry_hint(hint);
    } catch (...) {
        if (!registration->active.load(std::memory_order_acquire)) return;
        Logger::instance().info(
            "Remote-access recovery generation {} remains pending because "
            "scheduler dispatch was deferred: unknown error",
            hint.generation);
        retain_retry_hint(hint);
    }
}

void publish_retry_hint(const RemoteAccessRetryHint& hint) {
    if (!hint.schedule) return;
    std::shared_ptr<RetrySchedulerRegistration> registration;
    {
        auto& registry = retry_scheduler_registry();
        const std::lock_guard<std::mutex> lock(registry.mutex);
        registration = registry.registration;
        if (!registration) {
            if (!registry.pending ||
                hint.generation >= registry.pending->generation) {
                registry.pending = hint;
            }
            return;
        }
    }
    invoke_retry_scheduler(registration, hint);
}

void discard_retry_hint_through(std::uint64_t generation) {
    auto& registry = retry_scheduler_registry();
    const std::lock_guard<std::mutex> lock(registry.mutex);
    if (registry.pending &&
        registry.pending->generation <= generation) {
        registry.pending.reset();
    }
}

void publish_reconcile_result_hint(
    const RemoteAccessReconcileResult& result) {
    if (result.retry.schedule) {
        publish_retry_hint(result.retry);
    } else if (result.apply.applied ||
               (result.status.state == RemoteAccessRuntimeState::degraded &&
                !result.coalesced)) {
        discard_retry_hint_through(result.status.desired_generation);
    }
}

struct ClaimedIncidentNotification {
    IncidentNotificationKind kind{IncidentNotificationKind::none};
    std::uint64_t generation{0};
    std::string error;
};

std::optional<ClaimedIncidentNotification> claim_incident_notification(
    const RemoteAccessReconcileResult& result) {
    if (result.incident_notification_token == 0U) return std::nullopt;
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    if (value.pending_incident_notification_token !=
            result.incident_notification_token ||
        value.pending_incident_notification_generation !=
            result.status.desired_generation ||
        value.status.desired_generation !=
            result.status.desired_generation) {
        return std::nullopt;
    }

    const auto kind = value.pending_incident_notification_kind;
    if ((kind == IncidentNotificationKind::raised &&
         !value.status.incident_active) ||
        (kind == IncidentNotificationKind::cleared &&
         value.status.incident_active) ||
        kind == IncidentNotificationKind::none) {
        return std::nullopt;
    }

    // Clear only the exact token claimed above.  A newer completion can
    // replace the pending transition before this function obtains the lock;
    // that newer transition must remain owned by its own result publisher.
    invalidate_incident_notification_locked(value);
    value.incident_announced =
        kind == IncidentNotificationKind::raised;
    return ClaimedIncidentNotification{
        kind,
        result.status.desired_generation,
        result.apply.error,
    };
}

void publish_reconcile_incident(
    const RemoteAccessReconcileResult& result) {
    if (result.incident_notification_token == 0U) return;
    // Serializing claim+publication preserves the order of an announced
    // incident and its later clear without holding the coordinator mutex
    // across logging or a user-provided sink.
    const std::lock_guard<std::mutex> publication_lock(
        incident_publication_mutex());
    const auto notification = claim_incident_notification(result);
    if (!notification) return;
#ifdef KEEN_PBR3_TESTING
    RemoteAccessIncidentPublishHook hook;
    {
        const std::lock_guard<std::mutex> lock(
            incident_publish_hook_mutex());
        hook = incident_publish_hook_for_testing();
    }
    // The hook deliberately runs after claim while publication ownership is
    // still held.  A barrier test can prove a concurrent POST cannot
    // supersede the generation in this last pre-log window.
    if (hook) hook();
#endif
    if (notification->kind == IncidentNotificationKind::raised) {
        Logger::instance().error(
            "Cannot reconcile remote-access firewall state: {}",
            notification->error);
    } else if (notification->kind == IncidentNotificationKind::cleared) {
        Logger::instance().info(
            "Remote-access firewall state recovered and was verified on generation {}.",
            notification->generation);
    }
}

} // namespace

const char* remote_access_runtime_state_name(
    RemoteAccessRuntimeState state) noexcept {
    switch (state) {
    case RemoteAccessRuntimeState::closed: return "closed";
    case RemoteAccessRuntimeState::pending: return "pending";
    case RemoteAccessRuntimeState::applied: return "applied";
    case RemoteAccessRuntimeState::degraded: return "degraded";
    }
    return "degraded";
}

const char* remote_access_reconcile_phase_name(
    RemoteAccessReconcilePhase phase) noexcept {
    switch (phase) {
    case RemoteAccessReconcilePhase::idle: return "idle";
    case RemoteAccessReconcilePhase::internal: return "internal";
    case RemoteAccessReconcilePhase::prerequisites: return "prerequisites";
    case RemoteAccessReconcilePhase::discover_default_route:
        return "discover_default_route";
    case RemoteAccessReconcilePhase::verify_interface:
        return "verify_interface";
    case RemoteAccessReconcilePhase::detect_xtables_wait:
        return "detect_xtables_wait";
    case RemoteAccessReconcilePhase::remove_filter: return "remove_filter";
    case RemoteAccessReconcilePhase::remove_nat: return "remove_nat";
    case RemoteAccessReconcilePhase::install_filter: return "install_filter";
    case RemoteAccessReconcilePhase::install_nat: return "install_nat";
    case RemoteAccessReconcilePhase::verify_filter: return "verify_filter";
    case RemoteAccessReconcilePhase::verify_nat: return "verify_nat";
    }
    return "idle";
}

RemoteAccessSecurityBoundaryGuard::RemoteAccessSecurityBoundaryGuard(
    std::unique_lock<std::mutex> lock) noexcept
    : lock_(std::move(lock)) {}

RemoteAccessSecurityBoundaryGuard
acquire_remote_access_security_boundary() {
    return RemoteAccessSecurityBoundaryGuard{
        std::unique_lock<std::mutex>(
            remote_access_security_boundary_mutex())};
}

bool remote_access_blocks_auth_disable(
    const RemoteAccessSecurityBoundaryGuard&) {
    bool stored_enabled = false;
    bool stored_state_uncertain = false;
    RemoteAccessRuntimeStatus runtime;
    {
        const std::lock_guard<std::mutex> lock(settings_mutex());
        try {
            const auto path = settings_path();
            std::error_code exists_error;
            const bool exists =
                std::filesystem::exists(path, exists_error);
            if (exists_error) {
                stored_state_uncertain = true;
            }
            const auto raw = read_file(path);
            if (!raw.empty()) {
                const auto settings = nlohmann::json::parse(raw);
                if (!settings.contains("enabled") ||
                    !settings["enabled"].is_boolean()) {
                    stored_state_uncertain = true;
                } else {
                    stored_enabled = settings["enabled"].get<bool>();
                }
            } else if (exists) {
                stored_state_uncertain = true;
            }
        } catch (const std::exception&) {
            // An unreadable desired state is not authority to expose a panel
            // which may still have a retained kernel rule.
            stored_state_uncertain = true;
        }
        runtime = remote_access_runtime_status();
    }
    // Generation zero is merely the process default, not proof that stale
    // rules from a previous process were removed. Likewise, only the exact
    // applied desired generation is cleanup authority for an auth disable.
    const bool runtime_not_verified_closed =
        !runtime_status_is_verified_closed(runtime);
    return stored_state_uncertain || stored_enabled ||
           runtime_not_verified_closed ||
           runtime.desired_enabled ||
           runtime.state != RemoteAccessRuntimeState::closed;
}

bool remote_access_blocks_keenetic_auth(
    const RemoteAccessSecurityBoundaryGuard& guard) {
    return remote_access_blocks_auth_disable(guard);
}

RemoteAccessReconcileResult
defer_remote_access_reconcile_after_auth_enable(
    const RemoteAccessSecurityBoundaryGuard&) {
    RemoteAccessReconcileResult result;
    {
        const std::lock_guard<std::mutex> lock(settings_mutex());
        const auto desired = load_desired_state({});
        const auto current = remote_access_runtime_status();
        const bool already_converged =
            desired.enabled
                ? current.desired_generation != 0U &&
                      current.applied_generation ==
                          current.desired_generation &&
                      current.state == RemoteAccessRuntimeState::applied &&
                      current.desired_enabled &&
                      current.desired_port == desired.port
                : runtime_status_is_verified_closed(current);
        if (already_converged) {
            result.apply = {true, {}};
            result.status = current;
            return result;
        }
        // Empty listen is intentional. The deferred generation stores only
        // durable desired enable/port; retry on the daemon control loop loads
        // the current API listener before executing any firewall command.
        result = defer_new_generation(desired);
    }
    publish_reconcile_result_hint(result);
    publish_reconcile_incident(result);
    return result;
}

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

void set_remote_access_retry_scheduler(
    RemoteAccessRetryScheduler scheduler) {
    if (!scheduler) {
        reset_remote_access_retry_scheduler();
        return;
    }

    auto next = std::make_shared<RetrySchedulerRegistration>();
    next->callback = std::move(scheduler);
    std::shared_ptr<RetrySchedulerRegistration> previous;
    std::optional<RemoteAccessRetryHint> pending;
    {
        auto& registry = retry_scheduler_registry();
        const std::lock_guard<std::mutex> lock(registry.mutex);
        previous = std::move(registry.registration);
        registry.registration = next;
        pending = std::move(registry.pending);
        registry.pending.reset();
        if (previous) {
            // Retire while the registry lock still fences publishers that
            // captured the old registration. Their hints are forwarded to
            // the replacement instead of being lost.
            previous->redispatch_when_inactive.store(
                true, std::memory_order_release);
            previous->active.store(false, std::memory_order_release);
        }
    }
    if (previous) {
        const std::lock_guard<std::mutex> invocation_lock(
            previous->invocation_mutex);
        previous->callback = {};
    }
    if (pending) {
        invoke_retry_scheduler(next, *pending);
    }
}

void reset_remote_access_retry_scheduler() {
    std::shared_ptr<RetrySchedulerRegistration> previous;
    {
        auto& registry = retry_scheduler_registry();
        const std::lock_guard<std::mutex> lock(registry.mutex);
        previous = std::move(registry.registration);
        registry.pending.reset();
        if (previous) {
            // This is the lifetime fence: a publisher that already captured
            // the registration observes inactive before reset releases the
            // registry lock and cannot enter the callback afterwards.
            previous->active.store(false, std::memory_order_release);
        }
    }
    if (!previous) return;
    const std::lock_guard<std::mutex> invocation_lock(
        previous->invocation_mutex);
    previous->callback = {};
}

RemoteAccessReconcileResult refresh_remote_access_reconcile(
    const std::string& listen_address) {
    RemoteAccessReconcileResult immediate;
    std::optional<RemoteAccessReconcileClaim> claim;
    {
        const std::lock_guard<std::mutex> lock(settings_mutex());
        claim = begin_refresh_generation(
            load_desired_state(listen_address), immediate);
    }
    if (!claim) {
        publish_reconcile_result_hint(immediate);
        publish_reconcile_incident(immediate);
        return immediate;
    }
    auto result = execute_claim(*claim);
    publish_reconcile_result_hint(result);
    publish_reconcile_incident(result);
    return result;
}

RemoteAccessReconcileResult request_remote_access_reconcile(
    const std::string& listen_address) {
    return refresh_remote_access_reconcile(listen_address);
}

RemoteAccessReconcileResult retry_remote_access_reconcile(
    std::uint64_t expected_generation,
    const std::string& listen_address) {
    RemoteAccessReconcileResult immediate;
    std::optional<RemoteAccessReconcileClaim> claim;
    {
        const std::lock_guard<std::mutex> lock(settings_mutex());
        claim = begin_retry_generation(
            expected_generation,
            load_desired_state(listen_address),
            immediate);
    }
    if (!claim) {
        publish_reconcile_result_hint(immediate);
        publish_reconcile_incident(immediate);
        return immediate;
    }
    auto result = execute_claim(*claim);
    publish_reconcile_result_hint(result);
    publish_reconcile_incident(result);
    return result;
}

RemoteAccessRuntimeStatus remote_access_runtime_status() {
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    return value.status;
}

bool remote_access_runtime_is_verified_closed() {
    auto& value = coordinator();
    const std::lock_guard<std::mutex> lock(value.mutex);
    return runtime_status_is_verified_closed(value.status);
}

bool remote_access_runtime_blocks_unauthenticated_request(
    bool request_is_loopback) {
    return !request_is_loopback &&
           !remote_access_runtime_is_verified_closed();
}

RemoteAccessApplyResult apply_remote_access_rules(
    const std::string& listen_address) {
    const auto result = refresh_remote_access_reconcile(listen_address);
    if (!result.apply.applied && !result.coalesced && !result.stale &&
        result.status.state == RemoteAccessRuntimeState::pending) {
        Logger::instance().info(
            "Remote-access firewall reconciliation is pending: {}",
            result.apply.error);
    }
    return result.apply;
}

bool remove_remote_access_rules(RemoteAccessRemovalMode mode) {
    ReconcileCommandContext context;
    // Every command failure is owned by the reconciler/wrapper policy. A
    // low-level timeout must never bypass bounded incident suppression; the
    // normal wrapper raises one error below, while expected teardown stays
    // informational.
    constexpr auto failure_log = SafeExecFailureLog::DiagnosticOnly;
    const auto wait_mode =
        detect_xtables_wait_mode(context, failure_log);
    const bool removed =
        wait_mode != XtablesWaitMode::unknown &&
        remove_rules_once(wait_mode, context, failure_log);
    if (removed) {
        auto& value = coordinator();
        const std::lock_guard<std::mutex> lock(value.mutex);
        value.status.state = RemoteAccessRuntimeState::closed;
        if (!value.status.desired_enabled) {
            // Closed satisfies a disabled desired generation. Expected
            // teardown of an enabled generation is runtime cleanup only and
            // must not claim that its desired state was applied.
            value.status.applied_generation =
                value.status.desired_generation;
        }
        value.status.attempt = 0;
        value.status.phase = RemoteAccessReconcilePhase::idle;
        value.status.command_exit_code = 0;
        value.status.interface.clear();
        value.status.error.clear();
        value.status.incident_active = false;
        value.status.recovery_owned = false;
        value.status.maintenance = false;
        value.incident_announced = false;
        invalidate_incident_notification_locked(value);
        return true;
    }
    if (mode == RemoteAccessRemovalMode::normal) {
        Logger::instance().error(
            "Cannot remove and verify remote-access firewall rules "
            "(phase={}, exit={})",
            remote_access_reconcile_phase_name(context.phase),
            context.exit_code);
    } else {
        Logger::instance().info(
            "Remote-access firewall cleanup could not be verified during "
            "expected teardown (phase={}, exit={}); no incident was raised.",
            remote_access_reconcile_phase_name(context.phase),
            context.exit_code);
    }
    return false;
}

void register_remote_access_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/system/remote-access", [&ctx]() -> std::string {
        const auto config = ctx.get_visible_config();
        const auto listen = config.api.has_value()
                                ? config.api->listen.value_or(std::string{})
                                : std::string{};

        nlohmann::json settings;
        RemoteAccessRuntimeStatus runtime;
        auto security_boundary =
            acquire_remote_access_security_boundary();
        const bool keenetic_auth_switch_allowed =
            !remote_access_blocks_keenetic_auth(security_boundary);
        {
            const std::lock_guard<std::mutex> lock(settings_mutex());
            settings = load_settings();
            // Keep persisted desired settings and their coordinator snapshot
            // in one lock-ordered view (settings -> coordinator), matching
            // POST and refresh admission.
            runtime = remote_access_runtime_status();
        }
        const auto auth = load_remote_auth_state();
        settings["login_required"] = auth.readable && auth.enabled;
        settings["auth_provider"] =
            auth.readable ? auth.provider : "unavailable";
        settings["custom_port_supported"] = false;
        settings["supported_port"] = kInternalPort;
        settings["keenetic_auth_switch_allowed"] =
            keenetic_auth_switch_allowed;
        if (!auth.readable) {
            settings["blocked_reason"] = "auth_state_unavailable";
        } else if (!auth.enabled) {
            settings["blocked_reason"] = "login_disabled";
        } else if (auth.provider == "keenetic") {
            settings["blocked_reason"] =
                "keenetic_auth_plaintext_wan";
        } else if (!listen_address_is_reachable(listen)) {
            settings["blocked_reason"] = "listen_loopback";
        } else {
            settings["blocked_reason"] = nullptr;
        }
        settings["internal_port"] = kInternalPort;
        settings["listen"] = listen;
        settings["listen_reachable"] = listen_address_is_reachable(listen);
        settings["runtime"] = {
            {"state", remote_access_runtime_state_name(runtime.state)},
            {"desired_generation", runtime.desired_generation},
            {"applied_generation", runtime.applied_generation},
            {"attempt", runtime.attempt},
            {"interface", runtime.interface},
            {"phase", remote_access_reconcile_phase_name(runtime.phase)},
            {"command_exit_code", runtime.command_exit_code},
            {"error", runtime.error},
            {"incident_active", runtime.incident_active},
            {"recovery_owned", runtime.recovery_owned},
            {"maintenance", runtime.maintenance},
        };
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
            auto security_boundary =
                acquire_remote_access_security_boundary();
            // Refusing here rather than warning later: the whole point of the
            // check is that the panel never reaches the internet unprotected.
            const auto auth = load_remote_auth_state();
            if (enabled && !auth.readable) {
                response["error"] = "auth_state_unavailable";
                return response.dump();
            }
            if (enabled && !auth.enabled) {
                response["error"] = "login_disabled";
                return response.dump();
            }
            if (enabled && auth.provider == "keenetic") {
                response["error"] = "keenetic_auth_plaintext_wan";
                response["detail"] =
                    "Keenetic router credentials cannot be sent through a "
                    "panel published over plaintext WAN HTTP";
                return response.dump();
            }
            if (enabled && !listen_address_is_reachable(listen)) {
                response["error"] = "listen_loopback";
                response["listen"] = listen;
                return response.dump();
            }
            if (enabled && port != kInternalPort) {
                response["error"] = "custom_port_not_supported_safely";
                response["supported_port"] = kInternalPort;
                response["detail"] =
                    "a translated custom port cannot yet be verified without "
                    "also exposing direct WAN port 12121";
                return response.dump();
            }

            nlohmann::json settings;
            settings["enabled"] = enabled;
            settings["port"] = port;
            bool settings_durable = false;
            RemoteAccessReconcileResult reconcile;
            try {
                const std::lock_guard<std::mutex> lock(settings_mutex());
                settings_durable = save_settings(settings);
                // Serialize settings publication and generation admission so
                // concurrent POST responses cannot describe another writer's
                // desired state. No iptables command runs on this HTTP worker.
                reconcile = defer_new_generation(
                    DesiredRemoteAccessState{enabled, port, listen});
            } catch (const std::exception& error) {
                Logger::instance().error(
                    "Cannot write remote-access.json atomically: {}",
                    error.what());
                response["error"] = "cannot write remote-access.json";
                return response.dump();
            }
            publish_reconcile_result_hint(reconcile);
            publish_reconcile_incident(reconcile);
            if (!reconcile.apply.applied) {
                const bool permanent_degraded =
                    reconcile.status.state ==
                        RemoteAccessRuntimeState::degraded &&
                    !reconcile.status.recovery_owned;
                response["detail"] = reconcile.apply.error;
                response["degraded"] =
                    reconcile.status.state ==
                    RemoteAccessRuntimeState::degraded;
                response["pending"] = !permanent_degraded;
                response["generation"] =
                    reconcile.status.desired_generation;
                response["phase"] = remote_access_reconcile_phase_name(
                    reconcile.status.phase);
                response["retry_scheduled"] =
                    reconcile.status.recovery_owned;
                response["recovery_owned"] =
                    reconcile.status.recovery_owned;
                response["maintenance"] =
                    reconcile.status.maintenance;
                if (reconcile.retry.schedule) {
                    response["retry_after_ms"] =
                        reconcile.retry.delay.count();
                }
                response["durable"] = settings_durable;
                if (!settings_durable) {
                    response["warning"] =
                        "remote-access settings are visible but directory "
                        "durability could not be confirmed";
                }
                response["settings"] = settings;
                if (permanent_degraded) {
                    response["error"] =
                        "cannot apply remote-access firewall rules";
                    return response.dump();
                }
                response["ok"] = true;
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

void set_remote_access_incident_publish_hook_for_testing(
    RemoteAccessIncidentPublishHook hook) {
    const std::lock_guard<std::mutex> lock(
        incident_publish_hook_mutex());
    incident_publish_hook_for_testing() = std::move(hook);
}

void reset_remote_access_incident_publish_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        incident_publish_hook_mutex());
    incident_publish_hook_for_testing() = {};
}

void set_remote_access_desired_admission_hook_for_testing(
    RemoteAccessDesiredAdmissionHook hook) {
    const std::lock_guard<std::mutex> lock(
        desired_admission_hook_mutex());
    desired_admission_hook_for_testing() = std::move(hook);
}

void reset_remote_access_desired_admission_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        desired_admission_hook_mutex());
    desired_admission_hook_for_testing() = {};
}

void set_remote_access_security_fence_hook_for_testing(
    RemoteAccessSecurityFenceHook hook) {
    const std::lock_guard<std::mutex> lock(
        security_fence_hook_mutex());
    security_fence_hook_for_testing() = std::move(hook);
}

void reset_remote_access_security_fence_hook_for_testing() {
    const std::lock_guard<std::mutex> lock(
        security_fence_hook_mutex());
    security_fence_hook_for_testing() = {};
}

void reset_remote_access_reconciler_for_testing() {
    reset_remote_access_retry_scheduler();
    {
        auto& value = coordinator();
        const std::lock_guard<std::mutex> lock(value.mutex);
        value.status = {};
        value.next_generation = 0;
        value.in_flight = false;
        value.rerun_requested = false;
        value.next_incident_notification_token = 0;
        invalidate_incident_notification_locked(value);
        value.incident_announced = false;
    }
    {
        const std::lock_guard<std::mutex> lock(xtables_wait_mutex());
        xtables_wait_mode_storage() = XtablesWaitMode::unknown;
    }
    reset_remote_access_incident_publish_hook_for_testing();
    reset_remote_access_desired_admission_hook_for_testing();
    reset_remote_access_security_fence_hook_for_testing();
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
