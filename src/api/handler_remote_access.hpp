#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Opens the web interface to the outside world.
//
// The API already listens on every address; what keeps it private is the
// firmware's firewall. So this adds a deliberate hole for one TCP port on the
// WAN interface, and nothing else. It refuses to open when login is disabled -
// publishing an unauthenticated control panel to the internet is not a choice
// worth offering behind a single switch.
void register_remote_access_handler(ApiServer& server, ApiContext& ctx);

// Re-applies the stored rules. Called at startup and after every firewall
// rebuild: the firmware reapplies its own firewall on network events and wipes
// rules it does not own, so applying once at startup was not enough.
//
// listen_address is the panel's own bind address. A panel bound to loopback
// cannot be published no matter what the firewall says, and that failure is
// invisible from the outside - it looks exactly like a blocked port.
struct RemoteAccessApplyResult {
    bool applied{false};
    std::string error;
};

enum class RemoteAccessRuntimeState {
    closed,
    pending,
    applied,
    degraded,
};

enum class RemoteAccessReconcilePhase {
    idle,
    internal,
    prerequisites,
    discover_default_route,
    verify_interface,
    detect_xtables_wait,
    remove_filter,
    remove_nat,
    install_filter,
    install_nat,
    verify_filter,
    verify_nat,
};

const char* remote_access_runtime_state_name(
    RemoteAccessRuntimeState state) noexcept;
const char* remote_access_reconcile_phase_name(
    RemoteAccessReconcilePhase phase) noexcept;

// The reconciler never sleeps. Its owner schedules this generation-fenced
// hint and calls retry_remote_access_reconcile() when the timer fires.
struct RemoteAccessRetryHint {
    bool schedule{false};
    std::uint64_t generation{0};
    std::chrono::milliseconds delay{0};
    bool maintenance{false};
};

struct RemoteAccessRuntimeStatus {
    RemoteAccessRuntimeState state{RemoteAccessRuntimeState::closed};
    std::uint64_t desired_generation{0};
    std::uint64_t applied_generation{0};
    unsigned int attempt{0};
    bool desired_enabled{false};
    int desired_port{0};
    std::string interface;
    RemoteAccessReconcilePhase phase{RemoteAccessReconcilePhase::idle};
    int command_exit_code{0};
    std::string error;
    bool incident_active{false};
    // True only while the reconciler has an owned path to another attempt
    // (an admitted/retained hint or quiet maintenance).  Callers must not
    // infer this from attempt: a permanent failure can follow transient ones.
    bool recovery_owned{false};
    bool maintenance{false};
};

struct RemoteAccessReconcileResult {
    RemoteAccessApplyResult apply;
    RemoteAccessRetryHint retry;
    RemoteAccessRuntimeStatus status;
    bool coalesced{false};
    bool stale{false};
    bool incident_raised{false};
    bool incident_cleared{false};
    // Internal publication fence.  A notification is emitted only while this
    // token still names the current generation/state transition.
    std::uint64_t incident_notification_token{0};
};

using RemoteAccessRetryScheduler =
    std::function<void(const RemoteAccessRetryHint&)>;

// Auth disable and remote desired-state publication share this boundary.  It
// prevents either ordering from exposing an unauthenticated panel: remote
// enable sees the already-disabled auth file and refuses, or auth disable sees
// the newly enabled/pending remote state and refuses before replacing auth.
class RemoteAccessSecurityBoundaryGuard {
public:
    RemoteAccessSecurityBoundaryGuard(
        RemoteAccessSecurityBoundaryGuard&&) noexcept = default;
    RemoteAccessSecurityBoundaryGuard& operator=(
        RemoteAccessSecurityBoundaryGuard&&) noexcept = default;
    RemoteAccessSecurityBoundaryGuard(
        const RemoteAccessSecurityBoundaryGuard&) = delete;
    RemoteAccessSecurityBoundaryGuard& operator=(
        const RemoteAccessSecurityBoundaryGuard&) = delete;

private:
    explicit RemoteAccessSecurityBoundaryGuard(
        std::unique_lock<std::mutex> lock) noexcept;
    std::unique_lock<std::mutex> lock_;
    friend RemoteAccessSecurityBoundaryGuard
    acquire_remote_access_security_boundary();
};

RemoteAccessSecurityBoundaryGuard
acquire_remote_access_security_boundary();
// Must be called while the supplied guard is alive. True includes a pending
// disable whose firewall cleanup has not yet reached verified closed state.
bool remote_access_blocks_auth_disable(
    const RemoteAccessSecurityBoundaryGuard& guard);
// The router administrator password must never be accepted by a panel that is
// desired, applied, or possibly still reachable through plaintext WAN HTTP.
// As with auth disable, only a verified-closed generation is sufficient proof.
bool remote_access_blocks_keenetic_auth(
    const RemoteAccessSecurityBoundaryGuard& guard);
// Authentication was published first; this only admits a fresh desired
// generation and publishes a zero-delay hint. The daemon control loop remains
// the sole firewall writer.
RemoteAccessReconcileResult
defer_remote_access_reconcile_after_auth_enable(
    const RemoteAccessSecurityBoundaryGuard& guard);

// The daemon registers its control-loop timer bridge once. Until then the
// reconciler retains only the newest generation hint and dispatches it on
// registration, so an API POST cannot orphan required recovery work.
void set_remote_access_retry_scheduler(
    RemoteAccessRetryScheduler scheduler);
// Fences an in-flight dispatch before returning. Production wiring must call
// this before closing control-task admission or destroying the Scheduler.
void reset_remote_access_retry_scheduler();

// Reconciles a control-plane observation (startup, interface/default-route or
// central-firewall event). Runtime churn reuses the current desired generation
// and preserves its attempt/incident history; only a changed persisted desired
// state starts a new generation.
RemoteAccessReconcileResult refresh_remote_access_reconcile(
    const std::string& listen_address = {});

// Compatibility spelling for existing control-loop callers. New daemon
// wiring should use refresh_remote_access_reconcile() to make it explicit that
// a runtime observation is not a new user-desired generation.
RemoteAccessReconcileResult request_remote_access_reconcile(
    const std::string& listen_address = {});

// Executes a previously returned timer hint. A superseded generation is a
// no-op and cannot overwrite newer desired/applied state.
RemoteAccessReconcileResult retry_remote_access_reconcile(
    std::uint64_t expected_generation,
    const std::string& listen_address = {});

RemoteAccessRuntimeStatus remote_access_runtime_status();
// Application-layer fail-closed proof used while authentication is disabled.
// Generation zero, an unapplied generation, or any non-closed state is not
// authority to accept requests which might cross retained WAN rules.
bool remote_access_runtime_is_verified_closed();
// When login is disabled, only loopback recovery may bypass an unverified
// remote firewall state. Non-loopback API admission remains fail-closed until
// the exact disabled generation has been applied and verified closed.
bool remote_access_runtime_blocks_unauthenticated_request(
    bool request_is_loopback);

RemoteAccessApplyResult apply_remote_access_rules(
    const std::string& listen_address = {});

// Removes only the rules owned by the remote-access feature without changing
// the user's persisted preference.
enum class RemoteAccessRemovalMode {
    normal,
    expected_teardown,
};
bool remove_remote_access_rules(
    RemoteAccessRemovalMode mode = RemoteAccessRemovalMode::normal);

// True when the configured bind address can accept connections from outside.
bool listen_address_is_reachable(const std::string& listen_address);

#ifdef KEEN_PBR3_TESTING
using RemoteAccessCommandRunner =
    std::function<int(const std::vector<std::string>&)>;
void set_remote_access_command_runner_for_testing(
    RemoteAccessCommandRunner runner);
void reset_remote_access_command_runner_for_testing();
void reset_remote_access_reconciler_for_testing();
using RemoteAccessIncidentPublishHook = std::function<void()>;
void set_remote_access_incident_publish_hook_for_testing(
    RemoteAccessIncidentPublishHook hook);
void reset_remote_access_incident_publish_hook_for_testing();
using RemoteAccessDesiredAdmissionHook = std::function<void()>;
void set_remote_access_desired_admission_hook_for_testing(
    RemoteAccessDesiredAdmissionHook hook);
void reset_remote_access_desired_admission_hook_for_testing();
enum class RemoteAccessSecurityFenceStage {
    waiting,
    acquired,
};
using RemoteAccessSecurityFenceHook =
    std::function<void(RemoteAccessSecurityFenceStage)>;
void set_remote_access_security_fence_hook_for_testing(
    RemoteAccessSecurityFenceHook hook);
void reset_remote_access_security_fence_hook_for_testing();
#endif

} // namespace keen_pbr3

#endif
