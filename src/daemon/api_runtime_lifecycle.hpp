#pragma once

#include <functional>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

// Execute one setup attempt behind a strong ownership boundary. The rollback
// callback is deliberately required to be no-throw: after setup reports
// failure, no partially published API resource may remain for the caller.
template <typename SetupAttempt, typename Rollback>
void run_api_setup_with_strong_rollback(
    SetupAttempt&& setup_attempt,
    Rollback&& rollback) {
    static_assert(
        std::is_nothrow_invocable_v<Rollback&>,
        "failed API setup rollback must not throw");
    std::invoke(rollback);
    try {
        std::invoke(std::forward<SetupAttempt>(setup_attempt));
    } catch (...) {
        std::invoke(rollback);
        throw;
    }
}

// Replacing the conntrack monitor is a two-owner handoff: the old epoll
// registration must be retired before a new socket can be published. Keeping
// this ordering in one production seam makes setup_api() retries equivalent to
// a clean first setup instead of leaving a callback for a closed descriptor.
template <typename RetireCurrent, typename InstallReplacement>
void replace_api_conntrack_monitor_for_retry(
    RetireCurrent&& retire_current,
    InstallReplacement&& install_replacement) {
    std::invoke(std::forward<RetireCurrent>(retire_current));
    std::invoke(std::forward<InstallReplacement>(install_replacement));
}

// ApiServer handlers retain references into ApiContext. Destruction must stop
// and retire the server first, then release the context, and only then remove
// auxiliary event-loop state. The first two steps are required to be no-throw
// so cleanup cannot continue past a still-live server.
template <typename RetireServer,
          typename RetireContext,
          typename RetireConntrack>
void retire_api_runtime_in_dependency_order(
    RetireServer&& retire_server,
    RetireContext&& retire_context,
    RetireConntrack&& retire_conntrack) {
    static_assert(
        std::is_nothrow_invocable_v<RetireServer&>,
        "API server retirement must not fail before context retirement");
    static_assert(
        std::is_nothrow_invocable_v<RetireContext&>,
        "API context retirement must not fail after server retirement");

    std::invoke(retire_server);
    std::invoke(retire_context);
    std::invoke(std::forward<RetireConntrack>(retire_conntrack));
}

// setup_api() can finish while shutdown closes cold-boot service admission.
// The second gate therefore owns the just-created resources: a closed gate
// retires them synchronously instead of leaving a listener alive until the
// later global shutdown tail.
template <typename RetireRuntime>
bool retain_api_runtime_after_setup_if_gate_open(
    bool service_gate_open,
    RetireRuntime&& retire_runtime) noexcept {
    static_assert(
        std::is_nothrow_invocable_v<RetireRuntime&>,
        "post-setup API retirement must not throw");
    if (service_gate_open) {
        return true;
    }
    std::invoke(retire_runtime);
    return false;
}

} // namespace keen_pbr3
