#pragma once

#include "../config/config.hpp"
#include "../health/circuit_breaker.hpp"
#include "../health/url_tester.hpp"
#include "../util/blocking_executor.hpp"
#include "../util/traced_mutex.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

class RepeatingTaskScheduler;

// Only direct INTERFACE children have one stable device to bind a probe to.
// Selector children deliberately stay absent: their mark resolves to a
// dynamic leaf and binding them to one interface would change that contract.
using UrltestDirectChildInterfaceMap =
    std::map<std::string, std::string>;

// Per-urltest outbound state: test results, circuit breakers, selected child.
struct UrltestState {
    Outbound config;
    std::map<std::string, URLTestResult> last_results;
    std::map<std::string, CircuitBreaker> circuit_breakers;
    UrltestDirectChildInterfaceMap direct_child_interfaces;
    // Presence means a direct priority child has failed while selected and is
    // not eligible for user traffic until this many consecutive bound probe
    // successes reaches circuit_breaker.success_threshold. Nested selectors
    // keep their existing mark-only circuit-breaker contract.
    std::map<std::string, std::uint32_t> priority_recovery_successes;
    std::string selected_outbound;
    int scheduler_task_id{-1};
    bool probe_inflight{false};
    std::uint64_t generation{0};
    // Interface-health transitions are stronger than manual/status refreshes:
    // one probe admitted after the transition must observe them. Serials let a
    // transition which arrives during an already claimed probe remain pending
    // for exactly one trailing round.
    std::uint64_t external_health_request_serial{0};
    std::uint64_t external_health_completed_serial{0};
    std::uint64_t probe_external_health_serial{0};
    std::uint8_t external_health_failures{0};
    int external_health_retry_task_id{-1};
    bool external_health_retry_scheduling{false};
    std::uint64_t external_health_retry_epoch{0};
};

enum class UrltestSelectionChangeReason {
    initial,
    previous_unhealthy,
    healthy_rebalance,
};

struct UrltestSelectionChange {
    std::string urltest_tag;
    std::uint64_t probe_generation{0};
    std::string previous_child_tag;
    std::string new_child_tag;
    UrltestSelectionChangeReason reason{
        UrltestSelectionChangeReason::initial};
};

// Whether the retired child's conntrack entries should be removed after a
// committed selection switch.
//
// The default - no configured mode - removes them when the child was retired
// for being unhealthy. A degraded-but-UP child keeps its CONNMARK on every
// established flow, and with the old preserve default those flows kept routing
// into the dead child's table until conntrack expiry: the exact false-green
// shape the kill-switch exists to prevent (upstream 8ff85ec2 reached the same
// conclusion). An explicitly written "preserve" is still honoured - it is the
// operator's escape hatch, and unlike the default it is a stated choice.
//
// A nested selector child never gets the default cleanup: its mark is a group
// mark that other traffic may share, which is why explicit delete modes refuse
// nested children at validation. The default must not do what an explicit
// config is not allowed to say.
bool should_cleanup_retired_urltest_flows(
    const std::optional<ConntrackOnSwitch>& configured_mode,
    UrltestSelectionChangeReason reason,
    bool previous_child_is_selector) noexcept;

// Callback invoked when the selected outbound changes for a urltest. Returns
// true only after the controller has synchronously resolved the exact
// transition (by applying the candidate or converging to its live cursor). A
// false return or exception keeps the previously selected child authoritative
// so a later probe can retry. The immutable reason is computed from the same
// locked probe generation, and no UrltestManager lock is held during callback.
using UrltestChangeCallback =
    std::function<bool(const UrltestSelectionChange&)>;
// Returns true only when the controller accepted ownership of the exact probe
// generation. A false return (or an exception) leaves the manager responsible
// for abandoning that generation and releasing every begun circuit-breaker
// request.
using UrltestCommitCallback = std::function<bool(const std::string&,
                                                 std::uint64_t,
                                                 std::map<std::string, URLTestResult>,
                                                 TraceId)>;

// Manages periodic URL testing for urltest outbounds, tracks per-child-outbound
// latencies and circuit breaker states, and selects an outbound using the
// configured latency or declared-priority policy within weighted groups.
//
// All public methods are thread-safe.
class UrltestManager {
public:
    UrltestManager(URLTester& tester, const OutboundMarkMap& marks,
                   RepeatingTaskScheduler& scheduler,
                   BlockingExecutor& blocking_executor,
                   UrltestChangeCallback on_change,
                   UrltestCommitCallback on_commit);
    ~UrltestManager();

    UrltestManager(const UrltestManager&) = delete;
    UrltestManager& operator=(const UrltestManager&) = delete;

    // Register a urltest outbound, queue the initial URL test, and schedule
    // periodic retests. A successful initial selection invokes on_change_
    // asynchronously when its probe result is committed.
    void register_urltest(
        const Outbound& ut,
        std::string initial_selected_outbound = {},
        const UrltestDirectChildInterfaceMap& direct_child_interfaces = {});

    // Run tests immediately for a specific urltest outbound (e.g. on SIGUSR1).
    // Invokes on_change_ if the selection changes.
    void trigger_immediate_test(const std::string& urltest_tag);
    // A reachability transition from InterfaceProbe must not disappear merely
    // because a URLTEST probe was already in flight. Multiple such requests
    // coalesce, and transient admission/commit failures receive a bounded
    // retry. This deliberately has stronger semantics than the manual trigger
    // above, whose reentrant calls remain suppressed.
    void trigger_external_health_test(
        const std::string& urltest_tag) noexcept;
    bool commit_probe_results(const std::string& urltest_tag,
                              std::uint64_t generation,
                              std::map<std::string, URLTestResult> results);

#ifdef KEEN_PBR3_TESTING
    // Deterministic strong-guarantee regression hook: fail after the candidate
    // state was mutated but before any of it becomes authoritative.
    void fail_next_commit_after_prepare_for_testing();
#endif

    // Return the currently selected child outbound tag, or "" if none.
    std::string get_selected(const std::string& urltest_tag) const;

    // Return a state snapshot for API/status reporting.
    // Returns std::nullopt if the tag is not registered.
    std::optional<UrltestState> get_state(const std::string& urltest_tag) const;

    // Align the manager's transition cursor with the child which is actually
    // applied in the kernel. This is used after a failed transactional switch;
    // probe health/results remain intact and the next probe can retry from the
    // applied path.
    bool synchronize_selected(const std::string& urltest_tag,
                              const std::string& selected_outbound);
    // Generation-fenced variant used by an asynchronously admitted selection
    // transition. A stale callback must never overwrite a later registration.
    bool synchronize_selected_if_generation(
        const std::string& urltest_tag,
        std::uint64_t expected_generation,
        const std::string& selected_outbound);

    // Cancel all scheduled tasks and unregister all outbounds.
    void clear();

private:
    struct ExternalHealthResolution {
        bool launch_trailing{false};
        bool ensure_retry{false};
        int retry_task_to_cancel{-1};
    };

    // Check whether an async probe still belongs to the currently registered
    // state for the given tag. Caller must hold at least a shared_lock.
    bool is_probe_current(const std::string& tag,
                          std::uint64_t generation) const REQUIRES_SHARED(mutex_);

    // Run URL tests for all child outbounds of the given urltest and update
    // the internal selection. Returns the new selection if it changed.
    // Must NOT be called while holding mutex_.
    bool queue_probe_unlocked(const std::string& tag, const std::string& reason);

    // Release one exact probe generation after a worker/admission failure.
    // Stale workers cannot affect a later registration because the generation
    // is checked while holding mutex_.
    void abandon_probe(const std::string& tag,
                       std::uint64_t generation,
                       const std::vector<std::string>& candidate_tags) noexcept;
    void abandon_probe_results(
        const std::string& tag,
        std::uint64_t generation,
        const std::map<std::string, URLTestResult>& results) noexcept;

    // External-health request lifecycle. All scheduler and queue calls happen
    // without mutex_ held; the small state transitions themselves are exact
    // generation/serial updates under mutex_.
    void ensure_external_health_retry(const std::string& tag) noexcept;
    void run_external_health_retry(
        const std::string& tag,
        int registration_task_id,
        std::uint64_t retry_epoch) noexcept;
    void try_start_external_health_probe(const std::string& tag) noexcept;
    void record_external_health_start_failure(
        const std::string& tag,
        std::uint8_t expected_failures) noexcept;
    void record_claimed_external_health_failure_locked(
        UrltestState& state) noexcept;
    ExternalHealthResolution finish_external_health_probe_locked(
        UrltestState& state,
        bool controller_admitted) noexcept;
    void cancel_scheduler_task(int task_id) noexcept;

    // Periodic test entry point (called by the scheduler).
    // Runs tests and invokes on_change_ if the selection changes.
    void run_tests(const std::string& tag);

    // Select an outbound using weighted groups and the configured selection mode.
    // Caller must hold at least a shared_lock on mutex_.
    std::string select_outbound(const std::string& tag) REQUIRES_SHARED(mutex_);
    static std::string select_outbound_from_state(const UrltestState& state);

    URLTester& tester_;
    const OutboundMarkMap& marks_;
    RepeatingTaskScheduler& scheduler_;
    BlockingExecutor& blocking_executor_;
    UrltestChangeCallback on_change_;
    UrltestCommitCallback on_commit_;

    mutable TracedSharedMutex mutex_;
    std::map<std::string, UrltestState> states_ GUARDED_BY(mutex_);
    std::uint64_t generation_ GUARDED_BY(mutex_){1};
#ifdef KEEN_PBR3_TESTING
    bool fail_next_commit_after_prepare_ GUARDED_BY(mutex_){false};
#endif
};

} // namespace keen_pbr3
