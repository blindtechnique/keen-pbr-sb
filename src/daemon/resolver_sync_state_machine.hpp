#pragma once

#include "../api/generated/api_types.hpp"
#include "../dns/dns_txt_client.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct ResolverSyncSnapshot {
    std::string expected_hash;
    std::string actual_hash;
    std::optional<std::int64_t> actual_ts;
    std::optional<std::int64_t> last_probe_ts;
    std::optional<std::int64_t> apply_started_ts;
    std::optional<api::ResolverConfigSyncState> sync_state;
    api::ResolverConfigProbeStatus probe_status{api::ResolverConfigProbeStatus::UNKNOWN};
    api::ResolverLiveStatus live_status{api::ResolverLiveStatus::UNKNOWN};
};

// Exact, restorable state used to make a multi-stage runtime replacement
// transactional. Unlike ResolverSyncSnapshot, this also retains internal
// lifecycle flags and failure counters which affect subsequent probes.
struct ResolverSyncCheckpoint {
    std::string expected_hash;
    std::string actual_hash;
    std::optional<std::int64_t> actual_ts;
    std::optional<std::int64_t> last_probe_ts;
    std::optional<std::int64_t> apply_started_ts;
    api::ResolverConfigProbeStatus probe_status{
        api::ResolverConfigProbeStatus::UNKNOWN};
    int consecutive_probe_failures{0};
    bool runtime_active{true};
    bool resolver_configured{true};
};

class ResolverSyncStateMachine {
public:
    static constexpr std::int64_t kConvergingWindowSeconds = 15;

    void runtime_stopped();
    void resolver_not_configured();
    void expected_hash_updated(std::string expected_hash);
    void apply_started(std::int64_t ts, std::string expected_hash);
    void probe_succeeded(std::string actual_hash,
                         std::optional<std::int64_t> actual_ts,
                         std::optional<std::int64_t> probe_ts);
    void probe_failed(ResolverConfigHashProbeStatus status,
                      std::optional<std::int64_t> probe_ts);

    ResolverSyncSnapshot snapshot(std::int64_t now_ts) const;
    ResolverSyncCheckpoint checkpoint() const;
    void restore(const ResolverSyncCheckpoint& checkpoint);

    // How many probes in a row have failed. The caller uses this to decide
    // whether a failure is worth telling the user about: one is noise, several
    // in a row is a symptom.
    int consecutive_probe_failures() const {
        return consecutive_probe_failures_;
    }

    // A failure only discards what we already knew once it repeats. Clearing on
    // the first miss made a single lost datagram look like a stale resolver.
    static constexpr int kFailuresBeforeClearing = 3;

private:
    std::string expected_hash_;
    std::string actual_hash_;
    std::optional<std::int64_t> actual_ts_;
    std::optional<std::int64_t> last_probe_ts_;
    std::optional<std::int64_t> apply_started_ts_;
    api::ResolverConfigProbeStatus probe_status_{api::ResolverConfigProbeStatus::UNKNOWN};
    int consecutive_probe_failures_{0};
    bool runtime_active_{true};
    bool resolver_configured_{true};
};

api::ResolverConfigProbeStatus resolver_probe_status_from_hash_probe_status(
    ResolverConfigHashProbeStatus status);

// Probe timestamps are observability metadata. They do not change resolver
// health and must not fan out an otherwise identical runtime state over SSE.
bool resolver_sync_semantically_equal(const ResolverSyncSnapshot& lhs,
                                      const ResolverSyncSnapshot& rhs);

// Retry while the resolver generation has not converged. Attempts are
// zero-based: 1, 2, 4, 8, 16, 32, then 60 seconds. A successful mismatch
// remains actionable after the initial convergence window expires.
std::chrono::seconds resolver_convergence_retry_delay(std::uint32_t attempt);

// Side-effect-free policy for committing one resolver probe. The state
// machine remains authoritative for resolver health; this plan only decides
// whether the changed state is worth publishing and how the caller should
// advance its single convergence-retry timer.
struct ResolverProbeCommitPlan {
    bool publish_runtime_state{false};
    bool report_stale_txt_observation{false};
    bool schedule_convergence_retry{false};
    std::chrono::seconds convergence_retry_delay{0};
    std::uint32_t next_retry_attempt{0};
};

ResolverProbeCommitPlan plan_resolver_probe_commit(
    const ResolverSyncSnapshot& previous,
    const ResolverSyncSnapshot& current,
    std::uint32_t retry_attempt);

} // namespace keen_pbr3
