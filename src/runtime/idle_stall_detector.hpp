#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace keen_pbr3 {

enum class IdleStallAddressFamily : std::uint8_t {
    ipv4,
    ipv6,
};

enum class IdleStallProtocol : std::uint8_t {
    tcp,
    udp,
};

enum class IdleStallFlowReadiness : std::uint8_t {
    ineligible,
    tcp_established,
    udp_assured,
};

enum class IdleStallRecoveryPolicy : std::uint8_t {
    standard,
    packaged_whatsapp_ip_companion,
    packaged_meta_quic,
};

struct IdleStallFlowKey {
    IdleStallAddressFamily family{IdleStallAddressFamily::ipv4};
    IdleStallProtocol protocol{IdleStallProtocol::tcp};
    std::string source;
    std::string destination;
    std::uint16_t source_port{0};
    std::uint16_t destination_port{0};
    std::uint32_t full_mark{0};

    bool operator==(const IdleStallFlowKey& other) const noexcept {
        return family == other.family &&
               protocol == other.protocol &&
               source == other.source &&
               destination == other.destination &&
               source_port == other.source_port &&
               destination_port == other.destination_port &&
               full_mark == other.full_mark;
    }

    bool operator<(const IdleStallFlowKey& other) const noexcept {
        return std::tie(family,
                        protocol,
                        source,
                        destination,
                        source_port,
                        destination_port,
                        full_mark) <
               std::tie(other.family,
                        other.protocol,
                        other.source,
                        other.destination,
                        other.source_port,
                        other.destination_port,
                        other.full_mark);
    }
};

struct IdleStallFlowCounters {
    std::uint64_t original_packets{0};
    std::uint64_t original_bytes{0};
    std::uint64_t reply_packets{0};
    std::uint64_t reply_bytes{0};
};

struct IdleStallFlowSample {
    IdleStallFlowKey key;
    IdleStallFlowCounters counters;
    IdleStallFlowReadiness readiness{
        IdleStallFlowReadiness::ineligible};
    bool fastnat{false};
    IdleStallRecoveryPolicy recovery_policy{
        IdleStallRecoveryPolicy::standard};
};

struct IdleStallEpoch {
    std::uint64_t runtime_generation{0};
    std::uint64_t coverage_generation{0};

    bool valid() const noexcept {
        return runtime_generation != 0U && coverage_generation != 0U;
    }

    bool operator==(const IdleStallEpoch& other) const noexcept {
        return runtime_generation == other.runtime_generation &&
               coverage_generation == other.coverage_generation;
    }

    bool operator!=(const IdleStallEpoch& other) const noexcept {
        return !(*this == other);
    }
};

struct IdleStallScanStatus {
    bool snapshot_complete{true};
    bool counters_available{true};
    bool local_scope_complete{true};
    bool coverage_complete{true};

    bool trustworthy() const noexcept {
        return snapshot_complete && counters_available &&
               local_scope_complete && coverage_complete;
    }
};

struct IdleStallScan {
    IdleStallEpoch epoch;
    std::uint32_t owned_mark_mask{0};
    IdleStallScanStatus status;
    std::vector<IdleStallFlowSample> flows;
};

enum class IdleStallDecisionReason : std::uint8_t {
    idle_request_without_reply,
    idle_meta_quic_request_without_meaningful_reply,
    idle_fastnat_rotation,
};

struct IdleStallDeleteDecision {
    IdleStallFlowKey flow;
    IdleStallDecisionReason reason{
        IdleStallDecisionReason::idle_request_without_reply};
    IdleStallEpoch epoch;
    std::uint64_t attempt_id{0};
    IdleStallRecoveryPolicy recovery_policy{
        IdleStallRecoveryPolicy::standard};
};

struct IdleStallDetectorOptions {
    // Strong reconnect is enabled only for provenance-qualified list
    // policies. Thirty seconds keeps the ordinary/WhatsApp recovery window
    // short without turning the observer into a per-packet watchdog.
    std::chrono::seconds idle_threshold{30};
    std::chrono::seconds confirmation_delay{5};
    // Latency-sensitive packaged policies may request one early confirmation
    // scan. The ordinary cadence and every safety/rate boundary remain
    // unchanged.
    std::chrono::seconds whatsapp_confirmation_delay{1};
    // The packaged Meta profile is provenance-qualified by the caller and
    // applies only to UDP/443. It may detect a stale reused QUIC tuple sooner,
    // while the exact-delete path still waits for a separate one-shot
    // confirmation and live counter revalidation.
    std::chrono::seconds meta_quic_idle_threshold{15};
    std::chrono::seconds meta_quic_confirmation_delay{1};
    bool rotate_idle_fastnat_tcp{true};
    std::chrono::seconds fastnat_idle_rotation_threshold{30};
    // Active bidirectional UDP refreshes this guard on every five-second
    // observation. Keep only a short tail after the last media progress so a
    // completed call cannot suppress stale signalling recovery for minutes.
    std::chrono::seconds active_media_hold{15};
    // Bound repeated recovery for one client without leaving a newly stalled
    // replacement tuple untouched for two minutes.
    std::chrono::seconds source_cooldown{30};
    std::chrono::seconds meta_quic_source_cooldown{90};
    std::chrono::seconds global_rate_window{60};
    // Small bidirectional control exchanges must not make a long-idle
    // application flow look healthy. A direction has application progress
    // only when its byte delta for one complete scan exceeds this threshold.
    std::uint64_t tiny_keepalive_max_bytes_per_direction{256};
    std::size_t max_tracked_flows{256};
    std::size_t max_decisions_per_scan{2};
    std::size_t max_decisions_per_rate_window{8};
};

// Pure, bounded state machine for detecting a previously healthy forwarded
// flow which was idle, was reused by its client, and then received no reply.
// It performs no IO and never deletes anything itself. Callers remain
// responsible for observing only destination-covered forwarded flows and for
// applying returned decisions with a generation-fenced exact-tuple delete.
class IdleStallDetector {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    explicit IdleStallDetector(IdleStallDetectorOptions options = {})
        : options_(std::move(options)) {
        validate_options();
    }

    std::vector<IdleStallDeleteDecision> observe(
        const IdleStallScan& scan,
        TimePoint now) {
        // The fast hint belongs to one completed observation. If its caller
        // did not consume it before another snapshot arrived, it is stale and
        // must not create a delayed burst of one-second scans.
        latency_fast_followup_delay_.reset();
        prune_limits(now);

        if (!scan.epoch.valid() || scan.owned_mark_mask == 0U ||
            !scan.status.trustworthy() ||
            scan.flows.size() > options_.max_tracked_flows) {
            reset_observation_continuity();
            if (scan.epoch.valid()) {
                active_epoch_ = scan.epoch;
            } else {
                active_epoch_.reset();
            }
            return {};
        }

        if (!active_epoch_.has_value() ||
            *active_epoch_ != scan.epoch) {
            reset_observation_continuity();
            active_epoch_ = scan.epoch;
        }

        std::set<IdleStallFlowKey> unique_keys;
        for (const auto& sample : scan.flows) {
            if (!valid_key(sample.key) ||
                !unique_keys.insert(sample.key).second) {
                reset_observation_continuity();
                active_epoch_ = scan.epoch;
                return {};
            }
        }

        struct PreparedSample {
            const IdleStallFlowSample* sample{nullptr};
            FlowState* state{nullptr};
            bool baseline{false};
            bool original_grew{false};
            bool reply_grew{false};
            bool original_application_progress{false};
            bool reply_application_progress{false};
            bool was_idle{false};
        };

        std::vector<PreparedSample> prepared;
        prepared.reserve(scan.flows.size());
        std::set<IdleStallFlowKey> observed_keys;

        for (const auto& sample : scan.flows) {
            if (!eligible_sample(sample, scan.owned_mark_mask)) {
                continue;
            }
            observed_keys.insert(sample.key);
            auto [iterator, inserted] = states_.try_emplace(
                sample.key,
                FlowState{sample.counters,
                          now,
                          std::nullopt,
                          sample.recovery_policy});
            auto& state = iterator->second;
            if (inserted || counters_regressed(sample.counters,
                                               state.counters) ||
                state.recovery_policy != sample.recovery_policy) {
                pending_attempts_.erase(sample.key);
                state = FlowState{sample.counters,
                                  now,
                                  std::nullopt,
                                  sample.recovery_policy};
                prepared.push_back(
                    PreparedSample{&sample, &state, true, false, false,
                                   false, false, false});
                continue;
            }

            const bool original_grew =
                sample.counters.original_packets >
                    state.counters.original_packets ||
                sample.counters.original_bytes >
                    state.counters.original_bytes;
            const bool reply_grew =
                sample.counters.reply_packets >
                    state.counters.reply_packets ||
                sample.counters.reply_bytes > state.counters.reply_bytes;
            const std::uint64_t original_byte_delta =
                sample.counters.original_bytes -
                state.counters.original_bytes;
            const std::uint64_t reply_byte_delta =
                sample.counters.reply_bytes - state.counters.reply_bytes;
            prepared.push_back(PreparedSample{
                &sample,
                &state,
                false,
                original_grew,
                reply_grew,
                original_byte_delta >
                    options_.tiny_keepalive_max_bytes_per_direction,
                reply_byte_delta >
                    options_.tiny_keepalive_max_bytes_per_direction,
                now - state.last_activity_at >=
                    idle_threshold_for(sample.recovery_policy)});
        }

        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (observed_keys.count(iterator->first) == 0U) {
                pending_attempts_.erase(iterator->first);
                iterator = states_.erase(iterator);
            } else {
                ++iterator;
            }
        }

        // Establish source-wide media protection before evaluating any flow.
        // This makes the result independent of /proc line ordering: a TCP
        // signalling flow cannot be retired merely because it appeared before
        // the bidirectionally active UDP media flow in the same snapshot.
        for (const auto& current : prepared) {
            if (current.baseline ||
                current.sample->key.protocol != IdleStallProtocol::udp ||
                !current.original_grew || !current.reply_grew) {
                continue;
            }
            const auto source = source_key(current.sample->key);
            const auto protected_until = now + options_.active_media_hold;
            auto& current_until = active_media_until_[source];
            current_until = std::max(current_until, protected_until);
            if (current.reply_application_progress) {
                auto& application_until =
                    active_reply_media_until_[source];
                application_until =
                    std::max(application_until, protected_until);
            }
        }

        struct Candidate {
            IdleStallFlowKey key;
            IdleStallDecisionReason reason{
                IdleStallDecisionReason::idle_request_without_reply};
        };
        std::vector<Candidate> candidates;
        for (auto& current : prepared) {
            if (current.baseline) {
                continue;
            }
            auto& state = *current.state;
            const auto source = source_key(current.sample->key);
            const bool meta_quic_policy =
                state.recovery_policy ==
                IdleStallRecoveryPolicy::packaged_meta_quic;
            const auto& media_guard = meta_quic_policy
                ? active_reply_media_until_
                : active_media_until_;
            const bool media_protected =
                media_guard.count(source) != 0U &&
                now < media_guard.at(source);

            if (media_protected ||
                current.reply_application_progress) {
                state.suspect_since.reset();
                pending_attempts_.erase(current.sample->key);
            } else if (state.suspect_since.has_value()) {
                if (now - *state.suspect_since >=
                    confirmation_delay_for(state.recovery_policy)) {
                    candidates.push_back(Candidate{
                        current.sample->key,
                        meta_quic_policy
                            ? IdleStallDecisionReason::
                                  idle_meta_quic_request_without_meaningful_reply
                            : IdleStallDecisionReason::
                                  idle_request_without_reply});
                }
            } else if (current.was_idle &&
                       current.original_application_progress) {
                state.suspect_since = now;
                if (state.recovery_policy ==
                        IdleStallRecoveryPolicy::
                            packaged_whatsapp_ip_companion ||
                    state.recovery_policy ==
                        IdleStallRecoveryPolicy::packaged_meta_quic) {
                    const auto requested_delay =
                        confirmation_delay_for(state.recovery_policy);
                    if (!latency_fast_followup_delay_.has_value() ||
                        requested_delay < *latency_fast_followup_delay_) {
                        latency_fast_followup_delay_ = requested_delay;
                    }
                }
            } else if (options_.rotate_idle_fastnat_tcp &&
                       current.sample->fastnat &&
                       current.sample->key.protocol ==
                           IdleStallProtocol::tcp &&
                       current.original_grew &&
                       current.reply_grew &&
                       !current.original_application_progress &&
                       !current.reply_application_progress &&
                       now - state.last_activity_at >=
                           options_.fastnat_idle_rotation_threshold) {
                candidates.push_back(Candidate{
                    current.sample->key,
                    IdleStallDecisionReason::idle_fastnat_rotation});
            }

            if (current.original_application_progress ||
                current.reply_application_progress) {
                state.last_activity_at = now;
            }
            state.counters = current.sample->counters;
        }

        std::sort(
            candidates.begin(),
            candidates.end(),
            [this](const Candidate& left,
                   const Candidate& right) {
                const auto left_since =
                    states_.at(left.key).suspect_since;
                const auto right_since =
                    states_.at(right.key).suspect_since;
                if (left_since != right_since) {
                    return left_since < right_since;
                }
                return left.key < right.key;
            });

        const std::size_t committed_and_reserved = std::min(
            options_.max_decisions_per_rate_window,
            decision_times_.size() + pending_attempts_.size());
        const std::size_t global_capacity =
            options_.max_decisions_per_rate_window -
            committed_and_reserved;
        const bool committed_rate_limit_reached =
            decision_times_.size() >=
            options_.max_decisions_per_rate_window;
        const std::size_t decision_limit = std::min(
            options_.max_decisions_per_scan,
            global_capacity);
        std::vector<IdleStallDeleteDecision> decisions;
        decisions.reserve(std::min(decision_limit, candidates.size()));

        for (const auto& candidate : candidates) {
            auto& state = states_.at(candidate.key);
            const auto source = source_key(candidate.key);
            const auto cooldown = source_cooldown_until_.find(
                cooldown_key(candidate.key, state.recovery_policy));
            if (cooldown != source_cooldown_until_.end() &&
                now < cooldown->second) {
                // A source in cooldown must generate a new post-idle request
                // after the cooldown instead of carrying an old suspect over.
                state.suspect_since.reset();
                state.last_activity_at = now;
                continue;
            }
            const bool source_has_pending_attempt = std::any_of(
                pending_attempts_.begin(),
                pending_attempts_.end(),
                [&source](const auto& pending) {
                    return source_key(pending.first).family == source.family &&
                           source_key(pending.first).source == source.source;
                });
            if (source_has_pending_attempt) {
                continue;
            }
            if (decisions.size() >= decision_limit) {
                if (committed_rate_limit_reached) {
                    // A global safety limit is fail-closed. Do not release a
                    // latent deletion when the window expires without a new
                    // client request.
                    state.suspect_since.reset();
                    state.last_activity_at = now;
                }
                continue;
            }

            const std::uint64_t attempt_id = allocate_attempt_id();
            decisions.push_back(IdleStallDeleteDecision{
                candidate.key,
                candidate.reason,
                scan.epoch,
                attempt_id,
                state.recovery_policy});
            pending_attempts_[candidate.key] = PendingAttempt{
                scan.epoch,
                candidate.reason,
                attempt_id,
                state.recovery_policy};
        }

        return decisions;
    }

    // Commit rate/cooldown accounting only after the caller confirms that the
    // generation-fenced exact delete succeeded. A recognized failure merely
    // releases the bounded reservation so the same still-suspect flow may be
    // retried on a later scan. Stale, duplicate and cross-epoch acknowledgments
    // are rejected and cannot consume safety tokens.
    bool acknowledge_delete_result(
        const IdleStallDeleteDecision& decision,
        bool delete_succeeded,
        TimePoint now) {
        if (!active_epoch_.has_value() ||
            decision.epoch != *active_epoch_ ||
            decision.attempt_id == 0U) {
            return false;
        }
        const auto pending = pending_attempts_.find(decision.flow);
        if (pending == pending_attempts_.end() ||
            pending->second.epoch != decision.epoch ||
            pending->second.reason != decision.reason ||
            pending->second.attempt_id != decision.attempt_id ||
            pending->second.recovery_policy != decision.recovery_policy) {
            return false;
        }
        pending_attempts_.erase(pending);
        if (!delete_succeeded) {
            return true;
        }

        prune_limits(now);
        decision_times_.push_back(now);
        const auto source = source_key(decision.flow);
        const auto cooldown_until =
            now + source_cooldown_for(decision.recovery_policy);
        auto& current_until = source_cooldown_until_[cooldown_key(
            decision.flow, decision.recovery_policy)];
        current_until = std::max(current_until, cooldown_until);
        // Preserve the historical source-wide ordinary/WhatsApp cooldown,
        // while isolating the packaged Meta QUIC policy. Recovering media must
        // not suppress a WhatsApp reconnect on the same phone (or vice versa).
        for (auto& [key, state] : states_) {
            if (source_key(key).family != source.family ||
                source_key(key).source != source.source ||
                cooldown_key(key, state.recovery_policy).category !=
                    cooldown_key(
                        decision.flow, decision.recovery_policy).category) {
                continue;
            }
            state.suspect_since.reset();
            state.last_activity_at = now;
        }
        return true;
    }

    void reset() noexcept {
        active_epoch_.reset();
        states_.clear();
        active_media_until_.clear();
        active_reply_media_until_.clear();
        pending_attempts_.clear();
        source_cooldown_until_.clear();
        decision_times_.clear();
        latency_fast_followup_delay_.reset();
    }

    std::size_t tracked_flow_count() const noexcept {
        return states_.size();
    }

    // Backward-compatible name retained for focused WhatsApp tests and callers
    // outside the daemon. The hint may now also originate from the separately
    // provenance-qualified packaged Meta QUIC policy.
    std::optional<std::chrono::seconds>
    take_whatsapp_fast_followup_delay() noexcept {
        return take_latency_sensitive_fast_followup_delay();
    }

    std::optional<std::chrono::seconds>
    take_latency_sensitive_fast_followup_delay() noexcept {
        if (!latency_fast_followup_delay_.has_value()) {
            return std::nullopt;
        }
        const auto delay = latency_fast_followup_delay_;
        latency_fast_followup_delay_.reset();
        return delay;
    }

private:
    struct SourceKey {
        IdleStallAddressFamily family{IdleStallAddressFamily::ipv4};
        std::string source;

        bool operator<(const SourceKey& other) const noexcept {
            return std::tie(family, source) <
                   std::tie(other.family, other.source);
        }
    };

    enum class CooldownClass : std::uint8_t {
        ordinary_and_whatsapp,
        meta_quic,
    };

    struct CooldownKey {
        SourceKey source;
        CooldownClass category{
            CooldownClass::ordinary_and_whatsapp};

        bool operator<(const CooldownKey& other) const noexcept {
            return std::tie(source.family, source.source, category) <
                   std::tie(other.source.family,
                            other.source.source,
                            other.category);
        }
    };

    struct FlowState {
        IdleStallFlowCounters counters;
        TimePoint last_activity_at;
        std::optional<TimePoint> suspect_since;
        IdleStallRecoveryPolicy recovery_policy{
            IdleStallRecoveryPolicy::standard};
    };

    struct PendingAttempt {
        IdleStallEpoch epoch;
        IdleStallDecisionReason reason{
            IdleStallDecisionReason::idle_request_without_reply};
        std::uint64_t attempt_id{0};
        IdleStallRecoveryPolicy recovery_policy{
            IdleStallRecoveryPolicy::standard};
    };

    static SourceKey source_key(const IdleStallFlowKey& key) {
        return SourceKey{key.family, key.source};
    }

    static CooldownKey cooldown_key(
        const IdleStallFlowKey& key,
        IdleStallRecoveryPolicy policy) {
        return CooldownKey{
            source_key(key),
            policy == IdleStallRecoveryPolicy::packaged_meta_quic
                ? CooldownClass::meta_quic
                : CooldownClass::ordinary_and_whatsapp};
    }

    static bool valid_key(const IdleStallFlowKey& key) noexcept {
        return !key.source.empty() && !key.destination.empty() &&
               key.source_port != 0U && key.destination_port != 0U;
    }

    static bool eligible_sample(const IdleStallFlowSample& sample,
                                std::uint32_t owned_mark_mask) noexcept {
        if (sample.recovery_policy ==
                IdleStallRecoveryPolicy::packaged_meta_quic &&
            (sample.key.protocol != IdleStallProtocol::udp ||
             sample.key.destination_port != 443U)) {
            return false;
        }
        const bool state_matches_protocol =
            (sample.key.protocol == IdleStallProtocol::tcp &&
             sample.readiness ==
                 IdleStallFlowReadiness::tcp_established) ||
            (sample.key.protocol == IdleStallProtocol::udp &&
             sample.readiness == IdleStallFlowReadiness::udp_assured);
        if (!state_matches_protocol) {
            return false;
        }
        if (sample.key.full_mark == 0U) {
            return true;
        }
        const bool contains_owned_bits =
            (sample.key.full_mark & owned_mark_mask) != 0U;
        const bool contains_foreign_bits =
            (sample.key.full_mark & ~owned_mark_mask) != 0U;
        return contains_owned_bits && !contains_foreign_bits;
    }

    static bool counters_regressed(
        const IdleStallFlowCounters& current,
        const IdleStallFlowCounters& previous) noexcept {
        return current.original_packets < previous.original_packets ||
               current.original_bytes < previous.original_bytes ||
               current.reply_packets < previous.reply_packets ||
               current.reply_bytes < previous.reply_bytes;
    }

    std::chrono::seconds confirmation_delay_for(
        IdleStallRecoveryPolicy policy) const noexcept {
        if (policy == IdleStallRecoveryPolicy::
                          packaged_whatsapp_ip_companion) {
            return options_.whatsapp_confirmation_delay;
        }
        if (policy ==
            IdleStallRecoveryPolicy::packaged_meta_quic) {
            return options_.meta_quic_confirmation_delay;
        }
        return options_.confirmation_delay;
    }

    std::chrono::seconds idle_threshold_for(
        IdleStallRecoveryPolicy policy) const noexcept {
        return policy ==
                       IdleStallRecoveryPolicy::packaged_meta_quic
            ? options_.meta_quic_idle_threshold
            : options_.idle_threshold;
    }

    std::chrono::seconds source_cooldown_for(
        IdleStallRecoveryPolicy policy) const noexcept {
        return policy ==
                       IdleStallRecoveryPolicy::packaged_meta_quic
            ? options_.meta_quic_source_cooldown
            : options_.source_cooldown;
    }

    void reset_observation_continuity() noexcept {
        states_.clear();
        active_media_until_.clear();
        active_reply_media_until_.clear();
        pending_attempts_.clear();
        latency_fast_followup_delay_.reset();
    }

    std::uint64_t allocate_attempt_id() noexcept {
        ++next_attempt_id_;
        if (next_attempt_id_ == 0U) {
            ++next_attempt_id_;
        }
        return next_attempt_id_;
    }

    void prune_limits(TimePoint now) {
        while (!decision_times_.empty() &&
               now - decision_times_.front() >=
                   options_.global_rate_window) {
            decision_times_.pop_front();
        }
        for (auto iterator = source_cooldown_until_.begin();
             iterator != source_cooldown_until_.end();) {
            if (now >= iterator->second) {
                iterator = source_cooldown_until_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        for (auto iterator = active_media_until_.begin();
             iterator != active_media_until_.end();) {
            if (now >= iterator->second) {
                iterator = active_media_until_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        for (auto iterator = active_reply_media_until_.begin();
             iterator != active_reply_media_until_.end();) {
            if (now >= iterator->second) {
                iterator = active_reply_media_until_.erase(iterator);
            } else {
                ++iterator;
            }
        }
    }

    void validate_options() const {
        if (options_.idle_threshold <= std::chrono::seconds::zero() ||
            options_.confirmation_delay <= std::chrono::seconds::zero() ||
            options_.whatsapp_confirmation_delay <=
                std::chrono::seconds::zero() ||
            options_.whatsapp_confirmation_delay >
                options_.confirmation_delay ||
            options_.meta_quic_idle_threshold <=
                std::chrono::seconds::zero() ||
            options_.meta_quic_confirmation_delay <=
                std::chrono::seconds::zero() ||
            options_.meta_quic_confirmation_delay >
                options_.confirmation_delay ||
            options_.fastnat_idle_rotation_threshold <=
                std::chrono::seconds::zero() ||
            options_.active_media_hold <= std::chrono::seconds::zero() ||
            options_.source_cooldown <= std::chrono::seconds::zero() ||
            options_.meta_quic_source_cooldown <=
                std::chrono::seconds::zero() ||
            options_.global_rate_window <= std::chrono::seconds::zero() ||
            options_.max_tracked_flows == 0U ||
            options_.max_decisions_per_scan == 0U ||
            options_.max_decisions_per_rate_window == 0U) {
            throw std::invalid_argument(
                "IdleStallDetector options must be positive");
        }
    }

    IdleStallDetectorOptions options_;
    std::optional<IdleStallEpoch> active_epoch_;
    std::map<IdleStallFlowKey, FlowState> states_;
    std::map<SourceKey, TimePoint> active_media_until_;
    std::map<SourceKey, TimePoint> active_reply_media_until_;
    std::map<IdleStallFlowKey, PendingAttempt> pending_attempts_;
    std::map<CooldownKey, TimePoint> source_cooldown_until_;
    std::deque<TimePoint> decision_times_;
    std::uint64_t next_attempt_id_{0};
    std::optional<std::chrono::seconds> latency_fast_followup_delay_;
};

// Revalidation must preserve the historical broad UDP-media protection for
// ordinary/WhatsApp recovery, but a Meta QUIC keepalive on the exact stalled
// tuple is not proof that application delivery resumed. A newly appeared
// bidirectional flow is always protected; an existing Meta flow needs
// meaningful downstream byte progress.
inline bool idle_stall_live_media_progress_protects(
    IdleStallRecoveryPolicy policy,
    const IdleStallFlowCounters& current,
    const std::optional<IdleStallFlowCounters>& baseline,
    std::uint64_t application_reply_threshold = 256U) noexcept {
    if (!baseline.has_value()) {
        return current.original_packets != 0U &&
               current.reply_packets != 0U;
    }
    if (current.original_packets < baseline->original_packets ||
        current.original_bytes < baseline->original_bytes ||
        current.reply_packets < baseline->reply_packets ||
        current.reply_bytes < baseline->reply_bytes) {
        return false;
    }
    if (policy == IdleStallRecoveryPolicy::packaged_meta_quic) {
        return current.reply_bytes - baseline->reply_bytes >
               application_reply_threshold;
    }
    const bool original_progress =
        current.original_packets > baseline->original_packets ||
        current.original_bytes > baseline->original_bytes;
    const bool reply_progress =
        current.reply_packets > baseline->reply_packets ||
        current.reply_bytes > baseline->reply_bytes;
    return original_progress && reply_progress;
}

using IdleStallMediaBaselines =
    std::map<IdleStallFlowKey, IdleStallFlowCounters>;

inline IdleStallMediaBaselines idle_stall_media_baselines_from(
    const std::vector<IdleStallFlowSample>& samples) {
    IdleStallMediaBaselines baselines;
    for (const auto& sample : samples) {
        if (sample.key.protocol != IdleStallProtocol::udp ||
            sample.readiness != IdleStallFlowReadiness::udp_assured) {
            continue;
        }
        const auto [iterator, inserted] =
            baselines.emplace(sample.key, sample.counters);
        if (!inserted) {
            // Both semantic views come from one snapshot and normally carry
            // identical counters. Keep the maxima if they ever differ so a
            // later regression fails closed instead of inventing progress.
            iterator->second.original_packets = std::max(
                iterator->second.original_packets,
                sample.counters.original_packets);
            iterator->second.original_bytes = std::max(
                iterator->second.original_bytes,
                sample.counters.original_bytes);
            iterator->second.reply_packets = std::max(
                iterator->second.reply_packets,
                sample.counters.reply_packets);
            iterator->second.reply_bytes = std::max(
                iterator->second.reply_bytes,
                sample.counters.reply_bytes);
        }
    }
    return baselines;
}

// Meta revalidation is exact-tuple aware. Tiny bidirectional progress on the
// pending QUIC tuple is still a keepalive and does not block recovery. A
// different existing UDP tuple retains the historical broad call guard, a
// genuinely new bidirectional tuple protects immediately, and meaningful
// downstream progress on the pending tuple protects it directly.
inline bool idle_stall_live_media_flow_protects_pending(
    IdleStallRecoveryPolicy pending_policy,
    const IdleStallFlowKey& pending_key,
    const IdleStallFlowSample& current,
    const IdleStallMediaBaselines& baselines,
    std::uint64_t application_reply_threshold = 256U) noexcept {
    if (current.key.protocol != IdleStallProtocol::udp ||
        current.readiness != IdleStallFlowReadiness::udp_assured ||
        current.key.family != pending_key.family ||
        current.key.source != pending_key.source) {
        return false;
    }

    const auto baseline = baselines.find(current.key);
    const std::optional<IdleStallFlowCounters> baseline_counters =
        baseline == baselines.end()
            ? std::nullopt
            : std::optional<IdleStallFlowCounters>{baseline->second};
    const auto progress_policy =
        pending_policy == IdleStallRecoveryPolicy::packaged_meta_quic &&
                current.key == pending_key
            ? IdleStallRecoveryPolicy::packaged_meta_quic
            : IdleStallRecoveryPolicy::standard;
    return idle_stall_live_media_progress_protects(
        progress_policy,
        current.counters,
        baseline_counters,
        application_reply_threshold);
}

} // namespace keen_pbr3
