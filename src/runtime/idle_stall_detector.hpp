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
    // Exactly one realized, trusted mark owned by the immutable packaged
    // WhatsApp companion route may enable the preventive exact TCP-reset
    // actuator. Absence or ambiguity keeps it disabled for every client.
    std::optional<std::uint32_t> preventive_tcp_reset_owned_mark;
};

enum class IdleStallDecisionReason : std::uint8_t {
    idle_request_without_reply,
    idle_fastnat_rotation,
    idle_packaged_whatsapp_tcp_reset_rotation,
};

struct IdleStallDeleteDecision {
    IdleStallFlowKey flow;
    IdleStallDecisionReason reason{
        IdleStallDecisionReason::idle_request_without_reply};
    IdleStallEpoch epoch;
    std::uint64_t attempt_id{0};
};

struct IdleStallDetectorOptions {
    // Strong reconnect is currently enabled only for explicitly selected
    // latency-sensitive lists (the packaged WhatsApp IP companion). Thirty
    // seconds keeps the worst pre-emptive recovery window short without
    // turning the observer into a per-packet watchdog.
    std::chrono::seconds idle_threshold{30};
    std::chrono::seconds confirmation_delay{5};
    // The immutable packaged WhatsApp IP companion is the only policy that
    // may request one early confirmation scan. The ordinary cadence and every
    // safety/rate boundary remain unchanged.
    std::chrono::seconds whatsapp_confirmation_delay{1};
    bool rotate_idle_fastnat_tcp{true};
    std::chrono::seconds fastnat_idle_rotation_threshold{30};
    // Active bidirectional UDP refreshes this guard on every five-second
    // observation. Keep only a short tail after the last media progress so a
    // completed call cannot suppress stale signalling recovery for minutes.
    std::chrono::seconds active_media_hold{15};
    // Bound repeated recovery for one client without leaving a newly stalled
    // replacement tuple untouched for two minutes.
    std::chrono::seconds source_cooldown{30};
    std::chrono::seconds global_rate_window{60};
    // Small bidirectional control exchanges must not make a long-idle
    // application flow look healthy. A direction has application progress
    // only when its byte delta for one complete scan exceeds this threshold.
    std::uint64_t tiny_keepalive_max_bytes_per_direction{256};
    // A long-lived established TCP tuple that never grew beyond its initial
    // tiny handshake is the live WhatsApp failure mode seen on opted-in
    // Android senders. Absolute lifetime bounds prevent the preventive path
    // from rotating ordinary signalling or content transfers merely because
    // one observation interval was quiet.
    std::uint64_t preventive_tcp_reset_max_packets_per_direction{4};
    std::uint64_t preventive_tcp_reset_max_bytes_per_direction{512};
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
        whatsapp_fast_followup_requested_ = false;
        prune_limits(now);

        const bool preventive_authority_valid =
            !scan.preventive_tcp_reset_owned_mark.has_value() ||
            (*scan.preventive_tcp_reset_owned_mark != 0U &&
             (*scan.preventive_tcp_reset_owned_mark &
              ~scan.owned_mark_mask) == 0U);
        if (!scan.epoch.valid() || scan.owned_mark_mask == 0U ||
            !preventive_authority_valid ||
            !scan.status.trustworthy() ||
            scan.flows.size() > options_.max_tracked_flows) {
            reset_observation_continuity();
            if (scan.epoch.valid()) {
                active_epoch_ = scan.epoch;
                active_preventive_tcp_reset_owned_mark_ =
                    scan.preventive_tcp_reset_owned_mark;
            } else {
                active_epoch_.reset();
                active_preventive_tcp_reset_owned_mark_.reset();
            }
            return {};
        }

        if (!active_epoch_.has_value() ||
            *active_epoch_ != scan.epoch) {
            reset_observation_continuity();
            active_epoch_ = scan.epoch;
            active_preventive_tcp_reset_owned_mark_ =
                scan.preventive_tcp_reset_owned_mark;
        } else if (active_preventive_tcp_reset_owned_mark_ !=
                   scan.preventive_tcp_reset_owned_mark) {
            // Authority is part of the observation identity. Enabling,
            // disabling or changing the realized mark on unchanged CIDRs must
            // establish a fresh full quiet baseline before any exact reset.
            reset_observation_continuity();
            active_preventive_tcp_reset_owned_mark_ =
                scan.preventive_tcp_reset_owned_mark;
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
            bool counters_unchanged_for_idle{false};
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
                                  now,
                                  std::nullopt,
                                  sample.recovery_policy};
                prepared.push_back(
                    PreparedSample{&sample, &state, true, false, false,
                                   false, false, false, false});
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
                now - state.last_activity_at >= options_.idle_threshold,
                now - state.last_counter_change_at >=
                    options_.idle_threshold});
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
            const bool media_protected =
                active_media_until_.count(source) != 0U &&
                now < active_media_until_.at(source);

            if (media_protected ||
                current.reply_application_progress) {
                state.suspect_since.reset();
                pending_attempts_.erase(current.sample->key);
            } else if (state.suspect_since.has_value()) {
                if (now - *state.suspect_since >=
                    confirmation_delay_for(state.recovery_policy)) {
                    candidates.push_back(Candidate{
                        current.sample->key,
                        IdleStallDecisionReason::
                            idle_request_without_reply});
                }
            } else if (current.was_idle &&
                       current.original_application_progress) {
                state.suspect_since = now;
                if (state.recovery_policy ==
                    IdleStallRecoveryPolicy::
                        packaged_whatsapp_ip_companion) {
                    whatsapp_fast_followup_requested_ = true;
                }
            } else if (state.recovery_policy ==
                           IdleStallRecoveryPolicy::
                               packaged_whatsapp_ip_companion &&
                       scan.preventive_tcp_reset_owned_mark.has_value() &&
                       current.sample->key.full_mark ==
                           *scan.preventive_tcp_reset_owned_mark &&
                       current.sample->key.protocol ==
                           IdleStallProtocol::tcp &&
                       current.sample->key.destination_port == 443U &&
                       current.sample->key.full_mark != 0U &&
                       current.counters_unchanged_for_idle &&
                       !current.original_grew && !current.reply_grew &&
                       current.sample->counters.original_packets <=
                           options_.preventive_tcp_reset_max_packets_per_direction &&
                       current.sample->counters.reply_packets <=
                           options_.preventive_tcp_reset_max_packets_per_direction &&
                       current.sample->counters.original_bytes <=
                           options_.preventive_tcp_reset_max_bytes_per_direction &&
                       current.sample->counters.reply_bytes <=
                           options_.preventive_tcp_reset_max_bytes_per_direction &&
                       !current.original_application_progress &&
                       !current.reply_application_progress) {
                // This is deliberately narrower than FASTNAT rotation: only
                // an exact realized mark from the immutable packaged WhatsApp
                // companion may request the one-shot TCP reset.
                // A tuple must remain byte-for-byte unchanged for the full
                // threshold and stay within the tiny lifetime envelope. The
                // exact 2/2 handshake-only live failure qualifies; ordinary
                // dormant application flows and one-way activity do not.
                candidates.push_back(Candidate{
                    current.sample->key,
                    IdleStallDecisionReason::
                        idle_packaged_whatsapp_tcp_reset_rotation});
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
            if (current.original_grew || current.reply_grew) {
                state.last_counter_change_at = now;
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
            const auto cooldown = source_cooldown_until_.find(source);
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
                attempt_id});
            pending_attempts_[candidate.key] = PendingAttempt{
                scan.epoch,
                candidate.reason,
                attempt_id};
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
            pending->second.attempt_id != decision.attempt_id) {
            return false;
        }
        pending_attempts_.erase(pending);
        if (!delete_succeeded) {
            return true;
        }

        prune_limits(now);
        decision_times_.push_back(now);
        const auto source = source_key(decision.flow);
        const auto cooldown_until = now + options_.source_cooldown;
        auto& current_until = source_cooldown_until_[source];
        current_until = std::max(current_until, cooldown_until);
        // Cooldown is source-wide. Every old suspect for that source must be
        // retired at the same successful commit; otherwise a sibling tuple
        // could immediately spend another token without a new client request.
        for (auto& [key, state] : states_) {
            if (source_key(key).family != source.family ||
                source_key(key).source != source.source) {
                continue;
            }
            state.suspect_since.reset();
            state.last_activity_at = now;
        }
        return true;
    }

    void reset() noexcept {
        active_epoch_.reset();
        active_preventive_tcp_reset_owned_mark_.reset();
        states_.clear();
        active_media_until_.clear();
        pending_attempts_.clear();
        source_cooldown_until_.clear();
        decision_times_.clear();
        whatsapp_fast_followup_requested_ = false;
    }

    std::size_t tracked_flow_count() const noexcept {
        return states_.size();
    }

    // Consume the coalesced request emitted by one observation containing one
    // or more newly suspected packaged WhatsApp flows. A caller may schedule
    // one early scan with this delay; subsequent observations fall back to the
    // normal cadence unless another flow becomes newly suspect.
    std::optional<std::chrono::seconds>
    take_whatsapp_fast_followup_delay() noexcept {
        if (!whatsapp_fast_followup_requested_) {
            return std::nullopt;
        }
        whatsapp_fast_followup_requested_ = false;
        return options_.whatsapp_confirmation_delay;
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

    struct FlowState {
        IdleStallFlowCounters counters;
        TimePoint last_activity_at;
        TimePoint last_counter_change_at;
        std::optional<TimePoint> suspect_since;
        IdleStallRecoveryPolicy recovery_policy{
            IdleStallRecoveryPolicy::standard};
    };

    struct PendingAttempt {
        IdleStallEpoch epoch;
        IdleStallDecisionReason reason{
            IdleStallDecisionReason::idle_request_without_reply};
        std::uint64_t attempt_id{0};
    };

    static SourceKey source_key(const IdleStallFlowKey& key) {
        return SourceKey{key.family, key.source};
    }

    static bool valid_key(const IdleStallFlowKey& key) noexcept {
        return !key.source.empty() && !key.destination.empty() &&
               key.source_port != 0U && key.destination_port != 0U;
    }

    static bool eligible_sample(const IdleStallFlowSample& sample,
                                std::uint32_t owned_mark_mask) noexcept {
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
        return policy == IdleStallRecoveryPolicy::
                             packaged_whatsapp_ip_companion
            ? options_.whatsapp_confirmation_delay
            : options_.confirmation_delay;
    }

    void reset_observation_continuity() noexcept {
        states_.clear();
        active_media_until_.clear();
        pending_attempts_.clear();
        whatsapp_fast_followup_requested_ = false;
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
    }

    void validate_options() const {
        if (options_.idle_threshold <= std::chrono::seconds::zero() ||
            options_.confirmation_delay <= std::chrono::seconds::zero() ||
            options_.whatsapp_confirmation_delay <=
                std::chrono::seconds::zero() ||
            options_.whatsapp_confirmation_delay >
                options_.confirmation_delay ||
            options_.fastnat_idle_rotation_threshold <=
                std::chrono::seconds::zero() ||
            options_.active_media_hold <= std::chrono::seconds::zero() ||
            options_.source_cooldown <= std::chrono::seconds::zero() ||
            options_.global_rate_window <= std::chrono::seconds::zero() ||
            options_.preventive_tcp_reset_max_packets_per_direction == 0U ||
            options_.preventive_tcp_reset_max_bytes_per_direction == 0U ||
            options_.max_tracked_flows == 0U ||
            options_.max_decisions_per_scan == 0U ||
            options_.max_decisions_per_rate_window == 0U) {
            throw std::invalid_argument(
                "IdleStallDetector options must be positive");
        }
    }

    IdleStallDetectorOptions options_;
    std::optional<IdleStallEpoch> active_epoch_;
    std::optional<std::uint32_t>
        active_preventive_tcp_reset_owned_mark_;
    std::map<IdleStallFlowKey, FlowState> states_;
    std::map<SourceKey, TimePoint> active_media_until_;
    std::map<IdleStallFlowKey, PendingAttempt> pending_attempts_;
    std::map<SourceKey, TimePoint> source_cooldown_until_;
    std::deque<TimePoint> decision_times_;
    std::uint64_t next_attempt_id_{0};
    bool whatsapp_fast_followup_requested_{false};
};

} // namespace keen_pbr3
