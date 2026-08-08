#pragma once

#include "conntrack_manager.hpp"
#include "idle_stall_detector.hpp"
#include "whatsapp_catalog_identity.hpp"

#include "../config/config.hpp"
#include "../routing/firewall_state.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::uint32_t kUdpCallAffinityRefreshSeconds = 30U;
// Three refresh windows provide headroom for brief observer gaps while
// keeping an abandoned peer route bounded to roughly a minute and a half.
inline constexpr std::uint32_t kUdpCallAffinityPairTimeoutSeconds = 90U;
static_assert(kUdpCallAffinityPairTimeoutSeconds ==
              3U * kUdpCallAffinityRefreshSeconds);

// Call affinity is deliberately limited to the immutable packaged
// Meta/WhatsApp IP companion and follows the existing strong-reconnect opt-in.
// A generic user list must never acquire source-wide UDP authority merely
// because it was selected for stale-flow retirement.
inline std::set<std::string> whatsapp_call_affinity_list_names(
    const Config& config) {
    const auto daemon = config.daemon.value_or(DaemonConfig{});
    if (!daemon.reconnect_unmarked_flows_on_routing_change.value_or(true)) {
        return {};
    }

    std::optional<std::set<std::string>> explicitly_selected;
    if (daemon.reconnect_owned_flows_on_routing_change_lists.has_value()) {
        explicitly_selected.emplace(
            daemon.reconnect_owned_flows_on_routing_change_lists->begin(),
            daemon.reconnect_owned_flows_on_routing_change_lists->end());
    }

    std::set<std::string> selected;
    for (const auto& [list_name, list] :
         config.lists.value_or(std::map<std::string, ListConfig>{})) {
        if (list.catalog_identity != kWhatsappIpCatalogIdentity ||
            (explicitly_selected.has_value() &&
             explicitly_selected->count(list_name) == 0U)) {
            continue;
        }
        selected.insert(list_name);
    }
    return selected;
}

struct UdpCallAffinityTarget {
    std::string list_name;
    std::uint32_t fwmark{0};

    bool operator==(const UdpCallAffinityTarget& other) const noexcept {
        return list_name == other.list_name && fwmark == other.fwmark;
    }
};

namespace udp_call_affinity_detail {

inline bool seed_transport_is_ready(
    const ConntrackExactForwardedFlow& flow) noexcept {
    if (flow.protocol == ConntrackFlowProtocol::Udp) {
        return !flow.tcp_state.has_value();
    }
    return flow.protocol == ConntrackFlowProtocol::Tcp &&
           flow.tcp_state == ConntrackTcpState::Established;
}

inline bool route_is_broad_destination_mark(
    const RuleState& rule,
    std::uint32_t owned_mask) noexcept {
    if (rule.action_type != RuleActionType::Mark || rule.fwmark == 0U ||
        owned_mask == 0U || (rule.fwmark & ~owned_mask) != 0U ||
        rule.list_names.empty() || rule.set_names.empty()) {
        return false;
    }
    const auto& criteria = rule.criteria;
    return !criteria.src_udp_peer_set_name.has_value() &&
           !criteria.dscp.has_value() &&
           criteria.proto == L4Proto::Any && criteria.src_port.empty() &&
           criteria.dst_port.empty() && criteria.src_addr.empty() &&
           criteria.dst_addr.empty() && !criteria.negate_src_port &&
           !criteria.negate_dst_port && !criteria.negate_src_addr &&
           !criteria.negate_dst_addr;
}

inline bool counters_regressed(const ConntrackExactForwardedFlow& flow,
                               const ConntrackFlowCounters& original,
                               const ConntrackFlowCounters& reply) noexcept {
    return flow.original.packets < original.packets ||
           flow.original.bytes < original.bytes ||
           flow.reply.packets < reply.packets ||
           flow.reply.bytes < reply.bytes;
}

inline bool direction_progressed(const ConntrackFlowCounters& current,
                                 const ConntrackFlowCounters& previous) noexcept {
    return current.packets > previous.packets ||
           current.bytes > previous.bytes;
}

inline bool direction_progressed_by(
    const ConntrackFlowCounters& current,
    const ConntrackFlowCounters& previous,
    std::uint64_t minimum_packets,
    std::uint64_t minimum_bytes) noexcept {
    if (current.packets < previous.packets ||
        current.bytes < previous.bytes) {
        return false;
    }
    return current.packets - previous.packets >= minimum_packets &&
           current.bytes - previous.bytes >= minimum_bytes;
}

inline bool is_global_unicast_destination(
    const ConntrackExactForwardedFlow& flow) noexcept {
    if (flow.destination.empty() ||
        flow.destination.find('/') != std::string::npos) {
        return false;
    }

    if (flow.family == ConntrackFlowFamily::Ipv4) {
        in_addr address{};
        if (::inet_pton(AF_INET, flow.destination.c_str(), &address) != 1) {
            return false;
        }
        const std::uint32_t value = ntohl(address.s_addr);
        const std::uint8_t first = static_cast<std::uint8_t>(value >> 24U);
        const std::uint8_t second =
            static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
        const std::uint8_t third =
            static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
        if (first == 0U || first == 10U || first == 127U || first >= 224U ||
            (first == 100U && second >= 64U && second <= 127U) ||
            (first == 169U && second == 254U) ||
            (first == 172U && second >= 16U && second <= 31U) ||
            (first == 192U && second == 168U) ||
            (first == 192U && second == 0U && third == 0U) ||
            (first == 192U && second == 0U && third == 2U) ||
            (first == 192U && second == 88U && third == 99U) ||
            (first == 198U && (second == 18U || second == 19U)) ||
            (first == 198U && second == 51U && third == 100U) ||
            (first == 203U && second == 0U && third == 113U)) {
            return false;
        }
        return true;
    }

    if (flow.family == ConntrackFlowFamily::Ipv6) {
        in6_addr address{};
        if (::inet_pton(AF_INET6, flow.destination.c_str(), &address) != 1) {
            return false;
        }
        // Conservatively admit only 2000::/3 global unicast and reject the
        // documentation prefix. This excludes multicast, ULA, link-local,
        // loopback, unspecified and IPv4-mapped addresses.
        const bool global = (address.s6_addr[0] & 0xE0U) == 0x20U;
        const bool documentation =
            address.s6_addr[0] == 0x20U &&
            address.s6_addr[1] == 0x01U &&
            address.s6_addr[2] == 0x0dU &&
            address.s6_addr[3] == 0xb8U;
        return global && !documentation;
    }
    return false;
}

} // namespace udp_call_affinity_detail

// A list may feed multiple equivalent rules, but two different realised marks
// would make peer inheritance ambiguous. Such a list is excluded fail-closed.
inline std::vector<UdpCallAffinityTarget> active_udp_call_affinity_targets(
    const std::set<std::string>& selected_list_names,
    const std::vector<RuleState>& committed_rules,
    std::uint32_t owned_mask) {
    std::map<std::string, std::uint32_t> marks;
    std::set<std::string> ambiguous;
    for (const auto& rule : committed_rules) {
        if (!udp_call_affinity_detail::route_is_broad_destination_mark(
                rule, owned_mask)) {
            continue;
        }
        for (const auto& list_name : rule.list_names) {
            if (selected_list_names.count(list_name) == 0U) {
                continue;
            }
            const auto [position, inserted] =
                marks.emplace(list_name, rule.fwmark);
            if (!inserted && position->second != rule.fwmark) {
                ambiguous.insert(list_name);
            }
        }
    }

    std::vector<UdpCallAffinityTarget> targets;
    for (const auto& [list_name, mark] : marks) {
        if (ambiguous.count(list_name) == 0U) {
            targets.push_back({list_name, mark});
        }
    }
    return targets;
}

// The first bounded destination scan discovers which client sources have a
// currently live selected WhatsApp UDP/443 exchange. A second read-only scan
// may then include UDP from only those exact host addresses.
inline std::vector<std::string> udp_call_affinity_seed_sources(
    const std::vector<ConntrackExactForwardedFlow>& destination_flows,
    const std::vector<UdpCallAffinityTarget>& targets,
    std::uint32_t owned_mask) {
    std::set<std::uint32_t> allowed_marks;
    for (const auto& target : targets) {
        if (target.fwmark != 0U &&
            (target.fwmark & ~owned_mask) == 0U) {
            allowed_marks.insert(target.fwmark);
        }
    }
    std::set<std::pair<ConntrackFlowFamily, std::string>> unique;
    for (const auto& flow : destination_flows) {
        if (!udp_call_affinity_detail::seed_transport_is_ready(flow) ||
            flow.destination_port != 443U || !flow.assured ||
            !flow.seen_reply || flow.original.packets == 0U ||
            flow.reply.packets == 0U ||
            allowed_marks.count(flow.mark & owned_mask) == 0U) {
            continue;
        }
        unique.emplace(flow.family, flow.source);
    }
    std::vector<std::string> sources;
    sources.reserve(unique.size());
    for (const auto& source : unique) {
        sources.push_back(source.second);
    }
    return sources;
}

struct UdpCallAffinityDecision {
    ConntrackFlowFamily family{ConntrackFlowFamily::Ipv4};
    std::string source;
    std::string destination;
    std::uint16_t destination_port{0};
    std::string list_name;
    std::uint32_t fwmark{0};
    // Promotion carries unanswered direct-WAN baselines; refresh carries the
    // active bidirectional media baseline for the already-promoted target
    // that justifies extending the same exact kernel tuple. The flow may keep
    // only foreign ctmark bits because the affinity mark is intentionally not
    // persisted beyond the expiring classifier.
    std::vector<ConntrackExactForwardedFlow> baseline_flows;
    bool refresh_only{false};
};

struct UdpCallAffinityDetectorOptions {
    std::chrono::seconds active_seed_hold{15};
    std::chrono::seconds promoted_pair_hold{
        kUdpCallAffinityPairTimeoutSeconds};
    std::chrono::seconds active_pair_refresh_interval{
        kUdpCallAffinityRefreshSeconds};
    // Preserve a corroboration streak across two quiet five-second scan
    // windows so sparse ICE retransmits can still be correlated.
    std::chrono::seconds candidate_streak_hold{10};
    std::chrono::seconds global_rate_window{60};
    // A low-volume QUIC keepalive or ordinary message exchange must not open
    // call affinity. Over the five-second active scan a call easily exceeds
    // these deliberately modest bidirectional deltas.
    std::uint64_t minimum_seed_packets_per_direction{4};
    std::uint64_t minimum_seed_bytes_per_direction{1024};
    // Only sustained outbound bursts are confirmable. A four-peer fan-out is
    // confirmed after two correlated observations; smaller calls deliberately
    // take a third observation instead of being rejected outright.
    // ICE-style connectivity probes can be both small and sparse. One
    // packet still has to carry a non-trivial datagram, and promotion needs
    // two or three corroborating observations in the same trusted call
    // context, with a bounded gap for sparse retransmits.
    std::uint64_t minimum_candidate_packets_per_scan{1};
    std::uint64_t minimum_candidate_bytes_per_scan{64};
    std::size_t max_tracked_flows{256};
    // Each peer tuple is re-read before and after publication. Keep one mutation
    // batch small enough for embedded routers and the ten-second deadline.
    std::size_t max_pairs_per_source_per_scan{4};
    std::size_t max_pairs_per_scan{4};
    std::size_t max_pairs_per_rate_window{64};
    std::size_t max_stale_flows_per_pair{8};
};

// Pure bounded detector. It grants no route itself: callers must publish the
// exact source + UDP destination port + destination tuple into an
// already-committed expiring firewall
// set and only then retire the observed unmarked 5-tuples.
class UdpCallAffinityDetector {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    explicit UdpCallAffinityDetector(
        UdpCallAffinityDetectorOptions options = {})
        : options_(std::move(options)) {
        if (options_.active_seed_hold <= std::chrono::seconds::zero() ||
            options_.promoted_pair_hold <= std::chrono::seconds::zero() ||
            options_.active_pair_refresh_interval <=
                std::chrono::seconds::zero() ||
            options_.candidate_streak_hold <=
                std::chrono::seconds::zero() ||
            options_.global_rate_window <= std::chrono::seconds::zero() ||
            options_.minimum_seed_packets_per_direction == 0U ||
            options_.minimum_seed_bytes_per_direction == 0U ||
            options_.minimum_candidate_packets_per_scan == 0U ||
            options_.minimum_candidate_bytes_per_scan == 0U ||
            options_.max_tracked_flows == 0U ||
            options_.max_pairs_per_source_per_scan == 0U ||
            options_.max_pairs_per_scan == 0U ||
            options_.max_pairs_per_rate_window == 0U ||
            options_.max_stale_flows_per_pair == 0U) {
            throw std::invalid_argument(
                "invalid UDP call affinity detector options");
        }
    }

    std::vector<UdpCallAffinityDecision> observe(
        IdleStallEpoch epoch,
        const IdleStallScanStatus& status,
        std::uint32_t owned_mask,
        const std::vector<UdpCallAffinityTarget>& targets,
        const std::vector<ConntrackExactForwardedFlow>& destination_flows,
        const std::vector<ConntrackExactForwardedFlow>& source_wide_udp_flows,
        TimePoint now) {
        prune_limits(now);
        if (destination_flows.size() > options_.max_tracked_flows ||
            source_wide_udp_flows.size() > options_.max_tracked_flows) {
            reset_observation_continuity();
            active_epoch_ = epoch.valid()
                ? std::optional<IdleStallEpoch>{epoch}
                : std::nullopt;
            return {};
        }
        using ObservationFlowKey =
            std::tuple<ConntrackFlowFamily,
                       ConntrackFlowProtocol,
                       std::string,
                       std::string,
                       std::uint16_t,
                       std::uint16_t,
                       std::uint32_t>;
        std::set<ObservationFlowKey> observed_flow_keys;
        const auto remember_observed_flow = [&observed_flow_keys](
                                                const auto& flow) {
            observed_flow_keys.emplace(flow.family,
                                       flow.protocol,
                                       flow.source,
                                       flow.destination,
                                       flow.source_port,
                                       flow.destination_port,
                                       flow.mark);
        };
        for (const auto& flow : destination_flows) {
            remember_observed_flow(flow);
        }
        for (const auto& flow : source_wide_udp_flows) {
            remember_observed_flow(flow);
        }
        if (!epoch.valid() || !status.trustworthy() || owned_mask == 0U ||
            targets.empty() ||
            observed_flow_keys.size() > options_.max_tracked_flows) {
            reset_observation_continuity();
            active_epoch_ = epoch.valid()
                ? std::optional<IdleStallEpoch>{epoch}
                : std::nullopt;
            return {};
        }
        if (!active_epoch_.has_value() || *active_epoch_ != epoch) {
            reset_observation_continuity();
            active_epoch_ = epoch;
        }

        std::map<std::uint32_t, UdpCallAffinityTarget> targets_by_mark;
        for (const auto& target : targets) {
            if (target.list_name.empty() || target.fwmark == 0U ||
                (target.fwmark & ~owned_mask) != 0U) {
                reset_observation_continuity();
                active_epoch_ = epoch;
                return {};
            }
            const auto existing = targets_by_mark.find(target.fwmark);
            if (existing == targets_by_mark.end() ||
                target.list_name < existing->second.list_name) {
                targets_by_mark[target.fwmark] = target;
            }
        }

        using SourceKey =
            std::pair<ConntrackFlowFamily, std::string>;
        using SeedKey = std::tuple<ConntrackFlowFamily,
                                   ConntrackFlowProtocol,
                                   std::string,
                                   std::string,
                                   std::uint16_t,
                                   std::uint16_t,
                                   std::uint32_t>;
        using FlowKey = std::tuple<ConntrackFlowFamily,
                                   ConntrackFlowProtocol,
                                   std::string,
                                   std::string,
                                   std::uint16_t,
                                   std::uint16_t>;
        using PeerKey = std::tuple<ConntrackFlowFamily,
                                   std::string,
                                   std::uint16_t,
                                   std::string>;

        std::map<SeedKey, CounterState> next_seeds;
        std::map<SourceKey, std::set<std::uint32_t>> progressed_marks;
        std::set<SourceKey> regressed_seed_sources;
        std::set<SourceKey> first_snapshot_seed_sources;
        std::set<SourceKey> delta_seed_sources;
        std::set<SourceKey> previously_active_sources;
        for (const auto& [source, context] : active_contexts_) {
            (void)context;
            previously_active_sources.insert(source);
        }
        for (const auto& flow : destination_flows) {
            if (!udp_call_affinity_detail::seed_transport_is_ready(flow) ||
                flow.destination_port != 443U || !flow.assured ||
                !flow.seen_reply || flow.original.packets == 0U ||
                flow.reply.packets == 0U ||
                targets_by_mark.count(flow.mark & owned_mask) == 0U) {
                continue;
            }
            const SeedKey key{flow.family,
                              flow.protocol,
                              flow.source,
                              flow.destination,
                              flow.source_port,
                              flow.destination_port,
                              flow.mark & owned_mask};
            const auto previous = seed_counters_.find(key);
            const bool regressed =
                previous != seed_counters_.end() &&
                udp_call_affinity_detail::counters_regressed(
                    flow, previous->second.original, previous->second.reply);
            if (regressed) {
                regressed_seed_sources.emplace(flow.family, flow.source);
            } else {
                const CounterState empty_counters{};
                const auto& original_baseline =
                    previous == seed_counters_.end()
                    ? empty_counters.original
                    : previous->second.original;
                const auto& reply_baseline =
                    previous == seed_counters_.end()
                    ? empty_counters.reply
                    : previous->second.reply;
                // A new assured seed may contain the whole short signalling
                // burst before the first observer pass. Treat its absolute
                // counters as an initial activity delta. This only opens a
                // bounded provisional observation context and does not count
                // the peer's first burst; exact publication still requires
                // two or three subsequent unanswered ICE-style bursts.
                const bool progressed =
                    udp_call_affinity_detail::direction_progressed_by(
                        flow.original,
                        original_baseline,
                        options_.minimum_seed_packets_per_direction,
                        options_.minimum_seed_bytes_per_direction) &&
                    udp_call_affinity_detail::direction_progressed_by(
                        flow.reply,
                        reply_baseline,
                        options_.minimum_seed_packets_per_direction,
                        options_.minimum_seed_bytes_per_direction);
                if (progressed) {
                    const SourceKey source{flow.family, flow.source};
                    progressed_marks[source].insert(
                        flow.mark & owned_mask);
                    if (previous == seed_counters_.end()) {
                        first_snapshot_seed_sources.insert(source);
                    } else {
                        delta_seed_sources.insert(source);
                    }
                }
            }
            next_seeds.emplace(
                key, CounterState{flow.original, flow.reply});
        }
        seed_counters_ = std::move(next_seeds);

        for (const auto& [source, marks] : progressed_marks) {
            if (marks.size() != 1U ||
                regressed_seed_sources.count(source) != 0U) {
                active_contexts_.erase(source);
                continue;
            }
            const auto target = targets_by_mark.find(*marks.begin());
            if (target == targets_by_mark.end()) {
                active_contexts_.erase(source);
                continue;
            }
            active_contexts_[source] =
                ActiveContext{target->second, now + options_.active_seed_hold};
        }
        for (const auto& source : regressed_seed_sources) {
            active_contexts_.erase(source);
        }
        std::set<SourceKey> provisional_seed_sources;
        for (const auto& source : first_snapshot_seed_sources) {
            if (delta_seed_sources.count(source) == 0U &&
                previously_active_sources.count(source) == 0U &&
                regressed_seed_sources.count(source) == 0U) {
                provisional_seed_sources.insert(source);
            }
        }
        for (auto iterator = active_contexts_.begin();
             iterator != active_contexts_.end();) {
            if (now >= iterator->second.expires_at ||
                targets_by_mark.count(iterator->second.target.fwmark) == 0U) {
                iterator = active_contexts_.erase(iterator);
            } else {
                ++iterator;
            }
        }

        std::set<FlowKey> destination_flow_keys;
        for (const auto& flow : destination_flows) {
            destination_flow_keys.emplace(flow.family,
                                          flow.protocol,
                                          flow.source,
                                          flow.destination,
                                          flow.source_port,
                                          flow.destination_port);
        }

        std::vector<UdpCallAffinityDecision> decisions;
        std::map<SeedKey, CounterState> next_media;
        for (const auto& flow : source_wide_udp_flows) {
            const FlowKey flow_key{flow.family,
                                   flow.protocol,
                                   flow.source,
                                   flow.destination,
                                   flow.source_port,
                                   flow.destination_port};
            const PeerKey peer{flow.family,
                               flow.source,
                               flow.destination_port,
                               flow.destination};
            const auto promoted = promoted_until_.find(peer);
            if (flow.protocol != ConntrackFlowProtocol::Udp ||
                !flow.assured || !flow.seen_reply ||
                flow.original.packets == 0U || flow.reply.packets == 0U ||
                destination_flow_keys.count(flow_key) != 0U ||
                promoted == promoted_until_.end() ||
                now >= promoted->second.expires_at ||
                !udp_call_affinity_detail::is_global_unicast_destination(
                    flow)) {
                continue;
            }
            const auto configured_target =
                targets_by_mark.find(promoted->second.target.fwmark);
            const auto owned_mark = flow.mark & owned_mask;
            if (configured_target == targets_by_mark.end() ||
                !(configured_target->second == promoted->second.target) ||
                (owned_mark != 0U &&
                 owned_mark != promoted->second.target.fwmark)) {
                continue;
            }
            const SeedKey media_key{flow.family,
                                    flow.protocol,
                                    flow.source,
                                    flow.destination,
                                    flow.source_port,
                                    flow.destination_port,
                                    promoted->second.target.fwmark};
            const auto previous = media_counters_.find(media_key);
            const bool progressed =
                previous != media_counters_.end() &&
                !udp_call_affinity_detail::counters_regressed(
                    flow,
                    previous->second.original,
                    previous->second.reply) &&
                udp_call_affinity_detail::direction_progressed(
                    flow.original, previous->second.original) &&
                udp_call_affinity_detail::direction_progressed(
                    flow.reply, previous->second.reply);
            next_media.emplace(
                media_key, CounterState{flow.original, flow.reply});
            if (!progressed) {
                continue;
            }

            const auto& target = promoted->second.target;
            active_contexts_[{flow.family, flow.source}] =
                ActiveContext{target, now + options_.active_seed_hold};
            const auto refreshed = peer_refreshed_at_.find(peer);
            if (decisions.size() >= options_.max_pairs_per_scan ||
                (refreshed != peer_refreshed_at_.end() &&
                 now - refreshed->second <
                     options_.active_pair_refresh_interval)) {
                continue;
            }
            decisions.push_back(UdpCallAffinityDecision{
                flow.family,
                flow.source,
                flow.destination,
                flow.destination_port,
                target.list_name,
                target.fwmark,
                {flow},
                true});
            peer_refreshed_at_[peer] = now;
        }
        media_counters_ = std::move(next_media);

        std::map<FlowKey, CounterState> next_candidates;
        std::set<PeerKey> regressed_candidate_peers;
        std::set<PeerKey> observed_candidate_peers;
        std::set<PeerKey> burst_candidate_peers;
        std::map<SourceKey,
                 std::map<PeerKey,
                          std::vector<ConntrackExactForwardedFlow>>>
            candidates;
        for (const auto& flow : source_wide_udp_flows) {
            const FlowKey flow_key{flow.family,
                                   flow.protocol,
                                   flow.source,
                                   flow.destination,
                                   flow.source_port,
                                   flow.destination_port};
            if (flow.protocol != ConntrackFlowProtocol::Udp ||
                (flow.mark & owned_mask) != 0U ||
                flow.tcp_state.has_value()) {
                continue;
            }
            const auto previous = candidate_counters_.find(flow_key);
            const bool counters_restarted =
                previous != candidate_counters_.end() &&
                udp_call_affinity_detail::counters_regressed(
                    flow,
                    previous->second.original,
                    previous->second.reply);
            const PeerKey peer{flow.family,
                               flow.source,
                               flow.destination_port,
                               flow.destination};
            if (counters_restarted) {
                regressed_candidate_peers.insert(peer);
            }
            const bool candidate_burst =
                (previous == candidate_counters_.end() || counters_restarted)
                ? flow.original.packets >=
                      options_.minimum_candidate_packets_per_scan &&
                  flow.original.bytes >=
                      options_.minimum_candidate_bytes_per_scan
                : udp_call_affinity_detail::direction_progressed_by(
                      flow.original,
                      previous->second.original,
                      options_.minimum_candidate_packets_per_scan,
                      options_.minimum_candidate_bytes_per_scan);
            next_candidates.emplace(
                flow_key, CounterState{flow.original, flow.reply});

            const SourceKey source{flow.family, flow.source};
            const auto context = active_contexts_.find(source);
            if (context == active_contexts_.end() ||
                destination_flow_keys.count(flow_key) != 0U ||
                flow.assured || flow.seen_reply ||
                flow.reply.packets != 0U || flow.reply.bytes != 0U ||
                !udp_call_affinity_detail::is_global_unicast_destination(
                    flow)) {
                continue;
            }
            const auto promoted = promoted_until_.find(peer);
            if (promoted != promoted_until_.end() &&
                now < promoted->second.expires_at) {
                continue;
            }
            observed_candidate_peers.insert(peer);
            if (!candidate_burst) {
                continue;
            }
            burst_candidate_peers.insert(peer);
            candidates[source][peer].push_back(flow);
        }
        candidate_counters_ = std::move(next_candidates);

        for (auto iterator = candidate_streaks_.begin();
             iterator != candidate_streaks_.end();) {
            const auto& peer = iterator->first;
            const SourceKey source{std::get<0>(peer), std::get<1>(peer)};
            const auto context = active_contexts_.find(source);
            if (observed_candidate_peers.count(peer) == 0U ||
                regressed_candidate_peers.count(peer) != 0U ||
                (iterator->second.observations == 0U &&
                 burst_candidate_peers.count(peer) == 0U) ||
                context == active_contexts_.end() ||
                !(context->second.target == iterator->second.target) ||
                now - iterator->second.last_progress_at >
                    options_.candidate_streak_hold) {
                iterator = candidate_streaks_.erase(iterator);
            } else {
                ++iterator;
            }
        }

        for (auto& [source, pairs] : candidates) {
            const auto context = active_contexts_.find(source);
            if (context == active_contexts_.end()) {
                continue;
            }
            const std::size_t required_observations =
                pairs.size() >= kFastFanoutPairCount
                ? kFastFanoutRequiredObservations
                : kSparseFanoutRequiredObservations;
            for (const auto& [peer, flows] : pairs) {
                (void)flows;
                CandidateStreak streak{
                    provisional_seed_sources.count(source) == 0U
                        ? 1U
                        : 0U,
                    required_observations,
                    context->second.target,
                    now};
                const auto previous = candidate_streaks_.find(peer);
                if (regressed_candidate_peers.count(peer) == 0U &&
                    previous != candidate_streaks_.end() &&
                    previous->second.target == context->second.target) {
                    streak.observations =
                        previous->second.observations <
                                kSparseFanoutRequiredObservations
                        ? previous->second.observations + 1U
                        : previous->second.observations;
                }
                candidate_streaks_[peer] = std::move(streak);
            }
        }

        for (auto& [source, pairs] : candidates) {
            const auto context = active_contexts_.find(source);
            if (context == active_contexts_.end()) {
                continue;
            }
            std::size_t source_count = 0U;
            for (auto& [peer, flows] : pairs) {
                const auto streak = candidate_streaks_.find(peer);
                if (streak == candidate_streaks_.end() ||
                    streak->second.observations <
                        streak->second.required_observations) {
                    continue;
                }
                if (source_count >=
                        options_.max_pairs_per_source_per_scan ||
                    decisions.size() >= options_.max_pairs_per_scan ||
                    promotion_times_.size() >=
                        options_.max_pairs_per_rate_window) {
                    break;
                }
                std::sort(
                    flows.begin(), flows.end(),
                    [](const auto& left, const auto& right) {
                        return std::tie(left.source_port,
                                        left.destination_port,
                                        left.destination) <
                               std::tie(right.source_port,
                                        right.destination_port,
                                        right.destination);
                    });
                if (flows.size() > options_.max_stale_flows_per_pair) {
                    flows.resize(options_.max_stale_flows_per_pair);
                }
                const auto& [family,
                             source_address,
                             destination_port,
                             destination] = peer;
                decisions.push_back(UdpCallAffinityDecision{
                    family,
                    source_address,
                    destination,
                    destination_port,
                    context->second.target.list_name,
                    context->second.target.fwmark,
                    std::move(flows),
                    false});
                promoted_until_[peer] = PromotedPeer{
                    context->second.target,
                    now + options_.promoted_pair_hold};
                peer_refreshed_at_[peer] = now;
                promotion_times_[peer] = now;
                ++source_count;
            }
        }
        return decisions;
    }

    // A caller may temporarily shorten its normal observer interval while a
    // live exact pair is accumulating the second or third correlated burst.
    // Expired seed contexts and a saturated global mutation budget never ask
    // for extra scans.
    bool needs_fast_followup(TimePoint now) {
        prune_limits(now);
        if (promotion_times_.size() >=
            options_.max_pairs_per_rate_window) {
            return false;
        }
        for (const auto& [peer, streak] : candidate_streaks_) {
            const SourceKey source{std::get<0>(peer), std::get<1>(peer)};
            const auto context = active_contexts_.find(source);
            const auto promoted = promoted_until_.find(peer);
            if (context != active_contexts_.end() &&
                now < context->second.expires_at &&
                now - streak.last_progress_at <=
                    options_.candidate_streak_hold &&
                (promoted == promoted_until_.end() ||
                 now >= promoted->second.expires_at)) {
                return true;
            }
        }
        return false;
    }

    void release_failed(const UdpCallAffinityDecision& decision) noexcept {
        const auto peer = std::make_tuple(
            decision.family,
            decision.source,
            decision.destination_port,
            decision.destination);
        peer_refreshed_at_.erase(peer);
        if (!decision.refresh_only) {
            promoted_until_.erase(peer);
            promotion_times_.erase(peer);
        }
    }

    void confirm_installed(const UdpCallAffinityDecision& decision,
                           TimePoint now) noexcept {
        const auto peer = std::make_tuple(
            decision.family,
            decision.source,
            decision.destination_port,
            decision.destination);
        promoted_until_[peer] = PromotedPeer{
            UdpCallAffinityTarget{decision.list_name, decision.fwmark},
            now + options_.promoted_pair_hold};
        peer_refreshed_at_[peer] = now;
        candidate_streaks_.erase(peer);
    }

    std::vector<std::string> retained_guard_sources(TimePoint now) {
        prune_limits(now);
        std::set<SourceKey> sources;
        for (const auto& [source, context] : active_contexts_) {
            if (now < context.expires_at) {
                sources.insert(source);
            }
        }
        for (const auto& [peer, promoted] : promoted_until_) {
            if (now < promoted.expires_at) {
                sources.emplace(std::get<0>(peer), std::get<1>(peer));
            }
        }
        std::vector<std::string> result;
        result.reserve(sources.size());
        for (const auto& source : sources) {
            result.push_back(source.second);
        }
        return result;
    }

    void reset() noexcept {
        active_epoch_.reset();
        reset_observation_continuity();
        promoted_until_.clear();
        peer_refreshed_at_.clear();
        promotion_times_.clear();
    }

private:
    struct CounterState {
        ConntrackFlowCounters original;
        ConntrackFlowCounters reply;
    };
    struct ActiveContext {
        UdpCallAffinityTarget target;
        TimePoint expires_at;
    };
    struct CandidateStreak {
        std::size_t observations{0U};
        std::size_t required_observations{0U};
        UdpCallAffinityTarget target;
        TimePoint last_progress_at;
    };
    struct PromotedPeer {
        UdpCallAffinityTarget target;
        TimePoint expires_at;
    };

    static constexpr std::size_t kFastFanoutPairCount = 4U;
    static constexpr std::size_t kFastFanoutRequiredObservations = 2U;
    static constexpr std::size_t kSparseFanoutRequiredObservations = 3U;

    using SourceKey = std::pair<ConntrackFlowFamily, std::string>;
    using SeedKey = std::tuple<ConntrackFlowFamily,
                               ConntrackFlowProtocol,
                               std::string,
                               std::string,
                               std::uint16_t,
                               std::uint16_t,
                               std::uint32_t>;
    using FlowKey = std::tuple<ConntrackFlowFamily,
                               ConntrackFlowProtocol,
                               std::string,
                               std::string,
                               std::uint16_t,
                               std::uint16_t>;
    using PeerKey = std::tuple<ConntrackFlowFamily,
                               std::string,
                               std::uint16_t,
                               std::string>;

    void reset_observation_continuity() noexcept {
        seed_counters_.clear();
        media_counters_.clear();
        candidate_counters_.clear();
        active_contexts_.clear();
        candidate_streaks_.clear();
    }

    void prune_limits(TimePoint now) {
        for (auto iterator = promotion_times_.begin();
             iterator != promotion_times_.end();) {
            if (now - iterator->second >= options_.global_rate_window) {
                iterator = promotion_times_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        for (auto iterator = promoted_until_.begin();
             iterator != promoted_until_.end();) {
            if (now >= iterator->second.expires_at) {
                iterator = promoted_until_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        for (auto iterator = peer_refreshed_at_.begin();
             iterator != peer_refreshed_at_.end();) {
            if (promoted_until_.count(iterator->first) == 0U) {
                iterator = peer_refreshed_at_.erase(iterator);
            } else {
                ++iterator;
            }
        }
    }

    UdpCallAffinityDetectorOptions options_;
    std::optional<IdleStallEpoch> active_epoch_;
    std::map<SeedKey, CounterState> seed_counters_;
    std::map<SeedKey, CounterState> media_counters_;
    std::map<FlowKey, CounterState> candidate_counters_;
    std::map<SourceKey, ActiveContext> active_contexts_;
    std::map<PeerKey, CandidateStreak> candidate_streaks_;
    std::map<PeerKey, PromotedPeer> promoted_until_;
    std::map<PeerKey, TimePoint> peer_refreshed_at_;
    std::map<PeerKey, TimePoint> promotion_times_;
};

} // namespace keen_pbr3
