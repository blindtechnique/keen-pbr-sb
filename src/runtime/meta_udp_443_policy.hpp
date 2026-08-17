#pragma once

#include "whatsapp_catalog_identity.hpp"
#include "conntrack_manager.hpp"

#include "../config/config.hpp"
#include "../routing/firewall_state.hpp"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace keen_pbr3 {

enum class MetaUdp443PolicySelectionStatus : std::uint8_t {
    balanced,
    inactive,
    active,
    ambiguous,
};

struct MetaUdp443PolicySelection {
    MetaUdp443PolicySelectionStatus status{
        MetaUdp443PolicySelectionStatus::balanced};
    std::uint32_t fwmark{0U};
    std::vector<std::string> list_names;
    bool allow_unmarked_cleanup{false};

    bool active() const noexcept {
        return status == MetaUdp443PolicySelectionStatus::active;
    }
};

struct MetaUdp443CleanupCandidates {
    bool complete{false};
    std::vector<ConntrackExactForwardedFlow> flows;
};

inline bool meta_udp_443_messages_first_enabled(
    const Config& config) noexcept {
    const auto daemon = config.daemon.value_or(DaemonConfig{});
    return daemon.meta_udp443_policy.value_or(
               api::MetaUdp443Policy::BALANCED) ==
           api::MetaUdp443Policy::MESSAGES_FIRST;
}

namespace meta_udp_443_policy_detail {

// The compatibility mode is intentionally limited to an unqualified broad
// destination rule. Source, protocol, port or DSCP selectors would make a
// filter/FORWARD mark match claim authority over packets the route rule did
// not actually select.
inline bool route_is_broad_destination_mark(
    const RuleState& rule,
    std::uint32_t owned_mask) noexcept {
    if (rule.action_type != RuleActionType::Mark || rule.fwmark == 0U ||
        owned_mask == 0U || (rule.fwmark & ~owned_mask) != 0U ||
        rule.list_names.empty() || rule.set_names.empty()) {
        return false;
    }
    const auto& criteria = rule.criteria;
    return !criteria.dst_set_name.has_value() &&
           !criteria.src_udp_peer_set_name.has_value() &&
           !criteria.dscp.has_value() &&
           criteria.proto == L4Proto::Any && criteria.src_port.empty() &&
           criteria.dst_port.empty() && criteria.src_addr.empty() &&
           criteria.dst_addr.empty() && !criteria.negate_src_port &&
           !criteria.negate_dst_port && !criteria.negate_src_addr &&
           !criteria.negate_dst_addr;
}

} // namespace meta_udp_443_policy_detail

// Resolve the only authority accepted by messages_first: the immutable
// packaged Meta/WhatsApp IP companion, referenced by a realized broad MARK
// rule. Similar names and installed-but-unused lists have no effect. Multiple
// realized marks are rejected as ambiguous instead of guessing which route a
// packet would use.
inline MetaUdp443PolicySelection resolve_meta_udp_443_policy_selection(
    const Config& config,
    const std::vector<RuleState>& realized_rules,
    std::uint32_t owned_mask) {
    if (!meta_udp_443_messages_first_enabled(config)) {
        return {};
    }

    std::set<std::string> authoritative_lists;
    for (const auto& [list_name, list] :
         config.lists.value_or(std::map<std::string, ListConfig>{})) {
        if (list.catalog_identity == kWhatsappIpCatalogIdentity) {
            authoritative_lists.insert(list_name);
        }
    }

    MetaUdp443PolicySelection selection;
    selection.status = MetaUdp443PolicySelectionStatus::inactive;
    std::set<std::string> active_lists;
    std::uint32_t selected_mark = 0U;
    bool pass_precedes_authoritative_mark = false;
    bool earlier_pass = false;
    for (const auto& rule : realized_rules) {
        if (rule.action_type == RuleActionType::Pass) {
            earlier_pass = true;
            continue;
        }
        if (!meta_udp_443_policy_detail::route_is_broad_destination_mark(
                rule, owned_mask)) {
            continue;
        }
        bool contains_authoritative_list = false;
        for (const auto& list_name : rule.list_names) {
            if (authoritative_lists.count(list_name) == 0U) {
                continue;
            }
            contains_authoritative_list = true;
            active_lists.insert(list_name);
        }
        if (!contains_authoritative_list) {
            continue;
        }
        pass_precedes_authoritative_mark =
            pass_precedes_authoritative_mark || earlier_pass;
        if (selected_mark == 0U) {
            selected_mark = rule.fwmark;
        } else if (selected_mark != rule.fwmark) {
            selection.status = MetaUdp443PolicySelectionStatus::ambiguous;
            return selection;
        }
    }

    if (selected_mark == 0U || active_lists.empty()) {
        return selection;
    }
    selection.status = MetaUdp443PolicySelectionStatus::active;
    selection.fwmark = selected_mark;
    selection.allow_unmarked_cleanup =
        !pass_precedes_authoritative_mark;
    selection.list_names.assign(active_lists.begin(), active_lists.end());
    return selection;
}

// Convert one complete, immutable conntrack snapshot into exact activation
// cleanup candidates. Full mark zero may be retired only when ordered policy
// and inbound scope prove that it is not an intentional direct bypass. The
// expected keen-pbr component may coexist with foreign bits, which remain in
// the full-width exact delete selector.
inline MetaUdp443CleanupCandidates select_meta_udp_443_cleanup_candidates(
    const ConntrackFlowObservation& observation,
    const std::set<std::uint32_t>& expected_owned_marks,
    std::uint32_t owned_mask,
    bool allow_unmarked_cleanup = true) {
    MetaUdp443CleanupCandidates result;
    if (owned_mask == 0U || expected_owned_marks.empty() ||
        std::any_of(
            expected_owned_marks.begin(),
            expected_owned_marks.end(),
            [owned_mask](std::uint32_t mark) {
                return mark == 0U || (mark & ~owned_mask) != 0U;
            }) ||
        observation.invalid_owned_mask ||
        observation.invalid_destination_selectors != 0U ||
        observation.invalid_media_seed_destination_selectors != 0U ||
        observation.invalid_media_guard_sources != 0U ||
        observation.invalid_media_seed_candidate_records != 0U ||
        observation.skipped_destination_selectors != 0U ||
        observation.destination_input_truncated ||
        observation.media_seed_destination_input_truncated ||
        observation.snapshot_unavailable || observation.snapshot_truncated ||
        observation.line_limit_reached || observation.flow_limit_reached ||
        observation.local_address_scope_missing) {
        return result;
    }

    for (const auto& flow : observation.media_seed_flows) {
        const std::uint32_t live_owned_mark = flow.mark & owned_mask;
        if (flow.protocol != ConntrackFlowProtocol::Udp ||
            flow.destination_port != 443U ||
            (live_owned_mark == 0U &&
             (flow.mark != 0U || !allow_unmarked_cleanup)) ||
            (live_owned_mark != 0U &&
             expected_owned_marks.count(live_owned_mark) == 0U)) {
            continue;
        }
        result.flows.push_back(flow);
    }
    result.complete = true;
    return result;
}

} // namespace keen_pbr3
