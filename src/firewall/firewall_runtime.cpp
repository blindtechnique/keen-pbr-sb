#include "firewall_runtime.hpp"
#include "../runtime/nfqws_runtime_contract.hpp"

#include "../runtime/meta_udp_443_policy.hpp"

#include "../config/routing_state.hpp"
#include "../dns/dns_router.hpp"
#include "../lists/list_entry_visitor.hpp"
#include "../lists/list_set_usage.hpp"
#include "../lists/list_streamer.hpp"
#include "../runtime/udp_call_affinity.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/network_routes.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

std::optional<uint32_t> canonical_ipset_hashsize(
    const std::optional<int64_t>& value) {
    const int64_t effective = value.value_or(1024);
    if (effective < 1 ||
        effective > std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }
    return normalize_ipset_hashsize(static_cast<uint32_t>(effective));
}

bool ipset_hashsize_changed(const std::optional<int64_t>& current,
                            const std::optional<int64_t>& candidate) {
    const auto current_canonical = canonical_ipset_hashsize(current);
    const auto candidate_canonical = canonical_ipset_hashsize(candidate);
    if (current_canonical.has_value() && candidate_canonical.has_value()) {
        return current_canonical != candidate_canonical;
    }
    return current != candidate;
}

bool ipset_maxelem_changed(const std::optional<int64_t>& current,
                           const std::optional<int64_t>& candidate) {
    return current.value_or(65536) != candidate.value_or(65536);
}

const Outbound* find_outbound_by_tag(const std::vector<Outbound>& outbounds,
                                     const std::string& tag) {
    for (const auto& outbound : outbounds) {
        if (outbound.tag == tag) {
            return &outbound;
        }
    }
    return nullptr;
}

bool needs_native_vpn_direct_egress_snat(std::string_view stable_id) {
    constexpr std::string_view kSstpServiceId{
        "ndms-service:sstp-server"};
    constexpr std::string_view kOpenConnectServiceId{
        "ndms-service:oc-server"};
    constexpr std::string_view kL2tpServicePrefix{
        "ndms-crypto-map:l2tp:"};
    constexpr std::string_view kIkev1ServicePrefix{
        "ndms-crypto-map:ikev1:"};

    if (stable_id == kSstpServiceId ||
        stable_id == kOpenConnectServiceId) {
        return true;
    }
    const auto has_nonempty_suffix =
        [stable_id](std::string_view prefix) {
            return stable_id.size() > prefix.size() &&
                   stable_id.compare(0, prefix.size(), prefix) == 0;
        };
    return has_nonempty_suffix(kL2tpServicePrefix) ||
           has_nonempty_suffix(kIkev1ServicePrefix);
}

} // namespace

FirewallConfigApplyPolicy firewall_config_apply_policy(
    FirewallBackend backend,
    const Config& current,
    const Config& candidate) {
    if (backend != FirewallBackend::iptables) {
        return {};
    }

    const auto current_daemon = current.daemon.value_or(DaemonConfig{});
    const auto candidate_daemon = candidate.daemon.value_or(DaemonConfig{});
    if (!ipset_hashsize_changed(current_daemon.ipset_hashsize,
                                candidate_daemon.ipset_hashsize) &&
        !ipset_maxelem_changed(current_daemon.ipset_maxelem,
                               candidate_daemon.ipset_maxelem)) {
        return {};
    }

    return {FirewallApplyMode::Destructive, true};
}

PpeDeoffloadDesired ppe_deoffload_desired_from_observation(
    PpeDeoffloadMode mode,
    bool quic_enabled,
    const NfqwsPpeRuntimeContractObservation& observation) {
    PpeDeoffloadDesired desired;
    desired.mode = mode;
    desired.quic_enabled = quic_enabled;
    if (desired.mode == PpeDeoffloadMode::off) return desired;

    desired.nfqueue_active = observation.available;
    desired.strategy_ports_available = observation.available;
    desired.runtime_contract_detail = observation.diagnostic;
    if (!observation.available) return desired;

    desired.nfqueue_number = observation.contract.queue_number;
    for (const auto& range : observation.contract.tcp_ranges) {
        desired.tcp_ports.push_back(
            range.first == range.last
                ? std::to_string(range.first)
                : std::to_string(range.first) + ":" +
                      std::to_string(range.last));
    }
    desired.quic_443_active = observation.contract.quic_udp_443;
    return desired;
}

PpeDeoffloadDesired ppe_deoffload_desired_from_observation(
    const Config& config,
    const NfqwsPpeRuntimeContractObservation& observation) {
    const auto daemon_config = config.daemon.value_or(DaemonConfig{});
    return ppe_deoffload_desired_from_observation(
        daemon_config.ppe_deoffload_mode.value_or(
            api::PpeDeoffloadMode::OFF) == api::PpeDeoffloadMode::AUTO
            ? PpeDeoffloadMode::automatic
            : PpeDeoffloadMode::off,
        daemon_config.ppe_deoffload_quic_enabled.value_or(false),
        observation);
}

PpeDeoffloadDesired observe_ppe_deoffload_desired(
    PpeDeoffloadMode mode,
    bool quic_enabled) {
    if (mode == PpeDeoffloadMode::off) {
        return ppe_deoffload_desired_from_observation(
            mode, quic_enabled, {});
    }
    return ppe_deoffload_desired_from_observation(
        mode, quic_enabled, observe_nfqws_ppe_runtime_contract());
}

PpeDeoffloadDesired observe_ppe_deoffload_desired(const Config& config) {
    const auto daemon_config = config.daemon.value_or(DaemonConfig{});
    if (daemon_config.ppe_deoffload_mode.value_or(
            api::PpeDeoffloadMode::OFF) != api::PpeDeoffloadMode::AUTO) {
        // Preserve the explicit no-observation contract for mode=off.
        return ppe_deoffload_desired_from_observation(config, {});
    }
    return ppe_deoffload_desired_from_observation(
        config, observe_nfqws_ppe_runtime_contract());
}

std::vector<FirewallSourceEgressSnatSelector>
select_native_vpn_direct_egress_snat_selectors(
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets,
    const std::vector<std::string>& wan_interfaces) {
    std::vector<FirewallSourceEgressSnatSelector> result;
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& interface : wan_interfaces) {
        if (interface.empty()) {
            continue;
        }
        for (const auto& target : internal_vpn_targets) {
            if (!needs_native_vpn_direct_egress_snat(
                    target.stable_id)) {
                continue;
            }
            // `process_clients` intentionally does not participate here:
            // disabling policy routing must restore ordinary WAN reachability,
            // not remove the source NAT required by the firmware VPN pool.
            for (const auto& cidr : target.source_cidrs_v4) {
                if (cidr.empty() ||
                    !seen.emplace(interface, cidr).second) {
                    continue;
                }
                result.push_back({interface, cidr});
            }
        }
    }
    return result;
}

std::vector<FirewallSourceEgressSnatSelector>
select_native_vpn_direct_egress_snat_selectors(
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets) {
    return select_native_vpn_direct_egress_snat_selectors(
        internal_vpn_targets, default_route_interfaces());
}

std::vector<std::string>
changed_native_vpn_direct_egress_source_cidrs(
    const std::vector<FirewallSourceEgressSnatSelector>& previous,
    const std::vector<FirewallSourceEgressSnatSelector>& current) {
    const std::set<FirewallSourceEgressSnatSelector> previous_set(
        previous.begin(), previous.end());
    const std::set<FirewallSourceEgressSnatSelector> current_set(
        current.begin(), current.end());
    std::set<std::string> changed_sources;

    for (const auto& selector : previous_set) {
        if (current_set.find(selector) == current_set.end() &&
            !selector.cidr.empty()) {
            changed_sources.insert(selector.cidr);
        }
    }
    for (const auto& selector : current_set) {
        if (previous_set.find(selector) == previous_set.end() &&
            !selector.cidr.empty()) {
            changed_sources.insert(selector.cidr);
        }
    }
    return {changed_sources.begin(), changed_sources.end()};
}

StagedRuntimeFirewall stage_runtime_firewall(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& urltest_selections,
    const CacheManager& cache_manager,
    Firewall& firewall,
    FirewallApplyMode mode,
    const std::vector<InternalVpnServer>*
        effective_internal_vpn_servers,
    const std::vector<InternalVpnRuntimeTarget>*
        effective_internal_vpn_targets,
    const std::vector<FirewallSourceEgressSnatSelector>*
        native_vpn_direct_egress_snat_selectors,
    bool udp_call_affinity_ipset_available,
    const std::optional<KeeneticDnsSnapshot>& keenetic_dns_snapshot,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot,
    bool force_clear_dynamic_sets) {
    // Resolve and validate the complete DNS registry before preparing the
    // backend transaction.  In particular, a Keenetic DNS server without a
    // prepared snapshot must fail before any firewall state is touched.
    std::optional<DnsServerRegistry> dns_registry;
    if (config.dns.has_value()) {
        dns_registry.emplace(
            config.dns.value_or(DnsConfig{}), keenetic_dns_snapshot);
    }

    ListStreamer list_streamer = list_cache_snapshot
        ? ListStreamer(cache_manager, std::move(list_cache_snapshot))
        : ListStreamer(cache_manager);
    auto rule_states = build_fw_rule_states(config, outbound_marks, &urltest_selections);
    const RouteConfig route_config = config.route.value_or(RouteConfig{});
    const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(config);
    log_ipv6_support_decision_once(ipv6_decision);
    firewall.set_ipv6_enabled(ipv6_decision.enabled);
    const auto daemon_config = config.daemon.value_or(DaemonConfig{});
    firewall.set_clear_dynamic_sets_on_apply(
        force_clear_dynamic_sets ||
        daemon_config.clear_dynamic_sets_on_apply.value_or(true));
    firewall.set_ipset_hashsize(
        daemon_config.ipset_hashsize.has_value()
            ? std::optional<uint32_t>{static_cast<uint32_t>(
                  *daemon_config.ipset_hashsize)}
            : std::nullopt);
    firewall.set_ipset_maxelem(
        daemon_config.ipset_maxelem.has_value()
            ? std::optional<uint32_t>{static_cast<uint32_t>(
                  *daemon_config.ipset_maxelem)}
            : std::nullopt);
    firewall.set_ttl_bypass_enabled(
        config.daemon.value_or(DaemonConfig{}).ttl_bypass_enabled.value_or(true));
    firewall.set_ppe_deoffload_desired(
        observe_ppe_deoffload_desired(config));
    auto prefilter = effective_internal_vpn_targets != nullptr
        ? build_firewall_global_prefilter_for_runtime_targets(
              config, *effective_internal_vpn_targets)
        : (effective_internal_vpn_servers != nullptr
               ? build_firewall_global_prefilter(
                     config, *effective_internal_vpn_servers)
               : build_firewall_global_prefilter(config));
    prefilter.restore_conntrack_mark = true;
    prefilter.conntrack_mark_mask =
        fwmark_mask_value(config.fwmark.value_or(FwmarkConfig{}));
    firewall.set_global_prefilter(std::move(prefilter));
    firewall.set_fwmark_mask(
        fwmark_mask_value(config.fwmark.value_or(FwmarkConfig{})));
    firewall.prepare_apply(mode);

    const auto& all_outbounds = config.outbounds.value_or(std::vector<Outbound>{});
    static const std::map<std::string, ListConfig> empty_lists;
    const auto& lists_map = config.lists ? *config.lists : empty_lists;
    const auto& route_rules = route_config.rules.value_or(std::vector<RouteRule>{});
    std::map<std::string, ListSetUsage> list_usage_cache;
    // Unlike list_usage_cache (the first planning pass), this map describes
    // the bytes actually streamed into the pending kernel sets. Remote cache
    // files may be atomically replaced between the two passes, so security
    // policy must authorize family coverage only from this second view.
    std::map<std::string, ListSetUsage> applied_list_usage;
    AppliedListContentState candidate_list_content_state;

    for (size_t rule_idx = 0; rule_idx < route_rules.size(); ++rule_idx) {
        const auto& rule = route_rules[rule_idx];
        RuleState& rule_state = rule_states[rule_idx];

        if (rule_state.action_type == RuleActionType::Skip) {
            continue;
        }

        rule_state.set_names.clear();

        const bool is_blackhole = rule_state.action_type == RuleActionType::Drop;
        const bool is_pass = rule_state.action_type == RuleActionType::Pass;
        FirewallRuleCriteria criteria = build_firewall_rule_criteria(rule);
        rule_state.criteria = criteria;

        auto apply_rule = [&](const std::optional<std::string>& dst_set_name) {
            FirewallRuleCriteria rule_criteria = criteria;
            rule_criteria.dst_set_name = dst_set_name;

            if (is_blackhole) {
                firewall.create_drop_rule(rule_criteria);
            } else if (is_pass) {
                firewall.create_pass_rule(rule_criteria);
            } else if (rule_state.fwmark != 0) {
                firewall.create_mark_rule(rule_state.fwmark, rule_criteria);
            }
        };

        const auto& list_names = route_rule_lists(rule);
        if (!list_names.empty()) {
            bool emitted_rule = false;

            for (const auto& list_name : list_names) {
                auto list_cfg_it = lists_map.find(list_name);
                if (list_cfg_it == lists_map.end()) {
                    continue;
                }

                const auto& list_cfg = list_cfg_it->second;
                auto usage_it = list_usage_cache.find(list_name);
                if (usage_it == list_usage_cache.end()) {
                    usage_it = list_usage_cache.emplace(
                        list_name,
                        analyze_list_set_usage(list_name, list_cfg, list_streamer)).first;
                }
                const auto& usage = usage_it->second;
                ListSetUsage applied_usage = usage;

                const std::string set4 = firewall.static_set_name(list_name, AF_INET);
                const std::string set6 = firewall.static_set_name(list_name, AF_INET6);
                const std::string set4d = firewall.dynamic_set_name(list_name, AF_INET);
                const std::string set6d = firewall.dynamic_set_name(list_name, AF_INET6);

                if (usage.has_static_entries) {
                    // The list was inspected once to decide which kernel sets
                    // are required. Track the content actually handed to the
                    // set loaders during this second pass: a cache file may be
                    // atomically replaced between the two reads, and cleanup
                    // must never be based on the stale first observation.
                    applied_usage.has_static_entries = false;
                    applied_usage.has_domain_entries = false;
                    applied_usage.has_static_ipv4_entries = false;
                    applied_usage.has_static_ipv6_entries = false;
                    applied_usage.static_destinations.clear();
                    applied_usage.static_destinations_truncated = false;
                    firewall.create_ipset(set4, AF_INET, 0);
                    rule_state.set_names.push_back(set4);
                    if (ipv6_decision.enabled) {
                        firewall.create_ipset(set6, AF_INET6, 0);
                        rule_state.set_names.push_back(set6);
                    }

                    auto loader4 = firewall.create_batch_loader(set4);
                    auto loader6 = ipv6_decision.enabled
                        ? firewall.create_batch_loader(set6)
                        : nullptr;
                    FunctionalVisitor splitter([&](EntryType type, std::string_view entry) {
                        if (type == EntryType::Domain) {
                            applied_usage.has_domain_entries = true;
                            return;
                        }
                        applied_usage.has_static_entries = true;
                        if (applied_usage.static_destinations.size() <
                            ListSetUsage::kMaxTrackedStaticDestinations) {
                            applied_usage.static_destinations.emplace_back(entry);
                        } else {
                            applied_usage.static_destinations_truncated = true;
                        }
                        const bool is_ipv6 = entry.find(':') != std::string_view::npos;
                        if (is_ipv6) {
                            applied_usage.has_static_ipv6_entries = true;
                        } else {
                            applied_usage.has_static_ipv4_entries = true;
                        }
                        if (is_ipv6) {
                            if (loader6) {
                                loader6->on_entry(type, entry);
                            }
                        } else {
                            loader4->on_entry(type, entry);
                        }
                    });
                    list_streamer.stream_list(list_name, list_cfg, splitter);
                    loader4->finish();
                    if (loader6) {
                        loader6->finish();
                    }
                }

                std::sort(
                    applied_usage.static_destinations.begin(),
                    applied_usage.static_destinations.end());
                applied_usage.static_destinations.erase(
                    std::unique(
                        applied_usage.static_destinations.begin(),
                        applied_usage.static_destinations.end()),
                    applied_usage.static_destinations.end());
                candidate_list_content_state.static_destinations
                    .insert_or_assign(
                        list_name, applied_usage.static_destinations);
                if (applied_usage.has_domain_entries) {
                    candidate_list_content_state
                        .domain_entry_lists.insert(list_name);
                }
                if (applied_usage.static_destinations_truncated) {
                    candidate_list_content_state
                        .truncated_static_destination_lists.insert(list_name);
                }
                applied_list_usage.insert_or_assign(
                    list_name, applied_usage);

                if (usage.has_domain_entries) {
                    firewall.create_ipset(set4d, AF_INET, usage.dynamic_timeout);
                    rule_state.set_names.push_back(set4d);
                    if (ipv6_decision.enabled) {
                        firewall.create_ipset(set6d, AF_INET6, usage.dynamic_timeout);
                        rule_state.set_names.push_back(set6d);
                    }
                }

                if (usage.has_static_entries) {
                    apply_rule(set4);
                    if (ipv6_decision.enabled) {
                        apply_rule(set6);
                    }
                    emitted_rule = true;
                }
                if (usage.has_domain_entries) {
                    apply_rule(set4d);
                    if (ipv6_decision.enabled) {
                        apply_rule(set6d);
                    }
                    emitted_rule = true;
                }
            }

            if (!emitted_rule && criteria.has_rule_selector()) {
                apply_rule(std::nullopt);
            }
        } else if (criteria.has_rule_selector()) {
            apply_rule(std::nullopt);
        }
    }

    if (config.dns.has_value()) {
        const auto& dns_servers = config.dns->servers.value_or(std::vector<DnsServer>{});
        for (const auto& server : dns_servers) {
            if (!server.detour.has_value()) {
                continue;
            }

            const Outbound* detour_outbound =
                find_outbound_by_tag(all_outbounds, server.detour.value());
            if (!detour_outbound) {
                continue;
            }

            std::string effective_tag = detour_outbound->tag;
            if (detour_outbound->type == OutboundType::URLTEST) {
                auto selection_it = urltest_selections.find(effective_tag);
                if (selection_it != urltest_selections.end() && !selection_it->second.empty()) {
                    const Outbound* child =
                        find_outbound_by_tag(all_outbounds, selection_it->second);
                    if (child) {
                        effective_tag = child->tag;
                    }
                }
            }

            auto mark_it = outbound_marks.find(effective_tag);
            if (mark_it == outbound_marks.end()) {
                continue;
            }

            const auto resolved_servers = dns_registry->get_servers(server.tag);
            if (resolved_servers.empty()) {
                throw FirewallError("DNS server tag not found during detour setup: " + server.tag);
            }

            for (const DnsServerConfig* resolved_server : resolved_servers) {
                FirewallRuleCriteria criteria;
                criteria.proto = L4Proto::TcpUdp;
                criteria.dst_port = std::to_string(resolved_server->port);
                criteria.dst_addr = {resolved_server->resolved_ip};
                firewall.create_mark_rule(mark_it->second, criteria);
                // dnsmasq upstream queries originate on the router itself and
                // never traverse PREROUTING; mirror the detour mark into the
                // OUTPUT path so they are policy-routed through the detour too.
                firewall.create_output_mark_rule(mark_it->second, criteria);
            }
        }
    }

    if (config.dns.has_value() && config.dns->client_dns_enforcement.has_value()) {
        const auto& enforcement = *config.dns->client_dns_enforcement;
        if (enforcement.enabled.value_or(false)) {
            // Transparently redirect plain DNS from LAN to the local resolver
            // so clients cannot bypass domain-based routing with a custom DNS.
            firewall.create_dns_redirect_rules();
            if (enforcement.block_dot.value_or(true)) {
                // DNS-over-TLS has a dedicated port and can be blocked outright;
                // clients fall back to plain DNS, which is redirected above.
                FirewallRuleCriteria dot_criteria;
                dot_criteria.proto = L4Proto::TcpUdp;
                dot_criteria.dst_port = "853";
                firewall.create_drop_rule(dot_criteria);
            }
        }
    }

    // Masquerade egress on every interface policy routing can steer traffic
    // into. Without it, sources the firmware does not treat as LAN - notably
    // clients of a VPN server running on the router - enter the tunnel with a
    // private address and their connections hang unanswered.
    {
        std::vector<std::string> tunnel_interfaces;
        for (const auto& outbound : all_outbounds) {
            if (outbound.type != OutboundType::INTERFACE ||
                !outbound.interface.has_value() || outbound.interface->empty()) {
                continue;
            }
            tunnel_interfaces.push_back(*outbound.interface);
        }
        firewall.create_tunnel_snat_rules(tunnel_interfaces);
    }
    if (native_vpn_direct_egress_snat_selectors != nullptr) {
        firewall.create_source_egress_snat_rules(
            *native_vpn_direct_egress_snat_selectors);
    } else if (effective_internal_vpn_targets != nullptr) {
        firewall.create_source_egress_snat_rules(
            select_native_vpn_direct_egress_snat_selectors(
                *effective_internal_vpn_targets));
    }

    const auto meta_udp_443_selection =
        resolve_meta_udp_443_policy_selection(
            config, rule_states, firewall.fwmark_mask());
    if (meta_udp_443_selection.status ==
        MetaUdp443PolicySelectionStatus::ambiguous) {
        throw FirewallError(
            "daemon.meta_udp443_policy=messages_first requires the "
            "authoritative Meta/WhatsApp IP companion to resolve to one "
            "unambiguous active broad route");
    }
    if (meta_udp_443_selection.active()) {
        for (const auto& list_name : meta_udp_443_selection.list_names) {
            const auto usage = applied_list_usage.find(list_name);
            if (usage == applied_list_usage.end() ||
                !usage->second.has_static_entries) {
                throw FirewallError(
                    "daemon.meta_udp443_policy=messages_first requires "
                    "static IP coverage from the authoritative packaged "
                    "Meta/WhatsApp companion list '" + list_name + "'");
            }
            if (!usage->second.has_static_ipv4_entries) {
                throw FirewallError(
                    "daemon.meta_udp443_policy=messages_first requires "
                    "authoritative IPv4 coverage from the packaged "
                    "Meta/WhatsApp companion list '" + list_name + "'");
            }
            if (ipv6_decision.enabled &&
                !usage->second.has_static_ipv6_entries) {
                throw FirewallError(
                    "daemon.meta_udp443_policy=messages_first cannot be "
                    "enabled while IPv6 is active because the packaged "
                    "Meta/WhatsApp companion has no authoritative IPv6 "
                    "coverage; use balanced mode or disable IPv6");
            }

            firewall.create_forward_udp_reject_rule(
                meta_udp_443_selection.fwmark,
                firewall.static_set_name(list_name, AF_INET),
                443U);
            if (ipv6_decision.enabled) {
                firewall.create_forward_udp_reject_rule(
                    meta_udp_443_selection.fwmark,
                    firewall.static_set_name(list_name, AF_INET6),
                    443U);
            }
        }
    }

    // User rules and generated DNS mark/drop rules retain priority. The empty
    // runtime overlay is deliberately the final packet-classification rule,
    // then populated with exact source+destination pairs only after a bounded
    // active-call observation.
    const bool call_affinity_backend_available =
        firewall.backend() != FirewallBackend::iptables ||
        udp_call_affinity_ipset_available;
    const auto call_affinity_targets = call_affinity_backend_available
        ? active_udp_call_affinity_targets(
              whatsapp_call_affinity_list_names(config),
              rule_states,
              firewall.fwmark_mask())
        : std::vector<UdpCallAffinityTarget>{};
    for (const auto& target : call_affinity_targets) {
        // The trusted packaged Meta/WhatsApp companion currently contains
        // authoritative IPv4 ranges only. Do not publish an inert IPv6
        // classifier until the catalog can authorize IPv6 signalling seeds.
        const std::string set_name =
            firewall.media_affinity_set_name(target.list_name, AF_INET);
        firewall.create_udp_peer_set(
            set_name, AF_INET, kUdpCallAffinityPairTimeoutSeconds);
        FirewallRuleCriteria affinity;
        affinity.src_udp_peer_set_name = set_name;
        affinity.proto = L4Proto::Udp;
        affinity.persist_conntrack_mark = false;
        firewall.create_mark_rule(target.fwmark, affinity);
    }

    StagedRuntimeFirewall staged;
    staged.rule_states = std::move(rule_states);
    staged.list_content_state = std::move(candidate_list_content_state);
    staged.mode = mode;
    return staged;
}

void commit_runtime_firewall(Firewall& firewall,
                             const StagedRuntimeFirewall& staged) {
    firewall.apply(staged.mode);
}

std::vector<RuleState> apply_runtime_firewall(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& urltest_selections,
    const CacheManager& cache_manager,
    Firewall& firewall,
    FirewallApplyMode mode,
    const std::vector<InternalVpnServer>*
        effective_internal_vpn_servers,
    const std::vector<InternalVpnRuntimeTarget>*
        effective_internal_vpn_targets,
    const std::vector<FirewallSourceEgressSnatSelector>*
        native_vpn_direct_egress_snat_selectors,
    AppliedListContentState* applied_list_content_state,
    bool udp_call_affinity_ipset_available,
    const std::optional<KeeneticDnsSnapshot>& keenetic_dns_snapshot,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot,
    bool force_clear_dynamic_sets) {
    auto staged = stage_runtime_firewall(
        config,
        outbound_marks,
        urltest_selections,
        cache_manager,
        firewall,
        mode,
        effective_internal_vpn_servers,
        effective_internal_vpn_targets,
        native_vpn_direct_egress_snat_selectors,
        udp_call_affinity_ipset_available,
        keenetic_dns_snapshot,
        std::move(list_cache_snapshot),
        force_clear_dynamic_sets);
    commit_runtime_firewall(firewall, staged);
    // Published only after the commit, exactly as before: a transaction that
    // never reached the kernel must not advertise the list content it was
    // built from.
    if (applied_list_content_state != nullptr) {
        *applied_list_content_state =
            std::move(staged.list_content_state);
    }
    return std::move(staged.rule_states);
}

} // namespace keen_pbr3
