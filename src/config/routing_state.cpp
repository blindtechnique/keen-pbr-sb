#include "routing_state.hpp"

#include "addr_spec.hpp"
#include "../routing/target.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <set>
#include <tuple>

namespace keen_pbr3 {

namespace {

constexpr uint32_t kUnreachableRouteMetric = 65535;

const Outbound* find_outbound(const std::vector<Outbound>& outbounds,
                              const std::string& tag) {
    for (const auto& ob : outbounds) {
        if (ob.tag == tag) {
            return &ob;
        }
    }
    return nullptr;
}

std::string resolve_urltest_selection(
    const std::map<std::string, std::string>* selections,
    const std::string& urltest_tag) {
    if (!selections) return {};
    auto it = selections->find(urltest_tag);
    if (it == selections->end()) return {};
    return it->second;
}

L4Proto parse_rule_proto(const std::optional<std::string>& proto) {
    if (!proto.has_value() || proto->empty()) return L4Proto::Any;
    if (*proto == "tcp") return L4Proto::Tcp;
    if (*proto == "udp") return L4Proto::Udp;
    if (*proto == "tcp/udp") return L4Proto::TcpUdp;
    throw FirewallError("Unsupported route rule protocol: " + *proto);
}

bool route_matches_outbound(const DumpedRoute& route, const Outbound& outbound) {
    if (route.destination != "default" || route.blackhole || route.unreachable) {
        return false;
    }
    if (outbound.type != OutboundType::INTERFACE) {
        return false;
    }
    if (route.interface != outbound.interface) {
        return false;
    }
    if (route.family == AF_INET && outbound.gateway.has_value()) {
        return route.gateway == outbound.gateway;
    }
    if (route.family == AF_INET6 && outbound.gateway6.has_value()) {
        return route.gateway == outbound.gateway6;
    }
    return !route.gateway.has_value();
}

bool strict_enforcement_enabled(const Config& cfg, const Outbound& ob) {
    if (ob.strict_enforcement.has_value()) {
        return *ob.strict_enforcement;
    }
    const auto daemon_cfg = cfg.daemon.value_or(DaemonConfig{});
    if (daemon_cfg.strict_enforcement.has_value()) {
        return *daemon_cfg.strict_enforcement;
    }
    // Built-in default: tunnel-style interface outbounds (no gateway, e.g.
    // sing-box TUN or WireGuard/AmneziaWG links) get a kill-switch so marked
    // traffic cannot leak to the direct route while the tunnel is down or
    // restarting. Gateway-based outbounds (second WAN etc.) stay permissive.
    if (ob.type == OutboundType::INTERFACE
        && !ob.gateway.has_value() && !ob.gateway6.has_value()) {
        return true;
    }
    return false;
}

bool parse_ip(const std::string& ip, int family, void* out) {
    return inet_pton(family, ip.c_str(), out) == 1;
}

int detect_ip_family(const std::string& ip) {
    in_addr addr4{};
    if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
        return AF_INET;
    }

    in6_addr addr6{};
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
        return AF_INET6;
    }

    throw ConfigError("Invalid IP address: " + ip);
}

bool ipv4_prefix_contains(const in_addr& network, const in_addr& candidate, int prefix_len) {
    if (prefix_len <= 0) return true;
    const uint32_t network_bits = ntohl(network.s_addr);
    const uint32_t candidate_bits = ntohl(candidate.s_addr);
    const uint32_t mask = (prefix_len >= 32) ? 0xFFFFFFFFu : (~0u << (32 - prefix_len));
    return (network_bits & mask) == (candidate_bits & mask);
}

bool ipv6_prefix_contains(const in6_addr& network, const in6_addr& candidate, int prefix_len) {
    if (prefix_len <= 0) return true;
    const int full_bytes = prefix_len / 8;
    const int extra_bits = prefix_len % 8;

    if (full_bytes > 0 &&
        std::memcmp(network.s6_addr, candidate.s6_addr, static_cast<size_t>(full_bytes)) != 0) {
        return false;
    }
    if (extra_bits == 0) return true;

    const uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - extra_bits));
    return (network.s6_addr[full_bytes] & mask) == (candidate.s6_addr[full_bytes] & mask);
}

bool route_contains_ip(const DumpedRoute& route, const std::string& ip) {
    if (route.destination == "default") {
        return true;
    }

    const auto slash = route.destination.find('/');
    if (slash == std::string::npos) {
        return route.destination == ip;
    }

    const std::string network = route.destination.substr(0, slash);
    const int prefix_len = std::stoi(route.destination.substr(slash + 1));
    const int family = (ip.find(':') != std::string::npos) ? AF_INET6 : AF_INET;
    const int network_family = (network.find(':') != std::string::npos) ? AF_INET6 : AF_INET;
    if (family != network_family) {
        return false;
    }

    if (family == AF_INET) {
        in_addr network_addr{};
        in_addr ip_addr{};
        return parse_ip(network, AF_INET, &network_addr) &&
               parse_ip(ip, AF_INET, &ip_addr) &&
               ipv4_prefix_contains(network_addr, ip_addr, prefix_len);
    }

    in6_addr network_addr{};
    in6_addr ip_addr{};
    return parse_ip(network, AF_INET6, &network_addr) &&
           parse_ip(ip, AF_INET6, &ip_addr) &&
           ipv6_prefix_contains(network_addr, ip_addr, prefix_len);
}

bool interface_has_gateway_route(const std::vector<DumpedRoute>& routes,
                                 const std::string& iface,
                                 const std::string& gateway) {
    for (const auto& route : routes) {
        if (route.blackhole || route.unreachable) continue;
        if (!route.interface || *route.interface != iface) continue;
        if (route_contains_ip(route, gateway)) {
            return true;
        }
    }
    return false;
}

std::vector<RouteSpec> make_default_routes(uint32_t table_id, const Outbound& ob) {
    std::vector<RouteSpec> routes;

    auto build_route = [&](int family, const std::optional<std::string>& gateway) {
        RouteSpec route;
        route.destination = "default";
        route.table = table_id;
        route.family = family;
        route.interface = ob.interface.value_or("");
        route.gateway = gateway;
        routes.push_back(std::move(route));
    };

    const bool has_gateway4 = ob.gateway.has_value();
    const bool has_gateway6 = ob.gateway6.has_value();

    if (!has_gateway4 && !has_gateway6) {
        // Link-scope interface outbounds can carry both families, so install
        // both defaults to keep marked IPv6 traffic from bypassing the policy table.
        build_route(AF_INET, std::nullopt);
        build_route(AF_INET6, std::nullopt);
        return routes;
    }

    if (has_gateway4) {
        build_route(AF_INET, ob.gateway);
    }
    if (has_gateway6) {
        build_route(AF_INET6, ob.gateway6);
    }
    return routes;
}

std::vector<RouteSpec> make_family_closure_routes(uint32_t table_id, const Outbound& ob,
                                                  uint32_t metric = kUnreachableRouteMetric) {
    std::vector<RouteSpec> routes;
    const bool has_gateway4 = ob.gateway.has_value();
    const bool has_gateway6 = ob.gateway6.has_value();
    if (!has_gateway4 && !has_gateway6) {
        return routes;
    }

    if (!has_gateway4) {
        RouteSpec route;
        route.destination = "default";
        route.table = table_id;
        route.unreachable = true;
        route.metric = metric;
        route.family = AF_INET;
        routes.push_back(std::move(route));
    }

    if (!has_gateway6) {
        RouteSpec route;
        route.destination = "default";
        route.table = table_id;
        route.unreachable = true;
        route.metric = metric;
        route.family = AF_INET6;
        routes.push_back(std::move(route));
    }
    return routes;
}

std::vector<RouteSpec> make_unreachable_routes(uint32_t table_id,
                                               uint32_t metric = kUnreachableRouteMetric) {
    std::vector<RouteSpec> routes;
    for (int family : {AF_INET, AF_INET6}) {
        RouteSpec route;
        route.destination = "default";
        route.table = table_id;
        route.unreachable = true;
        route.metric = metric;
        route.family = family;
        routes.push_back(std::move(route));
    }
    return routes;
}

std::vector<const Outbound*> ordered_urltest_children(const std::vector<Outbound>& outbounds,
                                                      const Outbound& urltest) {
    std::vector<const Outbound*> ordered;
    if (!urltest.outbound_groups.has_value()) {
        return ordered;
    }

    struct GroupRef {
        size_t index;
        int64_t weight;
    };
    std::vector<GroupRef> groups;
    groups.reserve(urltest.outbound_groups->size());
    for (size_t i = 0; i < urltest.outbound_groups->size(); ++i) {
        groups.push_back({i, urltest.outbound_groups->at(i).weight.value_or(1)});
    }

    std::stable_sort(groups.begin(), groups.end(),
                     [](const GroupRef& a, const GroupRef& b) {
                         return a.weight < b.weight;
                     });

    for (const auto& group_ref : groups) {
        const auto& group = urltest.outbound_groups->at(group_ref.index);
        for (const auto& child_tag : group.outbounds) {
            const Outbound* child = find_outbound(outbounds, child_tag);
            if (child) {
                ordered.push_back(child);
            }
        }
    }
    return ordered;
}

// A urltest group may contain other urltest groups. Routing needs a concrete
// interface, so follow the chain of selections down to a leaf. The depth guard
// keeps a mis-typed configuration that references itself from looping forever.
constexpr int kMaxUrltestDepth = 8;

const Outbound* resolve_selected_interface(
    const std::vector<Outbound>& outbounds,
    const Outbound& outbound,
    const std::map<std::string, std::string>* selections,
    int depth = 0) {
    if (depth > kMaxUrltestDepth) {
        return nullptr;
    }
    if (outbound.type == OutboundType::INTERFACE) {
        return &outbound;
    }
    if (outbound.type != OutboundType::URLTEST) {
        return nullptr;
    }

    const std::string selected_tag = resolve_urltest_selection(selections, outbound.tag);
    if (selected_tag.empty()) {
        return nullptr;
    }
    const Outbound* child = find_outbound(outbounds, selected_tag);
    if (!child) {
        return nullptr;
    }
    return resolve_selected_interface(outbounds, *child, selections, depth + 1);
}

// Same walk, but stops at whatever the chain ends with — a blackhole child, for
// instance, still has to turn the rule into a drop.
const Outbound* resolve_effective_outbound(
    const std::vector<Outbound>& outbounds,
    const Outbound& outbound,
    const std::map<std::string, std::string>* selections,
    int depth = 0) {
    if (outbound.type != OutboundType::URLTEST) {
        return &outbound;
    }
    if (depth > kMaxUrltestDepth) {
        return nullptr;
    }
    const std::string selected_tag = resolve_urltest_selection(selections, outbound.tag);
    if (selected_tag.empty()) {
        return nullptr;
    }
    const Outbound* child = find_outbound(outbounds, selected_tag);
    if (!child) {
        return nullptr;
    }
    return resolve_effective_outbound(outbounds, *child, selections, depth + 1);
}

// Flattens a group into the interfaces that can actually carry traffic, keeping
// the configured order so the fallback metrics stay meaningful.
void collect_urltest_leaf_interfaces(const std::vector<Outbound>& outbounds,
                                     const Outbound& urltest,
                                     std::vector<const Outbound*>& collected,
                                     std::set<std::string>& visited,
                                     int depth = 0) {
    if (depth > kMaxUrltestDepth || !visited.insert(urltest.tag).second) {
        return;
    }
    for (const Outbound* child : ordered_urltest_children(outbounds, urltest)) {
        if (child->type == OutboundType::INTERFACE) {
            collected.push_back(child);
        } else if (child->type == OutboundType::URLTEST) {
            collect_urltest_leaf_interfaces(outbounds, *child, collected, visited,
                                            depth + 1);
        }
    }
}

// Returns the (offset)th non-reserved table ID starting from table_start.
static uint32_t safe_table_id(uint32_t table_start, uint32_t offset) {
    uint32_t id = table_start;
    uint32_t count = 0;
    while (true) {
        if (!is_reserved_table(id)) {
            if (count == offset) return id;
            ++count;
        }
        ++id;
    }
}

} // anonymous namespace

std::vector<std::string> find_affected_urltests(
    const std::vector<Outbound>& outbounds,
    const std::vector<std::string>& changed_outbound_tags) {
    std::set<std::string> affected_tags(changed_outbound_tags.begin(),
                                        changed_outbound_tags.end());
    std::set<std::string> affected_urltests;

    bool discovered_parent = true;
    while (discovered_parent) {
        discovered_parent = false;
        for (const auto& outbound : outbounds) {
            if (outbound.type != OutboundType::URLTEST ||
                affected_urltests.count(outbound.tag) > 0 ||
                !outbound.outbound_groups.has_value()) {
                continue;
            }

            bool contains_affected_child = false;
            for (const auto& group : *outbound.outbound_groups) {
                if (std::any_of(group.outbounds.begin(),
                                group.outbounds.end(),
                                [&affected_tags](const std::string& child_tag) {
                                    return affected_tags.count(child_tag) > 0;
                                })) {
                    contains_affected_child = true;
                    break;
                }
            }

            if (contains_affected_child) {
                affected_urltests.insert(outbound.tag);
                affected_tags.insert(outbound.tag);
                discovered_parent = true;
            }
        }
    }

    std::vector<std::string> result;
    result.reserve(affected_urltests.size());
    for (const auto& outbound : outbounds) {
        if (affected_urltests.count(outbound.tag) > 0) {
            result.push_back(outbound.tag);
        }
    }
    return result;
}

void populate_routing_state(const Config& cfg,
                            const OutboundMarkMap& marks,
                            RouteTable& routes,
                            PolicyRuleManager& rules,
                            OutboundReachabilityFn reachability_check,
                            const std::map<std::string, std::string>* urltest_selections,
                            bool ipv6_enabled) {
    const auto& outbounds = cfg.outbounds.value_or(std::vector<Outbound>{});
    const uint32_t table_start = static_cast<uint32_t>(
        cfg.iproute.value_or(IprouteConfig{}).table_start.value_or(150));
    const uint32_t fwmark_mask = fwmark_mask_value(cfg.fwmark.value_or(FwmarkConfig{}));
    std::vector<RouteSpec> planned_routes;
    std::vector<RuleSpec> planned_rules;

    auto add_route_if_enabled = [&](const RouteSpec& route) {
        if (!ipv6_enabled && route.family == AF_INET6) {
            return false;
        }
        planned_routes.push_back(route);
        return true;
    };

    // Reachability is a point-in-time input to one routing transaction. Cache
    // it per interface so a flapping link cannot produce a table assembled
    // from mutually inconsistent checks of the same child.
    std::map<std::string, bool> reachability_snapshot;
    auto is_reachable = [&](const Outbound& outbound) {
        const auto [it, inserted] =
            reachability_snapshot.try_emplace(outbound.tag, true);
        if (inserted && reachability_check) {
            it->second = reachability_check(outbound);
        }
        return it->second;
    };

    uint32_t table_offset = 0;
    for (const auto& ob : outbounds) {
        if (ob.type == OutboundType::INTERFACE) {
            auto mark_it = marks.find(ob.tag);
            if (mark_it == marks.end()) continue;

            uint32_t table_id = safe_table_id(table_start, table_offset);
            ++table_offset;

            const bool strict = strict_enforcement_enabled(cfg, ob);
            const bool reachable = is_reachable(ob);
            if (reachable) {
                for (const auto& route : make_default_routes(table_id, ob)) {
                    add_route_if_enabled(route);
                }
                for (const auto& route : make_family_closure_routes(table_id, ob)) {
                    add_route_if_enabled(route);
                }
            }
            if (strict) {
                for (const auto& route : make_unreachable_routes(table_id)) {
                    add_route_if_enabled(route);
                }
            }

            RuleSpec ip_rule;
            ip_rule.fwmark = mark_it->second;
            ip_rule.fwmask = fwmark_mask;
            ip_rule.table = table_id;
            ip_rule.priority = table_id;
            if (!ipv6_enabled) {
                ip_rule.family = AF_INET;
            }
            planned_rules.push_back(ip_rule);
        } else if (ob.type == OutboundType::TABLE) {
            auto mark_it = marks.find(ob.tag);
            if (mark_it == marks.end()) continue;

            RuleSpec ip_rule;
            ip_rule.fwmark = mark_it->second;
            ip_rule.fwmask = fwmark_mask;
            ip_rule.table = static_cast<uint32_t>(ob.table.value_or(0));
            ip_rule.priority = safe_table_id(table_start, table_offset);
            if (!ipv6_enabled) {
                ip_rule.family = AF_INET;
            }
            ++table_offset;
            planned_rules.push_back(ip_rule);
        } else if (ob.type == OutboundType::URLTEST) {
            auto mark_it = marks.find(ob.tag);
            if (mark_it == marks.end()) continue;

            uint32_t table_id = safe_table_id(table_start, table_offset);
            ++table_offset;

            std::vector<const Outbound*> ordered_children;
            {
                std::set<std::string> visited;
                collect_urltest_leaf_interfaces(outbounds, ob, ordered_children, visited);
            }

            const std::string selected_tag = resolve_urltest_selection(urltest_selections, ob.tag);
            const bool selection_ready = !selected_tag.empty();
            if (selection_ready) {
                const Outbound* selected =
                    resolve_selected_interface(outbounds, ob, urltest_selections);
                bool selected_primary_planned = false;
                if (selected && is_reachable(*selected)) {
                    for (const auto& route : make_default_routes(table_id, *selected)) {
                        if (add_route_if_enabled(route)) {
                            selected_primary_planned = true;
                        }
                    }
                    for (const auto& route : make_family_closure_routes(table_id, *selected)) {
                        add_route_if_enabled(route);
                    }
                }

                uint32_t metric = 1;
                for (const Outbound* child : ordered_children) {
                    // Do not duplicate a selected child whose metric-zero
                    // primary route is already present. If no usable primary
                    // route was emitted (for example an IPv6-only child while
                    // IPv6 is disabled), process it as a fallback using the
                    // same reachability snapshot.
                    if (selected_primary_planned &&
                        selected && child->tag == selected->tag) {
                        continue;
                    }
                    if (!is_reachable(*child)) {
                        continue;
                    }

                    bool usable_default_planned = false;
                    for (auto route : make_default_routes(table_id, *child)) {
                        route.metric = metric;
                        if (add_route_if_enabled(route)) {
                            usable_default_planned = true;
                        }
                    }

                    // A child that cannot emit a route for any enabled family
                    // must not consume a fallback priority.
                    if (!usable_default_planned) {
                        continue;
                    }

                    // Missing-family closures are terminal safety routes, not
                    // peers of this child's usable default. Giving them the
                    // fallback metric would make an early IPv4-only child
                    // shadow a later IPv6-capable child (and vice versa).
                    for (const auto& route :
                         make_family_closure_routes(table_id, *child)) {
                        add_route_if_enabled(route);
                    }
                    ++metric;
                }
            }

            // Urltest tables always end with a dual-stack kill-switch so marked
            // traffic cannot leak when no child route is usable or selected.
            for (const auto& route : make_unreachable_routes(table_id)) {
                add_route_if_enabled(route);
            }

            RuleSpec ip_rule;
            ip_rule.fwmark = mark_it->second;
            ip_rule.fwmask = fwmark_mask;
            ip_rule.table = table_id;
            ip_rule.priority = table_id;
            if (!ipv6_enabled) {
                ip_rule.family = AF_INET;
            }
            planned_rules.push_back(ip_rule);
        }
        // BLACKHOLE: no routing table, no ip rule
        // IGNORE: no routing needed
    }

    // Do not expose a policy rule until every route it can select exists.
    // If either phase fails, remove only the state tracked by this manager and
    // leave the caller to report a failed runtime apply instead of a partial one.
    try {
        for (const auto& route : planned_routes) {
            routes.add(route);
        }
        for (const auto& rule : planned_rules) {
            rules.add(rule);
        }
    } catch (...) {
        rules.clear();
        routes.clear();
        throw;
    }
}

void reconcile_kernel_routing_state(
    RouteTable& routes,
    PolicyRuleManager& rules,
    const std::vector<RouteSpec>& desired_routes,
    const std::vector<RuleSpec>& desired_rules,
    RouteReconcileMode mode) {
    routes.add_missing(desired_routes, mode);
    rules.add_missing(desired_rules);
    rules.remove_obsolete(desired_rules);
    routes.remove_obsolete(desired_routes);
}

bool is_interface_outbound_reachable(const Outbound& outbound, NetlinkManager& netlink) {
    return is_interface_outbound_reachable(outbound, netlink.dump_routes_in_table(254));
}

bool is_interface_outbound_reachable(
    const Outbound& outbound,
    const std::vector<DumpedRoute>& main_table_routes) {
    if (outbound.type != OutboundType::INTERFACE) {
        return true;
    }

    const auto iface = outbound.interface.value_or("");
    if (netlink_detail::query_interface_admin_state(iface) !=
        netlink_detail::InterfaceAdminState::Up) {
        return false;
    }

    if (outbound.gateway.has_value() &&
        !interface_has_gateway_route(main_table_routes, iface, *outbound.gateway)) {
        return false;
    }
    if (outbound.gateway6.has_value() &&
        !interface_has_gateway_route(main_table_routes, iface, *outbound.gateway6)) {
        return false;
    }

    return true;
}

FirewallGlobalPrefilter build_firewall_global_prefilter(
    const Config& cfg,
    const std::vector<InternalVpnServer>& internal_servers) {
    return build_firewall_global_prefilter_for_runtime_targets(
        cfg,
        internal_vpn_interface_runtime_targets(internal_servers));
}

FirewallGlobalPrefilter build_firewall_global_prefilter_for_runtime_targets(
    const Config& cfg,
    const std::vector<InternalVpnRuntimeTarget>& internal_targets) {
    FirewallGlobalPrefilter prefilter;
    prefilter.skip_established_or_dnat = true;
    prefilter.skip_marked_packets = cfg.daemon.value_or(DaemonConfig{}).skip_marked_packets.value_or(true);

    const auto route_cfg = cfg.route.value_or(RouteConfig{});
    const bool legacy_inbound_is_restricted =
        route_cfg.inbound_interfaces.has_value() &&
        !route_cfg.inbound_interfaces->empty();
    if (legacy_inbound_is_restricted) {
        prefilter.inbound_interfaces = *route_cfg.inbound_interfaces;
    }

    std::set<std::string> bypass_interfaces;
    std::set<std::string> include_sources_v4;
    std::set<std::string> include_sources_v6;
    std::set<std::pair<std::string, std::string>>
        bypass_sources_v4;
    std::set<std::pair<std::string, std::string>>
        bypass_sources_v6;
    std::set<std::tuple<std::string, std::string, std::string>>
        bypass_bridge_sources_v4;
    std::set<std::tuple<std::string, std::string, std::string>>
        bypass_bridge_sources_v6;
    std::set<std::pair<std::string, std::string>>
        dns_redirect_bypass_sources_v4;
    std::set<std::pair<std::string, std::string>>
        dns_redirect_bypass_sources_v6;
    for (const auto& target : internal_targets) {
        if (target.match_kind == InternalVpnRuntimeMatchKind::interface &&
            target.interface.has_value() &&
            !target.process_clients) {
            bypass_interfaces.insert(*target.interface);
            continue;
        }
        if (target.match_kind != InternalVpnRuntimeMatchKind::source_pool) {
            continue;
        }
        if (target.process_clients) {
            include_sources_v4.insert(
                target.source_cidrs_v4.begin(),
                target.source_cidrs_v4.end());
            include_sources_v6.insert(
                target.source_cidrs_v6.begin(),
                target.source_cidrs_v6.end());
            for (const auto& interface :
                 target.dns_redirect_bypass_ingress_v4) {
                for (const auto& cidr : target.source_cidrs_v4) {
                    dns_redirect_bypass_sources_v4.emplace(
                        interface, cidr);
                }
            }
            for (const auto& interface :
                 target.dns_redirect_bypass_ingress_v6) {
                for (const auto& cidr : target.source_cidrs_v6) {
                    dns_redirect_bypass_sources_v6.emplace(
                        interface, cidr);
                }
            }
        } else {
            // A source pool alone is not ingress ownership proof. Bind every
            // bypass to an exact, live server-owned interface. When no such
            // interface is verified the target fails closed until Netlink
            // reconciliation supplies one.
            for (const auto& interface :
                 target.verified_ingress_interfaces) {
                for (const auto& cidr : target.source_cidrs_v4) {
                    bypass_sources_v4.emplace(interface, cidr);
                }
                for (const auto& cidr : target.source_cidrs_v6) {
                    bypass_sources_v6.emplace(interface, cidr);
                }
            }
            for (const auto& ingress :
                 target.verified_bridge_ingress_interfaces) {
                for (const auto& cidr : target.source_cidrs_v4) {
                    bypass_bridge_sources_v4.emplace(
                        ingress.interface,
                        ingress.bridge_port,
                        cidr);
                }
                for (const auto& cidr : target.source_cidrs_v6) {
                    bypass_bridge_sources_v6.emplace(
                        ingress.interface,
                        ingress.bridge_port,
                        cidr);
                }
            }
        }
    }

    prefilter.bypass_inbound_interfaces.assign(
        bypass_interfaces.begin(), bypass_interfaces.end());
    prefilter.include_source_cidrs_v4.assign(
        include_sources_v4.begin(), include_sources_v4.end());
    prefilter.include_source_cidrs_v6.assign(
        include_sources_v6.begin(), include_sources_v6.end());
    for (const auto& [interface, cidr] : bypass_sources_v4) {
        prefilter.bypass_source_selectors_v4.push_back(
            {interface, cidr});
    }
    for (const auto& [interface, cidr] : bypass_sources_v6) {
        prefilter.bypass_source_selectors_v6.push_back(
            {interface, cidr});
    }
    for (const auto& [interface, bridge_port, cidr] :
         bypass_bridge_sources_v4) {
        prefilter.bypass_bridge_source_selectors_v4.push_back(
            {interface, bridge_port, cidr});
    }
    for (const auto& [interface, bridge_port, cidr] :
         bypass_bridge_sources_v6) {
        prefilter.bypass_bridge_source_selectors_v6.push_back(
            {interface, bridge_port, cidr});
    }
    for (const auto& [interface, cidr] :
         dns_redirect_bypass_sources_v4) {
        prefilter.dns_redirect_bypass_source_selectors_v4.push_back(
            {interface, cidr});
    }
    for (const auto& [interface, cidr] :
         dns_redirect_bypass_sources_v6) {
        prefilter.dns_redirect_bypass_source_selectors_v6.push_back(
            {interface, cidr});
    }

    if (legacy_inbound_is_restricted) {
        auto& inbound_interfaces = *prefilter.inbound_interfaces;
        for (const auto& target : internal_targets) {
            if (target.match_kind != InternalVpnRuntimeMatchKind::interface ||
                !target.interface.has_value() ||
                !target.process_clients ||
                bypass_interfaces.find(*target.interface) !=
                    bypass_interfaces.end() ||
                std::find(
                    inbound_interfaces.begin(),
                    inbound_interfaces.end(),
                    *target.interface) != inbound_interfaces.end()) {
                continue;
            }
            inbound_interfaces.push_back(*target.interface);
        }
    }

    return prefilter;
}

FirewallGlobalPrefilter build_firewall_global_prefilter(const Config& cfg) {
    const auto route_cfg = cfg.route.value_or(RouteConfig{});
    return build_firewall_global_prefilter(
        cfg,
        route_cfg.internal_vpn_servers.value_or(
            std::vector<InternalVpnServer>{}));
}

FirewallRuleCriteria build_firewall_rule_criteria(const RouteRule& rule) {
    auto strip_neg = [](const std::string& value) -> std::pair<std::string, bool> {
        if (!value.empty() && value.front() == '!') {
            return {value.substr(1), true};
        }
        return {value, false};
    };

    FirewallRuleCriteria criteria;
    criteria.proto = parse_rule_proto(rule.proto);
    if (rule.dscp.has_value()) {
        criteria.dscp = static_cast<uint8_t>(*rule.dscp);
    }

    {
        auto [port, negated] = strip_neg(rule.src_port.value_or(""));
        criteria.src_port = port;
        criteria.negate_src_port = negated;
    }
    {
        auto [port, negated] = strip_neg(rule.dest_port.value_or(""));
        criteria.dst_port = port;
        criteria.negate_dst_port = negated;
    }
    {
        AddrSpec spec = parse_addr_spec(rule.src_addr.value_or(""));
        criteria.negate_src_addr = spec.negate;
        criteria.src_addr = std::move(spec.addrs);
    }
    {
        AddrSpec spec = parse_addr_spec(rule.dest_addr.value_or(""));
        criteria.negate_dst_addr = spec.negate;
        criteria.dst_addr = std::move(spec.addrs);
    }

    return criteria;
}

std::optional<std::string> infer_urltest_selection_from_routes(
    const std::vector<Outbound>& outbounds,
    const Outbound& urltest,
    const std::vector<DumpedRoute>& routes) {
    std::optional<std::string> selected_tag;

    for (const auto& route : routes) {
        if (route.destination != "default" ||
            route.blackhole ||
            route.unreachable ||
            route.metric != 0) {
            continue;
        }

        std::optional<std::string> route_tag;
        for (const auto& group : urltest.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
            for (const auto& child_tag : group.outbounds) {
                const Outbound* child = find_outbound(outbounds, child_tag);
                if (!child || !route_matches_outbound(route, *child)) {
                    continue;
                }
                if (route_tag.has_value() && *route_tag != child_tag) {
                    return std::nullopt;
                }
                route_tag = child_tag;
            }
        }

        if (!route_tag.has_value()) {
            return std::nullopt;
        }
        if (selected_tag.has_value() && *selected_tag != *route_tag) {
            return std::nullopt;
        }
        selected_tag = std::move(route_tag);
    }

    return selected_tag;
}

std::vector<RuleState> build_fw_rule_states(
    const Config& cfg,
    const OutboundMarkMap& marks,
    const std::map<std::string, std::string>* urltest_selections) {
    std::vector<RuleState> rule_states;

    const auto& all_outbounds = cfg.outbounds.value_or(std::vector<Outbound>{});
    static const std::map<std::string, ListConfig> empty_lists;
    const auto& lists_map = cfg.lists ? *cfg.lists : empty_lists;
    const auto& route_rules =
        cfg.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{});

    for (size_t rule_idx = 0; rule_idx < route_rules.size(); ++rule_idx) {
        const auto& rule = route_rules[rule_idx];

        if (!route_rule_enabled(rule)) {
            RuleState rs;
            rs.rule_index = rule_idx;
            rs.list_names = route_rule_lists(rule);
            rs.outbound_tag = rule.outbound;
            rs.action_type = RuleActionType::Skip;
            rule_states.push_back(std::move(rs));
            continue;
        }

        auto decision = resolve_route_action(rule.outbound, all_outbounds);

        if (decision.is_skip) {
            RuleState rs;
            rs.rule_index = rule_idx;
            rs.list_names = route_rule_lists(rule);
            rs.outbound_tag = rule.outbound;
            rs.action_type = RuleActionType::Skip;
            rule_states.push_back(std::move(rs));
            continue;
        }

        if (!decision.outbound.has_value() || !*decision.outbound) {
            RuleState rs;
            rs.rule_index = rule_idx;
            rs.list_names = route_rule_lists(rule);
            rs.outbound_tag = rule.outbound;
            rs.action_type = RuleActionType::Skip;
            rule_states.push_back(std::move(rs));
            continue;
        }

        const Outbound* ob = *decision.outbound;

        if (decision.is_passthrough) {
            RuleState rs;
            rs.rule_index = rule_idx;
            rs.list_names = route_rule_lists(rule);
            rs.outbound_tag = rule.outbound;
            rs.action_type = RuleActionType::Pass;

            for (const auto& list_name : route_rule_lists(rule)) {
                auto list_cfg_it = lists_map.find(list_name);
                if (list_cfg_it == lists_map.end()) continue;

                const std::string set4  = "kpbr4_"  + list_name;
                const std::string set6  = "kpbr6_"  + list_name;
                const std::string set4d = "kpbr4d_" + list_name;
                const std::string set6d = "kpbr6d_" + list_name;

                rs.set_names.push_back(set4);
                rs.set_names.push_back(set6);
                rs.set_names.push_back(set4d);
                rs.set_names.push_back(set6d);
            }

            rule_states.push_back(std::move(rs));
            continue;
        }

        std::string effective_tag = ob->tag;
        const Outbound* effective_ob = ob;

        if (ob->type == OutboundType::URLTEST) {
            // Nested groups resolve down to whatever ends the chain, so a
            // blackhole still becomes a drop and an interface lends its mark.
            const Outbound* leaf =
                resolve_effective_outbound(all_outbounds, *ob, urltest_selections);
            if (leaf) {
                effective_ob = leaf;
                effective_tag = leaf->tag;
            }
        }

        const bool is_blackhole = (effective_ob->type == OutboundType::BLACKHOLE);

        RuleState rs;
        rs.rule_index = rule_idx;
        rs.list_names = route_rule_lists(rule);
        rs.outbound_tag = rule.outbound;

        if (is_blackhole) {
            rs.action_type = RuleActionType::Drop;
        } else {
            rs.action_type = RuleActionType::Mark;
            auto mark_it = marks.find(effective_tag);
            if (mark_it != marks.end()) {
                rs.fwmark = mark_it->second;
            }
        }

        for (const auto& list_name : route_rule_lists(rule)) {
            auto list_cfg_it = lists_map.find(list_name);
            if (list_cfg_it == lists_map.end()) continue;

            const std::string set4  = "kpbr4_"  + list_name;
            const std::string set6  = "kpbr6_"  + list_name;
            const std::string set4d = "kpbr4d_" + list_name;
            const std::string set6d = "kpbr6d_" + list_name;

            rs.set_names.push_back(set4);
            rs.set_names.push_back(set6);
            rs.set_names.push_back(set4d);
            rs.set_names.push_back(set6d);
        }

        rule_states.push_back(std::move(rs));
    }

    return rule_states;
}

void prune_fw_rule_states_to_realized_sets(
    const Config& cfg,
    std::vector<RuleState>& rule_states,
    const ListSetUsageFn& list_usage_fn,
    bool ipv6_enabled) {
    static const std::map<std::string, ListConfig> empty_lists;
    const auto& lists_map = cfg.lists ? *cfg.lists : empty_lists;
    const auto& route_rules =
        cfg.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{});

    std::map<std::string, ListSetUsage> usage_cache;

    for (auto& rs : rule_states) {
        if (rs.action_type == RuleActionType::Skip) {
            continue;
        }
        if (rs.rule_index >= route_rules.size()) {
            continue;
        }

        rs.set_names.clear();

        const auto& rule = route_rules[rs.rule_index];
        rs.criteria = build_firewall_rule_criteria(rule);
        for (const auto& list_name : route_rule_lists(rule)) {
            auto list_cfg_it = lists_map.find(list_name);
            if (list_cfg_it == lists_map.end()) continue;

            auto usage_it = usage_cache.find(list_name);
            if (usage_it == usage_cache.end()) {
                usage_it = usage_cache.emplace(
                    list_name,
                    list_usage_fn(list_name, list_cfg_it->second)).first;
            }
            const auto& usage = usage_it->second;

            if (usage.has_static_entries) {
                rs.set_names.push_back("kpbr4_" + list_name);
                if (ipv6_enabled) {
                    rs.set_names.push_back("kpbr6_" + list_name);
                }
            }
            if (usage.has_domain_entries) {
                rs.set_names.push_back("kpbr4d_" + list_name);
                if (ipv6_enabled) {
                    rs.set_names.push_back("kpbr6d_" + list_name);
                }
            }
        }
    }
}

} // namespace keen_pbr3
