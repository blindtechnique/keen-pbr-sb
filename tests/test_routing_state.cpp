#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/routing_state.hpp"
#include "../src/keenetic/internal_vpn_ingress_resolver.hpp"
#include "../src/routing/netlink.hpp"
#include "../src/routing/policy_rule.hpp"
#include "../src/routing/route_table.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <string>
#include <sys/socket.h>

using namespace keen_pbr3;

namespace {

constexpr uint32_t kUnreachableRouteMetric = 65535;

Config parse_minimal_config(const std::string& json) {
    Config cfg = parse_config(json);
    if (!cfg.dns.has_value()) {
        cfg.dns = DnsConfig{};
    }
    if (!cfg.dns->servers.has_value()) {
        DnsServer fallback_server;
        fallback_server.tag = "default_dns";
        fallback_server.address = "127.0.0.1";
        cfg.dns->servers = std::vector<DnsServer>{fallback_server};
    }
    if (!cfg.dns->fallback.has_value()) {
        cfg.dns->fallback = std::vector<std::string>{"default_dns"};
    }
    if (!cfg.dns->system_resolver.has_value()) {
        api::SystemResolver resolver;
        resolver.address = "127.0.0.1";
        cfg.dns->system_resolver = resolver;
    }
    validate_config(cfg);
    return cfg;
}

InternalVpnServer internal_vpn_policy(std::string interface_name,
                                      bool process_clients) {
    InternalVpnServer policy{};
    policy.interface = std::move(interface_name);
    policy.process_clients = process_clients;
    return policy;
}

const RouteSpec* find_route(const std::vector<RouteSpec>& routes,
                            uint32_t table,
                            bool blackhole,
                            bool unreachable,
                            uint32_t metric = 0,
                            std::optional<std::string> iface = std::nullopt) {
    for (const auto& route : routes) {
        if (route.table == table &&
            route.blackhole == blackhole &&
            route.unreachable == unreachable &&
            route.metric == metric &&
            route.interface == iface) {
            return &route;
        }
    }
    return nullptr;
}

size_t count_routes_in_table(const std::vector<RouteSpec>& routes, uint32_t table) {
    return static_cast<size_t>(std::count_if(routes.begin(),
                                             routes.end(),
                                             [table](const RouteSpec& route) {
                                                 return route.table == table;
                                             }));
}

size_t count_routes_by_family(const std::vector<RouteSpec>& routes, int family) {
    return static_cast<size_t>(std::count_if(routes.begin(),
                                             routes.end(),
                                             [family](const RouteSpec& route) {
                                                 return route.family == family;
                                             }));
}

} // namespace

TEST_CASE("build_fw_rule_states: ignore outbound becomes pass-through firewall rule") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"direct","type":"ignore"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"outbound":"direct"}
            ]
        }
    })");

    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    auto states = build_fw_rule_states(cfg, marks);

    REQUIRE(states.size() == 1);
    CHECK(states[0].action_type == RuleActionType::Pass);
    CHECK(states[0].set_names == std::vector<std::string>({
        "kpbr4_local", "kpbr6_local", "kpbr4d_local", "kpbr6d_local"
    }));
}

TEST_CASE("build_fw_rule_states: disabled route rule is skipped while enabled rules stay active") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"direct","type":"ignore"}
        ],
        "lists":{
            "disabled_list":{"ip_cidrs":["192.168.10.0/24"]},
            "enabled_list":{"ip_cidrs":["192.168.20.0/24"]}
        },
        "route":{
            "rules":[
                {"enabled":false,"list":["disabled_list"],"outbound":"direct"},
                {"list":["enabled_list"],"outbound":"direct"}
            ]
        }
    })");

    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    auto states = build_fw_rule_states(cfg, marks);

    REQUIRE(states.size() == 2);
    CHECK(states[0].action_type == RuleActionType::Skip);
    CHECK(states[0].set_names.empty());
    CHECK(states[0].outbound_tag == "direct");
    CHECK(states[1].action_type == RuleActionType::Pass);
    CHECK(states[1].set_names == std::vector<std::string>({
        "kpbr4_enabled_list", "kpbr6_enabled_list", "kpbr4d_enabled_list", "kpbr6d_enabled_list"
    }));
}

TEST_CASE("build_firewall_global_prefilter: missing inbound_interfaces keeps interface restriction disabled") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"outbound":"wan"}
            ]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK(prefilter.skip_established_or_dnat);
    CHECK(prefilter.skip_marked_packets);
    CHECK_FALSE(prefilter.has_inbound_interfaces());
    CHECK_FALSE(prefilter.inbound_interfaces.has_value());
}

TEST_CASE("build_firewall_global_prefilter: empty inbound_interfaces keeps interface restriction disabled") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "inbound_interfaces":[],
            "rules":[
                {"list":["local"],"outbound":"wan"}
            ]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK(prefilter.skip_established_or_dnat);
    CHECK(prefilter.skip_marked_packets);
    CHECK_FALSE(prefilter.has_inbound_interfaces());
    CHECK_FALSE(prefilter.inbound_interfaces.has_value());
}

TEST_CASE("build_firewall_global_prefilter: inbound_interfaces enables interface restriction") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "inbound_interfaces":["br0","wg0"],
            "rules":[
                {"list":["local"],"outbound":"wan"}
            ]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK(prefilter.skip_established_or_dnat);
    CHECK(prefilter.skip_marked_packets);
    REQUIRE(prefilter.inbound_interfaces.has_value());
    CHECK(prefilter.has_inbound_interfaces());
    CHECK(*prefilter.inbound_interfaces == std::vector<std::string>({"br0", "wg0"}));
}

TEST_CASE("build_firewall_global_prefilter: disabled internal VPN server bypasses legacy default-all") {
    auto cfg = parse_minimal_config(R"({
        "route":{
            "internal_vpn_servers":[
                {"interface":"nwg0","process_clients":false}
            ],
            "rules":[]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK_FALSE(prefilter.has_inbound_interfaces());
    CHECK(prefilter.bypass_inbound_interfaces ==
          std::vector<std::string>{"nwg0"});
}

TEST_CASE("build_firewall_global_prefilter: enabled internal VPN server extends explicit allowlist") {
    auto cfg = parse_minimal_config(R"({
        "route":{
            "inbound_interfaces":["br0"],
            "internal_vpn_servers":[
                {"interface":"nwg0","process_clients":true}
            ],
            "rules":[]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    REQUIRE(prefilter.inbound_interfaces.has_value());
    CHECK(*prefilter.inbound_interfaces ==
          std::vector<std::string>({"br0", "nwg0"}));
    CHECK_FALSE(prefilter.has_bypass_inbound_interfaces());
}

TEST_CASE("build_firewall_global_prefilter: runtime resolution does not rewrite stable config") {
    auto cfg = parse_minimal_config(R"({
        "route":{
            "inbound_interfaces":["br0"],
            "internal_vpn_servers":[
                {
                    "interface":"nwg0",
                    "ndms_id":"WireguardServer",
                    "process_clients":true
                }
            ],
            "rules":[]
        }
    })");
    auto effective = internal_vpn_policy("nwg2", true);
    effective.ndms_id = "WireguardServer";

    const auto prefilter =
        build_firewall_global_prefilter(cfg, {effective});
    REQUIRE(prefilter.inbound_interfaces.has_value());
    CHECK(*prefilter.inbound_interfaces ==
          std::vector<std::string>({"br0", "nwg2"}));
    REQUIRE(cfg.route->internal_vpn_servers.has_value());
    CHECK(cfg.route->internal_vpn_servers->front().interface == "nwg0");
}

TEST_CASE("build_firewall_global_prefilter: enabled internal VPN server does not restrict legacy default-all") {
    auto cfg = parse_minimal_config(R"({
        "route":{
            "internal_vpn_servers":[
                {"interface":"nwg0","process_clients":true}
            ],
            "rules":[]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK_FALSE(prefilter.has_inbound_interfaces());
    CHECK_FALSE(prefilter.has_bypass_inbound_interfaces());
}

TEST_CASE("build_firewall_global_prefilter: explicit empty ingress remains default-all with internal VPN policies") {
    auto cfg = parse_minimal_config(R"({
        "route":{
            "inbound_interfaces":[],
            "internal_vpn_servers":[
                {"interface":"nwg0","process_clients":true},
                {"interface":"ovpn0","process_clients":false}
            ],
            "rules":[]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK_FALSE(prefilter.has_inbound_interfaces());
    CHECK_FALSE(prefilter.inbound_interfaces.has_value());
    CHECK(prefilter.bypass_inbound_interfaces ==
          std::vector<std::string>{"ovpn0"});
}

TEST_CASE("build_firewall_global_prefilter: false wins defensively and legacy allowlist remains intact") {
    auto cfg = parse_minimal_config(R"({
        "route":{"inbound_interfaces":["br0","nwg0"],"rules":[]}
    })");
    REQUIRE(cfg.route.has_value());
    cfg.route->internal_vpn_servers = std::vector<InternalVpnServer>{
        internal_vpn_policy("nwg0", true),
        internal_vpn_policy("nwg0", false),
    };

    const auto prefilter = build_firewall_global_prefilter(cfg);
    REQUIRE(prefilter.inbound_interfaces.has_value());
    CHECK(*prefilter.inbound_interfaces ==
          std::vector<std::string>({"br0", "nwg0"}));
    CHECK(prefilter.bypass_inbound_interfaces ==
          std::vector<std::string>{"nwg0"});
}

TEST_CASE("build_firewall_global_prefilter: service pools extend an explicit ingress allowlist") {
    auto cfg = parse_minimal_config(R"({
        "route":{"inbound_interfaces":["br0"],"rules":[]}
    })");

    InternalVpnRuntimeTarget include;
    include.stable_id = "ndms-crypto-map:ike2";
    include.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    include.process_clients = true;
    include.source_cidrs_v4 = {"172.20.8.0/23"};
    include.source_cidrs_v6 = {"2001:db8:20::/64"};

    InternalVpnRuntimeTarget bypass;
    bypass.stable_id = "ndms-service:sstp-server";
    bypass.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    bypass.process_clients = false;
    bypass.interface = "Sstp0";
    bypass.verified_ingress_interfaces = {"br0"};
    bypass.source_cidrs_v4 = {"172.16.1.0/24"};

    const auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, {include, bypass});
    REQUIRE(prefilter.inbound_interfaces.has_value());
    CHECK(*prefilter.inbound_interfaces ==
          std::vector<std::string>{"br0"});
    CHECK(prefilter.include_source_cidrs_v4 ==
          std::vector<std::string>{"172.20.8.0/23"});
    CHECK(prefilter.include_source_cidrs_v6 ==
          std::vector<std::string>{"2001:db8:20::/64"});
    REQUIRE(prefilter.bypass_source_selectors_v4.size() == 1U);
    CHECK(
        prefilter.bypass_source_selectors_v4[0].interface ==
        "br0");
    CHECK(
        prefilter.bypass_source_selectors_v4[0].cidr ==
        "172.16.1.0/24");
}

TEST_CASE(
    "build_firewall_global_prefilter: addressless IKE keeps route scope "
    "while bypassing DNS redirect only") {
    auto cfg = parse_minimal_config(
        R"({"route":{"inbound_interfaces":["br0"],"rules":[]}})");

    InternalVpnRuntimeTarget ikev2;
    ikev2.stable_id =
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2";
    ikev2.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    ikev2.process_clients = true;
    ikev2.verified_ingress_interfaces = {"xfrms1"};
    ikev2.dns_redirect_bypass_ingress_v4 = {"xfrms1"};
    ikev2.source_cidrs_v4 = {"172.20.8.0/23"};

    const auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, {ikev2});
    CHECK(
        prefilter.include_source_cidrs_v4 ==
        std::vector<std::string>{"172.20.8.0/23"});
    CHECK(prefilter.bypass_source_selectors_v4.empty());
    REQUIRE(
        prefilter.dns_redirect_bypass_source_selectors_v4.size() ==
        1U);
    CHECK(
        prefilter.dns_redirect_bypass_source_selectors_v4[0]
            .interface == "xfrms1");
    CHECK(
        prefilter.dns_redirect_bypass_source_selectors_v4[0].cidr ==
        "172.20.8.0/23");
}

TEST_CASE(
    "build_firewall_global_prefilter: pooled bypass fails closed "
    "without verified server ingress") {
    auto cfg = parse_minimal_config(
        R"({"route":{"rules":[]}})");
    InternalVpnRuntimeTarget bypass;
    bypass.stable_id = "ndms-service:sstp-server";
    bypass.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    bypass.process_clients = false;
    bypass.interface = "br0";
    bypass.source_cidrs_v4 = {"172.16.1.0/24"};

    const auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, {bypass});
    CHECK_FALSE(prefilter.has_bypass_source_cidrs());
    CHECK(prefilter.bypass_inbound_interfaces.empty());
}

TEST_CASE(
    "bridged SSTP exclusion requires the verified physical bridge port") {
    auto cfg = parse_minimal_config(
        R"({"route":{"rules":[]}})");
    InternalVpnRuntimeTarget sstp;
    sstp.stable_id = "ndms-service:sstp-server";
    sstp.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    sstp.process_clients = false;
    sstp.interface = "br1";
    sstp.source_cidrs_v4 = {"172.16.1.0/24"};

    DumpedInterface bridge;
    bridge.name = "sstp-bridge";
    DumpedInterface peer_link;
    peer_link.name = "sstp-peer-link";
    peer_link.master_interface = "sstp-bridge";
    DumpedInterface br_link;
    br_link.name = "sstp-br-link";
    br_link.master_interface = "br1";
    DumpedInterface lan;
    lan.name = "br1";
    DumpedInterface session;
    session.name = "sstp3";
    session.admin_up = true;
    session.carrier = true;
    session.master_interface = "sstp-bridge";
    session.ipv4_peer_addresses = {"172.16.1.33/32"};

    std::vector<InternalVpnRuntimeTarget> targets{sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, br_link, lan, session});
    REQUIRE(targets.front().verified_ingress_interfaces.empty());
    REQUIRE(
        targets.front().verified_bridge_ingress_interfaces ==
        std::vector<InternalVpnVerifiedBridgeIngress>{
            {"br1", "sstp-br-link"}});

    auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, targets);
    CHECK(prefilter.bypass_source_selectors_v4.empty());
    REQUIRE(
        prefilter.bypass_bridge_source_selectors_v4.size() == 1U);
    CHECK(
        prefilter.bypass_bridge_source_selectors_v4[0].interface ==
        "br1");
    CHECK(
        prefilter.bypass_bridge_source_selectors_v4[0].bridge_port ==
        "sstp-br-link");
    CHECK(
        prefilter.bypass_bridge_source_selectors_v4[0].cidr ==
        "172.16.1.0/24");

    // The client pool plus only half of the veth topology is not ownership
    // proof. Do not degrade to a weak bridge-name/source-only bypass.
    targets = {sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, lan, session});
    REQUIRE(targets.front().verified_ingress_interfaces.empty());
    REQUIRE(targets.front().verified_bridge_ingress_interfaces.empty());
    prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, targets);
    CHECK(prefilter.bypass_source_selectors_v4.empty());
    CHECK(prefilter.bypass_bridge_source_selectors_v4.empty());
    CHECK_FALSE(prefilter.has_bypass_source_cidrs());
}

TEST_CASE("build_firewall_global_prefilter: inherited service include preserves default-all") {
    auto cfg = parse_minimal_config(
        R"({"route":{"rules":[]}})");
    InternalVpnRuntimeTarget include;
    include.stable_id = "ndms-service:sstp-server";
    include.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    include.process_clients = true;
    include.source_cidrs_v4 = {"172.16.1.0/24"};

    const auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, {include});
    CHECK_FALSE(prefilter.has_inbound_interfaces());
    CHECK(prefilter.include_source_cidrs_v4 ==
          std::vector<std::string>{"172.16.1.0/24"});
    CHECK_FALSE(prefilter.has_bypass_source_cidrs());
}

TEST_CASE("build_firewall_global_prefilter: daemon.skip_marked_packets false disables marked-packet bypass") {
    auto cfg = parse_minimal_config(R"({
        "daemon":{"skip_marked_packets":false},
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"outbound":"wan"}
            ]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK(prefilter.skip_established_or_dnat);
    CHECK_FALSE(prefilter.skip_marked_packets);
}

TEST_CASE("build_firewall_global_prefilter: daemon.skip_marked_packets null keeps marked-packet bypass enabled") {
    auto cfg = parse_minimal_config(R"({
        "daemon":{"skip_marked_packets":null},
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"outbound":"wan"}
            ]
        }
    })");

    const auto prefilter = build_firewall_global_prefilter(cfg);
    CHECK(prefilter.skip_established_or_dnat);
    CHECK(prefilter.skip_marked_packets);
}

TEST_CASE("build_fw_rule_states: urltest selection to blackhole becomes drop rule") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"bh","type":"blackhole"},
            {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "outbound_groups":[{"outbounds":["wan","bh"]}]}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"outbound":"auto"}
            ]
        }
    })");

    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    std::map<std::string, std::string> selections{{"auto", "bh"}};
    auto states = build_fw_rule_states(cfg, marks, &selections);

    REQUIRE(states.size() == 1);
    CHECK(states[0].action_type == RuleActionType::Drop);
}

TEST_CASE("build_fw_rule_states: selector-only route rule without list still becomes mark rule") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"cloudflare","type":"interface","interface":"wg0","gateway":"10.0.0.1"}
        ],
        "route":{
            "rules":[
                {"dest_port":"443,80","outbound":"cloudflare"}
            ]
        }
    })");

    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    auto states = build_fw_rule_states(cfg, marks);

    REQUIRE(states.size() == 1);
    CHECK(states[0].action_type == RuleActionType::Mark);
    CHECK(states[0].set_names.empty());
    CHECK(states[0].outbound_tag == "cloudflare");
    CHECK(states[0].fwmark != 0);
}

TEST_CASE("prune_fw_rule_states_to_realized_sets: removes nonexistent pass-through set variants") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"direct","type":"ignore"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"outbound":"direct"}
            ]
        }
    })");

    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    auto states = build_fw_rule_states(cfg, marks);

    prune_fw_rule_states_to_realized_sets(
        cfg,
        states,
        [](const std::string&, const ListConfig&) {
            ListSetUsage usage;
            usage.has_static_entries = true;
            usage.has_domain_entries = false;
            return usage;
        });

    REQUIRE(states.size() == 1);
    CHECK(states[0].action_type == RuleActionType::Pass);
    CHECK(states[0].set_names == std::vector<std::string>({
        "kpbr4_local", "kpbr6_local"
    }));
}

TEST_CASE("prune_fw_rule_states_to_realized_sets: matches runtime selectors and ipv6 filtering") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1"}
        ],
        "lists":{
            "local":{"ip_cidrs":["192.168.0.0/16"],"domains":["example.com"]}
        },
        "route":{
            "rules":[
                {"list":["local"],"src_addr":"!192.0.2.1","dest_port":"443","outbound":"vpn"}
            ]
        }
    })");

    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    auto states = build_fw_rule_states(cfg, marks);

    prune_fw_rule_states_to_realized_sets(
        cfg,
        states,
        [](const std::string&, const ListConfig&) {
            ListSetUsage usage;
            usage.has_static_entries = true;
            usage.has_domain_entries = true;
            return usage;
        },
        false);

    REQUIRE(states.size() == 1);
    CHECK(states[0].set_names == std::vector<std::string>({
        "kpbr4_local", "kpbr4d_local"
    }));
    CHECK(states[0].criteria.src_addr == std::vector<std::string>({"192.0.2.1"}));
    CHECK(states[0].criteria.negate_src_addr);
    CHECK(states[0].criteria.dst_port.to_config_string() == "443");
}

TEST_CASE("infer_urltest_selection_from_routes: accepts equivalent dual-stack defaults") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"backup","type":"interface","interface":"wg1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "outbound_groups":[{"outbounds":["vpn","backup"]}]}
        ]
    })");

    const auto& outbounds = *cfg.outbounds;
    const auto& urltest = outbounds[2];
    std::vector<DumpedRoute> routes(3);
    routes[0].destination = "default";
    routes[0].interface = "wg0";
    routes[0].family = AF_INET;
    routes[1].destination = "default";
    routes[1].interface = "wg0";
    routes[1].family = AF_INET6;
    routes[2].destination = "default";
    routes[2].interface = "wg1";
    routes[2].family = AF_INET;
    routes[2].metric = 1;

    CHECK(infer_urltest_selection_from_routes(outbounds, urltest, routes) ==
          std::optional<std::string>{"vpn"});
}

TEST_CASE("infer_urltest_selection_from_routes: rejects conflicting metric-zero defaults") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"backup","type":"interface","interface":"wg1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "outbound_groups":[{"outbounds":["vpn","backup"]}]}
        ]
    })");

    const auto& outbounds = *cfg.outbounds;
    const auto& urltest = outbounds[2];
    std::vector<DumpedRoute> routes(2);
    routes[0].destination = "default";
    routes[0].interface = "wg0";
    routes[0].family = AF_INET;
    routes[1].destination = "default";
    routes[1].interface = "wg1";
    routes[1].family = AF_INET6;

    CHECK_FALSE(infer_urltest_selection_from_routes(outbounds, urltest, routes).has_value());
}

TEST_CASE("populate_routing_state: strict enforcement installs unreachable default when down") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":true},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return false;
    });

    REQUIRE(routes.get_routes().size() == 2);
    CHECK(find_route(routes.get_routes(), 100, false, true, kUnreachableRouteMetric) != nullptr);
    CHECK(find_route(routes.get_routes(), 100, true, false) == nullptr);
}

TEST_CASE("populate_routing_state: strict enforcement installs real default when up") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":true},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    });

    REQUIRE(routes.get_routes().size() == 3);
    const RouteSpec* default_route = find_route(routes.get_routes(), 100, false, false, 0, std::optional<std::string>{"wg0"});
    REQUIRE(default_route != nullptr);
    CHECK(default_route->interface == std::optional<std::string>{"wg0"});
    CHECK(default_route->gateway == std::optional<std::string>{"10.8.0.1"});
    CHECK(find_route(routes.get_routes(), 100, false, true, kUnreachableRouteMetric) != nullptr);
}

TEST_CASE("populate_routing_state: ipv6 disabled emits only ipv4 interface routing state") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":true,"ipv6_enabled":false},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    }, nullptr, false);

    CHECK(count_routes_by_family(routes.get_routes(), AF_INET6) == 0);
    REQUIRE(rules.get_rules().size() == 1);
    CHECK(rules.get_rules()[0].family == AF_INET);
}

TEST_CASE("populate_routing_state: ipv6 disabled skips urltest ipv6 kill-switch route") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false,"ipv6_enabled":false},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com","interval":30,
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));
    std::map<std::string, std::string> selections{{"auto", "vpn"}};

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    }, &selections, false);

    CHECK(count_routes_by_family(routes.get_routes(), AF_INET6) == 0);
    REQUIRE(rules.get_rules().size() == 2);
    CHECK(rules.get_rules()[0].family == AF_INET);
    CHECK(rules.get_rules()[1].family == AF_INET);
}

TEST_CASE("populate_routing_state: unreachable interface outbound remains unavailable when strict is disabled") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":true},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1","strict_enforcement":false}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return false;
    });

    CHECK(routes.get_routes().empty());
    CHECK(find_route(routes.get_routes(), 100, false, true) == nullptr);
    REQUIRE(rules.get_rules().size() == 1);
    CHECK(rules.get_rules()[0].table == 100);
}

TEST_CASE("populate_routing_state: outbound true overrides daemon false") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1","strict_enforcement":true}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return false;
    });

    REQUIRE(routes.get_routes().size() == 2);
    CHECK(find_route(routes.get_routes(), 100, false, true, kUnreachableRouteMetric) != nullptr);
}

TEST_CASE("populate_routing_state: strict urltest installs selected primary, weighted fallbacks, and unreachable terminal") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1","gateway":"10.0.1.1"},
            {"tag":"vpn2","type":"interface","interface":"wg2","gateway":"10.0.2.1"},
            {"tag":"wan1","type":"interface","interface":"eth0","gateway":"192.168.1.1"},
            {"tag":"wan2","type":"interface","interface":"eth1","gateway":"192.168.2.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "strict_enforcement":true,
             "outbound_groups":[
                 {"weight":1,"outbounds":["vpn1","vpn2"]},
                 {"weight":2,"outbounds":["wan1","wan2"]}
             ]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    std::map<std::string, std::string> selections{{"auto", "vpn2"}};

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [](const Outbound&) { return true; },
        &selections);

    REQUIRE(routes.get_routes().size() == 14);
    CHECK(find_route(routes.get_routes(), 104, false, false, 0, std::optional<std::string>{"wg2"}) != nullptr);
    CHECK(find_route(routes.get_routes(), 104, false, false, 1, std::optional<std::string>{"wg1"}) != nullptr);
    CHECK(find_route(routes.get_routes(), 104, false, false, 2, std::optional<std::string>{"eth0"}) != nullptr);
    CHECK(find_route(routes.get_routes(), 104, false, false, 3, std::optional<std::string>{"eth1"}) != nullptr);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 104 &&
                                   !route.unreachable &&
                                   route.interface == "wg2";
                        }) == 1);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 104 &&
                                   route.unreachable &&
                                   route.metric == kUnreachableRouteMetric &&
                                   (route.family == AF_INET || route.family == AF_INET6);
                        }) == 2);
}

TEST_CASE("populate_routing_state: strict urltest skips unreachable children") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1","gateway":"10.0.1.1"},
            {"tag":"vpn2","type":"interface","interface":"wg2","gateway":"10.0.2.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "strict_enforcement":true,
             "outbound_groups":[{"weight":1,"outbounds":["vpn1","vpn2"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    std::map<std::string, std::string> selections{{"auto", "vpn2"}};

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [](const Outbound& ob) { return ob.tag != "vpn1"; },
        &selections);

    REQUIRE(routes.get_routes().size() == 5);
    CHECK(find_route(routes.get_routes(), 102, false, false, 0, std::optional<std::string>{"wg2"}) != nullptr);
    CHECK(find_route(routes.get_routes(), 102, false, false, 1, std::optional<std::string>{"wg1"}) == nullptr);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 102 &&
                                   route.unreachable &&
                                   route.metric == kUnreachableRouteMetric &&
                                   (route.family == AF_INET || route.family == AF_INET6);
                        }) == 2);
}

TEST_CASE("populate_routing_state: urltest uses one reachability snapshot per child") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1"},
            {"tag":"vpn2","type":"interface","interface":"wg2"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "strict_enforcement":true,
             "outbound_groups":[{"weight":1,"outbounds":["vpn1","vpn2"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    std::map<std::string, std::string> selections{{"auto", "vpn1"}};
    std::map<std::string, size_t> reachability_checks;

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [&reachability_checks](const Outbound& outbound) {
            ++reachability_checks[outbound.tag];
            return outbound.tag != "vpn1";
        },
        &selections);

    CHECK(reachability_checks["vpn1"] == 1);
    CHECK(reachability_checks["vpn2"] == 1);
    CHECK(find_route(routes.get_routes(), 102, false, false, 0,
                     std::optional<std::string>{"wg1"}) == nullptr);
    CHECK(find_route(routes.get_routes(), 102, false, false, 1,
                     std::optional<std::string>{"wg2"}) != nullptr);
}

TEST_CASE("populate_routing_state: mixed-family urltest closures stay terminal") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"dead","type":"interface","interface":"wg0","gateway":"10.0.0.1"},
            {"tag":"ipv4","type":"interface","interface":"wg4","gateway":"10.0.4.1"},
            {"tag":"ipv6","type":"interface","interface":"wg6","gateway6":"2001:db8::1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "strict_enforcement":true,
             "outbound_groups":[{"weight":1,"outbounds":["dead","ipv4","ipv6"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(
        cfg.fwmark.value_or(FwmarkConfig{}),
        cfg.outbounds.value_or(std::vector<Outbound>{}));

    std::map<std::string, std::string> selections{{"auto", "dead"}};
    std::map<std::string, size_t> reachability_checks;

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [&reachability_checks](const Outbound& outbound) {
            ++reachability_checks[outbound.tag];
            return outbound.tag != "dead";
        },
        &selections);

    CHECK(reachability_checks["dead"] == 1);
    CHECK(reachability_checks["ipv4"] == 1);
    CHECK(reachability_checks["ipv6"] == 1);
    CHECK(find_route(routes.get_routes(), 103, false, false, 1,
                     std::optional<std::string>{"wg4"}) != nullptr);
    CHECK(find_route(routes.get_routes(), 103, false, false, 2,
                     std::optional<std::string>{"wg6"}) != nullptr);
    CHECK(std::none_of(
        routes.get_routes().begin(),
        routes.get_routes().end(),
        [](const RouteSpec& route) {
            return route.table == 103 && route.unreachable &&
                   route.metric != kUnreachableRouteMetric;
        }));
    CHECK(std::count_if(
              routes.get_routes().begin(),
              routes.get_routes().end(),
              [](const RouteSpec& route) {
                  return route.table == 103 && route.unreachable &&
                         route.metric == kUnreachableRouteMetric &&
                         (route.family == AF_INET ||
                          route.family == AF_INET6);
              }) == 2);
}

TEST_CASE("populate_routing_state: disabled-family children do not consume fallback metrics") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false,"ipv6_enabled":false},
        "outbounds":[
            {"tag":"ipv6a","type":"interface","interface":"wg6a","gateway6":"2001:db8::1"},
            {"tag":"ipv6b","type":"interface","interface":"wg6b","gateway6":"2001:db8::2"},
            {"tag":"ipv4","type":"interface","interface":"wg4","gateway":"10.0.4.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "strict_enforcement":true,
             "outbound_groups":[{"weight":1,"outbounds":["ipv6a","ipv6b","ipv4"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(
        cfg.fwmark.value_or(FwmarkConfig{}),
        cfg.outbounds.value_or(std::vector<Outbound>{}));

    std::map<std::string, std::string> selections{{"auto", "ipv6a"}};
    std::map<std::string, size_t> reachability_checks;

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [&reachability_checks](const Outbound& outbound) {
            ++reachability_checks[outbound.tag];
            return true;
        },
        &selections,
        false);

    CHECK(reachability_checks["ipv6a"] == 1);
    CHECK(reachability_checks["ipv6b"] == 1);
    CHECK(reachability_checks["ipv4"] == 1);
    CHECK(find_route(routes.get_routes(), 103, false, false, 1,
                     std::optional<std::string>{"wg4"}) != nullptr);
    CHECK(std::none_of(
        routes.get_routes().begin(),
        routes.get_routes().end(),
        [](const RouteSpec& route) {
            return route.table == 103 && route.family == AF_INET6;
        }));
}

TEST_CASE("populate_routing_state: urltest without completed probe installs only terminal kill-switch routes") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1","gateway":"10.0.1.1"},
            {"tag":"vpn2","type":"interface","interface":"wg2","gateway":"10.0.2.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "outbound_groups":[{"weight":1,"outbounds":["vpn1","vpn2"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [](const Outbound&) { return true; },
        nullptr);

    CHECK(count_routes_in_table(routes.get_routes(), 102) == 2);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 102 &&
                                   route.unreachable &&
                                   route.metric == kUnreachableRouteMetric &&
                                   (route.family == AF_INET || route.family == AF_INET6);
                        }) == 2);
    REQUIRE(rules.get_rules().size() == 3);
    CHECK(rules.get_rules()[2].table == 102);
}

TEST_CASE("populate_routing_state: urltest without completed probe keeps only terminal kill-switch routes") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1","gateway":"10.0.1.1"},
            {"tag":"vpn2","type":"interface","interface":"wg2","gateway":"10.0.2.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "strict_enforcement":true,
             "outbound_groups":[{"weight":1,"outbounds":["vpn1","vpn2"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [](const Outbound&) { return true; },
        nullptr);

    REQUIRE(count_routes_in_table(routes.get_routes(), 102) == 2);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 102 &&
                                   route.unreachable &&
                                   route.metric == kUnreachableRouteMetric &&
                                   (route.family == AF_INET || route.family == AF_INET6);
                        }) == 2);
}

TEST_CASE("populate_routing_state: interface outbound without gateway installs dual-stack defaults") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    });

    // Tunnel-style outbounds (no gateway) default to strict enforcement:
    // two real defaults plus a dual-stack unreachable kill-switch.
    REQUIRE(routes.get_routes().size() == 4);
    CHECK(find_route(routes.get_routes(), 100, false, false, 0, std::optional<std::string>{"wg0"}) != nullptr);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 &&
                                   !route.unreachable &&
                                   !route.blackhole &&
                                   route.interface == std::optional<std::string>{"wg0"} &&
                                   (route.family == AF_INET || route.family == AF_INET6);
                        }) == 2);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 && route.unreachable;
                        }) == 2);
}

TEST_CASE("populate_routing_state: tunnel outbound strict default can be disabled per outbound") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","strict_enforcement":false}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    });

    REQUIRE(routes.get_routes().size() == 2);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 && route.unreachable;
                        }) == 0);
}

TEST_CASE("populate_routing_state: daemon strict_enforcement=false overrides tunnel default") {
    auto cfg = parse_minimal_config(R"({
        "daemon":{"strict_enforcement":false},
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    });

    REQUIRE(routes.get_routes().size() == 2);
}

TEST_CASE("populate_routing_state: interface outbound with IPv4 gateway closes IPv6 with unreachable default") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    });

    REQUIRE(routes.get_routes().size() == 2);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 &&
                                   !route.unreachable &&
                                   route.gateway == std::optional<std::string>{"10.8.0.1"} &&
                                   route.family == AF_INET;
                        }) == 1);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 &&
                                   route.unreachable &&
                                   route.family == AF_INET6;
                        }) == 1);
}

TEST_CASE("populate_routing_state: interface outbound with distinct IPv4 and IPv6 gateways installs both routes") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","gateway":"10.8.0.1","gateway6":"2001:db8::1"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(cfg, marks, routes, rules, [](const Outbound&) {
        return true;
    });

    REQUIRE(routes.get_routes().size() == 2);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 &&
                                   !route.unreachable &&
                                   route.family == AF_INET &&
                                   route.gateway == std::optional<std::string>{"10.8.0.1"};
                        }) == 1);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 100 &&
                                   !route.unreachable &&
                                   route.family == AF_INET6 &&
                                   route.gateway == std::optional<std::string>{"2001:db8::1"};
                        }) == 1);
}

// =============================================================================
// Reserved-table skipping
// =============================================================================

TEST_CASE("populate_routing_state: allocation skips reserved block 250-260") {
    // table_start=249: offset 0 → 249, offset 1 → 261 (250-260 skipped)
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":249},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1"},
            {"tag":"vpn2","type":"interface","interface":"wg2"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);
    populate_routing_state(cfg, marks, routes, rules);

    const auto& rule_list = rules.get_rules();
    REQUIRE(rule_list.size() == 2);
    CHECK(rule_list[0].table == 249);
    CHECK(rule_list[1].table == 261); // jumped over 250-260

    for (const auto& rule : rule_list) {
        CHECK_FALSE(is_reserved_table(rule.table));
    }
}

TEST_CASE("populate_routing_state: allocation skips prelocal table 128") {
    // table_start=127: offset 0 → 127, offset 1 → 129 (128 skipped)
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":127},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1"},
            {"tag":"vpn2","type":"interface","interface":"wg2"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);
    populate_routing_state(cfg, marks, routes, rules);

    const auto& rule_list = rules.get_rules();
    REQUIRE(rule_list.size() == 2);
    CHECK(rule_list[0].table == 127);
    CHECK(rule_list[1].table == 129); // jumped over 128

    for (const auto& rule : rule_list) {
        CHECK_FALSE(is_reserved_table(rule.table));
    }
}

TEST_CASE("populate_routing_state: no allocated table falls in reserved range") {
    // table_start=248 with 4 outbounds crosses both 250-260 and prelocal-adjacent area
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":248},
        "outbounds":[
            {"tag":"a","type":"interface","interface":"wg1"},
            {"tag":"b","type":"interface","interface":"wg2"},
            {"tag":"c","type":"interface","interface":"wg3"},
            {"tag":"d","type":"interface","interface":"wg4"}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);
    populate_routing_state(cfg, marks, routes, rules);

    for (const auto& rule : rules.get_rules()) {
        CHECK_FALSE(is_reserved_table(rule.table));
    }
    for (const auto& route : routes.get_routes()) {
        CHECK_FALSE(is_reserved_table(route.table));
    }
}

TEST_CASE("populate_routing_state: non-strict urltest still appends dual-stack kill-switch routes") {
    auto cfg = parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "daemon":{"strict_enforcement":false},
        "outbounds":[
            {"tag":"vpn1","type":"interface","interface":"wg1","gateway":"10.0.1.1"},
            {"tag":"vpn2","type":"interface","interface":"wg2","gateway":"10.0.2.1"},
            {"tag":"auto","type":"urltest","url":"http://example.com",
             "outbound_groups":[{"weight":1,"outbounds":["vpn1","vpn2"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    std::map<std::string, std::string> selections{{"auto", "vpn2"}};

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    populate_routing_state(
        cfg,
        marks,
        routes,
        rules,
        [](const Outbound&) { return true; },
        &selections);

    CHECK(count_routes_in_table(routes.get_routes(), 102) == 4);
    CHECK(find_route(routes.get_routes(),
                     102,
                     false,
                     false,
                     0,
                     std::optional<std::string>{"wg2"}) != nullptr);
    CHECK(find_route(routes.get_routes(),
                     102,
                     false,
                     false,
                     1,
                     std::optional<std::string>{"wg1"}) != nullptr);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 102 &&
                                   !route.unreachable &&
                                   route.interface == "wg2";
                        }) == 1);
    CHECK(std::count_if(routes.get_routes().begin(),
                        routes.get_routes().end(),
                        [](const RouteSpec& route) {
                            return route.table == 102 &&
                                   route.unreachable &&
                                   route.metric == kUnreachableRouteMetric;
                        }) == 2);
}

// A failover group may list another failover group. Routing has to follow the
// selections down to a real interface, otherwise the table would hold nothing
// but the kill-switch and the traffic would be dropped.
TEST_CASE("populate_routing_state: nested urltest resolves to a leaf interface") {
    auto cfg = parse_minimal_config(R"({
        "daemon":{"strict_enforcement":false},
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"vpn_a","type":"interface","interface":"wg0","gateway":"10.0.0.1"},
            {"tag":"vpn_b","type":"interface","interface":"wg1","gateway":"10.0.1.1"},
            {"tag":"inner","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["vpn_a","vpn_b"]}]},
            {"tag":"outer","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["inner"]}]}
        ]
    })");
    auto marks = allocate_outbound_marks(cfg.fwmark.value_or(FwmarkConfig{}),
                                         cfg.outbounds.value_or(std::vector<Outbound>{}));

    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    std::map<std::string, std::string> selections{
        {"outer", "inner"},
        {"inner", "vpn_b"},
    };
    populate_routing_state(cfg, marks, routes, rules,
                           [](const Outbound&) { return true; }, &selections);

    // The outer group gets its own table; it must carry the leaf interface.
    const auto& installed = routes.get_routes();
    const bool has_leaf = std::any_of(
        installed.begin(), installed.end(), [](const RouteSpec& route) {
            return route.interface == std::optional<std::string>{"wg1"} &&
                   !route.unreachable && route.metric == 0;
        });
    CHECK(has_leaf);
}

// A group that references itself is rejected outright, so a mis-typed config
// can never send the resolver into a loop.
TEST_CASE("config validation: self-referencing urltest is rejected") {
    CHECK_THROWS(parse_minimal_config(R"({
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"loop","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["loop"]}]}
        ]
    })"));
}

// Two groups pointing at each other are rejected before runtime state is built.
// The depth guard remains defence-in-depth for already loaded legacy state.
TEST_CASE("config validation: mutually referencing urltests are rejected") {
    CHECK_THROWS(parse_minimal_config(R"({
        "daemon":{"strict_enforcement":false},
        "iproute":{"table_start":100},
        "outbounds":[
            {"tag":"first","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["second"]}]},
            {"tag":"second","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["first"]}]}
        ]
    })"));
}

TEST_CASE("outbound marks stay stable when independent entries are reordered") {
    const auto first = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"zeta","type":"interface","interface":"wg0"},
            {"tag":"ignored","type":"ignore"},
            {"tag":"alpha","type":"table","table":200},
            {"tag":"selector","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["zeta","alpha"]}]}
        ]
    })");
    const auto second = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"selector","type":"urltest","url":"https://example.org",
             "outbound_groups":[{"outbounds":["zeta","alpha"]}]},
            {"tag":"alpha","type":"table","table":200},
            {"tag":"ignored","type":"ignore"},
            {"tag":"zeta","type":"interface","interface":"wg0"}
        ]
    })");

    const auto first_marks = allocate_outbound_marks(
        first.fwmark.value_or(FwmarkConfig{}),
        first.outbounds.value_or(std::vector<Outbound>{}));
    const auto second_marks = allocate_outbound_marks(
        second.fwmark.value_or(FwmarkConfig{}),
        second.outbounds.value_or(std::vector<Outbound>{}));

    CHECK(first_marks == second_marks);
    CHECK(first_marks.size() == 3);
    CHECK(first_marks.at("alpha") < first_marks.at("selector"));
    CHECK(first_marks.at("selector") < first_marks.at("zeta"));
    CHECK(first_marks.count("ignored") == 0);
}

TEST_CASE("routing state managers reconcile without destructive clear") {
    NetlinkManager netlink;
    RouteTable routes(netlink, true);
    PolicyRuleManager rules(netlink, true);

    RouteSpec old_route;
    old_route.destination = "default";
    old_route.table = 150;
    old_route.interface = "wg-old";
    RouteSpec new_route = old_route;
    new_route.interface = "wg-new";

    RuleSpec old_rule;
    old_rule.fwmark = 0x10000;
    old_rule.fwmask = 0xFF0000;
    old_rule.table = 150;
    old_rule.priority = 150;
    RuleSpec new_rule = old_rule;
    new_rule.table = 151;
    new_rule.priority = 151;

    routes.add(old_route);
    rules.add(old_rule);
    routes.reconcile({new_route});
    rules.reconcile({new_rule});

    REQUIRE(routes.get_routes().size() == 1);
    CHECK(routes.get_routes().front().interface == std::optional<std::string>{"wg-new"});
    REQUIRE(rules.get_rules().size() == 1);
    CHECK(rules.get_rules().front().table == 151);
}

TEST_CASE("route table clear only releases tracked routes") {
    NetlinkManager netlink;
    RouteTable routes(netlink, true);

    RouteSpec first;
    first.destination = "default";
    first.table = 150;
    first.interface = "wg0";
    RouteSpec second = first;
    second.table = 151;

    routes.add(first);
    routes.add(second);
    routes.clear();

    CHECK(routes.get_routes().empty());
}

TEST_CASE("live route matching keeps urltest metrics distinct") {
    RouteSpec selected;
    selected.destination = "default";
    selected.table = 155;
    selected.interface = "nwg2";
    selected.family = AF_INET;
    selected.metric = 0;

    RouteSpec fallback = selected;
    fallback.metric = 1;

    DumpedRoute live;
    live.destination = "default";
    live.table = 155;
    live.interface = "nwg2";
    live.family = AF_INET;
    live.metric = 0;
    live.protocol = KEEN_PBR_GENERATED_ROUTE_PROTOCOL;

    CHECK(route_table_detail::route_matches_live(selected, live));
    CHECK_FALSE(route_table_detail::route_matches_live(fallback, live));

    const auto missing =
        route_table_detail::find_missing_live_routes({selected, fallback}, {live});
    REQUIRE(missing.size() == 1);
    CHECK(missing.front().metric == 1);
}

TEST_CASE("live route matching does not adopt an unowned route") {
    RouteSpec expected;
    expected.destination = "default";
    expected.table = 155;
    expected.interface = "nwg2";
    expected.family = AF_INET;
    expected.protocol = KEEN_PBR_GENERATED_ROUTE_PROTOCOL;

    DumpedRoute live;
    live.destination = expected.destination;
    live.table = expected.table;
    live.interface = expected.interface;
    live.family = expected.family;
    live.protocol = 4;

    CHECK_FALSE(route_table_detail::route_matches_live(expected, live));
    CHECK(route_table_detail::find_missing_live_routes({expected}, {live}).size() == 1);
}

TEST_CASE("live route matching accepts the kernel IPv6 default metric") {
    RouteSpec expected;
    expected.destination = "default";
    expected.table = 155;
    expected.interface = "wg0";
    expected.family = AF_INET6;
    expected.metric = 0;

    DumpedRoute live;
    live.destination = expected.destination;
    live.table = expected.table;
    live.interface = expected.interface;
    live.family = AF_INET6;
    live.metric = 1024;
    live.protocol = KEEN_PBR_GENERATED_ROUTE_PROTOCOL;

    CHECK(route_table_detail::route_metric_matches_live(expected, live));
    CHECK(route_table_detail::route_matches_live(expected, live));

    expected.metric = 1;
    CHECK_FALSE(route_table_detail::route_metric_matches_live(expected, live));
    CHECK_FALSE(route_table_detail::route_matches_live(expected, live));
}

TEST_CASE("interface transitions trigger only their urltest parents") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"wg0"},
            {"tag":"backup","type":"interface","interface":"wg1"},
            {"tag":"other","type":"interface","interface":"wg2"},
            {
                "tag":"failover",
                "type":"urltest",
                "url":"https://www.gstatic.com/generate_204",
                "outbound_groups":[{"outbounds":["primary","backup"]}]
            },
            {
                "tag":"unrelated",
                "type":"urltest",
                "url":"https://www.gstatic.com/generate_204",
                "outbound_groups":[{"outbounds":["other"]}]
            }
        ]
    })");

    CHECK(find_affected_urltests(*cfg.outbounds, {"primary"}) ==
          std::vector<std::string>{"failover"});
    CHECK(find_affected_urltests(*cfg.outbounds, {"missing"}).empty());
}

TEST_CASE("interface transitions propagate through nested urltests") {
    auto cfg = parse_minimal_config(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"wg0"},
            {"tag":"backup","type":"interface","interface":"wg1"},
            {
                "tag":"inner",
                "type":"urltest",
                "url":"https://www.gstatic.com/generate_204",
                "outbound_groups":[{"outbounds":["primary","backup"]}]
            },
            {
                "tag":"outer",
                "type":"urltest",
                "url":"https://www.gstatic.com/generate_204",
                "outbound_groups":[{"outbounds":["inner"]}]
            }
        ]
    })");

    CHECK(find_affected_urltests(*cfg.outbounds, {"primary"}) ==
          std::vector<std::string>{"inner", "outer"});
}

namespace {

class RecordingRoutingNetlink final : public RouteNetlinkOperations,
                                       public RuleNetlinkOperations {
public:
    RouteAddResult add_route(const RouteSpec& spec) override {
        events.push_back("route:add:" + std::to_string(spec.table));
        if (std::any_of(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_occupies_same_slot(
                        spec, route);
                })) {
            return RouteAddResult::AlreadyPresent;
        }
        live_routes.push_back(to_live_route(spec));
        return RouteAddResult::Created;
    }

    void replace_route(const RouteSpec& spec) override {
        events.push_back("route:replace:" + std::to_string(spec.table));
        live_routes.erase(
            std::remove_if(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_occupies_same_slot(
                        spec, route);
                }),
            live_routes.end());
        live_routes.push_back(to_live_route(spec));
    }

    void delete_route(const RouteSpec& spec) override {
        events.push_back("route:delete:" + std::to_string(spec.table));
        live_routes.erase(
            std::remove_if(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_matches_live(spec, route);
                }),
            live_routes.end());
    }

    std::vector<DumpedRoute> dump_routes(int family = 0) override {
        if (family == 0) {
            return live_routes;
        }
        std::vector<DumpedRoute> result;
        std::copy_if(
            live_routes.begin(),
            live_routes.end(),
            std::back_inserter(result),
            [family](const DumpedRoute& route) {
                return route.family == family;
            });
        return result;
    }

    RuleAddResult add_rule_for_family(const RuleSpec& spec,
                                      int family) override {
        events.push_back("rule:add:" + std::to_string(spec.table));
        if (failing_rule_priority.has_value() &&
            spec.priority == *failing_rule_priority) {
            throw std::runtime_error("injected policy batch failure");
        }
        if (has_live_rule(spec, family)) {
            return RuleAddResult::AlreadyPresent;
        }
        live_rules.push_back(to_live_rule(spec, family));
        return RuleAddResult::Created;
    }

    void delete_rule_for_family(const RuleSpec& spec, int family) override {
        events.push_back("rule:delete:" + std::to_string(spec.table));
        live_rules.erase(
            std::remove_if(
                live_rules.begin(),
                live_rules.end(),
                [&](const DumpedRule& rule) {
                    return rule.priority == spec.priority &&
                           rule.fwmark == spec.fwmark &&
                           rule.fwmask == spec.fwmask &&
                           rule.table == spec.table &&
                           rule.family == family;
                }),
            live_rules.end());
    }

    std::vector<DumpedRule> dump_policy_rules(int family = 0) override {
        if (family == 0) {
            return live_rules;
        }
        std::vector<DumpedRule> result;
        std::copy_if(
            live_rules.begin(),
            live_rules.end(),
            std::back_inserter(result),
            [family](const DumpedRule& rule) {
                return rule.family == family;
            });
        return result;
    }

    void seed_generated_route(const RouteSpec& spec) {
        const auto generated = to_live_route(spec);
        if (!std::any_of(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_matches_live(
                        spec, route);
                })) {
            live_routes.push_back(generated);
        }
    }

    void seed_foreign_route(const RouteSpec& spec) {
        auto foreign = to_live_route(spec);
        foreign.protocol = 4;
        if (!std::any_of(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_matches_live(
                        route_table_detail::route_spec_from_live(foreign),
                        route);
                })) {
            live_routes.push_back(std::move(foreign));
        }
    }

    void seed_foreign_rule(const RuleSpec& spec, int family) {
        if (!has_live_rule(spec, family)) {
            live_rules.push_back(to_live_rule(spec, family));
        }
    }

    std::optional<std::uint32_t> failing_rule_priority;
    std::vector<std::string> events;
    std::vector<DumpedRoute> live_routes;
    std::vector<DumpedRule> live_rules;

    bool contains_live_route(const RouteSpec& spec) const {
        return has_live_route(spec);
    }

    bool contains_live_rule(const RuleSpec& spec, int family) const {
        return has_live_rule(spec, family);
    }

private:
    static DumpedRoute to_live_route(const RouteSpec& spec) {
        DumpedRoute route;
        route.destination = spec.destination;
        route.table = spec.table;
        route.interface = spec.interface;
        route.gateway = spec.gateway;
        route.blackhole = spec.blackhole;
        route.unreachable = spec.unreachable;
        route.family = spec.family;
        route.metric = spec.metric;
        route.protocol = spec.protocol;
        return route;
    }

    static DumpedRule to_live_rule(const RuleSpec& spec, int family) {
        return {
            spec.priority,
            spec.fwmark,
            spec.fwmask,
            spec.table,
            family,
        };
    }

    bool has_live_route(const RouteSpec& spec) const {
        return std::any_of(
            live_routes.begin(),
            live_routes.end(),
            [&](const DumpedRoute& route) {
                return route_table_detail::route_matches_live(spec, route);
            });
    }

    bool has_live_rule(const RuleSpec& spec, int family) const {
        return std::any_of(
            live_rules.begin(),
            live_rules.end(),
            [&](const DumpedRule& rule) {
                return rule.priority == spec.priority &&
                       rule.fwmark == spec.fwmark &&
                       rule.fwmask == spec.fwmask &&
                       rule.table == spec.table &&
                       rule.family == family;
            });
    }
};

RouteSpec coordinator_route(std::uint32_t table) {
    RouteSpec route;
    route.destination = "default";
    route.table = table;
    route.blackhole = true;
    route.family = AF_INET;
    return route;
}

RuleSpec coordinator_rule(std::uint32_t table) {
    RuleSpec rule;
    rule.fwmark = table;
    rule.table = table;
    rule.priority = table;
    rule.family = AF_INET;
    return rule;
}

} // namespace

TEST_CASE("kernel routing reconciliation preserves cross-manager add-before-delete order") {
    RecordingRoutingNetlink netlink;
    RouteTable routes(netlink);
    PolicyRuleManager rules(netlink);
    const auto old_route = coordinator_route(150);
    const auto old_rule = coordinator_rule(150);
    const auto new_route = coordinator_route(151);
    const auto new_rule = coordinator_rule(151);
    routes.add(old_route);
    rules.add(old_rule);
    netlink.events.clear();

    reconcile_kernel_routing_state(
        routes, rules, {new_route}, {new_rule});

    CHECK(netlink.events == std::vector<std::string>({
        "route:add:151",
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150",
    }));
}

TEST_CASE("kernel routing reconciliation converges after a partial rule failure") {
    RecordingRoutingNetlink netlink;
    RouteTable routes(netlink);
    PolicyRuleManager rules(netlink);
    const auto old_route = coordinator_route(150);
    const auto old_rule = coordinator_rule(150);
    const auto new_route = coordinator_route(151);
    const auto new_rule = coordinator_rule(151);
    routes.add(old_route);
    rules.add(old_rule);
    netlink.events.clear();
    netlink.failing_rule_priority = new_rule.priority;

    CHECK_THROWS_WITH(
        reconcile_kernel_routing_state(
            routes, rules, {new_route}, {new_rule}),
        "injected policy batch failure");
    CHECK(netlink.events == std::vector<std::string>({
        "route:add:151",
        "rule:add:151",
    }));
    CHECK(routes.size() == 2);
    CHECK(rules.size() == 1);

    netlink.failing_rule_priority.reset();
    netlink.events.clear();
    reconcile_kernel_routing_state(
        routes, rules, {new_route}, {new_rule});

    CHECK(netlink.events == std::vector<std::string>({
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150",
    }));
    REQUIRE(routes.get_routes().size() == 1);
    CHECK(routes.get_routes().front().table == new_route.table);
    REQUIRE(rules.get_rules().size() == 1);
    CHECK(rules.get_rules().front().table == new_rule.table);
}

TEST_CASE(
    "build_firewall_global_prefilter: verified OpenConnect ingress separates "
    "processed and bypassed client modes") {
    auto cfg = parse_minimal_config(
        R"({"route":{"inbound_interfaces":["br0"],"rules":[]}})");

    InternalVpnRuntimeTarget openconnect;
    openconnect.stable_id = "ndms-service:oc-server";
    openconnect.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    openconnect.process_clients = true;
    openconnect.verified_ingress_interfaces = {"oc7"};
    openconnect.source_cidrs_v4 = {"172.16.5.0/24"};
    openconnect.dns_redirect_local_destinations_v4 = {
        "192.168.77.1/32"};

    auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            cfg, {openconnect});
    CHECK(
        prefilter.include_source_cidrs_v4 ==
        std::vector<std::string>{"172.16.5.0/24"});
    CHECK(prefilter.bypass_source_selectors_v4.empty());
    CHECK(
        prefilter.dns_redirect_local_destination_selectors_v4 ==
        std::vector<FirewallIngressDestinationSelector>{
            {"oc7", "192.168.77.1/32"}});

    openconnect.process_clients = false;
    openconnect.dns_redirect_local_destinations_v4.clear();
    prefilter = build_firewall_global_prefilter_for_runtime_targets(
        cfg, {openconnect});
    CHECK(prefilter.include_source_cidrs_v4.empty());
    REQUIRE(prefilter.bypass_source_selectors_v4.size() == 1U);
    CHECK(
        prefilter.bypass_source_selectors_v4.front().interface ==
        "oc7");
    CHECK(
        prefilter.bypass_source_selectors_v4.front().cidr ==
        "172.16.5.0/24");
    CHECK(
        prefilter.dns_redirect_local_destination_selectors_v4.empty());

    // An authoritative pool without a verified live ocN ingress remains
    // fail-closed in exclusion mode.
    openconnect.verified_ingress_interfaces.clear();
    prefilter = build_firewall_global_prefilter_for_runtime_targets(
        cfg, {openconnect});
    CHECK(prefilter.bypass_source_selectors_v4.empty());
}

TEST_CASE("kernel routing reconciliation restores a replaced route when policy commit fails") {
    RecordingRoutingNetlink netlink;
    RouteTable routes(netlink);
    PolicyRuleManager rules(netlink);
    const auto old_route = coordinator_route(154);
    auto new_route = old_route;
    new_route.blackhole = false;
    new_route.unreachable = true;
    const auto old_rule = coordinator_rule(154);
    auto new_rule = old_rule;
    new_rule.fwmark = 0x90000;
    new_rule.priority = 155;
    routes.add(old_route);
    rules.add(old_rule);
    netlink.events.clear();
    netlink.failing_rule_priority = new_rule.priority;

    CHECK_THROWS_WITH(
        reconcile_kernel_routing_state(
            routes, rules, {new_route}, {new_rule}),
        "injected policy batch failure");

    CHECK(netlink.events == std::vector<std::string>({
        "route:add:154",
        "route:replace:154",
        "rule:add:154",
        "route:replace:154",
    }));
    CHECK(netlink.contains_live_route(old_route));
    CHECK_FALSE(netlink.contains_live_route(new_route));
    CHECK(netlink.contains_live_rule(old_rule, AF_INET));
}

TEST_CASE("kernel routing reconciliation does not adopt a policy rule without a live managed route") {
    RecordingRoutingNetlink netlink;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Down;
        });
    PolicyRuleManager rules(netlink);
    auto desired_route = coordinator_route(160);
    desired_route.blackhole = false;
    desired_route.interface = "tun0";
    const auto desired_rule = coordinator_rule(160);
    routes.adopt_desired({desired_route});
    netlink.seed_foreign_rule(desired_rule, AF_INET);

    reconcile_kernel_routing_state(
        routes,
        rules,
        {desired_route},
        {desired_rule},
        RouteReconcileMode::DeferredRepair);

    netlink.events.clear();
    rules.clear();
    CHECK(netlink.events.empty());
    CHECK(netlink.contains_live_rule(desired_rule, AF_INET));
}

TEST_CASE("kernel routing reconciliation refuses a foreign route collision") {
    RecordingRoutingNetlink netlink;
    RouteTable routes(netlink);
    PolicyRuleManager rules(netlink);
    const auto old_route = coordinator_route(150);
    const auto old_rule = coordinator_rule(150);
    const auto foreign_route = coordinator_route(151);
    const auto foreign_rule = coordinator_rule(151);
    routes.add(old_route);
    rules.add(old_rule);
    netlink.seed_foreign_route(foreign_route);
    netlink.seed_foreign_rule(foreign_rule, AF_INET);
    netlink.events.clear();

    CHECK_THROWS_AS(
        reconcile_kernel_routing_state(
            routes, rules, {foreign_route}, {foreign_rule}),
        NetlinkError);

    CHECK(netlink.events == std::vector<std::string>({"route:add:151"}));

    netlink.events.clear();
    rules.clear();
    routes.clear();
    CHECK(netlink.events == std::vector<std::string>({
        "rule:delete:150",
        "route:delete:150",
    }));
    REQUIRE(netlink.live_routes.size() == 1);
    CHECK(netlink.live_routes.front().table == foreign_route.table);
    REQUIRE(netlink.live_rules.size() == 1);
    CHECK(netlink.live_rules.front().table == foreign_rule.table);
}

TEST_CASE("kernel routing reconciliation removes only corroborated stale policy generation") {
    RecordingRoutingNetlink netlink;
    RouteTable routes(netlink);
    PolicyRuleManager rules(netlink);

    const auto desired_route = coordinator_route(159);
    const auto stale_generated_route = coordinator_route(154);
    const auto uncorroborated_foreign_route = coordinator_route(158);
    netlink.seed_generated_route(stale_generated_route);
    netlink.seed_foreign_route(uncorroborated_foreign_route);

    auto marked_rule = [](std::uint32_t table, std::uint32_t fwmark) {
        RuleSpec rule;
        rule.fwmark = fwmark;
        rule.fwmask = 0x00FF0000;
        rule.table = table;
        rule.priority = table;
        rule.family = AF_INET;
        return rule;
    };

    const auto desired_rule = marked_rule(159, 0x00070000);
    const auto stale_corroborated_rule = marked_rule(154, 0x00070000);
    const auto stale_uncorroborated_rule = marked_rule(158, 0x00070000);
    const auto unrelated_foreign_rule = marked_rule(154, 0x00090000);
    netlink.seed_foreign_rule(stale_corroborated_rule, AF_INET);
    netlink.seed_foreign_rule(stale_uncorroborated_rule, AF_INET);
    netlink.seed_foreign_rule(unrelated_foreign_rule, AF_INET);

    reconcile_kernel_routing_state(
        routes, rules, {desired_route}, {desired_rule});

    auto has_rule = [&](const RuleSpec& expected) {
        return std::any_of(
            netlink.live_rules.begin(),
            netlink.live_rules.end(),
            [&](const DumpedRule& actual) {
                return policy_rule_detail::rule_matches_live(expected, actual);
            });
    };
    CHECK(has_rule(desired_rule));
    CHECK_FALSE(has_rule(stale_corroborated_rule));
    CHECK(has_rule(stale_uncorroborated_rule));
    CHECK(has_rule(unrelated_foreign_rule));

    CHECK(netlink.events == std::vector<std::string>({
        "route:add:159",
        "rule:add:159",
        "rule:delete:154",
        "route:delete:154",
    }));
}
