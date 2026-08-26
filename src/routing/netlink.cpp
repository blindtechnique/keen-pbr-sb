#include "netlink.hpp"
#include "route_table.hpp"

#include "../log/logger.hpp"
#include "../util/format_compat.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <map>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>
#include <netlink/route/nexthop.h>

namespace keen_pbr3 {

namespace netlink_detail {

InterfaceAdminState query_interface_admin_state(
    const std::string& interface_name) noexcept {
    if (interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        return InterfaceAdminState::Missing;
    }

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return InterfaceAdminState::Unknown;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    const int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    const int saved_errno = errno;
    close(fd);
    if (rc < 0) {
        if (saved_errno == ENODEV || saved_errno == ENXIO ||
            saved_errno == ENOENT) {
            return InterfaceAdminState::Missing;
        }
        return InterfaceAdminState::Unknown;
    }

    return (ifr.ifr_flags & IFF_UP) != 0
        ? InterfaceAdminState::Up
        : InterfaceAdminState::Down;
}

bool route_delete_target_absent(int error_code) noexcept {
    return error_code == -NLE_OBJ_NOTFOUND || error_code == -NLE_NODEV;
}

} // namespace netlink_detail

namespace {

// Convert an nl_addr to a plain IP string (no prefix length suffix).
std::string nl_addr_to_ip_str(struct nl_addr* addr) {
    if (!addr) return "";
    char buf[128];
    nl_addr2str(addr, buf, sizeof(buf));
    std::string s(buf);
    auto pos = s.find('/');
    if (pos != std::string::npos) {
        s = s.substr(0, pos);
    }
    return s;
}

// Convert an nl_addr to its canonical string form, preserving prefix length.
std::string nl_addr_to_str(struct nl_addr* addr) {
    if (!addr) return "";
    char buf[128];
    nl_addr2str(addr, buf, sizeof(buf));
    return buf;
}

// RAII wrapper for nl_cache
struct CacheDeleter {
    void operator()(struct nl_cache* c) const {
        if (c) nl_cache_free(c);
    }
};
using CachePtr = std::unique_ptr<struct nl_cache, CacheDeleter>;

// Parse an IP address string to nl_addr, auto-detecting family.
// For CIDR notation (e.g., "10.0.0.0/8"), the prefix length is preserved.
// For plain IPs, uses host prefix length (32 for v4, 128 for v6).
struct NlAddrDeleter {
    void operator()(struct nl_addr* a) const {
        if (a) nl_addr_put(a);
    }
};
using NlAddrPtr = std::unique_ptr<struct nl_addr, NlAddrDeleter>;

NlAddrPtr parse_addr(const std::string& addr_str, int hint_family = AF_UNSPEC) {
    struct nl_addr* addr = nullptr;
    int err = nl_addr_parse(addr_str.c_str(), hint_family, &addr);
    if (err < 0) {
        throw NetlinkError("Failed to parse address '" + addr_str + "': " +
                           nl_geterror(err));
    }
    return NlAddrPtr(addr);
}

int detect_family(const std::string& addr_str) {
    if (addr_str.find(':') != std::string::npos) {
        return AF_INET6;
    }
    return AF_INET;
}

// RAII wrapper for rtnl_route
struct RouteDeleter {
    void operator()(struct rtnl_route* r) const {
        if (r) rtnl_route_put(r);
    }
};
using RoutePtr = std::unique_ptr<struct rtnl_route, RouteDeleter>;

DumpedRoute dumped_route_from_nl(struct rtnl_route* route) {
    DumpedRoute dumped;
    dumped.table = rtnl_route_get_table(route);
    dumped.family = rtnl_route_get_family(route);
    dumped.metric = static_cast<uint32_t>(rtnl_route_get_priority(route));
    dumped.protocol = rtnl_route_get_protocol(route);
    const int route_type = rtnl_route_get_type(route);
    dumped.blackhole = route_type == RTN_BLACKHOLE;
    dumped.unreachable = route_type == RTN_UNREACHABLE;
    const int nexthop_count = rtnl_route_get_nnexthops(route);
    dumped.exact_identity_representable =
        (dumped.blackhole || dumped.unreachable)
            ? nexthop_count == 0
            : route_type == RTN_UNICAST && nexthop_count == 1;

    if (struct nl_addr* destination = rtnl_route_get_dst(route)) {
        if (nl_addr_get_prefixlen(destination) == 0U) {
            dumped.destination = "default";
        } else {
            char buffer[128];
            nl_addr2str(destination, buffer, sizeof(buffer));
            dumped.destination = buffer;
        }
    }

    if (!dumped.blackhole && !dumped.unreachable &&
        nexthop_count > 0) {
        if (struct rtnl_nexthop* nexthop =
                rtnl_route_nexthop_n(route, 0)) {
            const int ifindex = rtnl_route_nh_get_ifindex(nexthop);
            if (ifindex > 0) {
                char ifname[IF_NAMESIZE];
                if (if_indextoname(static_cast<unsigned>(ifindex), ifname)) {
                    dumped.interface = ifname;
                }
            }
            struct nl_addr* gateway = rtnl_route_nh_get_gateway(nexthop);
            if (gateway && nl_addr_get_len(gateway) > 0) {
                dumped.gateway = nl_addr_to_ip_str(gateway);
            }
        }
    }
    return dumped;
}

// RAII wrapper for rtnl_nexthop
struct NexthopDeleter {
    void operator()(struct rtnl_nexthop* nh) const {
        if (nh) rtnl_route_nh_free(nh);
    }
};
using NexthopPtr = std::unique_ptr<struct rtnl_nexthop, NexthopDeleter>;

// RAII wrapper for rtnl_rule
struct RuleDeleter {
    void operator()(struct rtnl_rule* r) const {
        if (r) rtnl_rule_put(r);
    }
};
using RulePtr = std::unique_ptr<struct rtnl_rule, RuleDeleter>;

int route_family(const RouteSpec& spec) {
    if (spec.family != 0) {
        return spec.family;
    }
    if (spec.destination == "default") {
        return AF_INET;
    }
    return detect_family(spec.destination);
}

// Build the exact libnl object used by add/replace/delete. A missing output
// interface is transient for installation, while deletion is already complete
// because Linux removes routes when their interface vanishes.
RoutePtr build_route(const RouteSpec& spec,
                     bool missing_interface_means_absent = false) {
    const int family = route_family(spec);
    RoutePtr route(rtnl_route_alloc());
    if (!route) {
        throw NetlinkError("Failed to allocate route object");
    }

    rtnl_route_set_family(route.get(), family);
    if (spec.table != 0) {
        rtnl_route_set_table(route.get(), spec.table);
    }
    // Zero is part of route identity: urltest keeps metric-zero primary and
    // metric-N fallbacks in the same table.
    rtnl_route_set_priority(route.get(), spec.metric);
    rtnl_route_set_protocol(route.get(), spec.protocol);

    if (spec.destination == "default") {
        NlAddrPtr dst = parse_addr(
            family == AF_INET6 ? "::/0" : "0.0.0.0/0", family);
        rtnl_route_set_dst(route.get(), dst.get());
    } else {
        NlAddrPtr dst = parse_addr(spec.destination, family);
        rtnl_route_set_dst(route.get(), dst.get());
    }

    if (spec.blackhole) {
        rtnl_route_set_type(route.get(), RTN_BLACKHOLE);
        return route;
    }
    if (spec.unreachable) {
        rtnl_route_set_type(route.get(), RTN_UNREACHABLE);
        return route;
    }

    // Route type is part of exact delete identity.  Leaving it unset makes an
    // RTM_DELROUTE request a wildcard over foreign same-slot route types.
    rtnl_route_set_type(route.get(), RTN_UNICAST);

    NexthopPtr nh(rtnl_route_nh_alloc());
    if (!nh) {
        throw NetlinkError("Failed to allocate nexthop object");
    }
    if (spec.interface) {
        const unsigned int ifindex = if_nametoindex(spec.interface->c_str());
        if (ifindex == 0) {
            if (missing_interface_means_absent) {
                return {};
            }
            throw RouteInterfaceUnavailableError(
                "Interface not found: " + *spec.interface);
        }
        rtnl_route_nh_set_ifindex(nh.get(), static_cast<int>(ifindex));
    }
    if (spec.gateway) {
        NlAddrPtr gw = parse_addr(*spec.gateway, family);
        rtnl_route_nh_set_gateway(nh.get(), gw.get());
    }
    rtnl_route_add_nexthop(route.get(), nh.release());
    return route;
}

} // anonymous namespace

struct NetlinkManager::Impl {
    struct nl_sock* sock{nullptr};

    Impl() {
        sock = nl_socket_alloc();
        if (!sock) {
            throw NetlinkError("Failed to allocate netlink socket");
        }
        int err = nl_connect(sock, NETLINK_ROUTE);
        if (err < 0) {
#ifdef KEEN_PBR3_TESTING
            nl_socket_free(sock);
            sock = nullptr;
            return;
#else
            nl_socket_free(sock);
            throw NetlinkError(std::string("Failed to connect netlink socket: ") +
                               nl_geterror(err));
#endif
        }
    }

    ~Impl() {
        if (sock) {
            nl_close(sock);
            nl_socket_free(sock);
        }
    }
};

NetlinkManager::NetlinkManager() : impl_(std::make_unique<Impl>()) {}

NetlinkManager::~NetlinkManager() = default;

RouteAddResult NetlinkManager::add_route(const RouteSpec& spec) {
    KPBR_LOCK_GUARD(mutex_);
    const int family = route_family(spec);
    RoutePtr route = build_route(spec);

    int err = rtnl_route_add(impl_->sock, route.get(), NLM_F_CREATE | NLM_F_EXCL);
    if (err < 0) {
        if (err == -NLE_EXIST) {
            return RouteAddResult::AlreadyPresent;
        }
        if (err == -NLE_NODEV) {
            throw RouteInterfaceUnavailableError(keen_pbr3::format(
                "Route interface is unavailable: {} (dst={}, table={}, iface={})",
                nl_geterror(err),
                spec.destination,
                spec.table,
                spec.interface.value_or("(none)")));
        }
        throw NetlinkError(keen_pbr3::format(
            "Failed to add route: {} (dst={}, table={}, iface={}, gw={}, family={}, blackhole={})",
            nl_geterror(err),
            spec.destination,
            spec.table,
            spec.interface.value_or("(none)"),
            spec.gateway.value_or("(none)"),
            family,
            spec.blackhole));
    }
    return RouteAddResult::Created;
}

void NetlinkManager::replace_route(const RouteSpec& spec) {
    KPBR_LOCK_GUARD(mutex_);
    const int family = route_family(spec);
    RoutePtr route = build_route(spec);

    const int err = rtnl_route_add(
        impl_->sock, route.get(), NLM_F_CREATE | NLM_F_REPLACE);
    if (err < 0) {
        if (err == -NLE_NODEV) {
            throw RouteInterfaceUnavailableError(keen_pbr3::format(
                "Route interface is unavailable during replacement: {} (dst={}, table={}, iface={})",
                nl_geterror(err),
                spec.destination,
                spec.table,
                spec.interface.value_or("(none)")));
        }
        throw NetlinkError(keen_pbr3::format(
            "Failed to replace managed route: {} (dst={}, table={}, iface={}, gw={}, family={}, metric={})",
            nl_geterror(err),
            spec.destination,
            spec.table,
            spec.interface.value_or("(none)"),
            spec.gateway.value_or("(none)"),
            family,
            spec.metric));
    }
}

void NetlinkManager::delete_route(const RouteSpec& spec) {
    KPBR_LOCK_GUARD(mutex_);
    RoutePtr route = build_route(spec, true);
    if (!route) {
        return;
    }

    int err = rtnl_route_delete(impl_->sock, route.get(), 0);
    if (err < 0) {
        if (netlink_detail::route_delete_target_absent(err)) {
            return;
        }
        throw NetlinkError(std::string("Failed to delete route: ") + nl_geterror(err));
    }
}

RouteExactDeleteResult NetlinkManager::delete_route_if_exact(
    const RouteSpec&) {
    // Linux RTM_DELROUTE has no compare-and-delete predicate. In particular,
    // metric 0 is a wildcard in the kernel lookup, and a cache proof followed
    // by delete can remove a foreign racer. Keep the exact API fail-closed
    // until an exclusive route-writer capability is available.
    return RouteExactDeleteResult::PreconditionMismatch;
}

RouteExactReplaceResult NetlinkManager::replace_route_if_exact(
    const RouteSpec& expected,
    const RouteSpec& replacement) {
    (void)expected;
    (void)replacement;
    // Linux RTM_NEWROUTE/NLM_F_REPLACE has no compare-and-swap predicate. A
    // cache check followed by replace can overwrite a firmware/external racer.
    // Keep the exact transaction fail-closed until one exclusive route writer
    // owns both observation and replacement. Compatibility callers continue
    // to use replace_route() explicitly and receive no exactness claim.
    return RouteExactReplaceResult::PreconditionMismatch;
}

void NetlinkManager::flush_routes_in_table(uint32_t table_id, int family) {
    KPBR_LOCK_GUARD(mutex_);

    struct nl_cache* raw_cache = nullptr;
    int err = rtnl_route_alloc_cache(impl_->sock, family, 0, &raw_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc route cache: ") +
                           nl_geterror(err));
    }
    CachePtr cache(raw_cache);

    std::vector<RoutePtr> routes_to_delete;
    nl_cache_foreach(cache.get(), [](struct nl_object* obj, void* arg) {
        auto* routes = static_cast<std::vector<RoutePtr>*>(arg);
        auto* route = reinterpret_cast<struct rtnl_route*>(obj);
        if (rtnl_route_get_table(route) == 0) {
            return;
        }
        rtnl_route_get(route);
        routes->emplace_back(route);
    }, &routes_to_delete);

    for (auto& route : routes_to_delete) {
        if (rtnl_route_get_table(route.get()) != table_id) {
            continue;
        }
        try {
            int delete_err = rtnl_route_delete(impl_->sock, route.get(), 0);
            if (delete_err < 0) {
                throw NetlinkError(std::string("Failed to delete route during flush: ") +
                                   nl_geterror(delete_err));
            }
        } catch (const std::exception& e) {
            Logger::instance().warn("flush_routes_in_table: failed to delete route in table {}: {}",
                                    table_id, e.what());
        } catch (...) {
            Logger::instance().warn("flush_routes_in_table: failed to delete route in table {} (unknown error)",
                                    table_id);
        }
    }
}

RuleAddResult NetlinkManager::add_rule_for_family(const RuleSpec& spec, int family) {
    KPBR_LOCK_GUARD(mutex_);

    RulePtr rule(rtnl_rule_alloc());
    if (!rule) {
        throw NetlinkError("Failed to allocate rule object");
    }

    rtnl_rule_set_family(rule.get(), family);
    rtnl_rule_set_table(rule.get(), spec.table);
    rtnl_rule_set_mark(rule.get(), spec.fwmark);
    rtnl_rule_set_mask(rule.get(), spec.fwmask);

    if (spec.priority != 0) {
        rtnl_rule_set_prio(rule.get(), spec.priority);
    }

    rtnl_rule_set_action(rule.get(), FR_ACT_TO_TBL);

    const int err = rtnl_rule_add(impl_->sock, rule.get(), NLM_F_CREATE | NLM_F_EXCL);
    if (err == -NLE_EXIST) {
        return RuleAddResult::AlreadyPresent;
    }
    if (err < 0) {
        throw NetlinkError(std::string("Failed to add rule (family ") +
                           std::to_string(family) + "): " + nl_geterror(err));
    }
    return RuleAddResult::Created;
}

void NetlinkManager::delete_rule_for_family(const RuleSpec& spec, int family) {
    KPBR_LOCK_GUARD(mutex_);

    RulePtr rule(rtnl_rule_alloc());
    if (!rule) {
        throw NetlinkError("Failed to allocate rule object");
    }

    rtnl_rule_set_family(rule.get(), family);
    rtnl_rule_set_table(rule.get(), spec.table);
    rtnl_rule_set_mark(rule.get(), spec.fwmark);
    rtnl_rule_set_mask(rule.get(), spec.fwmask);

    if (spec.priority != 0) {
        rtnl_rule_set_prio(rule.get(), spec.priority);
    }

    rtnl_rule_set_action(rule.get(), FR_ACT_TO_TBL);

    const int err = rtnl_rule_delete(impl_->sock, rule.get(), 0);
    if (err < 0) {
        if (netlink_detail::route_delete_target_absent(err)) {
            return;
        }
        throw NetlinkError(std::string("Failed to delete rule (family ") +
                           std::to_string(family) + "): " + nl_geterror(err));
    }
}

RuleExactDeleteResult NetlinkManager::delete_rule_if_exact(
    const RuleSpec&,
    int) {
    // Linux RTM_DELRULE does not provide compare-and-delete semantics. A
    // pre-dump followed by the partial RuleSpec delete is racy and may delete
    // a foreign rule which acquired the same visible key. Until this backend
    // has an exclusive-writer proof or a complete atomic primitive, exact
    // transactions must fail closed. The compatibility deletion API above is
    // intentionally unchanged for its existing callers.
    return RuleExactDeleteResult::PreconditionMismatch;
}

std::vector<DumpedRoute> NetlinkManager::dump_routes(int family) {
    KPBR_LOCK_GUARD(mutex_);

    struct nl_cache* raw_cache = nullptr;
    int err = rtnl_route_alloc_cache(impl_->sock, family, 0, &raw_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc route cache: ") +
                           nl_geterror(err));
    }
    CachePtr cache(raw_cache);

    std::vector<DumpedRoute> result;
    struct DumpRoutesCtx {
        std::vector<DumpedRoute>* result;
    } ctx{&result};

    nl_cache_foreach(cache.get(), [](struct nl_object* obj, void* arg) {
        auto* ctx = static_cast<DumpRoutesCtx*>(arg);
        auto* route = reinterpret_cast<struct rtnl_route*>(obj);

        ctx->result->push_back(dumped_route_from_nl(route));
    }, &ctx);

    return result;
}

std::vector<DumpedRoute> NetlinkManager::dump_routes_in_table(uint32_t table_id,
                                                              int family) {
    auto routes = dump_routes(family);
    routes.erase(
        std::remove_if(routes.begin(), routes.end(),
                       [table_id](const DumpedRoute& route) {
                           return route.table != table_id;
                       }),
        routes.end());
    return routes;
}

std::vector<DumpedRule> NetlinkManager::dump_policy_rules(int family) {
    KPBR_LOCK_GUARD(mutex_);

    struct nl_cache* raw_cache = nullptr;
    int err = rtnl_rule_alloc_cache(impl_->sock, family, &raw_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc rule cache: ") +
                           nl_geterror(err));
    }
    CachePtr cache(raw_cache);

    std::vector<DumpedRule> result;

    nl_cache_foreach(cache.get(), [](struct nl_object* obj, void* arg) {
        auto* out = static_cast<std::vector<DumpedRule>*>(arg);
        auto* rule = reinterpret_cast<struct rtnl_rule*>(obj);

        DumpedRule dr;
        dr.priority = rtnl_rule_get_prio(rule);
        dr.fwmark   = rtnl_rule_get_mark(rule);
        dr.fwmask   = rtnl_rule_get_mask(rule);
        dr.table    = rtnl_rule_get_table(rule);
        dr.family   = rtnl_rule_get_family(rule);
        // libnl's high-level rule cache discards several kernel attributes
        // (for example FRA_TUN_ID, FRA_UID_RANGE and suppression selectors).
        // This partial projection therefore cannot prove a complete identity.
        // Compatibility consumers may still inspect the visible tuple, while
        // exact transactions fail closed until a raw RTM_GETRULE parser is
        // supplied.
        dr.exact_identity_representable = false;

        out->push_back(dr);
    }, &result);

    return result;
}

std::vector<DumpedInterface> NetlinkManager::dump_interfaces() {
    KPBR_LOCK_GUARD(mutex_);

    struct nl_cache* raw_link_cache = nullptr;
    int err = rtnl_link_alloc_cache(impl_->sock, AF_UNSPEC, &raw_link_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc link cache: ") +
                           nl_geterror(err));
    }
    CachePtr link_cache(raw_link_cache);

    struct nl_cache* raw_addr_cache = nullptr;
    err = rtnl_addr_alloc_cache(impl_->sock, &raw_addr_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc address cache: ") +
                           nl_geterror(err));
    }
    CachePtr addr_cache(raw_addr_cache);

    std::map<int, DumpedInterface> interfaces_by_index;

    nl_cache_foreach(link_cache.get(), [](struct nl_object* obj, void* arg) {
        auto* interfaces = static_cast<std::map<int, DumpedInterface>*>(arg);
        auto* link = reinterpret_cast<struct rtnl_link*>(obj);

        const int ifindex = rtnl_link_get_ifindex(link);
        const char* ifname = rtnl_link_get_name(link);
        if (ifindex <= 0 || ifname == nullptr || *ifname == '\0') {
            return;
        }

        DumpedInterface dumped;
        dumped.name = ifname;
        dumped.admin_up = (rtnl_link_get_flags(link) & IFF_UP) != 0;

        const int oper_state = rtnl_link_get_operstate(link);
        if (oper_state >= 0) {
            char oper_state_buf[32];
            const char* rendered = rtnl_link_operstate2str(
                oper_state,
                oper_state_buf,
                sizeof(oper_state_buf));
            if (rendered != nullptr && *rendered != '\0') {
                dumped.oper_state = rendered;
            }
        }

        const int carrier = rtnl_link_get_carrier(link);
        if (carrier >= 0) {
            dumped.carrier = carrier > 0;
        }

        interfaces->insert_or_assign(ifindex, std::move(dumped));
    }, &interfaces_by_index);

    // Resolve bridge/master ownership in a second pass: libnl does not
    // guarantee that the master link appears before its port in the cache.
    nl_cache_foreach(link_cache.get(), [](struct nl_object* obj, void* arg) {
        auto* interfaces = static_cast<std::map<int, DumpedInterface>*>(arg);
        auto* link = reinterpret_cast<struct rtnl_link*>(obj);
        const int ifindex = rtnl_link_get_ifindex(link);
        const int master_ifindex = rtnl_link_get_master(link);
        if (ifindex <= 0 || master_ifindex <= 0) {
            return;
        }
        const auto interface_it = interfaces->find(ifindex);
        const auto master_it = interfaces->find(master_ifindex);
        if (interface_it == interfaces->end() ||
            master_it == interfaces->end()) {
            return;
        }
        interface_it->second.master_interface =
            master_it->second.name;
    }, &interfaces_by_index);

    nl_cache_foreach(addr_cache.get(), [](struct nl_object* obj, void* arg) {
        auto* interfaces = static_cast<std::map<int, DumpedInterface>*>(arg);
        auto* addr = reinterpret_cast<struct rtnl_addr*>(obj);

        const int ifindex = rtnl_addr_get_ifindex(addr);
        if (ifindex <= 0) {
            return;
        }

        struct nl_addr* local = rtnl_addr_get_local(addr);
        if (!local) {
            return;
        }
        struct nl_addr* peer = rtnl_addr_get_peer(addr);

        auto interface_it = interfaces->find(ifindex);
        if (interface_it == interfaces->end()) {
            char ifname[IF_NAMESIZE];
            if (!if_indextoname(static_cast<unsigned int>(ifindex), ifname)) {
                return;
            }

            DumpedInterface dumped;
            dumped.name = ifname;
            interface_it = interfaces->insert({ifindex, std::move(dumped)}).first;
        }

        const std::string rendered = nl_addr_to_str(local);
        if (rendered.empty()) {
            return;
        }

        switch (nl_addr_get_family(local)) {
        case AF_INET:
            interface_it->second.ipv4_addresses.push_back(rendered);
            if (peer != nullptr) {
                const std::string rendered_peer = nl_addr_to_str(peer);
                if (!rendered_peer.empty() && rendered_peer != rendered) {
                    interface_it->second.ipv4_peer_addresses.push_back(
                        rendered_peer);
                }
            }
            break;
        case AF_INET6:
            interface_it->second.ipv6_addresses.push_back(rendered);
            if (peer != nullptr) {
                const std::string rendered_peer = nl_addr_to_str(peer);
                if (!rendered_peer.empty() && rendered_peer != rendered) {
                    interface_it->second.ipv6_peer_addresses.push_back(
                        rendered_peer);
                }
            }
            break;
        default:
            break;
        }
    }, &interfaces_by_index);

    std::vector<DumpedInterface> result;
    result.reserve(interfaces_by_index.size());
    for (auto& [ifindex, dumped] : interfaces_by_index) {
        (void)ifindex;
        std::sort(dumped.ipv4_addresses.begin(), dumped.ipv4_addresses.end());
        std::sort(dumped.ipv6_addresses.begin(), dumped.ipv6_addresses.end());
        std::sort(
            dumped.ipv4_peer_addresses.begin(),
            dumped.ipv4_peer_addresses.end());
        dumped.ipv4_peer_addresses.erase(
            std::unique(
                dumped.ipv4_peer_addresses.begin(),
                dumped.ipv4_peer_addresses.end()),
            dumped.ipv4_peer_addresses.end());
        std::sort(
            dumped.ipv6_peer_addresses.begin(),
            dumped.ipv6_peer_addresses.end());
        dumped.ipv6_peer_addresses.erase(
            std::unique(
                dumped.ipv6_peer_addresses.begin(),
                dumped.ipv6_peer_addresses.end()),
            dumped.ipv6_peer_addresses.end());
        result.push_back(std::move(dumped));
    }

    std::sort(result.begin(), result.end(), [](const DumpedInterface& lhs, const DumpedInterface& rhs) {
        return lhs.name < rhs.name;
    });

    return result;
}

} // namespace keen_pbr3
