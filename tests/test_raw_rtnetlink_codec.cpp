#include "../src/routing/raw_rtnetlink_codec.hpp"

#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr std::uint32_t kSequence = 41U;
constexpr std::uint32_t kPortId = 7123U;

template <typename Header>
std::vector<std::uint8_t> payload_with(const Header& header) {
    std::vector<std::uint8_t> payload(sizeof(Header), 0U);
    std::memcpy(payload.data(), &header, sizeof(header));
    return payload;
}

void append_attribute(std::vector<std::uint8_t>& payload,
                      const std::uint16_t type,
                      const void* bytes,
                      const std::size_t size) {
    const std::size_t attribute_length = RTA_LENGTH(size);
    const std::size_t offset = payload.size();
    payload.resize(offset + RTA_ALIGN(attribute_length), 0U);
    rtattr header{};
    header.rta_type = type;
    header.rta_len = static_cast<std::uint16_t>(attribute_length);
    std::memcpy(payload.data() + offset, &header, sizeof(header));
    if (size != 0U) {
        std::memcpy(payload.data() + offset + sizeof(header), bytes, size);
    }
}

template <typename T>
void append_scalar(std::vector<std::uint8_t>& payload,
                   const std::uint16_t type,
                   const T value) {
    append_attribute(payload, type, &value, sizeof(value));
}

void append_ip(std::vector<std::uint8_t>& payload,
               const std::uint16_t type,
               const int family,
               const char* text) {
    std::array<std::uint8_t, sizeof(in6_addr)> address{};
    const std::size_t size = family == AF_INET ? sizeof(in_addr)
                                               : sizeof(in6_addr);
    REQUIRE(inet_pton(family, text, address.data()) == 1);
    append_attribute(payload, type, address.data(), size);
}

void append_message(std::vector<std::uint8_t>& block,
                    const std::uint16_t type,
                    const std::vector<std::uint8_t>& payload,
                    const std::uint32_t sequence = kSequence,
                    const std::uint32_t port_id = kPortId,
                    const std::uint16_t flags = NLM_F_MULTI) {
    nlmsghdr header{};
    header.nlmsg_len = static_cast<std::uint32_t>(
        NLMSG_HDRLEN + payload.size());
    header.nlmsg_type = type;
    header.nlmsg_flags = flags;
    header.nlmsg_seq = sequence;
    header.nlmsg_pid = port_id;

    const std::size_t offset = block.size();
    block.resize(offset + NLMSG_ALIGN(header.nlmsg_len), 0U);
    std::memcpy(block.data() + offset, &header, sizeof(header));
    if (!payload.empty()) {
        std::memcpy(block.data() + offset + NLMSG_HDRLEN,
                    payload.data(), payload.size());
    }
}

void append_done(std::vector<std::uint8_t>& block) {
    append_message(block, NLMSG_DONE, {});
}

rtmsg route_header(const int family,
                   const std::uint8_t prefix,
                   const std::uint8_t table,
                   const std::uint8_t type = RTN_UNICAST) {
    rtmsg route{};
    route.rtm_family = static_cast<std::uint8_t>(family);
    route.rtm_dst_len = prefix;
    route.rtm_table = table;
    route.rtm_protocol = KEEN_PBR_GENERATED_ROUTE_PROTOCOL;
    route.rtm_scope = RT_SCOPE_UNIVERSE;
    route.rtm_type = type;
    return route;
}

fib_rule_hdr rule_header(const int family,
                         const std::uint8_t table,
                         const std::uint8_t action = FR_ACT_TO_TBL) {
    fib_rule_hdr rule{};
    rule.family = static_cast<std::uint8_t>(family);
    rule.table = table;
    rule.action = action;
    return rule;
}

RawRtnetlinkDumpOptions options() {
    static const RawRtnetlinkInterfaceName names[] = {
        {7U, "awg0"},
        {9U, "wan0"},
    };
    RawRtnetlinkDumpOptions value;
    value.sequence = kSequence;
    value.port_id = kPortId;
    value.interface_names = names;
    value.interface_name_count = sizeof(names) / sizeof(names[0]);
    return value;
}

}  // namespace

TEST_CASE("raw rtnetlink codec: IPv4 and IPv6 routes preserve exact visible identity") {
    std::vector<std::uint8_t> block;

    auto ipv4 = payload_with(route_header(AF_INET, 24U, RT_TABLE_UNSPEC));
    append_ip(ipv4, RTA_DST, AF_INET, "10.20.30.0");
    append_scalar(ipv4, RTA_TABLE, std::uint32_t{1001U});
    append_scalar(ipv4, RTA_OIF, std::uint32_t{7U});
    append_ip(ipv4, RTA_GATEWAY, AF_INET, "10.20.30.1");
    append_scalar(ipv4, RTA_PRIORITY, std::uint32_t{0U});
    append_message(block, RTM_NEWROUTE, ipv4);

    auto ipv6 = payload_with(route_header(AF_INET6, 64U, 200U));
    append_ip(ipv6, RTA_DST, AF_INET6, "2001:db8:1::");
    append_scalar(ipv6, RTA_OIF, std::uint32_t{9U});
    append_ip(ipv6, RTA_GATEWAY, AF_INET6, "2001:db8:1::1");
    append_scalar(ipv6, RTA_PRIORITY, std::uint32_t{0U});
    const rta_cacheinfo cache_info{};
    append_attribute(
        ipv6, RTA_CACHEINFO, &cache_info, sizeof(cache_info));
    append_scalar(ipv6, RTA_PREF, std::uint8_t{0U});
    append_message(block, RTM_NEWROUTE, ipv6);
    append_done(block);

    const auto parsed = parse_raw_rtnetlink_route_dump_block(
        block.data(), block.size(), options());

    REQUIRE(parsed.state == RawRtnetlinkDumpState::done);
    REQUIRE(parsed.routes.size() == 2U);
    const auto& v4 = parsed.routes[0];
    CHECK(v4.destination == "10.20.30.0/24");
    CHECK(v4.table == 1001U);
    CHECK(v4.interface == std::optional<std::string>{"awg0"});
    CHECK(v4.gateway == std::optional<std::string>{"10.20.30.1"});
    CHECK(v4.metric == 0U);
    CHECK(v4.protocol == KEEN_PBR_GENERATED_ROUTE_PROTOCOL);
    CHECK(v4.family == AF_INET);
    CHECK(v4.exact_identity_representable);

    const auto& v6 = parsed.routes[1];
    CHECK(v6.destination == "2001:db8:1::/64");
    CHECK(v6.table == 200U);
    CHECK(v6.interface == std::optional<std::string>{"wan0"});
    CHECK(v6.gateway == std::optional<std::string>{"2001:db8:1::1"});
    CHECK(v6.metric == 0U);
    CHECK(v6.family == AF_INET6);
    CHECK(v6.exact_identity_representable);
}

TEST_CASE("raw rtnetlink codec: default blackhole and unreachable routes are represented") {
    std::vector<std::uint8_t> block;
    auto unicast = payload_with(route_header(AF_INET, 0U, 101U));
    append_scalar(unicast, RTA_OIF, std::uint32_t{7U});
    append_message(block, RTM_NEWROUTE, unicast);
    append_message(block, RTM_NEWROUTE,
                   payload_with(route_header(
                       AF_INET, 0U, 102U, RTN_BLACKHOLE)));
    append_message(block, RTM_NEWROUTE,
                   payload_with(route_header(
                       AF_INET6, 0U, 103U, RTN_UNREACHABLE)));
    append_done(block);

    const auto parsed = parse_raw_rtnetlink_route_dump_block(
        block.data(), block.size(), options());

    REQUIRE(parsed.state == RawRtnetlinkDumpState::done);
    REQUIRE(parsed.routes.size() == 3U);
    CHECK(parsed.routes[0].destination == "default");
    CHECK_FALSE(parsed.routes[0].blackhole);
    CHECK_FALSE(parsed.routes[0].unreachable);
    CHECK(parsed.routes[0].interface == std::optional<std::string>{"awg0"});
    CHECK(parsed.routes[0].exact_identity_representable);
    CHECK(parsed.routes[1].blackhole);
    CHECK(parsed.routes[1].exact_identity_representable);
    CHECK(parsed.routes[2].unreachable);
    CHECK(parsed.routes[2].exact_identity_representable);
}

TEST_CASE("raw rtnetlink codec: duplicate hidden and multipath route data fails exactness") {
    auto route = payload_with(route_header(AF_INET, 0U, 120U));
    append_scalar(route, RTA_PRIORITY, std::uint32_t{7U});
    append_scalar(route, RTA_PRIORITY, std::uint32_t{8U});
    append_scalar(route, RTA_MULTIPATH, std::uint32_t{0U});
    append_scalar(route, RTA_PREFSRC, std::uint32_t{0U});
    std::vector<std::uint8_t> block;
    append_message(block, RTM_NEWROUTE, route);
    append_done(block);

    const auto parsed = parse_raw_rtnetlink_route_dump_block(
        block.data(), block.size(), options());

    REQUIRE(parsed.state == RawRtnetlinkDumpState::done);
    REQUIRE(parsed.routes.size() == 1U);
    // Linux retains the last duplicate value. The projection follows that
    // visible value but the non-canonical identity remains inexact.
    CHECK(parsed.routes[0].metric == 8U);
    CHECK_FALSE(parsed.routes[0].exact_identity_representable);
}

TEST_CASE("raw rtnetlink codec: unknown interface remains visible but never exact") {
    auto route = payload_with(route_header(AF_INET, 0U, 121U));
    append_scalar(route, RTA_OIF, std::uint32_t{9999U});
    std::vector<std::uint8_t> block;
    append_message(block, RTM_NEWROUTE, route);
    append_done(block);

    const auto parsed = parse_raw_rtnetlink_route_dump_block(
        block.data(), block.size(), options());

    REQUIRE(parsed.state == RawRtnetlinkDumpState::done);
    REQUIRE(parsed.routes.size() == 1U);
    CHECK_FALSE(parsed.routes[0].interface.has_value());
    CHECK_FALSE(parsed.routes[0].exact_identity_representable);
}

TEST_CASE("raw rtnetlink codec: IPv4 and IPv6 policy rules preserve their tuple") {
    std::vector<std::uint8_t> block;
    auto ipv4 = payload_with(rule_header(AF_INET, RT_TABLE_UNSPEC));
    append_scalar(ipv4, FRA_PRIORITY, std::uint32_t{1001U});
    append_scalar(ipv4, FRA_FWMARK, std::uint32_t{0x00040000U});
    append_scalar(ipv4, FRA_FWMASK, std::uint32_t{0x00ff0000U});
    append_scalar(ipv4, FRA_TABLE, std::uint32_t{1001U});
    append_scalar(
        ipv4,
        FRA_SUPPRESS_IFGROUP,
        std::numeric_limits<std::uint32_t>::max());
    append_scalar(
        ipv4,
        FRA_SUPPRESS_PREFIXLEN,
        std::numeric_limits<std::uint32_t>::max());
    append_scalar(ipv4, FRA_PROTOCOL, std::uint8_t{RTPROT_UNSPEC});
    append_message(block, RTM_NEWRULE, ipv4);

    auto ipv6 = payload_with(rule_header(AF_INET6, 200U));
    append_scalar(ipv6, FRA_PRIORITY, std::uint32_t{200U});
    append_scalar(ipv6, FRA_FWMARK, std::uint32_t{9U});
    append_scalar(ipv6, FRA_FWMASK, std::uint32_t{0xffffffffU});
    append_message(block, RTM_NEWRULE, ipv6);
    append_done(block);

    const auto parsed = parse_raw_rtnetlink_rule_dump_block(
        block.data(), block.size(), options());

    REQUIRE(parsed.state == RawRtnetlinkDumpState::done);
    REQUIRE(parsed.rules.size() == 2U);
    CHECK(parsed.rules[0].priority == 1001U);
    CHECK(parsed.rules[0].fwmark == 0x00040000U);
    CHECK(parsed.rules[0].fwmask == 0x00ff0000U);
    CHECK(parsed.rules[0].table == 1001U);
    CHECK(parsed.rules[0].family == AF_INET);
    CHECK(parsed.rules[0].exact_identity_representable);
    CHECK(parsed.rules[1].priority == 200U);
    CHECK(parsed.rules[1].table == 200U);
    CHECK(parsed.rules[1].family == AF_INET6);
    CHECK(parsed.rules[1].exact_identity_representable);
}

TEST_CASE("raw rtnetlink codec: selectors actions flags and duplicates make rules inexact") {
    std::vector<std::uint8_t> block;

    auto selector = payload_with(rule_header(AF_INET, 150U));
    const char interface[] = "br0";
    append_attribute(selector, FRA_IIFNAME, interface, sizeof(interface));
    append_message(block, RTM_NEWRULE, selector);

    auto action = payload_with(rule_header(AF_INET, 151U, FR_ACT_GOTO));
    append_message(block, RTM_NEWRULE, action);

    auto flags_header = rule_header(AF_INET6, 152U);
    flags_header.flags = 1U;
    append_message(block, RTM_NEWRULE, payload_with(flags_header));

    auto duplicate = payload_with(rule_header(AF_INET, 153U));
    append_scalar(duplicate, FRA_PRIORITY, std::uint32_t{153U});
    append_scalar(duplicate, FRA_PRIORITY, std::uint32_t{154U});
    append_message(block, RTM_NEWRULE, duplicate);
    append_done(block);

    const auto parsed = parse_raw_rtnetlink_rule_dump_block(
        block.data(), block.size(), options());

    REQUIRE(parsed.state == RawRtnetlinkDumpState::done);
    REQUIRE(parsed.rules.size() == 4U);
    for (const auto& rule : parsed.rules) {
        CHECK_FALSE(rule.exact_identity_representable);
    }
    CHECK(parsed.rules[3].priority == 154U);
}

TEST_CASE("raw rtnetlink codec: terminal and ownership classifications fail closed") {
    const auto valid_route = payload_with(route_header(AF_INET, 0U, 100U));

    SUBCASE("a valid block without DONE requests more data") {
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWROUTE, valid_route);
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::more);
        CHECK(parsed.routes.size() == 1U);
    }

    SUBCASE("a kernel errno discards an earlier object") {
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWROUTE, valid_route);
        nlmsgerr error{};
        error.error = -EPERM;
        append_message(block, NLMSG_ERROR, payload_with(error));
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::kernel_error);
        CHECK(parsed.kernel_error == -EPERM);
        CHECK(parsed.routes.empty());
    }

    SUBCASE("a wrong sequence is classified and discarded") {
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWROUTE, valid_route, kSequence + 1U);
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::sequence_mismatch);
        CHECK(parsed.routes.empty());
    }

    SUBCASE("a wrong netlink header port id is classified and discarded") {
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWROUTE, valid_route,
                       kSequence, kPortId + 1U);
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::port_id_mismatch);
        CHECK(parsed.routes.empty());
    }

    SUBCASE("a truncated attribute makes the whole block malformed") {
        auto route = valid_route;
        const std::uint8_t one_byte = 7U;
        append_attribute(route, RTA_PRIORITY, &one_byte, sizeof(one_byte));
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWROUTE, route);
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::malformed);
        CHECK(parsed.routes.empty());
    }

    SUBCASE("the other dump object type is never silently ignored") {
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWRULE,
                       payload_with(rule_header(AF_INET, 100U)));
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::unexpected_message);
        CHECK(parsed.routes.empty());
    }

#ifdef NLM_F_DUMP_INTR
    SUBCASE("an interrupted dump can never become an authoritative snapshot") {
        std::vector<std::uint8_t> block;
        append_message(block, RTM_NEWROUTE, valid_route, kSequence, kPortId,
                       static_cast<std::uint16_t>(NLM_F_MULTI | NLM_F_DUMP_INTR));
        const auto parsed = parse_raw_rtnetlink_route_dump_block(
            block.data(), block.size(), options());
        CHECK(parsed.state == RawRtnetlinkDumpState::dump_interrupted);
        CHECK(parsed.routes.empty());
    }
#endif
}

TEST_CASE("NetlinkManager completes live raw route and rule inventories") {
    NetlinkManager netlink;
    std::vector<DumpedRoute> routes;
    std::vector<DumpedRule> rules;

    CHECK_NOTHROW(routes = netlink.dump_routes());
    CHECK_NOTHROW(rules = netlink.dump_policy_rules());
    CHECK(std::all_of(
        routes.begin(), routes.end(), [](const DumpedRoute& route) {
            return !route.destination.empty() &&
                   (route.family == AF_INET ||
                    route.family == AF_INET6);
    }));
    CHECK_FALSE(rules.empty());
    CHECK(std::any_of(
        rules.begin(), rules.end(), [](const DumpedRule& rule) {
            return rule.family == AF_INET ||
                   rule.family == AF_INET6;
        }));
}

}  // namespace keen_pbr3
