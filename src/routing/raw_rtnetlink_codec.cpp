#include "raw_rtnetlink_codec.hpp"

#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cerrno>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::uint16_t kNetlinkAttributeTypeMask = 0x3fffU;
// Numeric Linux UAPI values are used instead of the enum spellings because
// Keenetic's GCC 8 sysroot intentionally ships older userspace headers. Newer
// kernels may still emit these attributes and exact parsing must not depend on
// the builder header vintage.
constexpr std::uint16_t kRouteAttributePreference = 20U;       // RTA_PREF
constexpr std::uint16_t kRuleAttributeSuppressIfgroup = 13U;   // FRA_SUPPRESS_IFGROUP
constexpr std::uint16_t kRuleAttributeSuppressPrefix = 14U;    // FRA_SUPPRESS_PREFIXLEN
constexpr std::uint16_t kRuleAttributeProtocol = 21U;          // FRA_PROTOCOL
#ifdef NLM_F_DUMP_INTR
constexpr std::uint16_t kDumpInterruptedFlag = NLM_F_DUMP_INTR;
#else
// Stable Linux UAPI value since the flag was introduced. Keeping the bit
// local prevents an old userspace header from accepting an interrupted dump.
constexpr std::uint16_t kDumpInterruptedFlag = 0x10U;
#endif

struct AttributeView {
    std::uint16_t type{0};
    bool has_type_flags{false};
    const std::uint8_t* payload{nullptr};
    std::size_t payload_size{0};
};

template <typename Visitor>
bool visit_attributes(const std::uint8_t* bytes,
                      const std::size_t size,
                      Visitor&& visitor) {
    std::size_t offset = 0U;
    while (offset < size) {
        const std::size_t remaining = size - offset;
        if (remaining < sizeof(rtattr)) return false;

        rtattr header{};
        std::memcpy(&header, bytes + offset, sizeof(header));
        if (header.rta_len < sizeof(rtattr) ||
            static_cast<std::size_t>(header.rta_len) > remaining) {
            return false;
        }

        AttributeView attribute;
        attribute.type = static_cast<std::uint16_t>(
            header.rta_type & kNetlinkAttributeTypeMask);
        attribute.has_type_flags =
            (header.rta_type & ~kNetlinkAttributeTypeMask) != 0U;
        attribute.payload = bytes + offset + sizeof(rtattr);
        attribute.payload_size =
            static_cast<std::size_t>(header.rta_len) - sizeof(rtattr);
        if (!visitor(attribute)) return false;

        const std::size_t aligned = RTA_ALIGN(header.rta_len);
        if (aligned > remaining) {
            // The final attribute may omit only its external alignment bytes.
            if (static_cast<std::size_t>(header.rta_len) != remaining) {
                return false;
            }
            offset = size;
        } else {
            offset += aligned;
        }
    }
    return true;
}

template <typename T>
bool read_scalar(const AttributeView& attribute, T& value) noexcept {
    if (attribute.payload_size != sizeof(T)) return false;
    std::memcpy(&value, attribute.payload, sizeof(T));
    return true;
}

bool address_string(const int family,
                    const AttributeView& attribute,
                    std::string& output) {
    char text[INET6_ADDRSTRLEN]{};
    if (family == AF_INET) {
        if (attribute.payload_size != sizeof(in_addr)) return false;
        in_addr address{};
        std::memcpy(&address, attribute.payload, sizeof(address));
        if (inet_ntop(AF_INET, &address, text, sizeof(text)) == nullptr) {
            return false;
        }
    } else if (family == AF_INET6) {
        if (attribute.payload_size != sizeof(in6_addr)) return false;
        in6_addr address{};
        std::memcpy(&address, attribute.payload, sizeof(address));
        if (inet_ntop(AF_INET6, &address, text, sizeof(text)) == nullptr) {
            return false;
        }
    } else {
        return false;
    }
    output = text;
    return true;
}

std::optional<std::string> interface_name(
    const std::uint32_t index,
    const RawRtnetlinkDumpOptions& options,
    bool& unambiguous) {
    std::optional<std::string> result;
    unambiguous = true;
    if (index == 0U || options.interface_names == nullptr) {
        unambiguous = false;
        return std::nullopt;
    }

    for (std::size_t i = 0U; i < options.interface_name_count; ++i) {
        const auto& candidate = options.interface_names[i];
        if (candidate.index != index) continue;
        if (candidate.name == nullptr || candidate.name[0] == '\0' || result) {
            unambiguous = false;
            continue;
        }
        result = candidate.name;
    }
    if (!result) unambiguous = false;
    return result;
}

bool decode_route(const std::uint8_t* payload,
                  const std::size_t payload_size,
                  const RawRtnetlinkDumpOptions& options,
                  DumpedRoute& output) {
    if (payload_size < sizeof(rtmsg)) return false;

    rtmsg message{};
    std::memcpy(&message, payload, sizeof(message));

    output.family = message.rtm_family;
    output.protocol = message.rtm_protocol;
    output.blackhole = message.rtm_type == RTN_BLACKHOLE;
    output.unreachable = message.rtm_type == RTN_UNREACHABLE;
    output.table = message.rtm_table;
    output.destination = message.rtm_dst_len == 0U ? "default" : "";
    output.exact_identity_representable =
        (message.rtm_family == AF_INET || message.rtm_family == AF_INET6) &&
        (message.rtm_type == RTN_UNICAST || output.blackhole ||
         output.unreachable) &&
        message.rtm_src_len == 0U && message.rtm_tos == 0U &&
        message.rtm_scope == RT_SCOPE_UNIVERSE && message.rtm_flags == 0U;

    if ((message.rtm_family == AF_INET && message.rtm_dst_len > 32U) ||
        (message.rtm_family == AF_INET6 && message.rtm_dst_len > 128U)) {
        return false;
    }

    bool saw_destination = false;
    bool saw_table = false;
    bool saw_interface = false;
    bool saw_gateway = false;
    bool saw_metric = false;
    bool saw_multipath = false;
    bool saw_cache_info = false;
    bool saw_preference = false;
    std::uint32_t table_attribute = 0U;

    const auto* attributes = payload + sizeof(rtmsg);
    const std::size_t attributes_size = payload_size - sizeof(rtmsg);
    const bool valid_attributes = visit_attributes(
        attributes, attributes_size, [&](const AttributeView& attribute) {
            if (attribute.has_type_flags) {
                output.exact_identity_representable = false;
            }
            switch (attribute.type) {
                case RTA_DST: {
                    if (saw_destination) {
                        output.exact_identity_representable = false;
                    }
                    saw_destination = true;
                    std::string address;
                    if (!address_string(message.rtm_family, attribute, address)) {
                        return false;
                    }
                    output.destination = message.rtm_dst_len == 0U
                        ? "default"
                        : address + "/" +
                              std::to_string(message.rtm_dst_len);
                    return true;
                }
                case RTA_TABLE: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_table) {
                        output.exact_identity_representable = false;
                    }
                    saw_table = true;
                    // Linux attribute parsers retain the last duplicate. Do
                    // the same for the visible projection while refusing to
                    // call the non-canonical wire identity exact.
                    table_attribute = value;
                    return true;
                }
                case RTA_OIF: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_interface) {
                        output.exact_identity_representable = false;
                    }
                    saw_interface = true;
                    bool unambiguous = false;
                    output.interface = interface_name(value, options, unambiguous);
                    if (!unambiguous) {
                        output.exact_identity_representable = false;
                    }
                    return true;
                }
                case RTA_GATEWAY: {
                    if (saw_gateway) {
                        output.exact_identity_representable = false;
                    }
                    saw_gateway = true;
                    std::string gateway;
                    if (!address_string(message.rtm_family, attribute, gateway)) {
                        return false;
                    }
                    output.gateway = std::move(gateway);
                    return true;
                }
                case RTA_PRIORITY: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_metric) {
                        output.exact_identity_representable = false;
                    }
                    saw_metric = true;
                    output.metric = value;
                    return true;
                }
                case RTA_MULTIPATH:
                    saw_multipath = true;
                    output.exact_identity_representable = false;
                    return true;
                case RTA_CACHEINFO:
                    if (saw_cache_info ||
                        attribute.payload_size !=
                            sizeof(rta_cacheinfo)) {
                        output.exact_identity_representable = false;
                    }
                    saw_cache_info = true;
                    return true;
                case kRouteAttributePreference: {
                    std::uint8_t preference = 0U;
                    if (!read_scalar(attribute, preference)) return false;
                    if (saw_preference || preference != 0U) {
                        // Medium is the canonical kernel default. High/low
                        // preference cannot be represented by RouteSpec.
                        output.exact_identity_representable = false;
                    }
                    saw_preference = true;
                    return true;
                }
                default:
                    // RouteSpec cannot reproduce this attribute, even when it
                    // looks like informational kernel metadata.
                    output.exact_identity_representable = false;
                    return true;
            }
        });
    if (!valid_attributes) return false;

    if (saw_table) {
        if (message.rtm_table != RT_TABLE_UNSPEC &&
            message.rtm_table != table_attribute) {
            output.exact_identity_representable = false;
        }
        output.table = table_attribute;
    } else if (message.rtm_table == RT_TABLE_UNSPEC) {
        output.exact_identity_representable = false;
    }

    if (message.rtm_dst_len != 0U && !saw_destination) {
        output.exact_identity_representable = false;
    }
    if (message.rtm_type == RTN_UNICAST &&
        (saw_multipath || (!saw_interface && !saw_gateway))) {
        // RouteSpec models one ordinary nexthop. A unicast route with no
        // visible nexthop, or an RTA_MULTIPATH graph, is a different shape.
        output.exact_identity_representable = false;
    }
    if ((output.blackhole || output.unreachable) &&
        (saw_interface || saw_gateway || saw_multipath)) {
        output.exact_identity_representable = false;
    }
    return true;
}

bool decode_rule(const std::uint8_t* payload,
                 const std::size_t payload_size,
                 DumpedRule& output) {
    if (payload_size < sizeof(fib_rule_hdr)) return false;

    fib_rule_hdr message{};
    std::memcpy(&message, payload, sizeof(message));

    output.family = message.family;
    output.table = message.table;
    output.exact_identity_representable =
        (message.family == AF_INET || message.family == AF_INET6) &&
        message.dst_len == 0U && message.src_len == 0U &&
        message.tos == 0U && message.res1 == 0U && message.res2 == 0U &&
        message.action == FR_ACT_TO_TBL && message.flags == 0U;

    bool saw_priority = false;
    bool saw_mark = false;
    bool saw_mask = false;
    bool saw_table = false;
    bool saw_suppress_ifgroup = false;
    bool saw_suppress_prefix = false;
    bool saw_protocol = false;
    std::uint32_t table_attribute = 0U;

    const auto* attributes = payload + sizeof(fib_rule_hdr);
    const std::size_t attributes_size = payload_size - sizeof(fib_rule_hdr);
    const bool valid_attributes = visit_attributes(
        attributes, attributes_size, [&](const AttributeView& attribute) {
            if (attribute.has_type_flags) {
                output.exact_identity_representable = false;
            }
            switch (attribute.type) {
                case FRA_PRIORITY: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_priority) {
                        output.exact_identity_representable = false;
                    }
                    saw_priority = true;
                    output.priority = value;
                    return true;
                }
                case FRA_FWMARK: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_mark) {
                        output.exact_identity_representable = false;
                    }
                    saw_mark = true;
                    output.fwmark = value;
                    return true;
                }
                case FRA_FWMASK: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_mask) {
                        output.exact_identity_representable = false;
                    }
                    saw_mask = true;
                    output.fwmask = value;
                    return true;
                }
                case FRA_TABLE: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_table) {
                        output.exact_identity_representable = false;
                    }
                    saw_table = true;
                    table_attribute = value;
                    return true;
                }
                case kRuleAttributeSuppressIfgroup: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_suppress_ifgroup ||
                        value !=
                            std::numeric_limits<std::uint32_t>::max()) {
                        output.exact_identity_representable = false;
                    }
                    saw_suppress_ifgroup = true;
                    return true;
                }
                case kRuleAttributeSuppressPrefix: {
                    std::uint32_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_suppress_prefix ||
                        value !=
                            std::numeric_limits<std::uint32_t>::max()) {
                        output.exact_identity_representable = false;
                    }
                    saw_suppress_prefix = true;
                    return true;
                }
                case kRuleAttributeProtocol: {
                    std::uint8_t value = 0U;
                    if (!read_scalar(attribute, value)) return false;
                    if (saw_protocol || value != RTPROT_UNSPEC) {
                        output.exact_identity_representable = false;
                    }
                    saw_protocol = true;
                    return true;
                }
                default:
                    // Any selector, alternate action metadata, or attribute
                    // unknown to this old-kernel-compatible projection makes
                    // the complete rule identity unrepresentable.
                    output.exact_identity_representable = false;
                    return true;
            }
        });
    if (!valid_attributes) return false;

    if (saw_table) {
        if (message.table != RT_TABLE_UNSPEC &&
            message.table != table_attribute) {
            output.exact_identity_representable = false;
        }
        output.table = table_attribute;
    } else if (message.table == RT_TABLE_UNSPEC) {
        output.exact_identity_representable = false;
    }

    // With a mark but no FRA_FWMASK Linux uses an all-ones mask.  With no
    // mark either, the absent selector is the zero/zero RuleSpec image.
    if (!saw_mask) {
        output.fwmask = saw_mark
            ? std::numeric_limits<std::uint32_t>::max()
            : 0U;
    }
    return true;
}

template <typename Result, typename Decode, typename Append, typename Clear>
Result parse_dump_block(const void* bytes,
                        const std::size_t size,
                        const RawRtnetlinkDumpOptions& options,
                        const std::uint16_t expected_type,
                        Decode&& decode,
                        Append&& append,
                        Clear&& clear) {
    Result result;
    result.state = RawRtnetlinkDumpState::malformed;
    if (bytes == nullptr || size < sizeof(nlmsghdr)) return result;

    const auto* input = static_cast<const std::uint8_t*>(bytes);
    std::size_t offset = 0U;
    while (offset < size) {
        const std::size_t remaining = size - offset;
        if (remaining < sizeof(nlmsghdr)) {
            clear(result);
            return result;
        }

        nlmsghdr header{};
        std::memcpy(&header, input + offset, sizeof(header));
        if (header.nlmsg_len < NLMSG_HDRLEN ||
            static_cast<std::size_t>(header.nlmsg_len) > remaining) {
            clear(result);
            return result;
        }
        if (header.nlmsg_seq != options.sequence) {
            clear(result);
            result.state = RawRtnetlinkDumpState::sequence_mismatch;
            return result;
        }
        if (header.nlmsg_pid != options.port_id) {
            clear(result);
            result.state = RawRtnetlinkDumpState::port_id_mismatch;
            return result;
        }
        if ((header.nlmsg_flags & kDumpInterruptedFlag) != 0U) {
            clear(result);
            result.state = RawRtnetlinkDumpState::dump_interrupted;
            return result;
        }

        const auto* payload = input + offset + NLMSG_HDRLEN;
        const std::size_t payload_size =
            static_cast<std::size_t>(header.nlmsg_len) - NLMSG_HDRLEN;
        const std::size_t aligned_length = NLMSG_ALIGN(header.nlmsg_len);
        std::size_t next_offset = 0U;
        if (aligned_length <= remaining) {
            next_offset = offset + aligned_length;
        } else if (static_cast<std::size_t>(header.nlmsg_len) == remaining) {
            next_offset = size;
        } else {
            clear(result);
            return result;
        }

        if (header.nlmsg_type == NLMSG_ERROR) {
            if (payload_size < sizeof(nlmsgerr)) {
                clear(result);
                return result;
            }
            nlmsgerr error{};
            std::memcpy(&error, payload, sizeof(error));
            if (error.error != 0) {
                clear(result);
                result.state = RawRtnetlinkDumpState::kernel_error;
                result.kernel_error = error.error;
                return result;
            }
        } else if (header.nlmsg_type == NLMSG_DONE) {
            if (payload_size != 0U && payload_size != sizeof(int)) {
                clear(result);
                return result;
            }
            if (payload_size == sizeof(int)) {
                int error = 0;
                std::memcpy(&error, payload, sizeof(error));
                if (error != 0) {
                    clear(result);
                    result.state = RawRtnetlinkDumpState::kernel_error;
                    result.kernel_error = error;
                    return result;
                }
            }
            if (next_offset != size) {
                clear(result);
                return result;
            }
            result.state = RawRtnetlinkDumpState::done;
            return result;
        } else if (header.nlmsg_type == NLMSG_OVERRUN) {
            clear(result);
            result.state = RawRtnetlinkDumpState::kernel_error;
            result.kernel_error = -ENOBUFS;
            return result;
        } else if (header.nlmsg_type != NLMSG_NOOP) {
            if (header.nlmsg_type != expected_type) {
                clear(result);
                result.state = RawRtnetlinkDumpState::unexpected_message;
                return result;
            }
            if (!decode(payload, payload_size, result)) {
                clear(result);
                result.state = RawRtnetlinkDumpState::malformed;
                return result;
            }
            append(result);
        }

        offset = next_offset;
    }

    result.state = RawRtnetlinkDumpState::more;
    return result;
}

}  // namespace

RawRtnetlinkRouteDumpBlock parse_raw_rtnetlink_route_dump_block(
    const void* bytes,
    const std::size_t size,
    const RawRtnetlinkDumpOptions& options) {
    std::optional<DumpedRoute> decoded;
    return parse_dump_block<RawRtnetlinkRouteDumpBlock>(
        bytes, size, options, RTM_NEWROUTE,
        [&](const std::uint8_t* payload,
            const std::size_t payload_size,
            RawRtnetlinkRouteDumpBlock&) {
            DumpedRoute route;
            if (!decode_route(payload, payload_size, options, route)) {
                return false;
            }
            decoded = std::move(route);
            return true;
        },
        [&](RawRtnetlinkRouteDumpBlock& result) {
            result.routes.push_back(std::move(*decoded));
            decoded.reset();
        },
        [](RawRtnetlinkRouteDumpBlock& result) { result.routes.clear(); });
}

RawRtnetlinkRuleDumpBlock parse_raw_rtnetlink_rule_dump_block(
    const void* bytes,
    const std::size_t size,
    const RawRtnetlinkDumpOptions& options) {
    std::optional<DumpedRule> decoded;
    return parse_dump_block<RawRtnetlinkRuleDumpBlock>(
        bytes, size, options, RTM_NEWRULE,
        [&](const std::uint8_t* payload,
            const std::size_t payload_size,
            RawRtnetlinkRuleDumpBlock&) {
            DumpedRule rule;
            if (!decode_rule(payload, payload_size, rule)) return false;
            decoded = std::move(rule);
            return true;
        },
        [&](RawRtnetlinkRuleDumpBlock& result) {
            result.rules.push_back(std::move(*decoded));
            decoded.reset();
        },
        [](RawRtnetlinkRuleDumpBlock& result) { result.rules.clear(); });
}

}  // namespace keen_pbr3
