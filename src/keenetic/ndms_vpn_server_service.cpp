#include "ndms_vpn_server_service.hpp"

#include "../crypto/sha256.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaximumRunningConfigLines = 16384U;
constexpr std::size_t kMaximumLineBytes = 4096U;
constexpr std::size_t kMaximumNamedSections = 256U;
constexpr std::size_t kMaximumServices = 64U;
constexpr std::size_t kMaximumIdentifierBytes = 96U;
constexpr std::size_t kMaximumCidrCover = 256U;
constexpr std::uint32_t kMaximumSourcePoolSize = 65536U;

std::string trim_ascii_whitespace(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1U);
}

bool starts_with(const std::string& value, std::string_view prefix) {
    return value.size() >= prefix.size() &&
           value.compare(0, prefix.size(), prefix) == 0;
}

bool valid_identifier(const std::string& value) {
    if (value.empty() || value.size() > kMaximumIdentifierBytes) {
        return false;
    }
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') ||
                   character == '_' || character == '-' ||
                   character == '.';
        });
}

std::optional<std::string> suffix_identifier(
    const std::string& line,
    std::string_view prefix) {
    if (!starts_with(line, prefix)) return std::nullopt;
    const auto value =
        trim_ascii_whitespace(line.substr(prefix.size()));
    if (!valid_identifier(value)) {
        throw std::invalid_argument(
            "NDMS VPN service configuration has an invalid object identifier");
    }
    return value;
}

std::vector<std::string> split_ascii_words(const std::string& line) {
    std::vector<std::string> result;
    std::size_t position = 0U;
    while (position < line.size()) {
        position = line.find_first_not_of(" \t", position);
        if (position == std::string::npos) break;
        const auto end = line.find_first_of(" \t", position);
        result.push_back(
            end == std::string::npos
                ? line.substr(position)
                : line.substr(position, end - position));
        if (end == std::string::npos) break;
        position = end;
    }
    return result;
}

template <typename T>
void assign_unique(std::optional<T>& destination,
                   T value,
                   const char* error) {
    if (destination.has_value() && *destination != value) {
        throw std::invalid_argument(error);
    }
    destination = std::move(value);
}

struct BinaryAddress {
    int family{AF_UNSPEC};
    std::array<std::uint8_t, 16> bytes{};
    std::size_t size{0U};
};

std::optional<BinaryAddress> parse_binary_address(
    const std::string& text) {
    BinaryAddress result;
    in_addr ipv4{};
    if (inet_pton(AF_INET, text.c_str(), &ipv4) == 1) {
        result.family = AF_INET;
        result.size = 4U;
        std::copy_n(
            reinterpret_cast<const std::uint8_t*>(&ipv4),
            result.size,
            result.bytes.begin());
        return result;
    }

    in6_addr ipv6{};
    if (inet_pton(AF_INET6, text.c_str(), &ipv6) != 1) {
        return std::nullopt;
    }
    result.family = AF_INET6;
    result.size = 16U;
    std::copy_n(
        reinterpret_cast<const std::uint8_t*>(&ipv6),
        result.size,
        result.bytes.begin());
    return result;
}

std::string canonical_address(const BinaryAddress& address) {
    char output[INET6_ADDRSTRLEN]{};
    const void* input = address.bytes.data();
    if (inet_ntop(
            address.family,
            input,
            output,
            sizeof(output)) == nullptr) {
        throw std::invalid_argument(
            "NDMS VPN service address cannot be canonicalized");
    }
    return output;
}

int compare_address(const BinaryAddress& left,
                    const BinaryAddress& right) {
    return std::lexicographical_compare(
               left.bytes.begin(),
               left.bytes.begin() + left.size,
               right.bytes.begin(),
               right.bytes.begin() + right.size)
               ? -1
               : (std::lexicographical_compare(
                      right.bytes.begin(),
                      right.bytes.begin() + right.size,
                      left.bytes.begin(),
                      left.bytes.begin() + left.size)
                      ? 1
                      : 0);
}

std::size_t trailing_zero_bits(const BinaryAddress& address) {
    std::size_t result = 0U;
    for (std::size_t index = address.size; index > 0U; --index) {
        const std::uint8_t byte = address.bytes[index - 1U];
        if (byte == 0U) {
            result += 8U;
            continue;
        }
        std::uint8_t value = byte;
        while ((value & 1U) == 0U) {
            ++result;
            value = static_cast<std::uint8_t>(value >> 1U);
        }
        break;
    }
    return result;
}

BinaryAddress block_end(BinaryAddress start, std::size_t host_bits) {
    for (std::size_t bit = 0U; bit < host_bits; ++bit) {
        const std::size_t byte_from_end = bit / 8U;
        const std::size_t bit_in_byte = bit % 8U;
        const std::size_t index =
            start.size - 1U - byte_from_end;
        start.bytes[index] = static_cast<std::uint8_t>(
            start.bytes[index] |
            static_cast<std::uint8_t>(1U << bit_in_byte));
    }
    return start;
}

bool increment_address(BinaryAddress& address) {
    for (std::size_t index = address.size; index > 0U; --index) {
        auto& byte = address.bytes[index - 1U];
        if (byte != std::numeric_limits<std::uint8_t>::max()) {
            ++byte;
            return true;
        }
        byte = 0U;
    }
    return false;
}

bool inclusive_address_span_at_most(
    const BinaryAddress& first,
    const BinaryAddress& last,
    std::uint32_t maximum_addresses) {
    auto cursor = first;
    for (std::uint32_t count = 1U;
         count <= maximum_addresses;
         ++count) {
        if (compare_address(cursor, last) == 0) {
            return true;
        }
        if (!increment_address(cursor)) {
            return false;
        }
    }
    return false;
}

std::optional<std::uint32_t> parse_decimal_u32(
    const std::string& value) {
    if (value.empty()) return std::nullopt;
    std::uint32_t parsed = 0U;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

std::string ipv4_pool_last_address(
    const std::string& first,
    const std::string& count_text,
    const char* invalid_error,
    const char* overflow_error) {
    const auto count = parse_decimal_u32(count_text);
    const auto address = parse_binary_address(first);
    if (!count || *count == 0U || *count > kMaximumSourcePoolSize ||
        !address || address->family != AF_INET) {
        throw std::invalid_argument(invalid_error);
    }

    std::uint32_t host = 0U;
    for (std::size_t index = 0U; index < 4U; ++index) {
        host = static_cast<std::uint32_t>(
            (host << 8U) | address->bytes[index]);
    }
    const auto additional = static_cast<std::uint64_t>(*count - 1U);
    if (static_cast<std::uint64_t>(host) + additional >
        std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(overflow_error);
    }
    host = static_cast<std::uint32_t>(
        static_cast<std::uint64_t>(host) + additional);

    BinaryAddress last = *address;
    for (std::size_t index = 0U; index < 4U; ++index) {
        const std::size_t shift = (3U - index) * 8U;
        last.bytes[index] = static_cast<std::uint8_t>(
            (host >> shift) & 0xFFU);
    }
    return canonical_address(last);
}

std::vector<std::string> address_range_or_count_cidrs(
    const std::pair<std::string, std::string>& range,
    const char* invalid_error,
    const char* overflow_error) {
    if (!parse_decimal_u32(range.second).has_value()) {
        return ndms_address_range_to_cidrs(
            range.first, range.second);
    }
    return ndms_address_range_to_cidrs(
        range.first,
        ipv4_pool_last_address(
            range.first,
            range.second,
            invalid_error,
            overflow_error));
}

struct IkePolicy {
    std::optional<std::string> mode;
};

struct CryptoMap {
    std::optional<std::string> profile;
    std::optional<std::pair<std::string, std::string>> l2tp_range;
    std::optional<std::string> l2tp_interface;
    std::optional<bool> l2tp_enabled;
    std::optional<std::pair<std::string, std::string>> virtual_range;
    std::optional<std::string> virtual_interface;
    std::optional<bool> virtual_enabled;
    std::optional<bool> enabled;
};

struct PooledServiceConfig {
    bool section_seen{false};
    bool service_enabled{false};
    std::optional<std::pair<std::string, std::string>> pool;
    std::optional<std::string> interface_id;
};

enum class SectionKind : std::uint8_t {
    none,
    ike_policy,
    crypto_map,
    sstp,
    openconnect,
};

struct CurrentSection {
    SectionKind kind{SectionKind::none};
    std::string name;
};

NdmsVpnServerService make_service(
    std::string id,
    std::string label,
    NdmsVpnServerServiceKind kind,
    bool enabled,
    std::optional<std::string> interface_id,
    std::vector<std::string> cidrs) {
    NdmsVpnServerService result;
    result.id = std::move(id);
    result.label = std::move(label);
    result.kind = kind;
    result.enabled = enabled;
    result.bound_interface_id = std::move(interface_id);
    for (auto& cidr : cidrs) {
        if (cidr.find(':') == std::string::npos) {
            result.source_cidrs_v4.push_back(std::move(cidr));
        } else {
            result.source_cidrs_v6.push_back(std::move(cidr));
        }
    }

    nlohmann::json structural{
        {"id", result.id},
        {"kind", ndms_vpn_server_service_kind_name(result.kind)},
        {"enabled", result.enabled},
        {"source_cidrs_v4", result.source_cidrs_v4},
        {"source_cidrs_v6", result.source_cidrs_v6},
    };
    if (result.bound_interface_id) {
        structural["bound_interface_id"] =
            *result.bound_interface_id;
    }
    result.inventory_revision = Sha256::hex(structural.dump());
    return result;
}

} // namespace

std::vector<std::string> ndms_address_range_to_cidrs(
    const std::string& first,
    const std::string& last) {
    auto current = parse_binary_address(first);
    const auto final = parse_binary_address(last);
    if (!current || !final ||
        current->family != final->family ||
        current->size != final->size ||
        compare_address(*current, *final) > 0) {
        throw std::invalid_argument(
            "NDMS VPN service address range is invalid");
    }
    if (canonical_address(*current) != first ||
        canonical_address(*final) != last) {
        throw std::invalid_argument(
            "NDMS VPN service address range is not canonical");
    }
    if (!inclusive_address_span_at_most(
            *current, *final, kMaximumSourcePoolSize)) {
        throw std::invalid_argument(
            "NDMS VPN service address range is too large");
    }

    const std::size_t address_bits = current->size * 8U;
    std::vector<std::string> result;
    while (compare_address(*current, *final) <= 0) {
        std::size_t host_bits =
            std::min(trailing_zero_bits(*current), address_bits);
        auto end = block_end(*current, host_bits);
        while (compare_address(end, *final) > 0) {
            if (host_bits == 0U) {
                throw std::invalid_argument(
                    "NDMS VPN service address range cannot be decomposed");
            }
            --host_bits;
            end = block_end(*current, host_bits);
        }

        result.push_back(
            canonical_address(*current) + "/" +
            std::to_string(address_bits - host_bits));
        if (result.size() > kMaximumCidrCover) {
            throw std::invalid_argument(
                "NDMS VPN service address range is too fragmented");
        }
        if (compare_address(end, *final) == 0) break;
        if (!increment_address(end)) {
            throw std::invalid_argument(
                "NDMS VPN service address range overflows");
        }
        current = end;
    }
    return result;
}

NdmsVpnServerServiceCatalog parse_ndms_vpn_server_service_catalog(
    const nlohmann::json& running_config) {
    if (!running_config.is_object()) {
        throw std::invalid_argument(
            "NDMS running-config response is not an object");
    }
    const auto messages = running_config.find("message");
    if (messages == running_config.end() || !messages->is_array() ||
        messages->size() > kMaximumRunningConfigLines) {
        throw std::invalid_argument(
            "NDMS running-config message is invalid");
    }

    std::map<std::string, IkePolicy> ike_policies;
    std::map<std::string, CryptoMap> crypto_maps;
    PooledServiceConfig sstp;
    PooledServiceConfig openconnect;
    CurrentSection current;

    for (const auto& item : *messages) {
        if (!item.is_string()) {
            throw std::invalid_argument(
                "NDMS running-config line is not a string");
        }
        const auto& raw = item.get_ref<const std::string&>();
        if (raw.size() > kMaximumLineBytes ||
            raw.find('\0') != std::string::npos) {
            throw std::invalid_argument(
                "NDMS running-config line is invalid");
        }
        const auto line = trim_ascii_whitespace(raw);
        if (line.empty()) continue;

        const bool top_level =
            raw.front() != ' ' && raw.front() != '\t';
        if (top_level) {
            current = {};
            if (line == "service sstp-server") {
                sstp.service_enabled = true;
                continue;
            }
            if (line == "no service sstp-server") {
                if (sstp.service_enabled) {
                    throw std::invalid_argument(
                        "NDMS SSTP service state is ambiguous");
                }
                continue;
            }
            if (line == "service oc-server") {
                openconnect.service_enabled = true;
                continue;
            }
            if (line == "no service oc-server") {
                if (openconnect.service_enabled) {
                    throw std::invalid_argument(
                        "NDMS OpenConnect service state is ambiguous");
                }
                continue;
            }
            if (line == "sstp-server") {
                if (sstp.section_seen) {
                    throw std::invalid_argument(
                        "NDMS SSTP service section is duplicated");
                }
                sstp.section_seen = true;
                current.kind = SectionKind::sstp;
                continue;
            }
            if (line == "oc-server") {
                if (openconnect.section_seen) {
                    throw std::invalid_argument(
                        "NDMS OpenConnect service section is duplicated");
                }
                openconnect.section_seen = true;
                current.kind = SectionKind::openconnect;
                continue;
            }
            if (const auto name =
                    suffix_identifier(line, "crypto ike policy ")) {
                if (!ike_policies.emplace(*name, IkePolicy{}).second) {
                    throw std::invalid_argument(
                        "NDMS IKE policy section is duplicated");
                }
                current = {SectionKind::ike_policy, *name};
                if (ike_policies.size() > kMaximumNamedSections) {
                    throw std::invalid_argument(
                        "NDMS running-config contains too many IKE policies");
                }
                continue;
            }
            if (const auto name =
                    suffix_identifier(line, "crypto map ")) {
                if (!crypto_maps.emplace(*name, CryptoMap{}).second) {
                    throw std::invalid_argument(
                        "NDMS crypto map section is duplicated");
                }
                current = {SectionKind::crypto_map, *name};
                if (crypto_maps.size() > kMaximumNamedSections) {
                    throw std::invalid_argument(
                        "NDMS running-config contains too many crypto maps");
                }
            }
            continue;
        }

        if (current.kind == SectionKind::ike_policy) {
            constexpr std::string_view prefix{"mode "};
            if (!starts_with(line, prefix)) continue;
            const auto mode =
                trim_ascii_whitespace(line.substr(prefix.size()));
            if (mode != "ikev1" && mode != "ikev2") {
                throw std::invalid_argument(
                    "NDMS IKE policy mode is invalid");
            }
            assign_unique(
                ike_policies.at(current.name).mode,
                mode,
                "NDMS IKE policy mode is ambiguous");
            continue;
        }

        if (current.kind == SectionKind::sstp ||
            current.kind == SectionKind::openconnect) {
            auto& service =
                current.kind == SectionKind::sstp
                    ? sstp
                    : openconnect;
            const char* service_name =
                current.kind == SectionKind::sstp
                    ? "SSTP"
                    : "OpenConnect";
            const auto words = split_ascii_words(line);
            if (words.size() == 2U && words[0] == "interface") {
                if (!valid_identifier(words[1])) {
                    throw std::invalid_argument(std::string(
                        "NDMS ") + service_name +
                        " bound interface is invalid");
                }
                assign_unique(
                    service.interface_id,
                    words[1],
                    current.kind == SectionKind::sstp
                        ? "NDMS SSTP bound interface is ambiguous"
                        : "NDMS OpenConnect bound interface is ambiguous");
            } else if (
                words.size() == 3U && words[0] == "pool-range") {
                assign_unique(
                    service.pool,
                    std::make_pair(words[1], words[2]),
                    current.kind == SectionKind::sstp
                        ? "NDMS SSTP source pool is ambiguous"
                        : "NDMS OpenConnect source pool is ambiguous");
            }
            continue;
        }

        if (current.kind != SectionKind::crypto_map) continue;
        auto& map = crypto_maps.at(current.name);
        const auto words = split_ascii_words(line);
        if (words.size() == 1U && words[0] == "enable") {
            assign_unique(
                map.enabled,
                true,
                "NDMS crypto map state is ambiguous");
        } else if (
            words.size() == 2U && words[0] == "no" &&
            words[1] == "enable") {
            assign_unique(
                map.enabled,
                false,
                "NDMS crypto map state is ambiguous");
        } else if (words.size() == 2U && words[0] == "set-profile") {
            if (!valid_identifier(words[1])) {
                throw std::invalid_argument(
                    "NDMS crypto map profile is invalid");
            }
            assign_unique(
                map.profile,
                words[1],
                "NDMS crypto map profile is ambiguous");
        } else if (
            words.size() == 4U && words[0] == "l2tp-server" &&
            words[1] == "range") {
            assign_unique(
                map.l2tp_range,
                std::make_pair(words[2], words[3]),
                "NDMS L2TP source pool is ambiguous");
        } else if (
            words.size() == 3U && words[0] == "l2tp-server" &&
            words[1] == "interface") {
            if (!valid_identifier(words[2])) {
                throw std::invalid_argument(
                    "NDMS L2TP bound interface is invalid");
            }
            assign_unique(
                map.l2tp_interface,
                words[2],
                "NDMS L2TP bound interface is ambiguous");
        } else if (
            words.size() == 2U && words[0] == "l2tp-server" &&
            words[1] == "enable") {
            assign_unique(
                map.l2tp_enabled,
                true,
                "NDMS L2TP state is ambiguous");
        } else if (
            words.size() == 3U && words[0] == "l2tp-server" &&
            words[1] == "no" && words[2] == "enable") {
            assign_unique(
                map.l2tp_enabled,
                false,
                "NDMS L2TP state is ambiguous");
        } else if (
            words.size() == 4U && words[0] == "virtual-ip" &&
            words[1] == "range") {
            assign_unique(
                map.virtual_range,
                std::make_pair(words[2], words[3]),
                "NDMS IKEv2 source pool is ambiguous");
        } else if (
            words.size() == 3U && words[0] == "virtual-ip" &&
            words[1] == "interface") {
            if (!valid_identifier(words[2])) {
                throw std::invalid_argument(
                    "NDMS IKEv2 bound interface is invalid");
            }
            assign_unique(
                map.virtual_interface,
                words[2],
                "NDMS IKEv2 bound interface is ambiguous");
        } else if (
            words.size() == 2U && words[0] == "virtual-ip" &&
            words[1] == "enable") {
            assign_unique(
                map.virtual_enabled,
                true,
                "NDMS virtual-IP state is ambiguous");
        } else if (
            words.size() == 3U && words[0] == "virtual-ip" &&
            words[1] == "no" && words[2] == "enable") {
            assign_unique(
                map.virtual_enabled,
                false,
                "NDMS virtual-IP state is ambiguous");
        }
    }

    NdmsVpnServerServiceCatalog result;
    result.firmware_available = true;
    const auto mark_unresolved = [&result](std::string id) {
        result.unresolved_service_ids.push_back(std::move(id));
    };
    for (const auto& [name, map] : crypto_maps) {
        if (map.l2tp_enabled.has_value() || map.l2tp_range.has_value()) {
            const auto service_id =
                "ndms-crypto-map:l2tp:" + name;
            bool service_verified = false;
            if (map.l2tp_range && map.l2tp_interface) {
                try {
                    result.services.push_back(make_service(
                        service_id,
                        name,
                        NdmsVpnServerServiceKind::l2tp,
                        map.enabled.value_or(false) &&
                            map.l2tp_enabled.value_or(false),
                        map.l2tp_interface,
                        address_range_or_count_cidrs(
                            *map.l2tp_range,
                             "NDMS L2TP source pool is invalid",
                             "NDMS L2TP source pool overflows IPv4")));
                    service_verified = true;
                } catch (const std::invalid_argument&) {
                    // This one service is not authoritative. Keep other
                    // independently parsed VPN servers visible and fail this
                    // service closed by omitting it.
                }
            }
            if (!service_verified &&
                map.enabled.value_or(false) &&
                map.l2tp_enabled.value_or(false)) {
                mark_unresolved(service_id);
            }
        }

        const bool has_virtual_service =
            map.virtual_range.has_value() ||
            map.virtual_enabled.has_value();
        bool virtual_service_verified = false;
        if (has_virtual_service && map.profile &&
            map.virtual_range && map.virtual_interface) {
            const auto policy = ike_policies.find(*map.profile);
            if (policy != ike_policies.end() &&
                policy->second.mode.has_value()) {
                const auto kind =
                    *policy->second.mode == "ikev1"
                        ? NdmsVpnServerServiceKind::ikev1
                        : NdmsVpnServerServiceKind::ikev2;
                const auto protocol =
                    kind == NdmsVpnServerServiceKind::ikev1
                        ? "ikev1"
                        : "ikev2";
                try {
                    result.services.push_back(make_service(
                        "ndms-crypto-map:" +
                            std::string(protocol) + ":" + name,
                        name,
                        kind,
                        map.enabled.value_or(false) &&
                            map.virtual_enabled.value_or(false),
                        map.virtual_interface,
                        address_range_or_count_cidrs(
                            *map.virtual_range,
                             "NDMS IKE source pool is invalid",
                             "NDMS IKE source pool overflows IPv4")));
                    virtual_service_verified = true;
                } catch (const std::invalid_argument&) {
                    // See L2TP above: retain the rest of the inventory.
                }
            }
        }
        if (has_virtual_service &&
            !virtual_service_verified &&
            map.enabled.value_or(false) &&
            map.virtual_enabled.value_or(false)) {
            // A missing/invalid profile mode prevents us from knowing which
            // exact IKE stable identity is current. Retaining both possible
            // identities is still exact and safe: only an already verified
            // LKG entry can match either candidate.
            std::optional<std::string> protocol;
            if (map.profile) {
                const auto policy = ike_policies.find(*map.profile);
                if (policy != ike_policies.end() &&
                    policy->second.mode.has_value()) {
                    protocol = *policy->second.mode;
                }
            }
            if (protocol) {
                mark_unresolved(
                    "ndms-crypto-map:" + *protocol + ":" + name);
            } else {
                mark_unresolved(
                    "ndms-crypto-map:ikev1:" + name);
                mark_unresolved(
                    "ndms-crypto-map:ikev2:" + name);
            }
        }
    }

    bool sstp_verified = false;
    if (sstp.section_seen && sstp.pool && sstp.interface_id) {
        try {
            result.services.push_back(make_service(
                "ndms-service:sstp-server",
                "SSTP server",
                NdmsVpnServerServiceKind::sstp,
                sstp.service_enabled,
                sstp.interface_id,
                address_range_or_count_cidrs(
                    *sstp.pool,
                    "NDMS SSTP source pool is invalid",
                    "NDMS SSTP source pool overflows IPv4")));
            sstp_verified = true;
        } catch (const std::invalid_argument&) {
            // Omit only the incomplete or invalid SSTP service.
        }
    }
    if (!sstp_verified && sstp.service_enabled) {
        mark_unresolved("ndms-service:sstp-server");
    }

    bool openconnect_verified = false;
    if (openconnect.section_seen &&
        openconnect.pool && openconnect.interface_id) {
        try {
            result.services.push_back(make_service(
                "ndms-service:oc-server",
                "OpenConnect server",
                NdmsVpnServerServiceKind::openconnect,
                openconnect.service_enabled,
                openconnect.interface_id,
                address_range_or_count_cidrs(
                    *openconnect.pool,
                    "NDMS OpenConnect source pool is invalid",
                    "NDMS OpenConnect source pool overflows IPv4")));
            openconnect_verified = true;
        } catch (const std::invalid_argument&) {
            // Omit only the incomplete or invalid OpenConnect service.
        }
    }
    if (!openconnect_verified && openconnect.service_enabled) {
        mark_unresolved("ndms-service:oc-server");
    }

    if (result.services.size() > kMaximumServices) {
        throw std::invalid_argument(
            "NDMS running-config contains too many VPN server services");
    }
    std::sort(
        result.services.begin(),
        result.services.end(),
        [](const auto& left, const auto& right) {
            return left.id < right.id;
        });
    std::sort(
        result.unresolved_service_ids.begin(),
        result.unresolved_service_ids.end());
    result.unresolved_service_ids.erase(
        std::unique(
            result.unresolved_service_ids.begin(),
            result.unresolved_service_ids.end()),
        result.unresolved_service_ids.end());
    return result;
}

const char* ndms_vpn_server_service_kind_name(
    NdmsVpnServerServiceKind kind) noexcept {
    switch (kind) {
    case NdmsVpnServerServiceKind::l2tp:
        return "l2tp";
    case NdmsVpnServerServiceKind::ikev1:
        return "ikev1";
    case NdmsVpnServerServiceKind::ikev2:
        return "ikev2";
    case NdmsVpnServerServiceKind::sstp:
        return "sstp";
    case NdmsVpnServerServiceKind::openconnect:
        return "openconnect";
    }
    return "unknown";
}

} // namespace keen_pbr3
