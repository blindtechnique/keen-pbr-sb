#include "ndms_interface_inventory.hpp"

#include "../crypto/sha256.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <initializer_list>
#include <nlohmann/json.hpp>
#include <set>
#include <string_view>
#include <utility>

namespace keen_pbr3 {

namespace {

std::string trim_ascii_whitespace(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::optional<std::string> string_field(const nlohmann::json& entry,
                                        const char* key) {
    const auto found = entry.find(key);
    if (found == entry.end() || !found->is_string()) return std::nullopt;
    return trim_ascii_whitespace(found->get_ref<const std::string&>());
}

char ascii_lower(char character) noexcept {
    if (character >= 'A' && character <= 'Z') {
        return static_cast<char>(character - 'A' + 'a');
    }
    return character;
}

std::string ascii_casefolded_trimmed(const std::string& value) {
    auto result = trim_ascii_whitespace(value);
    std::transform(result.begin(), result.end(), result.begin(), ascii_lower);
    return result;
}

// Firmware type values are compared as complete case-insensitive tokens.
// Punctuation and internal whitespace remain significant so malformed values
// cannot become allowlisted merely by deleting separators.
std::string canonical_type_token(const std::optional<std::string>& value) {
    if (!value) return {};
    return ascii_casefolded_trimmed(*value);
}

bool token_is(const std::string& token,
              std::initializer_list<std::string_view> expected) {
    return std::any_of(
        expected.begin(),
        expected.end(),
        [&token](const auto candidate) {
            return token == candidate;
        });
}

std::optional<bool> boolean_field(const nlohmann::json& entry,
                                  const char* key) {
    const auto found = entry.find(key);
    if (found == entry.end()) return std::nullopt;
    if (found->is_boolean()) return found->get<bool>();
    if (found->is_string()) {
        const auto value =
            ascii_casefolded_trimmed(found->get_ref<const std::string&>());
        if (token_is(value, {"true", "yes", "up", "connected", "on"})) {
            return true;
        }
        if (token_is(
                value,
                {"false", "no", "down", "disconnected", "off"})) {
            return false;
        }
    }
    return std::nullopt;
}

std::optional<unsigned> decimal_prefix(const std::string& value,
                                       unsigned maximum) {
    const auto token = trim_ascii_whitespace(value);
    if (token.empty()) return std::nullopt;
    unsigned parsed = 0;
    const auto result =
        std::from_chars(token.data(), token.data() + token.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != token.data() + token.size() ||
        parsed > maximum) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<unsigned> ipv4_mask_prefix(const std::string& value) {
    in_addr mask{};
    if (inet_pton(AF_INET, value.c_str(), &mask) != 1) {
        return decimal_prefix(value, 32);
    }

    const auto bits = ntohl(mask.s_addr);
    bool zero_seen = false;
    unsigned prefix = 0;
    for (int bit = 31; bit >= 0; --bit) {
        const bool set = (bits & (std::uint32_t{1} << bit)) != 0;
        if (set && zero_seen) return std::nullopt;
        if (set) {
            ++prefix;
        } else {
            zero_seen = true;
        }
    }
    return prefix;
}

std::optional<unsigned> local_prefix_length(const nlohmann::json& entry) {
    const auto address_field = string_field(entry, "address");
    if (!address_field || address_field->empty()) return std::nullopt;

    auto address = *address_field;
    std::optional<unsigned> embedded_prefix;
    const auto slash = address.find('/');
    if (slash != std::string::npos) {
        if (address.find('/', slash + 1) != std::string::npos) {
            return std::nullopt;
        }
        const auto suffix = address.substr(slash + 1);
        address.erase(slash);
        embedded_prefix = decimal_prefix(
            suffix,
            address.find(':') == std::string::npos ? 32U : 128U);
        if (!embedded_prefix) return std::nullopt;
    }

    in_addr ipv4{};
    in6_addr ipv6{};
    unsigned maximum = 0;
    const bool is_ipv4 = inet_pton(AF_INET, address.c_str(), &ipv4) == 1;
    if (is_ipv4) {
        maximum = 32;
    } else if (inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
        maximum = 128;
    } else {
        return std::nullopt;
    }

    std::optional<unsigned> mask_prefix;
    const auto mask = entry.find("mask");
    if (mask != entry.end()) {
        if (mask->is_number_unsigned()) {
            const auto value = mask->get<std::uint64_t>();
            if (value > maximum) return std::nullopt;
            mask_prefix = static_cast<unsigned>(value);
        } else if (mask->is_number_integer()) {
            const auto value = mask->get<std::int64_t>();
            if (value < 0 ||
                static_cast<std::uint64_t>(value) > maximum) {
                return std::nullopt;
            }
            mask_prefix = static_cast<unsigned>(value);
        } else if (mask->is_string()) {
            const auto value =
                trim_ascii_whitespace(mask->get_ref<const std::string&>());
            mask_prefix = is_ipv4 ? ipv4_mask_prefix(value)
                                  : decimal_prefix(value, maximum);
            if (!mask_prefix) return std::nullopt;
        } else {
            return std::nullopt;
        }
    }

    if (embedded_prefix && mask_prefix &&
        *embedded_prefix != *mask_prefix) {
        return std::nullopt;
    }
    return embedded_prefix ? embedded_prefix : mask_prefix;
}

bool has_non_host_local_subnet(const nlohmann::json& entry) {
    const auto address = string_field(entry, "address");
    const auto prefix = local_prefix_length(entry);
    if (!address || !prefix) return false;
    const bool ipv6 = address->find(':') != std::string::npos;
    return *prefix > 0U && (ipv6 ? *prefix <= 126U : *prefix <= 30U);
}

bool strict_false_field(const nlohmann::json& entry,
                        const char* key,
                        bool required) {
    const auto found = entry.find(key);
    if (found == entry.end()) return !required;
    if (found->is_boolean()) return !found->get<bool>();
    if (!found->is_string()) return false;
    const auto value =
        ascii_casefolded_trimmed(found->get_ref<const std::string&>());
    return token_is(value, {"false", "no"});
}

bool wireguard_server_shape(const nlohmann::json& entry) {
    if (!strict_false_field(entry, "global", true) ||
        !strict_false_field(entry, "defaultgw", false) ||
        !strict_false_field(entry, "default-route", false) ||
        !strict_false_field(entry, "default-gateway", false)) {
        return false;
    }
    return has_non_host_local_subnet(entry);
}

bool is_numbered_wireguard_name(const std::string& value) {
    constexpr std::string_view prefix{"Wireguard"};
    if (value.size() <= prefix.size() ||
        value.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    return std::all_of(
        value.begin() + prefix.size(),
        value.end(),
        [](const char character) {
            return character >= '0' && character <= '9';
        });
}

std::optional<std::string> exact_runtime_interface_name(
    const std::string& firmware_interface_name,
    const std::vector<std::string>& runtime_interface_names) {
    if (firmware_interface_name.empty()) return std::nullopt;
    if (std::find(
            runtime_interface_names.begin(),
            runtime_interface_names.end(),
            firmware_interface_name) != runtime_interface_names.end()) {
        return firmware_interface_name;
    }
    return std::nullopt;
}

enum class RoleEvidence {
    absent,
    valid,
    invalid_or_conflicting,
};

struct ParsedRole {
    NdmsInterfaceRole role{NdmsInterfaceRole::unknown};
    RoleEvidence evidence{RoleEvidence::absent};
};

ParsedRole parse_role(const nlohmann::json& entry) {
    std::optional<NdmsInterfaceRole> parsed;
    bool field_present = false;
    for (const auto* key : {"role", "mode", "interface-role"}) {
        const auto found = entry.find(key);
        if (found == entry.end()) continue;
        field_present = true;
        if (!found->is_string()) {
            return {
                NdmsInterfaceRole::unknown,
                RoleEvidence::invalid_or_conflicting,
            };
        }

        const auto value =
            ascii_casefolded_trimmed(found->get_ref<const std::string&>());
        NdmsInterfaceRole candidate;
        if (value == "client") {
            candidate = NdmsInterfaceRole::client;
        } else if (value == "server") {
            candidate = NdmsInterfaceRole::server;
        } else {
            return {
                NdmsInterfaceRole::unknown,
                RoleEvidence::invalid_or_conflicting,
            };
        }

        if (parsed && *parsed != candidate) {
            return {
                NdmsInterfaceRole::unknown,
                RoleEvidence::invalid_or_conflicting,
            };
        }
        parsed = candidate;
    }
    if (!field_present) {
        return {
            NdmsInterfaceRole::unknown,
            RoleEvidence::absent,
        };
    }
    return {
        parsed.value_or(NdmsInterfaceRole::unknown),
        RoleEvidence::valid,
    };
}

std::optional<NdmsTunnelKind> tunnel_kind_for_token(
    const std::string& token) {
    if (token_is(
            token,
            {"amneziawireguard",
             "amnezia wireguard",
             "amnezia-wireguard",
             "amnezia_wireguard",
             "amneziawg",
             "amnezia wg",
             "awg"})) {
        return NdmsTunnelKind::amnezia_wireguard;
    }
    if (token == "wireguard") return NdmsTunnelKind::wireguard;
    if (token == "openvpn") return NdmsTunnelKind::openvpn;
    if (token_is(token, {"ike", "ikev1", "ikev2", "ipsec"})) {
        return NdmsTunnelKind::ike;
    }
    if (token == "l2tp") return NdmsTunnelKind::l2tp;
    if (token == "sstp") return NdmsTunnelKind::sstp;
    if (token_is(token, {"openconnect", "anyconnect"})) {
        return NdmsTunnelKind::openconnect;
    }
    return std::nullopt;
}

std::optional<NdmsTunnelKind> classify(const nlohmann::json& entry) {
    // A present-but-malformed discriminator is not equivalent to an omitted
    // optional field. Another token must not turn a corrupt/conflicting RCI
    // record into a policy-authoritative tunnel.
    for (const auto* key : {"type", "subtype", "protocol"}) {
        const auto found = entry.find(key);
        if (found != entry.end() &&
            !found->is_null() &&
            !found->is_string()) {
            return std::nullopt;
        }
    }

    const std::array<std::string, 3> tunnel_tokens{
        canonical_type_token(string_field(entry, "type")),
        canonical_type_token(string_field(entry, "subtype")),
        canonical_type_token(string_field(entry, "protocol")),
    };

    // Proxy subtype tokens are only meaningful on an exact Proxy record.
    // Conversely, a malformed Proxy record cannot become a tunnel just
    // because another field contains a tunnel-looking value.
    if (tunnel_tokens[0] == "proxy") {
        const auto proxy_type =
            canonical_type_token(string_field(entry, "proxy-type"));
        if (proxy_type == "socks5") {
            return NdmsTunnelKind::socks5_proxy;
        }
        if (token_is(
                proxy_type,
                {"https", "httpsproxy", "https-proxy", "https_proxy"})) {
            return NdmsTunnelKind::https_proxy;
        }
        if (token_is(
                proxy_type,
                {"http", "httpproxy", "http-proxy", "http_proxy"})) {
            return NdmsTunnelKind::http_proxy;
        }
        return std::nullopt;
    }

    // An explicit unrelated type is authoritative. Generic tunnel/PPP
    // containers and absent/malformed types may be refined by subtype or
    // protocol, but Bridge/AccessPoint/etc. records never enter the inventory.
    if (!tunnel_tokens[0].empty() &&
        !token_is(tunnel_tokens[0], {"tunnel", "vpn", "ppp"}) &&
        !tunnel_kind_for_token(tunnel_tokens[0])) {
        return std::nullopt;
    }

    std::optional<NdmsTunnelKind> classified;
    for (const auto& token : tunnel_tokens) {
        const auto candidate = tunnel_kind_for_token(token);
        if (!candidate) continue;
        if (!classified || *classified == *candidate) {
            classified = candidate;
            continue;
        }
        const auto wireguard_and_amnezia =
            (*classified == NdmsTunnelKind::wireguard &&
             *candidate == NdmsTunnelKind::amnezia_wireguard) ||
            (*classified == NdmsTunnelKind::amnezia_wireguard &&
             *candidate == NdmsTunnelKind::wireguard);
        if (!wireguard_and_amnezia) return std::nullopt;
        classified = NdmsTunnelKind::amnezia_wireguard;
    }
    return classified;
}

// KeeneticOS reports "uptime" as whole seconds since the interface last came
// up, and reports 0 for an interface it does not consider up. A negative or
// non-integral value is firmware we do not understand, so it is dropped rather
// than guessed at.
std::optional<std::int64_t> uptime_seconds_field(const nlohmann::json& entry) {
    const auto field = entry.find("uptime");
    if (field == entry.end() || !field->is_number_integer()) {
        return std::nullopt;
    }
    const auto value = field->get<std::int64_t>();
    if (value < 0) {
        return std::nullopt;
    }
    return value;
}

struct ParsedEntry {
    std::string id;
    std::string firmware_interface_name;
    std::string label;
    std::string firmware_type;
    std::optional<NdmsTunnelKind> kind;
    NdmsInterfaceRole role{NdmsInterfaceRole::unknown};
    bool internal_vpn_server_candidate{false};
    bool internal_vpn_server_role_confirmation_required{false};
    std::optional<bool> connected;
    std::optional<bool> link;
    // Deliberately absent from inventory_revision below: this counter changes
    // every second, and folding it into the structural digest would churn the
    // interface identity on every poll and break optimistic concurrency.
    std::optional<std::int64_t> uptime_seconds;
    std::string inventory_revision;
};

std::string inventory_revision(const nlohmann::json& entry) {
    nlohmann::json structural = nlohmann::json::object();
    for (const auto* field :
         {"type",
          "subtype",
          "protocol",
          "proxy-type",
          "interface-name",
          "description",
          "role",
          "mode",
          "interface-role",
          "global",
          "defaultgw",
          "default-route",
          "default-gateway",
          "address",
          "mask",
          "mtu"}) {
        const auto found = entry.find(field);
        if (found != entry.end()) structural[field] = *found;
    }
    return Sha256::hex(structural.dump(
        -1,
        ' ',
        false,
        nlohmann::json::error_handler_t::replace));
}

} // namespace

std::optional<std::string> resolve_ndms_kernel_name(
    const std::string& firmware_interface_name,
    const std::vector<std::string>& runtime_interface_names) {
    if (const auto exact = exact_runtime_interface_name(
            firmware_interface_name,
            runtime_interface_names)) {
        return exact;
    }

    if (!is_numbered_wireguard_name(firmware_interface_name)) {
        return std::nullopt;
    }
    constexpr std::string_view firmware_prefix{"Wireguard"};
    const auto candidate =
        std::string{"nwg"} + firmware_interface_name.substr(firmware_prefix.size());
    if (std::find(
            runtime_interface_names.begin(),
            runtime_interface_names.end(),
            candidate) != runtime_interface_names.end()) {
        return candidate;
    }
    return std::nullopt;
}

NdmsInterfaceCatalog parse_ndms_interface_catalog(
    const nlohmann::json& interfaces) {
    NdmsInterfaceCatalog catalog;
    catalog.names = nlohmann::json::object();
    if (!interfaces.is_object()) return catalog;
    catalog.firmware_available = true;

    std::vector<ParsedEntry> parsed_entries;
    parsed_entries.reserve(interfaces.size());
    for (const auto& [id, entry] : interfaces.items()) {
        if (!entry.is_object()) continue;

        const auto raw_firmware_interface_name =
            string_field(entry, "interface-name");
        const auto firmware_interface_name =
            raw_firmware_interface_name && !raw_firmware_interface_name->empty()
                ? *raw_firmware_interface_name
                : trim_ascii_whitespace(id);
        if (firmware_interface_name.empty()) continue;

        const auto description = string_field(entry, "description");
        const auto firmware_type = string_field(entry, "type");
        const auto kind = classify(entry);
        const auto parsed_role = parse_role(entry);
        const auto role = parsed_role.role;
        const bool wireguard_kind =
            kind &&
            (*kind == NdmsTunnelKind::wireguard ||
             *kind == NdmsTunnelKind::amnezia_wireguard);
        const bool supported_typed_server =
            kind &&
            *kind != NdmsTunnelKind::http_proxy &&
            *kind != NdmsTunnelKind::https_proxy &&
            *kind != NdmsTunnelKind::socks5_proxy;
        const bool wireguard_candidate =
            wireguard_kind &&
            (role == NdmsInterfaceRole::server ||
             (parsed_role.evidence == RoleEvidence::absent &&
              wireguard_server_shape(entry)));
        const bool internal_vpn_server_candidate =
            wireguard_kind
                ? wireguard_candidate
                : supported_typed_server &&
                      role == NdmsInterfaceRole::server;
        parsed_entries.push_back(ParsedEntry{
            id,
            firmware_interface_name,
            description && !description->empty() ? *description : id,
            firmware_type.value_or(std::string{}),
            kind,
            role,
            internal_vpn_server_candidate,
            wireguard_candidate &&
                parsed_role.evidence == RoleEvidence::absent,
            boolean_field(entry, "connected"),
            boolean_field(entry, "link"),
            uptime_seconds_field(entry),
            inventory_revision(entry),
        });
    }

    // The JSON object normally arrives ordered, but make duplicate selection
    // independent of construction order: the lexicographically smallest RCI
    // record id wins a duplicate firmware identity.
    std::sort(
        parsed_entries.begin(),
        parsed_entries.end(),
        [](const auto& left, const auto& right) {
            if (left.id != right.id) return left.id < right.id;
            return left.firmware_interface_name <
                   right.firmware_interface_name;
        });

    for (const auto& parsed : parsed_entries) {
        catalog.interface_metadata.push_back(NdmsInterfaceMetadata{
            parsed.id,
            parsed.firmware_interface_name,
            parsed.label,
            parsed.firmware_type,
            parsed.connected,
            parsed.link,
            parsed.uptime_seconds,
        });
    }

    std::set<std::string> seen_firmware_names;
    for (const auto& parsed : parsed_entries) {
        if (!parsed.kind ||
            !seen_firmware_names.insert(parsed.firmware_interface_name).second) {
            continue;
        }
        catalog.tunnels.push_back(NdmsTunnelInterface{
            parsed.id,
            parsed.firmware_interface_name,
            std::nullopt,
            parsed.label,
            parsed.firmware_type,
            *parsed.kind,
            parsed.role,
            parsed.internal_vpn_server_candidate,
            parsed.internal_vpn_server_role_confirmation_required,
            parsed.connected,
            parsed.link,
            parsed.inventory_revision,
        });
    }

    std::sort(
        catalog.tunnels.begin(),
        catalog.tunnels.end(),
        [](const auto& left, const auto& right) {
            if (left.label != right.label) return left.label < right.label;
            return left.id < right.id;
        });
    return catalog;
}

NdmsInterfaceCatalog resolve_ndms_kernel_names(
    const NdmsInterfaceCatalog& catalog,
    const std::vector<std::string>& runtime_interface_names) {
    auto resolved = catalog;
    resolved.names = nlohmann::json::object();

    auto metadata = catalog.interface_metadata;
    std::sort(
        metadata.begin(),
        metadata.end(),
        [](const auto& left, const auto& right) {
            if (left.id != right.id) return left.id < right.id;
            return left.firmware_interface_name <
                   right.firmware_interface_name;
        });

    std::set<std::string> named_kernel_names;
    std::set<std::string> wireguard_mapping_ids;
    for (const auto& tunnel : catalog.tunnels) {
        if (tunnel.kind == NdmsTunnelKind::wireguard ||
            tunnel.kind == NdmsTunnelKind::amnezia_wireguard) {
            wireguard_mapping_ids.insert(tunnel.id);
        }
    }
    for (const auto& item : metadata) {
        auto kernel_name = exact_runtime_interface_name(
            item.firmware_interface_name,
            runtime_interface_names);
        if (!kernel_name &&
            wireguard_mapping_ids.find(item.id) !=
                wireguard_mapping_ids.end()) {
            kernel_name = resolve_ndms_kernel_name(
                item.firmware_interface_name,
                runtime_interface_names);
        }
        if (!kernel_name ||
            !named_kernel_names.insert(*kernel_name).second) {
            continue;
        }

        nlohmann::json name_entry{
            {"label", item.label},
            {"id", item.id},
            {"firmware_interface_name", item.firmware_interface_name},
            {"type", item.firmware_type},
        };
        if (item.connected) name_entry["connected"] = *item.connected;
        if (item.link) name_entry["link"] = *item.link;
        resolved.names[*kernel_name] = std::move(name_entry);
    }

    auto tunnels = catalog.tunnels;
    std::sort(
        tunnels.begin(),
        tunnels.end(),
        [](const auto& left, const auto& right) {
            if (left.id != right.id) return left.id < right.id;
            return left.firmware_interface_name <
                   right.firmware_interface_name;
        });

    resolved.tunnels.clear();
    std::set<std::string> seen_firmware_names;
    std::set<std::string> seen_kernel_names;
    for (auto& tunnel : tunnels) {
        tunnel.kernel_name = exact_runtime_interface_name(
            tunnel.firmware_interface_name,
            runtime_interface_names);
        if (!tunnel.kernel_name &&
            (tunnel.kind == NdmsTunnelKind::wireguard ||
             tunnel.kind == NdmsTunnelKind::amnezia_wireguard)) {
            tunnel.kernel_name = resolve_ndms_kernel_name(
                tunnel.firmware_interface_name,
                runtime_interface_names);
        }
        if (!seen_firmware_names.insert(tunnel.firmware_interface_name).second) {
            continue;
        }
        if (tunnel.kernel_name &&
            !seen_kernel_names.insert(*tunnel.kernel_name).second) {
            continue;
        }
        resolved.tunnels.push_back(std::move(tunnel));
    }

    std::sort(
        resolved.tunnels.begin(),
        resolved.tunnels.end(),
        [](const auto& left, const auto& right) {
            if (left.label != right.label) return left.label < right.label;
            return left.id < right.id;
        });
    return resolved;
}

NdmsInterfaceCatalog parse_ndms_interface_catalog(
    const nlohmann::json& interfaces,
    const std::vector<std::string>& runtime_interface_names) {
    return resolve_ndms_kernel_names(
        parse_ndms_interface_catalog(interfaces),
        runtime_interface_names);
}

const char* ndms_tunnel_kind_name(NdmsTunnelKind kind) noexcept {
    switch (kind) {
    case NdmsTunnelKind::amnezia_wireguard:
        return "amnezia_wireguard";
    case NdmsTunnelKind::wireguard:
        return "wireguard";
    case NdmsTunnelKind::openvpn:
        return "openvpn";
    case NdmsTunnelKind::ike:
        return "ike";
    case NdmsTunnelKind::l2tp:
        return "l2tp";
    case NdmsTunnelKind::sstp:
        return "sstp";
    case NdmsTunnelKind::openconnect:
        return "openconnect";
    case NdmsTunnelKind::http_proxy:
        return "http_proxy";
    case NdmsTunnelKind::https_proxy:
        return "https_proxy";
    case NdmsTunnelKind::socks5_proxy:
        return "socks5_proxy";
    }
    return "unknown";
}

const char* ndms_interface_role_name(NdmsInterfaceRole role) noexcept {
    switch (role) {
    case NdmsInterfaceRole::client:
        return "client";
    case NdmsInterfaceRole::server:
        return "server";
    case NdmsInterfaceRole::unknown:
        return "unknown";
    }
    return "unknown";
}

} // namespace keen_pbr3
