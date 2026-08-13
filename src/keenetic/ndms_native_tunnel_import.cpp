#include "ndms_native_tunnel_import.hpp"

#include "../config/addr_spec.hpp"
#include "../crypto/sha256.hpp"

#include <arpa/inet.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaximumLines = 4096U;
constexpr std::size_t kMaximumLineBytes = 8192U;
constexpr std::size_t kMaximumInterfaceAddresses = 16U;
constexpr std::size_t kMaximumDnsServers = 8U;
constexpr std::size_t kMaximumPeers = 64U;
constexpr std::size_t kMaximumAllowedIpsPerPeer = 128U;
constexpr std::size_t kMaximumTotalAllowedIps = 512U;
constexpr std::size_t kMaximumEndpointBytes = 512U;
constexpr std::size_t kMaximumAwgHeaderBytes = 256U;
constexpr std::size_t kMaximumAwgSignatureBytes = 4096U;

[[noreturn]] void fail(const NdmsNativeTunnelImportErrorCode code) {
    throw NdmsNativeTunnelImportError(code);
}

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : &value[0];
    for (std::size_t index = 0U;
         bytes != nullptr && index < value.size(); ++index) {
        bytes[index] = '\0';
    }
    value.clear();
}

class WipeStringGuard {
public:
    explicit WipeStringGuard(std::string& value) noexcept
        : value_(value) {}
    ~WipeStringGuard() { secure_wipe(value_); }

    WipeStringGuard(const WipeStringGuard&) = delete;
    WipeStringGuard& operator=(const WipeStringGuard&) = delete;

private:
    std::string& value_;
};

std::string trim_ascii(std::string_view value) {
    std::size_t begin = 0U;
    while (begin < value.size() &&
           std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }
    std::size_t end = value.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(value[end - 1U])) != 0) {
        --end;
    }
    return std::string(value.substr(begin, end - begin));
}

std::string ascii_lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

bool valid_utf8(const std::string& value) {
    for (std::size_t offset = 0U; offset < value.size();) {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::size_t continuation = 0U;
        std::uint32_t codepoint = 0U;
        if (first <= 0x7FU) {
            ++offset;
            continue;
        }
        if ((first & 0xE0U) == 0xC0U) {
            continuation = 1U;
            codepoint = first & 0x1FU;
        } else if ((first & 0xF0U) == 0xE0U) {
            continuation = 2U;
            codepoint = first & 0x0FU;
        } else if ((first & 0xF8U) == 0xF0U) {
            continuation = 3U;
            codepoint = first & 0x07U;
        } else {
            return false;
        }
        if (offset + continuation >= value.size()) return false;
        for (std::size_t index = 1U; index <= continuation; ++index) {
            const auto next =
                static_cast<unsigned char>(value[offset + index]);
            if ((next & 0xC0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (next & 0x3FU);
        }
        if ((continuation == 1U && codepoint < 0x80U) ||
            (continuation == 2U && codepoint < 0x800U) ||
            (continuation == 3U && codepoint < 0x10000U) ||
            codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            return false;
        }
        offset += continuation + 1U;
    }
    return true;
}

bool begins_with_uri_scheme(const std::string& value) {
    const auto separator = value.find("://");
    if (separator == std::string::npos || separator == 0U) return false;
    if (!std::isalpha(static_cast<unsigned char>(value.front()))) return false;
    return std::all_of(
        value.begin(), value.begin() + static_cast<std::ptrdiff_t>(separator),
        [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '+' ||
                   character == '-' || character == '.';
        });
}

std::string strip_inline_comment(const std::string& line) {
    for (std::size_t index = 0U; index < line.size(); ++index) {
        if ((line[index] == '#' || line[index] == ';') &&
            (index == 0U ||
             std::isspace(static_cast<unsigned char>(line[index - 1U])) != 0)) {
            return trim_ascii(std::string_view(line).substr(0U, index));
        }
    }
    return trim_ascii(line);
}

bool valid_field_name(const std::string& value) {
    return !value.empty() && value.size() <= 64U &&
           std::all_of(
               value.begin(), value.end(),
               [](const unsigned char character) {
                   return std::isalnum(character) != 0 || character == '_' ||
                          character == '-';
               });
}

using FieldMap = std::map<std::string, std::string>;

struct ParsedIni {
    FieldMap interface;
    std::vector<FieldMap> peers;

    ParsedIni() = default;
    ~ParsedIni() { wipe_secrets(); }
    ParsedIni(const ParsedIni&) = delete;
    ParsedIni& operator=(const ParsedIni&) = delete;
    ParsedIni(ParsedIni&& other) noexcept
        : interface(std::move(other.interface)),
          peers(std::move(other.peers)) {
        other.wipe_secrets();
    }
    ParsedIni& operator=(ParsedIni&& other) noexcept {
        if (this != &other) {
            wipe_secrets();
            interface = std::move(other.interface);
            peers = std::move(other.peers);
            other.wipe_secrets();
        }
        return *this;
    }

private:
    static void wipe(FieldMap& fields, const char* key) noexcept {
        const auto field = fields.find(key);
        if (field != fields.end()) secure_wipe(field->second);
    }
    void wipe_secrets() noexcept {
        wipe(interface, "privatekey");
        for (auto& peer : peers) wipe(peer, "presharedkey");
    }
};

bool dangerous_directive(const std::string& key) {
    static const std::set<std::string> dangerous{
        "postup", "postdown", "preup", "predown", "table",
        "saveconfig",
    };
    return dangerous.find(key) != dangerous.end();
}

bool allowed_interface_field(const std::string& key) {
    static const std::set<std::string> allowed{
        "address", "listenport", "privatekey", "dns", "mtu",
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    };
    return allowed.find(key) != allowed.end();
}

bool allowed_peer_field(const std::string& key) {
    static const std::set<std::string> allowed{
        "endpoint", "allowedips", "publickey", "presharedkey",
        "persistentkeepalive",
    };
    return allowed.find(key) != allowed.end();
}

ParsedIni parse_ini(std::string input) {
    WipeStringGuard input_guard(input);
    if (input.size() > kNdmsNativeTunnelImportMaximumBytes) {
        fail(NdmsNativeTunnelImportErrorCode::input_too_large);
    }
    if (!valid_utf8(input) || input.find('\0') != std::string::npos) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_encoding);
    }
    if (input.size() >= 3U &&
        static_cast<unsigned char>(input[0]) == 0xEFU &&
        static_cast<unsigned char>(input[1]) == 0xBBU &&
        static_cast<unsigned char>(input[2]) == 0xBFU) {
        // Preserve the allocation's full length so the final wipe reaches
        // every original byte, including a secret at the end of the file.
        input[0] = ' ';
        input[1] = ' ';
        input[2] = ' ';
    }

    enum class Section { none, interface, peer };
    Section section = Section::none;
    bool saw_interface = false;
    ParsedIni parsed;
    std::size_t line_count = 0U;
    std::size_t offset = 0U;

    while (offset <= input.size()) {
        if (++line_count > kMaximumLines) {
            fail(NdmsNativeTunnelImportErrorCode::limit_exceeded);
        }
        const auto newline = input.find('\n', offset);
        const auto length = newline == std::string::npos
            ? input.size() - offset
            : newline - offset;
        if (length > kMaximumLineBytes) {
            fail(NdmsNativeTunnelImportErrorCode::limit_exceeded);
        }
        std::string raw_line = input.substr(offset, length);
        WipeStringGuard raw_line_guard(raw_line);
        if (!raw_line.empty() && raw_line.back() == '\r') {
            raw_line.pop_back();
        }
        std::string line = strip_inline_comment(raw_line);
        WipeStringGuard line_guard(line);

        if (!line.empty()) {
            if (line.front() == '[' || line.back() == ']') {
                if (line.size() < 3U || line.front() != '[' ||
                    line.back() != ']') {
                    fail(NdmsNativeTunnelImportErrorCode::malformed_line);
                }
                const auto name = ascii_lower(trim_ascii(
                    std::string_view(line).substr(1U, line.size() - 2U)));
                if (name == "interface") {
                    if (saw_interface) {
                        fail(NdmsNativeTunnelImportErrorCode::duplicate_section);
                    }
                    if (!parsed.peers.empty()) {
                        fail(NdmsNativeTunnelImportErrorCode::malformed_line);
                    }
                    saw_interface = true;
                    section = Section::interface;
                } else if (name == "peer") {
                    if (!saw_interface) {
                        fail(NdmsNativeTunnelImportErrorCode::malformed_line);
                    }
                    if (parsed.peers.size() >= kMaximumPeers) {
                        fail(NdmsNativeTunnelImportErrorCode::limit_exceeded);
                    }
                    parsed.peers.emplace_back();
                    section = Section::peer;
                } else {
                    fail(NdmsNativeTunnelImportErrorCode::unknown_section);
                }
            } else {
                if (section == Section::none) {
                    fail(NdmsNativeTunnelImportErrorCode::malformed_line);
                }
                const auto equals = line.find('=');
                // Values can legitimately contain '=' (canonical WireGuard
                // base64 keys end with it), so only the first separator is
                // structural.
                if (equals == std::string::npos) {
                    fail(NdmsNativeTunnelImportErrorCode::malformed_line);
                }
                const auto raw_key = trim_ascii(
                    std::string_view(line).substr(0U, equals));
                if (!valid_field_name(raw_key)) {
                    fail(NdmsNativeTunnelImportErrorCode::malformed_line);
                }
                const auto key = ascii_lower(raw_key);
                if (dangerous_directive(key)) {
                    fail(NdmsNativeTunnelImportErrorCode::dangerous_directive);
                }
                if ((section == Section::interface &&
                     !allowed_interface_field(key)) ||
                    (section == Section::peer && !allowed_peer_field(key))) {
                    fail(NdmsNativeTunnelImportErrorCode::unknown_field);
                }
                auto value = trim_ascii(
                    std::string_view(line).substr(equals + 1U));
                WipeStringGuard value_guard(value);
                if (value.size() > kMaximumLineBytes) {
                    fail(NdmsNativeTunnelImportErrorCode::limit_exceeded);
                }
                auto& fields = section == Section::interface
                    ? parsed.interface
                    : parsed.peers.back();
                // Unlike emplace, try_emplace does not move the mapped
                // argument when the key already exists. That leaves a
                // duplicate secret in value for value_guard to erase.
                if (!fields.try_emplace(key, std::move(value)).second) {
                    fail(NdmsNativeTunnelImportErrorCode::duplicate_field);
                }
            }
        }

        if (newline == std::string::npos) break;
        offset = newline + 1U;
    }
    if (!saw_interface) {
        fail(NdmsNativeTunnelImportErrorCode::missing_required_field);
    }
    return parsed;
}

const std::string& required_field(
    const FieldMap& fields, const char* key) {
    const auto value = fields.find(key);
    if (value == fields.end() || value->second.empty()) {
        fail(NdmsNativeTunnelImportErrorCode::missing_required_field);
    }
    return value->second;
}

std::optional<std::string> optional_nonempty_field(
    const FieldMap& fields, const char* key) {
    const auto value = fields.find(key);
    if (value == fields.end()) return std::nullopt;
    if (value->second.empty()) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }
    return value->second;
}

std::uint32_t parse_decimal(
    const std::string& value,
    const std::uint32_t minimum,
    const std::uint32_t maximum) {
    if (value.empty()) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }
    std::uint32_t parsed = 0U;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        parsed < minimum || parsed > maximum) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }
    return parsed;
}

std::vector<std::string> parse_cidr_list(
    const std::string& value, const std::size_t maximum) {
    std::vector<std::string> result;
    std::size_t offset = 0U;
    while (offset <= value.size()) {
        const auto comma = value.find(',', offset);
        auto item = trim_ascii(std::string_view(value).substr(
            offset,
            comma == std::string::npos ? std::string::npos : comma - offset));
        if (item.empty() || result.size() >= maximum) {
            fail(item.empty()
                     ? NdmsNativeTunnelImportErrorCode::invalid_field
                     : NdmsNativeTunnelImportErrorCode::limit_exceeded);
        }
        try {
            validate_cidr(item);
        } catch (const std::invalid_argument&) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
        result.push_back(std::move(item));
        if (comma == std::string::npos) break;
        offset = comma + 1U;
    }
    return result;
}

bool valid_ip_address(const std::string& value) {
    std::array<unsigned char, 16> bytes{};
    return inet_pton(AF_INET, value.c_str(), bytes.data()) == 1 ||
           inet_pton(AF_INET6, value.c_str(), bytes.data()) == 1;
}

std::vector<std::string> parse_dns_list(const std::string& value) {
    std::vector<std::string> result;
    std::size_t offset = 0U;
    while (offset <= value.size()) {
        const auto comma = value.find(',', offset);
        auto item = trim_ascii(std::string_view(value).substr(
            offset,
            comma == std::string::npos ? std::string::npos : comma - offset));
        if (item.empty() || !valid_ip_address(item)) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
        if (result.size() >= kMaximumDnsServers) {
            fail(NdmsNativeTunnelImportErrorCode::limit_exceeded);
        }
        result.push_back(std::move(item));
        if (comma == std::string::npos) break;
        offset = comma + 1U;
    }
    return result;
}

void validate_wireguard_key(const std::string& value) {
    if (value.size() != 44U) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }
    const auto base64_character = [](const unsigned char character) {
        return (character >= 'A' && character <= 'Z') ||
               (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') ||
               character == '+' || character == '/';
    };
    // A 32-byte input has 42 unconstrained base64 sextets, then one sextet
    // whose low two bits must be zero, followed by exactly one '='. These
    // checks are therefore a complete canonical validation and avoid ever
    // materialising decoded private/PSK bytes in a generic codec stack.
    if (!std::all_of(
            value.begin(), value.begin() + 42,
            base64_character) ||
        std::string_view{"AEIMQUYcgkosw048"}.find(value[42]) ==
            std::string_view::npos ||
        value[43] != '=') {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }
}

bool valid_hostname(const std::string& value) {
    if (value.empty() || value.size() > 253U) return false;
    std::string hostname = value;
    if (!hostname.empty() && hostname.back() == '.') hostname.pop_back();
    if (hostname.empty()) return false;
    std::size_t offset = 0U;
    while (offset <= hostname.size()) {
        const auto dot = hostname.find('.', offset);
        const auto length = dot == std::string::npos
            ? hostname.size() - offset
            : dot - offset;
        if (length == 0U || length > 63U) return false;
        const auto label = std::string_view(hostname).substr(offset, length);
        if (label.front() == '-' || label.back() == '-' ||
            !std::all_of(
                label.begin(), label.end(),
                [](const unsigned char character) {
                    return std::isalnum(character) != 0 || character == '-';
                })) {
            return false;
        }
        if (dot == std::string::npos) break;
        offset = dot + 1U;
    }
    return true;
}

struct ParsedEndpoint {
    std::string host;
    std::uint16_t port{0};
};

ParsedEndpoint parse_endpoint(const std::string& value) {
    if (value.empty() || value.size() > kMaximumEndpointBytes ||
        std::any_of(
            value.begin(), value.end(),
            [](const unsigned char character) {
                return std::isspace(character) != 0 || character < 0x20U;
            })) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }

    std::string host;
    std::string port;
    if (value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string::npos || close + 2U > value.size() ||
            value[close + 1U] != ':') {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
        host = value.substr(1U, close - 1U);
        port = value.substr(close + 2U);
        std::array<unsigned char, 16> bytes{};
        if (inet_pton(AF_INET6, host.c_str(), bytes.data()) != 1) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
    } else {
        const auto colon = value.rfind(':');
        if (colon == std::string::npos || colon == 0U ||
            value.find(':') != colon) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
        host = value.substr(0U, colon);
        port = value.substr(colon + 1U);
        if (!valid_ip_address(host) && !valid_hostname(host)) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
    }
    const auto parsed_port = parse_decimal(port, 1U, 65535U);
    return {std::move(host), static_cast<std::uint16_t>(parsed_port)};
}

std::string take_secret_field(FieldMap& fields, const char* key) {
    auto field = fields.find(key);
    if (field == fields.end() || field->second.empty()) {
        fail(NdmsNativeTunnelImportErrorCode::missing_required_field);
    }
    validate_wireguard_key(field->second);
    auto value = std::move(field->second);
    secure_wipe(field->second);
    return value;
}

std::optional<NdmsNativeTunnelImportAwgParameters> parse_awg(
    const FieldMap& fields) {
    static const std::array<const char*, 22> names{
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
        // Padding keeps the array declaration visually grouped; empty entries
        // are ignored below and are not accepted as fields.
        "", "", "", "", "", "",
    };
    const bool present = std::any_of(
        names.begin(), names.end(),
        [&](const char* name) {
            return *name != '\0' && fields.find(name) != fields.end();
        });
    if (!present) return std::nullopt;

    const auto numeric = [&](const char* name) {
        return parse_decimal(required_field(fields, name), 0U,
                             std::numeric_limits<std::uint32_t>::max());
    };
    const auto text = [&](const char* name, const std::size_t maximum,
                          const bool allow_empty) {
        const auto field = fields.find(name);
        if (field == fields.end()) {
            fail(NdmsNativeTunnelImportErrorCode::missing_required_field);
        }
        if ((!allow_empty && field->second.empty()) ||
            field->second.size() > maximum) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
        return field->second;
    };
    const auto optional_numeric = [&](const char* name)
        -> std::optional<std::uint32_t> {
        const auto field = fields.find(name);
        if (field == fields.end()) return std::nullopt;
        return parse_decimal(
            field->second, 0U,
            std::numeric_limits<std::uint32_t>::max());
    };
    const auto optional_text = [&](const char* name)
        -> std::optional<std::string> {
        const auto field = fields.find(name);
        if (field == fields.end()) return std::nullopt;
        if (field->second.size() > kMaximumAwgSignatureBytes) {
            fail(NdmsNativeTunnelImportErrorCode::invalid_field);
        }
        return field->second;
    };

    NdmsNativeTunnelImportAwgParameters awg;
    awg.jc = numeric("jc");
    awg.jmin = numeric("jmin");
    awg.jmax = numeric("jmax");
    awg.s1 = numeric("s1");
    awg.s2 = numeric("s2");
    awg.s3 = optional_numeric("s3");
    awg.s4 = optional_numeric("s4");
    awg.h1 = text("h1", kMaximumAwgHeaderBytes, true);
    awg.h2 = text("h2", kMaximumAwgHeaderBytes, true);
    awg.h3 = text("h3", kMaximumAwgHeaderBytes, true);
    awg.h4 = text("h4", kMaximumAwgHeaderBytes, true);
    awg.i1 = optional_text("i1");
    awg.i2 = optional_text("i2");
    awg.i3 = optional_text("i3");
    awg.i4 = optional_text("i4");
    awg.i5 = optional_text("i5");

    if (awg.s3.has_value() != awg.s4.has_value()) {
        fail(NdmsNativeTunnelImportErrorCode::missing_required_field);
    }
    const bool disabled =
        awg.jc == 0U && awg.jmin == 0U && awg.jmax == 0U &&
        awg.s1 == 0U && awg.s2 == 0U && awg.h1.empty() &&
        awg.h2.empty() && awg.h3.empty() && awg.h4.empty();
    if (!disabled &&
        (awg.jc == 0U || awg.jmin == 0U || awg.jmax <= awg.jmin ||
         awg.s1 == 0U || awg.s2 == 0U || awg.h1.empty() ||
         awg.h2.empty() || awg.h3.empty() || awg.h4.empty())) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_field);
    }
    return awg;
}

NdmsNativeTunnelImport parse_conf(
    std::string input, const NdmsNativeTunnelImportSource source) {
    auto parsed = parse_ini(std::move(input));

    auto addresses = parse_cidr_list(
        required_field(parsed.interface, "address"),
        kMaximumInterfaceAddresses);
    std::vector<std::string> dns;
    if (const auto value = optional_nonempty_field(parsed.interface, "dns")) {
        dns = parse_dns_list(*value);
    }
    std::optional<std::uint16_t> listen_port;
    if (const auto value =
            optional_nonempty_field(parsed.interface, "listenport")) {
        listen_port = static_cast<std::uint16_t>(
            parse_decimal(*value, 0U, 65535U));
    }
    std::optional<std::uint32_t> mtu;
    if (const auto value = optional_nonempty_field(parsed.interface, "mtu")) {
        mtu = parse_decimal(*value, 576U, 65535U);
    }

    auto private_key_raw = take_secret_field(parsed.interface, "privatekey");
    NdmsNativeTunnelImportSecret private_key(std::move(private_key_raw));
    secure_wipe(private_key_raw);

    auto awg = parse_awg(parsed.interface);
    if (parsed.peers.empty()) {
        fail(NdmsNativeTunnelImportErrorCode::missing_required_field);
    }
    std::vector<NdmsNativeTunnelImportPeer> peers;
    peers.reserve(parsed.peers.size());
    std::size_t total_allowed_ips = 0U;
    for (auto& fields : parsed.peers) {
        const auto& public_key = required_field(fields, "publickey");
        validate_wireguard_key(public_key);
        auto allowed_ips = parse_cidr_list(
            required_field(fields, "allowedips"),
            kMaximumAllowedIpsPerPeer);
        total_allowed_ips += allowed_ips.size();
        if (total_allowed_ips > kMaximumTotalAllowedIps) {
            fail(NdmsNativeTunnelImportErrorCode::limit_exceeded);
        }
        const auto& endpoint_value = required_field(fields, "endpoint");
        auto endpoint = parse_endpoint(endpoint_value);

        std::optional<NdmsNativeTunnelImportSecret> preshared_key;
        if (fields.find("presharedkey") != fields.end()) {
            auto raw = take_secret_field(fields, "presharedkey");
            preshared_key.emplace(std::move(raw));
            secure_wipe(raw);
        }
        std::optional<std::uint16_t> persistent_keepalive;
        if (const auto value = optional_nonempty_field(
                fields, "persistentkeepalive")) {
            persistent_keepalive = static_cast<std::uint16_t>(
                parse_decimal(*value, 0U, 65535U));
        }
        peers.push_back(NdmsNativeTunnelImportPeer{
            public_key,
            std::move(preshared_key),
            endpoint_value,
            std::move(endpoint.host),
            endpoint.port,
            std::move(allowed_ips),
            persistent_keepalive,
        });
    }

    return NdmsNativeTunnelImport{
        source,
        awg ? NdmsNativeTunnelImportKind::amnezia_wireguard
            : NdmsNativeTunnelImportKind::wireguard,
        std::move(addresses),
        std::move(dns),
        listen_port,
        mtu,
        std::move(private_key),
        std::move(awg),
        std::move(peers),
    };
}

nlohmann::json optional_string_json(
    const std::optional<std::string>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

std::string build_revision(const NdmsNativeTunnelImport& input) {
    nlohmann::json canonical{
        {"schema", "ndms-native-import-v1"},
        {"kind", ndms_native_tunnel_import_kind_name(input.kind)},
        {"addresses", input.addresses},
        {"dns_servers", input.dns_servers},
        {"listen_port", input.listen_port
             ? nlohmann::json(*input.listen_port)
             : nlohmann::json(nullptr)},
        {"mtu", input.mtu ? nlohmann::json(*input.mtu)
                           : nlohmann::json(nullptr)},
        {"private_key_sha256", input.private_key.sha256()},
    };
    if (input.awg) {
        const auto& awg = *input.awg;
        canonical["awg"] = {
            {"jc", awg.jc}, {"jmin", awg.jmin}, {"jmax", awg.jmax},
            {"s1", awg.s1}, {"s2", awg.s2},
            {"s3", awg.s3 ? nlohmann::json(*awg.s3)
                            : nlohmann::json(nullptr)},
            {"s4", awg.s4 ? nlohmann::json(*awg.s4)
                            : nlohmann::json(nullptr)},
            {"h1", awg.h1}, {"h2", awg.h2}, {"h3", awg.h3},
            {"h4", awg.h4},
            {"i1", optional_string_json(awg.i1)},
            {"i2", optional_string_json(awg.i2)},
            {"i3", optional_string_json(awg.i3)},
            {"i4", optional_string_json(awg.i4)},
            {"i5", optional_string_json(awg.i5)},
        };
    } else {
        canonical["awg"] = nullptr;
    }
    canonical["peers"] = nlohmann::json::array();
    for (const auto& peer : input.peers) {
        canonical["peers"].push_back({
            {"public_key", peer.public_key},
            {"preshared_key_sha256",
             peer.preshared_key
                 ? nlohmann::json(peer.preshared_key->sha256())
                 : nlohmann::json(nullptr)},
            {"endpoint", peer.endpoint},
            {"allowed_ips", peer.allowed_ips},
            {"persistent_keepalive",
             peer.persistent_keepalive
                 ? nlohmann::json(*peer.persistent_keepalive)
                 : nlohmann::json(nullptr)},
        });
    }
    return "ndms-native-import-v1-" + Sha256::hex(canonical.dump());
}

} // namespace

const char* ndms_native_tunnel_import_error_code_name(
    const NdmsNativeTunnelImportErrorCode code) noexcept {
    switch (code) {
    case NdmsNativeTunnelImportErrorCode::input_too_large:
        return "input_too_large";
    case NdmsNativeTunnelImportErrorCode::invalid_encoding:
        return "invalid_encoding";
    case NdmsNativeTunnelImportErrorCode::unsupported_uri:
        return "unsupported_uri";
    case NdmsNativeTunnelImportErrorCode::invalid_base64:
        return "invalid_base64";
    case NdmsNativeTunnelImportErrorCode::invalid_compression:
        return "invalid_compression";
    case NdmsNativeTunnelImportErrorCode::invalid_json:
        return "invalid_json";
    case NdmsNativeTunnelImportErrorCode::unsupported_json_schema:
        return "unsupported_json_schema";
    case NdmsNativeTunnelImportErrorCode::malformed_line:
        return "malformed_line";
    case NdmsNativeTunnelImportErrorCode::unknown_section:
        return "unknown_section";
    case NdmsNativeTunnelImportErrorCode::duplicate_section:
        return "duplicate_section";
    case NdmsNativeTunnelImportErrorCode::duplicate_field:
        return "duplicate_field";
    case NdmsNativeTunnelImportErrorCode::unknown_field:
        return "unknown_field";
    case NdmsNativeTunnelImportErrorCode::dangerous_directive:
        return "dangerous_directive";
    case NdmsNativeTunnelImportErrorCode::missing_required_field:
        return "missing_required_field";
    case NdmsNativeTunnelImportErrorCode::invalid_field:
        return "invalid_field";
    case NdmsNativeTunnelImportErrorCode::limit_exceeded:
        return "limit_exceeded";
    }
    return "invalid_field";
}

NdmsNativeTunnelImportError::NdmsNativeTunnelImportError(
    const NdmsNativeTunnelImportErrorCode code)
    : std::runtime_error(
          std::string("native tunnel import rejected: ") +
          ndms_native_tunnel_import_error_code_name(code)),
      code_(code) {}

NdmsNativeTunnelImportErrorCode
NdmsNativeTunnelImportError::code() const noexcept {
    return code_;
}

NdmsNativeTunnelImportSecret::NdmsNativeTunnelImportSecret(
    std::string value)
    : value_(std::move(value)) {}

NdmsNativeTunnelImportSecret::~NdmsNativeTunnelImportSecret() {
    wipe();
}

NdmsNativeTunnelImportSecret::NdmsNativeTunnelImportSecret(
    NdmsNativeTunnelImportSecret&& other) noexcept {
    value_.swap(other.value_);
}

NdmsNativeTunnelImportSecret&
NdmsNativeTunnelImportSecret::operator=(
    NdmsNativeTunnelImportSecret&& other) noexcept {
    if (this != &other) {
        wipe();
        value_.swap(other.value_);
    }
    return *this;
}

const std::string&
NdmsNativeTunnelImportSecret::reveal_for_typed_rci() const noexcept {
    return value_;
}

std::string NdmsNativeTunnelImportSecret::sha256() const {
    return Sha256::hex(value_);
}

void NdmsNativeTunnelImportSecret::wipe() noexcept {
    secure_wipe(value_);
}

const char* ndms_native_tunnel_import_kind_name(
    const NdmsNativeTunnelImportKind kind) noexcept {
    switch (kind) {
    case NdmsNativeTunnelImportKind::wireguard:
        return "wireguard";
    case NdmsNativeTunnelImportKind::amnezia_wireguard:
        return "amnezia_wireguard";
    }
    return "wireguard";
}

NdmsNativeTunnelImport parse_ndms_native_tunnel_import(
    std::string input) {
    if (input.size() > kNdmsNativeTunnelImportMaximumBytes) {
        secure_wipe(input);
        fail(NdmsNativeTunnelImportErrorCode::input_too_large);
    }
    WipeStringGuard input_guard(input);
    if (!valid_utf8(input) || input.find('\0') != std::string::npos) {
        fail(NdmsNativeTunnelImportErrorCode::invalid_encoding);
    }
    auto trimmed = trim_ascii(input);
    WipeStringGuard trimmed_guard(trimmed);
    if (trimmed.rfind("vpn://", 0U) == 0U) {
        // nlohmann's AllocatorType cannot cover its lexer: raw token_string is
        // a hard-coded std::vector<char>, while error token/exception copies
        // are hard-coded std::string. Both may contain a complete nested
        // config and are freed without wiping. Keep vpn:// disabled rather
        // than advertise an allocator guarantee the lexer cannot provide.
        fail(NdmsNativeTunnelImportErrorCode::unsupported_uri);
    }
    if (begins_with_uri_scheme(trimmed)) {
        fail(NdmsNativeTunnelImportErrorCode::unsupported_uri);
    }
    return parse_conf(trimmed,
                      NdmsNativeTunnelImportSource::wireguard_conf);
}

NdmsNativeTunnelImportPreview
build_ndms_native_tunnel_import_preview(
    const NdmsNativeTunnelImport& input) {
    NdmsNativeTunnelImportPreview preview;
    preview.kind = input.kind;
    preview.address_count = input.addresses.size();
    preview.dns_count = input.dns_servers.size();
    preview.peer_count = input.peers.size();
    preview.has_private_key = true;
    for (const auto& peer : input.peers) {
        preview.allowed_ip_count += peer.allowed_ips.size();
        if (peer.preshared_key) ++preview.preshared_key_count;
    }
    if (input.peers.size() == 1U) {
        preview.endpoint_host = input.peers.front().endpoint_host;
        preview.endpoint_port = input.peers.front().endpoint_port;
        preview.persistent_keepalive =
            input.peers.front().persistent_keepalive;
    }
    if (input.awg) {
        preview.amnezia_parameter_names = {
            "Jc", "Jmin", "Jmax", "S1", "S2",
            "H1", "H2", "H3", "H4",
        };
        if (input.awg->s3) preview.amnezia_parameter_names.push_back("S3");
        if (input.awg->s4) preview.amnezia_parameter_names.push_back("S4");
        if (input.awg->i1) preview.amnezia_parameter_names.push_back("I1");
        if (input.awg->i2) preview.amnezia_parameter_names.push_back("I2");
        if (input.awg->i3) preview.amnezia_parameter_names.push_back("I3");
        if (input.awg->i4) preview.amnezia_parameter_names.push_back("I4");
        if (input.awg->i5) preview.amnezia_parameter_names.push_back("I5");
    }
    preview.revision = build_revision(input);
    return preview;
}

} // namespace keen_pbr3
