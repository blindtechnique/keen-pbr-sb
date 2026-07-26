#include "ndms_rci_restorable_snapshot.hpp"

#include "../config/addr_spec.hpp"
#include "../crypto/sha256.hpp"
#include "../util/base64.hpp"

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

constexpr std::size_t kMaximumResponseBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaximumDescriptionBytes = 512U;
constexpr std::size_t kMaximumAddresses = 64U;
constexpr std::size_t kMaximumPeers = 256U;
constexpr std::size_t kMaximumAllowedIps = 128U;
constexpr std::size_t kMaximumEndpointBytes = 512U;
constexpr std::size_t kMaximumAscHeaderBytes = 256U;
constexpr std::size_t kMaximumAscSignatureBytes = 4096U;
constexpr std::size_t kMaximumEnvelopeDepth = 16U;

[[noreturn]] void fail(const char* message) {
    throw NdmsRciRestorableSnapshotError(message);
}

std::string trim_ascii_whitespace(std::string_view value) {
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

bool safe_interface_id(const std::string& value) {
    return !value.empty() && value.size() <= 64U &&
           std::all_of(
               value.begin(),
               value.end(),
               [](const unsigned char character) {
                   return std::isalnum(character) != 0 ||
                          character == '_' || character == '-' ||
                          character == '.';
               });
}

bool valid_utf8(const std::string& value) {
    for (std::size_t offset = 0U; offset < value.size();) {
        const auto first =
            static_cast<unsigned char>(value[offset]);
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

bool json_content_type(const std::string& raw_content_type) {
    auto content_type = trim_ascii_whitespace(raw_content_type);
    std::transform(
        content_type.begin(),
        content_type.end(),
        content_type.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    const auto parameters = content_type.find(';');
    if (parameters != std::string::npos) {
        content_type =
            trim_ascii_whitespace(content_type.substr(0U, parameters));
    }
    if (content_type == "application/json") return true;
    constexpr std::string_view suffix{"+json"};
    return content_type.size() > suffix.size() &&
           content_type.compare(
               content_type.size() - suffix.size(),
               suffix.size(),
               suffix) == 0;
}

bool non_empty_error_value(const nlohmann::json& value) {
    if (value.is_null()) return false;
    if (value.is_boolean()) return value.get<bool>();
    if (value.is_number_integer()) return value.get<std::int64_t>() != 0;
    if (value.is_number_unsigned()) return value.get<std::uint64_t>() != 0U;
    if (value.is_string()) {
        return !trim_ascii_whitespace(
                    value.get_ref<const std::string&>())
                    .empty();
    }
    return !value.empty();
}

bool success_status_token(const std::string& value) {
    auto token = trim_ascii_whitespace(value);
    std::transform(
        token.begin(),
        token.end(),
        token.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return token == "ok" || token == "success" ||
           token == "succeeded" || token == "done" ||
           token == "completed";
}

bool failure_status_token(const std::string& value) {
    auto token = trim_ascii_whitespace(value);
    std::transform(
        token.begin(),
        token.end(),
        token.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return token == "error" || token == "failed" ||
           token == "failure" || token == "denied" ||
           token == "invalid";
}

void validate_status_value(
    const nlohmann::json& value,
    std::size_t depth);

void validate_status_record(
    const nlohmann::json& record,
    const std::size_t depth) {
    if (depth > kMaximumEnvelopeDepth) {
        fail("NDMS RCI snapshot response is too deeply nested");
    }
    if (!record.is_object()) {
        fail("NDMS RCI snapshot status entry is not an object");
    }

    for (const auto* key : {"error", "errors"}) {
        const auto error = record.find(key);
        if (error != record.end() &&
            non_empty_error_value(*error)) {
            fail("NDMS RCI snapshot request reported an error");
        }
    }

    bool has_result = false;
    for (const auto* key : {"status", "result"}) {
        const auto result = record.find(key);
        if (result == record.end()) continue;
        has_result = true;
        validate_status_value(*result, depth + 1U);
    }

    const auto code = record.find("code");
    if (code != record.end()) {
        has_result = true;
        if (code->is_number_integer()) {
            if (code->get<std::int64_t>() != 0) {
                fail("NDMS RCI snapshot returned a failing result code");
            }
        } else if (code->is_number_unsigned()) {
            if (code->get<std::uint64_t>() != 0U) {
                fail("NDMS RCI snapshot returned a failing result code");
            }
        } else {
            fail("NDMS RCI snapshot result code has an invalid type");
        }
    }
    if (!has_result) {
        fail("NDMS RCI snapshot status entry has no result");
    }
}

void validate_status_value(
    const nlohmann::json& value,
    const std::size_t depth) {
    if (depth > kMaximumEnvelopeDepth) {
        fail("NDMS RCI snapshot response is too deeply nested");
    }
    if (value.is_array()) {
        if (value.empty()) {
            fail("NDMS RCI snapshot status array is empty");
        }
        for (const auto& record : value) {
            validate_status_record(record, depth + 1U);
        }
        return;
    }
    if (value.is_object()) {
        validate_status_record(value, depth + 1U);
        return;
    }
    if (value.is_string()) {
        const auto& token =
            value.get_ref<const std::string&>();
        if (failure_status_token(token)) {
            fail("NDMS RCI snapshot request reported a failed status");
        }
        if (!success_status_token(token)) {
            fail("NDMS RCI snapshot returned an unknown status token");
        }
        return;
    }
    if (value.is_number_integer()) {
        if (value.get<std::int64_t>() != 0) {
            fail("NDMS RCI snapshot returned a failing status code");
        }
        return;
    }
    if (value.is_number_unsigned()) {
        if (value.get<std::uint64_t>() != 0U) {
            fail("NDMS RCI snapshot returned a failing status code");
        }
        return;
    }
    fail("NDMS RCI snapshot status has an invalid type");
}

void reject_nested_failures(
    const nlohmann::json& value,
    const std::size_t depth = 0U) {
    if (depth > kMaximumEnvelopeDepth) {
        fail("NDMS RCI snapshot response is too deeply nested");
    }
    if (value.is_array()) {
        for (const auto& item : value) {
            reject_nested_failures(item, depth + 1U);
        }
        return;
    }
    if (!value.is_object()) return;

    for (const auto* key : {"error", "errors"}) {
        const auto field = value.find(key);
        if (field != value.end() && non_empty_error_value(*field)) {
            fail("NDMS RCI snapshot request reported an error");
        }
    }
    const auto status = value.find("status");
    if (status != value.end()) {
        validate_status_value(*status, depth + 1U);
    }
    const auto code = value.find("code");
    if (code != value.end()) {
        if (code->is_number_integer()) {
            if (code->get<std::int64_t>() != 0) {
                fail("NDMS RCI snapshot returned a failing result code");
            }
        } else if (code->is_number_unsigned()) {
            if (code->get<std::uint64_t>() != 0U) {
                fail("NDMS RCI snapshot returned a failing result code");
            }
        } else {
            fail("NDMS RCI snapshot result code has an invalid type");
        }
    }
    for (auto field = value.begin(); field != value.end(); ++field) {
        if (field.key() == "status" ||
            field.key() == "code" ||
            field.key() == "error" ||
            field.key() == "errors") {
            continue;
        }
        reject_nested_failures(field.value(), depth + 1U);
    }
}

nlohmann::json parse_document(
    const NdmsRciSnapshotDocument& source,
    const std::string& expected_firmware_name) {
    if (!safe_interface_id(source.firmware_interface_name) ||
        source.firmware_interface_name != expected_firmware_name) {
        fail("NDMS RCI snapshot source identity does not match the requested interface");
    }
    if (source.response.status_code != 200) {
        fail("NDMS RCI snapshot request did not return HTTP 200");
    }
    if (!json_content_type(source.response.content_type)) {
        fail("NDMS RCI snapshot response is not JSON");
    }
    if (source.response.body.empty() ||
        source.response.body.size() > kMaximumResponseBytes) {
        fail("NDMS RCI snapshot response size is invalid");
    }

    nlohmann::json document;
    try {
        document = nlohmann::json::parse(source.response.body);
    } catch (...) {
        fail("NDMS RCI snapshot response contains invalid JSON");
    }
    if (!document.is_object()) {
        fail("NDMS RCI snapshot document is not an object");
    }
    reject_nested_failures(document);
    return document;
}

void validate_optional_rc_identity(
    const nlohmann::json& document,
    const NdmsTunnelInterface& expected) {
    const auto check = [&](const char* key,
                           const std::string& expected_value) {
        const auto field = document.find(key);
        if (field == document.end()) return;
        if (!field->is_string() ||
            trim_ascii_whitespace(
                field->get_ref<const std::string&>()) != expected_value) {
            fail("NDMS RCI snapshot document identity is invalid");
        }
    };
    check("id", expected.id);
    check(
        "name",
        expected.firmware_interface_name.empty()
            ? expected.id
            : expected.firmware_interface_name);
}

std::uint32_t parse_decimal(
    const std::string& raw,
    const char* error_message) {
    if (raw.empty() ||
        !std::all_of(
            raw.begin(),
            raw.end(),
            [](const unsigned char character) {
                return std::isdigit(character) != 0;
            })) {
        fail(error_message);
    }
    std::uint32_t value = 0U;
    const auto [end, error] = std::from_chars(
        raw.data(),
        raw.data() + raw.size(),
        value);
    if (error != std::errc{} || end != raw.data() + raw.size()) {
        fail(error_message);
    }
    return value;
}

std::uint32_t parse_json_uint(
    const nlohmann::json& value,
    const std::uint32_t maximum,
    const char* error_message) {
    std::uint64_t parsed = 0U;
    if (value.is_number_unsigned()) {
        parsed = value.get<std::uint64_t>();
    } else if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value < 0) fail(error_message);
        parsed = static_cast<std::uint64_t>(signed_value);
    } else {
        fail(error_message);
    }
    if (parsed > maximum) fail(error_message);
    return static_cast<std::uint32_t>(parsed);
}

std::string canonical_wireguard_key(
    const std::string& raw,
    const char* error_message) {
    const auto key = trim_ascii_whitespace(raw);
    if (key.size() != 44U) fail(error_message);
    try {
        const auto decoded = base64_decode(key);
        if (decoded.size() != 32U || base64_encode(decoded) != key) {
            fail(error_message);
        }
    } catch (const NdmsRciRestorableSnapshotError&) {
        throw;
    } catch (...) {
        fail(error_message);
    }
    return key;
}

std::string canonical_ip(
    const std::string& raw,
    int& family,
    const char* error_message) {
    std::array<unsigned char, 16U> bytes{};
    char output[INET6_ADDRSTRLEN]{};
    if (inet_pton(AF_INET, raw.c_str(), bytes.data()) == 1) {
        family = AF_INET;
    } else if (inet_pton(AF_INET6, raw.c_str(), bytes.data()) == 1) {
        family = AF_INET6;
    } else {
        fail(error_message);
    }
    if (inet_ntop(family, bytes.data(), output, sizeof(output)) == nullptr) {
        fail(error_message);
    }
    return output;
}

std::uint32_t dotted_ipv4_prefix(
    const std::string& raw,
    const char* error_message) {
    std::array<unsigned char, 4U> bytes{};
    if (inet_pton(AF_INET, raw.c_str(), bytes.data()) != 1) {
        fail(error_message);
    }
    std::uint32_t mask =
        (static_cast<std::uint32_t>(bytes[0]) << 24U) |
        (static_cast<std::uint32_t>(bytes[1]) << 16U) |
        (static_cast<std::uint32_t>(bytes[2]) << 8U) |
        static_cast<std::uint32_t>(bytes[3]);
    bool saw_zero = false;
    std::uint32_t prefix = 0U;
    for (int bit = 31; bit >= 0; --bit) {
        const bool set = (mask & (1U << bit)) != 0U;
        if (!set) {
            saw_zero = true;
        } else if (saw_zero) {
            fail(error_message);
        } else {
            ++prefix;
        }
    }
    return prefix;
}

std::string parse_address_mask(
    const nlohmann::json& value,
    const char* error_message) {
    if (!value.is_object()) fail(error_message);
    const auto address = value.find("address");
    const auto mask = value.find("mask");
    if (address == value.end() || !address->is_string() ||
        mask == value.end() || !mask->is_string()) {
        fail(error_message);
    }
    const auto raw_address =
        trim_ascii_whitespace(address->get_ref<const std::string&>());
    const auto raw_mask =
        trim_ascii_whitespace(mask->get_ref<const std::string&>());
    int family = AF_UNSPEC;
    const auto normalized =
        canonical_ip(raw_address, family, error_message);

    std::uint32_t prefix = 0U;
    const bool numeric =
        !raw_mask.empty() &&
        std::all_of(
            raw_mask.begin(),
            raw_mask.end(),
            [](const unsigned char character) {
                return std::isdigit(character) != 0;
            });
    if (numeric) {
        prefix = parse_decimal(raw_mask, error_message);
        if ((family == AF_INET && prefix > 32U) ||
            (family == AF_INET6 && prefix > 128U)) {
            fail(error_message);
        }
    } else {
        if (family != AF_INET) fail(error_message);
        prefix = dotted_ipv4_prefix(raw_mask, error_message);
    }
    return normalized + "/" + std::to_string(prefix);
}

std::vector<std::string> parse_address_collection(
    const nlohmann::json& value,
    const std::size_t maximum,
    const char* error_message) {
    std::vector<std::string> result;
    if (value.is_object()) {
        result.push_back(parse_address_mask(value, error_message));
    } else if (value.is_array()) {
        if (value.empty() || value.size() > maximum) fail(error_message);
        result.reserve(value.size());
        for (const auto& item : value) {
            result.push_back(parse_address_mask(item, error_message));
        }
    } else {
        fail(error_message);
    }
    if (result.empty() || result.size() > maximum) fail(error_message);
    std::sort(result.begin(), result.end());
    if (std::adjacent_find(result.begin(), result.end()) != result.end()) {
        fail(error_message);
    }
    return result;
}

bool valid_dns_hostname(const std::string& host) {
    if (host.empty() || host.size() > 253U) return false;
    std::size_t label_begin = 0U;
    while (label_begin < host.size()) {
        const auto label_end = host.find('.', label_begin);
        const auto end =
            label_end == std::string::npos ? host.size() : label_end;
        const auto length = end - label_begin;
        if (length == 0U || length > 63U ||
            host[label_begin] == '-' || host[end - 1U] == '-') {
            return false;
        }
        for (std::size_t index = label_begin; index < end; ++index) {
            const auto character =
                static_cast<unsigned char>(host[index]);
            if (std::isalnum(character) == 0 &&
                character != '-') {
                return false;
            }
        }
        if (label_end == std::string::npos) return true;
        label_begin = label_end + 1U;
    }
    return false;
}

std::string canonical_endpoint(
    const std::string& endpoint,
    const char* error_message) {
    if (endpoint.empty() || endpoint.size() > kMaximumEndpointBytes ||
        std::any_of(
            endpoint.begin(),
            endpoint.end(),
            [](const unsigned char character) {
                return std::isspace(character) != 0 ||
                       std::iscntrl(character) != 0;
            })) {
        fail(error_message);
    }
    const auto separator = endpoint.rfind(':');
    if (separator == std::string::npos ||
        separator == 0U ||
        separator + 1U >= endpoint.size()) {
        fail(error_message);
    }
    const auto port = endpoint.substr(separator + 1U);
    const auto parsed = parse_decimal(port, error_message);
    if (parsed == 0U || parsed > 65535U) fail(error_message);

    std::string host = endpoint.substr(0U, separator);
    if (host.find_first_of("/@?#") != std::string::npos) {
        fail(error_message);
    }
    if (host.front() == '[') {
        if (host.size() < 3U || host.back() != ']') {
            fail(error_message);
        }
        const auto raw_ip = host.substr(1U, host.size() - 2U);
        int family = AF_UNSPEC;
        const auto normalized =
            canonical_ip(raw_ip, family, error_message);
        if (family != AF_INET6) fail(error_message);
        host = "[" + normalized + "]";
    } else {
        if (host.find(':') != std::string::npos) {
            fail(error_message);
        }
        int family = AF_UNSPEC;
        std::array<unsigned char, 16U> bytes{};
        if (inet_pton(AF_INET, host.c_str(), bytes.data()) == 1) {
            host = canonical_ip(host, family, error_message);
        } else {
            std::transform(
                host.begin(),
                host.end(),
                host.begin(),
                [](const unsigned char character) {
                    return static_cast<char>(std::tolower(character));
                });
            if (!valid_dns_hostname(host)) fail(error_message);
        }
    }
    return host + ":" + std::to_string(parsed);
}

std::optional<std::string> parse_via(
    const nlohmann::json& peer,
    const char* error_message) {
    const auto connect = peer.find("connect");
    if (connect == peer.end()) return std::nullopt;
    if (!connect->is_object()) fail(error_message);
    const auto via = connect->find("via");
    if (via == connect->end()) return std::nullopt;
    if (!via->is_string()) fail(error_message);
    auto value =
        trim_ascii_whitespace(via->get_ref<const std::string&>());
    if (!safe_interface_id(value)) fail(error_message);
    return value;
}

struct RuntimePeerSupplement {
    std::optional<std::string> endpoint;
    std::optional<std::string> via_interface;
};

std::map<std::string, RuntimePeerSupplement> parse_runtime_supplements(
    const std::optional<NdmsRciSnapshotDocument>& runtime_source,
    const NdmsTunnelInterface& expected,
    const std::string& expected_firmware_name) {
    std::map<std::string, RuntimePeerSupplement> result;
    if (!runtime_source) return result;

    const auto runtime =
        parse_document(*runtime_source, expected_firmware_name);
    const auto id = runtime.find("id");
    if (id != runtime.end() &&
        (!id->is_string() ||
         trim_ascii_whitespace(id->get_ref<const std::string&>()) !=
             expected.id)) {
        fail("NDMS RCI runtime snapshot identity is invalid");
    }
    const auto interface_name = runtime.find("interface-name");
    if (interface_name != runtime.end()) {
        if (!interface_name->is_string()) {
            fail("NDMS RCI runtime snapshot identity is invalid");
        }
        const auto actual = trim_ascii_whitespace(
            interface_name->get_ref<const std::string&>());
        const auto expected_runtime =
            expected.kernel_name.value_or(expected_firmware_name);
        if (actual != expected_runtime &&
            actual != expected_firmware_name) {
            fail("NDMS RCI runtime snapshot identity is invalid");
        }
    }

    const auto wireguard = runtime.find("wireguard");
    if (wireguard == runtime.end() || !wireguard->is_object()) {
        fail("NDMS RCI runtime WireGuard data is invalid");
    }
    const auto peers = wireguard->find("peer");
    if (peers == wireguard->end() || !peers->is_array() ||
        peers->size() > kMaximumPeers) {
        fail("NDMS RCI runtime peer data is invalid");
    }
    for (const auto& peer : *peers) {
        if (!peer.is_object()) {
            fail("NDMS RCI runtime peer data is invalid");
        }
        const auto public_key = peer.find("public-key");
        if (public_key == peer.end() || !public_key->is_string()) {
            fail("NDMS RCI runtime peer identity is invalid");
        }
        const auto key = canonical_wireguard_key(
            public_key->get_ref<const std::string&>(),
            "NDMS RCI runtime peer identity is invalid");
        RuntimePeerSupplement supplement;
        const auto address = peer.find("remote-endpoint-address");
        const auto port = peer.find("remote-port");
        if (address != peer.end() || port != peer.end()) {
            if (address == peer.end() || !address->is_string() ||
                port == peer.end()) {
                fail("NDMS RCI runtime peer endpoint is invalid");
            }
            const auto port_value = parse_json_uint(
                *port,
                65535U,
                "NDMS RCI runtime peer endpoint is invalid");
            auto host = trim_ascii_whitespace(
                address->get_ref<const std::string&>());
            if (!host.empty() && port_value != 0U) {
                if (host.find(':') != std::string::npos &&
                    host.front() != '[') {
                    host = "[" + host + "]";
                }
                auto endpoint =
                    host + ":" + std::to_string(port_value);
                endpoint = canonical_endpoint(
                    endpoint,
                    "NDMS RCI runtime peer endpoint is invalid");
                supplement.endpoint = std::move(endpoint);
            }
        }
        const auto via = peer.find("via");
        if (via != peer.end()) {
            if (!via->is_string()) {
                fail("NDMS RCI runtime peer route is invalid");
            }
            auto value = trim_ascii_whitespace(
                via->get_ref<const std::string&>());
            if (!value.empty()) {
                if (!safe_interface_id(value)) {
                    fail("NDMS RCI runtime peer route is invalid");
                }
                supplement.via_interface = std::move(value);
            }
        }
        if (!result.emplace(key, std::move(supplement)).second) {
            fail("NDMS RCI runtime contains duplicate peers");
        }
    }
    return result;
}

std::optional<NdmsAwgAscParameters> parse_asc(
    const std::optional<NdmsRciSnapshotDocument>& source,
    const std::string& expected_firmware_name) {
    if (!source) return std::nullopt;
    const auto document =
        parse_document(*source, expected_firmware_name);
    if (document.empty()) return std::nullopt;

    const auto required_string =
        [&](const char* key,
            const std::size_t maximum,
            const bool allow_empty) {
            const auto field = document.find(key);
            if (field == document.end() || !field->is_string()) {
                fail("NDMS RCI ASC document is incomplete");
            }
            auto value = field->get<std::string>();
            if ((!allow_empty && value.empty()) ||
                value.size() > maximum ||
                !valid_utf8(value) ||
                std::any_of(
                    value.begin(),
                    value.end(),
                    [](const unsigned char character) {
                        return character == '\0' ||
                               character == '\r' ||
                               character == '\n';
                    })) {
                fail("NDMS RCI ASC field is invalid");
            }
            return value;
        };
    const auto required_number = [&](const char* key) {
        return parse_decimal(
            required_string(key, 10U, false),
            "NDMS RCI ASC numeric field is invalid");
    };

    NdmsAwgAscParameters asc;
    asc.jc = required_number("jc");
    asc.jmin = required_number("jmin");
    asc.jmax = required_number("jmax");
    asc.s1 = required_number("s1");
    asc.s2 = required_number("s2");
    asc.h1 = required_string("h1", kMaximumAscHeaderBytes, true);
    asc.h2 = required_string("h2", kMaximumAscHeaderBytes, true);
    asc.h3 = required_string("h3", kMaximumAscHeaderBytes, true);
    asc.h4 = required_string("h4", kMaximumAscHeaderBytes, true);

    const bool disabled =
        asc.jc == 0U && asc.jmin == 0U && asc.jmax == 0U &&
        asc.s1 == 0U && asc.s2 == 0U &&
        asc.h1.empty() && asc.h2.empty() &&
        asc.h3.empty() && asc.h4.empty();
    if (!disabled &&
        (asc.jc == 0U || asc.jmin == 0U ||
         asc.jmax <= asc.jmin || asc.s1 == 0U ||
         asc.s2 == 0U || asc.h1.empty() ||
         asc.h2.empty() || asc.h3.empty() ||
         asc.h4.empty())) {
        fail("NDMS RCI ASC parameter set is inconsistent");
    }

    const auto optional_number =
        [&](const char* key) -> std::optional<std::uint32_t> {
            const auto field = document.find(key);
            if (field == document.end()) return std::nullopt;
            if (!field->is_string()) {
                fail("NDMS RCI ASC numeric field is invalid");
            }
            const auto& value =
                field->get_ref<const std::string&>();
            if (value.empty()) return std::nullopt;
            return parse_decimal(
                value,
                "NDMS RCI ASC numeric field is invalid");
        };
    asc.s3 = optional_number("s3");
    asc.s4 = optional_number("s4");
    if (asc.s3.has_value() != asc.s4.has_value()) {
        fail("NDMS RCI ASC extended parameters are incomplete");
    }

    const auto optional_signature =
        [&](const char* key) -> std::optional<std::string> {
            const auto field = document.find(key);
            if (field == document.end()) return std::nullopt;
            if (!field->is_string()) {
                fail("NDMS RCI ASC signature field is invalid");
            }
            auto value = field->get<std::string>();
            if (value.size() > kMaximumAscSignatureBytes ||
                !valid_utf8(value) ||
                value.find('\0') != std::string::npos ||
                value.find('\r') != std::string::npos ||
                value.find('\n') != std::string::npos) {
                fail("NDMS RCI ASC signature field is invalid");
            }
            return value;
        };
    asc.i1 = optional_signature("i1");
    asc.i2 = optional_signature("i2");
    asc.i3 = optional_signature("i3");
    asc.i4 = optional_signature("i4");
    asc.i5 = optional_signature("i5");
    return asc;
}

nlohmann::json optional_json_string(
    const std::optional<std::string>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

std::string build_full_revision(
    const NdmsRciRestorableSnapshot& snapshot) {
    nlohmann::json canonical;
    canonical["schema"] = "ndms-rci-full-v1";
    canonical["interface_id"] = snapshot.interface_id;
    canonical["firmware_interface_name"] =
        snapshot.firmware_interface_name;
    canonical["kind"] = ndms_tunnel_kind_name(snapshot.kind);
    canonical["description"] =
        optional_json_string(snapshot.description);
    canonical["enabled"] = snapshot.enabled
        ? nlohmann::json(*snapshot.enabled)
        : nlohmann::json(nullptr);
    canonical["mtu"] = snapshot.mtu
        ? nlohmann::json(*snapshot.mtu)
        : nlohmann::json(nullptr);
    canonical["listen_port"] = snapshot.listen_port
        ? nlohmann::json(*snapshot.listen_port)
        : nlohmann::json(nullptr);
    canonical["addresses"] = snapshot.addresses;
    canonical["private_key_sha256"] =
        snapshot.private_key.sha256();

    if (snapshot.asc) {
        const auto& asc = *snapshot.asc;
        canonical["asc"] = {
            {"jc", asc.jc},
            {"jmin", asc.jmin},
            {"jmax", asc.jmax},
            {"s1", asc.s1},
            {"s2", asc.s2},
            {"h1", asc.h1},
            {"h2", asc.h2},
            {"h3", asc.h3},
            {"h4", asc.h4},
            {"s3", asc.s3 ? nlohmann::json(*asc.s3)
                           : nlohmann::json(nullptr)},
            {"s4", asc.s4 ? nlohmann::json(*asc.s4)
                           : nlohmann::json(nullptr)},
            {"i1", optional_json_string(asc.i1)},
            {"i2", optional_json_string(asc.i2)},
            {"i3", optional_json_string(asc.i3)},
            {"i4", optional_json_string(asc.i4)},
            {"i5", optional_json_string(asc.i5)},
        };
    } else {
        canonical["asc"] = nullptr;
    }

    canonical["peers"] = nlohmann::json::array();
    for (const auto& peer : snapshot.peers) {
        canonical["peers"].push_back({
            {"public_key", peer.public_key},
            {"preshared_key_sha256",
             peer.preshared_key
                 ? nlohmann::json(peer.preshared_key->sha256())
                 : nlohmann::json(nullptr)},
            {"endpoint", peer.endpoint},
            {"via_interface",
             optional_json_string(peer.via_interface)},
            {"allowed_ips", peer.allowed_ips},
            {"persistent_keepalive",
             peer.persistent_keepalive
                 ? nlohmann::json(*peer.persistent_keepalive)
                 : nlohmann::json(nullptr)},
        });
    }
    return "ndms-rci-full-v1-" + Sha256::hex(canonical.dump());
}

} // namespace

NdmsRciSecret::NdmsRciSecret(std::string value)
    : value_(std::move(value)) {}

NdmsRciSecret::~NdmsRciSecret() {
    wipe();
}

NdmsRciSecret::NdmsRciSecret(NdmsRciSecret&& other) noexcept {
    value_.swap(other.value_);
}

NdmsRciSecret& NdmsRciSecret::operator=(
    NdmsRciSecret&& other) noexcept {
    if (this != &other) {
        wipe();
        value_.swap(other.value_);
    }
    return *this;
}

const std::string& NdmsRciSecret::reveal_for_restore() const noexcept {
    return value_;
}

std::string NdmsRciSecret::sha256() const {
    return Sha256::hex(value_);
}

void NdmsRciSecret::wipe() noexcept {
    volatile char* bytes =
        value_.empty() ? nullptr : &value_[0];
    for (std::size_t index = 0U;
         bytes != nullptr && index < value_.size();
         ++index) {
        bytes[index] = '\0';
    }
    value_.clear();
}

NdmsRciRestorableSnapshot parse_ndms_rci_restorable_snapshot(
    NdmsRciRestorableSnapshotInput input,
    const NdmsTunnelInterface& expected_interface) {
    if (expected_interface.role != NdmsInterfaceRole::client) {
        fail("NDMS RCI restorable snapshots support client interfaces only");
    }
    if (expected_interface.kind != NdmsTunnelKind::wireguard &&
        expected_interface.kind !=
            NdmsTunnelKind::amnezia_wireguard) {
        fail("NDMS RCI restorable snapshot kind is unsupported");
    }
    if (!safe_interface_id(expected_interface.id)) {
        fail("NDMS RCI restorable snapshot interface id is invalid");
    }
    const auto firmware_name =
        expected_interface.firmware_interface_name.empty()
            ? expected_interface.id
            : expected_interface.firmware_interface_name;
    if (!safe_interface_id(firmware_name)) {
        fail("NDMS RCI restorable snapshot firmware identity is invalid");
    }

    const auto rc =
        parse_document(input.rc_interface, firmware_name);
    validate_optional_rc_identity(rc, expected_interface);

    NdmsRciRestorableSnapshot snapshot{
        expected_interface.id,
        firmware_name,
        expected_interface.kind,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        {},
        NdmsRciSecret(canonical_wireguard_key(
            input.private_key.reveal_for_restore(),
            "NDMS RCI private key is missing or invalid")),
        std::nullopt,
        {},
        {},
    };

    const auto description = rc.find("description");
    if (description != rc.end()) {
        if (!description->is_string()) {
            fail("NDMS RCI interface description is invalid");
        }
        const auto& value =
            description->get_ref<const std::string&>();
        if (value.size() > kMaximumDescriptionBytes ||
            !valid_utf8(value) ||
            value.find('\0') != std::string::npos) {
            fail("NDMS RCI interface description is invalid");
        }
        snapshot.description = value;
    }

    const auto up = rc.find("up");
    if (up != rc.end()) {
        if (!up->is_boolean()) {
            fail("NDMS RCI interface enabled state is invalid");
        }
        snapshot.enabled = up->get<bool>();
    }

    const auto ip = rc.find("ip");
    if (ip == rc.end() || !ip->is_object()) {
        fail("NDMS RCI interface IP configuration is incomplete");
    }
    const auto addresses = ip->find("address");
    if (addresses == ip->end()) {
        fail("NDMS RCI interface address configuration is incomplete");
    }
    snapshot.addresses = parse_address_collection(
        *addresses,
        kMaximumAddresses,
        "NDMS RCI interface address configuration is invalid");

    const auto mtu = ip->find("mtu");
    if (mtu != ip->end()) {
        if (!mtu->is_string()) {
            fail("NDMS RCI interface MTU is invalid");
        }
        const auto value = parse_decimal(
            mtu->get_ref<const std::string&>(),
            "NDMS RCI interface MTU is invalid");
        if (value < 576U || value > 65535U) {
            fail("NDMS RCI interface MTU is invalid");
        }
        snapshot.mtu = value;
    }

    const auto wireguard = rc.find("wireguard");
    if (wireguard == rc.end() || !wireguard->is_object()) {
        fail("NDMS RCI WireGuard configuration is incomplete");
    }
    const auto listen_port = wireguard->find("listen-port");
    if (listen_port != wireguard->end()) {
        if (!listen_port->is_object()) {
            fail("NDMS RCI WireGuard listen port is invalid");
        }
        const auto port = listen_port->find("port");
        if (port == listen_port->end()) {
            fail("NDMS RCI WireGuard listen port is invalid");
        }
        snapshot.listen_port = static_cast<std::uint16_t>(
            parse_json_uint(
                *port,
                65535U,
                "NDMS RCI WireGuard listen port is invalid"));
    }

    const auto runtime = parse_runtime_supplements(
        input.runtime_interface,
        expected_interface,
        firmware_name);
    const auto peers = wireguard->find("peer");
    if (peers == wireguard->end() || !peers->is_array() ||
        peers->empty() || peers->size() > kMaximumPeers) {
        fail("NDMS RCI client peer configuration is incomplete");
    }
    std::set<std::string> seen_peers;
    snapshot.peers.reserve(peers->size());
    for (const auto& peer : *peers) {
        if (!peer.is_object()) {
            fail("NDMS RCI peer configuration is invalid");
        }
        const auto key_field = peer.find("key");
        if (key_field == peer.end() || !key_field->is_string()) {
            fail("NDMS RCI peer public key is invalid");
        }
        auto public_key = canonical_wireguard_key(
            key_field->get_ref<const std::string&>(),
            "NDMS RCI peer public key is invalid");
        if (!seen_peers.insert(public_key).second) {
            fail("NDMS RCI peer public keys are duplicated");
        }

        std::optional<NdmsRciSecret> preshared_key;
        const auto psk = peer.find("preshared-key");
        if (psk != peer.end()) {
            if (!psk->is_string()) {
                fail("NDMS RCI peer preshared key is invalid");
            }
            const auto trimmed = trim_ascii_whitespace(
                psk->get_ref<const std::string&>());
            if (!trimmed.empty()) {
                preshared_key.emplace(canonical_wireguard_key(
                    trimmed,
                    "NDMS RCI peer preshared key is invalid"));
            }
        }

        std::optional<std::string> endpoint;
        const auto endpoint_field = peer.find("endpoint");
        if (endpoint_field != peer.end()) {
            if (!endpoint_field->is_object()) {
                fail("NDMS RCI peer endpoint is invalid");
            }
            const auto address = endpoint_field->find("address");
            if (address == endpoint_field->end() ||
                !address->is_string()) {
                fail("NDMS RCI peer endpoint is invalid");
            }
            auto value = trim_ascii_whitespace(
                address->get_ref<const std::string&>());
            value = canonical_endpoint(
                value,
                "NDMS RCI peer endpoint is invalid");
            endpoint = std::move(value);
        }

        auto via_interface = parse_via(
            peer,
            "NDMS RCI peer route is invalid");
        const auto runtime_peer = runtime.find(public_key);
        if (runtime_peer != runtime.end()) {
            if (!endpoint && runtime_peer->second.endpoint) {
                endpoint = runtime_peer->second.endpoint;
            }
            if (!via_interface &&
                runtime_peer->second.via_interface) {
                via_interface =
                    runtime_peer->second.via_interface;
            }
        }
        if (!endpoint) {
            fail("NDMS RCI client peer endpoint is missing");
        }

        const auto allow_ips = peer.find("allow-ips");
        if (allow_ips == peer.end()) {
            fail("NDMS RCI peer allowed IPs are missing");
        }
        auto allowed_ips = parse_address_collection(
            *allow_ips,
            kMaximumAllowedIps,
            "NDMS RCI peer allowed IPs are invalid");

        std::optional<std::uint16_t> keepalive;
        const auto keepalive_field =
            peer.find("keepalive-interval");
        if (keepalive_field != peer.end()) {
            if (!keepalive_field->is_object()) {
                fail("NDMS RCI peer keepalive is invalid");
            }
            const auto interval =
                keepalive_field->find("interval");
            if (interval == keepalive_field->end()) {
                fail("NDMS RCI peer keepalive is invalid");
            }
            keepalive = static_cast<std::uint16_t>(
                parse_json_uint(
                    *interval,
                    65535U,
                    "NDMS RCI peer keepalive is invalid"));
        }
        snapshot.peers.push_back({
            std::move(public_key),
            std::move(preshared_key),
            std::move(*endpoint),
            std::move(via_interface),
            std::move(allowed_ips),
            keepalive,
        });
    }
    std::sort(
        snapshot.peers.begin(),
        snapshot.peers.end(),
        [](const NdmsRciPeerSnapshot& left,
           const NdmsRciPeerSnapshot& right) {
            return left.public_key < right.public_key;
        });

    if (expected_interface.kind == NdmsTunnelKind::wireguard &&
        input.asc.has_value()) {
        fail("NDMS RCI plain WireGuard snapshot contains unexpected ASC data");
    }
    snapshot.asc = parse_asc(input.asc, firmware_name);
    if (expected_interface.kind ==
            NdmsTunnelKind::amnezia_wireguard &&
        !snapshot.asc.has_value()) {
        fail("NDMS RCI AmneziaWG snapshot is missing ASC data");
    }
    snapshot.full_revision = build_full_revision(snapshot);
    return snapshot;
}

} // namespace keen_pbr3
