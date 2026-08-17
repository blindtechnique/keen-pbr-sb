#include "ndms_rci_observation.hpp"

#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <limits>
#include <set>
#include <string_view>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::size_t kMaximumResponseBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaximumDescriptionBytes = 512U;
constexpr std::size_t kMaximumAddresses = 64U;
constexpr std::size_t kMaximumAddressBytes = 128U;
constexpr std::size_t kMaximumEnvelopeDepth = 16U;

std::string trim_ascii_whitespace(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::string ascii_lower_trimmed(const std::string& value) {
    auto result = trim_ascii_whitespace(value);
    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return result;
}

bool supported_observation_kind(const NdmsTunnelKind kind) noexcept {
    return kind == NdmsTunnelKind::wireguard ||
           kind == NdmsTunnelKind::amnezia_wireguard;
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

bool json_content_type(const std::string& raw_content_type) {
    auto content_type = ascii_lower_trimmed(raw_content_type);
    const auto parameters = content_type.find(';');
    if (parameters != std::string::npos) {
        content_type = trim_ascii_whitespace(
            content_type.substr(0, parameters));
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
    if (value.is_number_unsigned()) return value.get<std::uint64_t>() != 0;
    if (value.is_number_float()) return value.get<double>() != 0.0;
    if (value.is_string()) {
        return !trim_ascii_whitespace(value.get_ref<const std::string&>())
                    .empty();
    }
    return !value.empty();
}

bool success_status_token(const std::string& value) {
    const auto token = ascii_lower_trimmed(value);
    return token == "ok" || token == "success" ||
           token == "succeeded" || token == "done" ||
           token == "completed";
}

bool failure_status_token(const std::string& value) {
    const auto token = ascii_lower_trimmed(value);
    return token == "error" || token == "failed" ||
           token == "failure" || token == "denied" ||
           token == "invalid";
}

void validate_status_value(
    const nlohmann::json& value,
    const std::size_t depth);

void validate_status_record(
    const nlohmann::json& record,
    const std::size_t depth) {
    if (depth > kMaximumEnvelopeDepth) {
        throw NdmsRciObservationError(
            "NDMS RCI status envelope is too deeply nested");
    }
    if (!record.is_object()) {
        throw NdmsRciObservationError(
            "NDMS RCI status entry is not an object");
    }

    for (const auto* key : {"error", "errors"}) {
        const auto error = record.find(key);
        if (error != record.end() && non_empty_error_value(*error)) {
            throw NdmsRciObservationError(
                "NDMS RCI reported an error");
        }
    }

    bool has_result = false;
    for (const auto* key : {"status", "result"}) {
        const auto result = record.find(key);
        if (result == record.end()) continue;
        has_result = true;
        if (result->is_string()) {
            const auto& token = result->get_ref<const std::string&>();
            if (failure_status_token(token)) {
                throw NdmsRciObservationError(
                    "NDMS RCI reported a failed status");
            }
            if (!success_status_token(token)) {
                throw NdmsRciObservationError(
                    "NDMS RCI returned an unknown status token");
            }
            continue;
        }
        if (result->is_number_integer()) {
            if (result->get<std::int64_t>() != 0) {
                throw NdmsRciObservationError(
                    "NDMS RCI returned a failing status code");
            }
            continue;
        }
        if (result->is_number_unsigned()) {
            if (result->get<std::uint64_t>() != 0U) {
                throw NdmsRciObservationError(
                    "NDMS RCI returned a failing status code");
            }
            continue;
        }
        if (result->is_object() || result->is_array()) {
            validate_status_value(*result, depth + 1U);
            continue;
        }
        throw NdmsRciObservationError(
            "NDMS RCI status has an invalid type");
    }

    const auto code = record.find("code");
    if (code != record.end()) {
        has_result = true;
        if (code->is_number_integer()) {
            if (code->get<std::int64_t>() != 0) {
                throw NdmsRciObservationError(
                    "NDMS RCI returned a failing result code");
            }
        } else if (code->is_number_unsigned()) {
            if (code->get<std::uint64_t>() != 0U) {
                throw NdmsRciObservationError(
                    "NDMS RCI returned a failing result code");
            }
        } else {
            throw NdmsRciObservationError(
                "NDMS RCI result code has an invalid type");
        }
    }

    if (!has_result) {
        throw NdmsRciObservationError(
            "NDMS RCI status entry has no result");
    }
}

void validate_status_value(
    const nlohmann::json& value,
    const std::size_t depth) {
    if (depth > kMaximumEnvelopeDepth) {
        throw NdmsRciObservationError(
            "NDMS RCI status envelope is too deeply nested");
    }
    if (value.is_array()) {
        if (value.empty()) {
            throw NdmsRciObservationError(
                "NDMS RCI status array is empty");
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
        const auto& token = value.get_ref<const std::string&>();
        if (failure_status_token(token)) {
            throw NdmsRciObservationError(
                "NDMS RCI reported a failed status");
        }
        if (!success_status_token(token)) {
            throw NdmsRciObservationError(
                "NDMS RCI returned an unknown status token");
        }
        return;
    }
    if (value.is_number_integer()) {
        if (value.get<std::int64_t>() != 0) {
            throw NdmsRciObservationError(
                "NDMS RCI returned a failing status code");
        }
        return;
    }
    if (value.is_number_unsigned()) {
        if (value.get<std::uint64_t>() != 0U) {
            throw NdmsRciObservationError(
                "NDMS RCI returned a failing status code");
        }
        return;
    }
    throw NdmsRciObservationError(
        "NDMS RCI status has an invalid type");
}

void validate_error_envelopes(
    const nlohmann::json& value,
    const std::size_t depth = 0U) {
    if (depth > kMaximumEnvelopeDepth) {
        throw NdmsRciObservationError(
            "NDMS RCI response is too deeply nested");
    }
    if (value.is_array()) {
        for (const auto& item : value) {
            validate_error_envelopes(item, depth + 1U);
        }
        return;
    }
    if (!value.is_object()) return;

    for (const auto* key : {"error", "errors"}) {
        const auto error = value.find(key);
        if (error != value.end() && non_empty_error_value(*error)) {
            throw NdmsRciObservationError(
                "NDMS RCI reported an error");
        }
    }

    const auto status = value.find("status");
    if (status != value.end()) {
        if (status->is_object() || status->is_array()) {
            validate_status_value(*status, depth + 1U);
        } else if (status->is_string() &&
                   failure_status_token(
                       status->get_ref<const std::string&>())) {
            throw NdmsRciObservationError(
                "NDMS RCI reported a failed status");
        }
    }

    // RCI may wrap command results more than once. Walk the complete response
    // tree so an error nested below data/interface cannot be mistaken for a
    // valid observation. Values are never copied into diagnostics.
    for (auto field = value.begin(); field != value.end(); ++field) {
        if (field.key() == "status" ||
            field.key() == "error" ||
            field.key() == "errors") {
            continue;
        }
        validate_error_envelopes(field.value(), depth + 1U);
    }
}

bool identity_matches(
    const nlohmann::json& object,
    const NdmsTunnelInterface& expected_interface,
    bool& identity_present) {
    identity_present = false;
    const auto id = object.find("id");
    if (id != object.end()) {
        identity_present = true;
        if (!id->is_string() ||
            trim_ascii_whitespace(
                id->get_ref<const std::string&>()) !=
                expected_interface.id) {
            return false;
        }
    }

    const auto expected_firmware_name =
        expected_interface.firmware_interface_name.empty()
            ? expected_interface.id
            : expected_interface.firmware_interface_name;
    for (const auto* key : {"interface-name", "name"}) {
        const auto field = object.find(key);
        if (field == object.end()) continue;
        identity_present = true;
        if (!field->is_string() ||
            trim_ascii_whitespace(
                field->get_ref<const std::string&>()) !=
                expected_firmware_name) {
            return false;
        }
    }
    return true;
}

void collect_interface_candidates(
    const nlohmann::json& value,
    const NdmsTunnelInterface& expected_interface,
    std::vector<const nlohmann::json*>& candidates,
    const std::size_t depth = 0U) {
    if (depth > kMaximumEnvelopeDepth) {
        throw NdmsRciObservationError(
            "NDMS RCI response is too deeply nested");
    }
    if (value.is_array()) {
        for (const auto& item : value) {
            collect_interface_candidates(
                item,
                expected_interface,
                candidates,
                depth + 1U);
        }
        return;
    }
    if (!value.is_object()) return;

    std::set<std::string> expected_keys{expected_interface.id};
    if (!expected_interface.firmware_interface_name.empty()) {
        expected_keys.insert(expected_interface.firmware_interface_name);
    }
    for (const auto& expected_key : expected_keys) {
        const auto keyed = value.find(expected_key);
        if (keyed == value.end()) continue;
        if (!keyed->is_object()) {
            throw NdmsRciObservationError(
                "NDMS RCI interface entry is not an object");
        }
        candidates.push_back(&*keyed);
    }

    bool identity_present = false;
    if (identity_matches(
            value,
            expected_interface,
            identity_present) &&
        identity_present) {
        candidates.push_back(&value);
    }

    for (const auto* key : {"interface", "data", "result", "response"}) {
        const auto nested = value.find(key);
        if (nested != value.end()) {
            collect_interface_candidates(
                *nested,
                expected_interface,
                candidates,
                depth + 1U);
        }
    }
}

const nlohmann::json& locate_interface_entry(
    const nlohmann::json& document,
    const NdmsTunnelInterface& expected_interface) {
    std::vector<const nlohmann::json*> candidates;
    collect_interface_candidates(
        document,
        expected_interface,
        candidates);
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(
        std::unique(candidates.begin(), candidates.end()),
        candidates.end());
    if (candidates.empty()) {
        throw NdmsRciObservationError(
            "NDMS RCI response does not contain the requested interface");
    }
    if (candidates.size() != 1U) {
        throw NdmsRciObservationError(
            "NDMS RCI response contains ambiguous interface entries");
    }
    return *candidates.front();
}

enum class ParsedWireguardKind {
    generic,
    wireguard,
    amnezia_wireguard,
    unsupported,
};

ParsedWireguardKind classify_type_token(const std::string& raw_value) {
    const auto value = ascii_lower_trimmed(raw_value);
    if (value == "tunnel" || value == "vpn" || value == "interface") {
        return ParsedWireguardKind::generic;
    }
    if (value == "wireguard") {
        return ParsedWireguardKind::wireguard;
    }
    if (value == "amneziawireguard" ||
        value == "amnezia wireguard" ||
        value == "amnezia-wireguard" ||
        value == "amnezia_wireguard" ||
        value == "amneziawg" ||
        value == "amnezia wg" ||
        value == "awg") {
        return ParsedWireguardKind::amnezia_wireguard;
    }
    return ParsedWireguardKind::unsupported;
}

std::string validate_kind(
    const nlohmann::json& entry,
    const NdmsTunnelKind expected_kind) {
    bool saw_wireguard = false;
    bool saw_amnezia = false;
    std::string firmware_type;
    for (const auto* key : {"type", "subtype", "protocol"}) {
        const auto field = entry.find(key);
        if (field == entry.end()) continue;
        if (!field->is_string()) {
            throw NdmsRciObservationError(
                "NDMS RCI interface type has an invalid type");
        }
        const auto value =
            trim_ascii_whitespace(field->get_ref<const std::string&>());
        if (value.empty()) {
            throw NdmsRciObservationError(
                "NDMS RCI interface type is empty");
        }
        if (firmware_type.empty()) firmware_type = value;
        switch (classify_type_token(value)) {
        case ParsedWireguardKind::generic:
            break;
        case ParsedWireguardKind::wireguard:
            saw_wireguard = true;
            break;
        case ParsedWireguardKind::amnezia_wireguard:
            saw_amnezia = true;
            break;
        case ParsedWireguardKind::unsupported:
            throw NdmsRciObservationError(
                "NDMS RCI interface type is unsupported");
        }
    }

    if (!saw_wireguard && !saw_amnezia) {
        throw NdmsRciObservationError(
            "NDMS RCI response has no WG/AWG type evidence");
    }
    if (expected_kind == NdmsTunnelKind::wireguard && saw_amnezia) {
        throw NdmsRciObservationError(
            "NDMS RCI interface kind does not match inventory");
    }
    if (expected_kind == NdmsTunnelKind::amnezia_wireguard &&
        !saw_amnezia) {
        throw NdmsRciObservationError(
            "NDMS RCI interface kind does not match inventory");
    }
    return firmware_type;
}

std::optional<std::string> optional_string_field(
    const nlohmann::json& entry,
    const char* key,
    const std::size_t maximum_bytes) {
    const auto field = entry.find(key);
    if (field == entry.end()) return std::nullopt;
    if (!field->is_string()) {
        throw NdmsRciObservationError(
            "NDMS RCI interface string field has an invalid type");
    }
    auto value =
        trim_ascii_whitespace(field->get_ref<const std::string&>());
    if (value.size() > maximum_bytes) {
        throw NdmsRciObservationError(
            "NDMS RCI interface string field is too large");
    }
    return value;
}

template <typename Value>
std::optional<Value> optional_unsigned_field(
    const nlohmann::json& entry,
    const char* key,
    const std::uint64_t minimum,
    const std::uint64_t maximum) {
    const auto field = entry.find(key);
    if (field == entry.end()) return std::nullopt;
    if (!field->is_number_unsigned() && !field->is_number_integer()) {
        throw NdmsRciObservationError(
            "NDMS RCI interface numeric field has an invalid type");
    }
    if (field->is_number_integer() &&
        field->get<std::int64_t>() < 0) {
        throw NdmsRciObservationError(
            "NDMS RCI interface numeric field is out of range");
    }
    const auto value = field->get<std::uint64_t>();
    if (value < minimum || value > maximum ||
        value > std::numeric_limits<Value>::max()) {
        throw NdmsRciObservationError(
            "NDMS RCI interface numeric field is out of range");
    }
    return static_cast<Value>(value);
}

std::optional<bool> optional_bool_field(
    const nlohmann::json& entry,
    const char* key) {
    const auto field = entry.find(key);
    if (field == entry.end()) return std::nullopt;
    if (!field->is_boolean()) {
        throw NdmsRciObservationError(
            "NDMS RCI interface boolean field has an invalid type");
    }
    return field->get<bool>();
}

void append_address(
    const nlohmann::json& value,
    std::vector<std::string>& addresses) {
    if (!value.is_string()) {
        throw NdmsRciObservationError(
            "NDMS RCI interface address has an invalid type");
    }
    auto address =
        trim_ascii_whitespace(value.get_ref<const std::string&>());
    if (address.empty() || address.size() > kMaximumAddressBytes ||
        std::any_of(
            address.begin(),
            address.end(),
            [](const unsigned char character) {
                return std::iscntrl(character) != 0 ||
                       std::isspace(character) != 0;
            })) {
        throw NdmsRciObservationError(
            "NDMS RCI interface address is invalid");
    }
    addresses.push_back(std::move(address));
}

std::vector<std::string> parse_addresses(const nlohmann::json& entry) {
    std::vector<std::string> addresses;
    for (const auto* key : {"address", "addresses", "ip-address"}) {
        const auto field = entry.find(key);
        if (field == entry.end()) continue;
        if (field->is_array()) {
            if (field->size() > kMaximumAddresses) {
                throw NdmsRciObservationError(
                    "NDMS RCI interface has too many addresses");
            }
            for (const auto& value : *field) {
                append_address(value, addresses);
            }
        } else {
            append_address(*field, addresses);
        }
    }
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(
        std::unique(addresses.begin(), addresses.end()),
        addresses.end());
    if (addresses.size() > kMaximumAddresses) {
        throw NdmsRciObservationError(
            "NDMS RCI interface has too many addresses");
    }
    return addresses;
}

std::size_t parse_peer_count(const nlohmann::json& entry) {
    const nlohmann::json* peers = nullptr;
    for (const auto* key : {"peer", "peers"}) {
        const auto field = entry.find(key);
        if (field == entry.end()) continue;
        if (peers != nullptr) {
            throw NdmsRciObservationError(
                "NDMS RCI interface peer fields are ambiguous");
        }
        peers = &*field;
    }
    if (peers == nullptr) return 0U;
    if (!peers->is_array() && !peers->is_object()) {
        throw NdmsRciObservationError(
            "NDMS RCI interface peers have an invalid type");
    }
    if (peers->size() > 4096U) {
        throw NdmsRciObservationError(
            "NDMS RCI interface has too many peers");
    }
    for (const auto& peer : *peers) {
        if (!peer.is_object()) {
            throw NdmsRciObservationError(
                "NDMS RCI interface peer is not an object");
        }
    }
    return peers->size();
}

void validate_identity(
    const nlohmann::json& entry,
    const NdmsTunnelInterface& expected_interface) {
    bool identity_present = false;
    if (!identity_matches(
            entry,
            expected_interface,
            identity_present)) {
        throw NdmsRciObservationError(
            "NDMS RCI interface identity does not match inventory");
    }
    if (!identity_present) {
        // A keyed catalog entry is still unambiguous; locate_interface_entry
        // has already required the exact expected key.
        return;
    }
}

std::string observation_revision(
    const NdmsRciTunnelObservation& observation) {
    nlohmann::json safe = {
        {"schema", "ndms-rci-observation-v1"},
        {"interface_id", observation.interface_id},
        {"kind", ndms_tunnel_kind_name(observation.kind)},
        {"firmware_type", observation.firmware_type},
        {"peer_count", observation.peer_count},
        {"addresses", observation.addresses},
    };
    if (observation.description) {
        safe["description"] = *observation.description;
    }
    if (observation.enabled) safe["enabled"] = *observation.enabled;
    if (observation.mtu) safe["mtu"] = *observation.mtu;
    if (observation.listen_port) {
        safe["listen_port"] = *observation.listen_port;
    }
    return "ndms-rci-v1-" + Sha256::hex(safe.dump());
}

} // namespace

NdmsRciTunnelObservation parse_ndms_rci_tunnel_observation(
    const NdmsRciReadResponse& response,
    const NdmsTunnelInterface& expected_interface) {
    if (!supported_observation_kind(expected_interface.kind)) {
        throw NdmsRciObservationError(
            "NDMS RCI observation kind is unsupported");
    }
    if (!safe_interface_id(expected_interface.id)) {
        throw NdmsRciObservationError(
            "NDMS RCI interface identity is invalid");
    }
    if (response.status_code != 200) {
        throw NdmsRciObservationError(
            "NDMS RCI request did not return HTTP 200");
    }
    if (!json_content_type(response.content_type)) {
        throw NdmsRciObservationError(
            "NDMS RCI response is not JSON");
    }
    if (response.body.empty() ||
        response.body.size() > kMaximumResponseBytes) {
        throw NdmsRciObservationError(
            "NDMS RCI response body has an invalid size");
    }

    nlohmann::json document;
    try {
        document = nlohmann::json::parse(response.body);
    } catch (const nlohmann::json::parse_error&) {
        // Never attach parser context: it can contain credential material.
        throw NdmsRciObservationError(
            "NDMS RCI response contains invalid JSON");
    }
    if (!document.is_object() && !document.is_array()) {
        throw NdmsRciObservationError(
            "NDMS RCI response root has an invalid type");
    }

    validate_error_envelopes(document);
    const auto& entry =
        locate_interface_entry(document, expected_interface);
    validate_identity(entry, expected_interface);

    NdmsRciTunnelObservation observation;
    observation.interface_id = expected_interface.id;
    observation.kind = expected_interface.kind;
    observation.firmware_type =
        validate_kind(entry, expected_interface.kind);
    observation.description = optional_string_field(
        entry,
        "description",
        kMaximumDescriptionBytes);
    observation.enabled = optional_bool_field(entry, "enabled");
    observation.mtu = optional_unsigned_field<std::uint32_t>(
        entry,
        "mtu",
        576U,
        65535U);
    observation.listen_port = optional_unsigned_field<std::uint16_t>(
        entry,
        "listen-port",
        1U,
        65535U);
    observation.addresses = parse_addresses(entry);
    observation.peer_count = parse_peer_count(entry);
    observation.observation_revision =
        observation_revision(observation);
    return observation;
}

NdmsRciObservationGateway::NdmsRciObservationGateway(
    NdmsRciObservationFetcher fetcher)
    : fetcher_(std::move(fetcher)) {
    if (!fetcher_) {
        throw std::invalid_argument(
            "NDMS RCI observation fetcher must be configured");
    }
}

NdmsRciTunnelObservation NdmsRciObservationGateway::acquire(
    const NdmsTunnelInterface& expected_interface) const {
    return parse_ndms_rci_tunnel_observation(
        fetcher_(expected_interface),
        expected_interface);
}

} // namespace keen_pbr3
