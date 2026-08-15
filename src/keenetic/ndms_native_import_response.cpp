#include "ndms_native_import_response.hpp"

#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

using Json = nlohmann::json;

constexpr std::size_t kMaximumDepth = 32U;
constexpr std::size_t kMaximumNodes = 8192U;
constexpr std::size_t kMaximumKeys = 4096U;
constexpr std::size_t kMaximumKeyBytes = 256U;

std::string trim_ascii_whitespace(const std::string_view value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(begin, end - begin + 1U));
}

std::string ascii_lower_trimmed(const std::string_view value) {
    auto result = trim_ascii_whitespace(value);
    std::transform(
        result.begin(), result.end(), result.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return result;
}

bool json_content_type(const std::string_view raw_content_type) {
    auto content_type = ascii_lower_trimmed(raw_content_type);
    const auto parameters = content_type.find(';');
    if (parameters != std::string::npos) {
        content_type = trim_ascii_whitespace(
            content_type.substr(0U, parameters));
    }
    if (content_type == "application/json") return true;
    constexpr std::string_view suffix{"+json"};
    return content_type.size() > suffix.size() &&
           content_type.compare(
               content_type.size() - suffix.size(), suffix.size(), suffix) ==
               0;
}

bool measured_wireguard_name(const std::string& value) noexcept {
    return parse_ndms_wireguard_identity(value).has_value();
}

bool eligible_import_target(const std::string& value) noexcept {
    const auto identity = parse_ndms_wireguard_identity(value);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity);
}

class DuplicateRejectingSax final : public nlohmann::json_sax<Json> {
public:
    bool null() override { return primitive(); }
    bool boolean(bool) override { return primitive(); }
    bool number_integer(number_integer_t) override { return primitive(); }
    bool number_unsigned(number_unsigned_t) override { return primitive(); }
    bool number_float(number_float_t, const string_t&) override {
        return primitive();
    }
    bool string(string_t&) override { return primitive(); }
    bool binary(binary_t&) override { return primitive(); }

    bool start_object(std::size_t) override {
        return start_container(true);
    }

    bool key(string_t& value) override {
        if (frames_.empty() || !frames_.back().object) {
            invalid_syntax = true;
            return false;
        }
        ++key_count;
        if (key_count > kMaximumKeys || value.size() > kMaximumKeyBytes) {
            limit_exceeded = true;
            return false;
        }
        if (!frames_.back().keys.insert(value).second) {
            duplicate_key = true;
            return false;
        }
        return true;
    }

    bool end_object() override { return end_container(true); }

    bool start_array(std::size_t) override {
        return start_container(false);
    }

    bool end_array() override { return end_container(false); }

    bool parse_error(std::size_t,
                     const std::string&,
                     const nlohmann::detail::exception&) override {
        invalid_syntax = true;
        return false;
    }

    bool duplicate_key{false};
    bool limit_exceeded{false};
    bool invalid_syntax{false};
    std::size_t maximum_depth{0U};
    std::size_t node_count{0U};
    std::size_t object_count{0U};
    std::size_t array_count{0U};
    std::size_t key_count{0U};

private:
    struct Frame {
        explicit Frame(const bool is_object) : object(is_object) {}
        bool object;
        std::set<std::string> keys;
    };

    bool add_node() {
        ++node_count;
        if (node_count > kMaximumNodes) {
            limit_exceeded = true;
            return false;
        }
        return true;
    }

    bool primitive() { return add_node(); }

    bool start_container(const bool object) {
        if (!add_node()) return false;
        frames_.emplace_back(object);
        if (object) {
            ++object_count;
        } else {
            ++array_count;
        }
        maximum_depth = std::max(maximum_depth, frames_.size());
        if (frames_.size() > kMaximumDepth) {
            limit_exceeded = true;
            return false;
        }
        return true;
    }

    bool end_container(const bool object) {
        if (frames_.empty() || frames_.back().object != object) {
            invalid_syntax = true;
            return false;
        }
        frames_.pop_back();
        return true;
    }

    std::vector<Frame> frames_;
};

bool known_manifest_key(const std::string& key) {
    static const std::set<std::string> keys{
        "interface", "wireguard", "import", "status", "error",
        "errors", "code", "message", "ident", "created",
        "intersects"};
    return keys.find(key) != keys.end();
}

bool sensitive_key(const std::string& raw_key) {
    auto key = raw_key;
    std::transform(
        key.begin(), key.end(), key.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    static const std::set<std::string> keys{
        "private-key", "private_key", "preshared-key",
        "preshared_key", "privatekey", "presharedkey", "password",
        "secret", "token"};
    return keys.find(key) != keys.end();
}

NdmsNativeImportJsonValueKind json_value_kind(const Json& value) noexcept {
    if (value.is_null()) return NdmsNativeImportJsonValueKind::null_value;
    if (value.is_boolean()) return NdmsNativeImportJsonValueKind::boolean;
    if (value.is_number_unsigned()) {
        return NdmsNativeImportJsonValueKind::unsigned_integer;
    }
    if (value.is_number_integer()) {
        return NdmsNativeImportJsonValueKind::integer;
    }
    if (value.is_number_float()) {
        return NdmsNativeImportJsonValueKind::floating;
    }
    if (value.is_string()) return NdmsNativeImportJsonValueKind::string;
    if (value.is_object()) return NdmsNativeImportJsonValueKind::object;
    return NdmsNativeImportJsonValueKind::array;
}

void merge_kind(NdmsNativeImportJsonValueKind& aggregate,
                const NdmsNativeImportJsonValueKind observed) noexcept {
    if (aggregate == NdmsNativeImportJsonValueKind::absent) {
        aggregate = observed;
    } else if (aggregate != observed) {
        aggregate = NdmsNativeImportJsonValueKind::mixed;
    }
}

NdmsNativeImportStatusTokenKind status_token_kind(const Json& value) {
    if (!value.is_string()) return NdmsNativeImportStatusTokenKind::opaque;
    const auto token = ascii_lower_trimmed(
        value.get_ref<const std::string&>());
    if (token == "ok") return NdmsNativeImportStatusTokenKind::ok;
    if (token == "success") return NdmsNativeImportStatusTokenKind::success;
    if (token == "succeeded") {
        return NdmsNativeImportStatusTokenKind::succeeded;
    }
    if (token == "done") return NdmsNativeImportStatusTokenKind::done;
    if (token == "completed") {
        return NdmsNativeImportStatusTokenKind::completed;
    }
    if (token == "error") return NdmsNativeImportStatusTokenKind::error;
    if (token == "failed") return NdmsNativeImportStatusTokenKind::failed;
    if (token == "failure") {
        return NdmsNativeImportStatusTokenKind::failure;
    }
    if (token == "denied") return NdmsNativeImportStatusTokenKind::denied;
    if (token == "invalid") return NdmsNativeImportStatusTokenKind::invalid;
    return NdmsNativeImportStatusTokenKind::opaque;
}

void merge_token_kind(NdmsNativeImportStatusTokenKind& aggregate,
                      const NdmsNativeImportStatusTokenKind observed) noexcept {
    if (aggregate == NdmsNativeImportStatusTokenKind::absent) {
        aggregate = observed;
    } else if (aggregate != observed) {
        aggregate = NdmsNativeImportStatusTokenKind::mixed;
    }
}

std::string diagnostic_bytes(const Json& value) {
    if (value.is_string()) return value.get_ref<const std::string&>();
    return value.dump();
}

class RedactedDigest final {
public:
    void add(const std::string& value) {
        const auto length = std::to_string(value.size());
        hasher_.update(length);
        static constexpr char separator = ':';
        hasher_.update(&separator, 1U);
        hasher_.update(value);
        static constexpr char terminator = ';';
        hasher_.update(&terminator, 1U);
        bytes_ += value.size();
        ++count_;
    }

    std::size_t bytes() const noexcept { return bytes_; }
    std::size_t count() const noexcept { return count_; }

    std::string finish() {
        return count_ == 0U ? std::string{} : hasher_.hex_digest();
    }

private:
    Sha256 hasher_;
    std::size_t bytes_{0U};
    std::size_t count_{0U};
};

bool canonical_decimal_string(const std::string& candidate) {
    if (candidate.empty()) return false;
    std::size_t offset = candidate.front() == '-' ? 1U : 0U;
    if (offset == candidate.size()) return false;
    if (candidate.size() - offset > 1U && candidate[offset] == '0') {
        return false;
    }
    if (!std::all_of(
            candidate.begin() + static_cast<std::ptrdiff_t>(offset),
            candidate.end(), [](const unsigned char character) {
                return character >= '0' && character <= '9';
            })) {
        return false;
    }
    const auto digits = std::string_view{candidate}.substr(offset);
    if (candidate.front() == '-') {
        if (digits == "0") return false;
        constexpr std::string_view maximum{"9223372036854775808"};
        if (digits.size() > maximum.size() ||
            (digits.size() == maximum.size() && digits > maximum)) {
            return false;
        }
    } else {
        constexpr std::string_view maximum{"18446744073709551615"};
        if (digits.size() > maximum.size() ||
            (digits.size() == maximum.size() && digits > maximum)) {
            return false;
        }
    }
    return true;
}

bool canonical_decimal_code(const Json& value, std::string& output) {
    if (value.is_number_integer() || value.is_number_unsigned()) {
        output = value.dump();
        return true;
    }
    if (!value.is_string()) return false;
    const auto& candidate = value.get_ref<const std::string&>();
    if (!canonical_decimal_string(candidate)) return false;
    output = candidate;
    return true;
}

bool lowercase_hex_digest(const std::string& value) {
    return value.size() == 64U &&
           std::all_of(
               value.begin(), value.end(),
               [](const unsigned char character) {
                   return (character >= '0' && character <= '9') ||
                          (character >= 'a' && character <= 'f');
               });
}

void count_key(const std::string& key,
               NdmsNativeImportResponseManifestV2& manifest) {
    if (!known_manifest_key(key)) ++manifest.unknown_key_count;
    if (sensitive_key(key)) ++manifest.sensitive_key_count;

    if (key == "interface") ++manifest.interface_key_count;
    else if (key == "wireguard") ++manifest.wireguard_key_count;
    else if (key == "import") ++manifest.import_key_count;
    else if (key == "status") ++manifest.status_key_count;
    else if (key == "error") ++manifest.error_key_count;
    else if (key == "errors") ++manifest.errors_key_count;
    else if (key == "code") ++manifest.code_key_count;
    else if (key == "message") ++manifest.message_key_count;
    else if (key == "ident") ++manifest.ident_key_count;
    else if (key == "created") ++manifest.created_key_count;
    else if (key == "intersects") ++manifest.intersects_key_count;
}

void inspect_status_value(
    const Json& value,
    NdmsNativeImportResponseManifestV2& manifest) {
    if (!value.is_string()) {
        ++manifest.status_unknown_value_count;
        return;
    }
    const auto token = ascii_lower_trimmed(
        value.get_ref<const std::string&>());
    if (token == "ok" || token == "success" || token == "succeeded" ||
        token == "done" || token == "completed") {
        ++manifest.status_success_token_count;
        return;
    }
    if (token == "error" || token == "failed" || token == "failure" ||
        token == "denied" || token == "invalid") {
        ++manifest.status_failure_token_count;
        return;
    }
    ++manifest.status_unknown_value_count;
}

void inspect_tree(const Json& value,
                  NdmsNativeImportResponseManifestV2& manifest,
                  const Json* import_object,
                  const Json* wireguard_object,
                  const Json*& sole_outer_status,
                  std::size_t& outer_status_count,
                  const bool within_status_payload = false) {
    if (value.is_object()) {
        for (auto iterator = value.begin(); iterator != value.end();
             ++iterator) {
            count_key(iterator.key(), manifest);
            if (iterator.key() == "import" &&
                !iterator.value().is_object()) {
                ++manifest.sensitive_key_count;
            }
            if (iterator.key() == "status") {
                inspect_status_value(iterator.value(), manifest);
                if (!within_status_payload) {
                    ++outer_status_count;
                    sole_outer_status = outer_status_count == 1U
                        ? &iterator.value()
                        : nullptr;
                    if (&value == import_object) {
                        ++manifest.status_import_direct_key_count;
                    } else if (&value == wireguard_object) {
                        ++manifest.status_wireguard_sibling_key_count;
                    } else {
                        ++manifest.status_other_key_count;
                    }
                }
            }
            inspect_tree(
                iterator.value(), manifest, import_object, wireguard_object,
                sole_outer_status, outer_status_count,
                within_status_payload || iterator.key() == "status");
        }
    } else if (value.is_array()) {
        for (const auto& item : value) {
            inspect_tree(
                item, manifest, import_object, wireguard_object,
                sole_outer_status, outer_status_count,
                within_status_payload);
        }
    }
}

bool exact_keys(const Json& object,
                const std::initializer_list<const char*> keys) {
    if (!object.is_object() || object.size() != keys.size()) return false;
    return std::all_of(
        keys.begin(), keys.end(), [&object](const char* key) {
            return object.find(key) != object.end();
        });
}

const Json* locate_import_object(
    const Json& root,
    NdmsNativeImportResponseManifestV2& manifest) {
    if (!root.is_array() || root.size() != 1U ||
        !root.front().is_object()) {
        return nullptr;
    }
    const auto interface = root.front().find("interface");
    if (interface == root.front().end() || !interface->is_object()) {
        return nullptr;
    }
    const auto wireguard = interface->find("wireguard");
    if (wireguard == interface->end() || !wireguard->is_object()) {
        return nullptr;
    }
    const auto import = wireguard->find("import");
    if (import == wireguard->end() || !import->is_object()) return nullptr;
    manifest.import_path_count = 1U;
    return &*import;
}

const Json* locate_wireguard_object(const Json& root) {
    if (!root.is_array() || root.size() != 1U ||
        !root.front().is_object()) {
        return nullptr;
    }
    const auto interface = root.front().find("interface");
    if (interface == root.front().end() || !interface->is_object()) {
        return nullptr;
    }
    const auto wireguard = interface->find("wireguard");
    if (wireguard == interface->end() || !wireguard->is_object()) {
        return nullptr;
    }
    return &*wireguard;
}

bool known_direct_status_record_key(const std::string& key) {
    return key == "status" || key == "code" || key == "ident" ||
           key == "message" || key == "error" || key == "errors";
}

void inspect_direct_status_record(
    const Json& record,
    NdmsNativeImportResponseManifestV2& manifest,
    RedactedDigest& status_digest,
    RedactedDigest& code_digest,
    RedactedDigest& ident_digest,
    RedactedDigest& message_digest,
    std::string& decimal_code,
    bool& all_codes_decimal) {
    ++manifest.direct_status_record_count;
    manifest.direct_status_record_key_count += record.size();
    for (auto iterator = record.begin(); iterator != record.end(); ++iterator) {
        if (!known_direct_status_record_key(iterator.key())) {
            ++manifest.direct_status_record_unknown_key_count;
        }
        if (iterator.key() == "status") {
            ++manifest.direct_record_status_key_count;
            merge_kind(
                manifest.direct_record_status_value_kind,
                json_value_kind(iterator.value()));
            merge_token_kind(
                manifest.direct_record_status_token,
                status_token_kind(iterator.value()));
            status_digest.add(diagnostic_bytes(iterator.value()));
        } else if (iterator.key() == "code") {
            ++manifest.direct_record_code_key_count;
            merge_kind(
                manifest.direct_record_code_value_kind,
                json_value_kind(iterator.value()));
            std::string candidate;
            if (!canonical_decimal_code(iterator.value(), candidate)) {
                all_codes_decimal = false;
            } else if (decimal_code.empty()) {
                decimal_code = std::move(candidate);
            }
            code_digest.add(diagnostic_bytes(iterator.value()));
        } else if (iterator.key() == "ident") {
            ++manifest.direct_record_ident_key_count;
            merge_kind(
                manifest.direct_record_ident_value_kind,
                json_value_kind(iterator.value()));
            ident_digest.add(diagnostic_bytes(iterator.value()));
        } else if (iterator.key() == "message") {
            ++manifest.direct_record_message_key_count;
            merge_kind(
                manifest.direct_record_message_value_kind,
                json_value_kind(iterator.value()));
            message_digest.add(diagnostic_bytes(iterator.value()));
        }
    }
}

void inspect_direct_status(
    const Json& value,
    NdmsNativeImportResponseManifestV2& manifest) {
    manifest.direct_status_value_kind = json_value_kind(value);
    RedactedDigest status_digest;
    RedactedDigest code_digest;
    RedactedDigest ident_digest;
    RedactedDigest message_digest;
    std::string decimal_code;
    bool all_codes_decimal = true;

    const auto inspect_record = [&](const Json& record) {
        inspect_direct_status_record(
            record, manifest, status_digest, code_digest, ident_digest,
            message_digest, decimal_code, all_codes_decimal);
    };
    if (value.is_array()) {
        manifest.direct_status_array_length = value.size();
        for (const auto& item : value) {
            if (item.is_object()) {
                inspect_record(item);
            } else {
                ++manifest.direct_status_nonrecord_count;
            }
        }
    } else if (value.is_object()) {
        inspect_record(value);
    } else {
        manifest.direct_status_nonrecord_count = 1U;
    }

    manifest.direct_record_status_bytes = status_digest.bytes();
    manifest.direct_record_status_sha256 = status_digest.finish();
    manifest.direct_record_code_bytes = code_digest.bytes();
    manifest.direct_record_code_sha256 = code_digest.finish();
    manifest.direct_record_ident_bytes = ident_digest.bytes();
    manifest.direct_record_ident_sha256 = ident_digest.finish();
    manifest.direct_record_message_bytes = message_digest.bytes();
    manifest.direct_record_message_sha256 = message_digest.finish();

    if (code_digest.count() == 0U) {
        manifest.direct_record_code_evidence =
            NdmsNativeImportCodeEvidence::absent;
    } else if (code_digest.count() == 1U && all_codes_decimal) {
        manifest.direct_record_code_evidence =
            NdmsNativeImportCodeEvidence::decimal;
        manifest.direct_record_code_decimal = std::move(decimal_code);
    } else if (code_digest.count() == 1U) {
        manifest.direct_record_code_evidence =
            NdmsNativeImportCodeEvidence::opaque;
    } else {
        manifest.direct_record_code_evidence =
            NdmsNativeImportCodeEvidence::mixed;
    }
}

void inspect_direct_import(
    const Json& object,
    const std::string& expected_created_interface,
    NdmsNativeImportResponseManifestV2& manifest) {
    manifest.direct_import_key_count = object.size();
    manifest.direct_status_key_count = object.count("status");
    manifest.direct_code_key_count = object.count("code");
    manifest.direct_message_key_count = object.count("message");
    manifest.direct_ident_key_count = object.count("ident");

    const auto created = object.find("created");
    if (created == object.end()) {
        manifest.created_evidence =
            NdmsNativeImportCreatedEvidence::absent;
    } else if (!created->is_string()) {
        manifest.created_evidence =
            NdmsNativeImportCreatedEvidence::invalid;
    } else {
        const auto& value = created->get_ref<const std::string&>();
        if (value == expected_created_interface) {
            manifest.created_evidence =
                NdmsNativeImportCreatedEvidence::expected;
        } else if (measured_wireguard_name(value)) {
            manifest.created_evidence =
                NdmsNativeImportCreatedEvidence::other_wireguard;
        } else {
            manifest.created_evidence =
                NdmsNativeImportCreatedEvidence::invalid;
        }
    }

    const auto intersects = object.find("intersects");
    if (intersects == object.end()) {
        manifest.intersects_evidence =
            NdmsNativeImportIntersectsEvidence::absent;
    } else if (!intersects->is_string()) {
        manifest.intersects_evidence =
            NdmsNativeImportIntersectsEvidence::invalid;
    } else if (intersects->get_ref<const std::string&>().empty()) {
        manifest.intersects_evidence =
            NdmsNativeImportIntersectsEvidence::empty;
    } else {
        manifest.intersects_evidence =
            NdmsNativeImportIntersectsEvidence::nonempty;
    }
}

bool exact_two_field_envelope(const Json& root) {
    if (!root.is_array() || root.size() != 1U) return false;
    const auto& batch_item = root.front();
    if (!exact_keys(batch_item, {"interface"})) return false;
    const auto& interface = batch_item.at("interface");
    if (!exact_keys(interface, {"wireguard"})) return false;
    const auto& wireguard = interface.at("wireguard");
    if (!exact_keys(wireguard, {"import"})) return false;
    return exact_keys(wireguard.at("import"), {"created", "intersects"});
}

void classify_status(NdmsNativeImportResponseManifestV2& manifest) {
    if (manifest.status_key_count == 0U) {
        manifest.status_evidence = NdmsNativeImportStatusEvidence::absent;
    } else if (manifest.status_failure_token_count != 0U) {
        manifest.status_evidence = NdmsNativeImportStatusEvidence::failure;
    } else if (manifest.status_unknown_value_count != 0U ||
               manifest.status_success_token_count !=
                   manifest.status_key_count) {
        manifest.status_evidence = NdmsNativeImportStatusEvidence::unknown;
    } else {
        manifest.status_evidence = NdmsNativeImportStatusEvidence::success;
    }

    const auto import_direct =
        manifest.status_import_direct_key_count != 0U;
    const auto wireguard_sibling =
        manifest.status_wireguard_sibling_key_count != 0U;
    const auto other = manifest.status_other_key_count != 0U;
    const auto location_k = static_cast<unsigned int>(import_direct) +
                            static_cast<unsigned int>(wireguard_sibling) +
                            static_cast<unsigned int>(other);
    if (location_k == 0U) {
        manifest.status_location = NdmsNativeImportStatusLocation::absent;
    } else if (location_k > 1U) {
        manifest.status_location = NdmsNativeImportStatusLocation::multiple;
    } else if (import_direct) {
        manifest.status_location =
            NdmsNativeImportStatusLocation::import_direct;
    } else if (wireguard_sibling) {
        manifest.status_location =
            NdmsNativeImportStatusLocation::wireguard_sibling;
    } else {
        manifest.status_location = NdmsNativeImportStatusLocation::other;
    }
}

void append_field(std::string& output,
                  const char* key,
                  const std::string& value) {
    output.push_back('|');
    output.append(key);
    output.push_back('=');
    output.append(value);
}

void append_digest_field(std::string& output,
                         const char* key,
                         const std::string& value) {
    append_field(
        output, key,
        value.empty() || lowercase_hex_digest(value)
            ? value
            : std::string{"invalid"});
}

void append_decimal_field(std::string& output,
                          const char* key,
                          const std::string& value) {
    append_field(
        output, key,
        value.empty() || canonical_decimal_string(value)
            ? value
            : std::string{"invalid"});
}

void append_field(std::string& output,
                  const char* key,
                  const char* value) {
    append_field(output, key, std::string{value});
}

void append_field(std::string& output,
                  const char* key,
                  const std::size_t value) {
    append_field(output, key, std::to_string(value));
}

void append_field(std::string& output,
                  const char* key,
                  const int value) {
    append_field(output, key, std::to_string(value));
}

void append_field(std::string& output,
                  const char* key,
                  const bool value) {
    append_field(output, key, value ? "1" : "0");
}

} // namespace

NdmsNativeImportResponseManifestV2
inspect_ndms_native_import_response_v2(
    const NdmsNativeImportHttpResponseView& response,
    const std::string& expected_created_interface) {
    NdmsNativeImportResponseManifestV2 manifest;
    manifest.body_bytes = response.body.size();
    manifest.transport_ok = response.transport_ok;
    manifest.http_status = response.status_code;
    manifest.content_type_is_json = json_content_type(response.content_type);

    if (response.body.size() > kNdmsNativeImportMaximumResponseBytes) {
        manifest.outcome = NdmsNativeImportResponseOutcome::body_too_large;
        return manifest;
    }
    Sha256 response_hasher;
    response_hasher.update(response.body.data(), response.body.size());
    manifest.body_sha256 = response_hasher.hex_digest();

    if (!measured_wireguard_name(expected_created_interface)) {
        manifest.outcome =
            NdmsNativeImportResponseOutcome::expected_target_invalid;
        return manifest;
    }
    if (!eligible_import_target(expected_created_interface)) {
        manifest.outcome =
            NdmsNativeImportResponseOutcome::expected_target_ineligible;
        return manifest;
    }
    if (!response.transport_ok) {
        manifest.outcome = NdmsNativeImportResponseOutcome::transport_failed;
        return manifest;
    }
    if (response.status_code != 200) {
        manifest.outcome =
            NdmsNativeImportResponseOutcome::http_status_not_200;
        return manifest;
    }
    if (!manifest.content_type_is_json) {
        manifest.outcome =
            NdmsNativeImportResponseOutcome::content_type_not_json;
        return manifest;
    }
    if (response.body.empty()) {
        manifest.outcome = NdmsNativeImportResponseOutcome::body_empty;
        return manifest;
    }
    DuplicateRejectingSax preflight;
    const bool preflight_ok = Json::sax_parse(
        response.body.begin(), response.body.end(), &preflight);
    manifest.maximum_depth = preflight.maximum_depth;
    manifest.node_count = preflight.node_count;
    manifest.object_count = preflight.object_count;
    manifest.array_count = preflight.array_count;
    manifest.key_count = preflight.key_count;
    if (!preflight_ok) {
        if (preflight.duplicate_key) {
            manifest.json_state = NdmsNativeImportJsonState::duplicate_key;
            manifest.outcome =
                NdmsNativeImportResponseOutcome::duplicate_key;
        } else if (preflight.limit_exceeded) {
            manifest.json_state =
                NdmsNativeImportJsonState::structural_limit_exceeded;
            manifest.outcome = NdmsNativeImportResponseOutcome::
                structural_limit_exceeded;
        } else {
            manifest.json_state =
                NdmsNativeImportJsonState::invalid_syntax;
            manifest.outcome = NdmsNativeImportResponseOutcome::invalid_json;
        }
        return manifest;
    }

    Json root;
    try {
        root = Json::parse(response.body.begin(), response.body.end());
    } catch (const Json::exception&) {
        manifest.json_state = NdmsNativeImportJsonState::invalid_syntax;
        manifest.outcome = NdmsNativeImportResponseOutcome::invalid_json;
        return manifest;
    }
    manifest.json_state = NdmsNativeImportJsonState::valid;
    if (root.is_array()) {
        manifest.root_kind = NdmsNativeImportRootKind::array;
        manifest.root_item_count = root.size();
    } else if (root.is_object()) {
        manifest.root_kind = NdmsNativeImportRootKind::object;
        manifest.root_item_count = root.size();
    } else {
        manifest.root_kind = NdmsNativeImportRootKind::scalar;
        manifest.root_item_count = 1U;
    }

    const auto* import = locate_import_object(root, manifest);
    const auto* wireguard = locate_wireguard_object(root);
    const Json* located_status = nullptr;
    std::size_t outer_status_count = 0U;
    inspect_tree(
        root, manifest, import, wireguard, located_status,
        outer_status_count);
    classify_status(manifest);
    if (import != nullptr) {
        inspect_direct_import(
            *import, expected_created_interface, manifest);
    }
    if (located_status != nullptr) {
        inspect_direct_status(*located_status, manifest);
    }
    manifest.exact_two_field_shape = exact_two_field_envelope(root);

    if (manifest.error_key_count != 0U ||
        manifest.errors_key_count != 0U ||
        manifest.status_evidence ==
            NdmsNativeImportStatusEvidence::failure) {
        manifest.outcome = NdmsNativeImportResponseOutcome::explicit_failure;
        return manifest;
    }
    if (manifest.status_evidence == NdmsNativeImportStatusEvidence::unknown) {
        manifest.outcome = NdmsNativeImportResponseOutcome::status_unknown;
        return manifest;
    }
    if (!manifest.exact_two_field_shape) {
        manifest.outcome = NdmsNativeImportResponseOutcome::shape_mismatch;
        return manifest;
    }
    if (manifest.intersects_evidence !=
        NdmsNativeImportIntersectsEvidence::empty) {
        manifest.outcome = NdmsNativeImportResponseOutcome::
            intersections_nonempty;
        return manifest;
    }
    if (manifest.created_evidence !=
        NdmsNativeImportCreatedEvidence::expected) {
        manifest.outcome = NdmsNativeImportResponseOutcome::created_mismatch;
        return manifest;
    }
    manifest.outcome =
        NdmsNativeImportResponseOutcome::exact_two_field_success;
    return manifest;
}

NdmsNativeImportResponseManifestV2
inspect_ndms_native_import_response_v2(
    const NdmsNativeImportHttpResponse& response,
    const std::string& expected_created_interface) {
    return inspect_ndms_native_import_response_v2(
        NdmsNativeImportHttpResponseView{
            response.transport_ok,
            response.status_code,
            response.content_type,
            response.body},
        expected_created_interface);
}

std::string serialize_ndms_native_import_response_manifest_v2(
    const NdmsNativeImportResponseManifestV2& manifest) {
    std::string output{"ndms-native-import-response-v2"};
    append_field(output, "body_bytes", manifest.body_bytes);
    append_digest_field(output, "body_sha256", manifest.body_sha256);
    append_field(output, "transport_ok", manifest.transport_ok);
    append_field(output, "http_status", manifest.http_status);
    append_field(output, "content_json", manifest.content_type_is_json);
    append_field(output, "json", to_string(manifest.json_state));
    append_field(output, "root", to_string(manifest.root_kind));
    append_field(output, "root_items", manifest.root_item_count);
    append_field(output, "depth", manifest.maximum_depth);
    append_field(output, "nodes", manifest.node_count);
    append_field(output, "objects", manifest.object_count);
    append_field(output, "arrays", manifest.array_count);
    append_field(output, "keys", manifest.key_count);
    append_field(output, "unknown_k", manifest.unknown_key_count);
    append_field(output, "sensitive_k", manifest.sensitive_key_count);
    append_field(output, "interface_k", manifest.interface_key_count);
    append_field(output, "wireguard_k", manifest.wireguard_key_count);
    append_field(output, "import_k", manifest.import_key_count);
    append_field(output, "status_k", manifest.status_key_count);
    append_field(output, "error_k", manifest.error_key_count);
    append_field(output, "errors_k", manifest.errors_key_count);
    append_field(output, "code_k", manifest.code_key_count);
    append_field(output, "message_k", manifest.message_key_count);
    append_field(output, "ident_k", manifest.ident_key_count);
    append_field(output, "created_k", manifest.created_key_count);
    append_field(output, "intersects_k", manifest.intersects_key_count);
    append_field(
        output, "status_success_k", manifest.status_success_token_count);
    append_field(
        output, "status_failure_k", manifest.status_failure_token_count);
    append_field(
        output, "status_unknown_k", manifest.status_unknown_value_count);
    append_field(output, "status", to_string(manifest.status_evidence));
    append_field(
        output, "status_import_direct_k",
        manifest.status_import_direct_key_count);
    append_field(
        output, "status_wireguard_sibling_k",
        manifest.status_wireguard_sibling_key_count);
    append_field(
        output, "status_other_k", manifest.status_other_key_count);
    append_field(
        output, "status_location", to_string(manifest.status_location));
    append_field(output, "import_path_k", manifest.import_path_count);
    append_field(
        output, "direct_import_k", manifest.direct_import_key_count);
    append_field(
        output, "direct_status_k", manifest.direct_status_key_count);
    append_field(output, "direct_code_k", manifest.direct_code_key_count);
    append_field(
        output, "direct_message_k", manifest.direct_message_key_count);
    append_field(output, "direct_ident_k", manifest.direct_ident_key_count);
    append_field(
        output, "direct_status_type",
        to_string(manifest.direct_status_value_kind));
    append_field(
        output, "direct_status_array_len",
        manifest.direct_status_array_length);
    append_field(
        output, "direct_status_record_k",
        manifest.direct_status_record_count);
    append_field(
        output, "direct_status_nonrecord_k",
        manifest.direct_status_nonrecord_count);
    append_field(
        output, "record_keys", manifest.direct_status_record_key_count);
    append_field(
        output, "record_unknown_k",
        manifest.direct_status_record_unknown_key_count);
    append_field(
        output, "record_status_k",
        manifest.direct_record_status_key_count);
    append_field(
        output, "record_code_k", manifest.direct_record_code_key_count);
    append_field(
        output, "record_ident_k", manifest.direct_record_ident_key_count);
    append_field(
        output, "record_message_k",
        manifest.direct_record_message_key_count);
    append_field(
        output, "record_status_type",
        to_string(manifest.direct_record_status_value_kind));
    append_field(
        output, "record_code_type",
        to_string(manifest.direct_record_code_value_kind));
    append_field(
        output, "record_ident_type",
        to_string(manifest.direct_record_ident_value_kind));
    append_field(
        output, "record_message_type",
        to_string(manifest.direct_record_message_value_kind));
    append_field(
        output, "record_status_token",
        to_string(manifest.direct_record_status_token));
    append_field(
        output, "record_status_bytes",
        manifest.direct_record_status_bytes);
    append_digest_field(
        output, "record_status_sha256",
        manifest.direct_record_status_sha256);
    append_field(
        output, "record_code_evidence",
        to_string(manifest.direct_record_code_evidence));
    append_field(
        output, "record_code_bytes", manifest.direct_record_code_bytes);
    append_decimal_field(
        output, "record_code_decimal",
        manifest.direct_record_code_decimal);
    append_digest_field(
        output, "record_code_sha256",
        manifest.direct_record_code_sha256);
    append_field(
        output, "record_ident_bytes", manifest.direct_record_ident_bytes);
    append_digest_field(
        output, "record_ident_sha256",
        manifest.direct_record_ident_sha256);
    append_field(
        output, "record_message_bytes",
        manifest.direct_record_message_bytes);
    append_digest_field(
        output, "record_message_sha256",
        manifest.direct_record_message_sha256);
    append_field(output, "created", to_string(manifest.created_evidence));
    append_field(
        output, "intersects", to_string(manifest.intersects_evidence));
    append_field(output, "exact_shape", manifest.exact_two_field_shape);
    append_field(output, "outcome", to_string(manifest.outcome));
    return output;
}

const char* to_string(const NdmsNativeImportJsonState value) noexcept {
    switch (value) {
    case NdmsNativeImportJsonState::not_inspected: return "not_inspected";
    case NdmsNativeImportJsonState::valid: return "valid";
    case NdmsNativeImportJsonState::invalid_syntax: return "invalid_syntax";
    case NdmsNativeImportJsonState::duplicate_key: return "duplicate_key";
    case NdmsNativeImportJsonState::structural_limit_exceeded:
        return "structural_limit_exceeded";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportRootKind value) noexcept {
    switch (value) {
    case NdmsNativeImportRootKind::not_inspected: return "not_inspected";
    case NdmsNativeImportRootKind::array: return "array";
    case NdmsNativeImportRootKind::object: return "object";
    case NdmsNativeImportRootKind::scalar: return "scalar";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportStatusEvidence value) noexcept {
    switch (value) {
    case NdmsNativeImportStatusEvidence::absent: return "absent";
    case NdmsNativeImportStatusEvidence::success: return "success";
    case NdmsNativeImportStatusEvidence::failure: return "failure";
    case NdmsNativeImportStatusEvidence::unknown: return "unknown";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportStatusLocation value) noexcept {
    switch (value) {
    case NdmsNativeImportStatusLocation::absent: return "absent";
    case NdmsNativeImportStatusLocation::import_direct:
        return "import_direct";
    case NdmsNativeImportStatusLocation::wireguard_sibling:
        return "wireguard_sibling";
    case NdmsNativeImportStatusLocation::other: return "other";
    case NdmsNativeImportStatusLocation::multiple: return "multiple";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportJsonValueKind value) noexcept {
    switch (value) {
    case NdmsNativeImportJsonValueKind::absent: return "absent";
    case NdmsNativeImportJsonValueKind::null_value: return "null";
    case NdmsNativeImportJsonValueKind::boolean: return "boolean";
    case NdmsNativeImportJsonValueKind::integer: return "integer";
    case NdmsNativeImportJsonValueKind::unsigned_integer:
        return "unsigned_integer";
    case NdmsNativeImportJsonValueKind::floating: return "floating";
    case NdmsNativeImportJsonValueKind::string: return "string";
    case NdmsNativeImportJsonValueKind::object: return "object";
    case NdmsNativeImportJsonValueKind::array: return "array";
    case NdmsNativeImportJsonValueKind::mixed: return "mixed";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportStatusTokenKind value) noexcept {
    switch (value) {
    case NdmsNativeImportStatusTokenKind::absent: return "absent";
    case NdmsNativeImportStatusTokenKind::ok: return "ok";
    case NdmsNativeImportStatusTokenKind::success: return "success";
    case NdmsNativeImportStatusTokenKind::succeeded: return "succeeded";
    case NdmsNativeImportStatusTokenKind::done: return "done";
    case NdmsNativeImportStatusTokenKind::completed: return "completed";
    case NdmsNativeImportStatusTokenKind::error: return "error";
    case NdmsNativeImportStatusTokenKind::failed: return "failed";
    case NdmsNativeImportStatusTokenKind::failure: return "failure";
    case NdmsNativeImportStatusTokenKind::denied: return "denied";
    case NdmsNativeImportStatusTokenKind::invalid: return "invalid";
    case NdmsNativeImportStatusTokenKind::opaque: return "opaque";
    case NdmsNativeImportStatusTokenKind::mixed: return "mixed";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportCodeEvidence value) noexcept {
    switch (value) {
    case NdmsNativeImportCodeEvidence::absent: return "absent";
    case NdmsNativeImportCodeEvidence::decimal: return "decimal";
    case NdmsNativeImportCodeEvidence::opaque: return "opaque";
    case NdmsNativeImportCodeEvidence::mixed: return "mixed";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportCreatedEvidence value) noexcept {
    switch (value) {
    case NdmsNativeImportCreatedEvidence::absent: return "absent";
    case NdmsNativeImportCreatedEvidence::expected: return "expected";
    case NdmsNativeImportCreatedEvidence::other_wireguard:
        return "other_wireguard";
    case NdmsNativeImportCreatedEvidence::invalid: return "invalid";
    }
    return "unknown";
}

const char* to_string(
    const NdmsNativeImportIntersectsEvidence value) noexcept {
    switch (value) {
    case NdmsNativeImportIntersectsEvidence::absent: return "absent";
    case NdmsNativeImportIntersectsEvidence::empty: return "empty";
    case NdmsNativeImportIntersectsEvidence::nonempty: return "nonempty";
    case NdmsNativeImportIntersectsEvidence::invalid: return "invalid";
    }
    return "unknown";
}

const char* to_string(const NdmsNativeImportResponseOutcome value) noexcept {
    switch (value) {
    case NdmsNativeImportResponseOutcome::expected_target_invalid:
        return "expected_target_invalid";
    case NdmsNativeImportResponseOutcome::expected_target_ineligible:
        return "expected_target_ineligible";
    case NdmsNativeImportResponseOutcome::transport_failed:
        return "transport_failed";
    case NdmsNativeImportResponseOutcome::http_status_not_200:
        return "http_status_not_200";
    case NdmsNativeImportResponseOutcome::content_type_not_json:
        return "content_type_not_json";
    case NdmsNativeImportResponseOutcome::body_empty: return "body_empty";
    case NdmsNativeImportResponseOutcome::body_too_large:
        return "body_too_large";
    case NdmsNativeImportResponseOutcome::invalid_json: return "invalid_json";
    case NdmsNativeImportResponseOutcome::duplicate_key:
        return "duplicate_key";
    case NdmsNativeImportResponseOutcome::structural_limit_exceeded:
        return "structural_limit_exceeded";
    case NdmsNativeImportResponseOutcome::explicit_failure:
        return "explicit_failure";
    case NdmsNativeImportResponseOutcome::status_unknown:
        return "status_unknown";
    case NdmsNativeImportResponseOutcome::shape_mismatch:
        return "shape_mismatch";
    case NdmsNativeImportResponseOutcome::created_mismatch:
        return "created_mismatch";
    case NdmsNativeImportResponseOutcome::intersections_nonempty:
        return "intersections_nonempty";
    case NdmsNativeImportResponseOutcome::exact_two_field_success:
        return "exact_two_field_success";
    }
    return "unknown";
}

} // namespace keen_pbr3
