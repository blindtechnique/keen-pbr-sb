#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// Transport-neutral input for the pure stock-import response inspector. The
// caller owns authentication, the endpoint and the response lifetime.
struct NdmsNativeImportHttpResponse {
    bool transport_ok{false};
    int status_code{0};
    std::string content_type;
    std::string body;
};

// Non-owning view for secret-aware transports. It lets a caller inspect a
// response directly inside a move-only, wiping buffer without first creating
// an ordinary std::string copy whose destructor would leave the bytes behind.
// The referenced storage must remain alive for the duration of the call only.
struct NdmsNativeImportHttpResponseView {
    bool transport_ok{false};
    int status_code{0};
    std::string_view content_type;
    std::string_view body;
};

enum class NdmsNativeImportJsonState {
    not_inspected,
    valid,
    invalid_syntax,
    duplicate_key,
    structural_limit_exceeded,
};

enum class NdmsNativeImportRootKind {
    not_inspected,
    array,
    object,
    scalar,
};

enum class NdmsNativeImportStatusEvidence {
    absent,
    success,
    failure,
    unknown,
};

enum class NdmsNativeImportStatusLocation {
    absent,
    import_direct,
    wireguard_sibling,
    other,
    multiple,
};

enum class NdmsNativeImportJsonValueKind {
    absent,
    null_value,
    boolean,
    integer,
    unsigned_integer,
    floating,
    string,
    object,
    array,
    mixed,
};

enum class NdmsNativeImportStatusTokenKind {
    absent,
    ok,
    success,
    succeeded,
    done,
    completed,
    error,
    failed,
    failure,
    denied,
    invalid,
    opaque,
    mixed,
};

enum class NdmsNativeImportCodeEvidence {
    absent,
    decimal,
    opaque,
    mixed,
};

enum class NdmsNativeImportCreatedEvidence {
    absent,
    expected,
    other_wireguard,
    invalid,
};

enum class NdmsNativeImportIntersectsEvidence {
    absent,
    empty,
    nonempty,
    invalid,
};

enum class NdmsNativeImportResponseOutcome {
    expected_target_invalid,
    expected_target_ineligible,
    transport_failed,
    http_status_not_200,
    content_type_not_json,
    body_empty,
    body_too_large,
    invalid_json,
    duplicate_key,
    structural_limit_exceeded,
    explicit_failure,
    status_unknown,
    shape_mismatch,
    created_mismatch,
    intersections_nonempty,
    exact_two_field_success,
};

// Redacted structural evidence. It deliberately retains no response strings,
// status message, identifier, created value, intersection value or unknown
// JSON value. body_sha256 binds diagnostics to the caller-retained response.
struct NdmsNativeImportResponseManifestV2 {
    std::size_t body_bytes{0U};
    std::string body_sha256;
    bool transport_ok{false};
    int http_status{0};
    bool content_type_is_json{false};
    NdmsNativeImportJsonState json_state{
        NdmsNativeImportJsonState::not_inspected};
    NdmsNativeImportRootKind root_kind{
        NdmsNativeImportRootKind::not_inspected};
    std::size_t root_item_count{0U};

    std::size_t maximum_depth{0U};
    std::size_t node_count{0U};
    std::size_t object_count{0U};
    std::size_t array_count{0U};
    std::size_t key_count{0U};
    std::size_t unknown_key_count{0U};
    std::size_t sensitive_key_count{0U};

    std::size_t interface_key_count{0U};
    std::size_t wireguard_key_count{0U};
    std::size_t import_key_count{0U};
    std::size_t status_key_count{0U};
    std::size_t error_key_count{0U};
    std::size_t errors_key_count{0U};
    std::size_t code_key_count{0U};
    std::size_t message_key_count{0U};
    std::size_t ident_key_count{0U};
    std::size_t created_key_count{0U};
    std::size_t intersects_key_count{0U};

    std::size_t status_success_token_count{0U};
    std::size_t status_failure_token_count{0U};
    std::size_t status_unknown_value_count{0U};
    NdmsNativeImportStatusEvidence status_evidence{
        NdmsNativeImportStatusEvidence::absent};
    std::size_t status_import_direct_key_count{0U};
    std::size_t status_wireguard_sibling_key_count{0U};
    std::size_t status_other_key_count{0U};
    NdmsNativeImportStatusLocation status_location{
        NdmsNativeImportStatusLocation::absent};

    std::size_t import_path_count{0U};
    std::size_t direct_import_key_count{0U};
    std::size_t direct_status_key_count{0U};
    std::size_t direct_code_key_count{0U};
    std::size_t direct_message_key_count{0U};
    std::size_t direct_ident_key_count{0U};
    // Structural details of the sole outer status block, wherever its
    // status_location is. Multiple outer blocks intentionally retain counts
    // only and leave these fields absent.
    NdmsNativeImportJsonValueKind direct_status_value_kind{
        NdmsNativeImportJsonValueKind::absent};
    std::size_t direct_status_array_length{0U};
    std::size_t direct_status_record_count{0U};
    std::size_t direct_status_nonrecord_count{0U};
    std::size_t direct_status_record_key_count{0U};
    std::size_t direct_status_record_unknown_key_count{0U};
    std::size_t direct_record_status_key_count{0U};
    std::size_t direct_record_code_key_count{0U};
    std::size_t direct_record_ident_key_count{0U};
    std::size_t direct_record_message_key_count{0U};
    NdmsNativeImportJsonValueKind direct_record_status_value_kind{
        NdmsNativeImportJsonValueKind::absent};
    NdmsNativeImportJsonValueKind direct_record_code_value_kind{
        NdmsNativeImportJsonValueKind::absent};
    NdmsNativeImportJsonValueKind direct_record_ident_value_kind{
        NdmsNativeImportJsonValueKind::absent};
    NdmsNativeImportJsonValueKind direct_record_message_value_kind{
        NdmsNativeImportJsonValueKind::absent};
    NdmsNativeImportStatusTokenKind direct_record_status_token{
        NdmsNativeImportStatusTokenKind::absent};
    std::size_t direct_record_status_bytes{0U};
    std::string direct_record_status_sha256;
    NdmsNativeImportCodeEvidence direct_record_code_evidence{
        NdmsNativeImportCodeEvidence::absent};
    std::size_t direct_record_code_bytes{0U};
    std::string direct_record_code_decimal;
    std::string direct_record_code_sha256;
    std::size_t direct_record_ident_bytes{0U};
    std::string direct_record_ident_sha256;
    std::size_t direct_record_message_bytes{0U};
    std::string direct_record_message_sha256;
    NdmsNativeImportCreatedEvidence created_evidence{
        NdmsNativeImportCreatedEvidence::absent};
    NdmsNativeImportIntersectsEvidence intersects_evidence{
        NdmsNativeImportIntersectsEvidence::absent};
    bool exact_two_field_shape{false};

    NdmsNativeImportResponseOutcome outcome{
        NdmsNativeImportResponseOutcome::transport_failed};

    bool success() const noexcept {
        return outcome == NdmsNativeImportResponseOutcome::
            exact_two_field_success;
    }
};

// Maximum accepted response size. The bound is part of the fail-closed parser
// contract and is exposed only to make boundary tests exact.
constexpr std::size_t kNdmsNativeImportMaximumResponseBytes =
    128U * 1024U;

NdmsNativeImportResponseManifestV2
inspect_ndms_native_import_response_v2(
    const NdmsNativeImportHttpResponse& response,
    const std::string& expected_created_interface);

NdmsNativeImportResponseManifestV2
inspect_ndms_native_import_response_v2(
    const NdmsNativeImportHttpResponseView& response,
    const std::string& expected_created_interface);

// Stable, single-line, safe-character representation for WAL/diagnostics.
// It contains fixed enumerations, counts, booleans, a bounded decimal status
// code and one-way digests; raw status/identifier/message values are omitted.
std::string serialize_ndms_native_import_response_manifest_v2(
    const NdmsNativeImportResponseManifestV2& manifest);

const char* to_string(NdmsNativeImportJsonState value) noexcept;
const char* to_string(NdmsNativeImportRootKind value) noexcept;
const char* to_string(NdmsNativeImportStatusEvidence value) noexcept;
const char* to_string(NdmsNativeImportStatusLocation value) noexcept;
const char* to_string(NdmsNativeImportJsonValueKind value) noexcept;
const char* to_string(NdmsNativeImportStatusTokenKind value) noexcept;
const char* to_string(NdmsNativeImportCodeEvidence value) noexcept;
const char* to_string(NdmsNativeImportCreatedEvidence value) noexcept;
const char* to_string(NdmsNativeImportIntersectsEvidence value) noexcept;
const char* to_string(NdmsNativeImportResponseOutcome value) noexcept;

} // namespace keen_pbr3
