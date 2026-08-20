#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_response.hpp"

#include <algorithm>
#include <string>

using namespace keen_pbr3;

namespace {

NdmsNativeImportHttpResponse json_response(std::string body) {
    return {true, 200, "application/json; charset=utf-8", std::move(body)};
}

NdmsNativeImportResponseManifestV3 inspect(std::string body) {
    return inspect_ndms_native_import_response_v3(
        json_response(std::move(body)), "Wireguard5");
}

bool safe_manifest_character(const unsigned char character) {
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') ||
           character == '_' || character == '-' || character == '=' ||
           character == '|' || character == '.';
}

} // namespace

TEST_CASE("native import response accepts only the exact two-field envelope") {
    const auto first = inspect(
        R"([{"interface":{"wireguard":{"import":{"intersects":"","created":"Wireguard5"}}}}])");
    CHECK(first.success());
    CHECK(first.outcome ==
          NdmsNativeImportResponseOutcome::exact_two_field_success);
    CHECK(first.json_state == NdmsNativeImportJsonState::valid);
    CHECK(first.root_kind == NdmsNativeImportRootKind::array);
    CHECK(first.root_item_count == 1U);
    CHECK(first.import_path_count == 1U);
    CHECK(first.direct_import_key_count == 2U);
    CHECK(first.created_evidence ==
          NdmsNativeImportCreatedEvidence::expected);
    CHECK(first.intersects_evidence ==
          NdmsNativeImportIntersectsEvidence::empty);
    CHECK(first.status_evidence ==
          NdmsNativeImportStatusEvidence::absent);
    CHECK(first.status_location ==
          NdmsNativeImportStatusLocation::absent);

    const auto reversed = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])");
    CHECK(reversed.success());
}

TEST_CASE("native import response manifest binds the request kind without raw data") {
    const auto response = json_response(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])");
    const auto wg = inspect_ndms_native_import_response_v3(
        response,
        NdmsNativeTunnelImportKind::wireguard,
        "Wireguard5");
    const auto awg = inspect_ndms_native_import_response_v3(
        response,
        NdmsNativeTunnelImportKind::amnezia_wireguard,
        "Wireguard5");

    REQUIRE(wg.success());
    REQUIRE(awg.success());
    CHECK(wg.request_kind == NdmsNativeTunnelImportKind::wireguard);
    CHECK(awg.request_kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    const auto wg_manifest =
        serialize_ndms_native_import_response_manifest_v3(wg);
    const auto awg_manifest =
        serialize_ndms_native_import_response_manifest_v3(awg);
    CHECK(wg_manifest.rfind(
              "ndms-native-import-response-v3|", 0U) == 0U);
    CHECK(wg_manifest.rfind(
              "ndms-native-import-response-v2|", 0U) != 0U);
    CHECK(wg_manifest.find("kind=wireguard") != std::string::npos);
    CHECK(awg_manifest.find("kind=amnezia_wireguard") !=
          std::string::npos);
    CHECK(wg_manifest != awg_manifest);
}

TEST_CASE("native import response view avoids an owning response copy") {
    const std::string body =
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])";
    const std::string content_type{"application/json; charset=utf-8"};

    const auto viewed = inspect_ndms_native_import_response_v3(
        NdmsNativeImportHttpResponseView{
            true, 200, content_type, body},
        "Wireguard5");
    const auto owned = inspect_ndms_native_import_response_v3(
        NdmsNativeImportHttpResponse{
            true, 200, content_type, body},
        "Wireguard5");

    CHECK(viewed.success());
    CHECK(serialize_ndms_native_import_response_manifest_v3(viewed) ==
          serialize_ndms_native_import_response_manifest_v3(owned));
}

TEST_CASE("native import response rejects target and intersection mismatch") {
    const auto target = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard6","intersects":""}}}}])");
    CHECK_FALSE(target.success());
    CHECK(target.outcome ==
          NdmsNativeImportResponseOutcome::created_mismatch);
    CHECK(target.created_evidence ==
          NdmsNativeImportCreatedEvidence::other_wireguard);

    const auto intersects = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"Wireguard4"}}}}])");
    CHECK_FALSE(intersects.success());
    CHECK(intersects.outcome ==
          NdmsNativeImportResponseOutcome::intersections_nonempty);
    CHECK(intersects.intersects_evidence ==
          NdmsNativeImportIntersectsEvidence::nonempty);
}

TEST_CASE("native import response rejects every envelope extension") {
    const auto extra_import_field = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","future":true}}}}])");
    CHECK(extra_import_field.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);
    CHECK_FALSE(extra_import_field.exact_two_field_shape);

    const auto extra_wrapper_field = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""},"future":{}}}}])");
    CHECK(extra_wrapper_field.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);

    const auto two_batch_items = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}},{}])");
    CHECK(two_batch_items.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);

    const auto wrong_root = inspect(
        R"({"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}})");
    CHECK(wrong_root.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);
}

TEST_CASE("unknown stock status is structurally diagnosed and fails closed") {
    const std::string status_secret{"opaque-stock-status"};
    const std::string ident_secret{"internal-operation-ident"};
    const std::string message_secret{"private diagnostic message"};
    const auto result = inspect(
        std::string{
            R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","status":[{"status":")"} +
        status_secret + R"(","code":2,"ident":")" + ident_secret +
        R"(","message":")" + message_secret + R"("}]}}}}])");

    CHECK_FALSE(result.success());
    CHECK(result.outcome ==
          NdmsNativeImportResponseOutcome::status_unknown);
    CHECK(result.status_key_count == 2U);
    CHECK(result.status_import_direct_key_count == 1U);
    CHECK(result.status_other_key_count == 0U);
    CHECK(result.status_location ==
          NdmsNativeImportStatusLocation::import_direct);
    CHECK(result.direct_status_value_kind ==
          NdmsNativeImportJsonValueKind::array);
    CHECK(result.direct_status_array_length == 1U);
    CHECK(result.direct_status_record_count == 1U);
    CHECK(result.direct_status_nonrecord_count == 0U);
    CHECK(result.direct_status_record_key_count == 4U);
    CHECK(result.direct_status_record_unknown_key_count == 0U);
    CHECK(result.direct_record_status_key_count == 1U);
    CHECK(result.direct_record_code_key_count == 1U);
    CHECK(result.direct_record_ident_key_count == 1U);
    CHECK(result.direct_record_message_key_count == 1U);
    CHECK(result.direct_record_status_value_kind ==
          NdmsNativeImportJsonValueKind::string);
    CHECK(result.direct_record_code_value_kind ==
          NdmsNativeImportJsonValueKind::unsigned_integer);
    CHECK(result.direct_record_status_token ==
          NdmsNativeImportStatusTokenKind::opaque);
    CHECK(result.direct_record_status_bytes == status_secret.size());
    CHECK(result.direct_record_status_sha256.size() == 64U);
    CHECK(result.direct_record_code_evidence ==
          NdmsNativeImportCodeEvidence::decimal);
    CHECK(result.direct_record_code_decimal == "2");
    CHECK(result.direct_record_code_sha256.size() == 64U);
    CHECK(result.direct_record_ident_bytes == ident_secret.size());
    CHECK(result.direct_record_ident_sha256.size() == 64U);
    CHECK(result.direct_record_message_bytes == message_secret.size());
    CHECK(result.direct_record_message_sha256.size() == 64U);

    const auto serialized =
        serialize_ndms_native_import_response_manifest_v3(result);
    CHECK(serialized.find(status_secret) == std::string::npos);
    CHECK(serialized.find(ident_secret) == std::string::npos);
    CHECK(serialized.find(message_secret) == std::string::npos);
    CHECK(std::all_of(
        serialized.begin(), serialized.end(), safe_manifest_character));
}

TEST_CASE("status location distinguishes a wireguard sibling block") {
    const auto result = inspect(
        R"([{"interface":{"wireguard":{"status":[{"status":"other","code":"E_IMPORT","ident":"x","message":"y"}],"import":{"created":"Wireguard5","intersects":""}}}}])");
    CHECK(result.outcome ==
          NdmsNativeImportResponseOutcome::status_unknown);
    CHECK(result.status_location ==
          NdmsNativeImportStatusLocation::wireguard_sibling);
    CHECK(result.status_wireguard_sibling_key_count == 1U);
    CHECK(result.direct_status_value_kind ==
          NdmsNativeImportJsonValueKind::array);
    CHECK(result.direct_status_record_count == 1U);
    CHECK(result.direct_record_code_evidence ==
          NdmsNativeImportCodeEvidence::opaque);
    CHECK(result.direct_record_code_decimal.empty());
    CHECK(result.direct_record_code_sha256.size() == 64U);
}

TEST_CASE("root batch status keeps redacted record structure") {
    const auto result = inspect(
        R"([{"status":[{"status":"other","code":9,"ident":"batch","message":"diagnostic"}],"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])");
    CHECK(result.outcome ==
          NdmsNativeImportResponseOutcome::status_unknown);
    CHECK(result.status_location == NdmsNativeImportStatusLocation::other);
    CHECK(result.status_other_key_count == 1U);
    CHECK(result.direct_status_value_kind ==
          NdmsNativeImportJsonValueKind::array);
    CHECK(result.direct_status_array_length == 1U);
    CHECK(result.direct_status_record_count == 1U);
    CHECK(result.direct_record_status_token ==
          NdmsNativeImportStatusTokenKind::opaque);
    CHECK(result.direct_record_code_decimal == "9");
    CHECK(result.direct_record_ident_bytes == 5U);
    CHECK(result.direct_record_message_bytes == 10U);
}

TEST_CASE("opaque long status codes are hashed rather than serialized") {
    const std::string long_digits(96U, '7');
    const auto result = inspect(
        std::string{
            R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","status":[{"status":"other","code":")"} +
        long_digits + R"("}]}}}}])");
    CHECK(result.outcome ==
          NdmsNativeImportResponseOutcome::status_unknown);
    CHECK(result.direct_record_code_evidence ==
          NdmsNativeImportCodeEvidence::opaque);
    CHECK(result.direct_record_code_decimal.empty());
    CHECK(result.direct_record_code_bytes == long_digits.size());
    CHECK(result.direct_record_code_sha256.size() == 64U);
    const auto serialized =
        serialize_ndms_native_import_response_manifest_v3(result);
    CHECK(serialized.find(long_digits) == std::string::npos);
}

TEST_CASE("manifest serializer rejects forged free-form atoms") {
    auto result = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])");
    const std::string forged_secret{"FORGED_RAW_SECRET_MUST_NOT_APPEAR"};
    result.body_sha256 = forged_secret;
    result.direct_record_status_sha256 = forged_secret;
    result.direct_record_code_decimal = forged_secret;
    result.direct_record_code_sha256 = forged_secret;
    result.direct_record_ident_sha256 = forged_secret;
    result.direct_record_message_sha256 = forged_secret;
    const auto serialized =
        serialize_ndms_native_import_response_manifest_v3(result);
    CHECK(serialized.find(forged_secret) == std::string::npos);
    CHECK(serialized.find("invalid") != std::string::npos);
    CHECK(std::all_of(
        serialized.begin(), serialized.end(), safe_manifest_character));
}

TEST_CASE("secret-shaped labels and echoed import payload are counted only") {
    const std::string echoed_private{"PrivateKey=do-not-retain"};
    const auto result = inspect(
        std::string{
            R"([{"interface":{"wireguard":{"import":")"} +
        echoed_private +
        R"(","PrivateKey":"a","PresharedKey":"b"}}}])");
    CHECK(result.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);
    CHECK(result.sensitive_key_count == 3U);
    const auto serialized =
        serialize_ndms_native_import_response_manifest_v3(result);
    CHECK(serialized.find(echoed_private) == std::string::npos);
    CHECK(serialized.find("PrivateKey") == std::string::npos);
    CHECK(serialized.find("PresharedKey") == std::string::npos);
}

TEST_CASE("only allowlisted status strings receive status semantics") {
    const auto informational_code = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","status":"ok","code":37}}}}])");
    CHECK(informational_code.status_evidence ==
          NdmsNativeImportStatusEvidence::success);
    CHECK(informational_code.code_key_count == 1U);
    CHECK(informational_code.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);

    const auto failed = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","status":"failed"}}}}])");
    CHECK(failed.status_evidence ==
          NdmsNativeImportStatusEvidence::failure);
    CHECK(failed.outcome ==
          NdmsNativeImportResponseOutcome::explicit_failure);

    const auto explicit_error = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","error":null}}}}])");
    CHECK(explicit_error.error_key_count == 1U);
    CHECK(explicit_error.outcome ==
          NdmsNativeImportResponseOutcome::explicit_failure);
}

TEST_CASE("duplicate keys are rejected before DOM interpretation") {
    const auto duplicate_created = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","created":"Wireguard6","intersects":""}}}}])");
    CHECK(duplicate_created.json_state ==
          NdmsNativeImportJsonState::duplicate_key);
    CHECK(duplicate_created.outcome ==
          NdmsNativeImportResponseOutcome::duplicate_key);
    CHECK(duplicate_created.created_key_count == 0U);

    const auto duplicate_status = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","status":{"status":"ok","status":"failed"}}}}}])");
    CHECK(duplicate_status.outcome ==
          NdmsNativeImportResponseOutcome::duplicate_key);

    const auto duplicate_unknown = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","future":1,"future":2}}}}])");
    CHECK(duplicate_unknown.outcome ==
          NdmsNativeImportResponseOutcome::duplicate_key);

    const auto escaped_duplicate = inspect(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":"","future":1,"\u0066uture":2}}}}])");
    CHECK(escaped_duplicate.outcome ==
          NdmsNativeImportResponseOutcome::duplicate_key);
}

TEST_CASE("transport syntax and structural bounds fail closed") {
    auto transport = json_response("[]");
    transport.transport_ok = false;
    CHECK(inspect_ndms_native_import_response_v3(transport, "Wireguard5")
              .outcome == NdmsNativeImportResponseOutcome::transport_failed);

    auto http = json_response("[]");
    http.status_code = 500;
    CHECK(inspect_ndms_native_import_response_v3(http, "Wireguard5")
              .outcome ==
          NdmsNativeImportResponseOutcome::http_status_not_200);

    auto content = json_response("[]");
    content.content_type = "text/plain";
    CHECK(inspect_ndms_native_import_response_v3(content, "Wireguard5")
              .outcome ==
          NdmsNativeImportResponseOutcome::content_type_not_json);

    CHECK(inspect("[").outcome ==
          NdmsNativeImportResponseOutcome::invalid_json);
    CHECK(inspect(std::string(
                      kNdmsNativeImportMaximumResponseBytes + 1U, ' '))
              .outcome == NdmsNativeImportResponseOutcome::body_too_large);
    const auto oversized = inspect(std::string(
        kNdmsNativeImportMaximumResponseBytes + 1U, ' '));
    CHECK(oversized.body_sha256.empty());
    const auto oversized_manifest =
        serialize_ndms_native_import_response_manifest_v3(oversized);
    CHECK(std::all_of(
        oversized_manifest.begin(), oversized_manifest.end(),
        safe_manifest_character));

    std::string deep(33U, '[');
    deep += "0";
    deep.append(33U, ']');
    const auto deep_result = inspect(std::move(deep));
    CHECK(deep_result.json_state ==
          NdmsNativeImportJsonState::structural_limit_exceeded);
    CHECK(deep_result.outcome == NdmsNativeImportResponseOutcome::
                                    structural_limit_exceeded);
}

TEST_CASE("invalid expected target is rejected independently of response") {
    const auto response = json_response(
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])");
    const auto result =
        inspect_ndms_native_import_response_v3(response, "Wireguard05");
    CHECK(result.outcome ==
          NdmsNativeImportResponseOutcome::expected_target_invalid);
    CHECK_FALSE(result.success());

    for (const auto* unsupported_target : {
             "Wireguard127", "Wireguard999"}) {
        const auto unsupported_result =
            inspect_ndms_native_import_response_v3(
                response, unsupported_target);
        CHECK(unsupported_result.outcome ==
              NdmsNativeImportResponseOutcome::
                  expected_target_invalid);
        CHECK_FALSE(unsupported_result.success());
    }

    for (const auto* protected_target : {
             "Wireguard0", "Wireguard4", "Wireguard99",
             "Wireguard100", "Wireguard126"}) {
        const auto protected_result =
            inspect_ndms_native_import_response_v3(response, protected_target);
        CHECK(protected_result.outcome == NdmsNativeImportResponseOutcome::
                                              expected_target_ineligible);
        CHECK_FALSE(protected_result.success());
    }
}
