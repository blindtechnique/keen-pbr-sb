#include <doctest/doctest.h>

#include "../src/api/config_validation_json.hpp"

namespace keen_pbr3 {

TEST_CASE("config validation JSON preserves the legacy two-field contract") {
    const ConfigValidationIssue issue{"lists.example.ip_cidrs[2]", "Original diagnostic"};
    CHECK(serialize_config_validation_issue(issue) == nlohmann::json{
        {"path", "lists.example.ip_cidrs[2]"}, {"message", "Original diagnostic"}});
    CHECK(serialize_config_validation_issues({}) == nlohmann::json::array());
    const auto parsed = serialize_config_validation_issue(issue).get<api::ValidationErrorElement>();
    CHECK(parsed.path == issue.path);
    CHECK(parsed.message == issue.message);
    CHECK_FALSE(parsed.code.has_value());
    CHECK_FALSE(parsed.params.has_value());
    const auto roundtrip = nlohmann::json(parsed).get<api::ValidationErrorElement>();
    CHECK(roundtrip.path == parsed.path);
    CHECK(roundtrip.message == parsed.message);
    CHECK_FALSE(roundtrip.code.has_value());
    CHECK_FALSE(roundtrip.params.has_value());
}

TEST_CASE("config validation JSON carries codes and lossless string parameters") {
    const ConfigValidationIssue issue{
        "schema_version", "Original future-version diagnostic",
        "config.schema_version.unsupported",
        {{"version", "18446744073709551615"}, {"supported", "2"}}};
    const auto rendered = serialize_config_validation_issue(issue);
    CHECK(rendered == nlohmann::json{
        {"path", issue.path}, {"message", issue.message}, {"code", issue.code},
        {"params", {{"version", "18446744073709551615"}, {"supported", "2"}}}});
    CHECK(nlohmann::json::parse(rendered.dump()) == rendered);
    const auto parsed = rendered.get<api::ValidationErrorElement>();
    CHECK(parsed.code == issue.code);
    REQUIRE(parsed.params.has_value());
    CHECK(*parsed.params == issue.params);
    CHECK(nlohmann::json(parsed) == rendered);
}

TEST_CASE("config validation JSON DTO preserves unknown future field codes") {
    const ConfigValidationIssue issue{
        "future.field", "New diagnostic", "config.future_code", {{"value", "7"}}};
    const auto rendered = serialize_config_validation_issue(issue);
    const auto parsed = rendered.get<api::ValidationErrorElement>();
    CHECK(parsed.code == "config.future_code");
    REQUIRE(parsed.params.has_value());
    CHECK(parsed.params->at("value") == "7");
    CHECK(nlohmann::json(parsed) == rendered);
}

TEST_CASE("config validation JSON omits each empty metadata field independently") {
    const ConfigValidationIssue coded{
        "lists.example.ip_cidrs[3]", "IP/CIDR prefix length is invalid",
        "config.ip_cidr.invalid_prefix"};
    const ConfigValidationIssue parameterized{
        "future.field", "A diagnostic", {}, {{"value", "quoted \"text\"\nnext line"}}};
    const ConfigValidationIssue legacy{"old.field", "Old diagnostic"};
    const auto rendered = serialize_config_validation_issues({coded, parameterized, legacy});
    REQUIRE(rendered.size() == 3U);
    CHECK(rendered.at(0).at("code") == coded.code);
    CHECK_FALSE(rendered.at(0).contains("params"));
    CHECK_FALSE(rendered.at(1).contains("code"));
    CHECK(rendered.at(1).at("params").at("value") == parameterized.params.at("value"));
    CHECK(rendered.at(2) == nlohmann::json{
        {"path", legacy.path}, {"message", legacy.message}});
    CHECK(nlohmann::json::parse(rendered.dump()) == rendered);
}

TEST_CASE("JSON validation envelope preserves a fixed backup parse error") {
    try {
        const auto ignored = nlohmann::json::parse("{\"private-source\":");
        (void)ignored;
        FAIL("invalid JSON must produce a real parse exception");
    } catch (const nlohmann::json::parse_error& error) {
        const std::string message = "invalid backup JSON";
        const auto rendered = serialize_json_validation_error(message, error);
        CHECK(rendered == nlohmann::json{
            {"error", message},
            {"validation_errors", nlohmann::json::array({{
                {"path", "$"}, {"message", message}, {"code", "config.json.syntax"}}})}});
        CHECK_FALSE(rendered.at("validation_errors").at(0).contains("params"));
        CHECK(rendered.dump().find("private-source") == std::string::npos);

        const auto parsed = rendered.get<api::ErrorResponse>();
        CHECK(parsed.error == message);
        CHECK_FALSE(parsed.code.has_value());
        REQUIRE(parsed.validation_errors.has_value());
        REQUIRE(parsed.validation_errors->size() == 1U);
        const auto roundtrip = nlohmann::json(parsed).get<api::ErrorResponse>();
        CHECK(roundtrip.error == message);
        CHECK_FALSE(roundtrip.code.has_value());
        REQUIRE(roundtrip.validation_errors.has_value());
        REQUIRE(roundtrip.validation_errors->size() == 1U);
        const auto& issue = roundtrip.validation_errors->at(0);
        CHECK(issue.path == "$");
        CHECK(issue.message == message);
        CHECK(issue.code == "config.json.syntax");
        CHECK_FALSE(issue.params.has_value());
    }
}

TEST_CASE("JSON validation envelope preserves a prefixed request type error and path") {
    try {
        const auto ignored = nlohmann::json("not-an-integer").get<int>();
        (void)ignored;
        FAIL("a JSON string must produce a real integer type exception");
    } catch (const nlohmann::json::type_error& error) {
        const std::string message = std::string("Invalid JSON request: ") + error.what();
        const auto rendered = serialize_json_validation_error(message, error, "$");
        CHECK(rendered == nlohmann::json{
            {"error", message},
            {"validation_errors", nlohmann::json::array({{
                {"path", "$"}, {"message", message}, {"code", "config.json.type"}}})}});
        CHECK_FALSE(rendered.at("validation_errors").at(0).contains("params"));
        const auto custom_path = serialize_json_validation_error(message, error, "request.body");
        CHECK(custom_path.at("error") == message);
        CHECK(custom_path.at("validation_errors").at(0).at("path") == "request.body");
        CHECK(custom_path.at("validation_errors").at(0).at("message") == message);

        const auto parsed = rendered.get<api::ErrorResponse>();
        CHECK(parsed.error == message);
        CHECK_FALSE(parsed.code.has_value());
        REQUIRE(parsed.validation_errors.has_value());
        REQUIRE(parsed.validation_errors->size() == 1U);
        const auto roundtrip = nlohmann::json(parsed).get<api::ErrorResponse>();
        CHECK(roundtrip.error == message);
        CHECK_FALSE(roundtrip.code.has_value());
        REQUIRE(roundtrip.validation_errors.has_value());
        REQUIRE(roundtrip.validation_errors->size() == 1U);
        const auto& issue = roundtrip.validation_errors->at(0);
        CHECK(issue.path == "$");
        CHECK(issue.message == message);
        CHECK(issue.code == "config.json.type");
        CHECK_FALSE(issue.params.has_value());
    }
}

} // namespace keen_pbr3
