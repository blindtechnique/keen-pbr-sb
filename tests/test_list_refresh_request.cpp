#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_lists_refresh.hpp"

using namespace keen_pbr3;

namespace {

const std::string previous_digest(64, 'a');
const std::string candidate_digest(64, 'b');

nlohmann::json shrink_acceptance() {
    return {{"previous_sha256", previous_digest},
            {"candidate_sha256", candidate_digest}};
}

void expect_refresh_request_error(const std::string& body, const std::string& detail = {}) {
    bool rejected = false;
    try {
        (void)parse_list_refresh_request(body);
    } catch (const ApiError& error) {
        rejected = true;
        CHECK(error.status() == 400);
        if (!detail.empty()) {
            CHECK(std::string(error.what()).find(detail) != std::string::npos);
        }
    }
    CHECK(rejected);
}

} // namespace

TEST_CASE("list refresh parser keeps empty null and ordinary defaults") {
    for (const auto& body : {std::string{}, std::string("null"), std::string("{}"),
                            std::string(R"({"name":null})")}) {
        const auto request = parse_list_refresh_request(body);
        CHECK_FALSE(request.name.has_value());
        CHECK_FALSE(request.force_refresh.value_or(false));
        CHECK_FALSE(request.accept_shrink.has_value());
    }
    const auto named = parse_list_refresh_request(R"({"name":"example"})");
    CHECK(named.name == "example");
    CHECK_FALSE(named.force_refresh.value_or(false));
    CHECK_FALSE(named.accept_shrink.has_value());
}

TEST_CASE("list refresh parser preserves explicit force without accepting a replacement") {
    for (const auto force : {false, true}) {
        const auto body = nlohmann::json{{"name", "example"}, {"force_refresh", force}}.dump();
        const auto request = parse_list_refresh_request(body);
        CHECK(request.name == "example");
        CHECK(request.force_refresh == force);
        CHECK_FALSE(request.accept_shrink.has_value());
    }
    const auto all = parse_list_refresh_request(R"({"force_refresh":true})");
    CHECK_FALSE(all.name.has_value());
    CHECK(all.force_refresh == true);
}

TEST_CASE("list refresh parser retains both exact digests and forces accepted refresh") {
    for (const auto force : {false, true}) {
        const auto body = nlohmann::json{{"name", "example"}, {"force_refresh", force},
                                        {"accept_shrink", shrink_acceptance()}}.dump();
        const auto request = parse_list_refresh_request(body);
        CHECK(request.name == "example");
        CHECK(request.force_refresh == true);
        REQUIRE(request.accept_shrink.has_value());
        CHECK(request.accept_shrink->previous_sha256 == previous_digest);
        CHECK(request.accept_shrink->candidate_sha256 == candidate_digest);
    }
    const auto request = parse_list_refresh_request(nlohmann::json{
        {"name", "example"}, {"accept_shrink", shrink_acceptance()}}.dump());
    CHECK(request.force_refresh == true);
}

TEST_CASE("list refresh parser rejects malformed JSON roots and ordinary field types") {
    for (const auto* body : {"{", "broken", "[]", "true", "42", "\"example\""}) {
        expect_refresh_request_error(body, "Invalid request body");
    }
    for (const auto& name : {nlohmann::json(1), nlohmann::json(true), nlohmann::json::array()}) {
        expect_refresh_request_error(nlohmann::json{{"name", name}}.dump(), "name");
    }
    for (const auto& force : {nlohmann::json(nullptr), nlohmann::json(1),
                             nlohmann::json("true"), nlohmann::json::object()}) {
        expect_refresh_request_error(nlohmann::json{{"force_refresh", force}}.dump(), "force_refresh");
    }
}

TEST_CASE("list refresh parser requires one nonempty named list for shrink acceptance") {
    expect_refresh_request_error(nlohmann::json{{"accept_shrink", shrink_acceptance()}}.dump(),
                                 "one named list");
    for (const auto& name : {nlohmann::json(nullptr), nlohmann::json("")}) {
        expect_refresh_request_error(nlohmann::json{{"name", name},
            {"accept_shrink", shrink_acceptance()}}.dump(), "one named list");
    }
    for (const auto& acceptance : {nlohmann::json(nullptr), nlohmann::json(true),
                                  nlohmann::json("yes"), nlohmann::json::array()}) {
        expect_refresh_request_error(nlohmann::json{{"name", "example"},
            {"accept_shrink", acceptance}}.dump(), "one named list");
    }
}

TEST_CASE("list refresh parser requires two exact lowercase SHA256 digests") {
    for (const auto* field : {"previous_sha256", "candidate_sha256"}) {
        auto missing = shrink_acceptance();
        missing.erase(field);
        expect_refresh_request_error(nlohmann::json{{"name", "example"},
            {"accept_shrink", missing}}.dump(), "both list digests");
        for (const auto& value : {nlohmann::json(nullptr), nlohmann::json(1),
                                  nlohmann::json(std::string(63, 'a')),
                                  nlohmann::json(std::string(65, 'a')),
                                  nlohmann::json(std::string(64, 'A')),
                                  nlohmann::json(std::string(64, 'g'))}) {
            auto acceptance = shrink_acceptance();
            acceptance[field] = value;
            expect_refresh_request_error(nlohmann::json{{"name", "example"},
                {"accept_shrink", acceptance}}.dump());
        }
    }
}

TEST_CASE("list refresh apply errors preserve partial cache success without claiming runtime success") {
    const ListRefreshOperationResult partial{
        {"one", "two"}, {"one"}, {"three"}, false, "download completed"};
    struct FailureCase {
        const char* stage;
        const char* runtime_result;
    };
    for (const auto failure : {
             FailureCase{"prepare", "unchanged"},
             FailureCase{"owner_handoff", "unknown"},
             FailureCase{"terminal_wait", "unknown"},
             FailureCase{"terminal", "unchanged"},
             FailureCase{"terminal", "rolled_back"},
             FailureCase{"terminal", "unknown"}}) {
        CAPTURE(failure.stage);
        CAPTURE(failure.runtime_result);
        const std::string detail = "exact runtime failure detail";
        const auto error = make_list_refresh_apply_error(
            partial, failure.stage, detail, failure.runtime_result);
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        const auto body = nlohmann::json::parse(*error.body());
        CHECK(body["code"] == "list_refresh_apply_failed");
        CHECK(body["params"]["stage"] == failure.stage);
        CHECK(body["params"]["runtime_result"] == failure.runtime_result);
        CHECK(body["refreshed_lists"] == partial.refreshed_lists);
        CHECK(body["changed_lists"] == partial.changed_lists);
        CHECK(body["failed_lists"] == partial.failed_lists);
        CHECK(body["reloaded"] == false);
        CHECK_FALSE(body.contains("status"));
        CHECK(body["error"].get<std::string>().find(detail) != std::string::npos);
        CHECK(body["error"] == error.what());
        const auto compatible = body.get<api::ErrorResponse>();
        CHECK(compatible.code == "list_refresh_apply_failed");
        CHECK(compatible.error == error.what());
    }
}

TEST_CASE("list refresh apply error without terminal detail still has a diagnostic") {
    const auto error = make_list_refresh_apply_error({}, "terminal", {});
    CHECK(error.status() == 503);
    CHECK(std::string(error.what()) ==
          "Lists were refreshed, but routing changes were not applied");
    REQUIRE(error.body().has_value());
    const auto body = nlohmann::json::parse(*error.body());
    CHECK(body["params"]["runtime_result"] == "unknown");
    CHECK(body["reloaded"] == false);
}

#endif // WITH_API
