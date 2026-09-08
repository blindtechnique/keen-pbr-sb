#ifdef WITH_API

#include <doctest/doctest.h>
#include "../src/api/operation_error.hpp"

using namespace keen_pbr3;

TEST_CASE("operation error code preserves the existing ApiError contract") {
    const auto error = operation_error("original diagnostic", 409, "busy");
    CHECK(error.status() == 409);
    CHECK(std::string(error.what()) == "original diagnostic");
    REQUIRE(error.body().has_value());
    const auto body = nlohmann::json::parse(*error.body());
    CHECK(body == nlohmann::json{{"error", "original diagnostic"}, {"code", "busy"}});
    const auto parsed = body.get<api::ErrorResponse>();
    CHECK(parsed.code == "busy");
    CHECK(parsed.error == "original diagnostic");
}

TEST_CASE("operation error DTO accepts old responses and future codes") {
    const auto old_response = nlohmann::json{{"error", "old server"}}
                                  .get<api::ErrorResponse>();
    CHECK_FALSE(old_response.code.has_value());
    const auto future = nlohmann::json{{"error", "new diagnostic"},
                                     {"code", "future_reason"}}
                            .get<api::ErrorResponse>();
    CHECK(future.code == "future_reason");
    CHECK(nlohmann::json(future).at("code") == "future_reason");
}

TEST_CASE("subscription error codes remain per item on partial success") {
    api::SubscriptionApplyResultElement created;
    created.line = 1;
    created.outcome = api::Outcome::CREATED;
    api::SubscriptionApplyResultElement failed;
    failed.line = 2;
    failed.outcome = api::Outcome::FAILED;
    failed.error = "connection data was not accepted";
    failed.code = "invalid_connection";
    api::SubscriptionApplyResponse response;
    response.results = {created, failed};
    const nlohmann::json body = response;
    CHECK(body.at("results")[0].at("outcome") == "created");
    CHECK(body.at("results")[0].at("code").is_null());
    CHECK(body.at("results")[1].at("outcome") == "failed");
    CHECK(body.at("results")[1].at("code") == "invalid_connection");
    CHECK_FALSE(body.contains("code"));
    CHECK(body.get<api::SubscriptionApplyResponse>().results[1].code ==
          "invalid_connection");
}

#endif // WITH_API
