#include <doctest/doctest.h>
#include "../src/log/subscription_notices.hpp"
using namespace keen_pbr3;
using nlohmann::json;

TEST_CASE("subscription expiry notices progress at seven three and one days") {
    constexpr std::int64_t expiry = 2000000000;
    const auto sources = json::array({{{"id", "one"}, {"name", "Provider"}, {"expires_at", expiry}}});
    CHECK(subscription_notices(sources, expiry - 8 * 86400).empty());
    const auto seven = subscription_notices(sources, expiry - 7 * 86400);
    const auto four = subscription_notices(sources, expiry - 4 * 86400);
    const auto three = subscription_notices(sources, expiry - 3 * 86400);
    const auto two = subscription_notices(sources, expiry - 2 * 86400);
    const auto one = subscription_notices(sources, expiry - 86400);
    const auto expired = subscription_notices(sources, expiry);
    REQUIRE(seven.size() == 1);
    CHECK(seven[0]["days"] == 7);
    CHECK(seven[0]["id"] == four[0]["id"]);
    CHECK(three[0]["id"] != seven[0]["id"]);
    CHECK(three[0]["id"] == two[0]["id"]);
    CHECK(one[0]["id"] != three[0]["id"]);
    CHECK(expired[0]["kind"] == "expired");
    CHECK(expired[0]["id"] != one[0]["id"]);
}
TEST_CASE("subscription traffic notices require provider data and survive renewed cycles") {
    auto sources = json::array({{{"id", "one"}, {"name", "Provider"}}});
    CHECK(subscription_notices(sources, 100).empty());
    sources[0]["total_bytes"] = 1000;
    sources[0]["download_bytes"] = 950;
    CHECK(subscription_notices(sources, 100).empty());
    sources[0]["upload_bytes"] = 0;
    const auto low = subscription_notices(sources, 100);
    REQUIRE(low.size() == 1);
    CHECK(low[0]["kind"] == "traffic_low");
    CHECK(low[0]["remaining_percent"] == 5);
    sources[0]["download_bytes"] = 990;
    CHECK(subscription_notices(sources, 200)[0]["id"] == low[0]["id"]);
    sources[0]["usage_cycle"] = 1;
    CHECK(subscription_notices(sources, 200)[0]["id"] != low[0]["id"]);
    sources[0]["download_bytes"] = 1100;
    CHECK(subscription_notices(sources, 200)[0]["kind"] == "traffic_exhausted");
    CHECK(subscription_notices(sources, 200)[0]["remaining_percent"] == 0);
    sources[0]["total_bytes"] = 0;
    CHECK(subscription_notices(sources, 200).empty());
}
TEST_CASE("subscription new server notices are stable and never expose source credentials") {
    auto sources = json::array({{{"id", "one"}, {"name", "Provider"},
        {"url", "https://provider.example/private-secret"},
        {"pending_new_servers_count", 2}, {"pending_servers_revision", "1"}}});
    const auto first = subscription_notices(sources, 100);
    REQUIRE(first.size() == 1);
    CHECK(first[0]["count"] == 2);
    CHECK(first.dump().find("private-secret") == std::string::npos);
    CHECK(first[0]["id"] == subscription_notices(sources, 200)[0]["id"]);
    sources[0]["pending_servers_revision"] = "2";
    CHECK(first[0]["id"] != subscription_notices(sources, 200)[0]["id"]);
    sources[0]["pending_new_servers_count"] = 0;
    CHECK(subscription_notices(sources, 200).empty());
}
