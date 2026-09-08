#include <doctest/doctest.h>

#include "api/tunnel_probe_review_view.hpp"

using namespace keen_pbr3;

TEST_CASE("Tunnel review API only exposes proposals for the current measured path") {
    TunnelProbeReviewState history;
    sync_tunnel_probe_review(history, "path", {"example.com"}, {}, 1);
    auto& entry = history.entries.front();
    entry.record.direct_successes = 3;
    entry.eligible = true;
    entry.last_observation = DifferentialVerdict::works_without_help;
    entry.last_checked_unix_ms = 42;
    entry.next_due_unix_ms = 100;
    api::TunnelProbeHostsResponse response;
    response.routed = {"example.com"};
    response.config_is_draft = true;
    append_tunnel_probe_review_view(response, history, "path", true);
    REQUIRE(response.review_available.value_or(false));
    REQUIRE(response.reviews.has_value());
    REQUIRE(response.reviews->size() == 1);
    CHECK(response.reviews->front().suggested);
    CHECK(response.reviews->front().required_successes == 3);
    CHECK(response.reviews->front().last_checked_unix_ms == 42);
    CHECK(response.config_is_draft.value_or(false));

    SUBCASE("different tunnel or ISP invalidates a proposal") {
        append_tunnel_probe_review_view(response, history, "new-path", true);
        CHECK_FALSE(response.review_available.value_or(true));
        CHECK(response.reviews->empty());
    }
    SUBCASE("unknown ISP is not positive evidence") {
        append_tunnel_probe_review_view(response, history, "", true);
        CHECK_FALSE(response.review_available.value_or(true));
    }
    SUBCASE("unreadable history leaves ordinary host management intact") {
        append_tunnel_probe_review_view(response, history, "path", false);
        CHECK_FALSE(response.review_available.value_or(true));
        CHECK(response.routed == std::vector<std::string>{"example.com"});
    }
    SUBCASE("manual exclusion wins over stored successes") {
        response.excluded = response.routed;
        append_tunnel_probe_review_view(response, history, "path", true);
        CHECK(response.reviews->empty());
    }
    SUBCASE("an already removed host is not offered again") {
        response.routed.clear();
        append_tunnel_probe_review_view(response, history, "path", true);
        CHECK(response.reviews->empty());
    }
    SUBCASE("an inconclusive last attempt is not a new success") {
        entry.last_observation = DifferentialVerdict::inconclusive;
        append_tunnel_probe_review_view(response, history, "path", true);
        CHECK_FALSE(response.reviews->front().suggested);
    }
    SUBCASE("returned host requires the raised threshold") {
        entry.record.retirements = 2;
        entry.record.direct_successes = 5;
        append_tunnel_probe_review_view(response, history, "path", true);
        CHECK(response.reviews->front().required_successes == 5);
    }
    SUBCASE("saturated metadata timestamps never wrap into negative API values") {
        entry.next_due_unix_ms = UINT64_MAX;
        entry.last_checked_unix_ms = UINT64_MAX;
        append_tunnel_probe_review_view(response, history, "path", true);
        CHECK(response.reviews->front().next_check_unix_ms == INT64_MAX);
        CHECK(response.reviews->front().last_checked_unix_ms == INT64_MAX);
    }
}

TEST_CASE("Tunnel review API declares finite coverage without removing routed hosts") {
    api::TunnelProbeHostsResponse response;
    for (std::size_t i = 0; i <= kTunnelProbeReviewMaxEntries; ++i)
        response.routed.push_back(std::to_string(i) + ".example.com");
    append_tunnel_probe_review_view(response, {}, "path", false);
    CHECK(response.review_limited.value_or(false));
    CHECK(response.routed.size() == kTunnelProbeReviewMaxEntries + 1);
    const auto json = nlohmann::json(response);
    CHECK(json.at("reviews").is_array());
    CHECK(json.at("reviews").empty());
}
