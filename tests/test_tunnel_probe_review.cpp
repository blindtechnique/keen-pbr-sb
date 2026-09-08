#include "../src/health/tunnel_probe_review.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

constexpr std::uint64_t kHour = 60U * 60U * 1000U;
constexpr const char* kContext = "isp0|nwg2|found";
constexpr const char* kHost = "review.example";

class ReviewDirectory {
public:
    ReviewDirectory() {
        std::array<char, 64> pattern{};
        const std::string path = "/tmp/kpbr-review-test-XXXXXX";
        std::copy(path.begin(), path.end(), pattern.begin());
        const auto result = ::mkdtemp(pattern.data());
        if (!result) throw std::runtime_error("mkdtemp failed");
        path_ = result;
    }
    ~ReviewDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    std::string list() const { return (path_ / "found.lst").string(); }

private:
    std::filesystem::path path_;
};

std::string file_text(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_text(const std::string& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
    if (!output.good()) throw std::runtime_error("fixture write failed");
}

TunnelProbeReviewState active_state(std::uint64_t now = 100U) {
    TunnelProbeReviewState state;
    sync_tunnel_probe_review(state, kContext, {kHost}, {}, now);
    return state;
}

TunnelProbeReviewEntry& first(TunnelProbeReviewState& state) {
    if (state.entries.empty()) throw std::runtime_error("missing fixture record");
    return state.entries.front();
}

void direct_success(TunnelProbeReviewState& state) {
    const auto now = first(state).next_due_unix_ms;
    REQUIRE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::works_without_help, now));
}

} // namespace

TEST_CASE("tunnel review: missing sidecar is an ordinary empty history") {
    ReviewDirectory directory;
    std::string error = "previous error";
    const auto state = load_tunnel_probe_review(directory.list(), error);
    CHECK(error.empty());
    CHECK(state.entries.empty());
    CHECK_FALSE(state.limited);
    CHECK_FALSE(std::filesystem::exists(tunnel_probe_review_path(directory.list())));
}

TEST_CASE("tunnel review: only valid routed non-excluded entries are due") {
    TunnelProbeReviewState state;
    REQUIRE(sync_tunnel_probe_review(
        state, kContext,
        {"b.example", "a.example", "b.example", "never.example", "bad/host"},
        {"never.example"}, 100U));
    CHECK(state.entries.size() == 2U);
    CHECK(due_tunnel_probe_reviews(state, 99U, 8U).empty());
    CHECK(due_tunnel_probe_reviews(state, 100U, 1U) ==
          std::vector<std::string>{"a.example"});
    CHECK(due_tunnel_probe_reviews(state, 100U, 8U) ==
          std::vector<std::string>{"a.example", "b.example"});
    CHECK(due_tunnel_probe_reviews(state, 100U, 0U).empty());
    CHECK_FALSE(sync_tunnel_probe_review(
        state, kContext, {"b.example", "a.example", "never.example"},
        {"never.example"}, 999U));
    CHECK(first(state).updated_at_unix_ms == 100U);
}

TEST_CASE("tunnel review: three spaced direct successes propose but never remove") {
    auto state = active_state();
    direct_success(state);
    CHECK(first(state).record.direct_successes == 1U);
    CHECK(first(state).next_due_unix_ms == 100U + kHour);
    CHECK_FALSE(first(state).eligible);
    CHECK_FALSE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::works_without_help, 100U));
    direct_success(state);
    CHECK_FALSE(first(state).eligible);
    direct_success(state);
    CHECK(first(state).eligible);
    CHECK(first(state).active);
    CHECK(first(state).record.direct_successes == 3U);
    CHECK(state.entries.size() == 1U);
}

TEST_CASE("tunnel review: parent exclusions cover subdomains without substring matches") {
    TunnelProbeReviewState state;
    const std::vector<std::string> routed = {
        "example.com", "www.example.com", "notexample.com"};
    REQUIRE(sync_tunnel_probe_review(state, kContext, routed, {}, 100U));
    const auto visible = filter_tunnel_probe_reviews(state, routed, {"example.com"});
    REQUIRE(visible.size() == 1U);
    CHECK(visible.front().record.host == "notexample.com");
    REQUIRE(sync_tunnel_probe_review(state, kContext, routed, {"example.com"}, 200U));
    CHECK(due_tunnel_probe_reviews(state, 200U, 8U) ==
          std::vector<std::string>{"notexample.com"});
    CHECK_FALSE(observe_tunnel_probe_review(
        state, kContext, "www.example.com",
        DifferentialVerdict::works_without_help, 200U));
}

TEST_CASE("tunnel review: a block resets progress and backs off the next probe") {
    auto state = active_state();
    direct_success(state);
    const auto blocked_at = first(state).next_due_unix_ms;
    REQUIRE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::blocked_here, blocked_at));
    CHECK(first(state).record.direct_successes == 0U);
    CHECK(first(state).record.blocked_confirmations == 1U);
    CHECK(first(state).next_due_unix_ms == blocked_at + 2U * kHour);
    CHECK_FALSE(first(state).eligible);
    REQUIRE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::blocked_here,
        first(state).next_due_unix_ms));
    CHECK(first(state).record.blocked_confirmations == 2U);
}

TEST_CASE("tunnel review: inconclusive outages do not create a retirement proposal") {
    auto state = active_state();
    direct_success(state);
    direct_success(state);
    for (const auto verdict : {DifferentialVerdict::down_everywhere,
                               DifferentialVerdict::tunnel_broken,
                               DifferentialVerdict::inconclusive}) {
        REQUIRE(observe_tunnel_probe_review(
            state, kContext, kHost, verdict, first(state).next_due_unix_ms));
        CHECK(first(state).last_observation == verdict);
        CHECK(first(state).record.last == DifferentialVerdict::works_without_help);
        CHECK(first(state).record.direct_successes == 2U);
        CHECK_FALSE(first(state).eligible);
        CHECK(first(state).active);
    }
    direct_success(state);
    CHECK(first(state).eligible);
}

TEST_CASE("tunnel review: fresh membership and context discard stale observations") {
    auto state = active_state();
    REQUIRE(sync_tunnel_probe_review(state, kContext, {}, {}, 200U));
    CHECK_FALSE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::works_without_help, 200U));
    CHECK_FALSE(first(state).active);
    CHECK_FALSE(sync_tunnel_probe_review(state, kContext, {kHost}, {kHost}, 300U));
    CHECK(due_tunnel_probe_reviews(state, 300U, 8U).empty());
    REQUIRE(sync_tunnel_probe_review(state, "changed", {kHost}, {}, 400U));
    CHECK_FALSE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::works_without_help, 400U));
    CHECK(first(state).record.direct_successes == 0U);
}

TEST_CASE("tunnel review: context changes and reactivation preserve retirement history only") {
    auto state = active_state();
    direct_success(state);
    direct_success(state);
    direct_success(state);
    note_tunnel_probe_review_removal(state, kHost, 3U * kHour);
    CHECK(first(state).record.retirements == 1U);
    CHECK_FALSE(first(state).active);
    CHECK_FALSE(first(state).eligible);
    note_tunnel_probe_review_removal(state, kHost, 4U * kHour);
    CHECK(first(state).record.retirements == 1U);
    REQUIRE(sync_tunnel_probe_review(state, kContext, {kHost}, {}, 4U * kHour));
    direct_success(state);
    direct_success(state);
    direct_success(state);
    CHECK_FALSE(first(state).eligible);
    direct_success(state);
    CHECK(first(state).eligible);
    REQUIRE(sync_tunnel_probe_review(state, "new isp", {kHost}, {}, 9U * kHour));
    CHECK(first(state).record.retirements == 1U);
    CHECK(first(state).record.direct_successes == 0U);
    CHECK(first(state).last_checked_unix_ms == 0U);
    CHECK(first(state).next_due_unix_ms == 9U * kHour);
    CHECK_FALSE(first(state).eligible);
}

TEST_CASE("tunnel review: sidecar round-trip retains counters times and last observation") {
    ReviewDirectory directory;
    auto state = active_state();
    direct_success(state);
    direct_success(state);
    direct_success(state);
    REQUIRE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::tunnel_broken,
        first(state).next_due_unix_ms));
    std::string error;
    REQUIRE(save_tunnel_probe_review(directory.list(), state, error));
    CHECK(error.empty());
    const auto loaded = load_tunnel_probe_review(directory.list(), error);
    REQUIRE(error.empty());
    REQUIRE(loaded.entries.size() == 1U);
    CHECK(loaded.context == kContext);
    CHECK(loaded.entries.front().eligible);
    CHECK(loaded.entries.front().record.direct_successes == 3U);
    CHECK(loaded.entries.front().record.last == DifferentialVerdict::works_without_help);
    CHECK(loaded.entries.front().last_observation == DifferentialVerdict::tunnel_broken);
    CHECK(loaded.entries.front().next_due_unix_ms == first(state).next_due_unix_ms);
    CHECK(loaded.entries.front().last_checked_unix_ms == first(state).last_checked_unix_ms);
}

TEST_CASE("tunnel review: persisted inactive host removed again before worker sync raises threshold") {
    ReviewDirectory directory;
    auto state = active_state();
    note_tunnel_probe_review_removal(state, kHost, 200U);
    std::string error;
    REQUIRE(save_tunnel_probe_review(directory.list(), state, error));
    state = load_tunnel_probe_review(directory.list(), error);
    REQUIRE(error.empty());
    REQUIRE(state.entries.size() == 1U);
    CHECK_FALSE(first(state).active);
    CHECK(first(state).record.retirements == 1U);
    // The host returned to the actual list between worker passes. The API
    // syncs the pre-write list snapshot before recording its real removal.
    REQUIRE(sync_tunnel_probe_review(state, kContext, {kHost}, {}, 300U));
    note_tunnel_probe_review_removal(state, kHost, 300U);
    CHECK(first(state).record.retirements == 2U);
    CHECK_FALSE(first(state).active);
    CHECK(effective_retire_after(first(state).record, {}) == 5U);
    REQUIRE(save_tunnel_probe_review(directory.list(), state, error));
    state = load_tunnel_probe_review(directory.list(), error);
    REQUIRE(error.empty());
    REQUIRE(state.entries.size() == 1U);
    CHECK(first(state).record.retirements == 2U);
}

TEST_CASE("tunnel review: read-only API filtering cannot reactivate historical entries") {
    auto state = active_state();
    direct_success(state);
    direct_success(state);
    direct_success(state);
    CHECK(filter_tunnel_probe_reviews(state, {kHost}, {}).size() == 1U);
    CHECK(filter_tunnel_probe_reviews(state, {}, {}).empty());
    CHECK(filter_tunnel_probe_reviews(state, {kHost}, {kHost}).empty());
    note_tunnel_probe_review_removal(state, kHost, 9U * kHour);
    CHECK(filter_tunnel_probe_reviews(state, {kHost}, {}).empty());
    CHECK_FALSE(first(state).active);
}

TEST_CASE("tunnel review: active overflow is explicit and old inactive history is pruned first") {
    TunnelProbeReviewState state;
    std::vector<std::string> hosts;
    for (std::size_t i = 0; i < kTunnelProbeReviewMaxEntries + 3U; ++i) {
        hosts.push_back("host-" + std::to_string(i) + ".example");
    }
    REQUIRE(sync_tunnel_probe_review(state, kContext, hosts, {}, 100U));
    CHECK(state.entries.size() == kTunnelProbeReviewMaxEntries);
    CHECK(state.limited);
    CHECK(due_tunnel_probe_reviews(state, 100U, 1000U).size() ==
          kTunnelProbeReviewMaxEntries);
    const auto old_host = first(state).record.host;
    note_tunnel_probe_review_removal(state, old_host, 200U);
    hosts.erase(std::remove(hosts.begin(), hosts.end(), old_host), hosts.end());
    REQUIRE(sync_tunnel_probe_review(state, kContext, hosts, {}, 300U));
    CHECK(state.entries.size() == kTunnelProbeReviewMaxEntries);
    CHECK(std::none_of(state.entries.begin(), state.entries.end(),
        [&old_host](const auto& entry) { return entry.record.host == old_host; }));
    hosts.resize(2U);
    REQUIRE(sync_tunnel_probe_review(state, kContext, hosts, {}, 400U));
    CHECK_FALSE(state.limited);
    CHECK(due_tunnel_probe_reviews(state, 400U, 1000U).size() <= 2U);
}

TEST_CASE("tunnel review: inactive history stays bounded without an overflow warning") {
    TunnelProbeReviewState state;
    for (std::size_t i = 0; i < kTunnelProbeReviewMaxEntries + 20U; ++i) {
        note_tunnel_probe_review_removal(
            state, "old-" + std::to_string(i) + ".example", i + 1U);
    }
    CHECK(state.entries.size() == kTunnelProbeReviewMaxEntries);
    CHECK_FALSE(state.limited);
    CHECK(std::none_of(state.entries.begin(), state.entries.end(),
        [](const auto& entry) { return entry.record.host == "old-0.example"; }));
}

TEST_CASE("tunnel review: invalid or oversized metadata does not touch routed lists") {
    ReviewDirectory directory;
    write_text(directory.list(), std::string{kHost} + '\n');
    write_text(directory.list() + ".excluded", "never.example\n");
    const auto path = tunnel_probe_review_path(directory.list());
    std::string error;
    for (const auto& invalid : {std::string{"not json"}, std::string{"[]"},
        std::string(kTunnelProbeReviewMaxBytes + 1U, 'x')}) {
        write_text(path, invalid);
        const auto state = load_tunnel_probe_review(directory.list(), error);
        CHECK_FALSE(error.empty());
        CHECK(state.entries.empty());
        CHECK(file_text(directory.list()) == std::string{kHost} + '\n');
        CHECK(file_text(directory.list() + ".excluded") == "never.example\n");
    }
}

TEST_CASE("tunnel review: invalid counters and duplicate records reject the sidecar") {
    ReviewDirectory directory;
    auto state = active_state();
    std::string error;
    REQUIRE(save_tunnel_probe_review(directory.list(), state, error));
    const auto path = tunnel_probe_review_path(directory.list());
    const auto valid = nlohmann::json::parse(file_text(path));
    auto negative = valid;
    negative["entries"][0]["retirements"] = -1;
    write_text(path, negative.dump());
    CHECK(load_tunnel_probe_review(directory.list(), error).entries.empty());
    CHECK_FALSE(error.empty());
    auto duplicate = valid;
    duplicate["entries"].push_back(duplicate["entries"][0]);
    write_text(path, duplicate.dump());
    CHECK(load_tunnel_probe_review(directory.list(), error).entries.empty());
    CHECK_FALSE(error.empty());
    auto unproven = valid;
    unproven["entries"][0]["eligible"] = true;
    write_text(path, unproven.dump());
    const auto loaded = load_tunnel_probe_review(directory.list(), error);
    REQUIRE(error.empty());
    REQUIRE(loaded.entries.size() == 1U);
    CHECK_FALSE(loaded.entries.front().eligible);
}

TEST_CASE("tunnel review: failed metadata save leaves existing files intact") {
    ReviewDirectory directory;
    auto state = active_state();
    std::string error;
    REQUIRE(save_tunnel_probe_review(directory.list(), state, error));
    const auto path = tunnel_probe_review_path(directory.list());
    const auto original = file_text(path);
    state.entries.push_back(first(state));
    CHECK_FALSE(save_tunnel_probe_review(directory.list(), state, error));
    CHECK_FALSE(error.empty());
    CHECK(file_text(path) == original);
    CHECK_FALSE(save_tunnel_probe_review(directory.list() + "/missing/list", {}, error));
    CHECK_FALSE(error.empty());
    CHECK(file_text(path) == original);
}

TEST_CASE("tunnel review: context identifies every probe path and list target") {
    const auto context = tunnel_probe_review_context("tag", "nwg2", "isp0", "found", "/a");
    CHECK(context != tunnel_probe_review_context("other", "nwg2", "isp0", "found", "/a"));
    CHECK(context != tunnel_probe_review_context("tag", "nwg3", "isp0", "found", "/a"));
    CHECK(context != tunnel_probe_review_context("tag", "nwg2", "isp1", "found", "/a"));
    CHECK(context != tunnel_probe_review_context("tag", "nwg2", "isp0", "other", "/a"));
    CHECK(context != tunnel_probe_review_context("tag", "nwg2", "isp0", "found", "/b"));
    CHECK(tunnel_probe_review_context("a\nb", "c", "isp", "list", "/a") !=
          tunnel_probe_review_context("a", "b\nc", "isp", "list", "/a"));
}

TEST_CASE("tunnel review: large retirement counters and timestamps do not wrap") {
    auto state = active_state();
    first(state).record.retirements = UINT32_MAX;
    CHECK(effective_retire_after(first(state).record, {}) == 8U);
    direct_success(state);
    direct_success(state);
    direct_success(state);
    CHECK_FALSE(first(state).eligible);
    const auto near_max = std::numeric_limits<std::uint64_t>::max() - 100U;
    REQUIRE(observe_tunnel_probe_review(
        state, kContext, kHost, DifferentialVerdict::inconclusive, near_max));
    CHECK(first(state).next_due_unix_ms == std::numeric_limits<std::uint64_t>::max());
}

} // namespace keen_pbr3
