#include "../src/health/entry_review.hpp"

#include <doctest/doctest.h>

#include <string>

namespace keen_pbr3 {

namespace {

ReviewRecord entry(const char* host = "thumbnails.libretro.com") {
    ReviewRecord record;
    record.host = host;
    return record;
}

ReviewAction feed(ReviewRecord& record,
                  const DifferentialVerdict verdict,
                  const ReviewPolicy& policy = ReviewPolicy{}) {
    return review_step(record, verdict, policy);
}

}  // namespace

TEST_CASE("review: an entry that answers directly three times is offered back") {
    auto record = entry();

    CHECK(feed(record, DifferentialVerdict::works_without_help) == ReviewAction::keep);
    CHECK(feed(record, DifferentialVerdict::works_without_help) == ReviewAction::keep);
    CHECK(feed(record, DifferentialVerdict::works_without_help) ==
          ReviewAction::propose_retirement);
}

TEST_CASE("review: one confirmed block undoes the run") {
    auto record = entry();
    feed(record, DifferentialVerdict::works_without_help);
    feed(record, DifferentialVerdict::works_without_help);

    CHECK(feed(record, DifferentialVerdict::blocked_here) == ReviewAction::keep);
    CHECK(record.direct_successes == 0U);

    // Back to the start, not one step from the finish.
    CHECK(feed(record, DifferentialVerdict::works_without_help) == ReviewAction::keep);
    CHECK(feed(record, DifferentialVerdict::works_without_help) == ReviewAction::keep);
    CHECK(feed(record, DifferentialVerdict::works_without_help) ==
          ReviewAction::propose_retirement);
}

TEST_CASE("review: an outage neither advances nor undoes anything") {
    // The rule this file exists to protect. down_everywhere means the target is
    // down; letting it count would retire an entry because the site broke, and
    // letting it reset would punish an entry for somebody else's outage.
    auto record = entry();
    feed(record, DifferentialVerdict::works_without_help);
    feed(record, DifferentialVerdict::works_without_help);
    const auto before = record;

    CHECK(feed(record, DifferentialVerdict::down_everywhere) == ReviewAction::hold);

    CHECK(record.direct_successes == before.direct_successes);
    CHECK(record.blocked_confirmations == before.blocked_confirmations);
    CHECK(record.last == before.last);
    // The run continues where it was.
    CHECK(feed(record, DifferentialVerdict::works_without_help) ==
          ReviewAction::propose_retirement);
}

TEST_CASE("review: a broken tunnel says nothing about the entry either") {
    auto record = entry();
    feed(record, DifferentialVerdict::blocked_here);
    feed(record, DifferentialVerdict::blocked_here);
    const auto confirmations = record.blocked_confirmations;

    CHECK(feed(record, DifferentialVerdict::tunnel_broken) == ReviewAction::hold);

    // A transport fault must not read as "the block is confirmed again".
    CHECK(record.blocked_confirmations == confirmations);
}

TEST_CASE("review: a probe that proved nothing changes nothing") {
    auto record = entry();
    feed(record, DifferentialVerdict::works_without_help);
    const auto before = record;

    CHECK(feed(record, DifferentialVerdict::inconclusive) == ReviewAction::hold);

    CHECK(record.direct_successes == before.direct_successes);
    CHECK(record.blocked_confirmations == before.blocked_confirmations);
}

TEST_CASE("review: confirmations make us look less often, up to a ceiling") {
    const ReviewPolicy policy{3U, 8U, std::chrono::minutes{60},
                              std::chrono::minutes{480}};
    auto record = entry();

    CHECK(next_review_interval(record, policy) == std::chrono::minutes{60});
    feed(record, DifferentialVerdict::blocked_here, policy);
    CHECK(next_review_interval(record, policy) == std::chrono::minutes{120});
    feed(record, DifferentialVerdict::blocked_here, policy);
    CHECK(next_review_interval(record, policy) == std::chrono::minutes{240});
    for (int i = 0; i < 20; ++i) {
        feed(record, DifferentialVerdict::blocked_here, policy);
    }
    CHECK(next_review_interval(record, policy) == std::chrono::minutes{480});
}

TEST_CASE("review: one direct answer pulls the next look back to the base") {
    const ReviewPolicy policy{3U, 8U, std::chrono::minutes{60},
                              std::chrono::minutes{480}};
    auto record = entry();
    for (int i = 0; i < 6; ++i) {
        feed(record, DifferentialVerdict::blocked_here, policy);
    }
    REQUIRE(next_review_interval(record, policy) == std::chrono::minutes{480});

    feed(record, DifferentialVerdict::works_without_help, policy);

    // The one moment worth chasing: finish the run of confirmations quickly
    // rather than over days.
    CHECK(next_review_interval(record, policy) == std::chrono::minutes{60});
}

TEST_CASE("review: a host that came back is harder to retire the second time") {
    // Without this a site that flaps is added and removed forever, and each
    // round is a routing change somebody has to look at.
    auto record = entry();
    const ReviewPolicy policy;
    CHECK(effective_retire_after(record, policy) == 3U);

    note_retirement(record);

    CHECK(record.retirements == 1U);
    CHECK(record.direct_successes == 0U);
    CHECK(effective_retire_after(record, policy) == 4U);

    for (int i = 0; i < 3; ++i) {
        CHECK(feed(record, DifferentialVerdict::works_without_help, policy) ==
              ReviewAction::keep);
    }
    CHECK(feed(record, DifferentialVerdict::works_without_help, policy) ==
          ReviewAction::propose_retirement);
}

TEST_CASE("review: the bar rises but stops rising") {
    ReviewRecord record = entry();
    const ReviewPolicy policy{3U, 5U, std::chrono::minutes{60},
                              std::chrono::minutes{1440}};
    for (int i = 0; i < 10; ++i) note_retirement(record);

    CHECK(record.retirements == 10U);
    CHECK(effective_retire_after(record, policy) == 5U);
}

TEST_CASE("review: a policy with nonsense in it still behaves") {
    ReviewRecord record = entry();
    const ReviewPolicy policy{0U, 0U, std::chrono::minutes{0},
                              std::chrono::minutes{0}};

    CHECK(effective_retire_after(record, policy) >= 1U);
    CHECK(next_review_interval(record, policy) >= std::chrono::minutes{1});
    CHECK(feed(record, DifferentialVerdict::works_without_help, policy) ==
          ReviewAction::propose_retirement);
}

TEST_CASE("review: every action has a name to show") {
    CHECK(std::string{review_action_name(ReviewAction::keep)} == "keep");
    CHECK(std::string{review_action_name(ReviewAction::propose_retirement)} ==
          "propose_retirement");
    CHECK(std::string{review_action_name(ReviewAction::hold)} == "hold");
}

}  // namespace keen_pbr3
