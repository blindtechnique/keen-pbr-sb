#include "../src/health/log_follower.hpp"

#include <doctest/doctest.h>

#include <string>

namespace keen_pbr3 {

namespace {

LogPosition at(const std::uint64_t offset,
               const char* fingerprint,
               const char* partial = "") {
    LogPosition position;
    position.offset = offset;
    position.fingerprint = fingerprint;
    position.partial_line = partial;
    return position;
}

}  // namespace

TEST_CASE("follow: a first pass reads what is there") {
    CHECK(decide_follow(LogPosition{}, 1024U, "head") == FollowDecision::restart);
    CHECK(decide_follow(LogPosition{}, 0U, "") == FollowDecision::nothing_new);
}

TEST_CASE("follow: a file that grew and begins the same way is resumed") {
    CHECK(decide_follow(at(100U, "head"), 200U, "head") == FollowDecision::resume);
}

TEST_CASE("follow: nothing added means nothing to do") {
    CHECK(decide_follow(at(100U, "head"), 100U, "head") ==
          FollowDecision::nothing_new);
}

TEST_CASE("follow: a rotated file is read from the beginning") {
    // Rotation renames the old file and starts a new one. The offset would
    // land in the middle of a line of somebody else's text.
    CHECK(decide_follow(at(100U, "old head"), 4096U, "new head") ==
          FollowDecision::restart);
}

TEST_CASE("follow: a file truncated in place is read from the beginning") {
    // Some rotators truncate rather than rename, and then the beginning is
    // unchanged while everything after it is gone.
    CHECK(decide_follow(at(5000U, "head"), 12U, "head") == FollowDecision::restart);
}

TEST_CASE("follow: a rotated file that happens to be longer is still restarted") {
    // Size alone would say "resume" here. The fingerprint is what catches it.
    CHECK(decide_follow(at(100U, "old head"), 900000U, "new head") ==
          FollowDecision::restart);
}

TEST_CASE("follow: complete lines come out, the fragment stays behind") {
    const auto result = split_followed_lines(at(10U, "head"), "one\ntwo\nthre", 4096U);

    REQUIRE(result.lines.size() == 2U);
    CHECK(result.lines[0] == "one");
    CHECK(result.lines[1] == "two");
    CHECK(result.position.partial_line == "thre");
    CHECK(result.position.offset == 10U + 12U);
    CHECK_FALSE(result.truncated_by_budget);
}

TEST_CASE("follow: a line split across two passes is delivered once and whole") {
    const auto first = split_followed_lines(at(0U, "head"), "alpha\nbe", 4096U);
    REQUIRE(first.lines.size() == 1U);
    CHECK(first.position.partial_line == "be");

    const auto second = split_followed_lines(first.position, "ta\ngamma\n", 4096U);

    REQUIRE(second.lines.size() == 2U);
    CHECK(second.lines[0] == "beta");
    CHECK(second.lines[1] == "gamma");
    CHECK(second.position.partial_line.empty());
    // The carried fragment was counted when it arrived, not again now.
    CHECK(second.position.offset == 8U + 9U);
}

TEST_CASE("follow: the budget stops a backlog from becoming strings all at once") {
    const std::string chunk = "aaa\nbbb\nccc\n";

    const auto result = split_followed_lines(at(0U, "head"), chunk, 8U);

    CHECK(result.truncated_by_budget);
    REQUIRE(result.lines.size() == 2U);
    CHECK(result.lines[1] == "bbb");
    CHECK(result.position.offset == 8U);
    // The rest is not lost - the next pass starts where this one stopped.
    const auto next = split_followed_lines(result.position, "ccc\n", 4096U);
    REQUIRE(next.lines.size() == 1U);
    CHECK(next.lines[0] == "ccc");
}

TEST_CASE("follow: a fragment that cannot be a line is thrown away") {
    // A corrupt write, or the wrong file entirely. Carrying it would mean
    // carrying it again every pass until the router ran out of memory.
    const std::string huge(kMaxPartialLine + 10U, 'x');

    const auto result = split_followed_lines(at(0U, "head"), huge, huge.size() + 1U);

    CHECK(result.lines.empty());
    CHECK(result.dropped_oversize_fragment);
    CHECK(result.position.partial_line.empty());
    // The offset still advances, so the pass makes progress rather than
    // re-reading the same bytes forever.
    CHECK(result.position.offset == huge.size());
}

TEST_CASE("follow: carriage returns and empty lines do not become entries") {
    const auto result =
        split_followed_lines(at(0U, "head"), "one\r\n\n\ntwo\r\n", 4096U);

    REQUIRE(result.lines.size() == 2U);
    CHECK(result.lines[0] == "one");
    CHECK(result.lines[1] == "two");
}

TEST_CASE("follow: the fingerprint is carried forward unchanged") {
    const auto result = split_followed_lines(at(5U, "head"), "x\n", 4096U);

    CHECK(result.position.fingerprint == "head");
}

}  // namespace keen_pbr3
