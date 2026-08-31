#include "../src/lists/list_shrink_guard.hpp"

#include <doctest/doctest.h>

#include <sstream>

namespace keen_pbr3 {

TEST_CASE("counting: entries are counted by kind, noise is not counted") {
    std::istringstream body(
        "# заголовок каталога\n"
        "example.com\n"
        "\n"
        "*.example.org\n"
        "10.0.0.0/8\n"
        "1.2.3.4\n"
        "2001:db8::/32\n"
        "   \n"
        "not a host at all !!\n");

    const auto counts = count_list_entries(body);

    // Comments, blanks and unparseable junk are not entries: counting them
    // would make the guard compare noise and let a broken update through by
    // arriving with enough garbage in it.
    CHECK(counts.domains == 2);
    CHECK(counts.cidrs == 2);
    CHECK(counts.ips == 1);
    CHECK(counts.total() == 5);
}

TEST_CASE("counting: an empty body counts as nothing, not as a failure") {
    std::istringstream empty("");
    CHECK(count_list_entries(empty).total() == 0);

    std::istringstream only_noise("# всё выкинули\n\n\n");
    CHECK(count_list_entries(only_noise).total() == 0);
}

namespace {

ListEntryCounts domains(std::int64_t count) {
    ListEntryCounts counts;
    counts.domains = count;
    return counts;
}

}  // namespace

TEST_CASE("shrink guard: a first download has nothing to shrink from") {
    // Refusing here would mean a list could never arrive at all.
    const auto decision = decide_list_shrink(ListEntryCounts{}, domains(5000));

    CHECK(decision.verdict == ListShrinkVerdict::publish);
    CHECK(decision.reason.empty());
}

TEST_CASE("shrink guard: an update that keeps almost everything is published") {
    const auto decision = decide_list_shrink(domains(5000), domains(4900));

    CHECK(decision.verdict == ListShrinkVerdict::publish);
    CHECK(decision.retained_fraction > 0.9);
}

TEST_CASE("shrink guard: a list that grows is never suspicious") {
    const auto decision = decide_list_shrink(domains(5000), domains(9000));

    CHECK(decision.verdict == ListShrinkVerdict::publish);
}

TEST_CASE("shrink guard: an empty update against a real list is refused") {
    // The case this exists for: the source moved, a CDN served a stub, or a
    // generator upstream broke. The download succeeds, the file parses, and
    // publishing it would unroute everything the list carried while nothing
    // says so.
    const auto decision = decide_list_shrink(domains(5000), ListEntryCounts{});

    CHECK(decision.verdict == ListShrinkVerdict::refuse);
    CHECK(decision.reason.find("no entries at all") != std::string::npos);
    CHECK(decision.reason.find("5000") != std::string::npos);
}

TEST_CASE("shrink guard: losing more than half is refused, and says by how much") {
    const auto decision = decide_list_shrink(domains(5000), domains(1000));

    CHECK(decision.verdict == ListShrinkVerdict::refuse);
    CHECK(decision.retained_fraction == doctest::Approx(0.2));
    CHECK(decision.reason.find("1000") != std::string::npos);
    CHECK(decision.reason.find("5000") != std::string::npos);
    // The operator has to be able to tell how bad it was without doing the
    // division themselves.
    CHECK(decision.reason.find("20%") != std::string::npos);
}

TEST_CASE("shrink guard: exactly at the threshold is published") {
    // The threshold is what a source is allowed to lose, not what it must
    // beat: a rule that refuses at its own boundary is a rule nobody can
    // reason about.
    const auto decision = decide_list_shrink(domains(1000), domains(500));

    CHECK(decision.verdict == ListShrinkVerdict::publish);
    CHECK(decision.retained_fraction == doctest::Approx(0.5));
}

TEST_CASE("shrink guard: small lists move a lot and mean nothing by it") {
    // Three entries becoming one is an edit, not a failure. Relative change
    // says almost nothing in the small, which is what the floor is for.
    const auto decision = decide_list_shrink(domains(3), domains(1));

    CHECK(decision.verdict == ListShrinkVerdict::publish);
}

TEST_CASE("shrink guard: the floor is the source's to set") {
    ListShrinkPolicy strict;
    strict.min_previous_entries = 2;
    strict.min_retained_fraction = 0.9;

    const auto guarded = decide_list_shrink(domains(10), domains(5), strict);
    CHECK(guarded.verdict == ListShrinkVerdict::refuse);

    ListShrinkPolicy lenient;
    lenient.min_previous_entries = 50;
    lenient.min_retained_fraction = 0.1;

    const auto allowed = decide_list_shrink(domains(5000), domains(600), lenient);
    CHECK(allowed.verdict == ListShrinkVerdict::publish);
}

TEST_CASE("shrink guard: every kind of entry counts, not just domains") {
    // A list of address ranges that empties is exactly as broken as a list of
    // names that empties, and an SRS source can carry both.
    ListEntryCounts before;
    before.domains = 100;
    before.cidrs = 400;
    before.ips = 500;

    ListEntryCounts after;
    after.domains = 100;

    const auto decision = decide_list_shrink(before, after);

    CHECK(decision.verdict == ListShrinkVerdict::refuse);
    CHECK(decision.retained_fraction == doctest::Approx(0.1));
}

TEST_CASE("shrink guard: a shape change that keeps the total is published") {
    // The same source may legitimately move entries between kinds - a
    // generator that starts emitting suffixes instead of exact names, say.
    // Only the total is evidence about loss.
    ListEntryCounts before;
    before.domains = 1000;

    ListEntryCounts after;
    after.domains = 200;
    after.cidrs = 800;

    CHECK(decide_list_shrink(before, after).verdict ==
          ListShrinkVerdict::publish);
}

}  // namespace keen_pbr3
