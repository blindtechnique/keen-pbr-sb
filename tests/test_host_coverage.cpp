#include "../src/health/host_coverage.hpp"

#include "../src/health/probe_candidates.hpp"

#include <doctest/doctest.h>

#include <string>

namespace keen_pbr3 {

namespace {

CoverageIndex world() {
    CoverageIndex index;
    index.routing_lists.push_back(
        {"b2ip", {"youtube.com", "rutracker.org"}, {"5.9.0.0/16"}});
    index.routing_lists.push_back({"porn", {"redgifs.com"}, {}});
    index.nfqws_excluded = {"gosuslugi.ru"};
    index.nfqws_handled = {"linkedin.com", "thumbnails.libretro.com"};
    return index;
}

}  // namespace

TEST_CASE("coverage: a list that names the host exactly says so") {
    const auto index = world();

    const auto verdict = classify_coverage(index, "youtube.com");

    CHECK(verdict.source == CoverageSource::routing_list);
    CHECK(verdict.list_name == "b2ip");
    CHECK(verdict.entry == "youtube.com");
    CHECK(verdict.exact);
    CHECK(coverage_excludes_candidate(verdict));
}

TEST_CASE("coverage: a parent entry covers the subdomain, and says it was a parent") {
    const auto index = world();

    const auto verdict = classify_coverage(index, "www.youtube.com");

    CHECK(verdict.source == CoverageSource::routing_list);
    CHECK(verdict.entry == "youtube.com");
    CHECK_FALSE(verdict.exact);
}

TEST_CASE("coverage: the boundary is a dot, not a substring") {
    const auto index = world();

    CHECK(classify_coverage(index, "notyoutube.com").source == CoverageSource::none);
    CHECK(classify_coverage(index, "youtube.com.evil.tld").source ==
          CoverageSource::none);
}

TEST_CASE("coverage: a host nfqws2 was asked to handle is still a candidate") {
    // The decision this file exists for, and it was settled by measurement.
    // thumbnails.libretro.com sat in nfqws2's user.list with the service
    // restarted and the rotator given a full cycle of eight strategies: nothing
    // got through in sixteen attempts, while linkedin.com from the same file
    // opened directly in the same minute. Treating that file as coverage would
    // have hidden the one host that actually needed a tunnel.
    const auto index = world();

    const auto verdict = classify_coverage(index, "thumbnails.libretro.com");

    CHECK(verdict.source == CoverageSource::none);
    CHECK_FALSE(coverage_excludes_candidate(verdict));
    // It is still worth telling the operator that nfqws2 is already trying.
    CHECK(nfqws_was_asked_about(index, "thumbnails.libretro.com"));
    CHECK(nfqws_was_asked_about(index, "www.linkedin.com"));
    CHECK_FALSE(nfqws_was_asked_about(index, "example.com"));
}

TEST_CASE("coverage: an explicit hands-off is honoured") {
    const auto index = world();

    const auto verdict = classify_coverage(index, "www.gosuslugi.ru");

    CHECK(verdict.source == CoverageSource::nfqws_exclude);
    CHECK(verdict.entry == "gosuslugi.ru");
    CHECK(coverage_excludes_candidate(verdict));
}

TEST_CASE("coverage: an address is matched against addresses") {
    const auto index = world();

    const auto verdict = classify_coverage(index, "5.9.202.203");

    CHECK(verdict.source == CoverageSource::routing_list);
    CHECK(verdict.list_name == "b2ip");
    CHECK(verdict.entry == "5.9.0.0/16");
}

TEST_CASE("coverage: an address is never covered by a name-shaped entry") {
    // nfqws2 keeps names and addresses in separate files for a reason, and a
    // hostlist walk over an address would compare labels that are not labels.
    CoverageIndex index;
    index.routing_lists.push_back({"names", {"5.9.202.203"}, {}});
    index.nfqws_excluded = {"5.9.202.203"};

    CHECK(classify_coverage(index, "5.9.202.203").source == CoverageSource::none);
    CHECK_FALSE(nfqws_was_asked_about(index, "5.9.202.203"));
}

TEST_CASE("coverage: an address outside every prefix is uncovered") {
    const auto index = world();

    CHECK(classify_coverage(index, "1.1.1.1").source == CoverageSource::none);
}

TEST_CASE("coverage: lists are consulted in order, so the answer is stable") {
    CoverageIndex index;
    index.routing_lists.push_back({"first", {"example.com"}, {}});
    index.routing_lists.push_back({"second", {"example.com"}, {}});

    CHECK(classify_coverage(index, "example.com").list_name == "first");
}

TEST_CASE("coverage: case and an empty target are handled without surprises") {
    const auto index = world();

    CHECK(classify_coverage(index, "WWW.YouTube.COM").source ==
          CoverageSource::routing_list);
    CHECK(classify_coverage(index, "").source == CoverageSource::none);
}

TEST_CASE("coverage: the predicate fits the queue it was made for") {
    // The seam between stage one and stage two, exercised rather than assumed.
    const auto index = world();
    ProbeCandidateQueue queue{coverage_predicate(index)};

    queue.observe(NfqwsLogEvent{"www.youtube.com", NfqwsEvidence::retransmissions});
    queue.observe(NfqwsLogEvent{"gosuslugi.ru", NfqwsEvidence::retransmissions});
    queue.observe(
        NfqwsLogEvent{"thumbnails.libretro.com", NfqwsEvidence::retransmissions});
    queue.observe(NfqwsLogEvent{"5.9.202.203", NfqwsEvidence::retransmissions});

    const auto ranked = queue.ranked();

    REQUIRE(ranked.size() == 1U);
    CHECK(ranked.front().host == "thumbnails.libretro.com");
}

TEST_CASE("coverage: every source has a name to show") {
    CHECK(std::string{coverage_source_name(CoverageSource::routing_list)} ==
          "routing_list");
    CHECK(std::string{coverage_source_name(CoverageSource::nfqws_exclude)} ==
          "nfqws_exclude");
    CHECK(std::string{coverage_source_name(CoverageSource::none)} == "none");
}

}  // namespace keen_pbr3
