#include "../src/health/probe_candidates.hpp"

#include <doctest/doctest.h>

#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Lines copied from /opt/var/log/nfqws2.log on the owner's router, unedited.
constexpr const char* kUdpLine =
    "28.08.2026 19:37:25 : redto.wargaming.net : profile 8 (noname) : client "
    "192.168.1.44:55843 : proto quic : udp_in 0<=1 udp_out 4>=4";
constexpr const char* kCounterLine =
    "28.08.2026 19:37:25 : redto.wargaming.net : profile 8 (noname) : client "
    "192.168.1.44:55843 : proto quic : fail counter 1/3";
constexpr const char* kRetransLine =
    "28.08.2026 21:07:40 : b.bdstatic.com : profile 10 (noname) : client "
    "192.168.1.117:38218 : proto tls : retrans threshold reached";
constexpr const char* kRecoveredLine =
    "28.08.2026 20:11:02 : b.bdstatic.com : profile 10 (noname) : client "
    "192.168.1.117:38218 : proto tls : fail counter reset. website is working.";
constexpr const char* kAdoptedLine =
    "28.08.2026 18:02:11 : ogs.google.com : profile 10 (noname) : client "
    "192.168.1.82:51110 : proto tls : adding to /opt/etc/nfqws2/lists/auto.list";
constexpr const char* kRedirectLine =
    "28.08.2026 17:44:09 : example.ru : profile 10 (noname) : client "
    "192.168.1.82:51120 : proto tls : redirect to another domain";

NfqwsLogEvent parsed(const char* line) {
    NfqwsLogEvent event;
    REQUIRE(parse_nfqws_log_line(line, event));
    return event;
}

ProbeCandidateQueue::CoveragePredicate nothing_covered() {
    return [](const std::string&) { return false; };
}

}  // namespace

TEST_CASE("candidates: a real log line yields a host and a reason") {
    const auto udp = parsed(kUdpLine);
    CHECK(udp.host == "redto.wargaming.net");
    CHECK(udp.evidence == NfqwsEvidence::one_sided_udp);

    const auto retrans = parsed(kRetransLine);
    CHECK(retrans.host == "b.bdstatic.com");
    CHECK(retrans.evidence == NfqwsEvidence::retransmissions);

    const auto adopted = parsed(kAdoptedLine);
    CHECK(adopted.host == "ogs.google.com");
    CHECK(adopted.evidence == NfqwsEvidence::adopted);
}

TEST_CASE("candidates: the counter line is a consequence, not a second failure") {
    // Every failure is followed by "fail counter N/N". Counting both would
    // double every host's weight and change the ranking for no reason.
    const auto event = parsed(kCounterLine);

    CHECK(event.evidence == NfqwsEvidence::other);
    CHECK_FALSE(nfqws_evidence_is_failure(event.evidence));
}

TEST_CASE("candidates: recovery is read before the words it contains") {
    // "fail counter reset. website is working." contains "fail counter". Read in
    // the wrong order it becomes a failure, and a site that came back stays
    // queued for a tunnel it does not need. There were 320 of these lines.
    const auto event = parsed(kRecoveredLine);

    CHECK(event.evidence == NfqwsEvidence::recovered);
    CHECK_FALSE(nfqws_evidence_is_failure(event.evidence));
}

TEST_CASE("candidates: a host that came back leaves the queue") {
    ProbeCandidateQueue queue{nothing_covered()};
    queue.observe(parsed(kRetransLine));
    REQUIRE(queue.size() == 1U);

    queue.observe(parsed(kRecoveredLine));

    CHECK(queue.size() == 0U);
}

TEST_CASE("candidates: what the operator already decided about is not a candidate") {
    // Covered means: a routing rule holds it, or nfqws2's own user.list or
    // exclude.list names it, or it came from the catalogue.
    ProbeCandidateQueue queue{[](const std::string& host) {
        return host == "b.bdstatic.com";
    }};

    queue.observe(parsed(kRetransLine));
    queue.observe(parsed(kUdpLine));

    const auto ranked = queue.ranked();
    REQUIRE(ranked.size() == 1U);
    CHECK(ranked.front().host == "redto.wargaming.net");
}

TEST_CASE("candidates: the one DPI-specific shape outranks a pile of the rest") {
    // 88 redirects against 5842 retransmissions and one-sided UDP exchanges on
    // the owner's router. Weight by count alone and the only trustworthy
    // evidence never surfaces.
    ProbeCandidateQueue queue{nothing_covered()};
    for (int i = 0; i < 50; ++i) queue.observe(parsed(kRetransLine));
    queue.observe(parsed(kRedirectLine));

    const auto ranked = queue.ranked();
    REQUIRE(ranked.size() == 2U);
    CHECK(ranked.front().host == "example.ru");
    CHECK(ranked.front().dpi_specific);
    CHECK(ranked.back().failures == 50U);
}

TEST_CASE("candidates: adoption by nfqws2 outranks sheer volume") {
    ProbeCandidateQueue queue{nothing_covered()};
    for (int i = 0; i < 20; ++i) queue.observe(parsed(kUdpLine));
    queue.observe(parsed(kAdoptedLine));

    const auto ranked = queue.ranked();
    REQUIRE(ranked.size() == 2U);
    CHECK(ranked.front().host == "ogs.google.com");
    CHECK(ranked.front().adopted_by_nfqws);
}

TEST_CASE("candidates: the queue is bounded, and drops the weakest not the newest") {
    // 1552 distinct hosts appeared in one log on a router with 134 MiB free.
    ProbeCandidateQueue queue{nothing_covered(), 3U};
    for (const auto* host : {"a.example.com", "b.example.com", "c.example.com"}) {
        NfqwsLogEvent event{host, NfqwsEvidence::retransmissions};
        queue.observe(event);
    }
    REQUIRE(queue.size() == 3U);

    NfqwsLogEvent late{"late.example.com", NfqwsEvidence::redirect};
    queue.observe(late);

    const auto ranked = queue.ranked();
    CHECK(ranked.size() == 3U);
    CHECK(ranked.front().host == "late.example.com");
}

TEST_CASE("candidates: the same host is counted once, with its evidence merged") {
    ProbeCandidateQueue queue{nothing_covered()};
    queue.observe(parsed(kRetransLine));
    queue.observe(parsed(kRetransLine));
    NfqwsLogEvent redirect{"b.bdstatic.com", NfqwsEvidence::redirect};
    queue.observe(redirect);

    const auto ranked = queue.ranked();
    REQUIRE(ranked.size() == 1U);
    CHECK(ranked.front().failures == 3U);
    CHECK(ranked.front().dpi_specific);
}

TEST_CASE("candidates: lines that name no host are skipped") {
    NfqwsLogEvent event;
    CHECK_FALSE(parse_nfqws_log_line("", event));
    CHECK_FALSE(parse_nfqws_log_line("28.08.2026 19:37:25", event));
    CHECK_FALSE(parse_nfqws_log_line(
        "28.08.2026 19:37:25 : not a host : profile 8 : x : y : z", event));
}

TEST_CASE("candidates: an address instead of a name is still a candidate") {
    // A connection with no name in it keys on the address, and an address can
    // be probed and routed just as well. Recorded here because it decides what
    // the caller has to accept, not because it is obvious.
    NfqwsLogEvent event;
    REQUIRE(parse_nfqws_log_line(
        "28.08.2026 19:37:25 : 5.9.202.203 : profile 10 (noname) : client "
        "192.168.1.82:1 : proto tls : retrans threshold reached",
        event));
    CHECK(event.host == "5.9.202.203");
}

TEST_CASE("candidates: every reason has a name to show next to the host") {
    CHECK(std::string{nfqws_evidence_name(NfqwsEvidence::redirect)} == "redirect");
    CHECK(std::string{nfqws_evidence_name(NfqwsEvidence::recovered)} == "recovered");
    CHECK(std::string{nfqws_evidence_name(NfqwsEvidence::adopted)} == "adopted");
    CHECK(std::string{nfqws_evidence_name(NfqwsEvidence::other)} == "other");
}

}  // namespace keen_pbr3
