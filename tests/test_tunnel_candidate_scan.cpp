#include "../src/health/tunnel_candidate_scan.hpp"

#include <doctest/doctest.h>

#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Lines copied from /opt/var/log/nfqws2.log on the owner's router.
std::string retrans(const std::string& host) {
    return "28.08.2026 21:07:40 : " + host +
           " : profile 10 (noname) : client 192.168.1.117:38218 : proto tls : "
           "retrans threshold reached";
}

std::string redirect(const std::string& host) {
    return "28.08.2026 17:44:09 : " + host +
           " : profile 10 (noname) : client 192.168.1.82:51120 : proto tls : "
           "redirect to another domain";
}

std::string recovered(const std::string& host) {
    return "28.08.2026 20:11:02 : " + host +
           " : profile 10 (noname) : client 192.168.1.117:38218 : proto tls : "
           "fail counter reset. website is working.";
}

CoverageIndex coverage_with(std::vector<std::string> routed = {},
                            std::vector<std::string> nfqws_handled = {}) {
    CoverageIndex index;
    index.routing_lists.push_back({"b2ip", std::move(routed), {}});
    index.nfqws_handled = std::move(nfqws_handled);
    return index;
}

DifferentialProbeReport answer(DifferentialVerdict verdict) {
    DifferentialProbeReport report;
    report.verdict = verdict;
    report.direct.detail = "direct leg";
    report.tunnel.detail = "tunnel leg";
    return report;
}

// A probe that answers from a table, and records what it was asked.
struct ScriptedProbe {
    std::map<std::string, DifferentialVerdict> answers;
    mutable std::vector<std::string> asked;

    DifferentialProbeReport operator()(const std::string& host) const {
        asked.push_back(host);
        const auto it = answers.find(host);
        return answer(it == answers.end() ? DifferentialVerdict::inconclusive
                                          : it->second);
    }
};

}  // namespace

TEST_CASE("scan: the chain runs end to end and proposes only what earned it") {
    // The seams exercised rather than assumed: log lines in, coverage applied,
    // ranking honoured, verdicts sorted.
    TunnelCandidateScan scan(coverage_with(), TunnelScanConfig{8, 128});
    scan.observe({retrans("thumbnails.libretro.com"), retrans("i.ibb.co"),
                  retrans("pagead2.googlesyndication.com"),
                  retrans("www.google.com")});

    ScriptedProbe probe;
    probe.answers["thumbnails.libretro.com"] = DifferentialVerdict::blocked_here;
    probe.answers["i.ibb.co"] = DifferentialVerdict::blocked_here;
    probe.answers["pagead2.googlesyndication.com"] =
        DifferentialVerdict::down_everywhere;
    probe.answers["www.google.com"] = DifferentialVerdict::works_without_help;

    const auto report = scan.run_pass(std::ref(probe));

    CHECK(report.probed == 4);
    REQUIRE(report.proposals.size() == 2);
    CHECK(report.down_everywhere == 1);
    CHECK(report.works_without_help == 1);
    // Everything answered leaves the queue, so the next pass looks at hosts
    // nobody has examined.
    CHECK(report.remaining == 0);
    CHECK(scan.queued() == 0);
}

TEST_CASE("scan: what the operator already routes never reaches a probe") {
    TunnelCandidateScan scan(coverage_with({"youtube.com"}));
    scan.observe({retrans("www.youtube.com"), retrans("i.ibb.co")});

    ScriptedProbe probe;
    probe.answers["i.ibb.co"] = DifferentialVerdict::blocked_here;

    const auto report = scan.run_pass(std::ref(probe));

    CHECK(report.probed == 1);
    REQUIRE(probe.asked.size() == 1);
    CHECK(probe.asked.front() == "i.ibb.co");
}

TEST_CASE("scan: a host nfqws2 could not fix is proposed, and said to be so") {
    // The libretro case. Being in nfqws2's own hostlist is not coverage - it is
    // the strongest evidence there is - but the operator should see it.
    TunnelCandidateScan scan(
        coverage_with({}, {"thumbnails.libretro.com"}));
    scan.observe({retrans("thumbnails.libretro.com")});

    ScriptedProbe probe;
    probe.answers["thumbnails.libretro.com"] = DifferentialVerdict::blocked_here;

    const auto report = scan.run_pass(std::ref(probe));

    REQUIRE(report.proposals.size() == 1);
    CHECK(report.proposals.front().host == "thumbnails.libretro.com");
    CHECK(report.proposals.front().nfqws_was_asked);
}

TEST_CASE("scan: a pass is bounded, and the rest waits rather than disappears") {
    // Each probe is two HTTPS requests with timeouts. A router that has been
    // collecting complaints for a week must not spend a morning on them.
    TunnelCandidateScan scan(coverage_with(), TunnelScanConfig{2, 128});
    scan.observe({retrans("a.example.com"), retrans("b.example.com"),
                  retrans("c.example.com"), retrans("d.example.com")});

    ScriptedProbe probe;
    const auto report = scan.run_pass(std::ref(probe));

    CHECK(report.probed == 2);
    CHECK(report.remaining == 2);
    CHECK(scan.queued() == 2);

    const auto second = scan.run_pass(std::ref(probe));
    CHECK(second.probed == 2);
    CHECK(second.remaining == 0);
}

TEST_CASE("scan: the strongest evidence is probed first") {
    // 88 redirects against 5842 of everything else on the owner's router. If
    // the pass limit is spent on volume, the one trustworthy signal never gets
    // looked at.
    TunnelCandidateScan scan(coverage_with(), TunnelScanConfig{1, 128});
    for (int i = 0; i < 20; ++i) scan.observe({retrans("loud.example.com")});
    scan.observe({redirect("quiet.example.ru")});

    ScriptedProbe probe;
    scan.run_pass(std::ref(probe));

    REQUIRE(probe.asked.size() == 1);
    CHECK(probe.asked.front() == "quiet.example.ru");
}

TEST_CASE("scan: a host that came back is dropped before anything is spent") {
    TunnelCandidateScan scan(coverage_with());
    scan.observe({retrans("b.bdstatic.com")});
    REQUIRE(scan.queued() == 1);

    scan.observe({recovered("b.bdstatic.com")});

    ScriptedProbe probe;
    const auto report = scan.run_pass(std::ref(probe));
    CHECK(report.probed == 0);
    CHECK(probe.asked.empty());
}

TEST_CASE("scan: an unusable answer is counted, not turned into a proposal") {
    TunnelCandidateScan scan(coverage_with());
    scan.observe({retrans("a.example.com"), retrans("b.example.com")});

    ScriptedProbe probe;
    probe.answers["a.example.com"] = DifferentialVerdict::inconclusive;
    probe.answers["b.example.com"] = DifferentialVerdict::tunnel_broken;

    const auto report = scan.run_pass(std::ref(probe));

    CHECK(report.proposals.empty());
    CHECK(report.inconclusive == 1);
    CHECK(report.tunnel_broken == 1);
    // A panel can say "checked 2, none blocked" instead of showing nothing.
    CHECK(report.probed == 2);
}

TEST_CASE("scan: without a probe nothing is claimed and nothing is lost") {
    TunnelCandidateScan scan(coverage_with());
    scan.observe({retrans("a.example.com")});

    const auto report = scan.run_pass(nullptr);

    CHECK(report.probed == 0);
    CHECK(report.proposals.empty());
    CHECK(report.remaining == 1);
}

TEST_CASE("scan: lines that name no host cost nothing") {
    TunnelCandidateScan scan(coverage_with());
    scan.observe({"", "28.08.2026 21:07:40", "not a log line at all"});

    CHECK(scan.queued() == 0);
}

}  // namespace keen_pbr3
