#pragma once

// Who is worth probing, out of everything nfqws2 complains about.
//
// nfqws2 writes its auto-hostlist reasoning to the file named by
// --hostlist-auto-debug, one line per decision, with the host in it. On the
// owner's router that file held 13576 lines naming 1552 distinct hosts. It is
// the cheapest signal we have and it needs no new kernel work - but it is not
// an answer, for two measured reasons:
//
//   1. Of 5925 recorded causes, only 88 were the one shape nfqws2 itself treats
//      as DPI-specific (a redirect to another domain). The rest - retransmission
//      thresholds and one-sided UDP - are equally the signature of a server that
//      is down. The top of the list by failure count was advertising and
//      telemetry: safebrowsing.google.com, googleadservices, doubleclick.
//   2. A host that recovers is announced too ("fail counter reset. website is
//      working." - 320 times), and anything still counting it as a candidate is
//      simply out of date.
//
// So this file does not decide anything. It turns a noisy log into a short,
// bounded, ranked queue for the differential probe, which is the only thing
// here that can tell interference from an outage.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NfqwsEvidence {
    // "redirect to another domain". The only DPI-specific shape nfqws2 reports,
    // and the only one that survives being read on its own.
    redirect,
    // "retrans threshold reached".
    retransmissions,
    // "udp_in 0<=1 udp_out 4>=4".
    one_sided_udp,
    // "incoming RST".
    incoming_reset,
    // "adding to .../auto.list": nfqws2 decided this host is blocked and took
    // it over. Evidence about its opinion, not about the outcome.
    adopted,
    // "fail counter reset. website is working." - it recovered. This removes a
    // host from the queue rather than adding to it.
    recovered,
    // "fail counter N/N" and anything else: a consequence, carried so a caller
    // can show it, never a reason on its own.
    other,
};

struct NfqwsLogEvent {
    std::string host;
    NfqwsEvidence evidence{NfqwsEvidence::other};
};

// Parses one line of the --hostlist-auto-debug file. Returns false for anything
// that does not carry a host, including the file's own noise.
//
// The format is positional, fields separated by " : ":
//   28.08.2026 19:37:25 : host : profile 8 (noname) : client 1.2.3.4:5 : proto tls : message
bool parse_nfqws_log_line(const std::string& line, NfqwsLogEvent& event) noexcept;

struct ProbeCandidate {
    std::string host;
    // How many failure-shaped events named this host.
    std::uint32_t failures{0};
    // True once "redirect to another domain" was seen: the one piece of
    // evidence that points at interference rather than at an outage.
    bool dpi_specific{false};
    // True once nfqws2 took the host into its own auto-hostlist.
    bool adopted_by_nfqws{false};
};

// Accumulates hosts worth probing.
//
// Bounded on purpose: the router this runs on had 134 MiB free and 388 MiB
// already in swap. When the cap is reached the weakest candidate is dropped
// rather than the newest refused, so a late redirect still displaces an old
// pile of retransmissions.
class ProbeCandidateQueue {
public:
    // `covered` answers "is this host already handled" - by a routing rule, by
    // nfqws2's own user.list or exclude.list, or by the catalogue. A covered
    // host is not a candidate: the operator already decided about it.
    using CoveragePredicate = std::function<bool(const std::string&)>;

    explicit ProbeCandidateQueue(CoveragePredicate covered,
                                 std::size_t cap = 128U)
        : covered_(std::move(covered)), cap_(cap == 0U ? 1U : cap) {}

    void observe(const NfqwsLogEvent& event);

    // Ranked: DPI-specific evidence first, then hosts nfqws2 adopted, then by
    // how often they failed, then by name so the order is stable to look at.
    std::vector<ProbeCandidate> ranked() const;

    std::size_t size() const noexcept { return candidates_.size(); }

private:
    CoveragePredicate covered_;
    std::size_t cap_;
    std::vector<ProbeCandidate> candidates_;

    ProbeCandidate* find(const std::string& host);
    void drop_weakest();
};

// True for the shapes that mean "this connection broke", as opposed to
// bookkeeping. Exposed because the caller shows the reason next to the host.
bool nfqws_evidence_is_failure(NfqwsEvidence evidence) noexcept;

const char* nfqws_evidence_name(NfqwsEvidence evidence) noexcept;

}  // namespace keen_pbr3
