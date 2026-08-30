#pragma once

// The chain, joined up: nfqws2's complaints in, proposals out.
//
// The five parts before this one each answer their own question - which hosts
// are worth looking at, which the operator has already decided about, whether a
// tunnel actually helps, when to take an entry back, and how to read a growing
// log without reading it twice. This is what runs them in order, and it exists
// so the seams are exercised rather than assumed.
//
// Two properties matter more than the sequence:
//
//   - A pass is bounded. The queue holds at most a few dozen hosts and a pass
//     probes only the top of it, because each probe is two HTTPS requests with
//     timeouts and the router has other work. What is not probed this pass is
//     still there for the next one.
//   - A pass proposes. It never edits configuration, never moves traffic and
//     never retires anything by itself. The differential probe answers "would a
//     tunnel help", which is not the same question as "do you want this host in
//     your tunnel" - and on the owner's own data half the hosts that earned a
//     route were advertising endpoints.

#include "differential_probe.hpp"
#include "entry_review.hpp"
#include "host_coverage.hpp"
#include "probe_candidates.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct TunnelCandidateProposal {
    std::string host;
    // Always blocked_here for a proposal; carried so a caller that logs or
    // renders one does not have to remember why it was made.
    DifferentialVerdict verdict{DifferentialVerdict::blocked_here};
    // What nfqws2 had counted against this host when it entered the queue.
    std::uint32_t failures{0};
    bool dpi_specific{false};
    // nfqws2 was asked to handle this host and did not manage it. Not a reason
    // to skip it - the opposite - but the operator should see it.
    bool nfqws_was_asked{false};
    std::string direct_detail;
    std::string tunnel_detail;
};

struct TunnelScanReport {
    std::vector<TunnelCandidateProposal> proposals;
    // Everything that was probed and did not earn a route, by verdict, so a
    // panel can say "checked 8, none blocked" instead of showing nothing.
    std::size_t probed{0};
    std::size_t down_everywhere{0};
    std::size_t works_without_help{0};
    std::size_t tunnel_broken{0};
    std::size_t inconclusive{0};
    // Left in the queue for the next pass.
    std::size_t remaining{0};
};

struct TunnelScanConfig {
    // Probes per pass. Each is two requests with timeouts, so this is the knob
    // that decides what the feature costs while it is running.
    std::size_t max_probes_per_pass{8};
    std::size_t queue_cap{128};
};

class TunnelCandidateScan {
public:
    // Injected so a test can drive the whole chain against modelled answers,
    // and so the caller decides which tunnel a candidate is measured against.
    using ProbeFn = std::function<DifferentialProbeReport(const std::string&)>;

    TunnelCandidateScan(CoverageIndex coverage, TunnelScanConfig config = {});

    // Feeds lines from the --hostlist-auto-debug file, as LogFollower delivers
    // them. Lines that name no host are ignored; a host that recovered leaves
    // the queue.
    void observe(const std::vector<std::string>& log_lines);

    // Probes the head of the queue and returns what it found. A host is taken
    // out of the queue whatever the verdict: an answer, even an unhelpful one,
    // is worth more than the same host blocking the queue every pass. What was
    // inconclusive will come back on its own the next time nfqws2 complains
    // about it.
    TunnelScanReport run_pass(const ProbeFn& probe);

    std::size_t queued() const noexcept;

    // Visible for the caller that renders the queue before anything is probed.
    std::vector<ProbeCandidate> queue() const;

private:
    CoverageIndex coverage_;
    TunnelScanConfig config_;
    ProbeCandidateQueue queue_;
};

}  // namespace keen_pbr3
