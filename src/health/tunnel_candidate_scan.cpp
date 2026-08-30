#include "tunnel_candidate_scan.hpp"

#include <algorithm>

namespace keen_pbr3 {

TunnelCandidateScan::TunnelCandidateScan(CoverageIndex coverage,
                                         TunnelScanConfig config)
    : coverage_(std::move(coverage)),
      config_(config),
      // The predicate holds a reference to coverage_, which lives as long as
      // this object does. Built here rather than taken from outside so the
      // lifetime is one thing to reason about instead of two.
      queue_([this](const std::string& host) {
                 return coverage_excludes_candidate(
                     classify_coverage(coverage_, host));
             },
             config.queue_cap) {}

void TunnelCandidateScan::observe(const std::vector<std::string>& log_lines) {
    for (const auto& line : log_lines) {
        NfqwsLogEvent event;
        if (!parse_nfqws_log_line(line, event)) {
            continue;
        }
        queue_.observe(event);
    }
}

std::size_t TunnelCandidateScan::queued() const noexcept {
    return queue_.size();
}

std::vector<ProbeCandidate> TunnelCandidateScan::queue() const {
    return queue_.ranked();
}

TunnelScanReport TunnelCandidateScan::run_pass(const ProbeFn& probe) {
    TunnelScanReport report;
    if (!probe) {
        report.remaining = queue_.size();
        return report;
    }

    const auto ranked = queue_.ranked();
    const auto limit = std::min(ranked.size(), config_.max_probes_per_pass);

    for (std::size_t index = 0; index < limit; ++index) {
        const auto& candidate = ranked[index];
        const auto answer = probe(candidate.host);
        ++report.probed;

        switch (answer.verdict) {
            case DifferentialVerdict::blocked_here: {
                TunnelCandidateProposal proposal;
                proposal.host = candidate.host;
                proposal.verdict = answer.verdict;
                proposal.failures = candidate.failures;
                proposal.dpi_specific = candidate.dpi_specific;
                proposal.nfqws_was_asked =
                    nfqws_was_asked_about(coverage_, candidate.host);
                proposal.direct_detail = answer.direct.detail;
                proposal.tunnel_detail = answer.tunnel.detail;
                report.proposals.push_back(std::move(proposal));
                break;
            }
            case DifferentialVerdict::down_everywhere:
                ++report.down_everywhere;
                break;
            case DifferentialVerdict::works_without_help:
                ++report.works_without_help;
                break;
            case DifferentialVerdict::tunnel_broken:
                ++report.tunnel_broken;
                break;
            case DifferentialVerdict::inconclusive:
                ++report.inconclusive;
                break;
        }

        // Out of the queue whatever the answer. A host that stayed would be
        // probed again every pass and keep the ones behind it waiting; nfqws2
        // will complain again if it is still broken, and then it comes back
        // with fresh evidence rather than stale.
        queue_.forget(candidate.host);
    }

    report.remaining = queue_.size();
    return report;
}

}  // namespace keen_pbr3
