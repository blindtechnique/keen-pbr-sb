#pragma once

// `keen-pbr scan-tunnel-candidates <outbound>` - one pass of the chain, on
// demand, printed.
//
// The pieces this drives have been testable since they were written; what they
// have not been is reachable. Until the daemon runs them on a schedule and the
// panel shows what they found, this is how an operator asks the question:
// "of everything nfqws2 has been failing on, which hosts would this tunnel
// actually fix?"
//
// It reads and probes. It writes no configuration and moves no traffic: the
// answer is a list to look at, and a host that would work through a tunnel is
// still not necessarily a host anybody wants there.

#include "../config/config.hpp"

#include <string>

namespace keen_pbr3 {

struct ScanTunnelCandidatesOptions {
    // Which outbound to measure against. Its interface is what the tunnel leg
    // is pinned to.
    std::string outbound_tag;
    // How many hosts to probe in this pass. Two requests each.
    std::size_t max_probes{8};
};

// Returns a process exit code: 0 when the pass ran, 1 when it could not.
int run_scan_tunnel_candidates(const Config& config,
                               const ScanTunnelCandidatesOptions& options);

}  // namespace keen_pbr3
