#include "scan_tunnel_candidates.hpp"

#include "../health/differential_probe.hpp"
#include "../health/nfqws_scan_source.hpp"
#include "../health/tunnel_candidate_scan.hpp"
#include "../http/http_transport.hpp"
#include "../log/logger.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace keen_pbr3 {

namespace {

void print_report(const TunnelScanReport& report,
                  const std::string& outbound_tag) {
    std::cout << "\nProbed " << report.probed << " host(s) against "
              << outbound_tag << "; " << report.remaining
              << " left for the next pass.\n\n";

    if (report.proposals.empty()) {
        std::cout << "No host needs this tunnel.\n";
    } else {
        std::cout << "These answered only through the tunnel:\n\n";
        for (const auto& proposal : report.proposals) {
            std::cout << "  " << proposal.host << "\n";
            std::cout << "      nfqws2 failures: " << proposal.failures;
            if (proposal.dpi_specific) std::cout << ", redirected elsewhere";
            if (proposal.nfqws_was_asked) {
                std::cout << ", already in nfqws2's own hostlist";
            }
            std::cout << "\n      direct: " << proposal.direct_detail << "\n";
        }
        std::cout
            << "\nNothing was changed. A host that works through a tunnel is\n"
               "not automatically a host you want there - check the list before\n"
               "routing any of it.\n";
    }

    std::cout << "\nOther answers: " << report.down_everywhere
              << " unreachable everywhere, " << report.works_without_help
              << " already working, " << report.tunnel_broken
              << " tunnel at fault, " << report.inconclusive
              << " could not be proved.\n";
}

}  // namespace
// Returns a copy rather than a pointer, and the reason is a crash on the
// router.
//
// The first version bound `config.outbounds.value_or({})` to a const reference
// and returned `&*it` into it. value_or hands back a temporary by value; the
// reference extends its life to the end of the function and not one statement
// further, so the caller dereferenced freed memory and the process took
// SIGSEGV at an address that was plainly ASCII from a log line.
//
// It survived the whole suite because nothing exercises this file - the
// crash needs a config that actually names the outbound.
std::optional<Outbound> find_scan_outbound(const std::vector<Outbound>& outbounds,
                                           const std::string& tag) {
    const auto it = std::find_if(
        outbounds.begin(), outbounds.end(),
        [&tag](const Outbound& outbound) { return outbound.tag == tag; });
    if (it == outbounds.end()) return std::nullopt;
    return *it;
}


int run_scan_tunnel_candidates(const Config& config,
                               const ScanTunnelCandidatesOptions& options) {
    const auto outbound = find_scan_outbound(
        config.outbounds.value_or(std::vector<Outbound>{}), options.outbound_tag);
    if (!outbound.has_value()) {
        std::cerr << "Unknown outbound: " << options.outbound_tag << "\n";
        return 1;
    }
    if (!outbound->interface.has_value() || outbound->interface->empty()) {
        std::cerr << "Outbound " << options.outbound_tag
                  << " has no interface to pin a probe to; a mark alone would\n"
                     "measure whatever routing happened to pick.\n";
        return 1;
    }

    const auto source_result =
        read_nfqws_scan_source(kNfqwsConfigPath, read_whole_file);
    if (!source_result.source.has_value()) {
        switch (source_result.error) {
            case NfqwsScanSourceError::config_unreadable:
                std::cerr << "Cannot read " << kNfqwsConfigPath
                          << "; without it there is no list of what nfqws2 has\n"
                             "been failing on.\n";
                break;
            case NfqwsScanSourceError::no_debug_log:
                std::cerr
                    << "nfqws2 is not writing its auto-hostlist decisions "
                       "anywhere.\n"
                       "Add --hostlist-auto-debug=<file> to its configuration; "
                       "this\ncommand has nothing to read without it.\n";
                break;
            case NfqwsScanSourceError::no_isp_interface:
                std::cerr
                    << "Cannot tell which device faces the provider; the "
                       "direct\nleg would prove nothing.\n";
                break;
            case NfqwsScanSourceError::ok:
                break;
        }
        return 1;
    }
    const auto& source = *source_result.source;

    const auto log = read_whole_file(source.log_path);
    if (log.empty()) {
        std::cerr << "Nothing recorded in " << source.log_path << " yet.\n";
        return 1;
    }

    TunnelScanConfig scan_config;
    scan_config.max_probes_per_pass = options.max_probes;
    TunnelCandidateScan scan(build_scan_coverage(config, source), scan_config);

    std::vector<std::string> lines;
    std::istringstream log_lines(log);
    std::string line;
    while (std::getline(log_lines, line)) lines.push_back(line);
    scan.observe(lines);

    std::cout << "Read " << lines.size() << " line(s) from " << source.log_path
              << "; " << scan.queued() << " host(s) worth probing.\n";

    auto transport = default_http_transport();
    const auto probe = [&](const std::string& host) {
        DifferentialProbeRequest request;
        request.url = "https://" + host + "/";
        request.direct = DifferentialPath{0U, source.isp_interface};
        request.tunnel = DifferentialPath{0U, *outbound->interface};
        return run_differential_probe(*transport, request);
    };

    print_report(scan.run_pass(probe), options.outbound_tag);
    return 0;
}

}  // namespace keen_pbr3
