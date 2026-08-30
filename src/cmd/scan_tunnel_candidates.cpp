#include "scan_tunnel_candidates.hpp"

#include "../health/differential_probe.hpp"
#include "../health/tunnel_candidate_scan.hpp"
#include "../http/http_transport.hpp"
#include "../log/logger.hpp"
#include "../config/list_parser.hpp"
#include "../nfqws/list_match.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

namespace keen_pbr3 {

namespace {

constexpr const char* kNfqwsConfig = "/opt/etc/nfqws2/nfqws2.conf";

std::string read_whole_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return {};
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Pulls one `--flag=value` out of nfqws2.conf as it is written there.
//
// Deliberately a plain scan rather than a shell evaluation: this command only
// needs to find files to read, and running the operator's configuration as a
// script to learn a path would be a poor trade.
std::string nfqws_flag_value(const std::string& config, const std::string& flag) {
    const auto needle = flag + "=";
    std::size_t from = 0;
    while (true) {
        const auto at = config.find(needle, from);
        if (at == std::string::npos) return {};
        // Only accept it where a flag can start, so `--hostlist-auto-debug=`
        // is never matched inside `--hostlist-auto=`.
        const bool at_flag_start = at == 0 || config[at - 1] == ' ' ||
                                   config[at - 1] == '"' || config[at - 1] == '\n';
        if (at_flag_start) {
            auto value_at = at + needle.size();
            // Shell assignments carry their value in quotes - ISP_INTERFACE
            // is written `ISP_INTERFACE="eth3"` - while nfqws2 flags usually
            // do not. Reading until the first quote would return nothing for
            // the first shape and the whole rest of the line for neither.
            const bool quoted =
                value_at < config.size() && config[value_at] == '"';
            if (quoted) ++value_at;
            const auto end = config.find_first_of(quoted ? "\"\n" : " \"\n",
                                                  value_at);
            return config.substr(value_at, end == std::string::npos
                                               ? std::string::npos
                                               : end - value_at);
        }
        from = at + needle.size();
    }
}

std::vector<std::string> read_nfqws_list(const std::string& path) {
    if (path.empty()) return {};
    return nfqws::parse_hostlist(read_whole_file(path));
}

CoverageIndex build_coverage(const Config& config,
                             const std::string& nfqws_config) {
    CoverageIndex index;

    const auto& lists =
        config.lists.value_or(std::map<std::string, ListConfig>{});
    for (const auto& [name, list] : lists) {
        CoverageIndex::RoutingList entry;
        entry.name = name;
        if (list.domains.has_value()) {
            for (const auto& domain : *list.domains) {
                auto normalized = ListParser::normalize_domain(domain);
                if (normalized.has_value()) {
                    entry.domains.push_back(std::move(*normalized));
                }
            }
        }
        if (list.ip_cidrs.has_value()) {
            entry.addresses = *list.ip_cidrs;
        }
        // A list with neither is one that lives in a cache file; this command
        // says so rather than pretending the list is empty.
        index.routing_lists.push_back(std::move(entry));
    }

    index.nfqws_handled =
        read_nfqws_list(nfqws_flag_value(nfqws_config, "--hostlist"));
    index.nfqws_excluded =
        read_nfqws_list(nfqws_flag_value(nfqws_config, "--hostlist-exclude"));
    return index;
}

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

    const auto nfqws_config = read_whole_file(kNfqwsConfig);
    if (nfqws_config.empty()) {
        std::cerr << "Cannot read " << kNfqwsConfig
                  << "; without it there is no list of what nfqws2 has been\n"
                     "failing on.\n";
        return 1;
    }
    const auto log_path =
        nfqws_flag_value(nfqws_config, "--hostlist-auto-debug");
    if (log_path.empty()) {
        std::cerr
            << "nfqws2 is not writing its auto-hostlist decisions anywhere.\n"
               "Add --hostlist-auto-debug=<file> to its configuration; this\n"
               "command has nothing to read without it.\n";
        return 1;
    }
    const auto log = read_whole_file(log_path);
    if (log.empty()) {
        std::cerr << "Nothing recorded in " << log_path << " yet.\n";
        return 1;
    }

    // The provider's own device, so the direct leg really is direct.
    const auto isp_interface = nfqws_flag_value(nfqws_config, "ISP_INTERFACE");
    if (isp_interface.empty()) {
        std::cerr << "Cannot tell which device faces the provider; the direct\n"
                     "leg would prove nothing.\n";
        return 1;
    }

    TunnelScanConfig scan_config;
    scan_config.max_probes_per_pass = options.max_probes;
    TunnelCandidateScan scan(build_coverage(config, nfqws_config), scan_config);

    std::vector<std::string> lines;
    std::istringstream log_lines(log);
    std::string line;
    while (std::getline(log_lines, line)) lines.push_back(line);
    scan.observe(lines);

    std::cout << "Read " << lines.size() << " line(s) from " << log_path
              << "; " << scan.queued() << " host(s) worth probing.\n";

    auto transport = default_http_transport();
    const auto probe = [&](const std::string& host) {
        DifferentialProbeRequest request;
        request.url = "https://" + host + "/";
        request.direct = DifferentialPath{0U, isp_interface};
        request.tunnel = DifferentialPath{0U, *outbound->interface};
        return run_differential_probe(*transport, request);
    };

    print_report(scan.run_pass(probe), options.outbound_tag);
    return 0;
}

}  // namespace keen_pbr3
