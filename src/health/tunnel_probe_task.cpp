#include "tunnel_probe_task.hpp"

#include <sstream>
#include <utility>

namespace keen_pbr3 {

TunnelProbeTask::TunnelProbeTask(Io io) : io_(std::move(io)) {}

TunnelProbeTask::PassOutcome TunnelProbeTask::run(const Config& config) {
    PassOutcome outcome;

    const auto setup_result = resolve_tunnel_probe_setup(config);
    if (!setup_result.setup.has_value()) {
        outcome.refusal = setup_result.refusal;
        return outcome;
    }
    const auto& setup = *setup_result.setup;

    const auto source_result =
        read_nfqws_scan_source(kNfqwsConfigPath, io_.read_file);
    if (!source_result.source.has_value()) {
        outcome.source_error = source_result.error;
        return outcome;
    }
    const auto& source = *source_result.source;

    const auto log = io_.read_file(source.log_path);
    if (log.empty()) {
        outcome.log_empty = true;
        return outcome;
    }

    // What the list file holds now. Read before the scan is built so hosts
    // this automation has already routed count as covered: without that, a
    // restart would re-probe every host it moved last week, and each of those
    // probes costs two requests to a host that is no longer even failing.
    const auto existing = io_.read_file(setup.list_file);

    const std::string key = setup.outbound_tag + '\n' + setup.list_name;
    if (!scan_ || scan_key_ != key) {
        auto coverage = build_scan_coverage(config, source);
        CoverageIndex::RoutingList routed;
        routed.name = setup.list_name;
        routed.domains = parse_host_list_file(existing);
        coverage.routing_lists.push_back(std::move(routed));

        TunnelScanConfig scan_config;
        scan_config.max_probes_per_pass = setup.max_probes_per_pass;
        scan_ = std::make_unique<TunnelCandidateScan>(std::move(coverage),
                                                      scan_config);
        if (setup.require_registry_confirmation && io_.registry_lookup) {
            scan_->set_registry_lookup(io_.registry_lookup);
        }
        scan_key_ = key;
    }

    std::vector<std::string> lines;
    std::istringstream log_lines(log);
    std::string line;
    while (std::getline(log_lines, line)) lines.push_back(line);
    scan_->observe(lines);

    // Both legs pinned to a device. A mark alone would let routing decide, and
    // the comparison between "over the provider" and "over the tunnel" would
    // stop being a comparison.
    const auto probe = [this, &source, &setup](const std::string& host) {
        DifferentialProbeRequest request;
        request.url = "https://" + host + "/";
        request.direct = DifferentialPath{0U, source.isp_interface};
        request.tunnel = DifferentialPath{0U, setup.interface};
        return io_.run_probe(request);
    };

    const auto report = scan_->run_pass(probe);
    outcome.ran = true;
    outcome.probed = report.probed;
    outcome.remaining = report.remaining;

    auto plan = plan_host_append(existing, report.proposals,
                                 setup.require_registry_confirmation);
    outcome.unconfirmed = std::move(plan.unconfirmed);
    outcome.already_present = std::move(plan.already_present);
    if (plan.to_append.empty()) return outcome;

    const auto rendered = render_appended_list(existing, plan.to_append);
    if (!io_.write_file || !io_.write_file(setup.list_file, rendered)) {
        outcome.write_failed = true;
        return outcome;
    }

    outcome.appended = std::move(plan.to_append);
    if (io_.on_list_changed) io_.on_list_changed(setup);
    return outcome;
}

std::string TunnelProbeTask::describe(const PassOutcome& outcome) {
    if (outcome.refusal != TunnelProbeRefusal::none) {
        return describe_tunnel_probe_refusal(outcome.refusal);
    }
    switch (outcome.source_error) {
        case NfqwsScanSourceError::config_unreadable:
            return "nfqws2's configuration could not be read";
        case NfqwsScanSourceError::no_debug_log:
            return "nfqws2 is not writing its auto-hostlist decisions anywhere";
        case NfqwsScanSourceError::no_isp_interface:
            return "nfqws2's configuration does not say which device faces the "
                   "provider";
        case NfqwsScanSourceError::ok:
            break;
    }
    if (outcome.log_empty) {
        return "nfqws2 has recorded nothing to look at yet";
    }

    std::ostringstream out;
    out << "probed " << outcome.probed << ", " << outcome.remaining
        << " left for the next pass";
    if (!outcome.appended.empty()) {
        out << "; routed " << outcome.appended.size() << " host(s):";
        for (const auto& host : outcome.appended) out << ' ' << host;
    } else if (outcome.write_failed) {
        out << "; the list file could not be written, so nothing was routed";
    } else {
        out << "; nothing to route";
    }
    if (!outcome.unconfirmed.empty()) {
        out << "; " << outcome.unconfirmed.size()
            << " held back by the registry check";
    }
    if (!outcome.already_present.empty()) {
        out << "; " << outcome.already_present.size() << " already listed";
    }
    return out.str();
}

}  // namespace keen_pbr3
