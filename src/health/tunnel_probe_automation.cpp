#include "tunnel_probe_automation.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace keen_pbr3 {

const char* describe_tunnel_probe_refusal(TunnelProbeRefusal refusal) noexcept {
    switch (refusal) {
        case TunnelProbeRefusal::none:
            return "no refusal";
        case TunnelProbeRefusal::disabled:
            return "the tunnel probe automation is switched off";
        case TunnelProbeRefusal::no_outbound_named:
            return "no outbound is named to probe against";
        case TunnelProbeRefusal::outbound_not_configured:
            return "the named outbound is not in the configuration";
        case TunnelProbeRefusal::outbound_has_no_interface:
            return "the named outbound has no interface to pin a probe to";
        case TunnelProbeRefusal::no_list_named:
            return "no list is named to receive confirmed hosts";
        case TunnelProbeRefusal::list_not_configured:
            return "the named list is not in the configuration";
        case TunnelProbeRefusal::list_has_no_file:
            return "the named list has no file for this automation to append to";
    }
    return "unknown refusal";
}

TunnelProbeSetupResult resolve_tunnel_probe_setup(const Config& config) {
    TunnelProbeSetupResult result;

    const auto configured = config.tunnel_probe;
    if (!configured.has_value() || !configured->enabled.value_or(false)) {
        result.refusal = TunnelProbeRefusal::disabled;
        return result;
    }

    const auto outbound_tag = configured->outbound.value_or(std::string{});
    if (outbound_tag.empty()) {
        result.refusal = TunnelProbeRefusal::no_outbound_named;
        return result;
    }
    const auto list_name = configured->list.value_or(std::string{});
    if (list_name.empty()) {
        result.refusal = TunnelProbeRefusal::no_list_named;
        return result;
    }

    const auto& outbounds = config.outbounds.value_or(std::vector<Outbound>{});
    const auto outbound_it = std::find_if(
        outbounds.begin(), outbounds.end(),
        [&outbound_tag](const Outbound& outbound) {
            return outbound.tag == outbound_tag;
        });
    if (outbound_it == outbounds.end()) {
        result.refusal = TunnelProbeRefusal::outbound_not_configured;
        return result;
    }
    if (!outbound_it->interface.has_value() || outbound_it->interface->empty()) {
        result.refusal = TunnelProbeRefusal::outbound_has_no_interface;
        return result;
    }

    const auto& lists =
        config.lists.value_or(std::map<std::string, ListConfig>{});
    const auto list_it = lists.find(list_name);
    if (list_it == lists.end()) {
        result.refusal = TunnelProbeRefusal::list_not_configured;
        return result;
    }
    if (!list_it->second.file.has_value() || list_it->second.file->empty()) {
        result.refusal = TunnelProbeRefusal::list_has_no_file;
        return result;
    }

    TunnelProbeSetup setup;
    setup.outbound_tag = outbound_tag;
    setup.interface = *outbound_it->interface;
    setup.list_name = list_name;
    setup.list_file = *list_it->second.file;

    // The generated type carries every field as optional because the schema
    // gives them defaults rather than requiring them. A value below the
    // schema's own minimum is treated as absent instead of honoured: a pass
    // every second would be a way to hurt the router, not a configuration.
    const auto max_probes = configured->max_probes_per_pass.value_or(8);
    setup.max_probes_per_pass =
        max_probes >= 1 && max_probes <= 64 ? static_cast<std::size_t>(max_probes)
                                            : 8U;
    const auto interval = configured->interval_ms.value_or(3600000);
    setup.interval_ms = interval >= 60000 && interval <= 86400000
                            ? static_cast<std::uint64_t>(interval)
                            : 3600000U;
    setup.require_registry_confirmation =
        configured->require_registry_confirmation.value_or(true);

    result.setup = std::move(setup);
    return result;
}

std::vector<std::string> parse_host_list_file(const std::string& contents) {
    std::vector<std::string> hosts;
    std::istringstream lines(contents);
    std::string line;
    while (std::getline(lines, line)) {
        // A file written on Windows, or copied through one, keeps its carriage
        // returns; a host with a trailing CR would never match anything.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        if (line[first] == '#') continue;
        const auto last = line.find_last_not_of(" \t");
        hosts.push_back(line.substr(first, last - first + 1));
    }
    return hosts;
}

HostAppendPlan plan_host_append(
    const std::string& existing_file_contents,
    const std::vector<TunnelCandidateProposal>& proposals,
    bool require_registry_confirmation) {
    HostAppendPlan plan;

    const auto existing_hosts = parse_host_list_file(existing_file_contents);
    std::set<std::string> seen(existing_hosts.begin(), existing_hosts.end());

    for (const auto& proposal : proposals) {
        if (proposal.host.empty()) continue;
        if (require_registry_confirmation &&
            !proposal_confirmed_by_registry(proposal)) {
            plan.unconfirmed.push_back(proposal.host);
            continue;
        }
        // `seen` grows as we go, so one pass proposing the same host twice
        // still writes it once.
        if (!seen.insert(proposal.host).second) {
            plan.already_present.push_back(proposal.host);
            continue;
        }
        plan.to_append.push_back(proposal.host);
    }

    return plan;
}

std::string render_appended_list(const std::string& existing_file_contents,
                                 const std::vector<std::string>& to_append) {
    std::string out = existing_file_contents;
    if (!out.empty() && out.back() != '\n') out.push_back('\n');
    for (const auto& host : to_append) {
        out += host;
        out.push_back('\n');
    }
    return out;
}

}  // namespace keen_pbr3
