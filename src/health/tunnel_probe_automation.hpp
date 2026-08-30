#pragma once

// Turning a scan's proposals into a routing change - or refusing to.
//
// The measuring is done elsewhere; this is the part that decides whether a
// pass may run at all and what it is allowed to write. Both halves are pure so
// they can be argued with in tests rather than on a router: moving a host into
// a tunnel is not reversible in practice, because nfqws2's rules are bound to
// the provider interface and a routed host stops producing the evidence that
// put it there.

#include "tunnel_candidate_scan.hpp"

#include "../config/config.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Why a pass will not run. Every one of these is a statement about the
// configuration rather than a failure to retry: the daemon says it once and
// stands down until the configuration changes.
enum class TunnelProbeRefusal {
    none,
    // Nobody asked for it. The ordinary case, and the default.
    disabled,
    no_outbound_named,
    outbound_not_configured,
    // A probe leg is pinned to a device; a mark alone would measure whatever
    // routing happened to pick, which is the one thing this must not do.
    outbound_has_no_interface,
    no_list_named,
    list_not_configured,
    // The automation appends to a file it owns. A list without one would mean
    // rewriting the operator's configuration, which this deliberately never
    // does.
    list_has_no_file,
};

// A sentence explaining the refusal, for a log line.
const char* describe_tunnel_probe_refusal(TunnelProbeRefusal refusal) noexcept;

// Where the "never route this host" list lives, given the list file the
// automation appends to.
//
// Derived rather than configured: it belongs to the automation exactly as the
// list file does, and one more path in the schema would be one more thing to
// get wrong for no decision gained.
std::string tunnel_probe_exclude_file(const std::string& list_file);

// A validated pass: everything resolved, nothing left to look up.
struct TunnelProbeSetup {
    std::string outbound_tag;
    std::string interface;
    std::string list_name;
    std::string list_file;
    // Hosts here are never probed and never routed, whatever the evidence.
    // This is the undo for a host that should not have been moved: the probe
    // cannot argue with it, and neither can the registry.
    std::string exclude_file;
    std::size_t max_probes_per_pass{8};
    std::uint64_t interval_ms{60000};
    bool require_registry_confirmation{true};
};

struct TunnelProbeSetupResult {
    std::optional<TunnelProbeSetup> setup;
    TunnelProbeRefusal refusal{TunnelProbeRefusal::none};
};

// Resolves the configured automation against the rest of the configuration.
TunnelProbeSetupResult resolve_tunnel_probe_setup(const Config& config);

// What a pass would add to the list file, and what it held back.
struct HostAppendPlan {
    std::vector<std::string> to_append;
    // Refused because the operator put them on the never-list. Kept apart from
    // every other reason: this one is a decision a person made, and no amount
    // of fresh evidence is allowed to overturn it.
    std::vector<std::string> excluded;
    // Confirmed, but the file already names it. Expected while a routing
    // change has not taken effect yet: nfqws2 goes on failing on the host, so
    // the scan goes on proposing it.
    std::vector<std::string> already_present;
    // Proposals the registry gate held back. Kept separate from "nothing
    // found" because they are the ones worth looking at by hand.
    std::vector<std::string> unconfirmed;
};

// Decides what to write, given what the file already holds.
//
// `require_registry_confirmation` is the difference between "a tunnel fixes
// this" and "a tunnel fixes this and the block is state censorship". The first
// question alone cannot separate a censored site from an advertising endpoint
// that fails for its own reasons.
HostAppendPlan plan_host_append(
    const std::string& existing_file_contents,
    const std::string& excluded_file_contents,
    const std::vector<TunnelCandidateProposal>& proposals,
    bool require_registry_confirmation);

// The text to write back with `host` gone. Comments and blank lines are kept,
// so a file somebody annotated by hand survives an edit made from the panel.
std::string render_list_without(const std::string& contents,
                                const std::string& host);

// The text to write back with `host` added, if it is not already there.
std::string render_list_with(const std::string& contents,
                             const std::string& host);

// The hosts a list file already names, one per line, ignoring blanks and
// `#` comments.
std::vector<std::string> parse_host_list_file(const std::string& contents);

// The text to write back: what was there, then the new hosts, one per line.
// Always ends with a newline, and never introduces a second blank line.
std::string render_appended_list(const std::string& existing_file_contents,
                                 const std::vector<std::string>& to_append);

}  // namespace keen_pbr3
