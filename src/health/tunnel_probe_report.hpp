#pragma once

// The last pass of the nfqws2-to-tunnel automation, kept so something other
// than the log can show it.
//
// The pass logs what it did, but a router runs at `warn`, where its ordinary
// lines do not appear at all. Two things deserve to be visible without reading
// a log file: the hosts it routed - a change to where traffic goes, and not
// reversible in practice - and the hosts the registry check held back, which
// are the ones a person may want to decide about by hand.
//
// Deliberately a small store of its own rather than another function on the API
// context. One writer (the pass, on a worker thread), any number of readers
// (the API), one mutex, and no coupling to the daemon's wiring.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct TunnelProbeReport {
    // False before the first pass of this daemon run, which includes the
    // ordinary case of the automation being switched off - `refusal` says so.
    bool ever_ran{false};
    // Why the last attempt did nothing. Empty when the pass ran.
    std::string refusal;
    // The same sentence the daemon logs.
    std::string summary;
    std::size_t probed{0};
    std::size_t remaining{0};
    std::vector<std::string> routed;
    std::vector<std::string> held_back;
    std::uint64_t finished_at_unix_ms{0};
};

// Replaces what the last pass left. Safe to call from any thread.
void publish_tunnel_probe_report(TunnelProbeReport report);

// A copy of the last report, or a default one before the first pass.
TunnelProbeReport last_tunnel_probe_report();

// How something outside the daemon asks for the list to take effect.
//
// Editing the list file changes nothing until the firewall is applied, because
// that is when a list is read. The daemon installs a hook here at startup; the
// API calls it after an edit. Without this, removing a host from the panel
// would leave its traffic in the tunnel until the next unrelated apply - which
// is the opposite of what "never route this again" is for.
void set_tunnel_probe_refresh_hook(std::function<void()> hook);

// Runs the hook if one was installed. Safe to call when none was.
void request_tunnel_probe_refresh();

}  // namespace keen_pbr3
