#pragma once

// Two probes of one target, and the only comparison that separates a blocked
// site from a dead one.
//
// nfqws2 counts a failure when a connection breaks early: outgoing
// retransmissions, an incoming RST at a low sequence, a UDP exchange that goes
// out and never comes back. That is the signature of DPI - and equally the
// signature of a server that is down, a route that is gone, an uplink that
// dropped. On the owner's router only 88 of 5925 recorded failure causes were
// the one DPI-specific kind (a redirect to another domain). A list built from
// those counters alone would send advertising and telemetry endpoints through
// a paid tunnel.
//
// Asking the same question twice answers it. Probe the target over the
// provider and over the tunnel, and read the pair:
//
//   direct fails, tunnel answers  -> the path is being interfered with
//   neither answers               -> the target is down; a tunnel cannot help
//   both answer                   -> nothing to fix
//   direct answers, tunnel fails  -> the tunnel is the broken thing
//
// A leg that cannot prove which path it took proves nothing at all, and turns
// the whole comparison inconclusive. That rule is the point of this file: an
// unattributed probe that gets quietly counted as a failure is how a health
// check starts lying.

#include "../http/http_transport.hpp"

#include <cstdint>
#include <string>

namespace keen_pbr3 {

enum class PathOutcome {
    // The server answered. Any status counts - see probe_one_path().
    reachable,
    // The path was taken and carried nothing back.
    unreachable,
    // We could not prove the probe used this path. Never treat as a failure.
    unattributed,
};

enum class DifferentialVerdict {
    // Direct silent, tunnel answers. The only verdict that earns a route.
    blocked_here,
    // Neither path answers. A tunnel would not help, and adding one would hide
    // an outage behind a routing change.
    down_everywhere,
    // Both answer. Whatever nfqws2 counted, the target is reachable as it is.
    works_without_help,
    // Direct answers, tunnel does not. This says nothing about the target and
    // everything about the transport.
    tunnel_broken,
    // At least one leg proved nothing.
    inconclusive,
};

struct DifferentialObservation {
    PathOutcome direct{PathOutcome::unattributed};
    PathOutcome tunnel{PathOutcome::unattributed};
};

// The whole decision, kept apart from the network so it can be read and tested
// as a rule rather than inferred from behaviour.
DifferentialVerdict classify_differential(DifferentialObservation observation) noexcept;

const char* differential_verdict_name(DifferentialVerdict verdict) noexcept;

// Only `blocked_here` may move traffic. Everything else is a reason to leave
// routing alone, and the caller is not free to decide otherwise.
bool differential_verdict_justifies_tunnel(DifferentialVerdict verdict) noexcept;

struct DifferentialPath {
    std::uint32_t fwmark{0};
    // The device this leg must leave through. A mark alone is a preference: if
    // the table it selects holds no usable default, the lookup falls through to
    // main and the probe measures the provider while believing it measured the
    // tunnel. An empty device makes the leg unattributed by construction, and
    // that is reported rather than hidden.
    std::string interface;
};

struct DifferentialProbeRequest {
    // Probed as given. The caller builds it from the candidate host; this code
    // resolves nothing and follows nothing.
    std::string url;
    // The provider's own device, so "direct" really is direct.
    DifferentialPath direct;
    DifferentialPath tunnel;
    std::uint32_t timeout_ms{5000};
};

struct DifferentialLeg {
    PathOutcome outcome{PathOutcome::unattributed};
    // Zero when no response arrived.
    long status_code{0};
    // What happened, in words fit to show an operator.
    std::string detail;
};

struct DifferentialProbeReport {
    DifferentialLeg direct;
    DifferentialLeg tunnel;
    DifferentialVerdict verdict{DifferentialVerdict::inconclusive};
};

// One leg.
//
// Reachability is not success. A 403 or a 404 proves the packets arrived and
// the server replied, which is the entire question here; requiring 2xx - right
// for health checks, where URLTester requires it - would read every hostile but
// reachable server as blocked.
//
// Redirects are not followed, and a redirect that leaves the site counts as
// unreachable. That is the one failure shape nfqws2 itself treats as
// DPI-specific, and following it would land on the interceptor's page and call
// it an answer. "Leaves the site" is judged on the last two labels, because
// facebook.com answers 301 to www.facebook.com and an exact host comparison
// called that interference.
DifferentialLeg probe_one_path(HttpTransport& transport,
                               const std::string& url,
                               const DifferentialPath& path,
                               std::uint32_t timeout_ms);

// Both legs and the verdict. Blocking: callers put it on the blocking executor.
DifferentialProbeReport run_differential_probe(HttpTransport& transport,
                                               const DifferentialProbeRequest& request);

// Exposed for the probe and its tests: the host part of a URL, lower-cased,
// without userinfo or port. Empty when there is nothing that looks like one.
std::string differential_url_host(const std::string& url) noexcept;

}  // namespace keen_pbr3
