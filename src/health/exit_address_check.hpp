#pragma once

// "Is my traffic really going through this tunnel, and where does it come out?"
//
// The question an operator asks of a VPN is not whether a probe succeeded but
// whether it succeeded *through the tunnel*. Those are different questions, and
// conflating them is how a panel ends up reporting the router's own WAN as the
// tunnel's exit: a mark alone only expresses a routing preference, so when the
// outbound's table holds no usable default the lookup falls through to main and
// the request quietly succeeds over the provider. The probe therefore pins the
// socket to the outbound's device, and what it could not pin it must not claim
// to have measured.
//
// Hence three outcomes rather than two. "Could not attribute" is not a failure
// and not a success - it is the absence of evidence, and it is the outcome this
// file exists to keep separate.

#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {

// One probe, as measured. `attributed` says the socket was bound to the
// outbound's own device, so the outcome describes that transport rather than
// whatever routing the mark happened to select.
struct ExitProbeOutcome {
    bool ok{false};
    bool attributed{false};
    std::string address;
    std::uint32_t latency_ms{0};
    std::string error;
};

enum class ExitCheckVerdict {
    // Pinned to the outbound's device and the far side answered through it.
    working,
    // The socket could not be bound to a device belonging to this outbound.
    // Whatever came back describes some route, but not provably this one.
    unattributed,
    // Pinned, but no usable answer arrived.
    unreachable,
};

// Whether the address the world sees differs from the one it sees without the
// tunnel. Deliberately separate from the verdict: a tunnel that carries traffic
// is working even when the comparison could not be made.
enum class ExitAddressChange {
    changed,
    same,
    unknown,
};

const char* exit_check_verdict_name(ExitCheckVerdict verdict) noexcept;
const char* exit_address_change_name(ExitAddressChange change) noexcept;

// The echoed body as an address, or nothing.
//
// Validated rather than trusted: a captive portal answers 200 with HTML, and
// printing that as "your address" would dress a hijacked request as a result.
// Only something that parses as an IPv4 or IPv6 literal is an address.
std::optional<std::string> parse_echoed_address(const std::string& body);

// Attribution is checked before reachability on purpose. An unbindable probe
// that also failed is still, first and foremost, a probe that proves nothing
// about this transport - and saying "unreachable" would invite the operator to
// debug a tunnel this check never touched.
ExitCheckVerdict exit_check_verdict(const ExitProbeOutcome& through) noexcept;

ExitAddressChange exit_address_change(const ExitProbeOutcome& through,
                                      const ExitProbeOutcome& direct) noexcept;

}  // namespace keen_pbr3
