#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Ask the kernel where a packet would actually go.
//
// Every other routing check in this daemon compares our own bookkeeping
// against itself: the rule we installed appears in the rule dump, the table we
// filled holds the default we put in it. None of them can see a rule we did
// not install winning ahead of ours - a firmware policy sitting at a lower
// priority, an overlapping fwmask, a metric race inside one table. This asks
// the only authority that decides.
//
// This deliberately does not reuse system_trusted_local_route_proof()
// (src/api/trusted_local_connection.cpp). That one proves a TCP peer sits on a
// directly attached link, and therefore rejects every route through a gateway.
// A tunnel's route normally is through a gateway, so reusing it would answer
// "no route" for every working transport.

enum class FibVerdict {
    // The kernel named an outgoing interface.
    resolved,
    // The kernel answered that the packet goes nowhere: unreachable, blackhole
    // or prohibit. Our own kill-switch installs exactly this, so it is an
    // answer about a working configuration, not a fault.
    unroutable,
    // No verdict at all. Never render this as a fault; say the kernel was not
    // asked or did not answer.
    unavailable,
};

struct FibQuery {
    // A literal address. Nothing is resolved here - a name would make this a
    // question about DNS as well, and the caller already knows which address
    // it means.
    std::string destination;
    // The mark the packet would carry. Absent asks about unmarked traffic.
    std::optional<std::uint32_t> fwmark;
};

struct FibAnswer {
    FibVerdict verdict{FibVerdict::unavailable};
    // Set only when resolved.
    std::string interface;
    // Which table produced the answer, when the kernel says so. The difference
    // between "answered from table 152" and "answered from main" is the whole
    // point of asking.
    std::optional<std::uint32_t> table;
    // Why there is no interface, in words fit to show an operator.
    std::string detail;
};

// A marked query is only trustworthy when the kernel repeats the mark back.
//
// RTA_MARK reached inet_rtm_getroute in Linux 3.6. An older kernel accepts the
// attribute, silently ignores it, and answers about an *unmarked* packet - which
// on any policy-routed router is the provider. Believing that answer would light
// a permanent red on a healthy configuration, which is worse than having no
// check at all. So when a non-zero mark is asked about and the reply does not
// echo it, the verdict is `unavailable`. Losing the check on an old kernel is
// the cheaper mistake, and it needs no separate capability probe: every query
// carries its own proof.
FibAnswer system_fib_lookup(const FibQuery& query) noexcept;

// The reply parser, kept separate so it can be tested against synthetic
// messages without a kernel. `family` is the family the request was made for;
// `requested_mark` mirrors FibQuery::fwmark and drives the echo rule above.
FibAnswer parse_fib_reply(const void* bytes,
                          std::size_t size,
                          std::uint32_t sequence,
                          int family,
                          std::optional<std::uint32_t> requested_mark) noexcept;

}  // namespace keen_pbr3
