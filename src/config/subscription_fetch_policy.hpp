#pragma once

#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Whether the daemon may fetch a caller-supplied subscription URL at all.
//
// This runs as root on the router, inside the LAN, with a loopback RCI API and
// a loopback NDMS on port 79. A URL the operator pastes is attacker-influenced
// input in every threat model that matters: without a destination policy, the
// subscription importer is a confused deputy that will GET anything reachable
// from the router and hand the body back through the API.
//
// Deliberately two stages, because one is not enough:
//
//   1. classify_subscription_url() judges the URL itself - scheme, credentials,
//      and a host that is already a literal address.
//   2. subscription_destination_permitted() judges an ADDRESS, and must be
//      applied to every address actually connected to.
//
// Stage 1 alone is not a control. A hostname is resolved later and can point
// anywhere, including 127.0.0.1; and HttpClient follows up to five redirects
// silently, so the address finally contacted may have nothing to do with the
// URL that was judged. Any transport used for subscriptions has to consult
// stage 2 per connection, redirects included, or the policy is decoration.

enum class SubscriptionUrlVerdict : std::uint8_t {
    allowed,
    // Only http and https. Anything else - file, ftp, gopher, data - either
    // reaches the local filesystem or is a classic SSRF gadget.
    scheme_not_allowed,
    // Credentials in the URL. The roadmap requires that subscription secrets
    // never enter a URL, a log or frontend storage, and a URL is the one place
    // that reliably reaches all three.
    credentials_in_url,
    // The URL names a literal address that stage 2 refuses. Reported here so
    // an operator learns immediately rather than after a failed fetch.
    destination_not_permitted,
    malformed,
};

enum class SubscriptionDestinationVerdict : std::uint8_t {
    allowed,
    loopback,
    private_network,
    link_local,
    unique_local,
    multicast_or_broadcast,
    unspecified,
    reserved,
    unparsable,
};

const char* subscription_url_verdict_name(
    SubscriptionUrlVerdict verdict) noexcept;
const char* subscription_destination_verdict_name(
    SubscriptionDestinationVerdict verdict) noexcept;

// Judges a literal IPv4 or IPv6 address. An address that cannot be parsed is
// refused rather than allowed: this is the last gate before the daemon
// connects, and an address we do not understand is not one we can clear.
SubscriptionDestinationVerdict subscription_destination_permitted(
    const std::string& address) noexcept;

// Judges the URL. Hostnames are NOT resolved here - that is stage 2's job at
// connect time, and doing it here would only invite callers to trust the
// result.
SubscriptionUrlVerdict classify_subscription_url(const std::string& url);

// The bound on a subscription body. Sing-box subscriptions are configuration,
// not payload: a multi-megabyte answer is either hostile or a wrong URL, and
// this router has 1 GiB of RAM shared with the routing daemon.
inline constexpr std::size_t kSubscriptionMaximumBytes = 1024U * 1024U;

} // namespace keen_pbr3
