#pragma once

#ifdef WITH_API

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

// One address/netmask pair observed directly from the router kernel. The
// interface name is part of the proof: equal or overlapping address ranges on
// two links must fail closed rather than turn an RFC1918/CGNAT overlap into
// local authority.
struct TrustedLocalInterfaceAddress {
    std::string interface_name;
    std::string address;
    std::string netmask;
    bool up{false};
    bool loopback{false};
};

struct TrustedLocalConnectionSnapshot {
    // Exact numeric addresses which NDMS currently classifies as connected,
    // private, non-global management interfaces and whose /auth challenge was
    // verified. Never populate this from Host/X-Forwarded-* or RFC1918 tests.
    std::vector<std::string> verified_private_management_addresses;
    std::vector<TrustedLocalInterfaceAddress> interface_addresses;
};

// Result of a kernel route lookup for exactly `destination from source`.
// Route headers are never an input to this structure. `direct` means that the
// selected unicast route contained neither a gateway nor a multipath/via hop.
// `scope_allows_connected_prefix` accepts native link scope and the universe
// scope returned by some kernels for a resolved RTM_GETROUTE; the pure decision
// still requires the peer inside the exact connected getifaddrs prefix.
struct TrustedLocalRouteProof {
    std::string source_address;
    std::string destination_address;
    std::string interface_name;
    bool direct{false};
    bool scope_allows_connected_prefix{false};
};

// Pure fail-closed decision. `remote_address` and `local_address` must come
// from getpeername()/getsockname() on the accepted socket. Forwarding headers
// are an explicit denial because the current deployment has no trusted proxy
// boundary and must never reinterpret them as socket identity.
bool trusted_local_connection_is_proven(
    std::string_view remote_address,
    std::string_view local_address,
    bool has_forwarding_headers,
    const TrustedLocalConnectionSnapshot& snapshot,
    const std::optional<TrustedLocalRouteProof>& route) noexcept;

// Proves the narrow reverse-proxy case used by KeenDNS HTTPS web
// applications. The browser's immutable Origin scheme proves that the public
// hop was HTTPS, while the accepted socket peer must be the router itself
// (loopback or an exact live kernel-owned interface address). Forwarding
// headers alone are deliberately not an input and can never grant authority.
// This capability is for router-account login/step-up only; it is not a local
// management proof and must not be used to change authentication settings.
bool trusted_router_https_proxy_connection_is_proven(
    std::string_view remote_address,
    std::string_view local_address,
    std::string_view origin,
    std::string_view sec_fetch_site,
    std::string_view x_forwarded_proto,
    const std::vector<TrustedLocalInterfaceAddress>& interface_addresses)
    noexcept;

// Reads only kernel-owned interface metadata. NDMS authority remains a
// separate input so tests can exercise the decision without router calls.
std::vector<TrustedLocalInterfaceAddress>
system_trusted_local_interface_addresses();

// Performs a one-shot RTM_GETROUTE lookup for the accepted socket peer, with
// the accepted socket local address forced as the source. Failure, ambiguity,
// a gateway, an incompatible scope, or a non-unicast result all fail closed;
// the exact connected-prefix proof is completed by the pure decision.
std::optional<TrustedLocalRouteProof> system_trusted_local_route_proof(
    std::string_view remote_address,
    std::string_view local_address) noexcept;

struct TrustedLocalConnectionDecision {
    bool trusted{false};
    std::uint64_t evidence_generation{0U};
    std::chrono::seconds valid_for{};
};

// Bounds fixed-loopback NDMS discovery independently of the 30-second WebUI
// auth-status poll. Both successful and failed loads are cached for the TTL;
// concurrent callers share the same refresh.
class TrustedLocalConnectionCache final {
public:
    using Clock = std::chrono::steady_clock;
    using Loader =
        std::function<std::optional<TrustedLocalConnectionSnapshot>()>;
    using RouteLookup = std::function<std::optional<TrustedLocalRouteProof>(
        std::string_view, std::string_view)>;
    using Now = std::function<Clock::time_point()>;

    explicit TrustedLocalConnectionCache(
        Loader loader,
        std::chrono::seconds ttl = std::chrono::seconds{60},
        Now now = [] { return Clock::now(); },
        RouteLookup route_lookup = system_trusted_local_route_proof);

    TrustedLocalConnectionDecision evaluate(
        std::string_view remote_address,
        std::string_view local_address,
        bool has_forwarding_headers,
        // Credential-bearing requests require NDMS evidence no older than the
        // implementation's short freshness window; concurrent/flooded calls
        // still share that bounded refresh rather than querying RCI per body.
        bool require_credential_freshness = false);

    void invalidate();

private:
    Loader loader_;
    RouteLookup route_lookup_;
    std::chrono::seconds ttl_;
    Now now_;
    std::mutex mutex_;
    std::optional<TrustedLocalConnectionSnapshot> snapshot_;
    Clock::time_point refreshed_at_{};
    Clock::time_point refresh_after_{};
    bool loaded_{false};
    std::uint64_t evidence_generation_{0U};
};

} // namespace keen_pbr3

#endif // WITH_API
