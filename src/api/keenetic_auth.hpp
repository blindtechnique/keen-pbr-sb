#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

enum class KeeneticAuthAddressFamily {
    ipv4,
    ipv6,
};

// Injectable boundary for discovering addresses owned by this router. The
// production implementation reads getifaddrs(); deterministic tests and
// platform adapters can provide a fixed inventory without depending on the
// build host's network namespace.
class KeeneticAuthLocalAddressProvider {
public:
    virtual ~KeeneticAuthLocalAddressProvider() = default;

    virtual bool contains(KeeneticAuthAddressFamily family,
                          std::string_view canonical_address) const = 0;
};

struct KeeneticAuthEndpoint {
    std::string host;
    int port{80};
    std::string canonical;
};

// Only a numeric address assigned to one of this router's own interfaces is
// accepted. KeeneticOS may reject /auth through loopback, so the router's LAN
// address must be supported without allowing arbitrary LAN hosts. DNS names,
// alternate IP spellings and URL components remain rejected so this setting
// cannot turn the privileged daemon into an SSRF proxy.
std::optional<KeeneticAuthEndpoint> parse_keenetic_auth_endpoint(
    const std::string& endpoint,
    std::string* error = nullptr);

std::optional<KeeneticAuthEndpoint> parse_keenetic_auth_endpoint(
    const std::string& endpoint,
    const KeeneticAuthLocalAddressProvider& local_addresses,
    std::string* error = nullptr);

// Validates a login against the router firmware instead of a local password.
//
// KeeneticOS answers an unauthenticated request to /auth with 401 plus the
// headers X-NDM-Realm and X-NDM-Challenge. The client then replies with
// sha256(challenge + md5(login:realm:password)); the firmware accepts it with
// 200 and rejects it with 401. keen-pbr only forwards the check and never
// stores the password.
struct KeeneticAuthResult {
    bool authenticated{false};
    bool reachable{true};
    // Set only after /auth returned the Keenetic realm and challenge. A
    // reachable unrelated service on a stale port must still trigger NDMS
    // rediscovery, while a wrong password must not.
    bool endpoint_verified{false};
    std::string error;
};

// Proves that a candidate router-local address actually serves the Keenetic
// authentication challenge. No credentials are sent.
bool probe_keenetic_auth_challenge(const std::string& endpoint);

KeeneticAuthResult verify_keenetic_credentials(const std::string& endpoint,
                                               const std::string& username,
                                               const std::string& password);

} // namespace keen_pbr3
