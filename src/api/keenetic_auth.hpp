#pragma once

#include <optional>
#include <string>

namespace keen_pbr3 {

struct KeeneticAuthEndpoint {
    std::string host;
    int port{80};
    std::string canonical;
};

// Only a local firmware endpoint is accepted. In particular, DNS names,
// alternate IPv4 spellings and URL components are rejected so this setting
// cannot turn the privileged daemon into an SSRF proxy.
std::optional<KeeneticAuthEndpoint> parse_keenetic_auth_endpoint(
    const std::string& endpoint,
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
    std::string error;
};

KeeneticAuthResult verify_keenetic_credentials(const std::string& endpoint,
                                               const std::string& username,
                                               const std::string& password);

} // namespace keen_pbr3
