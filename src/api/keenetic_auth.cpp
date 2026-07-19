#include "keenetic_auth.hpp"

#include "../crypto/md5.hpp"
#include "../crypto/sha256.hpp"
#include "../log/logger.hpp"

#include <httplib.h>

#include <string>

namespace keen_pbr3 {

namespace {

struct ParsedEndpoint {
    std::string host;
    int port{80};
};

ParsedEndpoint parse_endpoint(const std::string& endpoint) {
    ParsedEndpoint parsed;
    std::string rest = endpoint;

    const auto scheme = rest.find("://");
    if (scheme != std::string::npos) {
        rest = rest.substr(scheme + 3);
    }
    const auto slash = rest.find('/');
    if (slash != std::string::npos) {
        rest = rest.substr(0, slash);
    }
    const auto colon = rest.rfind(':');
    if (colon != std::string::npos) {
        parsed.host = rest.substr(0, colon);
        try {
            parsed.port = std::stoi(rest.substr(colon + 1));
        } catch (const std::exception&) {
            parsed.port = 80;
        }
    } else {
        parsed.host = rest;
    }
    if (parsed.host.empty()) {
        parsed.host = "127.0.0.1";
    }
    return parsed;
}

} // namespace

KeeneticAuthResult verify_keenetic_credentials(const std::string& endpoint,
                                               const std::string& username,
                                               const std::string& password) {
    KeeneticAuthResult result;
    if (username.empty() || password.empty()) {
        result.error = "empty credentials";
        return result;
    }

    const ParsedEndpoint target = parse_endpoint(endpoint);
    httplib::Client client(target.host, target.port);
    client.set_connection_timeout(3);
    client.set_read_timeout(5);
    client.set_keep_alive(true);

    // First request is expected to fail: it carries the realm and the challenge.
    auto challenge_response = client.Get("/auth");
    if (!challenge_response) {
        result.reachable = false;
        result.error = "router web interface is unreachable";
        Logger::instance().error(
            "Keenetic auth: cannot reach {}:{} — {}", target.host, target.port,
            httplib::to_string(challenge_response.error()));
        return result;
    }

    // Some builds answer 200 when the account has no password configured.
    if (challenge_response->status == 200) {
        result.authenticated = true;
        return result;
    }

    const auto realm = challenge_response->get_header_value("X-NDM-Realm");
    const auto challenge = challenge_response->get_header_value("X-NDM-Challenge");
    if (realm.empty() || challenge.empty()) {
        result.error = "router did not provide an authentication challenge";
        return result;
    }

    const std::string md5_digest =
        crypto::md5_hex(username + ":" + realm + ":" + password);
    const std::string answer = Sha256::hex(challenge + md5_digest);

    httplib::Headers headers{
        {"X-NDM-Realm", realm},
        {"X-NDM-Challenge", challenge},
    };
    // Carry the session cookie the firmware handed out with the challenge.
    const auto cookie = challenge_response->get_header_value("Set-Cookie");
    if (!cookie.empty()) {
        headers.emplace("Cookie", cookie.substr(0, cookie.find(';')));
    }

    const std::string body =
        R"({"login":")" + username + R"(","password":")" + answer + R"("})";
    auto login_response = client.Post("/auth", headers, body, "application/json");
    if (!login_response) {
        result.reachable = false;
        result.error = "router did not answer the authentication request";
        return result;
    }

    result.authenticated = login_response->status == 200;
    if (!result.authenticated) {
        result.error = "router rejected the credentials";
    }
    return result;
}

} // namespace keen_pbr3
