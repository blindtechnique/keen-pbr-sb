#include "keenetic_auth.hpp"

#include "../crypto/md5.hpp"
#include "../crypto/sha256.hpp"
#include "../log/logger.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <array>
#include <charconv>
#include <cstring>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string>

namespace keen_pbr3 {
namespace {

bool address_belongs_to_local_interface(int family, const void* address) {
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) return false;

    bool found = false;
    for (const auto* current = interfaces; current != nullptr;
         current = current->ifa_next) {
        if (!current->ifa_addr || current->ifa_addr->sa_family != family) {
            continue;
        }
        if (family == AF_INET) {
            const auto* candidate =
                &reinterpret_cast<const sockaddr_in*>(current->ifa_addr)
                     ->sin_addr;
            found = std::memcmp(candidate, address, sizeof(in_addr)) == 0;
        } else if (family == AF_INET6) {
            const auto* candidate =
                &reinterpret_cast<const sockaddr_in6*>(current->ifa_addr)
                     ->sin6_addr;
            found = std::memcmp(candidate, address, sizeof(in6_addr)) == 0;
        }
        if (found) break;
    }
    freeifaddrs(interfaces);
    return found;
}

class SystemLocalAddressProvider final
    : public KeeneticAuthLocalAddressProvider {
public:
    bool contains(KeeneticAuthAddressFamily family,
                  std::string_view canonical_address) const override {
        const int native_family =
            family == KeeneticAuthAddressFamily::ipv4 ? AF_INET : AF_INET6;
        std::array<unsigned char, sizeof(in6_addr)> address{};
        const std::string address_text{canonical_address};
        if (inet_pton(native_family, address_text.c_str(), address.data()) != 1) {
            return false;
        }
        return address_belongs_to_local_interface(native_family,
                                                  address.data());
    }
};

bool is_canonical_local_ip_literal(const std::string& host,
                                   int family,
                                   const KeeneticAuthLocalAddressProvider&
                                       local_addresses,
                                   std::string* error) {
    std::array<unsigned char, sizeof(in6_addr)> address{};
    if (inet_pton(family, host.c_str(), address.data()) != 1) {
        if (error) *error = "endpoint host must be a numeric IP literal";
        return false;
    }

    std::array<char, INET6_ADDRSTRLEN> canonical{};
    if (!inet_ntop(family, address.data(), canonical.data(), canonical.size()) ||
        host != canonical.data()) {
        if (error) *error = "endpoint host must use canonical IP notation";
        return false;
    }
    const auto address_family =
        family == AF_INET ? KeeneticAuthAddressFamily::ipv4
                          : KeeneticAuthAddressFamily::ipv6;
    if (!local_addresses.contains(address_family, host)) {
        if (error) {
            *error = "endpoint address is not assigned to this router";
        }
        return false;
    }
    return true;
}

} // namespace

std::optional<KeeneticAuthEndpoint> parse_keenetic_auth_endpoint(
    const std::string& endpoint,
    const KeeneticAuthLocalAddressProvider& local_addresses,
    std::string* error) {
    const auto reject = [&](const char* message)
        -> std::optional<KeeneticAuthEndpoint> {
        if (error) *error = message;
        return std::nullopt;
    };
    if (endpoint.empty()) return reject("endpoint is empty");
    for (const unsigned char character : endpoint) {
        if (character <= 0x20U || character == 0x7fU) {
            return reject("endpoint contains whitespace or control characters");
        }
    }
    if (endpoint.find_first_of("/?#@\\") != std::string::npos) {
        return reject("endpoint must not contain URL components");
    }

    std::string host;
    std::string port_text;
    if (endpoint.front() == '[') {
        const auto close = endpoint.find(']');
        if (close == std::string::npos || close == 1) {
            return reject("invalid bracketed IPv6 endpoint");
        }
        host = endpoint.substr(1, close - 1);
        const auto suffix = endpoint.substr(close + 1);
        if (!suffix.empty()) {
            if (suffix.front() != ':' || suffix.size() == 1) {
                return reject("invalid bracketed IPv6 port");
            }
            port_text = suffix.substr(1);
        }
        std::string address_error;
        if (!is_canonical_local_ip_literal(
                host, AF_INET6, local_addresses, &address_error)) {
            if (error) *error = address_error;
            return std::nullopt;
        }
    } else {
        const auto colon = endpoint.find(':');
        if (colon == std::string::npos) {
            host = endpoint;
        } else {
            if (endpoint.find(':', colon + 1) != std::string::npos) {
                return reject("IPv6 endpoints must be bracketed");
            }
            host = endpoint.substr(0, colon);
            port_text = endpoint.substr(colon + 1);
            if (port_text.empty()) return reject("port is empty");
        }
        std::string address_error;
        if (!is_canonical_local_ip_literal(
                host, AF_INET, local_addresses, &address_error)) {
            if (error) *error = address_error;
            return std::nullopt;
        }
    }

    int port = 80;
    if (!port_text.empty()) {
        unsigned int parsed_port = 0;
        const auto parsed = std::from_chars(
            port_text.data(),
            port_text.data() + port_text.size(),
            parsed_port);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != port_text.data() + port_text.size() ||
            parsed_port == 0 || parsed_port > 65535U) {
            return reject("port must be between 1 and 65535");
        }
        port = static_cast<int>(parsed_port);
    }

    KeeneticAuthEndpoint parsed;
    parsed.host = host;
    parsed.port = port;
    parsed.canonical =
        host.find(':') != std::string::npos
            ? "[" + host + "]:" + std::to_string(port)
            : host + ":" + std::to_string(port);
    if (error) error->clear();
    return parsed;
}

std::optional<KeeneticAuthEndpoint> parse_keenetic_auth_endpoint(
    const std::string& endpoint,
    std::string* error) {
    static const SystemLocalAddressProvider local_addresses;
    return parse_keenetic_auth_endpoint(endpoint, local_addresses, error);
}

bool probe_keenetic_auth_challenge(const std::string& endpoint) {
    const auto target = parse_keenetic_auth_endpoint(endpoint);
    if (!target) return false;

    httplib::Client client(target->host, target->port);
    client.set_connection_timeout(1);
    client.set_read_timeout(1);
    client.set_keep_alive(false);
    const auto response = client.Get("/auth");
    if (!response || response->status != 401) return false;
    return !response->get_header_value("X-NDM-Realm").empty() &&
           !response->get_header_value("X-NDM-Challenge").empty();
}

KeeneticAuthResult verify_keenetic_credentials(const std::string& endpoint,
                                               const std::string& username,
                                               const std::string& password) {
    KeeneticAuthResult result;
    if (username.empty() || password.empty()) {
        result.error = "empty credentials";
        return result;
    }

    std::string endpoint_error;
    const auto target =
        parse_keenetic_auth_endpoint(endpoint, &endpoint_error);
    if (!target) {
        result.reachable = false;
        result.error = "invalid Keenetic endpoint";
        return result;
    }
    httplib::Client client(target->host, target->port);
    client.set_connection_timeout(3);
    client.set_read_timeout(5);
    client.set_keep_alive(true);

    // First request is expected to fail: it carries the realm and the challenge.
    auto challenge_response = client.Get("/auth");
    if (!challenge_response) {
        result.reachable = false;
        result.error = "router web interface is unreachable";
        Logger::instance().error(
            "Keenetic auth: cannot reach {}:{} — {}", target->host, target->port,
            httplib::to_string(challenge_response.error()));
        return result;
    }

    // A 200 response means the router did not issue a challenge. There is no
    // credential proof in that response, so accepting it would turn a router
    // with disabled web authentication into a bypass for keen-pbr-sb.
    if (challenge_response->status == 200) {
        result.error = "router authentication is not enabled";
        return result;
    }

    const auto realm = challenge_response->get_header_value("X-NDM-Realm");
    const auto challenge = challenge_response->get_header_value("X-NDM-Challenge");
    if (realm.empty() || challenge.empty()) {
        result.error = "router did not provide an authentication challenge";
        return result;
    }
    result.endpoint_verified = true;

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
        nlohmann::json{
            {"login", username},
            {"password", answer},
        }.dump();
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
