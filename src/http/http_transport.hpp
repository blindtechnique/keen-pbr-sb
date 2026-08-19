#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

using HttpCancellationToken = std::shared_ptr<const std::atomic<bool>>;

struct HttpTransportRequest {
    std::string url;
    long timeout_ms{0};
    std::string user_agent;
    uint32_t fwmark{0};
    // Bind the socket to this device (SO_BINDTODEVICE) when non-empty.
    // A mark alone only expresses a routing preference: if the policy table
    // the mark selects holds no usable default, the lookup falls through to
    // main and the request quietly succeeds over the WAN. Binding makes the
    // measurement attributable to the device, or makes it fail.
    std::string bind_interface;
    long max_redirects{5};
    std::vector<std::string> headers;
    bool discard_body{false};
    size_t max_response_size{size_t{8} * 1024U * 1024U};
    HttpCancellationToken cancellation;
    // Consulted with every address this transfer is about to connect to,
    // written as text, and refused by returning false.
    //
    // It has to live here rather than in the caller, because the caller cannot
    // see these addresses. A URL judged before the request names a host, not a
    // destination: the name is resolved later and may point anywhere, and with
    // CURLOPT_FOLLOWLOCATION every one of the redirect hops below opens its own
    // connection to an address that never appeared in the URL. A destination
    // policy applied anywhere except here is a policy the transfer can walk
    // around.
    //
    // Unset means unfiltered, which is what every existing caller wants: list
    // and catalog downloads go to addresses the operator configured, not to
    // ones an attacker supplied.
    std::function<bool(const std::string&)> destination_filter;

    // Called as bytes arrive, with what has been received and what the server
    // said the whole body is.
    //
    // `total` is zero when the server did not say - a chunked response has no
    // length to report - and a caller must render that as "so far" rather than
    // inventing a denominator. Curl reports what it knows; the difference
    // between "37% of 12 MB" and "4 MB so far" is the difference between a
    // progress bar that is true and one that is a guess.
    //
    // Called from curl's transfer thread, frequently. A caller that publishes
    // somewhere has to decide how often to actually do it.
    std::function<void(std::uint64_t received, std::uint64_t total)> progress;
};

struct HttpTransportResponse {
    long status_code{0};
    std::string body;
    // Lower-case names; values belong only to the final response after redirects.
    std::map<std::string, std::string> headers;
    std::chrono::milliseconds elapsed{0};
};

class HttpTransportError : public std::runtime_error {
public:
    explicit HttpTransportError(const std::string& message) : std::runtime_error(message) {}
};

class HttpTransportCancelled : public HttpTransportError {
public:
    explicit HttpTransportCancelled(const std::string& message)
        : HttpTransportError(message) {}
};

class HttpTransportBindError : public HttpTransportError {
public:
    explicit HttpTransportBindError(const std::string& message)
        : HttpTransportError(message) {}
};

class HttpTransport {
public:
    virtual ~HttpTransport() = default;
    virtual HttpTransportResponse perform(const HttpTransportRequest& request) = 0;
};

class LibcurlHttpTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest& request) override;
};

std::shared_ptr<HttpTransport> default_http_transport();

} // namespace keen_pbr3
