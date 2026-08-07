#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
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
