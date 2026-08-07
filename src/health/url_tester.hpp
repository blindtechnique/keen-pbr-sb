#pragma once

#include "../config/config.hpp"
#include "../http/http_transport.hpp"

#include <cstdint>
#include <string>
#include <memory>

namespace keen_pbr3 {

// Keep urltest probe timeouts independent from circuit-breaker cooldowns.
constexpr uint32_t kDefaultUrltestProbeTimeoutMs = 5000;

struct URLTestResult {
    bool success{false};
    uint32_t latency_ms{0};
    std::string error;
};

class URLTester {
public:
    URLTester();
    explicit URLTester(std::shared_ptr<HttpTransport> transport);
    ~URLTester();

    URLTester(const URLTester&) = delete;
    URLTester& operator=(const URLTester&) = delete;

    // Test a URL through an outbound identified by its fwmark.
    // Uses SO_MARK to route test traffic via the correct routing table.
    // Retries up to retry.attempts times with retry.interval_ms delay between attempts.
    // Returns the result with latency_ms from the fastest successful attempt.
    //
    // bind_interface additionally pins the socket to that device. Without it a
    // mark whose policy table holds no usable default falls through to main,
    // and the test then reports the router's own connectivity instead of the
    // outbound's. Pass it whenever the caller knows the device, so that a
    // success is attributable to that transport.
    URLTestResult test(const std::string& url, uint32_t fwmark,
                       uint32_t timeout_ms, const RetryConfig& retry,
                       const std::string& bind_interface = std::string());

private:
    URLTestResult test_once(const std::string& url, uint32_t fwmark,
                            uint32_t timeout_ms,
                            const std::string& bind_interface);
    std::shared_ptr<HttpTransport> transport_;
};

} // namespace keen_pbr3
