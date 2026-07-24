#pragma once

// Latency for every outbound interface, not just the members of a failover
// group.
//
// urltest already probes the children it chooses between, which left standalone
// interfaces - and native WireGuard or AmneziaWG tunnels the firmware brings up
// - with no figure at all. Probing everything with the same HTTP request makes
// the numbers comparable across transports and, unlike a ping to the peer,
// proves there is actually internet behind the tunnel.

#include "url_tester.hpp"

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct InterfaceProbeResult {
    uint32_t latency_ms{0};
    bool success{false};
    std::string error;
    std::chrono::steady_clock::time_point measured_at{};
};

class InterfaceProbe {
public:
    // Default probe target matches the one urltest uses, so a transport cannot
    // look fast here and slow there purely because of the endpoint.
    static constexpr const char* kDefaultUrl =
        "https://www.gstatic.com/generate_204";

    struct Target {
        std::string tag;
        uint32_t fwmark{0};
    };

    void set_url(std::string url) { url_ = std::move(url); }
    void set_timeout(std::chrono::milliseconds timeout) { timeout_ = timeout; }

    // Runs one round of probes. Blocking: callers put it on the daemon's
    // blocking executor rather than the event loop. Returns tags whose
    // reachability changed since the previous completed probe; the first
    // observation only establishes a baseline.
    std::vector<std::string> probe(const std::vector<Target>& targets);

    std::optional<InterfaceProbeResult> result_for(const std::string& tag) const;

    // Drops results for outbounds that no longer exist, so a renamed tag does
    // not keep reporting a latency measured for something else.
    void retain_only(const std::vector<std::string>& tags);

private:
    std::string url_{kDefaultUrl};
    std::chrono::milliseconds timeout_{5000};
    mutable std::mutex mutex_;
    std::map<std::string, InterfaceProbeResult> results_;
    URLTester tester_;
};

} // namespace keen_pbr3
