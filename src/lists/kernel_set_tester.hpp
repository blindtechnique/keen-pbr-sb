#pragma once

#include "../firewall/firewall.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct KernelSetTestResult {
    std::optional<bool> membership;
    bool timed_out{false};
};

class KernelSetTester {
public:
    explicit KernelSetTester(FirewallBackend backend);

    std::optional<bool> contains(const std::string& set_name,
                                 const std::string& ip) const;
    KernelSetTestResult contains_until(
        const std::string& set_name,
        const std::string& ip,
        std::chrono::steady_clock::time_point deadline) const;

private:
    FirewallBackend backend_;
};

} // namespace keen_pbr3
