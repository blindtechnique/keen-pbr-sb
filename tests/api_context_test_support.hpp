#pragma once

#ifdef WITH_API

#include "api/handlers.hpp"

#include <cstdlib>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <unistd.h>

namespace keen_pbr3 {
namespace test_support {

class EnvironmentVariableGuard {
public:
    EnvironmentVariableGuard(const char* name, std::string value)
        : name_(name) {
        if (const char* previous = std::getenv(name)) {
            previous_ = previous;
        }
        if (::setenv(name, value.c_str(), 1) != 0) {
            throw std::runtime_error(
                "failed to isolate API test environment");
        }
    }

    ~EnvironmentVariableGuard() {
        if (previous_.has_value()) {
            (void)::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

    EnvironmentVariableGuard(const EnvironmentVariableGuard&) = delete;
    EnvironmentVariableGuard& operator=(
        const EnvironmentVariableGuard&) = delete;

private:
    std::string name_;
    std::optional<std::string> previous_;
};

inline std::string missing_auth_path(int port) {
    return "/tmp/keen-pbr-missing-auth-" + std::to_string(::getpid()) +
           "-" + std::to_string(port) + ".json";
}

inline int isolated_api_port(int slot) {
    constexpr int kBasePort = 20000;
    constexpr int kProcessBuckets = 5000;
    constexpr int kPortsPerProcess = 8;
    return kBasePort +
           (static_cast<int>(::getpid()) % kProcessBuckets) *
               kPortsPerProcess +
           slot;
}

inline ApiContext make_minimal_api_context(
    SseBroadcaster& broadcaster,
    std::string config_path = "/tmp/keen-pbr-api-context-test.json") {
    return ApiContext{
        std::move(config_path),
        broadcaster,
        [] { return Config{}; },
        [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
        },
        [] {},
        [](const Config&) {},
        [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<std::string, api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        [] {},
        [] {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        [] {},
        [] {},
        [] {},
        [](std::optional<std::string>) {
            return ListRefreshOperationResult{};
        },
    };
}

} // namespace test_support
} // namespace keen_pbr3

#endif // WITH_API
