#pragma once

#ifdef WITH_API

#include "server.hpp"
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// Add presentation metadata at the branch that knows the cause. Keep the
// existing exception, HTTP status and diagnostic message for older clients.
inline ApiError operation_error(const std::string& message,
                                int status,
                                const char* code) {
    return ApiError(message, status,
                    nlohmann::json{{"error", message}, {"code", code}}.dump());
}

} // namespace keen_pbr3

#endif // WITH_API
