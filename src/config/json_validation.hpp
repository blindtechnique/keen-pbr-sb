#pragma once

#include "config.hpp"

#include <exception>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// Exception types and documented numeric IDs are stable metadata; what() is
// deliberately left to the caller, including any existing prefix or redaction.
inline const char* json_validation_error_code(const std::exception& error) noexcept {
    if (dynamic_cast<const nlohmann::json::parse_error*>(&error)) {
        return "config.json.syntax";
    }
    if (dynamic_cast<const nlohmann::json::type_error*>(&error)) {
        return "config.json.type";
    }
    if (const auto* range = dynamic_cast<const nlohmann::json::out_of_range*>(&error)) {
        if (range->id == 406) return "config.json.number_overflow";
        if (range->id == 403) return "config.json.missing_field";
    }
    return "config.json.decode";
}

inline ConfigValidationIssue make_json_validation_issue(
    std::string path, std::string message, const std::exception& error) {
    return {std::move(path), std::move(message), json_validation_error_code(error), {}};
}

} // namespace keen_pbr3
