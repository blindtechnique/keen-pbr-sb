#pragma once

#include "../config/config.hpp"
#include "../config/json_validation.hpp"

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// Additive field metadata: old consumers keep receiving path/message, and
// legacy validators do not acquire empty code/params fields on the wire.
inline nlohmann::json serialize_config_validation_issue(
    const ConfigValidationIssue& issue) {
    nlohmann::json rendered{{"path", issue.path}, {"message", issue.message}};
    if (!issue.code.empty()) rendered["code"] = issue.code;
    if (!issue.params.empty()) rendered["params"] = issue.params;
    return rendered;
}

inline nlohmann::json serialize_config_validation_issues(
    const std::vector<ConfigValidationIssue>& issues) {
    auto rendered = nlohmann::json::array();
    for (const auto& issue : issues) {
        rendered.push_back(serialize_config_validation_issue(issue));
    }
    return rendered;
}

// Preserve the caller's existing public message, even when it deliberately
// omits parser diagnostics (for example a backup upload). Classification uses
// the exception type/id, never the English message or document contents.
inline nlohmann::json serialize_json_validation_error(
    const std::string& message,
    const std::exception& error,
    const std::string& path = "$") {
    return {
        {"error", message},
        {"validation_errors", serialize_config_validation_issues({
            make_json_validation_issue(path, message, error)})},
    };
}

} // namespace keen_pbr3
