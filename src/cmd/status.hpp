#pragma once

#include "../config/config.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace keen_pbr3 {

// Returns 0 if all checks pass, 1 if any check is degraded/missing/error.
int run_status_command(const Config& config, const std::string& config_path);

// Render the live status response returned by the daemon control socket.
//
// Expected result payload:
// {
//   "config_path": "...",
//   "runtime_state": "running",
//   "routing_runtime_active": true,
//   "config": { ...active daemon config... },
//   "routing_health": { ...routing_health_report_to_json(...)... }
// }
//
// The daemon owns runtime state; the CLI must not rebuild desired routing from
// an on-disk config that may no longer match the active transaction.
int run_status_command(const nlohmann::json& response);

} // namespace keen_pbr3
