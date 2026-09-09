#pragma once

#include <string>
#include <nlohmann/json_fwd.hpp>

namespace keen_pbr3 {

std::string format_fork_version(const std::string& version,
                                const std::string& release);
bool is_newer_fork_version(const std::string& candidate, const std::string& current);
// Release tags retain the legacy -sb.N format; IPKs carry the build timestamp.
// This is discovery metadata only. The installer verifies package signatures.
std::string published_fork_version(const nlohmann::json& release);
bool safe_github_tag(const std::string& value);

} // namespace keen_pbr3
