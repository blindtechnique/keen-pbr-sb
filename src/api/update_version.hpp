#pragma once

#include <string>

namespace keen_pbr3 {

std::string format_fork_version(const std::string& version,
                                const std::string& release);
bool is_newer_fork_version(const std::string& candidate, const std::string& current);
bool safe_github_tag(const std::string& value);

} // namespace keen_pbr3
