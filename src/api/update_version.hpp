#pragma once

#include <string>
#include <filesystem>
#include <optional>
#include <nlohmann/json_fwd.hpp>

namespace keen_pbr3 {

std::string format_fork_version(const std::string& version,
                                const std::string& release);
bool is_newer_fork_version(const std::string& candidate, const std::string& current);
// Release tags retain the legacy -sb.N format; IPKs carry the build timestamp.
// This is discovery metadata only. The installer verifies package signatures.
std::string published_fork_version(const nlohmann::json& release);
bool safe_github_tag(const std::string& value);
// Missing preference inherits the installed channel; invalid data fails closed.
bool valid_update_channel(const std::string& channel);
std::optional<std::string> read_update_channel(const std::filesystem::path& path);
void save_update_channel(const std::filesystem::path& path, const std::string& channel);
bool channel_release_installable(const std::string& current,
                                 const std::string& latest,
                                 const std::string& installed_channel,
                                 const std::string& selected_channel);
// Discovery/cache validation only; installer signatures remain mandatory.
bool release_matches_channel(const nlohmann::json& release,
                             const std::string& channel);
nlohmann::json select_channel_release(const nlohmann::json& metadata,
                                      const std::string& channel);
bool release_cache_matches_channel(const nlohmann::json& cache,
                                   const std::string& channel);

} // namespace keen_pbr3
