#pragma once

#include "../config/config.hpp"
#include "../http/http_transport.hpp"
#include <filesystem>
#include <functional>
#include <string>

namespace keen_pbr3 {
struct RuntimeStateSnapshot;

inline constexpr const char* kUpdateOutboundPreference = "/opt/etc/keen-pbr/update-outbound";

// Empty means the router's ordinary path, not a promise of a direct WAN.
struct UpdateDownloadBinding {
    std::string outbound;
    std::string selected_outbound;
    std::string interface;
    std::uint32_t fwmark{0};
};

bool valid_update_outbound(const std::string& tag);
std::string read_update_outbound(const std::filesystem::path& path = kUpdateOutboundPreference);
void save_update_outbound(const std::filesystem::path& path, const std::string& tag);
std::string selected_update_download_outbound();

// Pure planning from one active config/runtime observation. Does not probe,
// create routes, refresh a group or accept an API draft as routing authority.
UpdateDownloadBinding plan_update_download_binding(
    const std::string& tag, const Config& config, const OutboundMarkMap& marks,
    const RuntimeStateSnapshot& runtime);
UpdateDownloadBinding request_update_download_binding(const std::string& tag);
nlohmann::json update_download_options(const Config& config);
nlohmann::json request_update_download_options();
// An unavailable daemon must not hide the saved preference or implicitly reset
// it. Reading the preference itself still fails closed if it is invalid.
nlohmann::json read_update_download_settings(
    const std::filesystem::path& path = kUpdateOutboundPreference,
    const std::function<nlohmann::json()>& read_options = request_update_download_options);
HttpTransportRequest make_update_download_request(
    const std::string& url, const UpdateDownloadBinding& binding, size_t max_bytes);
// A bounded stream to a sibling temporary file; failed requests preserve any
// previous destination. There is no in-memory IPK copy or direct-path retry.
void download_update_to_file(const std::string& url, const std::filesystem::path& output,
                            const UpdateDownloadBinding& binding, HttpTransport& transport);
} // namespace keen_pbr3
