#include "download_transport.hpp"
#include "../config/config_writer.hpp"
#include "../daemon/runtime_state_store.hpp"
#include "../ipc/control_client.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

#ifndef KEEN_PBR_CONTROL_SOCKET
#define KEEN_PBR_CONTROL_SOCKET "/run/keen-pbr/control.sock"
#endif

namespace keen_pbr3 {
namespace {
bool valid_interface(const std::string& value) {
    return !value.empty() && value.size() < 16 &&
        value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
[[noreturn]] void unavailable() {
    throw std::runtime_error("Selected update VPN/group is unavailable; download was not started. No fallback to the router path.");
}
}

bool valid_update_outbound(const std::string& tag) {
    return tag.empty() || (tag.size() <= 24 && tag.front() >= 'a' && tag.front() <= 'z' &&
        tag.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") == std::string::npos);
}

std::string read_update_outbound(const std::filesystem::path& path) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        (!ec && status.type() == std::filesystem::file_type::not_found)) return {};
    if (ec || !std::filesystem::is_regular_file(status))
        throw std::runtime_error("Update download setting is unreadable");
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > 25) throw std::runtime_error("Update download setting is invalid");
    std::ifstream input(path, std::ios::binary);
    std::string value{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (!input || input.bad()) throw std::runtime_error("Update download setting is unreadable");
    if (!value.empty() && value.back() == '\n') value.pop_back();
    if (!valid_update_outbound(value)) throw std::runtime_error("Update download setting is invalid");
    return value;
}

void save_update_outbound(const std::filesystem::path& path, const std::string& tag) {
    if (!valid_update_outbound(tag)) throw std::invalid_argument("Invalid update outbound");
    (void)read_update_outbound(path);
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0700;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    write_file_atomically(path, tag + "\n", options);
}

std::string selected_update_download_outbound() {
    // An explicit empty override deliberately chooses the ordinary path.
    if (const char* value = std::getenv("KEEN_PBR_UPDATE_OUTBOUND")) {
        if (!valid_update_outbound(value)) throw std::invalid_argument("Invalid update outbound override");
        return value;
    }
    return read_update_outbound();
}

UpdateDownloadBinding plan_update_download_binding(
    const std::string& tag, const Config& config, const OutboundMarkMap& marks,
    const RuntimeStateSnapshot& runtime) {
    if (!valid_update_outbound(tag)) throw std::invalid_argument("Invalid update outbound");
    if (tag.empty()) return {};
    if (!config.outbounds || runtime.runtime_state != RuntimeState::running ||
        !runtime.routing_runtime_active || !runtime.routing_inventory_complete ||
        !runtime.routing_kernel_state_known) unavailable();
    std::set<std::string> visited;
    auto selected = tag;
    const Outbound* leaf = nullptr;
    while (visited.insert(selected).second) {
        const auto found = std::find_if(config.outbounds->begin(), config.outbounds->end(),
            [&](const Outbound& ob) { return ob.tag == selected; });
        if (found == config.outbounds->end()) unavailable();
        if (found->type == OutboundType::INTERFACE) { leaf = &*found; break; }
        if (found->type != OutboundType::URLTEST) unavailable();
        const auto state = runtime.urltest_states.find(selected);
        if (state == runtime.urltest_states.end() || state->second.selection_pending ||
            state->second.selected_outbound.empty()) unavailable();
        // Selection must still belong to this exact configured group.
        bool member = false;
        if (found->outbound_groups) for (const auto& group : *found->outbound_groups) {
            if (std::find(group.outbounds.begin(), group.outbounds.end(),
                          state->second.selected_outbound) != group.outbounds.end()) member = true;
        }
        if (!member) unavailable();
        selected = state->second.selected_outbound;
    }
    if (!leaf || !leaf->interface || !valid_interface(*leaf->interface)) unavailable();
    const auto assigned = marks.find(selected);
    if (assigned == marks.end() || assigned->second == 0) unavailable();
    const bool installed = std::any_of(runtime.policy_rule_specs.begin(), runtime.policy_rule_specs.end(),
        [&](const RuleSpec& rule) {
            if (rule.fwmask == 0 || (assigned->second & rule.fwmask) != (rule.fwmark & rule.fwmask)) return false;
            return std::any_of(runtime.route_specs.begin(), runtime.route_specs.end(), [&](const RouteSpec& route) {
                return route.table == rule.table && route.family == rule.family && route.interface == leaf->interface &&
                    !route.blackhole && !route.unreachable &&
                    (route.destination == "default" || route.destination == "0.0.0.0/0" || route.destination == "::/0");
            });
        });
    if (!installed) unavailable();
    return {tag, selected, *leaf->interface, assigned->second};
}

UpdateDownloadBinding request_update_download_binding(const std::string& tag) {
    if (!valid_update_outbound(tag)) throw std::invalid_argument("Invalid update outbound");
    if (tag.empty()) return {};
    const auto response = ipc::request_control(KEEN_PBR_CONTROL_SOCKET,
        {{"protocol_version", ipc::kControlProtocolVersion}, {"request_id", "update-download"},
         {"operation", "update-download-plan"}, {"outbound", tag}}, 5000);
    if (!response.value("ok", false)) unavailable();
    const auto& result = response.at("result");
    UpdateDownloadBinding binding{tag, result.at("selected_outbound").get<std::string>(),
        result.at("interface").get<std::string>(), result.at("fwmark").get<std::uint32_t>()};
    if (binding.fwmark == 0 || !valid_interface(binding.interface) ||
        binding.selected_outbound.empty() || !valid_update_outbound(binding.selected_outbound)) unavailable();
    return binding;
}

nlohmann::json update_download_options(const Config& config) {
    auto options = nlohmann::json::array();
    if (config.outbounds) for (const auto& outbound : *config.outbounds) {
        if (outbound.type != OutboundType::INTERFACE && outbound.type != OutboundType::URLTEST) continue;
        options.push_back({{"tag", outbound.tag},
            {"name", outbound.display_name.value_or(outbound.tag)}});
    }
    return options;
}

nlohmann::json request_update_download_options() {
    const auto response = ipc::request_control(KEEN_PBR_CONTROL_SOCKET,
        {{"protocol_version", ipc::kControlProtocolVersion}, {"request_id", "update-download-options"},
         {"operation", "update-download-plan"}}, 5000);
    if (!response.value("ok", false)) throw std::runtime_error("Cannot read active update VPN choices");
    return response.at("result").at("options");
}

nlohmann::json read_update_download_settings(
    const std::filesystem::path& path, const std::function<nlohmann::json()>& read_options) {
    // Keep this read outside the catch: corrupt preferences are not permission
    // to use the ordinary path. Only daemon discovery may degrade to no choices.
    nlohmann::json settings{{"outbound", read_update_outbound(path)},
        {"options", nlohmann::json::array()}, {"options_available", false}};
    try {
        auto options = read_options();
        if (options.is_array()) {
            settings["options"] = std::move(options);
            settings["options_available"] = true;
        }
    } catch (const std::exception&) {
        // The user can retry discovery or explicitly save an ordinary path.
        // Do not change the saved choice or attempt an unbound request here.
    }
    return settings;
}

HttpTransportRequest make_update_download_request(
    const std::string& url, const UpdateDownloadBinding& binding, size_t max_bytes) {
    if (url.rfind("https://", 0) != 0) throw std::invalid_argument("Updates require HTTPS");
    if (!binding.outbound.empty() && (binding.fwmark == 0 || !valid_interface(binding.interface))) unavailable();
    HttpTransportRequest request;
    request.url = url;
    request.timeout_ms = 180000;
    request.user_agent = "keen-pbr-sb updater";
    request.fwmark = binding.fwmark;
    request.bind_interface = binding.interface;
    request.max_response_size = max_bytes;
    request.max_header_size = 64U * 1024U;
    request.https_only = true;
    // Never inherit an environment proxy that could resolve a different path.
    request.destination_filter = [](const std::string&) { return true; };
    return request;
}

void download_update_to_file(const std::string& url, const std::filesystem::path& output,
                            const UpdateDownloadBinding& binding, HttpTransport& transport) {
    auto request = make_update_download_request(url, binding, 64U * 1024U * 1024U);
    std::string temporary = output.string() + ".download.XXXXXX";
    const int fd = ::mkstemp(temporary.data());
    if (fd < 0) throw std::runtime_error("Cannot create update download temporary file");
    struct FileGuard {
        int fd; std::string path;
        ~FileGuard() { if (fd >= 0) ::close(fd); if (!path.empty()) ::unlink(path.c_str()); }
    } guard{fd, temporary};
    request.body_sink = [fd](const char* data, size_t size) {
        while (size != 0) {
            const auto written = ::write(fd, data, size);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) throw std::runtime_error("Cannot write update download");
            data += written;
            size -= static_cast<size_t>(written);
        }
    };
    const auto response = transport.perform(request);
    if (response.status_code != 200) throw std::runtime_error("Update download HTTP status " + std::to_string(response.status_code));
    if (::fsync(fd) != 0) throw std::runtime_error("Cannot persist update download");
    guard.fd = -1;
    if (::close(fd) != 0) throw std::runtime_error("Cannot close update download");
    if (::rename(temporary.c_str(), output.c_str()) != 0) throw std::runtime_error("Cannot publish update download");
    guard.path.clear();
}
} // namespace keen_pbr3
