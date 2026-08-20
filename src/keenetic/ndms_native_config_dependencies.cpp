#include "ndms_native_config_dependencies.hpp"

#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

namespace keen_pbr3 {
namespace {

bool safe_kernel_name(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 15U || value == "." ||
        value == "..") {
        return false;
    }
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            const bool ascii_alnum =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9');
            return ascii_alnum || character == '_' ||
                   character == '-' || character == '.' ||
                   character == ':';
        });
}

bool collect_config_references(
    const NdmsNativeConfigDependencyView& config,
    const std::string_view scope,
    const std::string& firmware_interface_name,
    const std::string& kernel_interface_name,
    std::vector<NdmsNativeKeenPbrDependency>& references) {
    for (const auto& outbound : config.interface_outbounds) {
        if (!outbound.interface.has_value() ||
            *outbound.interface != kernel_interface_name) {
            continue;
        }
        if (outbound.tag.empty()) return false;
        references.push_back({
            NdmsNativeKeenPbrDependencyKind::interface_outbound,
            std::string{scope} + ":outbound:" + outbound.tag,
        });
    }

    for (const auto& inbound_interface :
         config.route_inbound_kernel_interface_ids) {
        if (inbound_interface != kernel_interface_name) continue;
        references.push_back({
            NdmsNativeKeenPbrDependencyKind::inbound_interface_policy,
            std::string{scope} + ":route.inbound_interfaces:" +
                kernel_interface_name,
        });
    }

    for (const auto& server : config.internal_vpn_servers) {
        const bool matches_kernel =
            server.interface == kernel_interface_name;
        const bool matches_firmware =
            server.ndms_id.has_value() &&
            *server.ndms_id == firmware_interface_name;
        if (!matches_kernel && !matches_firmware) continue;
        references.push_back({
            NdmsNativeKeenPbrDependencyKind::internal_vpn_policy,
            std::string{scope} + ":route.internal_vpn_servers:" +
                firmware_interface_name,
        });
    }

    for (const auto& hidden_interface :
         config.hidden_native_firmware_interface_ids) {
        if (hidden_interface != firmware_interface_name) continue;
        references.push_back({
            NdmsNativeKeenPbrDependencyKind::native_interface_preference,
            std::string{scope} +
                ":ui_preferences.hidden_native_interface_ids:" +
                firmware_interface_name,
        });
    }
    return true;
}

} // namespace

NdmsNativeConfigDependencyView project_ndms_native_config_dependencies(
    const Config& config) {
    NdmsNativeConfigDependencyView projected;
    if (config.outbounds.has_value()) {
        const auto interface_count = static_cast<std::size_t>(std::count_if(
            config.outbounds->begin(), config.outbounds->end(),
            [](const auto& outbound) {
                return outbound.type == OutboundType::INTERFACE;
            }));
        projected.interface_outbounds.reserve(interface_count);
        for (const auto& outbound : *config.outbounds) {
            if (outbound.type != OutboundType::INTERFACE) continue;
            projected.interface_outbounds.push_back(
                {outbound.tag, outbound.interface});
        }
    }

    if (config.route.has_value()) {
        if (config.route->inbound_interfaces.has_value()) {
            projected.route_inbound_kernel_interface_ids =
                *config.route->inbound_interfaces;
        }
        if (config.route->internal_vpn_servers.has_value()) {
            projected.internal_vpn_servers.reserve(
                config.route->internal_vpn_servers->size());
            for (const auto& server :
                 *config.route->internal_vpn_servers) {
                projected.internal_vpn_servers.push_back(
                    {server.interface, server.ndms_id});
            }
        }
    }

    if (config.ui_preferences.has_value() &&
        config.ui_preferences->hidden_native_interface_ids.has_value()) {
        projected.hidden_native_firmware_interface_ids =
            *config.ui_preferences->hidden_native_interface_ids;
    }
    return projected;
}

NdmsNativeConfigDependencyProvider::NdmsNativeConfigDependencyProvider(
    NdmsNativeConfigDependencySnapshotReader reader)
    : reader_(std::move(reader)) {}

NdmsNativeKeenPbrDependencyObservation
NdmsNativeConfigDependencyProvider::observe_dependencies(
    const std::string& firmware_interface_name,
    const std::optional<std::string>& kernel_interface_name) noexcept {
    NdmsNativeKeenPbrDependencyObservation unavailable;
    unavailable.firmware_interface_name = firmware_interface_name;
    unavailable.kernel_interface_name = kernel_interface_name;
    try {
        if (!reader_) return unavailable;
        const auto snapshot = reader_();
        if (!snapshot.has_value()) return unavailable;
        return observe_ndms_native_config_dependencies(
            *snapshot, firmware_interface_name, kernel_interface_name);
    } catch (...) {
        return unavailable;
    }
}

NdmsNativeKeenPbrDependencyObservation
observe_ndms_native_config_dependencies(
    const NdmsNativeConfigDependencySnapshot& snapshot,
    const std::string& firmware_interface_name,
    const std::optional<std::string>& kernel_interface_name) noexcept {
    NdmsNativeKeenPbrDependencyObservation observation;
    observation.firmware_interface_name = firmware_interface_name;
    observation.kernel_interface_name = kernel_interface_name;
    try {
        const auto identity =
            parse_ndms_wireguard_identity(firmware_interface_name);
        if (!identity.has_value() ||
            !ndms_wireguard_identity_is_managed_candidate(*identity) ||
            identity->canonical_name() != firmware_interface_name ||
            !kernel_interface_name.has_value() ||
            !safe_kernel_name(*kernel_interface_name)) {
            return observation;
        }

        if (!collect_config_references(
                snapshot.active,
                "active",
                firmware_interface_name,
                *kernel_interface_name,
                observation.references)) {
            observation.references.clear();
            return observation;
        }
        if (snapshot.staged.has_value()) {
            if (!collect_config_references(
                    *snapshot.staged,
                    "staged",
                    firmware_interface_name,
                    *kernel_interface_name,
                    observation.references)) {
                observation.references.clear();
                return observation;
            }
        }

        std::sort(
            observation.references.begin(),
            observation.references.end(),
            [](const auto& left, const auto& right) {
                return std::pair{
                           static_cast<unsigned int>(left.kind),
                           left.dependent_id} <
                       std::pair{
                           static_cast<unsigned int>(right.kind),
                           right.dependent_id};
            });
        if (std::adjacent_find(
                observation.references.begin(),
                observation.references.end()) !=
            observation.references.end()) {
            observation.references.clear();
            return observation;
        }
        observation.keen_pbr_dependency_revision =
            ndms_native_keen_pbr_dependency_revision(observation);
        observation.complete = true;
        return observation;
    } catch (...) {
        observation.complete = false;
        observation.references.clear();
        observation.keen_pbr_dependency_revision.clear();
        return observation;
    }
}

} // namespace keen_pbr3
