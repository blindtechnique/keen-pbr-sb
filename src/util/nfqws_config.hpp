#pragma once

#include <string>
#include <vector>

namespace keen_pbr3 {

std::string nfqws_config_without_ipv6_toggle(const std::string& content);
// Removes only the exact two package-owned telemetry additions emitted by the
// generator. This keeps a pre-telemetry active 01/02/03 profile identifiable
// after a package upgrade without treating any other config delta as equal.
std::string nfqws_config_strategy_identity(const std::string& content);
bool nfqws_config_has_owned_rotator_telemetry(const std::string& content);
std::string nfqws_config_with_isp_interfaces(
    const std::string& content, const std::vector<std::string>& interfaces);

} // namespace keen_pbr3
