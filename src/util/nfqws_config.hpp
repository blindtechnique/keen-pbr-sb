#pragma once

#include <string>
#include <vector>

namespace keen_pbr3 {

std::string nfqws_config_without_ipv6_toggle(const std::string& content);
std::string nfqws_config_with_isp_interfaces(
    const std::string& content, const std::vector<std::string>& interfaces);

} // namespace keen_pbr3
