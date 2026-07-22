#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

std::vector<std::string> parse_default_route_interfaces(std::string_view routes);
std::vector<std::string> default_route_interfaces();
std::string primary_default_route_interface();

} // namespace keen_pbr3
