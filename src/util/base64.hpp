#pragma once

#include <string>
#include <string_view>

namespace keen_pbr3 {

std::string base64_encode(std::string_view input);
std::string base64_decode(std::string_view input);

} // namespace keen_pbr3
