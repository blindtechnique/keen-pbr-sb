#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace keen_pbr3::ipc {

constexpr std::uint32_t kControlProtocolVersion = 1;
constexpr std::size_t kMaxControlMessageBytes = 1024U * 1024U;

class ControlProtocolError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string encode_message(const nlohmann::json& envelope);
nlohmann::json decode_message(const std::string& frame);
void validate_request_envelope(const nlohmann::json& request);
nlohmann::json make_error_response(const nlohmann::json& request,
                                   std::string code,
                                   std::string message);

} // namespace keen_pbr3::ipc
