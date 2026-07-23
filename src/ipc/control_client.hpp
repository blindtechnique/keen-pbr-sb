#pragma once

#include "control_protocol.hpp"

#include <iosfwd>
#include <string>

namespace keen_pbr3::ipc {

nlohmann::json request_control(const std::string& socket_path,
                               const nlohmann::json& request,
                               int timeout_ms = 5000);

class ControlStreamError : public ControlProtocolError {
public:
    ControlStreamError(std::string message, bool active_bytes_streamed)
        : ControlProtocolError(std::move(message))
        , active_bytes_streamed_(active_bytes_streamed) {}

    bool active_bytes_streamed() const noexcept {
        return active_bytes_streamed_;
    }

private:
    bool active_bytes_streamed_;
};

void stream_control(const std::string& socket_path,
                    const nlohmann::json& request,
                    std::ostream& output,
                    int idle_timeout_ms = 15000);

} // namespace keen_pbr3::ipc
