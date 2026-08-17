#pragma once

#include "control_protocol.hpp"

#include <iosfwd>
#include <string>

namespace keen_pbr3::ipc {

class ControlTimeoutError final : public ControlProtocolError {
public:
    using ControlProtocolError::ControlProtocolError;
};

// The first timeout bounds connect plus request transmission. The second
// bounds the complete framed response. A negative response timeout preserves
// the legacy one-timeout call contract by reusing connect_timeout_ms.
nlohmann::json request_control(const std::string& socket_path,
                               const nlohmann::json& request,
                               int connect_timeout_ms = 5000,
                               int response_timeout_ms = -1);

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
                    int idle_timeout_ms = 15000,
                    int connect_timeout_ms = -1);

} // namespace keen_pbr3::ipc
