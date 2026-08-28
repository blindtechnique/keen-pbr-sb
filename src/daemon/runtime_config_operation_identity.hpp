#pragma once

#include <cstdint>

namespace keen_pbr3 {

enum class ConfigTerminalOperationKind : std::uint8_t {
    config_preapply,
    candidate,
    rollback,
};

struct ConfigTerminalOperationIdentity final {
    ConfigTerminalOperationKind kind{
        ConfigTerminalOperationKind::config_preapply};
    std::uint64_t operation_serial{0U};
    std::uint64_t base_runtime_generation{0U};
    std::uint64_t target_runtime_generation{0U};

    constexpr bool valid() const noexcept {
        return operation_serial != 0U &&
               base_runtime_generation != 0U &&
               target_runtime_generation != 0U;
    }

    constexpr bool operator==(
        const ConfigTerminalOperationIdentity& other) const noexcept {
        return kind == other.kind &&
               operation_serial == other.operation_serial &&
               base_runtime_generation == other.base_runtime_generation &&
               target_runtime_generation == other.target_runtime_generation;
    }
};

inline bool config_terminal_identity_matches(
    const ConfigTerminalOperationIdentity& expected,
    const ConfigTerminalOperationIdentity& observed,
    ConfigTerminalOperationKind required_kind) noexcept {
    return expected.valid() && observed.valid() &&
           expected.kind == required_kind &&
           observed.kind == required_kind && expected == observed;
}

} // namespace keen_pbr3
