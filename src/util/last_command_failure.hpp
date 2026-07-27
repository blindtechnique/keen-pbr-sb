#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::size_t kLastCommandFailureMaxBytes = 128U * 1024U;

// Non-owning input assembled at the failure site. Serialization and redaction
// happen only after a command has failed.
struct LastCommandFailureView {
    const std::vector<std::string>& command;
    int exit_code{-1};
    std::string_view input;
    std::string_view response;
    std::string_view reason;
};

// The recorder is deliberately best-effort. Neither a full filesystem nor a
// diagnostics permission problem may change the command's result or errno.
bool write_last_command_failure(
    const LastCommandFailureView& failure) noexcept;

// Securely opens one already-published snapshot without following symlinks.
// Missing, non-regular, oversized, or unreadable snapshots are treated as
// absent.
std::optional<std::string> read_last_command_failure() noexcept;

#ifdef KEEN_PBR3_TESTING
// Production never accepts an environment-controlled path. Tests may point
// the recorder at their private temporary directory through this compiled-out
// seam.
void set_last_command_failure_path_for_testing(
    std::optional<std::string> path) noexcept;
void set_last_command_failure_post_commit_failure_for_testing(
    bool enabled) noexcept;
#endif

} // namespace keen_pbr3
