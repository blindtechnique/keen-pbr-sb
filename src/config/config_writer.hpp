#pragma once

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace keen_pbr3 {

enum class AtomicFileWriteStage {
    write,
    file_fsync,
    rename,
    directory_fsync,
};

class AtomicFileWriteError final : public std::runtime_error {
public:
    AtomicFileWriteError(std::string message, bool committed);

    // True once rename(2) made the replacement visible. A later durability
    // error still requires callers to compensate the visible replacement.
    bool committed() const noexcept;

private:
    bool committed_{false};
};

struct AtomicFileWriteOptions {
    bool create_parent_directories{false};
    mode_t created_directory_mode{0755};
    mode_t default_file_mode{0600};
    mode_t preserved_file_mode_mask{07777};
    mode_t additional_file_mode_bits{0};
    std::optional<mode_t> file_mode;
    std::optional<uid_t> owner;
    std::optional<gid_t> group;
    // Optional transaction observer. It flips only after rename(2) has made
    // the new inode visible, including when a later directory fsync fails.
    bool* committed_result{nullptr};
#ifdef KEEN_PBR3_TESTING
    // Per-call deterministic fault seam. It is absent from production builds
    // and runs immediately before the corresponding durability operation.
    std::function<void(AtomicFileWriteStage)> fault_injector;
#endif
};

// Durably replace a regular file without following the destination or final
// parent-directory symlink. Existing ownership and mode are preserved unless
// explicitly overridden.
void write_file_atomically(
    const std::string& path,
    const std::string& body,
    const AtomicFileWriteOptions& options = {});

// Durably replace a regular config file. Existing ownership and mode are
// preserved; a newly created config is private to its owner (0600).
void write_config_atomically(const std::string& config_path,
                             const std::string& body);

} // namespace keen_pbr3
