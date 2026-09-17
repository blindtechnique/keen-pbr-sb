#pragma once

#include <cstddef>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace keen_pbr3 {

// Entware's installation prefix can retain the numeric owner from the
// filesystem on which it was prepared. The daemon and its executables already
// trust that installation. Do not require chown -R /opt just to use native VPNs.
//
// This exception is ONLY for /opt and /opt/etc on a path below the canonical
// root-owned /opt/etc/keen-pbr directory. The service directory, deeper parents
// and private state still require root ownership. Callers retain no-symlink,
// opened-inode checks and exact 0700/0600 checks on state directories/files.
inline bool ndms_native_parent_metadata_allowed(
    const std::vector<std::string>& components,
    const std::size_t index,
    const struct stat& metadata) noexcept {
    if (!S_ISDIR(metadata.st_mode) || (metadata.st_mode & 0022) != 0) {
        return false;
    }
    if (metadata.st_uid == 0) return true;
    return components.size() >= 4U && index < 2U &&
           components[0] == "opt" && components[1] == "etc" &&
           components[2] == "keen-pbr";
}

} // namespace keen_pbr3
