#pragma once

#include "../config/config_writer.hpp"

#include <filesystem>
#include <string>

namespace keen_pbr3 {

inline constexpr std::size_t kMaxNfqwsFileSize =
    2U * 1024U * 1024U;

struct NfqwsFileWriteResult {
    // False means rename made the replacement visible, but the following
    // directory fsync failed. Callers must continue runtime reconciliation and
    // may surface a warning; a pre-commit failure is still thrown.
    bool durable{true};
};

// Durably replaces an editable nfqws file. Plain files are written directly;
// .gz files are compressed into the private descriptor owned by the shared
// atomic writer. Existing ownership is preserved and files remain readable by
// the unprivileged nfqws process.
NfqwsFileWriteResult write_nfqws_file_atomically(
    const std::filesystem::path& path,
    const std::string& content,
    AtomicFileWriteOptions options = {});

} // namespace keen_pbr3
