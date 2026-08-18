#pragma once

#include "sing_box_installer.hpp"

#include "../http/http_transport.hpp"

#include <string>

namespace keen_pbr3 {

// The steps that actually touch the router, kept apart from the sequence that
// orders them. The sequence is the correctness and is tested exhaustively with
// these replaced; these are the parts that can only be judged against a real
// filesystem, so they are small, obvious, and do one thing each.
//
// `binary_path` is the file an install replaces - the one transports.json
// configures, not a fixed location. Everything is staged inside that file's
// own directory, because rename() is only atomic within a filesystem and
// /opt/tmp is not guaranteed to be the same one.

struct SingBoxInstallPaths {
    std::string binary_path;
    std::string managed_marker_path;
};

// Bounds the fetched release archive. sing-box ships around 12 MiB per
// architecture; this leaves room for growth and still refuses a body that is
// not a release at all.
inline constexpr std::size_t kSingBoxArchiveMaximumBytes =
    64U * 1024U * 1024U;

// Bytes received so far and the whole body's size, or zero for the size when
// the server did not say.
//
// Optional, and the reason it is a separate parameter rather than a step: the
// phases are what the installer knows, bytes are what the fetch knows, and
// only the caller can turn both into one thing an operator reads.
using SingBoxDownloadProgress =
    std::function<void(std::uint64_t received, std::uint64_t total)>;

SingBoxInstallSteps production_sing_box_install_steps(
    const SingBoxInstallPaths& paths,
    SingBoxDownloadProgress download_progress = {},
    // Aborts the transfers. Only the fetches take it, and deliberately: a
    // cancel is only ever honoured while nothing on the router has changed,
    // and by the time anything has, there is no transfer left to abort.
    HttpCancellationToken cancellation = {});

// Removes anything a previous run left behind in the staging directory. Called
// before staging rather than only after it, because the process that failed to
// clean up is by definition the one that could not run its own cleanup.
void discard_sing_box_staging(const SingBoxInstallPaths& paths);

} // namespace keen_pbr3
