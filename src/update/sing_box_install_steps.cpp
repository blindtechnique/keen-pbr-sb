#include "sing_box_install_steps.hpp"

#include "sing_box_install_observation.hpp"

#include "../config/subscription_fetch_policy.hpp"
#include "../crypto/sha256.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"
#include "../util/safe_exec.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

// Inside the target's own directory, so the rename that installs is a rename
// within one filesystem. A staging area under /opt/tmp would be a copy across
// filesystems wearing a rename's name, and would stop being atomic exactly
// when it mattered.
fs::path staging_directory(const SingBoxInstallPaths& paths) {
    return fs::path(paths.binary_path).parent_path() /
           ".keen-pbr-sing-box-staging";
}

bool write_file(const fs::path& path, const std::string& bytes,
                const mode_t mode) {
    const int descriptor =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (descriptor < 0) return false;
    std::size_t written = 0U;
    while (written < bytes.size()) {
        const auto wrote = ::write(descriptor, bytes.data() + written,
                                   bytes.size() - written);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            (void)::close(descriptor);
            return false;
        }
        written += static_cast<std::size_t>(wrote);
    }
    // The bytes have to be on the medium before the rename that publishes
    // them, or a power loss can leave the new name pointing at nothing.
    if (::fsync(descriptor) != 0) {
        (void)::close(descriptor);
        return false;
    }
    return ::close(descriptor) == 0;
}

bool fsync_directory(const fs::path& directory) {
    const int descriptor =
        ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0) return false;
    const bool synced = ::fsync(descriptor) == 0;
    (void)::close(descriptor);
    return synced;
}

} // namespace

void discard_sing_box_staging(const SingBoxInstallPaths& paths) {
    std::error_code error;
    fs::remove_all(staging_directory(paths), error);
}

SingBoxInstallSteps production_sing_box_install_steps(
    const SingBoxInstallPaths& paths,
    SingBoxDownloadProgress download_progress,
    HttpCancellationToken cancellation) {
    SingBoxInstallSteps steps;

    steps.fetch =
        [download_progress = std::move(download_progress),
         cancellation = std::move(cancellation)](
            const std::string& url) -> std::optional<std::string> {
        try {
            HttpClient client;
            client.set_timeout(std::chrono::seconds(60));
            client.set_max_response_size(kSingBoxArchiveMaximumBytes);
            HttpRequestOptions options;
            options.progress = download_progress;
            options.cancellation = cancellation;
            // The same public-internet rule the subscription fetch uses, and
            // for the same reason: a name that resolves to the router itself
            // must not be reachable from a fetch the operator did not choose
            // the address for. It is applied per connection, so a redirect
            // cannot walk around it.
            options.destination_filter = [](const std::string& address) {
                return subscription_destination_permitted(address) ==
                       SubscriptionDestinationVerdict::allowed;
            };
            auto body = client.download(url, options);
            if (body.empty()) return std::nullopt;
            return body;
        } catch (const std::exception& error) {
            Logger::instance().warn("sing-box install fetch failed: {}",
                                    error.what());
            return std::nullopt;
        }
    };

    steps.digest = [](const std::string& bytes) {
        return Sha256::hex(bytes);
    };

    steps.stage_archive =
        [paths](const std::string& archive_bytes) -> std::string {
        const auto staging = staging_directory(paths);
        std::error_code error;
        fs::remove_all(staging, error);
        if (!fs::create_directories(staging, error) || error) return {};
        // Nothing else may read a partially unpacked binary out of here.
        (void)::chmod(staging.c_str(), 0700);

        const auto archive = staging / "sing-box.tar.gz";
        if (!write_file(archive, archive_bytes, 0600)) return {};

        // These bytes already matched the digest the release publishes, so
        // this is not an untrusted archive - but it is unpacked into a fresh
        // private directory anyway, so a path that escaped would land
        // somewhere bounded rather than in /opt/bin.
        // Measured on the router: Entware provides /opt/bin/tar and there is
        // no /bin/tar at all, while a development container has the opposite.
        // Both are tried rather than one being assumed, because assuming the
        // wrong one fails only on the machine that matters.
        int exit_code = -1;
        for (const char* tar : {"/opt/bin/tar", "/bin/tar", "/usr/bin/tar"}) {
            std::error_code probe;
            if (!fs::exists(tar, probe) || probe) continue;
            exit_code = safe_exec_capture(
                              {tar, "-xzf", archive.string(), "-C",
                               staging.string()},
                              /*suppress_stderr=*/true,
                              /*max_bytes=*/64U * 1024U,
                              /*capture_stderr=*/false)
                            .exit_code;
            break;
        }
        if (exit_code != 0) {
            Logger::instance().warn(
                "sing-box archive could not be unpacked (exit {})",
                exit_code);
            return {};
        }

        // The official archive puts the binary one directory down. Search
        // rather than assume the directory name, but only inside staging.
        for (fs::recursive_directory_iterator iterator(staging, error), end;
             !error && iterator != end; iterator.increment(error)) {
            if (!iterator->is_regular_file(error) || error) continue;
            if (iterator->path().filename() != "sing-box") continue;
            const auto staged = iterator->path();
            if (::chmod(staged.c_str(), 0755) != 0) return {};
            return staged.string();
        }
        return {};
    };

    steps.read_staged_version =
        [](const std::string& staged_binary) -> std::string {
        // Bounded because this runs a binary that came off the internet. It
        // matched the digest the release publishes, which is why it got this
        // far, but "verified" and "trustworthy to read without a limit" are
        // different claims - the staged-version check exists precisely because
        // a verified archive can still hold the wrong build.
        const auto result = safe_exec_capture({staged_binary, "version"},
                                              /*suppress_stderr=*/true,
                                              /*max_bytes=*/8U * 1024U,
                                              /*capture_stderr=*/false);
        if (result.exit_code != 0 || result.truncated) return {};
        return parse_sing_box_version(result.stdout_output);
    };

    steps.install_atomically =
        [paths](const std::string& staged_binary) -> bool {
        const fs::path target(paths.binary_path);
        const auto directory = target.parent_path();
        const auto pending = directory / (target.filename().string() + ".new");

        std::error_code error;
        fs::remove(pending, error);
        // Copied rather than renamed out of staging: the staged tree is
        // removed afterwards either way, and a copy leaves the verified file
        // untouched if this fails partway.
        std::ifstream input(staged_binary, std::ios::binary);
        if (!input) return false;
        const std::string bytes(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        if (bytes.empty()) return false;
        if (!write_file(pending, bytes, 0755)) return false;

        // Keep the binary being replaced, byte for byte, beside the target.
        // Without it "undo this install" means "download the old release and
        // hope", which is not an undo. Best effort on purpose: failing to
        // preserve a copy is a reason to have no rollback, not a reason to
        // refuse an install the operator asked for - and the capability
        // reports which of those happened rather than assuming.
        //
        // Costs one binary's worth of space, about 12 MiB, in a directory on
        // the same filesystem so the copy cannot land somewhere that fills up
        // separately.
        if (fs::exists(target, error) && !error) {
            const auto previous =
                directory / (target.filename().string() + ".previous");
            fs::remove(previous, error);
            fs::copy_file(target, previous,
                          fs::copy_options::overwrite_existing, error);
        }

        // The rename is the moment the router changes. Everything before it is
        // reversible by deleting a file nobody runs.
        fs::rename(pending, target, error);
        if (error) {
            fs::remove(pending, error);
            return false;
        }
        // Without this the rename can be lost while the new file's contents
        // survive, which on the next boot is a target that points nowhere.
        return fsync_directory(directory);
    };

    steps.write_managed_marker = [paths]() -> bool {
        const fs::path marker(paths.managed_marker_path);
        std::error_code error;
        fs::create_directories(marker.parent_path(), error);
        const auto pending =
            marker.parent_path() / (marker.filename().string() + ".new");
        if (!write_file(pending, paths.binary_path + "\n", 0644)) {
            return false;
        }
        fs::rename(pending, marker, error);
        if (error) {
            fs::remove(pending, error);
            return false;
        }
        return fsync_directory(marker.parent_path());
    };

    return steps;
}

} // namespace keen_pbr3
