#pragma once

#include "component_feed_index.hpp"
#include "component_ipk_store.hpp"
#include "../util/safe_exec.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The package-manager half of an external component upgrade, with exact
// IPKs on both sides of the mutation:
//
//   prepare   opkg update; read the feed index opkg just refreshed; fetch
//             the listed IPK with `opkg download`; verify its size and
//             SHA-256 against the index; file it as `candidate` (a newer
//             version) or `current` (the installed version, retained while
//             the feed still serves it). Nothing installed is touched.
//   install   opkg install <candidate.ipk> - the verified file, not whatever
//             the feed serves by the time opkg looks again.
//   reinstall opkg install --force-downgrade --force-reinstall <current.ipk>
//             - the exact bytes the installed version came from, which is
//             what makes a rollback exact at the opkg-metadata level too.
//
// Every command goes through one injected runner so tests see the argv and
// the handler keeps its bounded executor. The object never writes the
// transaction journal: the caller owns the phases and records what this
// reports.
using ComponentCommandRunner = std::function<ExecCaptureResult(
    const std::vector<std::string>& argv, SafeExecTimeouts timeouts)>;

struct ComponentPackageOptions {
    std::string package;
    // opkg's copy of the feed index, refreshed by `opkg update`. Entware
    // stores it gzip-compressed; a plain file is accepted too.
    std::filesystem::path feed_list;
    std::string opkg{"/opt/bin/opkg"};
    // `opkg download` writes into the working directory and the executor
    // has no cwd option, so the download is wrapped in a shell `cd`. The
    // directory and package travel as positional parameters, never inside
    // the script text.
    std::string shell{"/bin/sh"};
    std::size_t max_feed_list_bytes{1U * 1024U * 1024U};
    std::size_t max_feed_index_bytes{4U * 1024U * 1024U};
    SafeExecTimeouts timeouts{std::chrono::minutes{10},
                              std::chrono::seconds{5}};
};

struct ComponentPackagePreparation {
    // The transaction's own account of what it found and decided. Command
    // output is the runner's to keep: the handler already copies and
    // annotates every command it runs, and copying it here as well would
    // show the operator each line twice.
    std::string output;
    // Set when preparation could not finish; nothing installed was touched.
    std::string error;
    bool timed_out{false};
    bool termination_uncertain{false};

    bool feed_updated{false};
    bool feed_read{false};
    std::string installed_version;
    // The feed's entry for this package, whatever its version.
    std::optional<FeedPackageEntry> listed;
    // Listed version is newer than the installed one; verified in candidate
    // when candidate_verified is set.
    std::optional<FeedPackageEntry> target;
    bool up_to_date{false};
    IpkRetentionAction retention{IpkRetentionAction::unavailable};
    // The store's current slot holds the installed version: an exact
    // reinstall is possible.
    bool previous_exact{false};
    bool candidate_verified{false};
};

class ComponentPackageTransaction {
public:
    ComponentPackageTransaction(ComponentPackageOptions options,
                                ComponentIpkStore& store,
                                ComponentCommandRunner run);

    // Reads and verifies; installs nothing. Safe to call without a journal.
    ComponentPackagePreparation prepare(const std::string& installed_version);

    // The retention half of prepare on its own: refresh the feed and, when
    // it still serves the installed version, keep an exact copy of it. A
    // newer version is reported but not fetched. This is what a restore
    // point runs, so the installed version's bytes are kept before the
    // feed moves on, not only on the day an upgrade is attempted.
    ComponentPackagePreparation retain_installed(
        const std::string& installed_version);

    // `opkg install <candidate.ipk>`. Refuses (error result, no command)
    // unless the candidate slot is usable right now.
    ExecCaptureResult install_candidate();

    // `opkg install --force-downgrade --force-reinstall <current.ipk>`.
    // Refuses unless the current slot is usable and holds exactly
    // `expected_version`.
    ExecCaptureResult reinstall_current(const std::string& expected_version);

    // The candidate installed and was proven so by the caller: it becomes
    // current, current becomes previous.
    void promote_installed_candidate();

private:
    ComponentPackagePreparation prepare_impl(
        const std::string& installed_version, bool stage_target);
    std::vector<std::string> download_argv(
        const std::filesystem::path& staging) const;
    std::optional<std::string> read_feed_index(std::string& error) const;

    ComponentPackageOptions options_;
    ComponentIpkStore& store_;
    ComponentCommandRunner run_;
};

// Builds the argv `prepare` uses for the download, exposed so tests and the
// handler's diagnostics name the same command.
std::vector<std::string> component_download_argv(
    const ComponentPackageOptions& options,
    const std::filesystem::path& staging);

} // namespace keen_pbr3
