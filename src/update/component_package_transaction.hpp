#pragma once

#include "component_feed_index.hpp"
#include "component_ipk_store.hpp"
#include "../util/safe_exec.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
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
//
// `working_directory` is empty for every command except the download:
// `opkg download` writes into the working directory, and the child is moved
// there with chdir() before exec. Not with `sh -c 'cd ...'`: on KeeneticOS
// /bin/sh is the NDM shell wrapper, which forwards only the command text and
// drops every positional parameter, so a wrapper built that way ran
// `cd "" && exec ""` on the device.
using ComponentCommandRunner = std::function<ExecCaptureResult(
    const std::vector<std::string>& argv,
    SafeExecTimeouts timeouts,
    const std::filesystem::path& working_directory)>;

struct ComponentPackageOptions {
    std::string package;
    // opkg's copy of the feed index, refreshed by `opkg update`. Entware
    // stores it gzip-compressed; a plain file is accepted too.
    std::filesystem::path feed_list;
    std::string opkg{"/opt/bin/opkg"};
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

    // `opkg install <candidate.ipk>`. Throws ComponentPackageRefused, with no
    // command issued, unless the candidate slot is usable right now - a
    // refusal must never look like a package manager that ran and failed.
    ExecCaptureResult install_candidate();

    // `opkg install --force-downgrade --force-reinstall <current.ipk>`.
    // Throws ComponentPackageRefused unless the current slot is usable and
    // holds exactly `expected_version`.
    ExecCaptureResult reinstall_current(const std::string& expected_version);

    // The candidate installed and was proven so by the caller: it becomes
    // current, current becomes previous.
    void promote_installed_candidate();

private:
    ComponentPackagePreparation prepare_impl(
        const std::string& installed_version, bool stage_target);
    void finish_interrupted_promotion(const std::string& installed_version,
                                      std::string& output);
    std::optional<std::string> read_feed_index(std::string& error) const;

    ComponentPackageOptions options_;
    ComponentIpkStore& store_;
    ComponentCommandRunner run_;
};

// Thrown by install_candidate / reinstall_current when the store does not
// hold what they would install. No command has run when this is raised.
class ComponentPackageRefused : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The argv `prepare` runs, in the staging directory, to fetch the package.
std::vector<std::string> component_download_argv(
    const ComponentPackageOptions& options);

} // namespace keen_pbr3
