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

// Everything a scripted install needs to know about the world outside the
// IPK: where the component's init script lives, where it is renamed to
// while the package's own postinst runs (same directory, so the rename is
// atomic; dot-prefixed, so init never globs it), which opkg configuration
// makes `opkg -o` see the same feeds and architectures as a plain run, and
// which shell and tar drive the scripts and the extraction.
struct ScriptedInstallPaths {
    std::filesystem::path init_script{"/opt/etc/init.d/S51nfqws2"};
    std::filesystem::path held_init_script{
        "/opt/etc/init.d/.S51nfqws2.kpbr-held"};
    std::filesystem::path opkg_conf{"/opt/etc/opkg.conf"};
    std::filesystem::path offline_root{"/"};
    std::string shell{"/opt/bin/sh"};
    std::string tar{"/opt/bin/tar"};
    // The component's active configuration, and where its own preinst moves
    // it when the packaged CONFIG_VERSION has moved past what the file
    // declares. Both are read, never written, by this code: the package
    // performs the migration, and the transaction's job is to see it coming
    // and say so.
    std::filesystem::path config_file{"/opt/etc/nfqws2/nfqws2.conf"};
    std::filesystem::path migrated_config_file{
        "/opt/etc/nfqws2/nfqws2.conf-old"};
};

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
    ScriptedInstallPaths scripted;
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

// What a scripted install did, step by step. The `_ok` flags default to
// "fine" so a step that never had to run (a package without that script, an
// init script that was never held) reads as passed, not as skipped-looking-
// failed; `_ran` says whether it actually happened.
struct ScriptedInstallReport {
    // The IPK's own maintainer scripts were laid out for running. When this
    // is false nothing has been mutated and the caller may fall back to a
    // plain opkg install, which runs the scripts itself - start included.
    bool scripts_extracted{false};
    bool preinst_ran{false};
    bool preinst_ok{true};
    // The caller's service stop, in the slot where a plain upgrade ran the
    // old package's prerm: after preinst, before any file is replaced. A
    // failed stop refuses the unpack - replacing the files of a service
    // that could not be proven stopped is the plain flow's bug, not a
    // behavior to keep.
    bool service_stop_ran{false};
    bool service_stop_ok{true};
    // `opkg -o` was issued: from here on the component may have changed.
    bool mutation_started{false};
    bool unpack_ok{false};
    // The init script was renamed aside so the package's postinst finds no
    // file to start or stop.
    bool init_held{false};
    bool postinst_ran{false};
    bool postinst_ok{true};
    // False only when the init script was held and the rename back failed:
    // the held copy still exists under ScriptedInstallPaths::
    // held_init_script and boot recovery restores it by name.
    bool init_restored{true};
    // The package's own preinst moves the active configuration aside when
    // the packaged CONFIG_VERSION has moved past what the file declares, and
    // then tells its postinst to treat the upgrade as a fresh install - so
    // the operator's tuned file is replaced by the package default. That is
    // the package's decision, not ours to prevent, but it must never be a
    // surprise: predicted before preinst runs and confirmed after.
    bool config_migration_expected{false};
    bool config_migrated{false};
    // What the file declared and what the package carries, when both could
    // be read; empty otherwise.
    std::string config_version_before;
    std::string config_version_packaged;
    // Human-readable lines about the steps above, for the operator log.
    std::string notes;
};

inline bool scripted_install_succeeded(
    const ScriptedInstallReport& report) noexcept {
    return report.scripts_extracted && report.preinst_ok &&
           report.service_stop_ok && report.unpack_ok &&
           report.postinst_ok && report.init_restored;
}

// Where a scripted install's own step notes go as they happen. The report
// keeps a copy, but a caller that is also collecting command output wants
// each note at the point it was written, not appended after every command
// the package manager printed - the transaction's stop would otherwise be
// shown to the operator below the unpack it ran before.
using ScriptedNoteSink = std::function<void(const std::string& line)>;

// The caller's service stop for a scripted install, run where a plain
// upgrade ran the old package's prerm. Writes through the same note sink;
// returns false when the service could not be proven stopped.
using ScriptedServiceStop = std::function<bool(const ScriptedNoteSink& note)>;

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

    // The scripted variants of the two installs above. The slot refusals
    // are identical; the difference is who runs the maintainer scripts.
    //
    // `opkg -o <root>` unpacks the IPK, updates the package database and
    // marks the package installed, but never runs a maintainer script - and
    // a later `opkg configure` will not either, because the package is
    // already marked configured (measured on the target opkg). So this runs
    // the IPK's own scripts itself, in opkg's order, with one difference:
    // while postinst runs, the component's init script is renamed aside, so
    // the script's `[ -f "$INIT_SCRIPT" ]`-guarded start and stop find
    // nothing to run. Everything else the scripts do - config migrations,
    // the multiplatform binary copy postinst performs (the real binary is
    // NOT in data.tar.gz at its final path) - happens exactly as a plain
    // install would do it. The service start stays with the caller.
    //
    //   extract scripts -> preinst <install|upgrade> -> opkg -o unpack
    //   -> hold init script -> postinst configure -> restore init script
    //
    // When the scripts cannot be laid out (report.scripts_extracted stays
    // false) nothing has run and nothing was mutated; the caller decides
    // whether to fall back to the plain install.
    //
    // `stop_service`, when provided, runs after preinst and before the
    // unpack - the slot where a plain upgrade ran the old package's
    // prerm-driven service stop, which this flow otherwise suppresses
    // entirely (no prerm runs, and the held init script silences
    // postinst's guarded stop). Without it a running service would keep
    // executing the old image while its files are replaced underneath.
    //
    // `note`, when provided, receives every step note as it is written, so
    // a caller interleaving them with command output shows the operator the
    // order things actually happened in.
    void scripted_install_candidate(bool upgrade,
                                    ScriptedInstallReport& report,
                                    const ScriptedServiceStop& stop_service =
                                        {},
                                    const ScriptedNoteSink& note = {});
    void scripted_reinstall_current(const std::string& expected_version,
                                    ScriptedInstallReport& report,
                                    const ScriptedServiceStop& stop_service =
                                        {},
                                    const ScriptedNoteSink& note = {});

    // The candidate installed and was proven so by the caller: it becomes
    // current, current becomes previous.
    void promote_installed_candidate();

private:
    ComponentPackagePreparation prepare_impl(
        const std::string& installed_version, bool stage_target);
    void finish_interrupted_promotion(const std::string& installed_version,
                                      std::string& output);
    std::optional<std::string> read_feed_index(std::string& error) const;
    void scripted_install(IpkSlot slot,
                          const std::vector<std::string>& extra_install_flags,
                          bool upgrade,
                          ScriptedInstallReport& report,
                          const ScriptedServiceStop& stop_service,
                          const ScriptedNoteSink& note);

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
