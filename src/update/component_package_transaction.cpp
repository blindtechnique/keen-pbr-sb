#include "component_package_transaction.hpp"

#include "rescue_integrity.hpp"

#include <fstream>
#include <stdexcept>
#include <system_error>

namespace keen_pbr3 {

namespace fs = std::filesystem;

namespace {

// Bounded read: at most `limit` bytes, and a refusal (nullopt) when the file
// is larger, so a runaway file can never be read "mostly".
std::optional<std::string> read_bounded(const fs::path& path,
                                        std::size_t limit) {
    if (!rescue_integrity::regular_file(path)) return std::nullopt;
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error || size > limit) return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    std::string body(static_cast<std::size_t>(size), '\0');
    input.read(&body[0], static_cast<std::streamsize>(body.size()));
    if (static_cast<std::size_t>(input.gcount()) != body.size()) {
        return std::nullopt;
    }
    return body;
}

bool gzip_framed(const std::string& bytes) noexcept {
    return bytes.size() >= 2 &&
           static_cast<unsigned char>(bytes[0]) == 0x1f &&
           static_cast<unsigned char>(bytes[1]) == 0x8b;
}

void append_line(std::string& output, const std::string& line) {
    if (!output.empty() && output.back() != '\n') output += '\n';
    output += line;
    output += '\n';
}

} // namespace

std::vector<std::string> component_download_argv(
    const ComponentPackageOptions& options) {
    return {options.opkg, "download", options.package};
}

ComponentPackageTransaction::ComponentPackageTransaction(
    ComponentPackageOptions options,
    ComponentIpkStore& store,
    ComponentCommandRunner run)
    : options_(std::move(options)), store_(store), run_(std::move(run)) {}

std::optional<std::string> ComponentPackageTransaction::read_feed_index(
    std::string& error) const {
    const auto raw = read_bounded(options_.feed_list,
                                  options_.max_feed_list_bytes);
    if (!raw) {
        error = "feed index " + options_.feed_list.string() +
                " is missing, unreadable or larger than " +
                std::to_string(options_.max_feed_list_bytes) + " bytes";
        return std::nullopt;
    }
    if (!gzip_framed(*raw)) return raw;
    try {
        return gunzip_to_string(*raw, options_.max_feed_index_bytes);
    } catch (const std::exception& failure) {
        error = std::string("feed index could not be decompressed: ") +
                failure.what();
        return std::nullopt;
    }
}

// A promotion interrupted after the install was verified leaves the
// installed version's exact bytes in `candidate` while `current` still
// names the one before. Nothing else would ever move them: the feed has
// moved on, so they cannot be fetched again, and the next upgrade would
// overwrite the slot. Finish the move here, where every preparation starts,
// so the store tells the truth before anything reads it.
void ComponentPackageTransaction::finish_interrupted_promotion(
    const std::string& installed_version, std::string& output) {
    if (installed_version.empty()) return;
    const auto candidate = store_.inspect(IpkSlot::candidate);
    if (candidate.state != IpkSlotState::usable ||
        candidate.retained->version != installed_version) {
        return;
    }
    const auto current = store_.inspect(IpkSlot::current);
    if (current.state == IpkSlotState::usable &&
        current.retained->version == installed_version) {
        // Both hold it; the candidate is a leftover of a finished move.
        store_.discard(IpkSlot::candidate);
        return;
    }
    try {
        store_.promote_candidate();
        append_line(output,
                    "Finished an interrupted promotion: the exact copy of "
                    "the installed version " + installed_version +
                        " is now current.");
    } catch (const std::exception& failure) {
        append_line(output,
                    std::string("An interrupted promotion could not be "
                                "finished: ") + failure.what());
    }
}

ComponentPackagePreparation ComponentPackageTransaction::prepare(
    const std::string& installed_version) {
    return prepare_impl(installed_version, /*stage_target=*/true);
}

ComponentPackagePreparation ComponentPackageTransaction::retain_installed(
    const std::string& installed_version) {
    return prepare_impl(installed_version, /*stage_target=*/false);
}

ComponentPackagePreparation ComponentPackageTransaction::prepare_impl(
    const std::string& installed_version, bool stage_target) {
    ComponentPackagePreparation preparation;
    preparation.installed_version = installed_version;

    const auto fail = [&](const std::string& reason) {
        preparation.error = reason;
        append_line(preparation.output, reason + ".");
        return preparation;
    };

    finish_interrupted_promotion(installed_version, preparation.output);

    // 1. Feed metadata. A failure here touched nothing of the component.
    {
        const auto update =
            run_({options_.opkg, "update"}, options_.timeouts, {});
        preparation.timed_out = update.timed_out;
        preparation.termination_uncertain = update.termination_uncertain;
        if (update.timed_out || update.termination_uncertain ||
            update.exit_code != 0) {
            return fail("opkg update did not finish cleanly; the feed index "
                        "was not refreshed");
        }
        preparation.feed_updated = true;
    }

    // 2. What the feed names, from the copy opkg just wrote. `opkg download`
    // fetches the newest stanza, so that is the one that can be verified;
    // an older stanza that happens to be the installed version is noted
    // but cannot be retained through opkg.
    std::string read_error;
    const auto index = read_feed_index(read_error);
    if (!index) return fail(read_error);
    preparation.feed_read = true;
    const auto entries = parse_opkg_packages_index(*index);
    for (const auto& entry : entries) {
        if (entry.package != options_.package) continue;
        if (!preparation.listed ||
            feed_version_newer(entry.version, preparation.listed->version)) {
            preparation.listed = entry;
        }
    }
    if (!preparation.listed) {
        return fail("the feed index does not identify an exact IPK for " +
                    options_.package);
    }
    const auto& listed = *preparation.listed;
    append_line(preparation.output,
                "Feed lists " + options_.package + " " + listed.version +
                    " (" + listed.filename + ", " +
                    std::to_string(listed.size) + " bytes).");

    // 3. What the store already holds for the installed version.
    const auto current = store_.inspect(IpkSlot::current);
    std::optional<RetainedIpk> retained_current;
    if (current.state == IpkSlotState::usable) {
        retained_current = current.retained;
    } else if (current.state == IpkSlotState::corrupt) {
        append_line(preparation.output,
                    "The retained copy of the installed package is corrupt (" +
                        current.detail + ") and will not be used.");
    }
    preparation.previous_exact =
        retained_current && retained_current->version == installed_version;

    const bool listed_is_installed = listed.version == installed_version;
    // With nothing installed (a fresh install prepares with an empty
    // version) anything the feed serves is the target: a version whose
    // numerics parse as zeros would otherwise compare "not newer than
    // nothing" and misreport an empty router as up to date.
    const bool listed_is_newer =
        installed_version.empty()
            ? true
            : feed_version_newer(listed.version, installed_version);
    preparation.retention = decide_ipk_retention(
        installed_version, retained_current,
        listed_is_installed ? preparation.listed : std::nullopt);
    if (listed_is_newer) {
        preparation.target = listed;
    } else {
        preparation.up_to_date = true;
    }

    const bool need_download =
        (stage_target && preparation.target.has_value()) ||
        preparation.retention == IpkRetentionAction::retain_now;
    if (!need_download) {
        if (preparation.up_to_date) {
            append_line(preparation.output,
                        "Installed version " + installed_version +
                            " is the latest the feed serves.");
        } else if (preparation.target) {
            append_line(preparation.output,
                        "A newer version " + preparation.target->version +
                            " is available; it is not fetched here.");
        }
        if (preparation.retention == IpkRetentionAction::already_retained) {
            append_line(preparation.output,
                        "An exact copy of the installed package is retained.");
        } else if (preparation.retention == IpkRetentionAction::unavailable) {
            const auto installed_entry = find_feed_entry(
                entries, options_.package, installed_version);
            append_line(preparation.output,
                        installed_entry
                            ? "The feed still lists the installed version " +
                                  installed_version +
                                  " behind a newer one; opkg download "
                                  "fetches only the newest, so no exact copy "
                                  "can be retained."
                            : "The feed no longer serves the installed "
                                  "version " + installed_version +
                                  "; no exact copy of it can be retained.");
        }
        return preparation;
    }

    // 4. Fetch the one IPK the feed serves, verify it against the index.
    fs::path staging;
    try {
        staging = store_.staging_directory();
    } catch (const std::exception& failure) {
        return fail(std::string("package staging directory is unusable: ") +
                    failure.what());
    }
    const auto download =
        run_(component_download_argv(options_), options_.timeouts, staging);
    preparation.timed_out = download.timed_out;
    preparation.termination_uncertain = download.termination_uncertain;
    if (download.timed_out || download.termination_uncertain ||
        download.exit_code != 0) {
        return fail("opkg download " + options_.package +
                    " did not finish cleanly; nothing was installed");
    }
    const auto downloaded = staging / fs::path(listed.filename).filename();
    const auto bytes = read_bounded(downloaded, listed.size);
    if (!bytes) {
        return fail("the downloaded file " + downloaded.string() +
                    " is missing or not the size the feed promised");
    }
    const auto slot = preparation.target ? IpkSlot::candidate
                                         : IpkSlot::current;
    try {
        store_.adopt(slot, *bytes, listed);
    } catch (const std::exception& failure) {
        return fail(std::string("the downloaded package was refused: ") +
                    failure.what());
    }
    std::error_code error;
    fs::remove(downloaded, error);

    if (preparation.target) {
        preparation.candidate_verified = true;
        append_line(preparation.output,
                    "Target " + listed.version +
                        " verified against the feed index (SHA-256 " +
                        listed.sha256.substr(0, 12) + "...) and staged.");
        if (!preparation.previous_exact && !installed_version.empty()) {
            // Upgrade wording, and only for an upgrade: a fresh install
            // has no installed version whose copy could be missed.
            append_line(preparation.output,
                        "No exact copy of the installed version " +
                            installed_version +
                            " is retained: the feed serves only " +
                            listed.version +
                            ". A failed upgrade can restore captured files "
                            "but not exact package metadata.");
        }
    } else {
        preparation.previous_exact = true;
        append_line(preparation.output,
                    "Exact copy of the installed version " +
                        installed_version + " retained.");
    }
    return preparation;
}

ExecCaptureResult ComponentPackageTransaction::install_candidate() {
    const auto candidate = store_.inspect(IpkSlot::candidate);
    if (candidate.state != IpkSlotState::usable) {
        throw ComponentPackageRefused(
            std::string("no verified candidate package to install "
                        "(candidate slot is ") +
            ipk_slot_state_name(candidate.state) + ")");
    }
    return run_({options_.opkg, "install",
                 store_.ipk_path(IpkSlot::candidate).string()},
                options_.timeouts, {});
}

ExecCaptureResult ComponentPackageTransaction::reinstall_current(
    const std::string& expected_version) {
    const auto current = store_.inspect(IpkSlot::current);
    if (current.state != IpkSlotState::usable) {
        throw ComponentPackageRefused(
            std::string("no exact copy of the previous package to "
                        "reinstall (current slot is ") +
            ipk_slot_state_name(current.state) + ")");
    }
    if (current.retained->version != expected_version) {
        throw ComponentPackageRefused(
            "the retained package is version " + current.retained->version +
            ", not " + expected_version + "; refusing to reinstall it");
    }
    return run_({options_.opkg, "install", "--force-downgrade",
                 "--force-reinstall",
                 store_.ipk_path(IpkSlot::current).string()},
                options_.timeouts, {});
}

void ComponentPackageTransaction::promote_installed_candidate() {
    store_.promote_candidate();
}

void ComponentPackageTransaction::scripted_install_candidate(
    bool upgrade, ScriptedInstallReport& report,
    const ScriptedServiceStop& stop_service) {
    const auto candidate = store_.inspect(IpkSlot::candidate);
    if (candidate.state != IpkSlotState::usable) {
        throw ComponentPackageRefused(
            std::string("no verified candidate package to install "
                        "(candidate slot is ") +
            ipk_slot_state_name(candidate.state) + ")");
    }
    scripted_install(IpkSlot::candidate, {}, upgrade, report, stop_service);
}

void ComponentPackageTransaction::scripted_reinstall_current(
    const std::string& expected_version, ScriptedInstallReport& report,
    const ScriptedServiceStop& stop_service) {
    const auto current = store_.inspect(IpkSlot::current);
    if (current.state != IpkSlotState::usable) {
        throw ComponentPackageRefused(
            std::string("no exact copy of the previous package to "
                        "reinstall (current slot is ") +
            ipk_slot_state_name(current.state) + ")");
    }
    if (current.retained->version != expected_version) {
        throw ComponentPackageRefused(
            "the retained package is version " + current.retained->version +
            ", not " + expected_version + "; refusing to reinstall it");
    }
    // The reinstall is a downgrade or a same-version replay to opkg; the
    // scripts still see it as an upgrade of an installed package.
    scripted_install(IpkSlot::current,
                     {"--force-downgrade", "--force-reinstall"},
                     /*upgrade=*/true, report, stop_service);
}

namespace {

// The extraction scratch holds the whole IPK - the multi-arch data.tar.gz
// included - so it is removed on every exit, early returns and unwinding
// alike, not only on the straight-through path.
struct StagingCleanup {
    fs::path stage;
    ~StagingCleanup() {
        std::error_code error;
        fs::remove_all(stage, error);
    }
};

} // namespace

void ComponentPackageTransaction::scripted_install(
    IpkSlot slot, const std::vector<std::string>& extra_install_flags,
    bool upgrade, ScriptedInstallReport& report,
    const ScriptedServiceStop& stop_service) {
    const auto ipk = store_.ipk_path(slot);
    const auto command_ok = [](const ExecCaptureResult& result) {
        return result.exit_code == 0 && !result.timed_out &&
               !result.termination_uncertain;
    };

    // 1. Lay the IPK's own maintainer scripts out in the store's staging
    // directory. Wholesale extraction, because the member names vary
    // (`control.tar.gz` in the feed's IPKs, `./control.tar.gz` in others)
    // and the archive holds nothing else of size beyond data.tar.gz.
    fs::path stage;
    try {
        stage = store_.staging_directory();
    } catch (const std::exception& failure) {
        append_line(report.notes,
                    std::string("The staging directory for the package "
                                "scripts is unavailable: ") +
                        failure.what());
        return;
    }
    const StagingCleanup staging_cleanup{stage};
    const auto scripts_dir = stage / "control";
    if (!command_ok(run_({options_.scripted.tar, "-xzf", ipk.string(), "-C",
                          stage.string()},
                         options_.timeouts, {}))) {
        append_line(report.notes,
                    "The package archive could not be unpacked for its "
                    "maintainer scripts; nothing was mutated.");
        return;
    }
    std::error_code fs_error;
    fs::path control_archive = stage / "control.tar.gz";
    if (!fs::is_regular_file(control_archive, fs_error)) {
        append_line(report.notes,
                    "The package archive holds no control.tar.gz; nothing "
                    "was mutated.");
        return;
    }
    fs::create_directories(scripts_dir, fs_error);
    if (fs_error ||
        !command_ok(run_({options_.scripted.tar, "-xzf",
                          control_archive.string(), "-C",
                          scripts_dir.string()},
                         options_.timeouts, {}))) {
        append_line(report.notes,
                    "The package's control archive could not be unpacked; "
                    "nothing was mutated.");
        return;
    }
    report.scripts_extracted = true;

    // 2. preinst, before the unpack, exactly where opkg runs it: on this
    // component it decides config migrations by moving the old config aside
    // so the unpack below lays down the fresh one.
    const auto preinst = scripts_dir / "preinst";
    if (fs::is_regular_file(preinst, fs_error)) {
        report.preinst_ran = true;
        report.preinst_ok = command_ok(
            run_({options_.scripted.shell, preinst.string(),
                  upgrade ? "upgrade" : "install"},
                 options_.timeouts, {}));
        if (!report.preinst_ok) {
            append_line(report.notes,
                        "The package's preinst script failed; the package "
                        "manager was not run.");
            return;
        }
    }

    // 2b. The caller's service stop, in the old prerm's slot: a plain
    // upgrade stopped the running service here, and nothing later in this
    // flow will (postinst's guarded stop is exactly what the held init
    // script silences). A service that cannot be proven stopped keeps its
    // files: the unpack is refused.
    if (stop_service) {
        report.service_stop_ran = true;
        report.service_stop_ok = stop_service(report.notes);
        if (!report.service_stop_ok) {
            append_line(report.notes,
                        "The running service could not be proven stopped; "
                        "the package manager was not run.");
            return;
        }
    }

    // 3. The unpack. `-o` skips every maintainer script; `-f` names the
    // real opkg configuration explicitly, because with an offline root opkg
    // resolves its configuration against that root and would otherwise run
    // without the architecture and feed lines a plain run sees.
    std::vector<std::string> install_argv{
        options_.opkg, "-o", options_.scripted.offline_root.string(), "-f",
        options_.scripted.opkg_conf.string(), "install"};
    install_argv.insert(install_argv.end(), extra_install_flags.begin(),
                        extra_install_flags.end());
    install_argv.push_back(ipk.string());
    report.mutation_started = true;
    report.unpack_ok =
        command_ok(run_(install_argv, options_.timeouts, {}));
    if (!report.unpack_ok) {
        append_line(report.notes,
                    "opkg could not unpack the package; the maintainer "
                    "scripts were not run.");
        return;
    }

    // 4-6. postinst between holding the init script aside and putting it
    // back. The script guards its service start and stop with a file
    // check, so a held-aside init script turns both into silent no-ops
    // while the config work and the multiplatform binary copy still run.
    // The unpack above just laid the new init script down, which is why
    // the hold happens here and not before opkg; a stale held copy from an
    // interrupted earlier run is replaced by the rename.
    const auto postinst = scripts_dir / "postinst";
    if (!fs::is_regular_file(postinst, fs_error)) {
        append_line(report.notes,
                    "The package has no postinst script; nothing had to be "
                    "suppressed.");
        return;
    }
    const auto& init = options_.scripted.init_script;
    const auto& held = options_.scripted.held_init_script;
    const auto init_status = fs::symlink_status(init, fs_error);
    if (fs_error && init_status.type() != fs::file_type::not_found) {
        // Absence is fine (libstdc++ reports it as not_found, with the
        // error code set to ENOENT); any other errored stat means the init
        // script may well be there. Running postinst on that guess would
        // let its real stop and start escape the transaction, so this
        // fails closed instead.
        report.postinst_ok = false;
        append_line(report.notes,
                    "The init script could not be inspected (" +
                        fs_error.message() +
                        "); postinst was not run and the package's real "
                        "binary was not installed.");
        return;
    }
    if (fs::exists(init_status)) {
        fs::rename(init, held, fs_error);
        if (fs_error) {
            // Running postinst with the init script in place would start
            // the service outside the transaction; failing the install is
            // the smaller harm. The binary has not been switched, which the
            // caller's verification is built to catch.
            report.postinst_ok = false;
            append_line(report.notes,
                        "The init script could not be held aside (" +
                            fs_error.message() +
                            "); postinst was not run and the package's real "
                            "binary was not installed.");
            return;
        }
        report.init_held = true;
        report.init_restored = false;
    }
    report.postinst_ran = true;
    const auto restore_init = [&] {
        if (!report.init_held || report.init_restored) return;
        std::error_code restore_error;
        fs::rename(held, init, restore_error);
        if (restore_error) {
            append_line(report.notes,
                        "The init script could not be restored from " +
                            held.string() + " (" + restore_error.message() +
                            "); boot recovery restores it by that name.");
        } else {
            report.init_restored = true;
        }
    };
    try {
        report.postinst_ok = command_ok(
            run_({options_.scripted.shell, postinst.string(), "configure"},
                 options_.timeouts, {}));
    } catch (...) {
        // Whatever the runner threw, the init script must not stay held.
        restore_init();
        throw;
    }
    if (!report.postinst_ok) {
        append_line(report.notes, "The package's postinst script failed.");
    }
    restore_init();
}

} // namespace keen_pbr3
