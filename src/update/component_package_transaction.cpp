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

ExecCaptureResult refused(const std::string& reason) {
    ExecCaptureResult result;
    result.exit_code = -1;
    result.stdout_output = reason + "\n";
    return result;
}

} // namespace

std::vector<std::string> component_download_argv(
    const ComponentPackageOptions& options,
    const fs::path& staging) {
    return {
        options.shell,
        "-c",
        "cd \"$1\" && exec \"$2\" download \"$3\"",
        "keen-pbr-component-download",
        staging.string(),
        options.opkg,
        options.package,
    };
}

ComponentPackageTransaction::ComponentPackageTransaction(
    ComponentPackageOptions options,
    ComponentIpkStore& store,
    ComponentCommandRunner run)
    : options_(std::move(options)), store_(store), run_(std::move(run)) {}

std::vector<std::string> ComponentPackageTransaction::download_argv(
    const fs::path& staging) const {
    return component_download_argv(options_, staging);
}

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

    // 1. Feed metadata. A failure here touched nothing of the component.
    {
        const auto update = run_({options_.opkg, "update"}, options_.timeouts);
        preparation.timed_out = update.timed_out;
        preparation.termination_uncertain = update.termination_uncertain;
        if (update.timed_out || update.termination_uncertain ||
            update.exit_code != 0) {
            return fail("opkg update did not finish cleanly; the feed index "
                        "was not refreshed");
        }
        preparation.feed_updated = true;
    }

    // 2. What the feed names, from the copy opkg just wrote.
    std::string read_error;
    const auto index = read_feed_index(read_error);
    if (!index) return fail(read_error);
    preparation.feed_read = true;
    const auto entries = parse_opkg_packages_index(*index);
    for (const auto& entry : entries) {
        if (entry.package == options_.package) {
            preparation.listed = entry;
            break;
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
    const bool listed_is_newer =
        feed_version_newer(listed.version, installed_version);
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
            append_line(preparation.output,
                        "The feed no longer serves the installed version " +
                            installed_version +
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
    const auto download = run_(download_argv(staging), options_.timeouts);
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
        if (!preparation.previous_exact) {
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
        return refused(std::string("no verified candidate package to "
                                   "install (candidate slot is ") +
                       ipk_slot_state_name(candidate.state) + ")");
    }
    return run_({options_.opkg, "install",
                 store_.ipk_path(IpkSlot::candidate).string()},
                options_.timeouts);
}

ExecCaptureResult ComponentPackageTransaction::reinstall_current(
    const std::string& expected_version) {
    const auto current = store_.inspect(IpkSlot::current);
    if (current.state != IpkSlotState::usable) {
        return refused(std::string("no exact copy of the previous package "
                                   "to reinstall (current slot is ") +
                       ipk_slot_state_name(current.state) + ")");
    }
    if (current.retained->version != expected_version) {
        return refused("the retained package is version " +
                       current.retained->version + ", not " +
                       expected_version + "; refusing to reinstall it");
    }
    return run_({options_.opkg, "install", "--force-downgrade",
                 "--force-reinstall",
                 store_.ipk_path(IpkSlot::current).string()},
                options_.timeouts);
}

void ComponentPackageTransaction::promote_installed_candidate() {
    store_.promote_candidate();
}

} // namespace keen_pbr3
