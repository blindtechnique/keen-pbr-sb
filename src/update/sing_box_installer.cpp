#include "sing_box_installer.hpp"

namespace keen_pbr3 {

const char* sing_box_install_outcome_name(
    const SingBoxInstallOutcome outcome) noexcept {
    switch (outcome) {
    case SingBoxInstallOutcome::installed:
        return "installed";
    case SingBoxInstallOutcome::release_refused:
        return "release_refused";
    case SingBoxInstallOutcome::download_failed:
        return "download_failed";
    case SingBoxInstallOutcome::checksum_mismatch:
        return "checksum_mismatch";
    case SingBoxInstallOutcome::archive_unusable:
        return "archive_unusable";
    case SingBoxInstallOutcome::staged_version_mismatch:
        return "staged_version_mismatch";
    case SingBoxInstallOutcome::install_failed:
        return "install_failed";
    case SingBoxInstallOutcome::marker_not_written:
        return "marker_not_written";
    }
    return "release_refused";
}

SingBoxInstallReport install_pinned_sing_box(
    const SingBoxInstallSteps& steps,
    const std::string& release_json_url,
    const std::string& pinned_version,
    const std::string& asset_architecture) {
    SingBoxInstallReport report;

    // A missing step is a caller error, and the safe reading of "this
    // installer was assembled wrong" is that nothing gets installed.
    if (!steps.fetch || !steps.digest || !steps.stage_archive ||
        !steps.read_staged_version || !steps.install_atomically ||
        !steps.write_managed_marker) {
        report.outcome = SingBoxInstallOutcome::install_failed;
        return report;
    }

    const auto release = steps.fetch(release_json_url);
    if (!release.has_value()) {
        report.outcome = SingBoxInstallOutcome::download_failed;
        return report;
    }

    const auto plan = plan_sing_box_release(
        *release, pinned_version, asset_architecture);
    report.release_verdict = plan.verdict;
    if (plan.verdict != SingBoxReleaseVerdict::ready) {
        // Includes checksums_missing, which is the refusal that separates this
        // path from the shell installer.
        report.outcome = SingBoxInstallOutcome::release_refused;
        return report;
    }

    const auto archive = steps.fetch(plan.archive_url);
    if (!archive.has_value()) {
        report.outcome = SingBoxInstallOutcome::download_failed;
        return report;
    }
    const auto checksums = steps.fetch(plan.checksums_url);
    if (!checksums.has_value()) {
        // The checksums file being unreachable is not a reason to install
        // without it. It is the same refusal as it never having existed.
        report.outcome = SingBoxInstallOutcome::download_failed;
        return report;
    }

    report.release_verdict = verify_sing_box_archive(
        *checksums, plan.archive_name, steps.digest(*archive));
    if (report.release_verdict != SingBoxReleaseVerdict::ready) {
        report.outcome = SingBoxInstallOutcome::checksum_mismatch;
        return report;
    }

    // Only now are the bytes unpacked. Everything above happened in memory,
    // so a release that fails verification never reaches the filesystem.
    const auto staged = steps.stage_archive(*archive);
    if (staged.empty()) {
        report.outcome = SingBoxInstallOutcome::archive_unusable;
        return report;
    }

    report.staged_version = steps.read_staged_version(staged);
    if (report.staged_version != pinned_version) {
        // The archive verified against its published digest and still does not
        // contain the release it claims to. That is upstream's problem, but
        // finding it here rather than after the swap is ours - and the check
        // is on the staged copy precisely so the running binary is still the
        // old one when it fails.
        report.outcome = SingBoxInstallOutcome::staged_version_mismatch;
        return report;
    }

    if (!steps.install_atomically(staged)) {
        report.outcome = SingBoxInstallOutcome::install_failed;
        return report;
    }

    if (!steps.write_managed_marker()) {
        // The binary is in place and correct; only its provenance record is
        // missing. Not a failure of the install, and not a success either:
        // without the marker the next capability read calls this binary the
        // operator's and refuses to touch it.
        report.outcome = SingBoxInstallOutcome::marker_not_written;
        return report;
    }

    report.outcome = SingBoxInstallOutcome::installed;
    return report;
}

} // namespace keen_pbr3
