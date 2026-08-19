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
    case SingBoxInstallOutcome::cancelled:
        return "cancelled";
    }
    return "release_refused";
}

bool sing_box_install_phase_is_reversible(
    const SingBoxInstallPhase phase) noexcept {
    switch (phase) {
    case SingBoxInstallPhase::reading_release:
    case SingBoxInstallPhase::downloading_archive:
    case SingBoxInstallPhase::downloading_checksums:
    case SingBoxInstallPhase::verifying_archive:
    case SingBoxInstallPhase::unpacking:
    case SingBoxInstallPhase::checking_staged_version:
        // In memory, or in a staging directory nobody runs from.
        return true;
    case SingBoxInstallPhase::installing:
    case SingBoxInstallPhase::recording_marker:
        // The binary is being replaced. Stopping here cannot leave the router
        // better off than finishing does.
        return false;
    }
    // A phase this build does not know is treated as the moment of change.
    // Guessing the other way would allow a cancel through a step that was
    // added precisely because it changes something.
    return false;
}

void SingBoxInstallCancellationCoordinator::begin(const Token& token) {
    const std::lock_guard<std::mutex> lock(mutex_);
    token_ = token;
    reversible_ = token_ != nullptr;
}

void SingBoxInstallCancellationCoordinator::finish(
    const Token& token) noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (token_ != token) return;
    token_.reset();
    reversible_ = false;
}

bool SingBoxInstallCancellationCoordinator::enter_phase(
    const Token& token,
    const SingBoxInstallPhase phase) {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!token || token_ != token ||
        token->load(std::memory_order_relaxed)) {
        return false;
    }
    // This assignment and cancel() are under the same mutex. In particular,
    // entering `installing` closes cancellation before the rename can start.
    reversible_ = sing_box_install_phase_is_reversible(phase);
    return true;
}

SingBoxInstallCancelVerdict
SingBoxInstallCancellationCoordinator::cancel() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!token_) return SingBoxInstallCancelVerdict::not_running;
    if (!reversible_) {
        return SingBoxInstallCancelVerdict::past_point_of_no_return;
    }
    token_->store(true, std::memory_order_relaxed);
    return SingBoxInstallCancelVerdict::accepted;
}

const char* sing_box_install_phase_name(
    const SingBoxInstallPhase phase) noexcept {
    switch (phase) {
    case SingBoxInstallPhase::reading_release:
        return "reading_release";
    case SingBoxInstallPhase::downloading_archive:
        return "downloading_archive";
    case SingBoxInstallPhase::downloading_checksums:
        return "downloading_checksums";
    case SingBoxInstallPhase::verifying_archive:
        return "verifying_archive";
    case SingBoxInstallPhase::unpacking:
        return "unpacking";
    case SingBoxInstallPhase::checking_staged_version:
        return "checking_staged_version";
    case SingBoxInstallPhase::installing:
        return "installing";
    case SingBoxInstallPhase::recording_marker:
        return "recording_marker";
    }
    return "installing";
}

SingBoxInstallReport install_pinned_sing_box(
    const SingBoxInstallSteps& steps,
    const std::string& release_json_url,
    const std::string& pinned_version,
    const std::string& asset_architecture,
    const SingBoxInstallProgress& progress,
    const SingBoxInstallPhaseAdmission& phase_admission) {
    SingBoxInstallReport report;

    const auto entering = [&progress, &phase_admission](
                              const SingBoxInstallPhase phase) {
        if (phase_admission && !phase_admission(phase)) return false;
        if (progress) progress(phase);
        return true;
    };

    // A missing step is a caller error, and the safe reading of "this
    // installer was assembled wrong" is that nothing gets installed. No phase
    // is announced for it: nothing was attempted, and the caller's own
    // reporter is what tells anyone watching that the attempt ended.
    if (!steps.fetch || !steps.digest || !steps.stage_archive ||
        !steps.read_staged_version || !steps.install_atomically ||
        !steps.write_managed_marker) {
        report.outcome = SingBoxInstallOutcome::install_failed;
        return report;
    }

    if (!entering(SingBoxInstallPhase::reading_release)) {
        report.outcome = SingBoxInstallOutcome::cancelled;
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

    if (!entering(SingBoxInstallPhase::downloading_archive)) {
        report.outcome = SingBoxInstallOutcome::cancelled;
        return report;
    }
    const auto archive = steps.fetch(plan.archive_url);
    if (!archive.has_value()) {
        report.outcome = SingBoxInstallOutcome::download_failed;
        return report;
    }
    const auto actual_digest = steps.digest(*archive);
    if (!plan.checksums_url.empty()) {
        if (!entering(SingBoxInstallPhase::downloading_checksums)) {
            report.outcome = SingBoxInstallOutcome::cancelled;
            return report;
        }
        const auto checksums = steps.fetch(plan.checksums_url);
        if (!checksums.has_value()) {
            // The checksums file being unreachable is not a reason to install
            // without it, and not a reason to fall back to the asset digest
            // either: a release that publishes both and cannot serve one is
            // not a release this should be guessing about.
            report.outcome = SingBoxInstallOutcome::download_failed;
            return report;
        }
        if (!entering(SingBoxInstallPhase::verifying_archive)) {
            report.outcome = SingBoxInstallOutcome::cancelled;
            return report;
        }
        report.release_verdict = verify_sing_box_archive(
            *checksums, plan.archive_name, actual_digest);
    } else {
        // No checksums file. The digest GitHub publishes for this exact asset
        // is what the download is compared against - measured on the pinned
        // release, sing-box publishes no checksums file at all, so without
        // this the install would refuse every time.
        if (!entering(SingBoxInstallPhase::verifying_archive)) {
            report.outcome = SingBoxInstallOutcome::cancelled;
            return report;
        }
        report.release_verdict =
            plan.asset_digest == actual_digest
                ? SingBoxReleaseVerdict::ready
                : SingBoxReleaseVerdict::checksum_mismatch;
    }
    if (report.release_verdict != SingBoxReleaseVerdict::ready) {
        report.outcome = SingBoxInstallOutcome::checksum_mismatch;
        return report;
    }

    // Only now are the bytes unpacked. Everything above happened in memory,
    // so a release that fails verification never reaches the filesystem.
    if (!entering(SingBoxInstallPhase::unpacking)) {
        report.outcome = SingBoxInstallOutcome::cancelled;
        return report;
    }
    const auto staged = steps.stage_archive(*archive);
    if (staged.empty()) {
        report.outcome = SingBoxInstallOutcome::archive_unusable;
        return report;
    }

    if (!entering(SingBoxInstallPhase::checking_staged_version)) {
        report.outcome = SingBoxInstallOutcome::cancelled;
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

    if (!entering(SingBoxInstallPhase::installing)) {
        report.outcome = SingBoxInstallOutcome::cancelled;
        return report;
    }
    const auto commit = steps.install_atomically(staged);
    report.binary_committed = commit.committed;
    report.binary_durable = commit.committed && commit.durable;
    if (!commit.committed) {
        report.outcome = SingBoxInstallOutcome::install_failed;
        return report;
    }

    // Once committed, cancellation stays closed even when the caller supplied
    // an inconsistent custom admission callback. The production coordinator
    // already made this transition non-reversible under its mutex.
    if (!entering(SingBoxInstallPhase::recording_marker)) {
        report.outcome = SingBoxInstallOutcome::marker_not_written;
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
