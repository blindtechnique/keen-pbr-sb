#include "component_boot_recovery.hpp"

namespace keen_pbr3 {

const char* component_boot_recovery_action_name(
    ComponentBootRecoveryAction action) noexcept {
    switch (action) {
    case ComponentBootRecoveryAction::none: return "none";
    case ComponentBootRecoveryAction::clear_journal: return "clear_journal";
    case ComponentBootRecoveryAction::restore_files: return "restore_files";
    case ComponentBootRecoveryAction::reinstall_previous:
        return "reinstall_previous";
    case ComponentBootRecoveryAction::restore_files_inexact:
        return "restore_files_inexact";
    case ComponentBootRecoveryAction::manual: return "manual";
    }
    return "unknown";
}

ComponentBootRecoveryPlan decide_component_boot_recovery(
    const ComponentBootRecoveryEvidence& evidence) {
    ComponentBootRecoveryPlan plan;
    const auto& journal = evidence.journal;

    switch (journal.state) {
    case ComponentTransactionState::none:
        plan.reason = "no component transaction was in flight";
        return plan;
    case ComponentTransactionState::in_flight:
        plan.reason = "a live process owns the component transaction";
        return plan;
    case ComponentTransactionState::unreadable:
        // A torn journal is itself evidence of an interruption, and one
        // whose pre-mutation record is gone. There is nothing to compare
        // against, so nothing may be reinstalled or restored by guesswork.
        plan.action = ComponentBootRecoveryAction::manual;
        plan.reason = "the component transaction journal cannot be read";
        return plan;
    case ComponentTransactionState::abandoned:
        break;
    }

    if (!journal.record) {
        plan.action = ComponentBootRecoveryAction::manual;
        plan.reason = "the abandoned transaction carries no record";
        return plan;
    }
    const auto& record = *journal.record;

    if (record.phase == ComponentTransactionPhase::started) {
        plan.action = ComponentBootRecoveryAction::clear_journal;
        plan.clear_journal_on_success = true;
        plan.reason = "the transaction was interrupted before any mutation";
        return plan;
    }
    if (record.phase == ComponentTransactionPhase::verified) {
        // Package, configuration and runtime were all verified before the
        // interruption; what did not finish is bookkeeping. Reinstalling
        // the previous version from here would undo a finished upgrade.
        plan.action = ComponentBootRecoveryAction::clear_journal;
        plan.clear_journal_on_success = true;
        plan.reason = "the upgrade was verified before the interruption; "
                      "only bookkeeping was left";
        return plan;
    }

    if (record.operation == "install" &&
        evidence.installed_version.empty() &&
        evidence.installed_binary_sha256.empty()) {
        // An interrupted fresh install, and nothing is installed now: both
        // the package database and the binary say so. There was nothing
        // before the install to restore, and there is nothing after it to
        // repair - the retry is simply installing again. Requiring both
        // signals keeps a transient opkg failure (version unreadable but
        // the binary on disk) on the manual path below.
        plan.action = ComponentBootRecoveryAction::clear_journal;
        plan.clear_journal_on_success = true;
        plan.reason = "the interrupted operation was a fresh install and "
                      "nothing is installed; there was nothing before it "
                      "to restore";
        return plan;
    }

    const bool capture_usable =
        evidence.capture == ComponentCaptureState::usable;

    // Is the package provably what it was before the mutation? Both halves
    // must be known and must match: an unreadable version or digest is not
    // a match, it is an unknown.
    const bool version_known =
        !record.previous_version.empty() && !evidence.installed_version.empty();
    const bool digest_known = !record.binary_sha256.empty() &&
                              !evidence.installed_binary_sha256.empty();
    const bool package_unchanged =
        version_known && digest_known &&
        evidence.installed_version == record.previous_version &&
        evidence.installed_binary_sha256 == record.binary_sha256;

    if (package_unchanged) {
        if (capture_usable) {
            plan.action = ComponentBootRecoveryAction::restore_files;
            plan.clear_journal_on_success = true;
            plan.reason =
                "the installed package is the pre-mutation one; only the "
                "captured files need restoring";
        } else {
            // Binary and version match, but the configuration the package
            // manager may have touched cannot be put back. Not clearable:
            // "unchanged" is a claim about the package, not the component.
            plan.action = ComponentBootRecoveryAction::manual;
            plan.reason =
                "the installed package is the pre-mutation one, but there is "
                "no usable capture to restore its files from";
        }
        return plan;
    }

    const bool exact_previous_available =
        record.exact_previous_ipk &&
        evidence.previous_ipk.state == IpkSlotState::usable &&
        evidence.previous_ipk.retained &&
        !record.previous_version.empty() &&
        evidence.previous_ipk.retained->version == record.previous_version;

    if (exact_previous_available && capture_usable) {
        plan.action = ComponentBootRecoveryAction::reinstall_previous;
        plan.reinstall_version = record.previous_version;
        plan.clear_journal_on_success = true;
        plan.reason = "the exact previous package " + record.previous_version +
                      " and a usable capture are both held";
        return plan;
    }
    if (exact_previous_available) {
        // The package can be put back exactly; its captured files cannot.
        // Reinstalling alone would leave package defaults where the
        // operator's configuration was, and calling that recovered would be
        // the overstatement this path exists to avoid.
        plan.action = ComponentBootRecoveryAction::manual;
        plan.reason = "the exact previous package is held, but there is no "
                      "usable capture to restore its files from";
        return plan;
    }
    if (capture_usable) {
        plan.action = ComponentBootRecoveryAction::restore_files_inexact;
        plan.reason =
            record.exact_previous_ipk
                ? "the journal promised an exact previous package but the "
                  "store no longer holds it; captured files only"
                : "no exact previous package was retained; captured files "
                  "only";
        return plan;
    }
    plan.action = ComponentBootRecoveryAction::manual;
    plan.reason = "neither an exact previous package nor a usable capture "
                  "is available";
    return plan;
}

} // namespace keen_pbr3
