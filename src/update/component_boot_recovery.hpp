#pragma once

#include "component_capture.hpp"
#include "component_ipk_store.hpp"
#include "component_transaction_journal.hpp"

#include <string>

namespace keen_pbr3 {

// What to do about a component transaction journal found at boot, decided
// from evidence alone. This pure decision is separate from the existing
// executor, which runs opkg and restores the service under the shared
// update/lifecycle lock. Keeping the decision pure lets tests cover leftover
// state without a router; the executor consumes this verdict.
enum class ComponentBootRecoveryAction {
    // No journal, or one another live process owns. Nothing to do here.
    none,
    // The journal says nothing was mutated. Remove it; the component is as
    // it was.
    clear_journal,
    // No exact IPK is available, but the installed version and binary digest
    // match the journal. Preserve the existing captured-file repair fallback;
    // these observations alone do not verify every opkg metadata file.
    restore_files,
    // An abandoned mutating/verifying upgrade has an exact previous IPK and
    // a usable capture. Reinstall package metadata even when the observed
    // version and binary still match, then restore captured files and runtime.
    reinstall_previous,
    // No exact previous package, but a usable capture: restore files only.
    // opkg metadata stays unverified, so the journal must be retained
    // afterwards exactly as the interactive path retains it.
    restore_files_inexact,
    // Nothing on disk can put the component back. Leave the journal, block
    // upgrades, tell the operator.
    manual,
};

const char* component_boot_recovery_action_name(
    ComponentBootRecoveryAction action) noexcept;

struct ComponentBootRecoveryEvidence {
    ComponentTransactionStatus journal;
    // The store's current slot, inspected now.
    IpkSlotInspection previous_ipk;
    ComponentCaptureState capture{ComponentCaptureState::absent};
    // From `opkg status`; empty when it could not be read.
    std::string installed_version;
    // SHA-256 of the installed binary; empty when it could not be read.
    std::string installed_binary_sha256;
};

struct ComponentBootRecoveryPlan {
    ComponentBootRecoveryAction action{ComponentBootRecoveryAction::none};
    // One sentence for the log and the operator.
    std::string reason;
    // The version to reinstall, for reinstall_previous.
    std::string reinstall_version;
    // Whether the journal may be cleared once the action succeeds. False for
    // restore_files_inexact and manual.
    bool clear_journal_on_success{false};
};

ComponentBootRecoveryPlan decide_component_boot_recovery(
    const ComponentBootRecoveryEvidence& evidence);

} // namespace keen_pbr3
