#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include "../update/component_boot_recovery.hpp"
#include "../update/maintenance_lock.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#ifdef KEEN_PBR3_TESTING
#include "../update/component_package_transaction.hpp"
#include "../update/package_footprint.hpp"
#include "../util/nfqws_file_writer.hpp"
#include "../util/safe_exec.hpp"
#include "../util/nfqws_strategy_assets.hpp"

#include <chrono>
#include <filesystem>
#include <vector>
#endif

namespace keen_pbr3 {
void register_nfqws_handler(ApiServer& server, ApiContext& ctx);

// What one run of the boot-time component recovery amounted to.
enum class NfqwsBootRecoveryOutcome {
    // No journal, or one a live process owns: nothing to recover.
    nothing_to_do,
    // The maintenance lease was held by someone else (S80 still starting,
    // an operator's update). Nothing was read under the lease; the caller
    // retries later.
    lease_busy,
    // The plan ran to completion and the journal was cleared: the component
    // is a known quantity again.
    recovered,
    // The plan ran, or nothing could run, and the journal stays: package
    // metadata is still unverified and web upgrades stay blocked, on
    // purpose. `plan`/`reason` say which.
    journal_retained,
    // The plan ran and did not get the component back. Journal retained.
    failed,
};

const char* nfqws_boot_recovery_outcome_name(
    NfqwsBootRecoveryOutcome outcome) noexcept;

struct NfqwsBootRecoveryResult {
    NfqwsBootRecoveryOutcome outcome{NfqwsBootRecoveryOutcome::nothing_to_do};
    // decide_component_boot_recovery's action name and reason.
    std::string plan;
    std::string reason;
    // The operator log of what ran, bounded.
    std::string output;
    bool journal_cleared{false};
    // Which journal this answered: its started_at and operation. A journal
    // that stays on disk (journal_retained, failed) must not be answered
    // again at the next daemon start - re-running a reinstall against a
    // package the operator has since repaired by hand would downgrade the
    // repair. Zero/empty when the journal carried no record.
    std::int64_t journal_started_at{0};
    std::string journal_operation;
};

// The durable record of a previous run's answer, as much of it as the skip
// decision needs.
struct NfqwsBootRecoveryLastAnswer {
    std::int64_t journal_started_at{0};
    std::string journal_operation;
    std::string outcome;
};

// Runs the boot-time recovery of an interrupted nfqws2 package transaction:
// reads the journal; under the maintenance lease (the same one the web
// upgrade and S80 take, in the same order: lease, then the nfqws mutex)
// decides from the journal, the exact-IPK store, the capture and opkg, and
// executes the decision with the very helpers the interactive rollback
// uses. Blocking for up to minutes when opkg runs: call from a worker
// thread, never from the control loop. Never throws.
NfqwsBootRecoveryResult run_nfqws_boot_recovery(ApiContext& ctx) noexcept;

// The boot recovery as orchestration over its inputs and effects, so the
// decision-to-action mapping, the lease handling and the recorded outcome can
// be driven without a router. Production wires every hook to the real helper.
struct NfqwsBootRecoveryStepResult {
    bool rolled_back{false};
    bool package_metadata_restored{false};
};

struct NfqwsBootRecoveryHooks {
    std::function<ComponentTransactionStatus()> read_journal;
    // What a previous run answered, if anything; nullopt when none.
    std::function<std::optional<NfqwsBootRecoveryLastAnswer>()>
        read_last_answer;
    // nullptr means busy; other failures throw MaintenanceLockError.
    std::function<std::unique_ptr<MaintenanceLease>()> acquire_lease;
    // Whether the held-aside init script name exists - a free filesystem
    // look, no lease. When it does, the run proceeds to the lease and the
    // heal below even where it would otherwise return early (no journal,
    // journal already answered): the held name is physical evidence that a
    // scripted install's hold was never undone, and no early-return gate
    // may leave the boot sequence without its init script.
    std::function<bool()> init_script_held;
    // A scripted install holds the init script aside (renamed to a name
    // only that code creates) while the package's postinst runs; a crash in
    // that window leaves the boot without the script. Runs under the lease
    // before any plan is decided, so the stop/start the plans perform find
    // the init script where they expect it. Returns a note for the operator
    // log, empty when there was nothing to heal.
    std::function<std::string()> heal_init_script;
    std::function<IpkSlotInspection()> inspect_current_ipk;
    std::function<ComponentCaptureState()> capture_state;
    // Empty when unknown; never throw.
    std::function<std::string()> installed_version;
    std::function<std::string()> installed_binary_sha256;
    // Runs restore_files / reinstall_previous / restore_files_inexact.
    std::function<NfqwsBootRecoveryStepResult(
        const ComponentBootRecoveryPlan&,
        const ComponentTransactionRecord&,
        std::string& output)>
        execute_restore;
    std::function<bool()> clear_journal;
    std::function<void()> discard_candidate;
    std::function<void(const NfqwsBootRecoveryResult&)> record_result;
};

#ifdef KEEN_PBR3_TESTING
NfqwsBootRecoveryResult run_nfqws_boot_recovery_for_testing(
    const NfqwsBootRecoveryHooks& hooks);

struct NfqwsApplyStrategyTestHooks {
    std::function<bool()> installed;
    std::function<std::vector<ConfigValidationIssue>(
        const std::string&, const std::string&)>
        validate;
    std::function<NfqwsStrategyAssetSync(const std::string&)> provision;
    std::function<NfqwsFileWriteResult(const std::string&)> write_active;
    std::function<std::string(int&)> restart;
};

struct NfqwsPostUpgradeFootprintAssessment {
    PackageFootprint footprint;
    PackageFootprintDiff diff;
    PackageBinaryOutcome binary_outcome{
        PackageBinaryOutcome::indeterminate};
    bool recovery_required{true};
    std::string error;
};

// Exercises the exact post-opkg boundary without running a package manager.
// Any exception or incomplete observation must become a recovery decision,
// never escape past the handler's captured-file restore branch.
NfqwsPostUpgradeFootprintAssessment
assess_nfqws_post_upgrade_footprint_for_testing(
    const PackageFootprint& before,
    std::function<PackageFootprint()> observe_after);

struct NfqwsBoundedOpkgTestResult {
    std::string output;
    int status{-1};
    bool timed_out{false};
    bool termination_uncertain{false};
    bool upgrade_started{false};
    bool up_to_date{false};
    bool previous_exact{false};
    std::string target_version;
    bool scripted{false};
    bool scripted_ok{false};
    bool init_restored{true};
};

// Runs the production package sequence (opkg update, feed index read, opkg
// download into the store's staging directory, verification, opkg install
// of the verified file) through an injected executor, against a store root
// and feed index the test owns. Tests can force a timeout without starting
// opkg or waiting for the production deadline, while still checking the
// fixed argv and timeout contract.
// `scripted` points the scripted-install paths (init script, its held
// name, the shell/tar that run the extraction and the scripts) into
// directories the test owns; the default is the production layout, whose
// init script does not exist on a build machine, so the hold step simply
// finds nothing to hold.
NfqwsBoundedOpkgTestResult run_nfqws_bounded_opkg_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts,
        const std::filesystem::path&)> execute,
    const std::string& installed_version,
    const std::string& store_root,
    const std::string& feed_list,
    const ScriptedInstallPaths& scripted = {},
    // The service stop the production upgrade hands in, run between the
    // package's preinst and the unpack.
    std::function<bool(std::string&)> stop_service = {});

struct NfqwsInstallTestResult {
    std::string output;
    int status{-1};
    bool timed_out{false};
    bool termination_uncertain{false};
    bool install_started{false};
    std::string target_version;
    bool feed_conf_written{false};
    bool scripted{false};
    bool scripted_ok{false};
    bool init_restored{true};
};

// Runs the production fresh-install sequence (feed definition, HTTPS
// prerequisites, feed refresh, verified download, opkg install of the
// verified file) through an injected executor against paths the test owns.
NfqwsInstallTestResult run_nfqws_install_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts,
        const std::filesystem::path&)> execute,
    const std::string& store_root,
    const std::string& feed_list,
    const std::string& feed_conf,
    // The prepared hook production uses to journal "mutating" before opkg
    // install may run; returning false must refuse the install.
    std::function<bool(const std::string& target_version)> on_prepared = {},
    const ScriptedInstallPaths& scripted = {});

// The exact-rollback step: reinstall the store's copy of `expected_version`
// and prove it through the injected version reader.
bool reinstall_exact_previous_nfqws_package_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts,
        const std::filesystem::path&)> execute,
    const std::string& expected_version,
    std::function<std::string()> read_installed_version,
    const std::string& store_root,
    std::string& output,
    const ScriptedInstallPaths& scripted = {});

struct NfqwsPostMutationGuardTestResult {
    bool operation_completed{false};
    bool component_broken{true};
    bool recovery_attempted{false};
    bool rolled_back{false};
    std::string operation_error;
    std::string recovery_error;
};

// Exercises the same exception boundary that surrounds opkg and every
// post-opkg observation/description/config/runtime step in production.
NfqwsPostMutationGuardTestResult guard_nfqws_post_mutation_for_testing(
    std::function<bool()> operation,
    std::function<bool()> recover,
    bool recovery_allowed = true);

bool should_clear_nfqws_upgrade_journal_for_testing(
    bool component_broken,
    bool package_mutation_started,
    bool rolled_back,
    bool termination_uncertain,
    bool exact_rollback_verified = false);

bool nfqws_package_metadata_verified_for_testing(
    bool transaction_present);

struct NfqwsCapturedRestoreFinalizationTestResult {
    bool ok{false};
    bool clear_journal{false};
    bool package_metadata_verified{false};
    std::string terminal_state;
};

NfqwsCapturedRestoreFinalizationTestResult
finalize_nfqws_captured_file_restore_for_testing(bool files_restored);

// Deterministic seam for the read/generation/read admission used by GET and
// check_update. `mutation_between_reads` models a journal write followed by a
// clear (none -> active -> none), which still must invalidate the optimistic
// response even though both filesystem snapshots look clean.
bool nfqws_optimistic_publish_survives_mutation_for_testing(
    bool mutation_between_reads);

void register_nfqws_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    NfqwsApplyStrategyTestHooks hooks);
#endif
}

#endif
