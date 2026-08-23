#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#ifdef KEEN_PBR3_TESTING
#include "../update/package_footprint.hpp"
#include "../util/nfqws_file_writer.hpp"
#include "../util/safe_exec.hpp"
#include "../util/nfqws_strategy_assets.hpp"

#include <chrono>
#include <functional>
#include <string>
#include <vector>
#endif

namespace keen_pbr3 {
void register_nfqws_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
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
};

// Runs the production package sequence (opkg update, feed index read, opkg
// download into the store's staging directory, verification, opkg install
// of the verified file) through an injected executor, against a store root
// and feed index the test owns. Tests can force a timeout without starting
// opkg or waiting for the production deadline, while still checking the
// fixed argv and timeout contract.
NfqwsBoundedOpkgTestResult run_nfqws_bounded_opkg_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts)> execute,
    const std::string& installed_version,
    const std::string& store_root,
    const std::string& feed_list);

// The exact-rollback step: reinstall the store's copy of `expected_version`
// and prove it through the injected version reader.
bool reinstall_exact_previous_nfqws_package_for_testing(
    std::function<ExecCaptureResult(
        const std::vector<std::string>&, SafeExecTimeouts)> execute,
    const std::string& expected_version,
    std::function<std::string()> read_installed_version,
    const std::string& store_root,
    std::string& output);

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
