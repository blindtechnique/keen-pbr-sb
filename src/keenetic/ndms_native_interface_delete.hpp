#pragma once

#include "ndms_native_import_recovery_dispatch.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// The one production step that actually removes an interface from the router.
// Until now the recovery dispatcher took this as an injected std::function and
// every hardware run supplied a fake, so the rollback the WAL machinery exists
// to drive had no implementation at all.
//
// Both effects are injected so the whole decision is testable without a
// router: reading is a bounded RCI GET, mutating is one command. Production
// code deliberately has no factory for this capability; this primitive and
// the operator-level wrapper are linked only into tests until the durable
// panel-delete coordinator is proven safe.
struct NdmsNativeInterfaceDeleteDependencies final {
    // Returns the parsed document for an RCI path, or nullopt when the read
    // itself failed. An interface that does not exist is NOT a failure: the
    // firmware answers with a zero-byte body, which arrives here as a
    // null json - and absence is exactly what this operation wants to prove.
    std::function<std::optional<nlohmann::json>(const std::string& rci_path)>
        read_document;
    // Runs one ndmc command. True only when ndmc reported success; a command
    // whose result is unknown must report false, because "probably deleted"
    // is the one answer this operation may never give.
    std::function<bool(const std::string& ndmc_command)> run_command;
};

// Deletes exactly the interface the WAL admitted, and only while it still
// carries this transaction's marker.
//
// The ordering is the point. Ownership is re-checked against a fresh read
// immediately before the mutation, not inherited from the observation that
// authorized the plan: between that observation and this call the world may
// have moved, and an interface that stopped being ours is one we must never
// remove. Afterwards absence is proven by another read - `deleted_confirmed`
// is what advances the WAL to a phase that asserts absence, so it may not be
// returned on the strength of ndmc's exit code alone.
//
// An interface that is already gone confirms: the postcondition holds, and
// refusing there would strand a rollback that has nothing left to do.
NdmsNativeImportRecoveryDeleteOutcome delete_exact_owned_ndms_interface(
    const std::string& interface_name,
    const std::string& marker,
    const NdmsNativeInterfaceDeleteDependencies& dependencies);

// The exact command this operation issues. Exposed so a test can pin the
// spelling - a delete that names the wrong interface is unrecoverable, and
// the string is the whole of what the router is told.
std::string ndms_native_interface_delete_command(
    const std::string& interface_name);

} // namespace keen_pbr3
