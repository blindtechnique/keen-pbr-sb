#pragma once

#include "../backup/recovery_coordinator.hpp"
#include "../update/maintenance_lock.hpp"

#include <functional>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class RecoverPersistentStateExitCode : int {
    success = 0,
    blocked = 20,
    retryable = 21,
};

using RecoveryMaintenanceLeaseFactory =
    std::function<std::unique_ptr<MaintenanceLease>(
        const std::string& operation)>;
using RecoveryRuntimeActiveProbe =
    std::function<bool(backup::RecoveryOperation operation)>;

struct RecoverPersistentStateOptions {
    backup::RecoveryCoordinatorLayout layout;
    RecoveryMaintenanceLeaseFactory lease_factory;
    RecoveryRuntimeActiveProbe runtime_active_probe;
};

// Runs the offline persistent recovery command without reading or parsing the
// working keen-pbr configuration. The supplied layout and lease factory make
// the complete command contract testable without touching /opt.
int run_recover_persistent_state(
    const RecoverPersistentStateOptions& options,
    std::ostream& output);

// Production entry point used by main(). The default layout is derived from
// the compiled-in configuration prefix (/opt for Keenetic, / otherwise).
int run_recover_persistent_state_command();

#ifdef KEEN_PBR3_TESTING
// A config-save journal may include transports.json. Recovery intentionally
// uses the conservative full managed-stack boundary because the lightweight
// preflight does not parse the journal effects before checking /proc.
std::vector<std::string>
recovery_managed_process_names_for_testing(
    backup::RecoveryOperation operation);
#endif

} // namespace keen_pbr3
