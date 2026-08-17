#include "rollback_availability.hpp"

#include "rescue_integrity.hpp"

#include <system_error>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

bool marker_present(const std::filesystem::path& path) {
    std::error_code error;
    const bool exists = std::filesystem::exists(path, error);
    // An unreadable rescue directory must never read as "no recovery needed".
    return exists || static_cast<bool>(error);
}

bool executable_nonempty_file(const std::filesystem::path& path) {
    return rescue_integrity::regular_nonempty_file(path) &&
           ::access(path.c_str(), X_OK) == 0;
}

bool directory_present(const std::filesystem::path& path) {
    std::error_code error;
    const bool exists = std::filesystem::exists(path, error);
    return exists && !error;
}

} // namespace

PackageRollbackState classify_package_rollback(
    const PackageRollbackObservations& observations) {
    if (observations.recovery_unknown)
        return PackageRollbackState::recovery_unknown;
    if (observations.recovery_pending)
        return PackageRollbackState::recovery_pending;
    if (!observations.helper_usable)
        return PackageRollbackState::helper_missing;
    // Neither half of the pair exists: nothing was ever captured. Only when
    // something is there does an absence become evidence of damage.
    if (!observations.previous_package_present &&
        !observations.previous_config_present) {
        return PackageRollbackState::never_captured;
    }
    if (!observations.previous_package_verified)
        return PackageRollbackState::package_unverified;
    if (!observations.previous_config_verified)
        return PackageRollbackState::snapshot_unverified;
    return PackageRollbackState::available;
}

bool package_rollback_is_available(PackageRollbackState state) noexcept {
    return state == PackageRollbackState::available;
}

const char* package_rollback_state_name(PackageRollbackState state) noexcept {
    switch (state) {
        case PackageRollbackState::available:
            return "available";
        case PackageRollbackState::recovery_pending:
            return "recovery_pending";
        case PackageRollbackState::recovery_unknown:
            return "recovery_unknown";
        case PackageRollbackState::helper_missing:
            return "helper_missing";
        case PackageRollbackState::never_captured:
            return "never_captured";
        case PackageRollbackState::package_unverified:
            return "package_unverified";
        case PackageRollbackState::snapshot_unverified:
            return "snapshot_unverified";
    }
    return "recovery_unknown";
}

const char* package_rollback_state_message(
    PackageRollbackState state) noexcept {
    switch (state) {
        case PackageRollbackState::available:
            return "a verified previous package is available";
        case PackageRollbackState::recovery_pending:
            return "package recovery is pending; finish recovery before "
                   "starting a rollback";
        case PackageRollbackState::recovery_unknown:
            return "the rescue store reports an unknown state; run rescue "
                   "recovery before starting a rollback";
        case PackageRollbackState::helper_missing:
            return "the rescue helper is not installed";
        case PackageRollbackState::never_captured:
            return "no previous package was ever captured; only an update "
                   "started from this panel records one, so an installation "
                   "made with opkg leaves nothing to roll back to";
        case PackageRollbackState::package_unverified:
            return "the recorded previous package does not match its checksum";
        case PackageRollbackState::snapshot_unverified:
            return "the previous configuration snapshot is incomplete or "
                   "corrupted";
    }
    return "the rescue store reports an unknown state";
}

PackageRollbackObservations observe_package_rollback(
    const RescueStoreLayout& layout) {
    PackageRollbackObservations observations;
    observations.recovery_pending = marker_present(layout.pending_marker);
    observations.recovery_unknown = marker_present(layout.unknown_marker);
    observations.helper_usable = executable_nonempty_file(layout.helper);
    observations.previous_package_present =
        rescue_integrity::regular_nonempty_file(layout.previous_package);
    observations.previous_package_verified =
        observations.previous_package_present &&
        rescue_integrity::verified_ipk_file(layout.previous_package);
    observations.previous_config_present =
        directory_present(layout.previous_config);
    observations.previous_config_verified =
        observations.previous_config_present &&
        rescue_integrity::verified_snapshot(layout.previous_config);
    return observations;
}

} // namespace keen_pbr3
