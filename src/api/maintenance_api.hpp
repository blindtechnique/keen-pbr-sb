#pragma once

#ifdef WITH_API

#include "../update/maintenance_lock.hpp"
#include "server.hpp"

namespace keen_pbr3 {

[[noreturn]] inline void throw_maintenance_api_error(
    const MaintenanceLockError& error) {
    switch (error.kind()) {
    case MaintenanceLockErrorKind::busy:
    case MaintenanceLockErrorKind::stale_generation:
        throw ApiError(error.what(), 409);
    case MaintenanceLockErrorKind::protocol_mismatch:
    case MaintenanceLockErrorKind::unsafe_state:
    case MaintenanceLockErrorKind::guardian_died:
        throw ApiError(error.what(), 503);
    case MaintenanceLockErrorKind::helper_execution:
    case MaintenanceLockErrorKind::timeout:
    case MaintenanceLockErrorKind::malformed_response:
    case MaintenanceLockErrorKind::system_error:
        throw ApiError(error.what(), 500);
    }
    throw ApiError(error.what(), 500);
}

} // namespace keen_pbr3

#endif // WITH_API
