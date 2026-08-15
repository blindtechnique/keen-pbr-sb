#pragma once

#include "ndms_catalog_cache.hpp"
#include "ndms_native_import_recovery_observation.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Per-target evidence from the measured direct-JSON reads - link state and
// the secret-independent full revision. The catalog snapshot cannot supply
// these; they come from the same read plan the preflight already names, and
// arrive here as data so this builder stays pure.
struct NdmsNativeImportRecoveryTargetEvidence {
    std::string interface_name;
    bool link_down{false};
    std::string full_revision;
};

// Builds one typed catalog probe from one catalog snapshot plus the direct
// per-target reads. The last unwired seam of the recovery chain: everything
// downstream - observation, classification, lease, plan, dispatch - consumes
// typed probes, and until now nothing produced one from the structures the
// firmware readers actually return.
//
// Fail-closed through marker_scan_complete: a snapshot that is not fresh, a
// firmware that was not available, any unsafe catalog slot, or a sighted
// marker with no matching per-target evidence all mark the scan incomplete.
// An incomplete scan can hide a second marker, and a hidden second marker is
// how a rollback deletes the wrong interface - so the observation builder
// downstream refuses authority for it, which is the point.
NdmsNativeImportRecoveryCatalogProbe
build_ndms_native_import_recovery_probe(
    const NdmsCatalogSnapshot& snapshot,
    std::uint8_t expected_target_slot,
    const std::string& marker,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>&
        target_evidence);

} // namespace keen_pbr3
