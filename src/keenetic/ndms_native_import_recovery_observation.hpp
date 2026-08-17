#pragma once

#include "ndms_native_import_wal.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// One marker sighting inside one bounded catalog read: an interface whose
// description carries the exact ownership marker of the transaction.
struct NdmsNativeImportRecoveryMarkerSighting {
    std::string interface_name;
    bool link_down{false};
    // The secret-independent config+ASC revision measured for this interface.
    std::string full_revision;
};

// One complete, bounded read of the live WireGuard catalog. The reader that
// fills this must set marker_scan_complete only when every slot of the
// measured Wireguard0..Wireguard126 namespace was actually inspected; a scan
// that gave up half way is a scan that can miss a second marker, and a missed
// second marker is how a rollback deletes the wrong interface.
struct NdmsNativeImportRecoveryCatalogProbe {
    std::uint64_t observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::string protected_catalog_sha256;
    bool marker_scan_complete{false};
    std::vector<NdmsNativeImportRecoveryMarkerSighting> marker_sightings;
};

// Builds the observation the recovery classifier consumes, from measurements
// and nothing else.
//
// This is the missing half named in the roadmap's writer blockers: the
// classifier exists and is fail-closed, but every caller had to assemble its
// observation by hand, and nothing could honestly set `authoritative`. The
// same lesson as build_system_auth_inputs earlier in this project: the
// judgement was never the defect, the inputs handed to it were, so the inputs
// get their own tested seam.
//
// Two probes, not one, and the later must carry a strictly greater catalog
// generation: absence observed once is a moment, absence observed twice
// across an advancing generation is a state. Any internal inconsistency, any
// disagreement between the probes, an incomplete scan, an epoch that does not
// match the baseline's - all of it degrades to a default observation whose
// `authoritative` is false, which the classifier answers with
// retry_read_only_observation. Degrading to a retry can stall recovery;
// guessing can delete an interface the operator owns. The builder never
// guesses.
NdmsNativeImportRecoveryObservation
build_ndms_native_import_recovery_observation(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryCatalogProbe& earlier,
    const NdmsNativeImportRecoveryCatalogProbe& later,
    const std::optional<std::string>& published_ownership_revision);

} // namespace keen_pbr3
