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

// One complete, bounded direct read of the live WireGuard catalog, paired with
// the restart-stable stamp durably issued for those exact measured bytes.
// Process-local cache generation/epoch counters deliberately do not cross this
// seam: they restart at zero and cannot prove post-crash ordering.
struct NdmsNativeImportRecoveryCatalogProbe {
    NdmsNativeObservationStamp durable_observation;
    // Independently derived from the catalog and direct per-target evidence.
    // It must equal durable_observation.catalog_revision, preventing a stamp
    // from one read from being attached to another read's payload.
    std::string measured_catalog_revision;
    std::string protected_catalog_sha256;
    // True only when every Wireguard0..Wireguard126 slot was safe and the
    // direct evidence for every marker sighting was present and unambiguous.
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
// Two probes, not one. Both durable sequences must be strictly newer than the
// WAL baseline, carry the WAL's exact authority+mutation epoch, and the later
// sequence must be strictly newer than the earlier one. Absence observed once
// is a moment; absence observed twice across advancing durable observations is
// a state. Any internal inconsistency, disagreement, incomplete scan, mixed
// authority/epoch or reused/stale sequence degrades to a default observation
// whose `authoritative` is false, which the classifier answers with
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
