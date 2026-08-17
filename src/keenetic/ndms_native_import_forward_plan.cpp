#include "ndms_native_import_forward_plan.hpp"

namespace keen_pbr3 {

namespace {

using Step = NdmsNativeImportRecoveryStep;
using Phase = NdmsNativeImportWalPhase;

constexpr std::string_view kTargetRevisionPrefix{"ndms-rci-full-v1-"};

bool measured_revision_valid(const std::string& value) {
    if (value.size() != kTargetRevisionPrefix.size() + 64U ||
        value.compare(0U, kTargetRevisionPrefix.size(),
                      kTargetRevisionPrefix) != 0) {
        return false;
    }
    for (std::size_t index = kTargetRevisionPrefix.size();
         index < value.size(); ++index) {
        const char ch = value[index];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

} // namespace

NdmsNativeImportForwardCompletion
plan_ndms_native_import_forward_completion(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryObservation& observation,
    const std::string& measured_target_revision) {
    NdmsNativeImportForwardCompletion completion;
    completion.enriched = record;

    if (record.phase != Phase::response_recorded &&
        record.phase != Phase::target_verified) {
        return completion;
    }
    // The world must be at rest and measured: an unauthoritative observation
    // finishes nothing, and a drifted protected catalog or a generation that
    // never advanced past the baseline is a world still moving.
    if (!observation.authoritative || !observation.generation_advanced ||
        !observation.protected_catalog_unchanged) {
        return completion;
    }
    if (observation.marker_match_count != 1U ||
        !observation.marker_target.has_value() ||
        !observation.target_absent_in_baseline) {
        return completion;
    }
    // The stock importer creates the interface disabled. One that is up was
    // enabled by somebody, and an interface somebody already uses is not ours
    // to finish quietly - or to roll back, which is why this mirrors the
    // classifier's exact-owned gate instead of relaxing it.
    if (!observation.target_down) {
        return completion;
    }
    const auto& sighting = *observation.marker_target;
    if (sighting != record.baseline.expected_created_interface) {
        return completion;
    }
    if (record.created_interface.has_value() &&
        *record.created_interface != sighting) {
        return completion;
    }
    // target_fingerprint_matches is only meaningful against recorded
    // evidence. At response_recorded nothing is recorded yet and the
    // measurement is adopted; at target_verified the measurement must match
    // what verification recorded, or the interface changed since and gets
    // re-verified rather than trusted.
    if (record.phase == Phase::target_verified &&
        !observation.target_fingerprint_matches) {
        return completion;
    }

    // The measurement becomes the durable record, so it is held to the exact
    // canonical shape before anything durable is planned around it - and when
    // the record already carries a revision, the measurement must reproduce
    // it byte for byte.
    if (!measured_revision_valid(measured_target_revision)) {
        return completion;
    }
    if (record.target_full_revision.has_value() &&
        *record.target_full_revision != measured_target_revision) {
        return completion;
    }

    completion.enriched.created_interface = sighting;
    completion.enriched.target_full_revision = measured_target_revision;
    if (record.phase == Phase::response_recorded) {
        completion.plan.steps = {Step::advance_wal_target_verified,
                                 Step::publish_ownership,
                                 Step::advance_wal_ownership_published,
                                 Step::remove_wal_record};
    } else {
        completion.plan.steps = {Step::publish_ownership,
                                 Step::advance_wal_ownership_published,
                                 Step::remove_wal_record};
    }
    return completion;
}

} // namespace keen_pbr3
