#include "runtime_cold_boot_publication.hpp"

#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

RuntimeColdBootPublicationCheckpoint
prepare_runtime_cold_boot_publication_checkpoint(
    const RuntimeResolverPublicationTarget& resolver,
    std::shared_ptr<const ResolverGenerationSnapshot> candidate_generation,
    RuntimeInternalVpnLkgStore& internal_vpn_lkg_store,
    const InternalVpnRuntimeResolution& internal_vpn_resolution,
    const InternalVpnServiceRuntimeResolution&
        internal_vpn_service_resolution) {
    if (!candidate_generation) {
        throw std::invalid_argument(
            "cold-boot resolver generation is unavailable");
    }

    RuntimeColdBootPublicationCheckpoint checkpoint;
    checkpoint.resolver_generation = std::move(candidate_generation);
    checkpoint.previous_resolver_sync = resolver.sync.checkpoint();
    checkpoint.previous_resolver_retry_attempt = resolver.retry_attempt;
    checkpoint.previous_apply_started_ts =
        resolver.apply_started_ts.load(std::memory_order_acquire);

    ResolverSyncStateMachine candidate_sync;
    candidate_sync.restore(checkpoint.previous_resolver_sync);
    candidate_sync.expected_hash_updated(
        checkpoint.resolver_generation->expected_hash);
    if (checkpoint.previous_apply_started_ts > 0) {
        candidate_sync.apply_started(
            checkpoint.previous_apply_started_ts,
            checkpoint.resolver_generation->expected_hash);
    }
    checkpoint.candidate_resolver_sync = candidate_sync.checkpoint();

    checkpoint.internal_vpn_lkg =
        internal_vpn_lkg_store.prepare_publication(
            internal_vpn_resolution,
            internal_vpn_service_resolution);
    return checkpoint;
}

} // namespace keen_pbr3
