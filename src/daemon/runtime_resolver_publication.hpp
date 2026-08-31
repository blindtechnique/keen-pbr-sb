#pragma once

#include "resolver_sync_state_machine.hpp"
#include "runtime_resolver_generation_snapshot.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

namespace keen_pbr3 {

enum class RuntimeResolverGenerationPublication : std::uint8_t {
    retain_source,
    exchange_preimage,
};

struct RuntimeResolverPublicationTarget final {
    std::shared_ptr<const ResolverGenerationSnapshot>& generation;
    ResolverSyncStateMachine& sync;
    std::uint32_t& retry_attempt;
    std::atomic<std::int64_t>& apply_started_ts;
};

struct RuntimeResolverPublicationSource final {
    std::shared_ptr<const ResolverGenerationSnapshot>& generation;
    ResolverSyncCheckpoint& sync;
    std::uint32_t retry_attempt{0U};
    std::int64_t apply_started_ts{0};
};

// Publishes the controller-side resolver tuple after the caller's existing
// generation/CAS fence has admitted it. Stream admission and retry policy stay
// with their current owners; this checkpoint only prevents the four cursor
// fields from drifting between DNS and config publication paths.
void publish_runtime_resolver_checkpoint(
    RuntimeResolverPublicationTarget target,
    RuntimeResolverPublicationSource source,
    RuntimeResolverGenerationPublication generation_publication) noexcept;

} // namespace keen_pbr3
