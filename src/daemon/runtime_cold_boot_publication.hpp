#pragma once

#include "runtime_firewall_core_publication.hpp"
#include "runtime_firewall_publication_tail_progress.hpp"
#include "runtime_internal_vpn_lkg_store.hpp"
#include "runtime_resolver_publication.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace keen_pbr3 {

// Fallibly prepared values for the existing cold-boot publication fence.
// This is not an admission object or a recovery journal: the lifecycle owner
// still decides whether the exact generation may enter the runner below.
struct RuntimeColdBootPublicationCheckpoint final {
    RuntimeInternalVpnLkgPublication internal_vpn_lkg;
    std::shared_ptr<const ResolverGenerationSnapshot> resolver_generation;
    ResolverSyncCheckpoint candidate_resolver_sync;
    ResolverSyncCheckpoint previous_resolver_sync;
    std::uint32_t previous_resolver_retry_attempt{0U};
    std::int64_t previous_apply_started_ts{0};
};

struct RuntimeColdBootPublicationTarget final {
    RuntimeFirewallCorePublicationTarget core;
    RuntimeFirewallCorePublication& core_publication;
    RuntimeResolverPublicationTarget resolver;
    RuntimeInternalVpnLkgStore& internal_vpn_lkg_store;
    RuntimeFirewallPublicationTailProgress& progress;
};

// Captures the exact resolver preimage, derives the candidate resolver sync
// checkpoint and prepares the reversible native-VPN LKG pair. All allocation
// and LKG merge work therefore remains outside the existing no-throw
// generation/publication fence.
RuntimeColdBootPublicationCheckpoint
prepare_runtime_cold_boot_publication_checkpoint(
    const RuntimeResolverPublicationTarget& resolver,
    std::shared_ptr<const ResolverGenerationSnapshot> candidate_generation,
    RuntimeInternalVpnLkgStore& internal_vpn_lkg_store,
    const InternalVpnRuntimeResolution& internal_vpn_resolution,
    const InternalVpnServiceRuntimeResolution&
        internal_vpn_service_resolution);

namespace detail {

// Allocation-free ordering seam shared by production and focused tests.
// Rollback mirrors the old Daemon catch block: retire running state first,
// then restore resolver, LKG and core, and finally republish the restored
// runtime cursor. Every rollback step is best effort and cannot suppress a
// later restore step.
template <
    typename PublishCore,
    typename RestoreCore,
    typename PublishLkg,
    typename RestoreLkg,
    typename PublishResolver,
    typename RestoreResolver,
    typename ActivateRuntime,
    typename RollbackRuntime,
    typename PublishRuntimeState>
bool run_runtime_cold_boot_publication_steps(
    PublishCore&& publish_core,
    RestoreCore&& restore_core,
    PublishLkg&& publish_lkg,
    RestoreLkg&& restore_lkg,
    PublishResolver&& publish_resolver,
    RestoreResolver&& restore_resolver,
    ActivateRuntime&& activate_runtime,
    RollbackRuntime&& rollback_runtime,
    PublishRuntimeState&& publish_runtime_state) noexcept {
    bool core_published = false;
    bool lkg_published = false;
    bool resolver_published = false;

    try {
        std::invoke(publish_core);
        core_published = true;
        std::invoke(publish_lkg);
        lkg_published = true;
        std::invoke(publish_resolver);
        resolver_published = true;
        std::invoke(activate_runtime);
        std::invoke(publish_runtime_state);
        return true;
    } catch (...) {
        try {
            std::invoke(rollback_runtime);
        } catch (...) {
        }
        if (resolver_published) {
            try {
                std::invoke(restore_resolver);
            } catch (...) {
            }
        }
        if (lkg_published) {
            try {
                std::invoke(restore_lkg);
            } catch (...) {
            }
        }
        if (core_published) {
            try {
                std::invoke(restore_core);
            } catch (...) {
            }
        }
        try {
            std::invoke(publish_runtime_state);
        } catch (...) {
        }
        return false;
    }
}

} // namespace detail

// Publishes one already admitted cold-boot checkpoint. Runtime-state mutation
// stays in three thin caller callbacks so this component does not acquire a
// second Daemon, scheduler, admission or retry dependency.
template <
    typename ActivateRuntime,
    typename RollbackRuntime,
    typename PublishRuntimeState>
bool publish_runtime_cold_boot_checkpoint(
    RuntimeColdBootPublicationTarget target,
    RuntimeColdBootPublicationCheckpoint& checkpoint,
    ActivateRuntime&& activate_runtime,
    RollbackRuntime&& rollback_runtime,
    PublishRuntimeState&& publish_runtime_state) noexcept {
    const bool committed = detail::run_runtime_cold_boot_publication_steps(
        [&target]() noexcept {
            if (target.progress.core_published() ||
                !target.core_publication.committed) {
                return;
            }
            publish_runtime_firewall_core(
                target.core,
                target.core_publication,
                RuntimeFirewallCoreMetaPublication::exchange_preimage);
            target.progress.mark_core_published();
        },
        [&target]() noexcept {
            if (!target.progress.core_published() ||
                !target.core_publication.committed) {
                return;
            }
            publish_runtime_firewall_core(
                target.core,
                target.core_publication,
                RuntimeFirewallCoreMetaPublication::exchange_preimage);
            target.progress.mark_core_restored();
        },
        [&target, &checkpoint]() {
            target.internal_vpn_lkg_store.exchange(
                checkpoint.internal_vpn_lkg);
            target.progress.mark_internal_vpn_lkg_published();
        },
        [&target, &checkpoint]() {
            target.internal_vpn_lkg_store.exchange(
                checkpoint.internal_vpn_lkg);
            target.progress.mark_internal_vpn_lkg_restored();
        },
        [&target, &checkpoint]() noexcept {
            publish_runtime_resolver_checkpoint(
                target.resolver,
                RuntimeResolverPublicationSource{
                    checkpoint.resolver_generation,
                    checkpoint.candidate_resolver_sync,
                    0U,
                    checkpoint.previous_apply_started_ts},
                RuntimeResolverGenerationPublication::exchange_preimage);
        },
        [&target, &checkpoint]() noexcept {
            publish_runtime_resolver_checkpoint(
                target.resolver,
                RuntimeResolverPublicationSource{
                    checkpoint.resolver_generation,
                    checkpoint.previous_resolver_sync,
                    checkpoint.previous_resolver_retry_attempt,
                    checkpoint.previous_apply_started_ts},
                RuntimeResolverGenerationPublication::exchange_preimage);
        },
        [&activate_runtime]() {
            std::invoke(activate_runtime);
        },
        [&target, &rollback_runtime]() {
            std::invoke(rollback_runtime);
            target.progress.set_start_finalized(false);
        },
        [&publish_runtime_state]() {
            std::invoke(publish_runtime_state);
        });
    if (committed) {
        // The externally visible runtime cursor is part of the transaction.
        // Do not claim finalization until its publication has returned.
        target.progress.set_start_finalized(true);
    }
    return committed;
}

} // namespace keen_pbr3
