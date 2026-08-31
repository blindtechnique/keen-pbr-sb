#include "runtime_internal_vpn_lkg_store.hpp"

#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_service_resolver.hpp"

#include <utility>

namespace keen_pbr3 {
namespace {

bool can_publish_lkg(InternalVpnRuntimeResolutionState state) noexcept {
    return state == InternalVpnRuntimeResolutionState::verified ||
        state ==
            InternalVpnRuntimeResolutionState::authoritative_negative;
}

void merge_servers(
    std::vector<InternalVpnServer>& current,
    const InternalVpnRuntimeResolution& resolution) {
    if (!can_publish_lkg(resolution.state)) return;
    current = merge_internal_vpn_verified_includes_lkg(
        current,
        resolution.verified_includes_for_lkg,
        resolution.retain_verified_include_ndms_ids);
}

void merge_service_targets(
    std::vector<InternalVpnRuntimeTarget>& current,
    const InternalVpnServiceRuntimeResolution& resolution) {
    if (!can_publish_lkg(resolution.state)) return;
    current = merge_internal_vpn_service_verified_includes_lkg(
        current,
        resolution.verified_includes_for_lkg,
        resolution.retain_verified_include_service_ids);
}

} // namespace

std::vector<InternalVpnServer>
RuntimeInternalVpnLkgStore::snapshot_servers() const {
    KPBR_LOCK_GUARD(mutex_);
    return servers_;
}

std::vector<InternalVpnRuntimeTarget>
RuntimeInternalVpnLkgStore::snapshot_service_targets() const {
    KPBR_LOCK_GUARD(mutex_);
    return service_targets_;
}

void RuntimeInternalVpnLkgStore::update_servers(
    const InternalVpnRuntimeResolution& resolution) {
    if (!can_publish_lkg(resolution.state)) return;
    KPBR_LOCK_GUARD(mutex_);
    merge_servers(servers_, resolution);
}

void RuntimeInternalVpnLkgStore::update_service_targets(
    const InternalVpnServiceRuntimeResolution& resolution) {
    if (!can_publish_lkg(resolution.state)) return;
    KPBR_LOCK_GUARD(mutex_);
    merge_service_targets(service_targets_, resolution);
}

RuntimeInternalVpnLkgPublication
RuntimeInternalVpnLkgStore::prepare_publication(
    const InternalVpnRuntimeResolution& server_resolution,
    const InternalVpnServiceRuntimeResolution& service_resolution) const {
    KPBR_LOCK_GUARD(mutex_);
    RuntimeInternalVpnLkgPublication publication{
        servers_,
        service_targets_,
    };
    merge_servers(publication.servers, server_resolution);
    merge_service_targets(
        publication.service_targets, service_resolution);
    return publication;
}

void RuntimeInternalVpnLkgStore::exchange(
    RuntimeInternalVpnLkgPublication& publication) {
    KPBR_LOCK_GUARD(mutex_);
    servers_.swap(publication.servers);
    service_targets_.swap(publication.service_targets);
}

} // namespace keen_pbr3
