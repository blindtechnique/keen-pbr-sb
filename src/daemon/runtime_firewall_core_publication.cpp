#include "runtime_firewall_core_publication.hpp"

#include <type_traits>
#include <utility>

namespace keen_pbr3 {

void publish_runtime_firewall_core(
    RuntimeFirewallCorePublicationTarget target,
    RuntimeFirewallCorePublication& publication,
    RuntimeFirewallCoreMetaPublication meta_publication) noexcept {
    static_assert(
        std::is_nothrow_swappable_v<std::optional<std::uint32_t>>,
        "the committed Meta cursor must exchange without throwing");
    static_assert(
        std::is_nothrow_copy_assignable_v<std::optional<std::uint32_t>>,
        "the committed Meta cursor must publish without throwing");

    target.firewall_state.swap_rules(publication.rules);
    target.list_content_state.static_destinations.swap(
        publication.list_content_state.static_destinations);
    target.list_content_state.domain_entry_lists.swap(
        publication.list_content_state.domain_entry_lists);
    target.list_content_state.truncated_static_destination_lists.swap(
        publication.list_content_state.truncated_static_destination_lists);
    target.list_usage.swap(publication.list_usage);
    target.list_fingerprints.swap(publication.list_fingerprints);
    target.internal_vpn_resolution_cache.exchange_active(
        publication.internal_vpn_servers,
        publication.internal_vpn_service_targets);
    target.native_vpn_direct_egress_snat_selectors.swap(
        publication.native_vpn_direct_egress_snat_selectors);

    if (meta_publication ==
        RuntimeFirewallCoreMetaPublication::exchange_preimage) {
        target.committed_meta_fwmark.swap(
            publication.committed_meta_fwmark);
        using std::swap;
        swap(
            target.committed_meta_owned_mask,
            publication.committed_meta_owned_mask);
    } else {
        target.committed_meta_fwmark = publication.committed_meta_fwmark;
        target.committed_meta_owned_mask =
            publication.committed_meta_owned_mask;
    }
}

} // namespace keen_pbr3
