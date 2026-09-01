#pragma once

#include "../config/config.hpp"
#include "../firewall/firewall.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "conntrack_cleanup_coordinator.hpp"
#include "internal_vpn_resolution_cache.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Complete controller-side image paired with one verified firewall COMMIT.
// The operation owner and its lifecycle-specific generation fence decide when
// this image may be published; this type only keeps the committed tuple
// together so every path publishes the same fields.
struct RuntimeFirewallCorePublication final {
    bool prepared{false};
    bool committed{false};
    std::vector<RuleState> rules;
    AppliedListContentState list_content_state;
    std::map<std::string, ListSetUsage> list_usage;
    std::map<std::string, std::string> list_fingerprints;
    std::vector<InternalVpnServer> internal_vpn_servers;
    std::vector<InternalVpnRuntimeTarget> internal_vpn_service_targets;
    std::vector<FirewallSourceEgressSnatSelector>
        native_vpn_direct_egress_snat_selectors;
    std::optional<std::uint32_t> committed_meta_fwmark;
    std::uint32_t committed_meta_owned_mask{0U};
};

// Transactional START/background publication keeps the old Meta cursor in the
// same object for an exact restore. Config, DNS and URLTEST transactions have a
// separately prepared rollback publication, so their candidate Meta cursor is
// intentionally retained instead.
enum class RuntimeFirewallCoreMetaPublication : std::uint8_t {
    retain_candidate,
    exchange_preimage,
};

struct RuntimeFirewallCorePublicationTarget final {
    FirewallState& firewall_state;
    AppliedListContentState& list_content_state;
    std::map<std::string, ListSetUsage>& list_usage;
    std::map<std::string, std::string>& list_fingerprints;
    InternalVpnResolutionCache& internal_vpn_resolution_cache;
    ConntrackCleanupCoordinator& conntrack_cleanup_coordinator;
    std::optional<std::uint32_t>& committed_meta_fwmark;
    std::uint32_t& committed_meta_owned_mask;
};

// Allocation-free controller checkpoint. The caller must already hold the
// existing control-loop/generation publication authority. Native-VPN state is
// exchanged as one exact pair through its sole owner.
void publish_runtime_firewall_core(
    RuntimeFirewallCorePublicationTarget target,
    RuntimeFirewallCorePublication& publication,
    RuntimeFirewallCoreMetaPublication meta_publication) noexcept;

} // namespace keen_pbr3
