#pragma once

#include "port_spec_util.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace keen_pbr3 {

class ListEntryVisitor;
enum class L4Proto : uint8_t {
    Any,
    Tcp,
    Udp,
    TcpUdp,
};

inline const char* l4_proto_name(L4Proto proto) {
    switch (proto) {
    case L4Proto::Any:
        return "";
    case L4Proto::Tcp:
        return "tcp";
    case L4Proto::Udp:
        return "udp";
    case L4Proto::TcpUdp:
        return "tcp/udp";
    }
    return "";
}

// Match criteria for firewall mark/drop/pass rules.
// All fields default to empty meaning "any".
struct FirewallRuleCriteria {
    std::optional<std::string> dst_set_name; // named destination set matcher, if any
    std::optional<uint8_t> dscp;        // DSCP tag selector, empty = any
    L4Proto proto = L4Proto::Any;
    PortSpec src_port;                 // parsed source port selector
    PortSpec dst_port;                 // parsed destination port selector
    std::vector<std::string> src_addr; // CIDR list, empty = any source address
    std::vector<std::string> dst_addr; // CIDR list, empty = any destination address
    bool negate_src_port = false;      // if true, match packets NOT from src_port
    bool negate_dst_port = false;      // if true, match packets NOT to dst_port
    bool negate_src_addr = false;      // if true, match packets NOT from src_addr
    bool negate_dst_addr = false;      // if true, match packets NOT to dst_addr
    bool empty() const {
        return !dst_set_name.has_value() && !dscp.has_value()
            && proto == L4Proto::Any
            && src_port.empty() && dst_port.empty()
            && src_addr.empty() && dst_addr.empty();
    }

    bool has_rule_selector() const {
        return dst_set_name.has_value() || dscp.has_value()
            || !src_port.empty() || !dst_port.empty()
            || !src_addr.empty() || !dst_addr.empty();
    }
};

using ProtoPortFilter = FirewallRuleCriteria;

struct FirewallIngressSourceSelector {
    std::string interface;
    std::string cidr;
};

struct FirewallGlobalPrefilter {
    std::optional<std::vector<std::string>> inbound_interfaces;
    // Explicit ingress interfaces that must bypass keen-pbr before conntrack
    // mark restoration, route classification, and client DNS redirection.
    std::vector<std::string> bypass_inbound_interfaces;
    // Service-based NDMS VPN servers have stable client pools. Inclusion may
    // use a verified pool directly; bypass is stricter and is always scoped to
    // the exact ingress interface verified in the current Netlink inventory.
    std::vector<std::string> include_source_cidrs_v4;
    std::vector<std::string> include_source_cidrs_v6;
    std::vector<FirewallIngressSourceSelector>
        bypass_source_selectors_v4;
    std::vector<FirewallIngressSourceSelector>
        bypass_source_selectors_v6;
    bool skip_established_or_dnat{false};
    bool skip_marked_packets{false};
    // Restore only the keen-pbr-owned portion of the conntrack mark before
    // classifying a packet. RAW PREROUTING deliberately disables this because
    // it runs before conntrack; mangle PREROUTING/OUTPUT and IPv6 can use it.
    bool restore_conntrack_mark{false};
    uint32_t conntrack_mark_mask{0};

    bool has_inbound_interfaces() const {
        return inbound_interfaces.has_value() && !inbound_interfaces->empty();
    }

    bool has_bypass_inbound_interfaces() const {
        return !bypass_inbound_interfaces.empty();
    }

    bool has_include_source_cidrs() const {
        return !include_source_cidrs_v4.empty() ||
               !include_source_cidrs_v6.empty();
    }

    bool has_bypass_source_cidrs() const {
        return !bypass_source_selectors_v4.empty() ||
               !bypass_source_selectors_v6.empty();
    }

    bool empty() const {
        return !skip_established_or_dnat && !skip_marked_packets
            && !restore_conntrack_mark && !has_inbound_interfaces()
            && !has_bypass_inbound_interfaces()
            && !has_include_source_cidrs()
            && !has_bypass_source_cidrs();
    }
};

// Marks packets the router itself emitted into a detour tunnel. The kernel
// picks a source address during the first route lookup, before mangle OUTPUT
// runs, so a marked packet would leave the tunnel carrying the WAN address and
// never get an answer back. Backends masquerade packets carrying this bit so
// the source becomes the tunnel address. The bit lives outside the configurable
// fwmark mask, which keeps the policy rules matching as before.
inline constexpr uint32_t kRouterOriginMark = 0x01000000u;

class FirewallError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The transaction itself is valid, but KeeneticOS changed the shared kernel
// firewall state concurrently. Callers may retry this error with backoff;
// ordinary FirewallError remains a permanent/configuration failure.
class TransientFirewallError : public FirewallError {
public:
    using FirewallError::FirewallError;
};

// Concrete firewall backend selected for runtime use.
enum class FirewallBackend : uint8_t {
    iptables,
    nftables
};

// User-facing backend preference from config.
enum class FirewallBackendPreference : uint8_t {
    auto_detect,
    iptables,
    nftables
};

// How pending firewall changes should be applied.
enum class FirewallApplyMode : uint8_t {
    // Recreate backend-owned firewall state from scratch, including sets.
    Destructive,
    // Refresh chains/rules while preserving existing set contents when possible.
    PreserveSets
};

enum class FirewallSetGeneration : uint8_t { A, B };

// Read-only health of the backend-owned tunnel SNAT scaffold.
// Missing means the last applied contract required SNAT but its scaffold no
// longer matches. Stale means SNAT is intentionally disabled but owned
// artifacts are still present; it is safe to reconcile, but it must not be
// treated as a lost egress path (and therefore must not trigger conntrack
// eviction). Unknown means the backend could not be inspected (for example
// because xtables was locked) and must not be treated as an instruction to
// mutate live firewall state.
enum class OwnedSnatState : uint8_t {
    healthy,
    missing,
    stale,
    unknown,
};

// Abstract firewall interface for managing IP sets and packet marking rules.
// Both iptables and nftables backends implement this interface.
//
// Usage pattern (transactional rebuild):
//   create_ipset() / create_mark_rule() / create_drop_rule() / create_pass_rule() — buffer operations
//   create_batch_loader() → stream entries → finish()
//   apply()    — atomically commit everything using the requested apply mode
class Firewall {
public:
    virtual ~Firewall() = default;

    // Start a new buffered apply attempt. Backends may select attempt-scoped
    // physical names before sets and rules are queued.
    virtual void prepare_apply(FirewallApplyMode mode) { (void)mode; }

    virtual std::string static_set_name(const std::string& list_name, int family) const {
        return std::string(family == AF_INET6 ? "kpbr6_" : "kpbr4_") + list_name;
    }

    virtual std::string dynamic_set_name(const std::string& list_name, int family) const {
        return std::string(family == AF_INET6 ? "kpbr6d_" : "kpbr4d_") + list_name;
    }

    // Create a named IP set for storing IP addresses and/or CIDR subnets.
    // set_name: unique name for the set
    // family: AF_INET or AF_INET6
    // timeout: TTL in seconds for entries (0 = no timeout)
    virtual void create_ipset(const std::string& set_name, int family,
                              uint32_t timeout = 0) = 0;

    // Create a firewall rule that marks packets matching the given criteria
    // with the specified firewall mark (fwmark).
    // fwmark: mark value to apply to matching packets
    // criteria: optional match criteria (default = any packet)
    virtual void create_mark_rule(uint32_t fwmark,
                                  const FirewallRuleCriteria& criteria = {}) = 0;

    // Create a mark rule for router-originated (locally generated) packets.
    // Backends hook this into the OUTPUT path (mangle OUTPUT / nft output hook)
    // so DNS detour marks apply to dnsmasq upstream queries as well.
    // Only static addr/port criteria are supported; dst_set_name is ignored.
    virtual void create_output_mark_rule(uint32_t fwmark,
                                         const FirewallRuleCriteria& criteria = {}) = 0;

    // Create a firewall rule that drops packets matching the given criteria.
    // Used for blackhole outbounds that don't need routing tables or fwmarks.
    virtual void create_drop_rule(const FirewallRuleCriteria& criteria = {}) = 0;

    // Redirect plain DNS (tcp/udp dport 53) arriving from the configured
    // inbound interfaces to the router's local resolver (client DNS
    // enforcement). Backends implement this with a NAT REDIRECT chain.
    virtual void create_dns_redirect_rules() = 0;
    // Masquerade keen-pbr-marked forwarded traffic leaving through the listed
    // tunnel interfaces. The firmware only masquerades source networks it
    // routed itself, so clients of a VPN server on the router (and any other
    // network it does not consider LAN) would otherwise enter the tunnel with
    // a private source address and never receive an answer.
    virtual void create_tunnel_snat_rules(
        const std::vector<std::string>& interfaces) = 0;
    virtual OwnedSnatState inspect_owned_snat_state() const = 0;

    // Create a firewall rule that stops keen-pbr processing for matching packets
    // and leaves them unmodified for normal system routing.
    virtual void create_pass_rule(const FirewallRuleCriteria& criteria = {}) = 0;

    // Create a batch loader visitor for streaming IP/CIDR entries into a set.
    // Returns a ListEntryVisitor that buffers entries for atomic application.
    // Caller must call finish() on the returned visitor after streaming is complete.
    virtual std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string& set_name) = 0;

    // Apply all pending changes atomically (where supported by the backend).
    // The apply mode is intentionally explicit: a missing argument must never
    // silently turn a live runtime refresh into a destructive replacement.
    virtual void apply(FirewallApplyMode mode) = 0;

    // Configure a backend-wide prefilter emitted ahead of mark/drop/pass rules.
    void set_global_prefilter(FirewallGlobalPrefilter prefilter) {
        global_prefilter_ = std::move(prefilter);
    }

    const FirewallGlobalPrefilter& global_prefilter() const {
        return global_prefilter_;
    }

    void set_ipv6_enabled(bool enabled) {
        ipv6_enabled_ = enabled;
    }

    bool ipv6_enabled() const {
        return ipv6_enabled_;
    }

    void set_fwmark_mask(uint32_t fwmark_mask) {
        fwmark_mask_ = fwmark_mask;
    }

    uint32_t fwmark_mask() const {
        return fwmark_mask_;
    }

    void set_clear_dynamic_sets_on_apply(bool clear) {
        clear_dynamic_sets_on_apply_ = clear;
    }

    bool clear_dynamic_sets_on_apply() const {
        return clear_dynamic_sets_on_apply_;
    }

    // Remove all firewall rules and IP sets created by this instance.
    // Should be called on daemon shutdown.
    virtual void cleanup() = 0;

    // Return the backend type for this firewall instance.
    virtual FirewallBackend backend() const = 0;
    virtual bool uses_raw_prerouting() const { return false; }

    // Non-copyable
    Firewall(const Firewall&) = delete;
    Firewall& operator=(const Firewall&) = delete;

protected:
    Firewall() = default;

    FirewallGlobalPrefilter global_prefilter_;
    uint32_t fwmark_mask_{0xFFFFFFFFu};
    bool ipv6_enabled_{true};
    bool clear_dynamic_sets_on_apply_{true};
};

// Return the stable config/CLI label for a concrete backend.
const char* firewall_backend_name(FirewallBackend backend);

// Factory function to create the appropriate firewall backend.
// backend_pref: auto-detect, iptables, or nftables.
// Throws FirewallError if requested backend is not available.
std::unique_ptr<Firewall> create_firewall(
    FirewallBackendPreference backend_pref = FirewallBackendPreference::auto_detect,
    bool use_raw_prerouting = false);

} // namespace keen_pbr3
