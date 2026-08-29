#pragma once

#include "ppe_deoffload.hpp"
#include "port_spec_util.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <utility>
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
    // Named set of exact source + UDP destination port + destination tuples.
    // This is reserved for bounded runtime affinity overlays; unlike
    // dst_set_name it never grants a peer address authority for every LAN
    // client or every service on the peer.
    std::optional<std::string> src_udp_peer_set_name;
    std::optional<uint8_t> dscp;        // DSCP tag selector, empty = any
    L4Proto proto = L4Proto::Any;
    // Runtime affinity is refreshed from live traffic and must expire with its
    // kernel tuple rather than leaving an owned ctmark behind indefinitely.
    bool persist_conntrack_mark = true;
    PortSpec src_port;                 // parsed source port selector
    PortSpec dst_port;                 // parsed destination port selector
    std::vector<std::string> src_addr; // CIDR list, empty = any source address
    std::vector<std::string> dst_addr; // CIDR list, empty = any destination address
    bool negate_src_port = false;      // if true, match packets NOT from src_port
    bool negate_dst_port = false;      // if true, match packets NOT to dst_port
    bool negate_src_addr = false;      // if true, match packets NOT from src_addr
    bool negate_dst_addr = false;      // if true, match packets NOT to dst_addr
    bool empty() const {
        return !dst_set_name.has_value() && !src_udp_peer_set_name.has_value()
            && !dscp.has_value()
            && proto == L4Proto::Any
            && src_port.empty() && dst_port.empty()
            && src_addr.empty() && dst_addr.empty();
    }

    bool has_rule_selector() const {
        return dst_set_name.has_value() || src_udp_peer_set_name.has_value()
            || dscp.has_value()
            || !src_port.empty() || !dst_port.empty()
            || !src_addr.empty() || !dst_addr.empty();
    }
};

using ProtoPortFilter = FirewallRuleCriteria;

struct FirewallIngressSourceSelector {
    // Service bypass selectors always contain a live, server-owned kernel
    // ingress plus its authoritative client pool. Source-only bypass is
    // forbidden because a spoofed/private source on another interface must
    // never escape keen-pbr classification.
    std::string interface;
    std::string cidr;
};

struct FirewallIngressDestinationSelector {
    std::string interface;
    std::string destination;

    bool operator==(
        const FirewallIngressDestinationSelector& other) const {
        return interface == other.interface &&
               destination == other.destination;
    }
};

struct FirewallBridgeIngressSourceSelector {
    // Both names come from a verified live bridge topology. The source CIDR
    // comes from authoritative NDMS inventory. Backends must match all three
    // fields or fail closed.
    std::string interface;
    std::string bridge_port;
    std::string cidr;
};

struct FirewallSourceEgressSnatSelector {
    // Both values come from runtime-owned observations: the source CIDR from
    // the native VPN service inventory and the egress interface from the live
    // routing inventory. Backends match both fields so this rule cannot turn
    // into a broad source-only masquerade.
    std::string interface;
    std::string cidr;

    bool operator==(
        const FirewallSourceEgressSnatSelector& other) const {
        return interface == other.interface && cidr == other.cidr;
    }

    bool operator<(
        const FirewallSourceEgressSnatSelector& other) const {
        return interface < other.interface ||
               (interface == other.interface && cidr < other.cidr);
    }
};

struct FirewallGlobalPrefilter {
    std::optional<std::vector<std::string>> inbound_interfaces;
    // Explicit ingress interfaces that must bypass keen-pbr before conntrack
    // mark restoration, route classification, and client DNS redirection.
    std::vector<std::string> bypass_inbound_interfaces;
    // Service-based NDMS VPN servers have stable client pools. The resolver
    // accepts them only from an authoritative NDMS inventory, rejects
    // overlapping pools, and binds bypass to exact live L2TP/IKE or direct
    // SSTP ingress. Bridged SSTP fails closed until a physical bridge-port
    // selector is available in both firewall backends.
    std::vector<std::string> include_source_cidrs_v4;
    std::vector<std::string> include_source_cidrs_v6;
    std::vector<FirewallIngressSourceSelector>
        bypass_source_selectors_v4;
    std::vector<FirewallIngressSourceSelector>
        bypass_source_selectors_v6;
    std::vector<FirewallBridgeIngressSourceSelector>
        bypass_bridge_source_selectors_v4;
    std::vector<FirewallBridgeIngressSourceSelector>
        bypass_bridge_source_selectors_v6;
    // DNS-only passthrough. Unlike bypass_source_selectors_* these selectors
    // do not disable route classification, mark stickiness, or tunnel SNAT.
    // They only avoid an unsafe NAT REDIRECT on an addressless verified VPN
    // ingress (for example Keenetic IKE xfrms devices).
    std::vector<FirewallIngressSourceSelector>
        dns_redirect_bypass_source_selectors_v4;
    std::vector<FirewallIngressSourceSelector>
        dns_redirect_bypass_source_selectors_v6;
    // DNS-only passthrough for a router-owned destination on a verified
    // native-VPN ingress. Unlike the source selectors above, this keeps only
    // the already-local resolver address out of REDIRECT; arbitrary external
    // DNS remains subject to normal client DNS enforcement.
    std::vector<FirewallIngressDestinationSelector>
        dns_redirect_local_destination_selectors_v4;
    std::vector<FirewallIngressDestinationSelector>
        dns_redirect_local_destination_selectors_v6;
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
               !bypass_source_selectors_v6.empty() ||
               !bypass_bridge_source_selectors_v4.empty() ||
               !bypass_bridge_source_selectors_v6.empty();
    }

    bool has_dns_redirect_bypass_source_cidrs() const {
        return !dns_redirect_bypass_source_selectors_v4.empty() ||
               !dns_redirect_bypass_source_selectors_v6.empty() ||
               !dns_redirect_local_destination_selectors_v4.empty() ||
               !dns_redirect_local_destination_selectors_v6.empty();
    }

    bool empty() const {
        return !skip_established_or_dnat && !skip_marked_packets
            && !restore_conntrack_mark && !has_inbound_interfaces()
            && !has_bypass_inbound_interfaces()
            && !has_include_source_cidrs()
            && !has_bypass_source_cidrs()
            && !has_dns_redirect_bypass_source_cidrs();
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

// Raised when an inspection-only RulesOnly apply cannot safely reuse the
// currently live sets: a set is missing, its schema drifted, or the realized
// state the reuse was planned from does not match. Callers restage exactly
// once with PreserveSets. It is deliberately not a TransientFirewallError: a
// failed preflight has touched nothing, so the transient-recovery machinery,
// which assumes a half-applied kernel, must not run for it.
class FirewallRulesOnlyError : public FirewallError {
public:
    explicit FirewallRulesOnlyError(const std::string& message,
                                    bool external_repair = false)
        : FirewallError(message), external_repair_(external_repair) {}

    // True when the refusal describes state an outside actor left behind -
    // on Keenetic, an NDMS netfilter rebuild wiping the mangle dispatchers
    // is routine - and the PreserveSets fallback repairs it by design. The
    // caller logs such a refusal as information, not as a warning: a
    // completed, designed repair is not something the operator's bell
    // should claim is wrong. Refusals about the daemon's own bookkeeping
    // (a reused set missing, a schema that drifted) stay warnings.
    bool external_repair() const noexcept { return external_repair_; }

private:
    bool external_repair_{false};
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

// Independent per-family placement of forwarded-traffic classification.
// OUTPUT always stays in mangle; these flags select only the PREROUTING
// table, and only for the iptables backend. The families are independent on
// purpose: Keenetic firmwares ship iptable_raw and ip6table_raw separately,
// and one being absent must not cost the other its NDMS-rebuild immunity.
// (Semantic port of upstream ca5a2e02.)
struct RawPreroutingMode {
    bool ipv4{false};
    bool ipv6{false};

    bool uses(bool is_ipv6) const noexcept { return is_ipv6 ? ipv6 : ipv4; }
    bool any() const noexcept { return ipv4 || ipv6; }
};

// How pending firewall changes should be applied.
enum class FirewallApplyMode : uint8_t {
    // Recreate backend-owned firewall state from scratch, including sets.
    Destructive,
    // Refresh chains/rules while preserving existing set contents when possible.
    PreserveSets,
    // Rebuild packet-classification rules while reusing the currently live
    // static and dynamic sets. Nothing touches a set and no list is streamed:
    // a urltest failover or an interface event changes which rules point at
    // which sets, not what the sets contain, and restreaming an rkn-sized list
    // through `ipset restore` on every failover was the cost of not saying so.
    // Preflight failure falls back to PreserveSets. (Semantic port of upstream
    // ad4899dc.)
    RulesOnly
};

enum class FirewallSetGeneration : uint8_t { A, B };

// Return the kernel-normalized initial hashsize for an ipset declaration.
// The result is absent when the next power of two cannot fit in uint32.
std::optional<uint32_t> normalize_ipset_hashsize(uint32_t requested);

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

// Read-only health of the opt-in Meta UDP/443 FORWARD policy. `missing`
// means messages-first was the last successfully applied contract but its
// first hook/chain/rules vanished. `stale` means balanced was committed while
// owned blocking artifacts remain, or the live contract differs from the
// exact committed one. Inspection failures are never mutation authority.
enum class OwnedForwardUdpRejectState : uint8_t {
    healthy,
    missing,
    stale,
    unknown,
};

// Exact, short-lived TCP flow selected by a higher-level runtime observer for
// one opt-in IPv4 client.  The backend must match every field, including the
// complete packet mark, so this primitive can never degrade into a host-wide
// or destination-wide reset policy.
struct FirewallExactTcpResetRule {
    std::string source;
    std::string destination;
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    std::uint32_t full_mark{0U};

    bool operator==(const FirewallExactTcpResetRule& other) const {
        return source == other.source &&
               destination == other.destination &&
               source_port == other.source_port &&
               destination_port == other.destination_port &&
               full_mark == other.full_mark;
    }
};

enum class FirewallExactTcpResetResult : uint8_t {
    installed,
    unsupported,
    failed,
};

// Result of one exact runtime UDP-peer publication.  A failed command after
// crossing the mutation boundary cannot be treated as a proved no-op: the
// caller must retain its recovery authority unless either publication or the
// compensating removal was verified.
struct FirewallUdpPeerMutationResult final {
    bool mutation_boundary_entered{false};
    bool publication_verified{false};
    bool removal_attempted{false};
    bool removal_verified{false};

    bool installed() const noexcept {
        return mutation_boundary_entered && publication_verified;
    }

    bool ambiguous() const noexcept {
        return mutation_boundary_entered && !publication_verified &&
               !removal_verified;
    }

    // Preserve the existing bool call site while the typed runtime owner is
    // introduced. New mutation code must consume the structured fields.
    operator bool() const noexcept { return installed(); }
};

enum class FirewallOwnedCleanupState : std::uint8_t {
    verified_absent,
    owned_artifacts_present,
    observation_failed,
};

struct FirewallOwnedCleanupInspection final {
    FirewallOwnedCleanupState state{
        FirewallOwnedCleanupState::observation_failed};
    std::string detail;

    bool verified_absent() const noexcept {
        return state == FirewallOwnedCleanupState::verified_absent;
    }
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

    virtual std::string media_affinity_set_name(
        const std::string& list_name,
        int family) const {
        // Seven-byte prefix preserves the existing 24-byte technical list-ID
        // allowance under ipset's 31-byte name limit.
        return std::string(family == AF_INET6 ? "kpbr6m_" : "kpbr4m_") +
               list_name;
    }

    // Create a named IP set for storing IP addresses and/or CIDR subnets.
    // set_name: unique name for the set
    // family: AF_INET or AF_INET6
    // timeout: TTL in seconds for entries (0 = no timeout)
    virtual void create_ipset(const std::string& set_name, int family,
                              uint32_t timeout = 0) = 0;

    // Create an initially empty, expiring set keyed by exact source host, UDP
    // destination port and destination host. Runtime call affinity populates
    // it only after a bounded conntrack observation proves an active selected
    // call context.
    virtual void create_udp_peer_set(const std::string& set_name,
                                     int family,
                                     uint32_t timeout) = 0;

    // Add one exact UDP peer tuple to a previously applied affinity set.
    // Implementations validate both addresses and the non-zero port, then
    // report success only after the element update and a fresh read-only proof
    // that the corresponding classifier rule is still published through the
    // active chain. A missing set, family mismatch, or out-of-band rule drift
    // fails closed. Once mutation_boundary_entered is true, an unverified
    // publication is safe only when compensating removal was also verified.
    virtual FirewallUdpPeerMutationResult add_udp_peer(
        const std::string& set_name,
        const std::string& source,
        std::uint16_t destination_port,
        const std::string& destination) = 0;

    // Arm one short-lived TCP reset window for an exact observed IPv4 flow.
    // Backends that cannot provide the complete match contract fail closed.
    // The default deliberately keeps this experimental actuator unavailable
    // to nftables until it has an equally narrow, tested implementation.
    virtual FirewallExactTcpResetResult install_exact_tcp_reset(
        const FirewallExactTcpResetRule& rule) {
        (void)rule;
        return FirewallExactTcpResetResult::unsupported;
    }
    virtual bool remove_exact_tcp_reset(
        const FirewallExactTcpResetRule& rule) {
        (void)rule;
        return false;
    }

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

    // Reject forwarded UDP for one already-realized destination route. This
    // deliberately lives in filter/FORWARD (not mangle PREROUTING) so the
    // client receives an ICMP port-unreachable and can fall back immediately.
    // Backends must match the exact keen-pbr-owned mark/mask and destination
    // set, publish the hook before ordinary ESTABLISHED acceptance, and leave
    // every other UDP port and destination untouched.
    virtual void create_forward_udp_reject_rule(
        uint32_t expected_fwmark,
        const std::string& dst_set_name,
        std::uint16_t destination_port) = 0;

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
    // Masquerade traffic from an authoritative native-VPN source pool only
    // when it leaves through an explicitly observed egress interface. This is
    // intentionally independent of keen-pbr marks: direct/bypass traffic must
    // retain ordinary Internet access too.
    virtual void create_source_egress_snat_rules(
        const std::vector<FirewallSourceEgressSnatSelector>& selectors) = 0;
    virtual OwnedSnatState inspect_owned_snat_state() const = 0;
    virtual OwnedForwardUdpRejectState
    inspect_forward_udp_reject_state() const = 0;

    // Monotonic publication boundary for the independently owned
    // Meta/WhatsApp UDP/443 filter. Callers snapshot this before apply() and
    // compare it after an exception: an unchanged value proves the failure
    // happened in ordinary mangle/NAT work before any Meta filter mutation
    // was attempted. A changed value deliberately remains conservative,
    // because a restore/batch command may have committed before its result
    // became observable.
    std::uint64_t meta_udp443_publication_epoch() const noexcept {
        return meta_udp443_publication_epoch_.load(
            std::memory_order_acquire);
    }

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

    // Optional ipset capacity hints. The iptables backend applies them to its
    // owned hash sets; nftables deliberately ignores them.
    void set_ipset_hashsize(std::optional<uint32_t> hashsize) {
        ipset_hashsize_ = std::move(hashsize);
    }

    const std::optional<uint32_t>& ipset_hashsize() const {
        return ipset_hashsize_;
    }

    void set_ipset_maxelem(std::optional<uint32_t> maxelem) {
        ipset_maxelem_ = std::move(maxelem);
    }

    const std::optional<uint32_t>& ipset_maxelem() const {
        return ipset_maxelem_;
    }

    // Defaults to on. Every nfqws2 strategy this project ships uses a
    // TTL-dependent desync, so a router with `ip ttl-fix` enabled breaks all of
    // them at once; an opt-in switch would leave the fix off for everyone who
    // never learns it exists. This is an escape hatch, not a feature flag.
    void set_ttl_bypass_enabled(bool enabled) {
        ttl_bypass_enabled_ = enabled;
    }

    bool ttl_bypass_enabled() const {
        return ttl_bypass_enabled_;
    }

    // The active-runtime observer supplies validated ports and process/queue
    // state. The backend still performs live kernel/userspace capability
    // checks inside its serialized apply before it mutates the PPE graph.
    void set_ppe_deoffload_desired(PpeDeoffloadDesired desired) {
        std::lock_guard<std::mutex> lock(ppe_deoffload_desired_mutex_);
        ppe_deoffload_desired_ = std::move(desired);
    }

    PpeDeoffloadDesired ppe_deoffload_desired() const {
        std::lock_guard<std::mutex> lock(ppe_deoffload_desired_mutex_);
        return ppe_deoffload_desired_;
    }

    // Remove all firewall rules and IP sets created by this instance.
    // Should be called on daemon shutdown.
    virtual void cleanup() = 0;
    // Destructive cleanup followed by a fresh read-only proof that every
    // keen-pbr-owned artifact is absent. The compatibility fallback is
    // deliberately never a proof: STOP publication requires a backend
    // override which can classify incomplete observations fail-closed.
    virtual FirewallOwnedCleanupInspection cleanup_and_inspect_owned() {
        cleanup();
        return {
            FirewallOwnedCleanupState::observation_failed,
            "firewall backend does not implement verified cleanup",
        };
    }

    // Return the backend type for this firewall instance.
    virtual FirewallBackend backend() const = 0;
    // Resolved per-family placement of forwarded-traffic classification.
    // OUTPUT remains mangle for both families.
    virtual RawPreroutingMode raw_prerouting_mode() const { return {}; }
    // Compatibility accessor: the historical flag always meant IPv4 RAW.
    virtual bool uses_raw_prerouting() const {
        return raw_prerouting_mode().ipv4;
    }

    // State of the owned TTL bypass rule, as a stable name, or empty when the
    // backend does not implement one. Empty rather than a fabricated "ok":
    // the nftables backend has no such rule, and claiming a state it never
    // computed would be worse than reporting nothing.
    virtual std::string ttl_bypass_state_name() const { return {}; }
    virtual std::string ttl_bypass_state_detail() const { return {}; }

    // Passive health view. Backends that cannot own the IPv4 xtables graph
    // still preserve the configured mode instead of reporting a fabricated
    // "off" state when automatic de-offload was requested.
    virtual PpeDeoffloadSnapshot ppe_deoffload_snapshot() const {
        PpeDeoffloadSnapshot snapshot;
        const auto desired = ppe_deoffload_desired();
        snapshot.mode = desired.mode;
        snapshot.desired_quic =
            desired.quic_enabled && desired.quic_443_active;
        try {
            snapshot.desired_tcp_ports =
                build_ppe_deoffload_graph_spec(desired).tcp_chunks;
        } catch (const std::invalid_argument& error) {
            snapshot.detail = error.what();
            snapshot.degraded = true;
        }
        if (snapshot.mode == PpeDeoffloadMode::automatic) {
            snapshot.state = PpeDeoffloadState::backend_incompatible;
            if (snapshot.detail.empty()) {
                snapshot.detail =
                    "PPE de-offload requires the iptables backend";
            }
        }
        return snapshot;
    }

    // Refreshes the stored passive observation from an existing serialized
    // control-loop owner. API/IPC callers only read the snapshot and never
    // launch firewall tools themselves.
    virtual PpeObservationRefreshResult
    refresh_ppe_deoffload_observation() noexcept {
        return PpeObservationRefreshResult::inactive;
    }

    // Non-copyable
    Firewall(const Firewall&) = delete;
    Firewall& operator=(const Firewall&) = delete;

protected:
    Firewall() = default;

    void enter_meta_udp443_publication_boundary() const noexcept {
        meta_udp443_publication_epoch_.fetch_add(
            1U, std::memory_order_acq_rel);
    }

    FirewallGlobalPrefilter global_prefilter_;
    uint32_t fwmark_mask_{0xFFFFFFFFu};
    bool ipv6_enabled_{true};
    bool clear_dynamic_sets_on_apply_{true};
    std::optional<uint32_t> ipset_hashsize_;
    std::optional<uint32_t> ipset_maxelem_;
    bool ttl_bypass_enabled_{true};
    mutable std::mutex ppe_deoffload_desired_mutex_;
    PpeDeoffloadDesired ppe_deoffload_desired_;

private:
    mutable std::atomic<std::uint64_t>
        meta_udp443_publication_epoch_{0U};
};

// Return the stable config/CLI label for a concrete backend.
const char* firewall_backend_name(FirewallBackend backend);

// Factory function to create the appropriate firewall backend.
// backend_pref: auto-detect, iptables, or nftables.
// raw_prerouting: independent per-family RAW PREROUTING placement.
// Throws FirewallError if requested backend is not available.
std::unique_ptr<Firewall> create_firewall(
    FirewallBackendPreference backend_pref = FirewallBackendPreference::auto_detect,
    RawPreroutingMode raw_prerouting = {});

// Compatibility overload for callers using the historical IPv4-only flag.
inline std::unique_ptr<Firewall> create_firewall(
    FirewallBackendPreference backend_pref,
    bool use_raw_prerouting) {
    return create_firewall(
        backend_pref, RawPreroutingMode{use_raw_prerouting, false});
}

} // namespace keen_pbr3
