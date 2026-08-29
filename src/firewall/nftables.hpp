#pragma once

#include "firewall.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

class NftablesFirewall : public Firewall {
public:
    // Initialize the nftables backend; does not modify firewall state yet.
    NftablesFirewall();
    // Destructor performs best-effort cleanup without virtual dispatch.
    ~NftablesFirewall() override;

    void prepare_apply(FirewallApplyMode mode) override;

    // Buffer an nftables named set (ipv4_addr/ipv6_addr, optional timeout).
    void create_ipset(const std::string& set_name, int family,
                      uint32_t timeout = 0) override;
    void create_udp_peer_set(const std::string& set_name,
                             int family,
                             uint32_t timeout) override;
    FirewallUdpPeerMutationResult add_udp_peer(
        const std::string& set_name,
        const std::string& source,
        std::uint16_t destination_port,
        const std::string& destination) override;

    // Buffer a meta mark set rule that matches the given criteria.
    void create_mark_rule(uint32_t fwmark,
                          const FirewallRuleCriteria& criteria = {}) override;
    // Buffer a mark rule for router-originated traffic (output hook, type route
    // so marked local packets are re-routed after the mark is applied).
    void create_output_mark_rule(uint32_t fwmark,
                                 const FirewallRuleCriteria& criteria = {}) override;
    // Buffer a drop verdict rule that matches the given criteria.
    void create_drop_rule(const FirewallRuleCriteria& criteria = {}) override;
    void create_forward_udp_reject_rule(
        uint32_t expected_fwmark,
        const std::string& dst_set_name,
        std::uint16_t destination_port) override;
    // Buffer NAT redirect rules that force LAN plain-DNS to the local resolver.
    void create_dns_redirect_rules() override;
    void create_tunnel_snat_rules(
        const std::vector<std::string>& interfaces) override;
    void create_source_egress_snat_rules(
        const std::vector<FirewallSourceEgressSnatSelector>& selectors) override;
    OwnedSnatState inspect_owned_snat_state() const override;
    OwnedForwardUdpRejectState
    inspect_forward_udp_reject_state() const override;
    // Buffer a pass-through verdict rule that matches the given criteria.
    void create_pass_rule(const FirewallRuleCriteria& criteria = {}) override;

    // Return an NftBatchVisitor that appends element values to the pending
    // element buffer for set_name; elements are flushed during apply().
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string& set_name) override;

    // Atomically apply all pending table/set/rule/element operations via
    // a single 'nft -j -f -' invocation with a JSON batch.
    void apply(FirewallApplyMode mode) override;
    // Delete the inet KeenPbrTable table, removing all sets and rules within it.
    void cleanup() override;
    FirewallOwnedCleanupInspection cleanup_and_inspect_owned() override;
    // Returns FirewallBackend::nftables.
    FirewallBackend backend() const override;

private:
    void clear_cleanup_state_after_verified_absence();

    enum class MarkMergeMode : uint8_t {
        LegacyConstant,
        RegisterMerge,
    };
    using CapabilityProbe = std::function<bool()>;

    explicit NftablesFirewall(CapabilityProbe capability_probe);

    static constexpr const char* TABLE_NAME = "KeenPbrTable";
    static constexpr const char* CHAIN_NAME = "prerouting";
    static constexpr const char* OUTPUT_CHAIN_NAME = "output";
    static constexpr const char* FORWARD_UDP_REJECT_CHAIN_NAME =
        "meta_udp_443";
    static constexpr const char* DNS_NAT_CHAIN_NAME = "dns_redirect";
    static constexpr const char* SNAT_CHAIN_NAME = "router_origin_snat";
    void cleanup_live_impl(bool verification_required = true);
    void cleanup_impl(bool verification_required = true);
    bool table_exists() const;

    struct LiveTableState {
        bool table_exists{false};
        bool chain_exists{false};
        bool output_chain_exists{false};
        bool forward_udp_reject_chain_exists{false};
        bool dns_nat_chain_exists{false};
        bool snat_chain_exists{false};
        std::set<std::string> set_names;
        std::map<std::string, std::string> set_schemas;
    };

    LiveTableState read_live_table_state() const;
    nlohmann::json build_apply_document(const LiveTableState& live_state,
                                        bool emit_full_table,
                                        bool destructive_apply,
                                        bool clear_dynamic_sets,
                                        MarkMergeMode mark_merge_mode =
                                            MarkMergeMode::LegacyConstant,
                                        bool rules_only = false);
    // RulesOnly reuses the live sets untouched, so every set the staged rules
    // name must already exist with the exact schema the rules assume. Throws
    // FirewallRulesOnlyError; the caller restages with PreserveSets.
    void preflight_reused_sets(const LiveTableState& live_state) const;
    FirewallApplyMode prepared_mode_{FirewallApplyMode::Destructive};

    // Describes an nftables named set to be created.
    struct PendingSet {
        std::string name;
        std::string type;   // "ipv4_addr" or "ipv6_addr"
        uint32_t timeout;   // entry TTL in seconds (0 = no timeout)
        bool source_udp_peer{false};
    };

    // Describes a rule to be added to the prerouting chain.
    struct PendingRule {
        int family;  // AF_INET or AF_INET6
        enum Action { Mark, Drop, Pass } action; // meta mark, drop, or accept verdict
        uint32_t fwmark; // only for Mark
        uint32_t fwmark_mask{0xFFFFFFFFu}; // only for Mark
        FirewallRuleCriteria criteria; // optional packet match criteria
        bool output{false}; // true → output chain (router-originated traffic)
    };

    struct PublishedUdpPeerClassifier {
        int family{AF_INET};
        uint32_t timeout{0};
        nlohmann::json expected_expr;
    };

    struct PendingForwardUdpReject {
        int family{AF_INET};
        uint32_t expected_fwmark{0};
        uint32_t fwmark_mask{0};
        std::string dst_set_name;
        std::uint16_t destination_port{0};
    };

    // Build the nftables JSON object for creating the inet KeenPbrTable table.
    static nlohmann::json build_table_json();
    // Build the JSON object for a named set with type and optional timeout.
    static nlohmann::json build_set_json(const PendingSet& ps);
    // Build the JSON object for the prerouting chain (type filter, hook prerouting).
    static nlohmann::json build_chain_json();
    // Build the JSON object for the output chain (type route, hook output).
    static nlohmann::json build_output_chain_json();
    // Build the JSON object for deleting the prerouting chain.
    static nlohmann::json build_delete_chain_json();
    // Build the JSON object for deleting the output chain.
    static nlohmann::json build_delete_output_chain_json();
    static nlohmann::json build_forward_udp_reject_chain_json();
    static nlohmann::json build_delete_forward_udp_reject_chain_json();
    static nlohmann::json build_forward_udp_reject_rule_json(
        const PendingForwardUdpReject& rule);
    static std::optional<nlohmann::json>
    normalize_forward_udp_reject_rule_expr(nlohmann::json expr);
    static OwnedForwardUdpRejectState parse_forward_udp_reject_state(
        const std::string& document,
        const std::vector<PendingForwardUdpReject>& expected_rules);
    static OwnedForwardUdpRejectState classify_forward_udp_reject_inspection(
        const std::string& output,
        int exit_code,
        bool timed_out,
        bool truncated,
        const std::vector<PendingForwardUdpReject>& expected_rules);
    OwnedForwardUdpRejectState inspect_forward_udp_reject_state(
        const std::vector<PendingForwardUdpReject>& expected_rules) const;
    static nlohmann::json build_flush_set_json(const std::string& set_name);
    static nlohmann::json build_delete_set_json(const std::string& set_name);
    static bool is_dynamic_set_name(const std::string& set_name);
    static bool is_managed_set_name(const std::string& set_name);
    static std::string set_schema_key(const PendingSet& set);
    // Build the JSON objects for the DNS redirect nat chain and its rules.
    static nlohmann::json build_dns_nat_chain_json();
    static nlohmann::json build_delete_dns_nat_chain_json();
    static nlohmann::json build_dns_redirect_rules_json(
        const FirewallGlobalPrefilter& prefilter,
        const std::map<std::string, std::pair<int, uint32_t>>&
            udp_peer_sets = {});
    static nlohmann::json build_snat_chain_json();
    static nlohmann::json build_delete_snat_chain_json();
    static nlohmann::json build_snat_rule_json();
    static nlohmann::json build_interface_snat_rule_json(
        const std::string& interface,
        uint32_t fwmark_mask);
    static nlohmann::json build_source_egress_snat_rule_json(
        const FirewallSourceEgressSnatSelector& selector);
    static OwnedSnatState parse_owned_snat_state(
        const std::string& document,
        bool expected,
        const std::vector<std::string>& expected_interfaces,
        const std::vector<FirewallSourceEgressSnatSelector>&
            expected_source_egress_selectors,
        uint32_t expected_fwmark_mask);
    OwnedSnatState inspect_owned_snat_state(
        bool expected,
        const std::vector<std::string>& expected_interfaces,
        const std::vector<FirewallSourceEgressSnatSelector>&
            expected_source_egress_selectors,
        uint32_t expected_fwmark_mask) const;
    static std::chrono::milliseconds owned_snat_inspect_timeout();
    static std::chrono::milliseconds owned_snat_inspect_kill_grace();
    // Build all prerouting rule add-commands, including global prefilter rules.
    static nlohmann::json build_rule_add_commands(
        const FirewallGlobalPrefilter& prefilter,
        const std::vector<PendingRule>& rules,
        MarkMergeMode mark_merge_mode = MarkMergeMode::LegacyConstant);
    // Build the JSON rule object for a meta mark set action matching a named set.
    static nlohmann::json build_mark_rule_json(
        const PendingRule& pr,
        uint32_t conntrack_mark_mask = 0,
        MarkMergeMode mark_merge_mode = MarkMergeMode::LegacyConstant);
    // Build the JSON rule object for a drop verdict matching a named set.
    static nlohmann::json build_drop_rule_json(const PendingRule& pr);
    // Build the JSON rule object for a pass-through verdict matching a named set.
    static nlohmann::json build_pass_rule_json(const PendingRule& pr);
    // Build nftables match expression(s) for proto/port filter.
    // Returns a (possibly empty) array of JSON match expressions.
    static nlohmann::json build_port_match_exprs(L4Proto proto,
                                                  const PortSpec& src_port,
                                                  const PortSpec& dst_port,
                                                  bool negate_src_port = false,
                                                  bool negate_dst_port = false);
    // Build nftables match expression(s) for source/destination CIDR constraints.
    // ip_proto is "ip" or "ip6". Returns a (possibly empty) array of JSON match expressions.
    static nlohmann::json build_addr_match_exprs(const std::string& ip_proto,
                                                  const std::vector<std::string>& src_addr,
                                                  const std::vector<std::string>& dst_addr,
                                                  bool negate_src_addr = false,
                                                  bool negate_dst_addr = false);
    // Build nftables match expression(s) for DSCP.
    static nlohmann::json build_dscp_match_exprs(const std::string& ip_proto,
                                                  std::optional<uint8_t> dscp);
    // Build the JSON element-add object for bulk-loading elems into a named set.
    static nlohmann::json build_elements_json(const std::string& set_name,
                                              const nlohmann::json& elems);
    static nlohmann::json build_udp_peer_update_document(
        const std::string& set_name,
        const std::string& source,
        std::uint16_t destination_port,
        const std::string& destination,
        bool already_present);
    static std::optional<nlohmann::json> normalize_rule_expr(
        nlohmann::json expr);
    static bool udp_peer_classifier_document_matches(
        const std::string& document,
        const std::string& set_name,
        const PublishedUdpPeerClassifier& classifier);
    std::map<std::string, PublishedUdpPeerClassifier>
    build_pending_udp_peer_classifiers(MarkMergeMode mark_merge_mode) const;
    bool udp_peer_classifier_is_published(
        const std::string& set_name,
        const PublishedUdpPeerClassifier& classifier) const noexcept;
    void append_rules_for_family(int family,
                                 PendingRule::Action action,
                                 uint32_t fwmark,
                                 const FirewallRuleCriteria& criteria,
                                 bool output_scope = false);
    static nlohmann::json build_register_merge_probe_document();
    static bool probe_register_merge_capability();
    static MarkMergeMode resolve_mark_merge_mode(
        std::optional<MarkMergeMode>& cached_mode,
        const CapabilityProbe& capability_probe);
    MarkMergeMode mark_merge_mode();

    // Sets queued for creation, flushed by apply().
    std::vector<PendingSet> pending_sets_;
    // Per-set element buffers (JSON arrays) for batch element loading, keyed by set name.
    std::map<std::string, nlohmann::json> pending_elements_;
    // Rules queued for insertion into the prerouting chain, flushed by apply().
    std::vector<PendingRule> pending_rules_;
    std::vector<PendingForwardUdpReject> pending_forward_udp_rejects_;

    // Track created sets for family lookup: set_name -> family (AF_INET/AF_INET6)
    std::map<std::string, int> created_sets_;
    std::map<std::string, std::pair<int, uint32_t>> udp_peer_sets_;
    std::map<std::string, PublishedUdpPeerClassifier>
        published_udp_peer_classifiers_;
    mutable std::mutex pair_state_mutex_;

    // True once the inet KeenPbrTable table has been created via apply().
    bool table_created_ = false;
    // A failed strict STOP retains broad recovery ownership even when the
    // table disappeared between mutation and its final cross-backend proof.
    bool strict_cleanup_pending_ = false;

    // Client DNS enforcement requested for the next apply().
    bool dns_redirect_requested_ = false;
    bool router_origin_snat_requested_ = false;
    std::vector<std::string> snat_interfaces_;
    std::vector<FirewallSourceEgressSnatSelector>
        source_egress_snat_selectors_;
    // Last successfully applied SNAT contract. It is intentionally not reset
    // by prepare_apply(), so the runtime monitor observes the live generation
    // until a replacement transaction has committed.
    bool last_applied_snat_expected_ = false;
    std::vector<std::string> last_applied_snat_interfaces_;
    std::vector<FirewallSourceEgressSnatSelector>
        last_applied_source_egress_snat_selectors_;
    uint32_t last_applied_snat_fwmark_mask_ = 0xFFFFFFFFu;
    // The monitor must inspect the last verified generation, not an
    // in-progress replacement assembled between prepare_apply() and apply().
    std::vector<PendingForwardUdpReject>
        last_applied_forward_udp_rejects_;
    CapabilityProbe mark_merge_capability_probe_;
    std::optional<MarkMergeMode> mark_merge_mode_;

#ifdef KEEN_PBR3_TESTING
    friend class NftablesBuilderTest;
#endif
};

// Factory function called from firewall.cpp
std::unique_ptr<Firewall> create_nftables_firewall();

} // namespace keen_pbr3
