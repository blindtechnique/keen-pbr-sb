#pragma once

#include "firewall.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keen_pbr3 {

#ifdef KEEN_PBR3_TESTING
namespace testing {
bool restore_wait_option_supported_for_test(const std::string& program);
void reset_restore_wait_option_probe_for_test();
} // namespace testing
#endif

class IptablesFirewall : public Firewall {
public:
    // Initialize the iptables backend; does not modify firewall state yet.
    explicit IptablesFirewall(bool use_raw_prerouting = false);
    // Kernel firewall state is persistent and is removed only by explicit
    // cleanup(), never as a side effect of C++ object destruction.
    ~IptablesFirewall() override = default;

    void prepare_apply(FirewallApplyMode mode) override;
    std::string static_set_name(const std::string& list_name, int family) const override;

    // Buffer an ipset create command (hash:net family, optional timeout).
    void create_ipset(const std::string& set_name, int family,
                      uint32_t timeout = 0) override;

    // Buffer an iptables/ip6tables -j MARK --set-mark rule for the given ipset.
    void create_mark_rule(uint32_t fwmark,
                          const FirewallRuleCriteria& criteria = {}) override;
    // Buffer a MARK rule for router-originated traffic (mangle OUTPUT hook).
    // Used for DNS detour so dnsmasq upstream queries are policy-routed too.
    void create_output_mark_rule(uint32_t fwmark,
                                 const FirewallRuleCriteria& criteria = {}) override;
    // Buffer an iptables/ip6tables -j DROP rule for the given criteria.
    void create_drop_rule(const FirewallRuleCriteria& criteria = {}) override;
    // Buffer NAT REDIRECT rules that force LAN plain-DNS to the local resolver.
    void create_dns_redirect_rules() override;
    // Buffer NAT MASQUERADE rules for traffic leaving via tunnel interfaces.
    void create_tunnel_snat_rules(
        const std::vector<std::string>& interfaces) override;
    // Buffer an iptables/ip6tables -j RETURN rule for the given criteria.
    void create_pass_rule(const FirewallRuleCriteria& criteria = {}) override;

    // Return an IpsetRestoreVisitor that appends 'add' lines to the pending
    // element buffer for set_name; entries are flushed during apply().
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string& set_name) override;

    // Atomically apply all pending ipsets (via ipset restore) and rules
    // (via iptables-restore / ip6tables-restore), always materializing the
    // KeenPbrTable chain scaffold and PREROUTING jump for diagnostics.
    void apply(FirewallApplyMode mode = FirewallApplyMode::Destructive) override;
    // Destroy all buffered ipsets (ipset destroy) and flush/delete the
    // KeenPbrTable chain from both iptables and ip6tables mangle tables.
    void cleanup() override;
    // Returns FirewallBackend::iptables.
    FirewallBackend backend() const override;
    bool uses_raw_prerouting() const override {
        return use_raw_prerouting_;
    }

private:
    static constexpr const char* CHAIN_NAME = "KeenPbrTable";
    static constexpr const char* RAW_CHAIN_NAME = "KeenPbrRaw";
    static constexpr const char* RAW_CONNTRACK_CHAIN_NAME =
        "KeenPbrRawCt";
    static constexpr const char* OUTPUT_CHAIN_NAME = "KeenPbrOutput";
    static constexpr const char* DNS_NAT_CHAIN_NAME = "KeenPbrDnsRdr";
    static constexpr const char* SNAT_CHAIN_NAME = "KeenPbrSnat";
    void cleanup_live_impl(bool preserve_dynamic_sets = false,
                           bool sweep_live_state = false);
    void cleanup_impl();
    void cleanup_rules_impl(bool sweep_live_state = false);
    void cleanup_nat_rules_impl(bool sweep_live_state = false);
    void cleanup_saved_sets(bool preserve_dynamic_sets);
    static void cleanup_legacy_generation_chains(const char* command);

    // Describes a set to be created via 'ipset restore'.
    struct PendingSet {
        std::string name;
        std::string family_str; // "inet" or "inet6"
        uint32_t timeout;       // entry TTL in seconds (0 = no timeout)
    };

    // Describes an iptables/ip6tables rule to be added to KeenPbrTable.
    struct PendingRule {
        std::string set_name; // ipset name to match with --match-set
        bool ipv6;            // true → ip6tables, false → iptables
        enum Action { Mark, Drop, Pass } action; // MARK, DROP, or RETURN target
        uint32_t fwmark; // only for Mark
        uint32_t fwmark_mask{0xFFFFFFFFu}; // only for Mark
        FirewallRuleCriteria criteria; // optional packet match criteria
        bool output{false}; // true → KeenPbrOutput (mangle OUTPUT), false → KeenPbrTable (PREROUTING)
    };

    enum class LiveGenerationState { A, B, Missing, Invalid };

    // Build the 'create <name> hash:net family <f> [timeout <t>]' line.
    static std::string build_ipset_create_line(const PendingSet& ps);
    static bool is_dynamic_set_name(const std::string& set_name);
    static bool dynamic_set_schema_compatible(
        const std::string& xml,
        const PendingSet& expected);
    void preflight_dynamic_set_schemas(bool effective_ipv6) const;
    // Build a complete iptables-restore script for the given protocol and rules.
    static std::string build_ipt_script(bool ipv6,
                                        const std::vector<PendingRule>& rules,
                                        const FirewallGlobalPrefilter& prefilter = {});
    static std::string build_generation_ipt_script(
        bool ipv6,
        const std::string& prerouting_chain,
        const std::string& output_chain,
        bool replace_active_chains,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {});
    static std::string build_raw_prerouting_script(
        const std::string& prerouting_chain,
        bool replace_active_chain,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {});
    static std::string build_output_generation_script(
        const std::string& output_chain,
        bool replace_active_chain,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {});
    static std::string build_raw_conntrack_script(
        bool replace_active_chain,
        const FirewallGlobalPrefilter& prefilter = {});
    static std::string build_conntrack_prefilter_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain);
    // Build early RETURN lines for the global prefilter.
    static std::string build_prefilter_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain = CHAIN_NAME,
        bool allow_conntrack = true);
    // Build the proto/port fragments for a single rule (single proto, not
    // tcp/udp). Oversized positive multiport lists expand into alternative
    // rules; negated chunks stay in one fragment so their AND semantics are
    // preserved.
    static std::vector<std::string> build_proto_port_fragments(
        L4Proto proto,
        const PortSpec& src_port,
        const PortSpec& dst_port,
        bool negate_src_port = false,
        bool negate_dst_port = false);
    // Build one or more iptables-restore lines for a queued rule.
    static std::vector<std::string> build_rule_lines(
        const PendingRule& pr,
        const FirewallGlobalPrefilter& prefilter,
        bool allow_conntrack = true);
    bool ipv6_backend_available() const;
    LiveGenerationState inspect_live_generation(bool ipv6) const;
    LiveGenerationState inspect_dispatcher(
        const char* command,
        const char* table,
        const std::string& dispatcher,
        const std::string& generation_a,
        const std::string& generation_b) const;
    FirewallSetGeneration select_target_generation(bool ipv6) const;
    void ensure_target_generation_inactive(
        bool ipv6,
        FirewallSetGeneration target) const;
    void publish_dispatcher(
        bool ipv6,
        bool output,
        FirewallSetGeneration generation) const;
    static LiveGenerationState parse_live_generation(
        const std::string& rules,
        const std::string& dispatcher,
        const std::string& generation_a,
        const std::string& generation_b);
    static FirewallSetGeneration target_generation_for_states(
        LiveGenerationState primary,
        LiveGenerationState secondary);
    void reconcile_hooks(bool ipv6) const;
    void verify_applied_generation(
        bool ipv6,
        FirewallSetGeneration target) const;
    static size_t count_exact_jump(
        const std::string& rules,
        const std::string& source_chain,
        const std::string& target_chain);
    static void reconcile_hook(
        const char* command,
        const char* table,
        const char* builtin_chain,
        const char* target_chain);
    static void remove_all_hooks(
        const char* command,
        const char* table,
        const char* builtin_chain,
        const char* target_chain);
    const char* prerouting_table_name(bool ipv6) const;
    const char* prerouting_dispatcher_chain_name(bool ipv6) const;
    const char* prerouting_generation_chain(
        FirewallSetGeneration generation,
        bool ipv6) const;
    // Expand filter (proto, src_addr, dst_addr) into cross-product of PendingRules
    // and append them to out.  tcp/udp is split into two entries.  Multiple CIDRs
    // in src_addr / dst_addr each become separate rules (OR semantics when combined).
    void append_rules_for_family(bool ipv6,
                                 PendingRule::Action action,
                                 uint32_t fwmark,
                                 const FirewallRuleCriteria& criteria,
                                 bool output_scope = false);

    // Sets queued for creation, flushed by apply().
    std::vector<PendingSet> pending_sets_;
    // Per-set element buffers for ipset restore lines, keyed by set name.
    std::map<std::string, std::ostringstream> pending_elements_;
    // Rules queued for insertion into KeenPbrTable, flushed by apply().
    std::vector<PendingRule> pending_rules_;

    // Track created ipsets: set_name -> family (AF_INET/AF_INET6)
    std::map<std::string, int> created_sets_;

    // Track whether chain + jump rule exist for each protocol
    bool chain_v4_created_ = false;
    bool chain_v6_created_ = false;
    static const char* generation_prerouting_chain(FirewallSetGeneration generation);
    static const char* generation_output_chain(FirewallSetGeneration generation);
    static const char* raw_generation_prerouting_chain(
        FirewallSetGeneration generation);
    FirewallSetGeneration target_v4_generation_{FirewallSetGeneration::A};
    FirewallSetGeneration target_v6_generation_{FirewallSetGeneration::A};
    bool apply_prepared_{false};
    bool use_raw_prerouting_{false};

    // DNS redirect (client DNS enforcement) state
    bool dns_redirect_requested_ = false;
    bool router_origin_snat_requested_ = false;
    // Tunnel interfaces whose egress needs masquerading.
    std::vector<std::string> snat_interfaces_;
    bool dns_nat_v4_created_ = false;
    bool dns_nat_v6_created_ = false;

    // Build the nat-table restore script: REDIRECT rules for port 53 and the
    // masquerade rule for router-originated detour traffic.
    static std::string build_dns_nat_script(
        const FirewallGlobalPrefilter& prefilter,
        bool dns_redirect,
        bool router_origin_snat,
        const std::vector<std::string>& snat_interfaces);

#ifdef KEEN_PBR3_TESTING
    friend class IptablesBuilderTest;
    // Allow test access to build_proto_port_fragment
    friend struct IptablesBuilderTestHelper;
#endif
};

// Factory function called from firewall.cpp
std::unique_ptr<Firewall> create_iptables_firewall(
    bool use_raw_prerouting = false);

} // namespace keen_pbr3
