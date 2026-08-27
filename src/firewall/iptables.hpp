#pragma once

#include "firewall.hpp"
#include "ttl_bypass.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keen_pbr3 {

#ifdef KEEN_PBR3_TESTING
namespace testing {
struct IptablesControlResultForTest {
    std::string stdout_output;
    int exit_code{-1};
    bool truncated{false};
    bool timed_out{false};
    bool termination_uncertain{false};
};
using IptablesControlRunnerForTest = std::function<
    IptablesControlResultForTest(const std::vector<std::string>&)>;

void set_iptables_control_runner_for_test(
    IptablesControlRunnerForTest runner);
void reset_iptables_control_runner_for_test();
bool restore_wait_option_supported_for_test(const std::string& program);
bool restore_test_option_supported_for_test(const std::string& program);
std::optional<bool> control_wait_option_supported_for_test(
    const std::string& program);
IptablesControlResultForTest run_iptables_control_for_test(
    const std::vector<std::string>& args);
void reset_restore_wait_option_probe_for_test();
bool xtables_match_registered_for_test(
    const std::string& inventory_path,
    const std::string& match);
FirewallGlobalPrefilter iptables_effective_prefilter_for_test(
    const FirewallGlobalPrefilter& requested,
    bool effective_ipv6,
    const std::string& ipv4_inventory_path,
    const std::string& ipv6_inventory_path);
} // namespace testing
#endif

class IptablesFirewall : public Firewall {
public:
    // Initialize the iptables backend; does not modify firewall state yet.
    explicit IptablesFirewall(RawPreroutingMode raw_prerouting = {});
    // Compatibility constructor: the historical bool always meant IPv4 RAW.
    explicit IptablesFirewall(bool use_raw_prerouting)
        : IptablesFirewall(
              RawPreroutingMode{use_raw_prerouting, false}) {}
    // Kernel firewall state is persistent and is removed only by explicit
    // cleanup(), never as a side effect of C++ object destruction.
    ~IptablesFirewall() override = default;

    void prepare_apply(FirewallApplyMode mode) override;
    std::string static_set_name(const std::string& list_name, int family) const override;

    // Buffer an ipset create command (hash:net family, optional timeout).
    void create_ipset(const std::string& set_name, int family,
                      uint32_t timeout = 0) override;
    void create_udp_peer_set(const std::string& set_name,
                             int family,
                             uint32_t timeout) override;
    bool add_udp_peer(const std::string& set_name,
                      const std::string& source,
                      std::uint16_t destination_port,
                      const std::string& destination) override;
    FirewallExactTcpResetResult install_exact_tcp_reset(
        const FirewallExactTcpResetRule& rule) override;
    bool remove_exact_tcp_reset(
        const FirewallExactTcpResetRule& rule) override;

    // Buffer an iptables/ip6tables -j MARK --set-mark rule for the given ipset.
    void create_mark_rule(uint32_t fwmark,
                          const FirewallRuleCriteria& criteria = {}) override;
    // Buffer a MARK rule for router-originated traffic (mangle OUTPUT hook).
    // Used for DNS detour so dnsmasq upstream queries are policy-routed too.
    void create_output_mark_rule(uint32_t fwmark,
                                 const FirewallRuleCriteria& criteria = {}) override;
    // Buffer an iptables/ip6tables -j DROP rule for the given criteria.
    void create_drop_rule(const FirewallRuleCriteria& criteria = {}) override;
    void create_forward_udp_reject_rule(
        uint32_t expected_fwmark,
        const std::string& dst_set_name,
        std::uint16_t destination_port) override;
    // Buffer NAT REDIRECT rules that force LAN plain-DNS to the local resolver.
    void create_dns_redirect_rules() override;
    // Buffer NAT MASQUERADE rules for traffic leaving via tunnel interfaces.
    void create_tunnel_snat_rules(
        const std::vector<std::string>& interfaces) override;
    void create_source_egress_snat_rules(
        const std::vector<FirewallSourceEgressSnatSelector>& selectors) override;
    OwnedSnatState inspect_owned_snat_state() const override;
    OwnedForwardUdpRejectState
    inspect_forward_udp_reject_state() const override;
    // Buffer an iptables/ip6tables -j RETURN rule for the given criteria.
    void create_pass_rule(const FirewallRuleCriteria& criteria = {}) override;

    // Return an IpsetRestoreVisitor that appends 'add' lines to the pending
    // element buffer for set_name; entries are flushed during apply().
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string& set_name) override;

    // Atomically apply all pending ipsets (via ipset restore) and rules
    // (via iptables-restore / ip6tables-restore), always materializing the
    // KeenPbrTable chain scaffold and PREROUTING jump for diagnostics.
    void apply(FirewallApplyMode mode) override;
    // Destroy all buffered ipsets (ipset destroy) and flush/delete the
    // KeenPbrTable chain from both iptables and ip6tables mangle tables.
    void cleanup() override;
    // Returns FirewallBackend::iptables.
    FirewallBackend backend() const override;
    RawPreroutingMode raw_prerouting_mode() const override {
        return raw_prerouting_;
    }
    bool uses_raw_prerouting() const override {
        return raw_prerouting_.ipv4;
    }

private:
    static constexpr const char* CHAIN_NAME = "KeenPbrTable";
    static constexpr const char* RAW_CHAIN_NAME = "KeenPbrRaw";
    static constexpr const char* RAW_CONNTRACK_CHAIN_NAME =
        "KeenPbrRawCt";
    static constexpr const char* OUTPUT_CHAIN_NAME = "KeenPbrOutput";
    static constexpr const char* DNS_NAT_CHAIN_NAME = "KeenPbrDnsRdr";
    static constexpr const char* SNAT_CHAIN_NAME = "KeenPbrSnat";
    static constexpr const char* META_UDP_443_CHAIN_NAME =
        "KeenPbrMeta443";
    static constexpr const char* EXACT_TCP_RESET_CHAIN_NAME =
        "KeenPbrTcpRst";
    static constexpr const char* DNS_NAT_VALIDATION_CHAIN_NAME =
        "KeenPbrDnsValidate";
    static constexpr const char* SNAT_VALIDATION_CHAIN_NAME =
        "KeenPbrSnatValidate";
    void cleanup_live_impl(bool preserve_dynamic_sets = false,
                           bool sweep_live_state = false);
    void cleanup_impl();
    void cleanup_rules_impl(bool sweep_live_state = false);
    void cleanup_nat_rules_impl(bool sweep_live_state = false);
    void apply_nat_rules(
        bool effective_ipv6,
        FirewallApplyMode mode,
        const FirewallGlobalPrefilter& prefilter);
    void apply_nat_rules(bool effective_ipv6, FirewallApplyMode mode);
    void cleanup_saved_sets(bool preserve_dynamic_sets);
    static void cleanup_legacy_generation_chains(const char* command);

    // Describes a set to be created via 'ipset restore'.
    struct PendingSet {
        std::string name;
        std::string family_str; // "inet" or "inet6"
        uint32_t timeout;       // entry TTL in seconds (0 = no timeout)
        std::optional<uint32_t> hashsize;
        std::optional<uint32_t> maxelem;
        bool source_udp_peer{false};
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

    struct PendingForwardUdpReject {
        std::string set_name;
        bool ipv6{false};
        uint32_t fwmark{0U};
        uint32_t fwmark_mask{0U};
        std::uint16_t destination_port{0U};
    };

    struct PublishedUdpPeerClassifier {
        int family{AF_INET};
        uint32_t timeout{0};
        FirewallSetGeneration generation{FirewallSetGeneration::A};
        // Exact rules as rendered by `iptables -S <active generation>`.
        // The vector includes MARK, optional CONNMARK save, and RETURN so a
        // surviving set match cannot silently fall through to later policy.
        std::vector<std::string> expected_rules;
        // RAW PREROUTING classifies before conntrack. Its mangle companion
        // must return this expiring tuple before any generic save-mark rule,
        // otherwise the temporary authority can leak into persistent ctmark.
        std::optional<std::string> expected_raw_conntrack_bypass_rule;
    };

    enum class LiveGenerationState { A, B, Missing, Invalid };

    // Build the 'create <name> hash:net family <f> [timeout <t>]' line.
    static std::string build_ipset_create_line(const PendingSet& ps);
    static bool is_dynamic_set_name(const std::string& set_name);
    static bool dynamic_set_schema_compatible(
        const std::string& xml,
        const PendingSet& expected);
    void preflight_dynamic_set_schemas(bool effective_ipv6) const;
    // RulesOnly never creates a set, so every set the staged rules name must
    // already be live with the expected family, type and timeout. Throws
    // FirewallRulesOnlyError, which the caller turns into a PreserveSets
    // restage; nothing has been touched by then.
    void preflight_reused_set_schemas(bool effective_ipv6) const;
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
        bool ipv6,
        const std::string& prerouting_chain,
        bool replace_active_chain,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {});
    // Compatibility helper: IPv4 RAW PREROUTING.
    static std::string build_raw_prerouting_script(
        const std::string& prerouting_chain,
        bool replace_active_chain,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {}) {
        return build_raw_prerouting_script(
            false, prerouting_chain, replace_active_chain, rules, prefilter);
    }
    static std::string build_output_generation_script(
        bool ipv6,
        const std::string& output_chain,
        bool replace_active_chain,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {});
    // Compatibility helper: IPv4 OUTPUT generation.
    static std::string build_output_generation_script(
        const std::string& output_chain,
        bool replace_active_chain,
        const std::vector<PendingRule>& rules,
        const FirewallGlobalPrefilter& prefilter = {}) {
        return build_output_generation_script(
            false, output_chain, replace_active_chain, rules, prefilter);
    }
    static std::string build_raw_conntrack_script(
        bool ipv6,
        bool replace_active_chain,
        const FirewallGlobalPrefilter& prefilter = {},
        const std::vector<PendingRule>& rules = {});
    // Compatibility helper: the IPv4 mangle companion.
    static std::string build_raw_conntrack_script(
        bool replace_active_chain,
        const FirewallGlobalPrefilter& prefilter = {},
        const std::vector<PendingRule>& rules = {}) {
        return build_raw_conntrack_script(
            false, replace_active_chain, prefilter, rules);
    }
    static std::string build_forward_udp_reject_script(
        bool ipv6,
        const std::string& generation_chain,
        const std::vector<PendingForwardUdpReject>& rules);
    static std::string build_exact_tcp_reset_rule_line(
        const FirewallExactTcpResetRule& rule);
    static std::vector<std::string> build_exact_tcp_reset_rule_spec(
        const FirewallExactTcpResetRule& rule);
    static bool exact_tcp_reset_rules_match(
        const std::string& rendered_rules,
        const std::vector<FirewallExactTcpResetRule>& expected_rules);
    static std::string build_exact_tcp_reset_script(
        bool chain_exists,
        std::size_t hook_count,
        const std::vector<FirewallExactTcpResetRule>& rules);
    FirewallExactTcpResetResult replace_exact_tcp_reset_rules_locked(
        const std::vector<FirewallExactTcpResetRule>& rules,
        bool cleanup_on_verification_failure = true);
    void stage_forward_reject_generation(
        bool ipv6,
        FirewallSetGeneration generation) const;
    static std::string build_conntrack_prefilter_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain);
    static std::string build_skip_marked_packet_line(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain);
    static std::string build_bypass_inbound_interface_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain);
    static std::string build_bypass_source_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain,
        bool ipv6);
    static std::string build_bypass_bridge_source_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain,
        bool ipv6);
    // Build early RETURN lines for the global prefilter.
    static std::string build_prefilter_lines(
        const FirewallGlobalPrefilter& prefilter,
        const std::string& chain = CHAIN_NAME,
        bool allow_conntrack = true,
        bool ipv6 = false);
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
    static bool forward_reject_generation_references_are_owned(
        const std::string& rules,
        LiveGenerationState state,
        const std::string& generation_a,
        const std::string& generation_b);
    static FirewallSetGeneration target_generation_for_states(
        LiveGenerationState primary,
        LiveGenerationState secondary);
    void reconcile_hooks(bool ipv6) const;
    // Keeps our single tagged RETURN first in the firmware's TTL chain, when
    // that chain exists and the kernel has the matches. Never creates,
    // flushes or deletes the chain, and never touches a rule without our tag.
    void reconcile_ttl_bypass() const;
    // Takes our rule back out of the firmware chain on teardown.
    void remove_ttl_bypass() const;

public:
    // Last observed state of the TTL bypass, for health reporting.
    TtlBypassState ttl_bypass_state() const;
    std::string ttl_bypass_state_name() const override;
    std::string ttl_bypass_state_detail() const override;
    std::string ttl_bypass_detail() const;
    PpeDeoffloadSnapshot ppe_deoffload_snapshot() const override;
    PpeObservationRefreshResult
    refresh_ppe_deoffload_observation() noexcept override;
#ifdef KEEN_PBR3_TESTING
    void remove_ttl_bypass_for_test() const;
    void reconcile_ppe_deoffload_for_test();
    void remove_ppe_deoffload_for_test();
#endif

private:
    void reconcile_ppe_deoffload() noexcept;
    void remove_ppe_deoffload_strict();
    void publish_ppe_deoffload_snapshot(
        PpeDeoffloadSnapshot snapshot) const;
    void verify_applied_generation(
        bool ipv6,
        FirewallSetGeneration target) const;
    std::map<std::string, PublishedUdpPeerClassifier>
    build_pending_udp_peer_classifiers(
        const FirewallGlobalPrefilter& prefilter,
        bool effective_ipv6) const;
    bool udp_peer_classifier_is_published(
        const std::string& set_name,
        const PublishedUdpPeerClassifier& classifier) const noexcept;
    static bool classifier_rules_present(
        const std::string& rules,
        const std::string& set_name,
        const std::vector<std::string>& expected_rules);
    static bool raw_conntrack_bypass_precedes_save(
        const std::string& rules,
        const std::string& set_name,
        const std::string& expected_rule);
    static size_t count_exact_jump(
        const std::string& rules,
        const std::string& source_chain,
        const std::string& target_chain);
    static void reconcile_hook(
        const char* command,
        const char* table,
        const char* builtin_chain,
        const char* target_chain);
    static const char* forward_reject_generation_chain(
        FirewallSetGeneration generation);
    LiveGenerationState inspect_forward_reject_generation(
        bool ipv6) const;
    FirewallSetGeneration select_forward_reject_target_generation(
        bool ipv6) const;
    void ensure_forward_reject_target_generation_inactive(
        bool ipv6,
        FirewallSetGeneration target) const;
    void publish_forward_reject_dispatcher(
        bool ipv6,
        FirewallSetGeneration generation) const;
    void publish_and_verify_forward_reject_generation(
        bool ipv6,
        FirewallSetGeneration generation);
    void verify_forward_reject_generation(
        bool ipv6,
        FirewallSetGeneration generation) const;
    void disable_forward_reject_scaffold(bool ipv6) const;
    static OwnedSnatState inspect_owned_snat_state(
        const char* command,
        bool expected,
        const std::vector<std::string>& expected_interfaces,
        const std::vector<FirewallSourceEgressSnatSelector>&
            expected_source_egress_selectors,
        uint32_t expected_fwmark_mask);
    static OwnedSnatState combine_owned_snat_states(
        OwnedSnatState ipv4,
        OwnedSnatState ipv6);
    static void verify_owned_snat_after_apply(
        const char* command,
        bool expected,
        const std::vector<std::string>& expected_interfaces,
        const std::vector<FirewallSourceEgressSnatSelector>&
            expected_source_egress_selectors,
        uint32_t expected_fwmark_mask);
    static void remove_all_hooks(
        const char* command,
        const char* table,
        const char* builtin_chain,
        const char* target_chain);
    static void remove_nat_chain_checked(
        const char* command,
        const char* builtin_chain,
        const char* target_chain);
    static bool ipv6_nat_table_available();
    void cleanup_nat_family_checked(const char* command, bool ipv6);
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
    std::vector<PendingForwardUdpReject> pending_forward_udp_rejects_;

    // Track created ipsets: set_name -> family (AF_INET/AF_INET6)
    std::map<std::string, int> created_sets_;
    // Pair sets additionally retain their default timeout for safe live adds.
    std::map<std::string, std::pair<int, uint32_t>> udp_peer_sets_;
    // Snapshot committed only after the full firewall apply and its health
    // checks succeed. Pending declarations are never treated as live proof.
    std::map<std::string, PublishedUdpPeerClassifier>
        published_udp_peer_classifiers_;
    mutable std::mutex pair_state_mutex_;

    // Track whether chain + jump rule exist for each protocol
    bool chain_v4_created_ = false;
    bool chain_v6_created_ = false;
    bool forward_reject_v4_created_ = false;
    bool forward_reject_v6_created_ = false;
    bool exact_tcp_reset_chain_created_ = false;
    // A restore command can time out after the kernel accepted COMMIT. Keep
    // this separate from the last verified snapshot so callers never mistake
    // an indeterminate publication for an absent short-lived reset chain.
    bool exact_tcp_reset_publication_uncertain_ = false;
    std::vector<FirewallExactTcpResetRule> installed_exact_tcp_resets_;
    static const char* generation_prerouting_chain(FirewallSetGeneration generation);
    static const char* generation_output_chain(FirewallSetGeneration generation);
    static const char* raw_generation_prerouting_chain(
        FirewallSetGeneration generation);
    FirewallSetGeneration target_v4_generation_{FirewallSetGeneration::A};
    FirewallSetGeneration target_v6_generation_{FirewallSetGeneration::A};
    FirewallSetGeneration target_forward_reject_v4_generation_{
        FirewallSetGeneration::A};
    FirewallSetGeneration target_forward_reject_v6_generation_{
        FirewallSetGeneration::A};
    bool last_applied_forward_reject_v4_expected_{false};
    bool last_applied_forward_reject_v6_expected_{false};
    bool last_applied_forward_reject_v6_managed_{false};
    FirewallSetGeneration last_applied_forward_reject_v4_generation_{
        FirewallSetGeneration::A};
    FirewallSetGeneration last_applied_forward_reject_v6_generation_{
        FirewallSetGeneration::A};
    std::vector<PendingForwardUdpReject>
        last_applied_forward_udp_rejects_;
    bool apply_prepared_{false};
    FirewallApplyMode prepared_mode_{FirewallApplyMode::Destructive};
    // Under RulesOnly the rule chains still flip to the inactive A/B slot, but
    // the static sets they name must stay the live ones: nothing recreates a
    // set, so a name from the target slot would point at a set that is not
    // there. Every other mode keeps the two in step; RulesOnly leaves these
    // untouched from the previous apply - after one rules-only flip the live
    // rules name the opposite slot's sets, so "the live rules generation" is
    // NOT the static slot, and recomputing these from it demands sets that
    // never existed.
    FirewallSetGeneration target_static_v4_generation_{FirewallSetGeneration::A};
    FirewallSetGeneration target_static_v6_generation_{FirewallSetGeneration::A};
    RawPreroutingMode raw_prerouting_{};
    // Per-family shorthand: the raw table is per netfilter family, and every
    // call site already knows which family it is emitting for.
    bool uses_raw_prerouting(bool ipv6) const noexcept {
        return raw_prerouting_.uses(ipv6);
    }
    // Result of the last TTL bypass reconciliation, for health. Guarded
    // because apply() runs on the firewall worker while health is read from
    // an API thread.
    mutable std::mutex ttl_bypass_mutex_;
    mutable TtlBypassState ttl_bypass_state_{TtlBypassState::chain_absent};
    mutable std::string ttl_bypass_detail_;
    mutable std::mutex ppe_deoffload_mutex_;
    mutable PpeDeoffloadSnapshot ppe_deoffload_snapshot_;
    mutable std::optional<PpeDeoffloadGraphSpec>
        published_ppe_deoffload_spec_;

    // DNS redirect (client DNS enforcement) state
    bool dns_redirect_requested_ = false;
    bool router_origin_snat_requested_ = false;
    // Tunnel interfaces whose egress needs masquerading.
    std::vector<std::string> snat_interfaces_;
    // Native-VPN source pools whose direct egress needs masquerading.
    std::vector<FirewallSourceEgressSnatSelector>
        source_egress_snat_selectors_;
    // Last successfully applied SNAT contract. Runtime health inspection must
    // validate the desired state, including the intentional absence of SNAT.
    bool last_applied_snat_v4_expected_ = false;
    bool last_applied_snat_v6_expected_ = false;
    // An IPv6 family which participated in the last successful transaction
    // remains part of runtime inspection even when its desired SNAT state is
    // absence. This lets the monitor distinguish stale IPv6 artifacts from a
    // lost expected IPv6 scaffold without probing unsupported routers.
    bool last_applied_snat_v6_managed_ = false;
    std::vector<std::string> last_applied_snat_interfaces_;
    std::vector<FirewallSourceEgressSnatSelector>
        last_applied_source_egress_snat_selectors_v4_;
    std::vector<FirewallSourceEgressSnatSelector>
        last_applied_source_egress_snat_selectors_v6_;
    uint32_t last_applied_snat_fwmark_mask_ = 0xFFFFFFFFu;
    bool dns_nat_v4_created_ = false;
    bool dns_nat_v6_created_ = false;

    // Build the nat-table restore script: REDIRECT rules for port 53 and the
    // masquerade rule for router-originated detour traffic.
    static std::string build_dns_nat_script(
        const FirewallGlobalPrefilter& prefilter,
        bool dns_redirect,
        bool router_origin_snat,
        const std::vector<std::string>& snat_interfaces,
        bool ipv6 = false,
        uint32_t fwmark_mask = 0xFFFFFFFFu,
        const std::vector<FirewallSourceEgressSnatSelector>&
            source_egress_snat_selectors = {},
        const std::map<std::string, std::pair<int, uint32_t>>&
            udp_peer_sets = {});
    static std::string build_nat_validation_script(
        const std::string& nat_script);
    static void preflight_nat_restore(
        const std::string& restore_program,
        const std::string& nat_script);

#ifdef KEEN_PBR3_TESTING
    friend class IptablesBuilderTest;
    // Allow test access to build_proto_port_fragment
    friend struct IptablesBuilderTestHelper;
#endif
    friend void cleanup_stale_iptables_ppe_deoffload_strict();
};

// Factory function called from firewall.cpp
std::unique_ptr<Firewall> create_iptables_firewall(
    RawPreroutingMode raw_prerouting = {});

// Backend-transition/lifecycle bridge. nftables uses this inside the same
// serialized firewall apply so an owned legacy IPv4 iptables PPE graph cannot
// survive a backend switch. A missing iptables tool is a no-op only when no
// durable PPE owner marker exists.
void cleanup_stale_iptables_ppe_deoffload_strict();

} // namespace keen_pbr3
