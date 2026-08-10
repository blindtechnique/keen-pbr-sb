#include "iptables.hpp"
#include "ipset_restore_pipe.hpp"
#include "port_spec_util.hpp"
#include "../log/logger.hpp"
#include "../util/format_compat.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/safe_exec.hpp"
#include <rapidxml.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>

namespace keen_pbr3 {

namespace {

bool is_ipv6_addr(const std::string& addr) {
    return addr.find(':') != std::string::npos;
}

std::vector<std::string> filter_addrs_by_family(const std::vector<std::string>& addrs,
                                                bool ipv6) {
    std::vector<std::string> filtered;
    for (const auto& addr : addrs) {
        if (is_ipv6_addr(addr) == ipv6) {
            filtered.push_back(addr);
        }
    }
    return filtered;
}

std::vector<FirewallSourceEgressSnatSelector>
filter_source_egress_snat_selectors_by_family(
    const std::vector<FirewallSourceEgressSnatSelector>& selectors,
    bool ipv6) {
    std::vector<FirewallSourceEgressSnatSelector> filtered;
    for (const auto& selector : selectors) {
        if (is_ipv6_addr(selector.cidr) == ipv6) {
            filtered.push_back(selector);
        }
    }
    return filtered;
}

std::vector<L4Proto> expand_l4_protos(L4Proto proto) {
    if (proto == L4Proto::TcpUdp) {
        return {L4Proto::Tcp, L4Proto::Udp};
    }
    return {proto};
}

std::vector<L4Proto> expand_l4_protos_for_iptables(const FirewallRuleCriteria& criteria) {
    if (criteria.proto == L4Proto::Any
        && (!criteria.src_port.empty() || !criteria.dst_port.empty())) {
        // iptables requires an explicit L4 protocol whenever port matchers are used.
        return {L4Proto::Tcp, L4Proto::Udp};
    }
    return expand_l4_protos(criteria.proto);
}

} // namespace

IptablesFirewall::IptablesFirewall(bool use_raw_prerouting)
    : use_raw_prerouting_(use_raw_prerouting) {
    // S80keen-pbr capability-gates raw PREROUTING before adding the daemon
    // argument. Do not repeat `iptables -t raw -S` here: Keenetic may briefly
    // hold the xtables lock between the init probe and daemon construction,
    // which is not evidence that the raw table disappeared. The transactional
    // restore in apply() is authoritative and its failure is retried without
    // taking down the API process.
}

static bool exact_udp_peer_matches_family(const std::string& source,
                                          std::uint16_t destination_port,
                                          const std::string& destination,
                                          int family) {
    if ((family != AF_INET && family != AF_INET6) || destination_port == 0U ||
        source.empty() ||
        destination.empty() || source.find('/') != std::string::npos ||
        destination.find('/') != std::string::npos) {
        return false;
    }
    std::array<unsigned char, 16> source_bytes{};
    std::array<unsigned char, 16> destination_bytes{};
    return ::inet_pton(family, source.c_str(), source_bytes.data()) == 1 &&
           ::inet_pton(
               family, destination.c_str(), destination_bytes.data()) == 1;
}

static bool valid_exact_tcp_reset_rule(
    const FirewallExactTcpResetRule& rule) {
    if (rule.source.empty() || rule.destination.empty() ||
        rule.source_port == 0U || rule.destination_port == 0U ||
        rule.full_mark == 0U ||
        rule.source.find('/') != std::string::npos ||
        rule.destination.find('/') != std::string::npos) {
        return false;
    }

    std::array<unsigned char, 4> source_bytes{};
    std::array<unsigned char, 4> destination_bytes{};
    return ::inet_pton(
               AF_INET, rule.source.c_str(), source_bytes.data()) == 1 &&
           ::inet_pton(
               AF_INET,
               rule.destination.c_str(),
               destination_bytes.data()) == 1;
}

const char* IptablesFirewall::generation_prerouting_chain(
    FirewallSetGeneration generation) {
    return generation == FirewallSetGeneration::A
        ? "KeenPbrTable_A"
        : "KeenPbrTable_B";
}

const char* IptablesFirewall::generation_output_chain(
    FirewallSetGeneration generation) {
    return generation == FirewallSetGeneration::A
        ? "KeenPbrOutput_A"
        : "KeenPbrOutput_B";
}

const char* IptablesFirewall::raw_generation_prerouting_chain(
    FirewallSetGeneration generation) {
    return generation == FirewallSetGeneration::A
        ? "KeenPbrRaw_A"
        : "KeenPbrRaw_B";
}

const char* IptablesFirewall::forward_reject_generation_chain(
    FirewallSetGeneration generation) {
    return generation == FirewallSetGeneration::A
        ? "KeenPbrMeta443_A"
        : "KeenPbrMeta443_B";
}

void IptablesFirewall::prepare_apply(FirewallApplyMode mode) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    pending_forward_udp_rejects_.clear();
    udp_peer_sets_.clear();
    dns_redirect_requested_ = false;
    router_origin_snat_requested_ = false;
    snat_interfaces_.clear();
    source_egress_snat_selectors_.clear();

    target_v4_generation_ = mode == FirewallApplyMode::Destructive
        ? FirewallSetGeneration::A
        : select_target_generation(false);
    target_v6_generation_ = mode == FirewallApplyMode::Destructive
        ? FirewallSetGeneration::A
        : (!ipv6_enabled() || !ipv6_backend_available()
            ? FirewallSetGeneration::A
            : select_target_generation(true));
    apply_prepared_ = true;
}

std::string IptablesFirewall::static_set_name(const std::string& list_name,
                                              int family) const {
    const FirewallSetGeneration generation = family == AF_INET6
        ? target_v6_generation_
        : target_v4_generation_;
    // ipset names are limited to 31 bytes. Replacing the old seven-byte
    // kpbr4_/kpbr6_ prefix with another seven-byte prefix preserves the
    // existing 24-byte list-tag allowance.
    const char slot = generation == FirewallSetGeneration::A ? 's' : 'S';
    return keen_pbr3::format("kpbr{}{}_{}", family == AF_INET6 ? 6 : 4, slot, list_name);
}

void IptablesFirewall::create_ipset(const std::string& set_name, int family,
                                     uint32_t timeout) {
    PendingSet ps;
    ps.name = set_name;
    ps.family_str = (family == AF_INET6) ? "inet6" : "inet";
    ps.timeout = timeout;
    const auto existing = std::find_if(
        pending_sets_.begin(), pending_sets_.end(),
        [&set_name](const PendingSet& pending) { return pending.name == set_name; });
    if (existing == pending_sets_.end()) {
        pending_sets_.push_back(std::move(ps));
    } else if (existing->family_str != ps.family_str ||
               existing->timeout != ps.timeout ||
               existing->source_udp_peer != ps.source_udp_peer) {
        throw FirewallError("conflicting ipset declaration for " + set_name);
    }
    created_sets_[set_name] = family;
}

void IptablesFirewall::create_udp_peer_set(const std::string& set_name,
                                            int family,
                                            uint32_t timeout) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    if (timeout == 0U) {
        throw FirewallError("UDP peer set requires a non-zero timeout");
    }
    if (family != AF_INET && family != AF_INET6) {
        throw FirewallError("invalid UDP peer set family");
    }
    PendingSet ps;
    ps.name = set_name;
    ps.family_str = family == AF_INET6 ? "inet6" : "inet";
    ps.timeout = timeout;
    ps.source_udp_peer = true;
    const auto existing = std::find_if(
        pending_sets_.begin(), pending_sets_.end(),
        [&set_name](const PendingSet& pending) {
            return pending.name == set_name;
        });
    if (existing == pending_sets_.end()) {
        pending_sets_.push_back(std::move(ps));
    } else if (existing->family_str != ps.family_str ||
               existing->timeout != ps.timeout ||
               !existing->source_udp_peer) {
        throw FirewallError("conflicting ipset declaration for " + set_name);
    }
    created_sets_[set_name] = family;
    udp_peer_sets_[set_name] = {family, timeout};
}

bool IptablesFirewall::add_udp_peer(const std::string& set_name,
                                    const std::string& source,
                                    std::uint16_t destination_port,
                                    const std::string& destination) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    const auto set = published_udp_peer_classifiers_.find(set_name);
    if (set == published_udp_peer_classifiers_.end() ||
        !exact_udp_peer_matches_family(
            source, destination_port, destination, set->second.family)) {
        return false;
    }
    // Refuse to grant even a short-lived tuple into already-drifted rules.
    // Re-check after the write as well, because KeeneticOS can replace its
    // firewall between these two operations.
    if (!udp_peer_classifier_is_published(set_name, set->second)) {
        return false;
    }
    const std::string peer = source + ",udp:" +
        std::to_string(destination_port) + "," + destination;
    const bool inserted = safe_exec(
            {"ipset",
             "-exist",
             "add",
             set_name,
             peer,
             "timeout",
             std::to_string(set->second.timeout)},
            /*suppress_output=*/true) == 0;
    if (!inserted) {
        return false;
    }
    if (udp_peer_classifier_is_published(set_name, set->second)) {
        return true;
    }

    // A successful element write without a live classifier must not remain
    // latent: firmware may restore an old chain after our proof failed.
    (void)safe_exec(
        {"ipset", "-exist", "del", set_name, peer},
        /*suppress_output=*/true);
    return false;
}

void IptablesFirewall::append_rules_for_family(bool ipv6,
                                               PendingRule::Action action,
                                               uint32_t fwmark,
                                               const FirewallRuleCriteria& criteria,
                                               bool output_scope) {
    const std::vector<std::string> any_addr{""};
    const auto filtered_src_addrs = criteria.src_addr.empty()
        ? any_addr
        : filter_addrs_by_family(criteria.src_addr, ipv6);
    const auto filtered_dst_addrs = criteria.dst_addr.empty()
        ? any_addr
        : filter_addrs_by_family(criteria.dst_addr, ipv6);
    if ((!criteria.src_addr.empty() && filtered_src_addrs.empty())
        || (!criteria.dst_addr.empty() && filtered_dst_addrs.empty())) {
        return;
    }

    for (const auto proto : expand_l4_protos_for_iptables(criteria)) {
        const std::vector<std::string>& src_addrs = filtered_src_addrs;
        const std::vector<std::string>& dst_addrs = filtered_dst_addrs;
        for (const auto& src : src_addrs) {
            for (const auto& dst : dst_addrs) {
                PendingRule pr;
                pr.ipv6     = ipv6;
                pr.action   = action;
                pr.fwmark   = fwmark;
                pr.fwmark_mask = fwmark_mask();
                pr.criteria = criteria;
                pr.criteria.proto = proto;
                pr.criteria.src_addr = src.empty()
                    ? std::vector<std::string>{}
                    : std::vector<std::string>{src};
                pr.criteria.dst_addr = dst.empty()
                    ? std::vector<std::string>{}
                    : std::vector<std::string>{dst};
                if (output_scope && action == PendingRule::Mark) {
                    pr.fwmark |= kRouterOriginMark;
                    pr.fwmark_mask |= kRouterOriginMark;
                }
                pr.output = output_scope;
                pending_rules_.push_back(std::move(pr));
            }
        }
    }
}

void IptablesFirewall::create_mark_rule(uint32_t fwmark,
                                        const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value() &&
        criteria.src_udp_peer_set_name.has_value()) {
        throw FirewallError(
            "a rule cannot match both destination and UDP peer sets");
    }
    const auto& set_name = criteria.src_udp_peer_set_name.has_value()
        ? criteria.src_udp_peer_set_name
        : criteria.dst_set_name;
    if (set_name.has_value()) {
        auto it = created_sets_.find(*set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Mark, fwmark, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Mark, fwmark, criteria);
    append_rules_for_family(true, PendingRule::Mark, fwmark, criteria);
}

void IptablesFirewall::create_output_mark_rule(uint32_t fwmark,
                                               const FirewallRuleCriteria& criteria) {
    router_origin_snat_requested_ = true;
    // Router-originated traffic (dnsmasq upstream queries, list downloads with
    // detour) never traverses PREROUTING, so DNS detour marks must also be
    // present in mangle OUTPUT. Ipset-based criteria are intentionally not
    // supported here: only static addr/port matches are used for detours.
    append_rules_for_family(false, PendingRule::Mark, fwmark, criteria,
                            /*output_scope=*/true);
    append_rules_for_family(true, PendingRule::Mark, fwmark, criteria,
                            /*output_scope=*/true);
}

void IptablesFirewall::create_drop_rule(const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value() &&
        criteria.src_udp_peer_set_name.has_value()) {
        throw FirewallError(
            "a rule cannot match both destination and UDP peer sets");
    }
    const auto& set_name = criteria.src_udp_peer_set_name.has_value()
        ? criteria.src_udp_peer_set_name
        : criteria.dst_set_name;
    if (set_name.has_value()) {
        auto it = created_sets_.find(*set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Drop, 0, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Drop, 0, criteria);
    append_rules_for_family(true, PendingRule::Drop, 0, criteria);
}

void IptablesFirewall::create_forward_udp_reject_rule(
    uint32_t expected_fwmark,
    const std::string& dst_set_name,
    std::uint16_t destination_port) {
    const auto set = created_sets_.find(dst_set_name);
    const uint32_t owned_mask = fwmark_mask();
    if (set == created_sets_.end()) {
        throw FirewallError(
            "forward UDP reject references an undeclared destination set: " +
            dst_set_name);
    }
    if (destination_port == 0U || owned_mask == 0U ||
        expected_fwmark == 0U || (expected_fwmark & ~owned_mask) != 0U) {
        throw FirewallError("invalid forward UDP reject mark/port contract");
    }
    PendingForwardUdpReject pending;
    pending.set_name = dst_set_name;
    pending.ipv6 = set->second == AF_INET6;
    pending.fwmark = expected_fwmark;
    pending.fwmark_mask = owned_mask;
    pending.destination_port = destination_port;
    pending_forward_udp_rejects_.push_back(std::move(pending));
}

void IptablesFirewall::create_pass_rule(const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value() &&
        criteria.src_udp_peer_set_name.has_value()) {
        throw FirewallError(
            "a rule cannot match both destination and UDP peer sets");
    }
    const auto& set_name = criteria.src_udp_peer_set_name.has_value()
        ? criteria.src_udp_peer_set_name
        : criteria.dst_set_name;
    if (set_name.has_value()) {
        auto it = created_sets_.find(*set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Pass, 0, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Pass, 0, criteria);
    append_rules_for_family(true, PendingRule::Pass, 0, criteria);
}

void IptablesFirewall::create_tunnel_snat_rules(
    const std::vector<std::string>& interfaces) {
    if (interfaces.empty()) {
        return;
    }
    router_origin_snat_requested_ = true;
    for (const auto& iface : interfaces) {
        if (std::find(snat_interfaces_.begin(), snat_interfaces_.end(), iface) ==
            snat_interfaces_.end()) {
            snat_interfaces_.push_back(iface);
        }
    }
}

void IptablesFirewall::create_source_egress_snat_rules(
    const std::vector<FirewallSourceEgressSnatSelector>& selectors) {
    for (const auto& selector : selectors) {
        if (selector.interface.empty() || selector.cidr.empty()) {
            continue;
        }
        source_egress_snat_selectors_.push_back(selector);
    }
    std::sort(
        source_egress_snat_selectors_.begin(),
        source_egress_snat_selectors_.end());
    source_egress_snat_selectors_.erase(
        std::unique(
            source_egress_snat_selectors_.begin(),
            source_egress_snat_selectors_.end()),
        source_egress_snat_selectors_.end());
    if (!source_egress_snat_selectors_.empty()) {
        router_origin_snat_requested_ = true;
    }
}

void IptablesFirewall::create_dns_redirect_rules() {
    dns_redirect_requested_ = true;
}

std::string IptablesFirewall::build_dns_nat_script(
    const FirewallGlobalPrefilter& prefilter,
    bool dns_redirect,
    bool router_origin_snat,
    const std::vector<std::string>& snat_interfaces,
    bool ipv6,
    uint32_t fwmark_mask,
    const std::vector<FirewallSourceEgressSnatSelector>&
        source_egress_snat_selectors,
    const std::map<std::string, std::pair<int, uint32_t>>&
        udp_peer_sets) {
    std::vector<std::string> iface_frags;
    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()) {
        for (const auto& iface : *prefilter.inbound_interfaces) {
            iface_frags.push_back(" -i " + iface);
        }
        const auto& source_cidrs = ipv6
            ? prefilter.include_source_cidrs_v6
            : prefilter.include_source_cidrs_v4;
        for (const auto& cidr : source_cidrs) {
            iface_frags.push_back(" -s " + cidr);
        }
    } else {
        iface_frags.push_back("");
    }

    std::string s;
    s += "*nat\n";
    if (dns_redirect) {
        // Keep the builtin hook outside the restore transaction. With
        // --noflush the existing hook continues to point at this chain while
        // the chain contents are replaced atomically; a failed COMMIT leaves
        // the previously working redirect untouched.
        s += keen_pbr3::format(
            ":{} - [0:0]\n-F {}\n",
            DNS_NAT_CHAIN_NAME,
            DNS_NAT_CHAIN_NAME);
        s += build_bypass_inbound_interface_lines(
            prefilter, DNS_NAT_CHAIN_NAME);
        s += build_bypass_source_lines(
            prefilter, DNS_NAT_CHAIN_NAME, ipv6);
        s += build_bypass_bridge_source_lines(
            prefilter, DNS_NAT_CHAIN_NAME, ipv6);
        const auto& dns_only_bypass_selectors = ipv6
            ? prefilter.dns_redirect_bypass_source_selectors_v6
            : prefilter.dns_redirect_bypass_source_selectors_v4;
        for (const auto& selector : dns_only_bypass_selectors) {
            if (selector.interface.empty()) {
                continue;
            }
            s += keen_pbr3::format(
                "-A {} -i {} -s {} -j RETURN\n",
                DNS_NAT_CHAIN_NAME,
                selector.interface,
                selector.cidr);
        }
        const auto& local_destination_selectors = ipv6
            ? prefilter.dns_redirect_local_destination_selectors_v6
            : prefilter.dns_redirect_local_destination_selectors_v4;
        for (const auto& selector : local_destination_selectors) {
            if (selector.interface.empty() ||
                selector.destination.empty()) {
                continue;
            }
            for (const char* proto : {"udp", "tcp"}) {
                s += keen_pbr3::format(
                    "-A {} -i {} -d {} -p {} --dport 53 -j RETURN\n",
                    DNS_NAT_CHAIN_NAME,
                    selector.interface,
                    selector.destination,
                    proto);
            }
        }
        for (const auto& [set_name, declaration] : udp_peer_sets) {
            const bool set_is_ipv6 = declaration.first == AF_INET6;
            if (set_is_ipv6 != ipv6) {
                continue;
            }
            // WhatsApp media may use UDP/53 without carrying DNS. Only an
            // already-confirmed exact source+port+destination tuple bypasses
            // client DNS enforcement; ordinary UDP/53 is still redirected.
            s += keen_pbr3::format(
                "-A {} -p udp --dport 53 -m set --match-set {} "
                "src,dst,dst -j RETURN\n",
                DNS_NAT_CHAIN_NAME,
                set_name);
        }
        for (const auto& iface_frag : iface_frags) {
            for (const char* proto : {"udp", "tcp"}) {
                s += keen_pbr3::format(
                    "-A {}{} -p {} --dport 53 -j REDIRECT --to-ports 53\n",
                    DNS_NAT_CHAIN_NAME, iface_frag, proto);
            }
        }
    }
    if (router_origin_snat) {
        // Without this the packet keeps the source address chosen before the
        // mark was applied and the tunnel peer drops it.
        s += keen_pbr3::format(
            ":{} - [0:0]\n-F {}\n",
            SNAT_CHAIN_NAME,
            SNAT_CHAIN_NAME);
        s += keen_pbr3::format(
            "-A {} -m mark --mark {:#x}/{:#x} -j MASQUERADE\n",
            SNAT_CHAIN_NAME, kRouterOriginMark, kRouterOriginMark);
        // Forwarded traffic from networks the firmware does not masquerade for
        // this interface - clients of a VPN server running on the router, guest
        // segments, anything routed here by policy rather than by the firmware.
        // Flows the firmware already translated keep their conntrack entry and
        // are unaffected, so this only fills the gap.
        for (const auto& iface : snat_interfaces) {
            s += keen_pbr3::format(
                "-A {} -o {} -m mark ! --mark 0x0/{:#x} -j MASQUERADE\n",
                SNAT_CHAIN_NAME, iface, fwmark_mask);
        }
        for (const auto& selector : source_egress_snat_selectors) {
            if (is_ipv6_addr(selector.cidr) != ipv6) {
                continue;
            }
            s += keen_pbr3::format(
                "-A {} -s {} -o {} -j MASQUERADE\n",
                SNAT_CHAIN_NAME,
                selector.cidr,
                selector.interface);
        }
    }
    s += "COMMIT\n";
    return s;
}

std::unique_ptr<ListEntryVisitor> IptablesFirewall::create_batch_loader(
    const std::string& set_name) {
    auto& buf = pending_elements_[set_name];
    return std::make_unique<IpsetRestoreVisitor>(buf, set_name);
}

// Inserts "-w <seconds>" right after the program name for the restore tools.
static std::vector<std::string> with_wait_option(const std::vector<std::string>& args) {
    std::vector<std::string> out;
    out.reserve(args.size() + 2);
    out.push_back(args.front());
    out.emplace_back("-w");
    out.emplace_back("10");
    out.insert(out.end(), args.begin() + 1, args.end());
    return out;
}

static bool is_restore_tool(const std::string& program) {
    return program == "iptables-restore" || program == "ip6tables-restore";
}

// IPv4 and IPv6 restore binaries are not guaranteed to be the same build on
// Entware. Keep their capability results independent: probing one tool must
// never make us pass an unsupported option to the other.
static std::atomic<int>& restore_wait_support_cache(const std::string& program) {
    static std::atomic<int> ipv4{-1}; // -1 unknown, 0 no, 1 yes
    static std::atomic<int> ipv6{-1};
    return program == "ip6tables-restore" ? ipv6 : ipv4;
}

static std::atomic<int>& restore_test_support_cache(const std::string& program) {
    static std::atomic<int> ipv4{-1}; // -1 unknown, 0 no, 1 yes
    static std::atomic<int> ipv6{-1};
    return program == "ip6tables-restore" ? ipv6 : ipv4;
}

static bool restore_failure_is_transient(
    const std::string& error_output,
    const std::string& script);

static bool restore_test_option_explicitly_unsupported(
    std::string error_output) {
    std::transform(
        error_output.begin(),
        error_output.end(),
        error_output.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
    constexpr std::array<std::string_view, 7> unsupported_markers{
        "unknown option",
        "unrecognized option",
        "unrecognised option",
        "invalid option",
        "illegal option",
        "unsupported option",
        "option not supported",
    };
    return std::any_of(
        unsupported_markers.begin(),
        unsupported_markers.end(),
        [&error_output](std::string_view marker) {
            return error_output.find(marker) != std::string::npos;
        });
}

static bool restore_test_option_supported(const std::string& program) {
    auto& cache = restore_test_support_cache(program);
    const int cached = cache.load(std::memory_order_acquire);
    if (cached >= 0) {
        return cached == 1;
    }

    constexpr std::string_view probe_script{"*filter\nCOMMIT\n"};
    std::string error_output;
    SafeExecFailureDetail failure_detail;
    const int exit_code = safe_exec_pipe_stdin(
        {program, "--test"},
        std::string{probe_script},
        &error_output,
        SafeExecFailureLog::Suppressed,
        &failure_detail,
        SafeExecTimeouts{
            std::chrono::seconds{2},
            std::chrono::milliseconds{500}});
    if (exit_code == 0) {
        cache.store(1, std::memory_order_release);
        Logger::instance().verbose(
            "{} xtables test option support: yes", program);
        return true;
    }

    const std::string detail = error_output.empty()
        ? failure_detail.reason
        : error_output;
    const std::string message = keen_pbr3::format(
        "{} --test capability probe failed with status {}{}{}",
        program,
        exit_code,
        detail.empty() ? "" : ": ",
        detail);

    // A timeout/exec failure or an exhausted xtables wait says nothing about
    // option support. Classify it before parsing stderr so even a partial
    // diagnostic containing "unknown option" cannot poison the cache.
    if (exit_code < 0 || exit_code == 4 ||
        restore_failure_is_transient(
            error_output, std::string{probe_script})) {
        throw TransientFirewallError(message);
    }

    // safe_exec_pipe_stdin bounds captured stderr at 8 KiB. At the boundary
    // the diagnostic may be partial, so it cannot be authoritative evidence
    // that --test is unsupported.
    constexpr std::size_t kCapturedStderrLimit = 8U * 1024U;
    if (error_output.size() >= kCapturedStderrLimit) {
        throw FirewallError(message + " (stderr truncated)");
    }

    if (restore_test_option_explicitly_unsupported(error_output)) {
        cache.store(0, std::memory_order_release);
        Logger::instance().verbose(
            "{} xtables test option support: no", program);
        return false;
    }

    throw FirewallError(message);
}

static bool restore_wait_option_supported(const std::string& program) {
    auto& cache = restore_wait_support_cache(program);
    const int cached = cache.load(std::memory_order_acquire);
    if (cached >= 0) {
        return cached == 1;
    }

    // Probe the option without feeding the real transaction to the tool.
    // Entware's legacy iptables-restore rejects -w, and using the actual rules
    // as the capability probe logs a scary failure even though the subsequent
    // unguarded fallback succeeds.
    const auto probe = safe_exec_capture(
        {program, "-w", "0", "--test"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/1024);
    const int supported =
        !probe.timed_out && !probe.truncated && probe.exit_code == 0 ? 1 : 0;
    cache.store(supported, std::memory_order_release);
    Logger::instance().verbose(
        "{} xtables wait option support: {}",
        program,
        supported == 1 ? "yes" : "no");
    return supported == 1;
}

#ifdef KEEN_PBR3_TESTING
namespace testing {

bool restore_wait_option_supported_for_test(const std::string& program) {
    return restore_wait_option_supported(program);
}

bool restore_test_option_supported_for_test(const std::string& program) {
    return restore_test_option_supported(program);
}

void reset_restore_wait_option_probe_for_test() {
    restore_wait_support_cache("iptables-restore").store(
        -1, std::memory_order_release);
    restore_wait_support_cache("ip6tables-restore").store(
        -1, std::memory_order_release);
    restore_test_support_cache("iptables-restore").store(
        -1, std::memory_order_release);
    restore_test_support_cache("ip6tables-restore").store(
        -1, std::memory_order_release);
}

} // namespace testing
#endif

static std::optional<unsigned long> restore_failure_line_number(
    const std::string& error_output) {
    const auto marker = error_output.find("line");
    if (marker == std::string::npos) {
        return std::nullopt;
    }
    try {
        auto cursor = marker + 4;
        while (cursor < error_output.size() &&
               (error_output[cursor] == ':' ||
                std::isspace(static_cast<unsigned char>(error_output[cursor])))) {
            ++cursor;
        }
        if (cursor >= error_output.size() ||
            !std::isdigit(static_cast<unsigned char>(error_output[cursor]))) {
            return std::nullopt;
        }
        return std::stoul(error_output.substr(cursor));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

static std::optional<std::string> restore_script_line(
    const std::string& script,
    unsigned long line_number) {
    std::istringstream stream(script);
    std::string line;
    for (unsigned long index = 1;
         index <= line_number && std::getline(stream, line);
         ++index) {
        if (index == line_number) {
            return line;
        }
    }
    return std::nullopt;
}

static bool is_commit_line(std::string line) {
    const auto first = std::find_if_not(
        line.begin(), line.end(), [](unsigned char ch) { return std::isspace(ch); });
    const auto last = std::find_if_not(
        line.rbegin(), line.rend(), [](unsigned char ch) { return std::isspace(ch); })
                          .base();
    return first < last && std::string(first, last) == "COMMIT";
}

// Legacy iptables-restore has no -w. On Keenetic, a concurrent NDMS firewall
// replacement can surface either as an xtables-lock diagnostic or as a failure
// on the transaction's COMMIT line. A malformed rule fails on its own line and
// must not be hidden behind retries.
static bool restore_failure_is_transient(const std::string& error_output,
                                         const std::string& script) {
    std::string normalized = error_output;
    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    constexpr std::array<std::string_view, 5> lock_markers{
        "xtables lock",
        "holding the xtables lock",
        "resource temporarily unavailable",
        "temporarily unavailable",
        "device or resource busy",
    };
    if (std::any_of(
            lock_markers.begin(),
            lock_markers.end(),
            [&normalized](std::string_view marker) {
                return normalized.find(marker) != std::string::npos;
            })) {
        return true;
    }

    const auto line_number = restore_failure_line_number(error_output);
    if (!line_number.has_value()) {
        return false;
    }
    const auto line = restore_script_line(script, *line_number);
    return line.has_value() && is_commit_line(*line);
}

// Turns "exited with status 1" into something actionable.
//
// iptables-restore prints the reason and, usually, "Error occurred at line: N".
// Quoting that line from the script we just fed it is the difference between a
// message the user can act on and one that only says something went wrong.
static std::string describe_restore_failure(const std::string& tool,
                                            int status,
                                            const std::string& error_output,
                                            const std::string& script) {
    std::string message =
        keen_pbr3::format("{} exited with status {}", tool, status);
    if (!error_output.empty()) {
        message += ": " + error_output;
    }

    // Двоеточие после "line" ставят не все сборки: одни печатают
    // "Error occurred at line: 113", другие — "line 113 failed". Раньше
    // разбирался только первый вариант, и в самом частом случае номер строки
    // оставался известен, а правило — нет.
    if (const auto line_number = restore_failure_line_number(error_output);
        line_number.has_value()) {
        if (const auto line = restore_script_line(script, *line_number);
            line.has_value()) {
            message += keen_pbr3::format(" (rule: {})", *line);
        }
    }

    return message;
}

static constexpr std::array<std::chrono::milliseconds, 4>
    restore_retry_delays{
        std::chrono::milliseconds{50},
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
        std::chrono::milliseconds{400},
    };

enum class IptablesCommandOutcome {
    Success,
    TransientFailure,
    PermanentFailure,
};

static constexpr std::array<std::chrono::milliseconds, 4>
    iptables_control_retry_delays{
        std::chrono::milliseconds{25},
        std::chrono::milliseconds{50},
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
    };

static std::string normalized_iptables_output(
    const ExecCaptureResult& result) {
    std::string normalized = result.stdout_output;
    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
    return normalized;
}

static bool command_reports_table_unavailable(
    const ExecCaptureResult& result) {
    const std::string normalized = normalized_iptables_output(result);
    constexpr std::array<std::string_view, 6> markers{
        "table does not exist",
        "table `nat' does not exist",
        "can't initialize iptables table `nat'",
        "can't initialize ip6tables table `nat'",
        "address family not supported",
        "protocol not supported",
    };
    return std::any_of(
        markers.begin(),
        markers.end(),
        [&normalized](std::string_view marker) {
            return normalized.find(marker) != std::string::npos;
        });
}

static bool command_reports_chain_missing(
    const ExecCaptureResult& result) {
    const std::string normalized = normalized_iptables_output(result);
    const bool legacy_target_missing =
        (normalized.find("couldn't load target") != std::string::npos ||
         normalized.find("could not load target") != std::string::npos) &&
        normalized.find("no such file or directory") != std::string::npos;
    return normalized.find("no chain/target/match") != std::string::npos ||
           normalized.find("does a matching rule exist") != std::string::npos ||
           legacy_target_missing;
}

static IptablesCommandOutcome classify_iptables_command(
    const ExecCaptureResult& result) {
    if (result.exit_code == 0 && !result.timed_out && !result.truncated) {
        return IptablesCommandOutcome::Success;
    }
    if (result.truncated) {
        // A complete table snapshot is required for exact hook counting. A
        // stable oversized result will not heal by retrying.
        return IptablesCommandOutcome::PermanentFailure;
    }
    const std::string normalized = normalized_iptables_output(result);
    constexpr std::array<std::string_view, 7> permanent_markers{
        "permission denied",
        "operation not permitted",
        "can't initialize iptables table",
        "can't initialize ip6tables table",
        "unknown option",
        "bad argument",
        "invalid argument",
    };
    if (std::any_of(
            permanent_markers.begin(),
            permanent_markers.end(),
            [&normalized](std::string_view marker) {
                return normalized.find(marker) != std::string::npos;
            })) {
        return IptablesCommandOutcome::PermanentFailure;
    }
    if (result.timed_out || result.exit_code < 0 ||
        result.exit_code == 1 || result.exit_code == 4) {
        // For the fixed -S/-A/-D commands below, exit 1 means the table/chain
        // changed between inspection and mutation. Exit 4 is the documented
        // xtables resource/lock failure. Both are normal short-lived races
        // while KeeneticOS republishes its firewall.
        return IptablesCommandOutcome::TransientFailure;
    }
    return IptablesCommandOutcome::PermanentFailure;
}

static ExecCaptureResult run_iptables_control(
    const std::vector<std::string>& args) {
    return safe_exec_capture(
        args,
        /*suppress_stderr=*/false,
        /*max_bytes=*/256U * 1024U,
        /*capture_stderr=*/true,
        /*drain_after_limit=*/true,
        SafeExecFailureLog::Suppressed,
        SafeExecTimeouts{
            std::chrono::seconds{2},
            std::chrono::milliseconds{500}});
}

static void record_iptables_control_failure(
    const std::vector<std::string>& args,
    const ExecCaptureResult& result,
    std::string_view fallback_reason = "nonzero_exit") {
    const std::string_view reason =
        result.timed_out
            ? std::string_view{"timeout"}
            : result.truncated
                ? std::string_view{"output_truncated"}
                : fallback_reason;
    record_safe_exec_pipe_failure(
        args,
        result.exit_code,
        {},
        result.stdout_output,
        reason);
}

static void pipe_to_cmd(const std::vector<std::string>& args, const std::string& input) {
    Logger::instance().verbose("{} script:\n{}", args[0], input);

    if (is_restore_tool(args[0])) {
        // KeeneticOS can replace its own chains between our snapshot and the
        // atomic commit. -w protects the xtables lock on newer tools; the same
        // bounded retry also covers generation/COMMIT races on both new and
        // legacy Entware builds.
        const bool wait_supported =
            restore_wait_option_supported(args[0]);
        const auto restore_args =
            wait_supported ? with_wait_option(args) : args;
        const SafeExecTimeouts restore_timeouts{
            wait_supported
                ? std::chrono::seconds{12}
                : std::chrono::seconds{2},
            std::chrono::milliseconds{500},
        };
        for (std::size_t attempt = 0;
             attempt <= restore_retry_delays.size();
             ++attempt) {
            std::string error_output;
            SafeExecFailureDetail failure_detail;
            int status = safe_exec_pipe_stdin(
                restore_args,
                input,
                &error_output,
                SafeExecFailureLog::Suppressed,
                &failure_detail,
                restore_timeouts);
            if (status == 0) {
                return;
            }

            // safe_exec_pipe_stdin returns a negative status for timeout or
            // another parent-side execution interruption. A missing program
            // still exits as 127, so retrying the negative result is both
            // bounded and safe while covering a legacy restore blocked on the
            // xtables lock without a useful stderr diagnostic.
            const bool transient =
                status < 0 || status == 4 ||
                restore_failure_is_transient(error_output, input);
            // A negative status already consumed the full bounded command
            // timeout. Likewise, exit 4 from a wait-capable restore means its
            // ten-second xtables wait was exhausted. Hand either case to the
            // daemon's outer backoff immediately instead of blocking the
            // control loop for several more full lock waits.
            const bool wait_exhausted =
                wait_supported && status == 4;
            const bool final_attempt =
                attempt == restore_retry_delays.size() ||
                status < 0 ||
                wait_exhausted;
            if (!transient || final_attempt) {
                const std::string_view reason =
                    failure_detail.reason.empty()
                        ? (status < 0
                               ? std::string_view{"execution_failed"}
                               : std::string_view{"nonzero_exit"})
                        : std::string_view{failure_detail.reason};
                record_safe_exec_pipe_failure(
                    restore_args,
                    status,
                    input,
                    error_output,
                    reason,
                    failure_detail.numeric_detail,
                    failure_detail.numeric_value);
            }
            if (!transient) {
                throw FirewallError(
                    describe_restore_failure(args[0], status, error_output, input));
            }

            if (final_attempt) {
                throw TransientFirewallError(
                    describe_restore_failure(args[0], status, error_output, input));
            }
            Logger::instance().verbose(
                "{} transient transaction failure; retrying in {} ms ({}/{})",
                args[0],
                restore_retry_delays[attempt].count(),
                attempt + 1,
                restore_retry_delays.size());
            std::this_thread::sleep_for(restore_retry_delays[attempt]);
        }
    }

    std::string error_output;
    int status = safe_exec_pipe_stdin(
        args,
        input,
        &error_output,
        SafeExecFailureLog::DiagnosticOnly);
    if (status != 0) {
        throw FirewallError(describe_restore_failure(args[0], status, error_output, input));
    }
}

namespace {

bool xtables_match_registered(
    std::string_view inventory_path,
    std::string_view match) {
    std::ifstream inventory{std::string{inventory_path}};
    std::string registered_match;
    while (inventory >> registered_match) {
        if (registered_match == match) {
            return true;
        }
    }
    return false;
}

bool physdev_match_available(
    std::string_view inventory_path,
    bool allow_module_load) {
    // `iptables-restore --test` only validates the userspace extension on
    // legacy xtables. It can accept `-m physdev` even when the running kernel
    // has no registered matcher and the real transaction then fails at
    // COMMIT. The proc inventory is the authoritative in-kernel capability.
    if (xtables_match_registered(inventory_path, "physdev")) {
        return true;
    }

    if (allow_module_load) {
        // Some firmware images ship xt_physdev as a loadable module. Try it
        // once per daemon lifetime, then trust only the refreshed kernel
        // inventory. Custom inventory paths used by tests never reach this
        // branch and therefore cannot mutate the host running the tests.
        static std::once_flag physdev_module_load_once;
        std::call_once(physdev_module_load_once, [] {
            const int status = safe_exec(
                {"modprobe", "xt_physdev"},
                /*suppress_output=*/true);
            Logger::instance().verbose(
                "One-time xt_physdev module load attempt completed with "
                "status {}",
                status);
        });
        if (xtables_match_registered(inventory_path, "physdev")) {
            return true;
        }
    }

    Logger::instance().verbose(
        "{} does not register the physdev matcher; keeping bridged "
        "SSTP bypass fail-closed",
        inventory_path);
    return false;
}

FirewallGlobalPrefilter iptables_effective_prefilter_with_inventories(
    const FirewallGlobalPrefilter& requested,
    bool effective_ipv6,
    std::string_view ipv4_inventory_path,
    std::string_view ipv6_inventory_path,
    bool allow_module_load) {
    FirewallGlobalPrefilter effective = requested;
    if (!effective.bypass_bridge_source_selectors_v4.empty()) {
        const bool ipv4_physdev_available =
            physdev_match_available(ipv4_inventory_path, allow_module_load);
        if (!ipv4_physdev_available) {
            throw FirewallError(
                "Cannot exclude clients of a bridged SSTP server: "
                "this firmware kernel does not provide the iptables "
                "physdev matcher. The previous firewall ruleset "
                "was kept unchanged.");
        }
    }
    if (!effective.bypass_bridge_source_selectors_v6.empty()) {
        if (!effective_ipv6) {
            effective.bypass_bridge_source_selectors_v6.clear();
        } else if (!physdev_match_available(
                       ipv6_inventory_path,
                       allow_module_load)) {
            throw FirewallError(
                "Cannot exclude IPv6 clients of a bridged SSTP server: "
                "this firmware kernel does not provide the ip6tables "
                "physdev matcher. The previous firewall ruleset "
                "was kept unchanged.");
        }
    }
    return effective;
}

FirewallGlobalPrefilter iptables_effective_prefilter(
    const FirewallGlobalPrefilter& requested,
    bool effective_ipv6) {
    return iptables_effective_prefilter_with_inventories(
        requested,
        effective_ipv6,
        "/proc/net/ip_tables_matches",
        "/proc/net/ip6_tables_matches",
        /*allow_module_load=*/true);
}

class NatValidationCleanup final {
public:
    NatValidationCleanup(std::string command,
                         std::string dns_chain,
                         std::string snat_chain)
        : command_(std::move(command)),
          dns_chain_(std::move(dns_chain)),
          snat_chain_(std::move(snat_chain)) {
        cleanup();
    }

    ~NatValidationCleanup() {
        cleanup();
    }

    NatValidationCleanup(const NatValidationCleanup&) = delete;
    NatValidationCleanup& operator=(const NatValidationCleanup&) = delete;

private:
    void cleanup() const {
        // Validation chains are never hooked into a builtin chain. A stale
        // chain can therefore only be residue from an interrupted preflight.
        safe_exec(
            {command_, "-t", "nat", "-F", dns_chain_},
            /*suppress_output=*/true);
        safe_exec(
            {command_, "-t", "nat", "-X", dns_chain_},
            /*suppress_output=*/true);
        safe_exec(
            {command_, "-t", "nat", "-F", snat_chain_},
            /*suppress_output=*/true);
        safe_exec(
            {command_, "-t", "nat", "-X", snat_chain_},
            /*suppress_output=*/true);
    }

    std::string command_;
    std::string dns_chain_;
    std::string snat_chain_;
};

} // namespace

#ifdef KEEN_PBR3_TESTING
namespace testing {

bool xtables_match_registered_for_test(
    const std::string& inventory_path,
    const std::string& match) {
    return xtables_match_registered(inventory_path, match);
}

FirewallGlobalPrefilter iptables_effective_prefilter_for_test(
    const FirewallGlobalPrefilter& requested,
    bool effective_ipv6,
    const std::string& ipv4_inventory_path,
    const std::string& ipv6_inventory_path) {
    return iptables_effective_prefilter_with_inventories(
        requested,
        effective_ipv6,
        ipv4_inventory_path,
        ipv6_inventory_path,
        /*allow_module_load=*/false);
}

} // namespace testing
#endif

std::string IptablesFirewall::build_nat_validation_script(
    const std::string& nat_script) {
    const auto replace_all = [](std::string& value,
                                std::string_view from,
                                std::string_view to) {
        std::size_t offset = 0;
        while ((offset = value.find(from, offset)) != std::string::npos) {
            value.replace(offset, from.size(), to);
            offset += to.size();
        }
    };

    std::istringstream input(nat_script);
    std::string output;
    std::string line;
    while (std::getline(input, line)) {
        replace_all(line, DNS_NAT_CHAIN_NAME, DNS_NAT_VALIDATION_CHAIN_NAME);
        replace_all(line, SNAT_CHAIN_NAME, SNAT_VALIDATION_CHAIN_NAME);

        // Legacy restore binaries have no --test. Stage the exact generated
        // NAT rules in deterministic, unhooked owned chains instead. The
        // builtin hook lines are fixed scaffolding and deliberately omitted:
        // validation must never redirect a live packet.
        if (line == keen_pbr3::format(
                        "-A PREROUTING -j {}",
                        DNS_NAT_VALIDATION_CHAIN_NAME) ||
            line == keen_pbr3::format(
                        "-A POSTROUTING -j {}",
                        SNAT_VALIDATION_CHAIN_NAME)) {
            continue;
        }
        output += line;
        output.push_back('\n');
    }
    return output;
}

void IptablesFirewall::preflight_nat_restore(
    const std::string& restore_program,
    const std::string& nat_script) {
    if (restore_test_option_supported(restore_program)) {
        // Validate the exact transaction that will be committed after the old
        // NAT chains are removed.
        pipe_to_cmd(
            {restore_program, "--test", "--noflush", "--counters"},
            nat_script);
        return;
    }

    // Entware still ships legacy restore variants without --test on some
    // Keenetic architectures. Validate the same generated match/target rules
    // in unhooked temporary chains, preserving the active DNS/SNAT hooks.
    const std::string command =
        restore_program == "ip6tables-restore"
            ? "ip6tables"
            : "iptables";
    NatValidationCleanup cleanup(
        command,
        DNS_NAT_VALIDATION_CHAIN_NAME,
        SNAT_VALIDATION_CHAIN_NAME);
    pipe_to_cmd(
        {restore_program, "--noflush", "--counters"},
        build_nat_validation_script(nat_script));
}

std::string IptablesFirewall::build_ipset_create_line(const PendingSet& ps) {
    // Keenetic's netfilter-addons package exposes hash:ip,port,ip across the
    // supported firmware line, while older kernels may not expose
    // hash:ip,port,ip. The middle dimension is the UDP destination port.
    const char* type = ps.source_udp_peer
        ? "hash:ip,port,ip"
        : "hash:net";
    if (ps.timeout > 0) {
        return keen_pbr3::format("create {} {} family {} timeout {} -exist\n",
                                 ps.name, type, ps.family_str, ps.timeout);
    } else {
        return keen_pbr3::format("create {} {} family {} -exist\n",
                                 ps.name, type, ps.family_str);
    }
}

bool IptablesFirewall::dynamic_set_schema_compatible(
    const std::string& xml,
    const PendingSet& expected) {
    if (xml.empty() || xml.find('\0') != std::string::npos) {
        return false;
    }

    std::vector<char> buffer(xml.begin(), xml.end());
    buffer.push_back('\0');
    rapidxml::xml_document<> document;
    try {
        document.parse<
            rapidxml::parse_trim_whitespace |
            rapidxml::parse_validate_closing_tags>(buffer.data());
    } catch (const rapidxml::parse_error&) {
        return false;
    }

    auto* root = document.first_node("ipsets");
    if (root == nullptr || document.first_node() != root ||
        root->next_sibling() != nullptr) {
        return false;
    }
    auto* set = root->first_node("ipset");
    if (set == nullptr || set->next_sibling("ipset") != nullptr) {
        return false;
    }
    for (auto* child = root->first_node(); child != nullptr;
         child = child->next_sibling()) {
        if (child->type() == rapidxml::node_element && child != set) {
            return false;
        }
    }

    auto* name = set->first_attribute("name");
    auto* type = set->first_node("type");
    auto* header = set->first_node("header");
    if (name == nullptr || type == nullptr || header == nullptr ||
        set->last_attribute("name") != name ||
        set->last_node("type") != type ||
        set->last_node("header") != header) {
        return false;
    }
    auto* family = header->first_node("family");
    auto* timeout_node = header->first_node("timeout");
    if (family == nullptr || header->last_node("family") != family ||
        (timeout_node != nullptr &&
         header->last_node("timeout") != timeout_node)) {
        return false;
    }

    const std::string_view live_name(name->value(), name->value_size());
    const std::string_view live_type(type->value(), type->value_size());
    const std::string_view live_family(
        family->value(), family->value_size());
    uint32_t live_timeout = 0;
    if (timeout_node != nullptr) {
        const char* begin = timeout_node->value();
        const char* end = begin + timeout_node->value_size();
        const auto parsed = std::from_chars(begin, end, live_timeout);
        if (parsed.ec != std::errc{} || parsed.ptr != end) {
            return false;
        }
    }
    return live_name == expected.name &&
           live_type == (expected.source_udp_peer
                             ? "hash:ip,port,ip"
                             : "hash:net") &&
           live_family == expected.family_str &&
           live_timeout == expected.timeout;
}

void IptablesFirewall::preflight_dynamic_set_schemas(
    bool effective_ipv6) const {
    const bool has_dynamic = std::any_of(
        pending_sets_.begin(),
        pending_sets_.end(),
        [&](const PendingSet& set) {
            return is_dynamic_set_name(set.name) &&
                   (set.family_str != "inet6" || effective_ipv6);
        });
    if (!has_dynamic) {
        return;
    }

    const auto names = safe_exec_capture(
        {"ipset", "list", "-n"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/256U * 1024U);
    if (names.exit_code != 0 || names.truncated || names.timed_out) {
        throw FirewallError("failed to inspect dynamic ipset schemas");
    }

    std::set<std::string> live_names;
    std::istringstream name_lines(names.stdout_output);
    std::string live_name;
    while (std::getline(name_lines, live_name)) {
        if (!live_name.empty()) {
            live_names.insert(live_name);
        }
    }

    for (const auto& set : pending_sets_) {
        if (!is_dynamic_set_name(set.name) ||
            (set.family_str == "inet6" && !effective_ipv6) ||
            live_names.find(set.name) == live_names.end()) {
            continue;
        }
        const auto schema = safe_exec_capture(
            {"ipset", "list", "-t", set.name, "-o", "xml"},
            /*suppress_stderr=*/true,
            /*max_bytes=*/256U * 1024U);
        if (schema.exit_code != 0 || schema.truncated || schema.timed_out) {
            throw FirewallError(
                "failed to inspect dynamic ipset schema for " + set.name);
        }
        if (!dynamic_set_schema_compatible(schema.stdout_output, set)) {
            throw FirewallError(
                "incompatible existing dynamic ipset schema for " + set.name);
        }
    }
}

bool IptablesFirewall::ipv6_backend_available() const {
    return iptables_ipv6_supported();
}

const char* IptablesFirewall::prerouting_table_name(bool ipv6) const {
    return use_raw_prerouting_ && !ipv6 ? "raw" : "mangle";
}

const char* IptablesFirewall::prerouting_dispatcher_chain_name(bool ipv6) const {
    return use_raw_prerouting_ && !ipv6 ? RAW_CHAIN_NAME : CHAIN_NAME;
}

const char* IptablesFirewall::prerouting_generation_chain(
    FirewallSetGeneration generation,
    bool ipv6) const {
    return use_raw_prerouting_ && !ipv6
        ? raw_generation_prerouting_chain(generation)
        : generation_prerouting_chain(generation);
}

IptablesFirewall::LiveGenerationState
IptablesFirewall::inspect_live_generation(bool ipv6) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    return inspect_dispatcher(
        command,
        prerouting_table_name(ipv6),
        prerouting_dispatcher_chain_name(ipv6),
        prerouting_generation_chain(FirewallSetGeneration::A, ipv6),
        prerouting_generation_chain(FirewallSetGeneration::B, ipv6));
}

IptablesFirewall::LiveGenerationState IptablesFirewall::inspect_dispatcher(
    const char* command,
    const char* table,
    const std::string& dispatcher,
    const std::string& generation_a,
    const std::string& generation_b) const {
    ExecCaptureResult last_result;
    const std::vector<std::string> inspect_args{
        command, "-t", table, "-S"};
    for (std::size_t attempt = 0;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        last_result = run_iptables_control(inspect_args);
        const auto outcome = classify_iptables_command(last_result);
        if (outcome == IptablesCommandOutcome::Success) {
            return parse_live_generation(
                last_result.stdout_output,
                dispatcher,
                generation_a,
                generation_b);
        }
        if (outcome == IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(inspect_args, last_result);
            throw FirewallError(
                "failed to execute iptables dispatcher inspection for " +
                dispatcher);
        }
        if (last_result.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            break;
        }
        Logger::instance().verbose(
            "{} dispatcher inspection was transiently unavailable; "
            "retrying in {} ms ({}/{})",
            dispatcher,
            iptables_control_retry_delays[attempt].count(),
            attempt + 1,
            iptables_control_retry_delays.size());
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }
    record_iptables_control_failure(inspect_args, last_result);
    throw TransientFirewallError(
        "failed to inspect live iptables dispatcher " + dispatcher);
}

FirewallSetGeneration IptablesFirewall::select_target_generation(
    bool ipv6) const {
    auto primary = inspect_live_generation(ipv6);

    const char* command = ipv6 ? "ip6tables" : "iptables";
    auto secondary = inspect_dispatcher(
        command,
        "mangle",
        OUTPUT_CHAIN_NAME,
        generation_output_chain(FirewallSetGeneration::A),
        generation_output_chain(FirewallSetGeneration::B));

    const auto generation_from_state =
        [](LiveGenerationState state)
        -> std::optional<FirewallSetGeneration> {
        if (state == LiveGenerationState::A) {
            return FirewallSetGeneration::A;
        }
        if (state == LiveGenerationState::B) {
            return FirewallSetGeneration::B;
        }
        return std::nullopt;
    };
    const auto state_for_generation =
        [](FirewallSetGeneration generation) {
        return generation == FirewallSetGeneration::A
            ? LiveGenerationState::A
            : LiveGenerationState::B;
    };

    if (const auto authoritative = generation_from_state(primary);
        authoritative.has_value()) {
        if (secondary == LiveGenerationState::Invalid ||
            (generation_from_state(secondary).has_value() &&
             secondary != state_for_generation(*authoritative))) {
            // Forwarded traffic is authoritative. Repair OUTPUT before any
            // inactive-slot ipsets are flushed or repopulated.
            publish_dispatcher(ipv6, /*output=*/true, *authoritative);
            secondary = inspect_dispatcher(
                command,
                "mangle",
                OUTPUT_CHAIN_NAME,
                generation_output_chain(FirewallSetGeneration::A),
                generation_output_chain(FirewallSetGeneration::B));
            if (secondary != state_for_generation(*authoritative)) {
                throw TransientFirewallError(
                    "failed to synchronize live iptables OUTPUT dispatcher");
            }
        }
    } else if (primary == LiveGenerationState::Invalid) {
        if (const auto authoritative = generation_from_state(secondary);
            authoritative.has_value()) {
            // OUTPUT is the only valid witness. Repair the forwarded dispatcher
            // to the same generation before selecting the opposite inactive slot.
            publish_dispatcher(
                ipv6,
                /*output=*/false,
                *authoritative);
            primary = inspect_live_generation(ipv6);
            if (primary != state_for_generation(*authoritative)) {
                throw TransientFirewallError(
                    "failed to synchronize live iptables PREROUTING dispatcher");
            }
        }
    }

    return target_generation_for_states(primary, secondary);
}

void IptablesFirewall::ensure_target_generation_inactive(
    bool ipv6,
    FirewallSetGeneration target) const {
    if (select_target_generation(ipv6) != target) {
        throw TransientFirewallError(
            "live iptables generation changed while preparing apply");
    }
}

void IptablesFirewall::publish_dispatcher(
    bool ipv6,
    bool output,
    FirewallSetGeneration generation) const {
    const char* restore = ipv6 ? "ip6tables-restore" : "iptables-restore";
    const char* table = output ? "mangle" : prerouting_table_name(ipv6);
    const char* dispatcher = output
        ? OUTPUT_CHAIN_NAME
        : prerouting_dispatcher_chain_name(ipv6);
    const char* target = output
        ? generation_output_chain(generation)
        : prerouting_generation_chain(generation, ipv6);
    const std::string script = keen_pbr3::format(
        "*{}\n:{} - [0:0]\n-F {}\n-A {} -j {}\nCOMMIT\n",
        table,
        dispatcher,
        dispatcher,
        dispatcher,
        target);
    pipe_to_cmd({restore, "--noflush", "--counters"}, script);
}

namespace {

std::vector<std::size_t> exact_jump_positions(
    const std::string& rules,
    const std::string& source_chain,
    const std::string& target_chain) {
    const std::string rule_prefix = "-A " + source_chain + " ";
    const std::string expected =
        rule_prefix + "-j " + target_chain;
    std::vector<std::size_t> positions;
    std::size_t position = 0U;
    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind(rule_prefix, 0U) != 0U) {
            continue;
        }
        ++position;
        if (line == expected) {
            positions.push_back(position);
        }
    }
    return positions;
}

bool chain_declared(const std::string& rules, const std::string& chain) {
    const std::string expected = "-N " + chain;
    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        if (line == expected) {
            return true;
        }
    }
    return false;
}

std::size_t jump_reference_count(
    const std::string& rules,
    const std::string& target_chain) {
    std::size_t count = 0U;
    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        for (const auto* option : {" -j ", " -g ",
                                   " --jump ", " --goto "}) {
            const std::string needle =
                std::string{option} + target_chain;
            const auto position = line.find(needle);
            if (position == std::string::npos) {
                continue;
            }
            const auto end = position + needle.size();
            if (end == line.size() || line[end] == ' ') {
                ++count;
                break;
            }
        }
    }
    return count;
}

bool parse_rendered_uint32(std::string_view text, std::uint32_t& value) {
    int base = 10;
    if (text.size() > 2U && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2U);
        base = 16;
    }
    if (text.empty()) {
        return false;
    }
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value, base);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

bool rendered_ipv4_equals(
    const std::string& rendered,
    const std::string& expected) {
    return rendered == expected || rendered == expected + "/32";
}

bool rendered_mark_equals(
    const std::string& rendered,
    std::uint32_t expected) {
    const auto separator = rendered.find('/');
    if (separator == std::string::npos) {
        return false;
    }
    std::uint32_t value = 0U;
    std::uint32_t mask = 0U;
    return parse_rendered_uint32(
               std::string_view{rendered}.substr(0U, separator), value) &&
           parse_rendered_uint32(
               std::string_view{rendered}.substr(separator + 1U), mask) &&
           value == expected && mask == 0xFFFFFFFFU;
}

std::optional<std::uint8_t> rendered_tcp_flags(
    const std::string& rendered) {
    std::uint32_t numeric = 0U;
    if (parse_rendered_uint32(rendered, numeric)) {
        if (numeric <= 0xFFU) {
            return static_cast<std::uint8_t>(numeric);
        }
        return std::nullopt;
    }

    std::uint8_t flags = 0U;
    std::size_t begin = 0U;
    while (begin <= rendered.size()) {
        const auto end = rendered.find(',', begin);
        const std::string_view flag{
            rendered.data() + begin,
            (end == std::string::npos ? rendered.size() : end) - begin};
        if (flag == "FIN") {
            flags |= 0x01U;
        } else if (flag == "SYN") {
            flags |= 0x02U;
        } else if (flag == "RST") {
            flags |= 0x04U;
        } else if (flag == "PSH") {
            flags |= 0x08U;
        } else if (flag == "ACK") {
            flags |= 0x10U;
        } else if (flag == "URG") {
            flags |= 0x20U;
        } else {
            return std::nullopt;
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1U;
    }
    return flags;
}

bool rendered_exact_tcp_reset_rule_matches(
    const std::string& line,
    const FirewallExactTcpResetRule& expected) {
    std::istringstream input(line);
    std::vector<std::string> tokens{
        std::istream_iterator<std::string>{input},
        std::istream_iterator<std::string>{}};
    if (tokens.size() < 3U || tokens[0] != "-A" ||
        tokens[1] != "KeenPbrTcpRst") {
        return false;
    }

    bool source = false;
    bool destination = false;
    bool protocol = false;
    bool tcp_match = false;
    bool mark_match = false;
    bool source_port = false;
    bool destination_port = false;
    bool mark = false;
    bool tcp_flags = false;
    bool jump = false;
    bool reject = false;
    for (std::size_t index = 2U; index < tokens.size();) {
        const auto& option = tokens[index++];
        if (index >= tokens.size()) {
            return false;
        }
        const auto& value = tokens[index++];
        if (option == "-s") {
            if (source || !rendered_ipv4_equals(value, expected.source)) {
                return false;
            }
            source = true;
        } else if (option == "-d") {
            if (destination ||
                !rendered_ipv4_equals(value, expected.destination)) {
                return false;
            }
            destination = true;
        } else if (option == "-p") {
            if (protocol || value != "tcp") {
                return false;
            }
            protocol = true;
        } else if (option == "-m") {
            if (value == "tcp" && !tcp_match) {
                tcp_match = true;
            } else if (value == "mark" && !mark_match) {
                mark_match = true;
            } else {
                return false;
            }
        } else if (option == "--sport" ||
                   option == "--source-port") {
            std::uint32_t parsed = 0U;
            if (source_port ||
                !parse_rendered_uint32(value, parsed) ||
                parsed != expected.source_port) {
                return false;
            }
            source_port = true;
        } else if (option == "--dport" ||
                   option == "--destination-port") {
            std::uint32_t parsed = 0U;
            if (destination_port ||
                !parse_rendered_uint32(value, parsed) ||
                parsed != expected.destination_port) {
                return false;
            }
            destination_port = true;
        } else if (option == "--mark") {
            if (mark || !rendered_mark_equals(value, expected.full_mark)) {
                return false;
            }
            mark = true;
        } else if (option == "--tcp-flags") {
            if (tcp_flags || index >= tokens.size()) {
                return false;
            }
            const auto mask = rendered_tcp_flags(value);
            const auto comparison = rendered_tcp_flags(tokens[index++]);
            if (!mask.has_value() || !comparison.has_value() ||
                *mask != 0x16U || *comparison != 0x10U) {
                return false;
            }
            tcp_flags = true;
        } else if (option == "-j") {
            if (jump || value != "REJECT") {
                return false;
            }
            jump = true;
        } else if (option == "--reject-with") {
            if (reject || value != "tcp-reset") {
                return false;
            }
            reject = true;
        } else {
            return false;
        }
    }

    return source && destination && protocol && tcp_match && mark_match &&
           source_port && destination_port && mark && tcp_flags && jump &&
           reject;
}

} // namespace

bool IptablesFirewall::exact_tcp_reset_rules_match(
    const std::string& rendered_rules,
    const std::vector<FirewallExactTcpResetRule>& expected_rules) {
    std::vector<std::string> live_rules;
    const std::string prefix =
        std::string{"-A "} + EXACT_TCP_RESET_CHAIN_NAME + " ";
    std::istringstream input(rendered_rules);
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind(prefix, 0U) == 0U) {
            live_rules.push_back(line);
        }
    }
    if (live_rules.size() != expected_rules.size()) {
        return false;
    }

    std::vector<bool> matched(expected_rules.size(), false);
    for (const auto& live : live_rules) {
        bool found = false;
        for (std::size_t index = 0U; index < expected_rules.size(); ++index) {
            if (!matched[index] &&
                rendered_exact_tcp_reset_rule_matches(
                    live, expected_rules[index])) {
                matched[index] = true;
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

FirewallExactTcpResetResult
IptablesFirewall::replace_exact_tcp_reset_rules_locked(
    const std::vector<FirewallExactTcpResetRule>& rules,
    bool cleanup_on_verification_failure) {
    const std::vector<std::string> inspect_args{
        "iptables", "-t", "filter", "-S"};
    ExecCaptureResult before;
    for (std::size_t attempt = 0U;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        before = run_iptables_control(inspect_args);
        if (before.exit_code == 127 && !before.timed_out) {
            return FirewallExactTcpResetResult::unsupported;
        }
        if (command_reports_table_unavailable(before)) {
            return FirewallExactTcpResetResult::unsupported;
        }
        const auto outcome = classify_iptables_command(before);
        if (outcome == IptablesCommandOutcome::Success) {
            break;
        }
        if (outcome == IptablesCommandOutcome::PermanentFailure ||
            before.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            record_iptables_control_failure(inspect_args, before);
            return FirewallExactTcpResetResult::failed;
        }
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }

    const bool chain_exists = chain_declared(
        before.stdout_output, EXACT_TCP_RESET_CHAIN_NAME);
    const auto hooks = exact_jump_positions(
        before.stdout_output, "FORWARD", EXACT_TCP_RESET_CHAIN_NAME);
    if (jump_reference_count(
            before.stdout_output, EXACT_TCP_RESET_CHAIN_NAME) !=
            hooks.size() ||
        (!chain_exists && !hooks.empty())) {
        Logger::instance().warn(
            "iptables exact TCP reset chain has an unexpected reference; "
            "refusing to replace it");
        return FirewallExactTcpResetResult::failed;
    }

    // A fresh firewall object may discover an owned chain left by a crashed
    // daemon. Retain that observed ownership before probing restore support:
    // a transient probe failure must not make later cleanup forget live RSTs.
    if (chain_exists || !hooks.empty()) {
        exact_tcp_reset_chain_created_ = true;
        exact_tcp_reset_publication_uncertain_ = true;
    }

    if (rules.empty() && !chain_exists && hooks.empty()) {
        exact_tcp_reset_chain_created_ = false;
        exact_tcp_reset_publication_uncertain_ = false;
        installed_exact_tcp_resets_.clear();
        return FirewallExactTcpResetResult::installed;
    }

    const auto restore_probe = run_iptables_control(
        {"iptables-restore", "--version"});
    if (restore_probe.exit_code == 127 && !restore_probe.timed_out) {
        return FirewallExactTcpResetResult::unsupported;
    }
    if (classify_iptables_command(restore_probe) !=
        IptablesCommandOutcome::Success) {
        record_iptables_control_failure(
            {"iptables-restore", "--version"}, restore_probe);
        return FirewallExactTcpResetResult::failed;
    }

    // From this point onward the next restore may reach COMMIT even if the
    // parent observes a timeout or another execution error. Record potential
    // ownership before publication so every failure path remains fail-closed.
    exact_tcp_reset_chain_created_ = true;
    exact_tcp_reset_publication_uncertain_ = true;
    try {
        pipe_to_cmd(
            {"iptables-restore", "--noflush", "--counters"},
            build_exact_tcp_reset_script(
                chain_exists, hooks.size(), rules));
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "failed to publish exact TCP reset rule: {}", error.what());
        if (!rules.empty()) {
            // A timed-out restore can have committed just before the parent
            // lost its result. Immediately attempt a separately verified
            // teardown. If absence cannot be proved, retain uncertain
            // ownership so remove/stop/startup cleanup will retry it.
            const auto cleanup = replace_exact_tcp_reset_rules_locked(
                {}, /*cleanup_on_verification_failure=*/false);
            if (cleanup != FirewallExactTcpResetResult::installed) {
                exact_tcp_reset_chain_created_ = true;
                exact_tcp_reset_publication_uncertain_ = true;
            }
        }
        return FirewallExactTcpResetResult::failed;
    }

    const auto after = run_iptables_control(inspect_args);
    const auto after_outcome = classify_iptables_command(after);
    const auto after_hooks = after_outcome == IptablesCommandOutcome::Success
        ? exact_jump_positions(
              after.stdout_output, "FORWARD", EXACT_TCP_RESET_CHAIN_NAME)
        : std::vector<std::size_t>{};
    bool verified = rules.empty()
        ? after_outcome == IptablesCommandOutcome::Success &&
              !chain_declared(
                  after.stdout_output, EXACT_TCP_RESET_CHAIN_NAME) &&
              after_hooks.empty() &&
              jump_reference_count(
                  after.stdout_output, EXACT_TCP_RESET_CHAIN_NAME) == 0U
        : after_outcome == IptablesCommandOutcome::Success &&
              chain_declared(
                  after.stdout_output, EXACT_TCP_RESET_CHAIN_NAME) &&
              after_hooks.size() == 1U && after_hooks.front() == 1U &&
              jump_reference_count(
                  after.stdout_output, EXACT_TCP_RESET_CHAIN_NAME) == 1U &&
              exact_tcp_reset_rules_match(
                  after.stdout_output, rules);
    if (!verified) {
        record_iptables_control_failure(
            inspect_args, after, "exact_tcp_reset_verification_failed");
        if (cleanup_on_verification_failure && !rules.empty()) {
            const auto cleanup = replace_exact_tcp_reset_rules_locked(
                {}, /*cleanup_on_verification_failure=*/false);
            if (cleanup == FirewallExactTcpResetResult::installed) {
                installed_exact_tcp_resets_.clear();
                exact_tcp_reset_chain_created_ = false;
                exact_tcp_reset_publication_uncertain_ = false;
            } else {
                exact_tcp_reset_chain_created_ = true;
                exact_tcp_reset_publication_uncertain_ = true;
            }
        }
        return FirewallExactTcpResetResult::failed;
    }

    exact_tcp_reset_chain_created_ = !rules.empty();
    exact_tcp_reset_publication_uncertain_ = false;
    if (rules.empty()) {
        installed_exact_tcp_resets_.clear();
    }
    return FirewallExactTcpResetResult::installed;
}

FirewallExactTcpResetResult IptablesFirewall::install_exact_tcp_reset(
    const FirewallExactTcpResetRule& rule) {
    if (!valid_exact_tcp_reset_rule(rule)) {
        return FirewallExactTcpResetResult::failed;
    }

    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    auto replacement = installed_exact_tcp_resets_;
    if (std::find(replacement.begin(), replacement.end(), rule) ==
        replacement.end()) {
        replacement.push_back(rule);
    }
    std::sort(
        replacement.begin(),
        replacement.end(),
        [](const auto& lhs, const auto& rhs) {
            if (lhs.source != rhs.source) {
                return lhs.source < rhs.source;
            }
            if (lhs.destination != rhs.destination) {
                return lhs.destination < rhs.destination;
            }
            if (lhs.source_port != rhs.source_port) {
                return lhs.source_port < rhs.source_port;
            }
            if (lhs.destination_port != rhs.destination_port) {
                return lhs.destination_port < rhs.destination_port;
            }
            return lhs.full_mark < rhs.full_mark;
        });

    const auto result = replace_exact_tcp_reset_rules_locked(replacement);
    if (result == FirewallExactTcpResetResult::installed) {
        installed_exact_tcp_resets_ = std::move(replacement);
    }
    return result;
}

bool IptablesFirewall::remove_exact_tcp_reset(
    const FirewallExactTcpResetRule& rule) {
    if (!valid_exact_tcp_reset_rule(rule)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    auto replacement = installed_exact_tcp_resets_;
    const auto found = std::find(
        replacement.begin(), replacement.end(), rule);
    if (found == replacement.end()) {
        if (!exact_tcp_reset_publication_uncertain_ &&
            (!replacement.empty() || !exact_tcp_reset_chain_created_)) {
            return true;
        }
        const bool removed = replace_exact_tcp_reset_rules_locked({}) ==
            FirewallExactTcpResetResult::installed;
        if (removed) {
            installed_exact_tcp_resets_.clear();
        }
        return removed;
    }
    replacement.erase(found);
    const auto result = replace_exact_tcp_reset_rules_locked(replacement);
    if (result != FirewallExactTcpResetResult::installed) {
        return false;
    }
    installed_exact_tcp_resets_ = std::move(replacement);
    return true;
}

bool IptablesFirewall::forward_reject_generation_references_are_owned(
    const std::string& rules,
    LiveGenerationState state,
    const std::string& generation_a,
    const std::string& generation_b) {
    const auto a_references = jump_reference_count(rules, generation_a);
    const auto b_references = jump_reference_count(rules, generation_b);
    switch (state) {
    case LiveGenerationState::Missing:
        return a_references == 0U && b_references == 0U;
    case LiveGenerationState::A:
        // The dispatcher owns the only live generation reference.
        return a_references == 1U && b_references == 0U;
    case LiveGenerationState::B:
        return a_references == 0U && b_references == 1U;
    case LiveGenerationState::Invalid:
        return false;
    }
    return false;
}

IptablesFirewall::LiveGenerationState
IptablesFirewall::inspect_forward_reject_generation(bool ipv6) const {
    return inspect_dispatcher(
        ipv6 ? "ip6tables" : "iptables",
        "filter",
        META_UDP_443_CHAIN_NAME,
        forward_reject_generation_chain(FirewallSetGeneration::A),
        forward_reject_generation_chain(FirewallSetGeneration::B));
}

FirewallSetGeneration
IptablesFirewall::select_forward_reject_target_generation(bool ipv6) const {
    const auto state = inspect_forward_reject_generation(ipv6);
    if (state == LiveGenerationState::A) {
        return FirewallSetGeneration::B;
    }
    if (state == LiveGenerationState::B) {
        return FirewallSetGeneration::A;
    }
    if (state == LiveGenerationState::Missing) {
        return FirewallSetGeneration::A;
    }
    throw TransientFirewallError(
        "no authoritative live Meta UDP/443 filter generation");
}

void IptablesFirewall::ensure_forward_reject_target_generation_inactive(
    bool ipv6,
    FirewallSetGeneration target) const {
    const auto state = inspect_forward_reject_generation(ipv6);
    if (state == LiveGenerationState::Invalid) {
        throw TransientFirewallError(
            "invalid live Meta UDP/443 filter dispatcher");
    }
    const auto target_state = target == FirewallSetGeneration::A
        ? LiveGenerationState::A
        : LiveGenerationState::B;
    if (state == target_state) {
        throw TransientFirewallError(
            "live Meta UDP/443 filter generation changed while preparing apply");
    }
}

void IptablesFirewall::publish_forward_reject_dispatcher(
    bool ipv6,
    FirewallSetGeneration generation) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    const char* restore = ipv6
        ? "ip6tables-restore"
        : "iptables-restore";
    const char* target = forward_reject_generation_chain(generation);
    const std::vector<std::string> inspect_args{
        command, "-t", "filter", "-S"};
    ExecCaptureResult before;
    for (std::size_t attempt = 0U;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        before = run_iptables_control(inspect_args);
        const auto outcome = classify_iptables_command(before);
        if (outcome == IptablesCommandOutcome::Success) {
            break;
        }
        if (outcome == IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(inspect_args, before);
            throw FirewallError(
                "failed to inspect Meta UDP/443 filter before publication");
        }
        if (before.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            record_iptables_control_failure(inspect_args, before);
            throw TransientFirewallError(
                "temporarily failed to inspect Meta UDP/443 filter before publication");
        }
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }

    const auto live = parse_live_generation(
        before.stdout_output,
        META_UDP_443_CHAIN_NAME,
        forward_reject_generation_chain(FirewallSetGeneration::A),
        forward_reject_generation_chain(FirewallSetGeneration::B));
    if (live == LiveGenerationState::Invalid) {
        throw TransientFirewallError(
            "invalid live Meta UDP/443 filter dispatcher before publication");
    }
    const auto target_state = generation == FirewallSetGeneration::A
        ? LiveGenerationState::A
        : LiveGenerationState::B;
    if (live == target_state) {
        throw TransientFirewallError(
            "Meta UDP/443 filter target became active before publication");
    }

    const auto hooks = exact_jump_positions(
        before.stdout_output, "FORWARD", META_UDP_443_CHAIN_NAME);
    if (jump_reference_count(
            before.stdout_output, META_UDP_443_CHAIN_NAME) != hooks.size() ||
        !forward_reject_generation_references_are_owned(
            before.stdout_output,
            live,
            forward_reject_generation_chain(FirewallSetGeneration::A),
            forward_reject_generation_chain(FirewallSetGeneration::B))) {
        throw TransientFirewallError(
            "unexpected Meta UDP/443 filter graph reference");
    }

    std::string script = "*filter\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n-A {} -j {}\n",
        META_UDP_443_CHAIN_NAME,
        META_UDP_443_CHAIN_NAME,
        META_UDP_443_CHAIN_NAME,
        target);
    // Rebuild the owned hook and dispatcher in one kernel transaction. If
    // insertion at rule 1 or the target-chain reference fails, the previous
    // generation and hook order remain unchanged.
    for (std::size_t index = 0U; index < hooks.size(); ++index) {
        script += keen_pbr3::format(
            "-D FORWARD -j {}\n", META_UDP_443_CHAIN_NAME);
    }
    script += keen_pbr3::format(
        "-I FORWARD 1 -j {}\nCOMMIT\n",
        META_UDP_443_CHAIN_NAME);
    // This is the first operation in the iptables apply which can mutate the
    // independently owned Meta filter. Everything above is read-only
    // preflight; ordinary mangle/NAT publication earlier in apply() must not
    // be misreported as a Meta boundary failure.
    enter_meta_udp443_publication_boundary();
    pipe_to_cmd({restore, "--noflush", "--counters"}, script);
}

void IptablesFirewall::publish_and_verify_forward_reject_generation(
    bool ipv6,
    FirewallSetGeneration generation) {
    publish_forward_reject_dispatcher(ipv6, generation);
    // The restore COMMIT above is the publication boundary. Record ownership
    // before post-COMMIT verification so stop/retry cannot skip a blocking
    // hook merely because the firmware changed it immediately afterward.
    if (ipv6) {
        forward_reject_v6_created_ = true;
    } else {
        forward_reject_v4_created_ = true;
    }
    verify_forward_reject_generation(ipv6, generation);
}

IptablesFirewall::LiveGenerationState
IptablesFirewall::parse_live_generation(
    const std::string& rules,
    const std::string& dispatcher,
    const std::string& generation_a,
    const std::string& generation_b) {
    const std::string jump_a = "-A " + dispatcher + " -j " + generation_a;
    const std::string jump_b = "-A " + dispatcher + " -j " + generation_b;
    size_t a_count = 0;
    size_t b_count = 0;
    size_t other_rule_count = 0;
    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        if (line == jump_a) {
            ++a_count;
        } else if (line == jump_b) {
            ++b_count;
        } else if (line.rfind("-A " + dispatcher + " ", 0) == 0) {
            ++other_rule_count;
        }
    }
    if (a_count == 1 && b_count == 0 && other_rule_count == 0) {
        return LiveGenerationState::A;
    }
    if (b_count == 1 && a_count == 0 && other_rule_count == 0) {
        return LiveGenerationState::B;
    }
    if (a_count == 0 && b_count == 0 && other_rule_count == 0) {
        return LiveGenerationState::Missing;
    }
    return LiveGenerationState::Invalid;
}

FirewallSetGeneration IptablesFirewall::target_generation_for_states(
    LiveGenerationState primary,
    LiveGenerationState secondary) {
    // select_target_generation() synchronizes a damaged dispatcher to the
    // valid counterpart before this decision. The valid generation therefore
    // remains authoritative while the opposite slot is staged.
    if (primary == LiveGenerationState::A) {
        return FirewallSetGeneration::B;
    }
    if (primary == LiveGenerationState::B) {
        return FirewallSetGeneration::A;
    }
    if (secondary == LiveGenerationState::A) {
        return FirewallSetGeneration::B;
    }
    if (secondary == LiveGenerationState::B) {
        return FirewallSetGeneration::A;
    }
    if (primary == LiveGenerationState::Missing &&
        secondary == LiveGenerationState::Missing) {
        // No managed dispatcher currently activates either slot. This covers
        // both first installation and self-healing after the stable scaffold
        // vanished; stale generation chains/ipsets do not make a slot active.
        return FirewallSetGeneration::A;
    }
    // Two snapshots can legitimately straddle an NDMS publication and expose
    // no authoritative managed generation for a few milliseconds. Stay
    // fail-closed, but let the bounded outer reconciler take a fresh pair
    // instead of reporting an immediate permanent outage.
    throw TransientFirewallError(
        "no authoritative live iptables generation; refusing to mutate ipsets");
}

size_t IptablesFirewall::count_exact_jump(
    const std::string& rules,
    const std::string& source_chain,
    const std::string& target_chain) {
    const std::string expected =
        "-A " + source_chain + " -j " + target_chain;
    size_t count = 0;
    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        if (line == expected) {
            ++count;
        }
    }
    return count;
}

void IptablesFirewall::verify_forward_reject_generation(
    bool ipv6,
    FirewallSetGeneration generation) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    const auto expected = generation == FirewallSetGeneration::A
        ? LiveGenerationState::A
        : LiveGenerationState::B;
    const std::string generation_chain =
        forward_reject_generation_chain(generation);
    std::multiset<std::string> expected_rule_lines;
    for (const auto& rule : pending_forward_udp_rejects_) {
        if (rule.ipv6 != ipv6) {
            continue;
        }
        expected_rule_lines.insert(keen_pbr3::format(
            // `iptables -S` prints the protocol before extension matches and
            // materializes the implicit UDP matcher used by `--dport`.
            // Compare with that stable save form rather than the accepted
            // iptables-restore input order emitted by the staging script.
            "-A {} -p udp -m mark --mark {:#x}/{:#x} "
            "-m udp --dport {} "
            "-m set --match-set {} dst -j REJECT --reject-with {}",
            generation_chain,
            rule.fwmark,
            rule.fwmark_mask,
            rule.destination_port,
            rule.set_name,
            ipv6 ? "icmp6-port-unreachable" : "icmp-port-unreachable"));
    }
    const std::vector<std::string> inspect_args{
        command, "-t", "filter", "-S"};
    ExecCaptureResult last_result;
    for (std::size_t attempt = 0U;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        last_result = run_iptables_control(inspect_args);
        const auto outcome = classify_iptables_command(last_result);
        if (outcome == IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(inspect_args, last_result);
            throw FirewallError(
                "Meta UDP/443 filter generation verification failed");
        }
        if (outcome == IptablesCommandOutcome::Success &&
            parse_live_generation(
                last_result.stdout_output,
                META_UDP_443_CHAIN_NAME,
                forward_reject_generation_chain(
                    FirewallSetGeneration::A),
                forward_reject_generation_chain(
                    FirewallSetGeneration::B)) == expected) {
            const auto hook_positions = exact_jump_positions(
                last_result.stdout_output,
                "FORWARD",
                META_UDP_443_CHAIN_NAME);
            std::multiset<std::string> observed_rule_lines;
            std::istringstream rule_input(last_result.stdout_output);
            std::string line;
            const std::string prefix = "-A " + generation_chain + " ";
            while (std::getline(rule_input, line)) {
                if (line.rfind(prefix, 0U) == 0U) {
                    observed_rule_lines.insert(line);
                }
            }
            if (hook_positions.size() == 1U &&
                hook_positions.front() == 1U &&
                jump_reference_count(
                    last_result.stdout_output,
                    META_UDP_443_CHAIN_NAME) == 1U &&
                forward_reject_generation_references_are_owned(
                    last_result.stdout_output,
                    expected,
                    forward_reject_generation_chain(
                        FirewallSetGeneration::A),
                    forward_reject_generation_chain(
                        FirewallSetGeneration::B)) &&
                observed_rule_lines == expected_rule_lines) {
                return;
            }
        }
        if (last_result.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            break;
        }
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }
    record_iptables_control_failure(inspect_args, last_result);
    throw TransientFirewallError(
        "Meta UDP/443 filter generation did not remain published");
}

OwnedForwardUdpRejectState
IptablesFirewall::inspect_forward_udp_reject_state() const {
    const auto inspect_family = [this](
        bool ipv6,
        bool managed,
        bool expected,
        FirewallSetGeneration generation) {
        if (ipv6 && !managed) {
            return OwnedForwardUdpRejectState::healthy;
        }
        const char* command = ipv6 ? "ip6tables" : "iptables";
        const std::vector<std::string> args{
            command, "-t", "filter", "-S"};
        const auto live = run_iptables_control(args);
        if ((ipv6 && live.exit_code == 127 && !live.timed_out) ||
            command_reports_table_unavailable(live)) {
            return expected
                ? OwnedForwardUdpRejectState::missing
                : OwnedForwardUdpRejectState::healthy;
        }
        if (classify_iptables_command(live) !=
            IptablesCommandOutcome::Success) {
            return OwnedForwardUdpRejectState::unknown;
        }

        const std::string generation_a =
            forward_reject_generation_chain(FirewallSetGeneration::A);
        const std::string generation_b =
            forward_reject_generation_chain(FirewallSetGeneration::B);
        const auto state = parse_live_generation(
            live.stdout_output,
            META_UDP_443_CHAIN_NAME,
            generation_a,
            generation_b);
        const auto hooks = exact_jump_positions(
            live.stdout_output, "FORWARD", META_UDP_443_CHAIN_NAME);
        const bool any_owned_artifact =
            chain_declared(live.stdout_output, META_UDP_443_CHAIN_NAME) ||
            chain_declared(live.stdout_output, generation_a) ||
            chain_declared(live.stdout_output, generation_b) ||
            jump_reference_count(
                live.stdout_output, META_UDP_443_CHAIN_NAME) != 0U;
        if (!expected) {
            return any_owned_artifact
                ? OwnedForwardUdpRejectState::stale
                : OwnedForwardUdpRejectState::healthy;
        }

        const auto expected_state = generation == FirewallSetGeneration::A
            ? LiveGenerationState::A
            : LiveGenerationState::B;
        if (!any_owned_artifact || state == LiveGenerationState::Missing ||
            hooks.empty()) {
            return OwnedForwardUdpRejectState::missing;
        }
        if (state != expected_state || hooks.size() != 1U ||
            hooks.front() != 1U ||
            jump_reference_count(
                live.stdout_output, META_UDP_443_CHAIN_NAME) != 1U ||
            !forward_reject_generation_references_are_owned(
                live.stdout_output,
                state,
                generation_a,
                generation_b)) {
            return OwnedForwardUdpRejectState::stale;
        }

        const std::string active_chain =
            forward_reject_generation_chain(generation);
        std::multiset<std::string> expected_rules;
        for (const auto& rule : last_applied_forward_udp_rejects_) {
            if (rule.ipv6 != ipv6) {
                continue;
            }
            expected_rules.insert(keen_pbr3::format(
                "-A {} -p udp -m mark --mark {:#x}/{:#x} "
                "-m udp --dport {} "
                "-m set --match-set {} dst -j REJECT --reject-with {}",
                active_chain,
                rule.fwmark,
                rule.fwmark_mask,
                rule.destination_port,
                rule.set_name,
                ipv6 ? "icmp6-port-unreachable" :
                       "icmp-port-unreachable"));
        }
        std::multiset<std::string> observed_rules;
        const std::string prefix = "-A " + active_chain + " ";
        std::istringstream input(live.stdout_output);
        std::string line;
        while (std::getline(input, line)) {
            if (line.rfind(prefix, 0U) == 0U) {
                observed_rules.insert(line);
            }
        }
        return !expected_rules.empty() && observed_rules == expected_rules
            ? OwnedForwardUdpRejectState::healthy
            : OwnedForwardUdpRejectState::stale;
    };

    const auto ipv4 = inspect_family(
        /*ipv6=*/false,
        /*managed=*/true,
        last_applied_forward_reject_v4_expected_,
        last_applied_forward_reject_v4_generation_);
    const auto ipv6 = inspect_family(
        /*ipv6=*/true,
        last_applied_forward_reject_v6_managed_,
        last_applied_forward_reject_v6_expected_,
        last_applied_forward_reject_v6_generation_);
    if (ipv4 == OwnedForwardUdpRejectState::unknown ||
        ipv6 == OwnedForwardUdpRejectState::unknown) {
        return OwnedForwardUdpRejectState::unknown;
    }
    if (ipv4 == OwnedForwardUdpRejectState::missing ||
        ipv6 == OwnedForwardUdpRejectState::missing) {
        return OwnedForwardUdpRejectState::missing;
    }
    if (ipv4 == OwnedForwardUdpRejectState::stale ||
        ipv6 == OwnedForwardUdpRejectState::stale) {
        return OwnedForwardUdpRejectState::stale;
    }
    return OwnedForwardUdpRejectState::healthy;
}

void IptablesFirewall::disable_forward_reject_scaffold(bool ipv6) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    const char* restore = ipv6
        ? "ip6tables-restore"
        : "iptables-restore";
    const std::vector<std::string> inspect_args{
        command, "-t", "filter", "-S"};
    const auto before = run_iptables_control(inspect_args);
    if (ipv6 && before.exit_code == 127 && !before.timed_out) {
        if (forward_reject_v6_created_) {
            throw FirewallError(
                "ip6tables disappeared while the Meta UDP/443 filter was owned");
        }
        return;
    }
    if (command_reports_table_unavailable(before)) {
        if (ipv6 && forward_reject_v6_created_) {
            throw FirewallError(
                "IPv6 filter table disappeared while the Meta UDP/443 filter was owned");
        }
        return;
    }
    if (classify_iptables_command(before) !=
        IptablesCommandOutcome::Success) {
        record_iptables_control_failure(inspect_args, before);
        throw TransientFirewallError(
            "could not inspect Meta UDP/443 filter before disabling it");
    }

    const auto hook_positions = exact_jump_positions(
        before.stdout_output, "FORWARD", META_UDP_443_CHAIN_NAME);
    const bool dispatcher_exists = chain_declared(
        before.stdout_output, META_UDP_443_CHAIN_NAME);
    const std::string generation_a =
        forward_reject_generation_chain(FirewallSetGeneration::A);
    const std::string generation_b =
        forward_reject_generation_chain(FirewallSetGeneration::B);
    const bool generation_a_exists =
        chain_declared(before.stdout_output, generation_a);
    const bool generation_b_exists =
        chain_declared(before.stdout_output, generation_b);

    if (hook_positions.empty() && !dispatcher_exists &&
        !generation_a_exists && !generation_b_exists) {
        return;
    }
    const auto live = parse_live_generation(
        before.stdout_output,
        META_UDP_443_CHAIN_NAME,
        generation_a,
        generation_b);
    if (live == LiveGenerationState::Invalid ||
        jump_reference_count(
            before.stdout_output, META_UDP_443_CHAIN_NAME) !=
            hook_positions.size()) {
        throw TransientFirewallError(
            "Meta UDP/443 filter scaffold is inconsistent; refusing partial disable");
    }

    std::string script = "*filter\n";
    for (std::size_t index = 0U; index < hook_positions.size(); ++index) {
        script += keen_pbr3::format(
            "-D FORWARD -j {}\n", META_UDP_443_CHAIN_NAME);
    }
    if (dispatcher_exists) {
        script += keen_pbr3::format(
            "-F {}\n-X {}\n",
            META_UDP_443_CHAIN_NAME,
            META_UDP_443_CHAIN_NAME);
    }
    if (generation_a_exists) {
        script += keen_pbr3::format(
            "-F {}\n-X {}\n", generation_a, generation_a);
    }
    if (generation_b_exists) {
        script += keen_pbr3::format(
            "-F {}\n-X {}\n", generation_b, generation_b);
    }
    script += "COMMIT\n";
    // iptables-restore commits the hook and all owned-chain removals as one
    // transaction. A failed cleanup therefore leaves messages_first fully
    // authoritative instead of producing a half-disabled policy.
    enter_meta_udp443_publication_boundary();
    pipe_to_cmd({restore, "--noflush", "--counters"}, script);

    const auto after = run_iptables_control(inspect_args);
    if (classify_iptables_command(after) !=
            IptablesCommandOutcome::Success ||
        !exact_jump_positions(
             after.stdout_output, "FORWARD", META_UDP_443_CHAIN_NAME)
             .empty() ||
        chain_declared(after.stdout_output, META_UDP_443_CHAIN_NAME) ||
        chain_declared(after.stdout_output, generation_a) ||
        chain_declared(after.stdout_output, generation_b)) {
        record_iptables_control_failure(inspect_args, after);
        throw TransientFirewallError(
            "Meta UDP/443 filter scaffold remained after atomic disable");
    }
}

OwnedSnatState IptablesFirewall::inspect_owned_snat_state(
    const char* command,
    bool expected,
    const std::vector<std::string>& expected_interfaces,
    const std::vector<FirewallSourceEgressSnatSelector>&
        expected_source_egress_selectors,
    uint32_t expected_fwmark_mask) {
    const std::vector<std::string> hook_args{
        command, "-t", "nat", "-S", "POSTROUTING"};
    const auto hook = run_iptables_control(hook_args);
    if (command_reports_table_unavailable(hook) ||
        command_reports_chain_missing(hook)) {
        return expected
            ? OwnedSnatState::missing
            : OwnedSnatState::healthy;
    }
    if (classify_iptables_command(hook) !=
        IptablesCommandOutcome::Success) {
        return OwnedSnatState::unknown;
    }

    const auto hook_count = count_exact_jump(
        hook.stdout_output, "POSTROUTING", SNAT_CHAIN_NAME);
    size_t owned_hook_reference_count = 0U;
    std::istringstream hook_rules(hook.stdout_output);
    std::string line;
    const std::string owned_jump = keen_pbr3::format(
        "-j {}", SNAT_CHAIN_NAME);
    while (std::getline(hook_rules, line)) {
        if (line.find(owned_jump) != std::string::npos) {
            ++owned_hook_reference_count;
        }
    }
    const std::vector<std::string> chain_args{
        command, "-t", "nat", "-S", SNAT_CHAIN_NAME};
    const auto chain = run_iptables_control(chain_args);
    if (command_reports_table_unavailable(chain) ||
        command_reports_chain_missing(chain)) {
        if (expected) {
            return OwnedSnatState::missing;
        }
        return owned_hook_reference_count == 0U
            ? OwnedSnatState::healthy
            : OwnedSnatState::stale;
    }
    if (classify_iptables_command(chain) !=
        IptablesCommandOutcome::Success) {
        return OwnedSnatState::unknown;
    }
    if (chain.stdout_output.empty()) {
        if (expected) {
            return OwnedSnatState::missing;
        }
        return owned_hook_reference_count == 0U
            ? OwnedSnatState::healthy
            : OwnedSnatState::stale;
    }

    // A stale unhooked chain is still drift from the last applied contract.
    if (!expected) {
        return OwnedSnatState::stale;
    }

    std::vector<std::string> expected_rules;
    expected_rules.push_back(keen_pbr3::format(
        "-A {} -m mark --mark {:#x}/{:#x} -j MASQUERADE",
        SNAT_CHAIN_NAME, kRouterOriginMark, kRouterOriginMark));
    for (const auto& interface : expected_interfaces) {
        expected_rules.push_back(keen_pbr3::format(
            "-A {} -o {} -m mark ! --mark 0x0/{:#x} -j MASQUERADE",
            SNAT_CHAIN_NAME, interface, expected_fwmark_mask));
    }
    for (const auto& selector : expected_source_egress_selectors) {
        expected_rules.push_back(keen_pbr3::format(
            "-A {} -s {} -o {} -j MASQUERADE",
            SNAT_CHAIN_NAME,
            selector.cidr,
            selector.interface));
    }

    size_t declaration_count = 0U;
    bool unexpected_line = false;
    std::vector<std::string> observed_rules;
    std::istringstream chain_rules(chain.stdout_output);
    while (std::getline(chain_rules, line)) {
        if (line.empty()) {
            continue;
        }
        if (line == keen_pbr3::format("-N {}", SNAT_CHAIN_NAME)) {
            ++declaration_count;
            continue;
        }
        if (line.rfind(
                keen_pbr3::format("-A {} ", SNAT_CHAIN_NAME),
                0) == 0) {
            observed_rules.push_back(line);
            continue;
        }
        unexpected_line = true;
    }

    return hook_count == 1U &&
           owned_hook_reference_count == 1U &&
           declaration_count == 1U &&
           !unexpected_line &&
           observed_rules == expected_rules
        ? OwnedSnatState::healthy
        : OwnedSnatState::missing;
}

OwnedSnatState IptablesFirewall::combine_owned_snat_states(
    OwnedSnatState ipv4,
    OwnedSnatState ipv6) {
    if (ipv4 == OwnedSnatState::unknown ||
        ipv6 == OwnedSnatState::unknown) {
        return OwnedSnatState::unknown;
    }
    if (ipv4 == OwnedSnatState::missing ||
        ipv6 == OwnedSnatState::missing) {
        return OwnedSnatState::missing;
    }
    if (ipv4 == OwnedSnatState::stale ||
        ipv6 == OwnedSnatState::stale) {
        return OwnedSnatState::stale;
    }
    return OwnedSnatState::healthy;
}

OwnedSnatState IptablesFirewall::inspect_owned_snat_state() const {
    const auto ipv4 = inspect_owned_snat_state(
        "iptables",
        last_applied_snat_v4_expected_,
        last_applied_snat_interfaces_,
        last_applied_source_egress_snat_selectors_v4_,
        last_applied_snat_fwmark_mask_);
    const auto ipv6 =
        (last_applied_snat_v6_managed_ ||
         last_applied_snat_v6_expected_)
        ? inspect_owned_snat_state(
              "ip6tables",
              last_applied_snat_v6_expected_,
              last_applied_snat_interfaces_,
              last_applied_source_egress_snat_selectors_v6_,
              last_applied_snat_fwmark_mask_)
        : OwnedSnatState::healthy;
    return combine_owned_snat_states(ipv4, ipv6);
}

void IptablesFirewall::verify_owned_snat_after_apply(
    const char* command,
    bool expected,
    const std::vector<std::string>& expected_interfaces,
    const std::vector<FirewallSourceEgressSnatSelector>&
        expected_source_egress_selectors,
    uint32_t expected_fwmark_mask) {
    const auto state = inspect_owned_snat_state(
        command,
        expected,
        expected_interfaces,
        expected_source_egress_selectors,
        expected_fwmark_mask);
    if (state == OwnedSnatState::healthy) {
        return;
    }
    if (state == OwnedSnatState::missing) {
        throw TransientFirewallError(keen_pbr3::format(
            "{} tunnel SNAT scaffold is missing after apply", command));
    }
    if (state == OwnedSnatState::stale) {
        throw TransientFirewallError(keen_pbr3::format(
            "{} stale tunnel SNAT scaffold remains after apply", command));
    }
    throw TransientFirewallError(keen_pbr3::format(
        "{} tunnel SNAT scaffold could not be inspected after apply",
        command));
}

void IptablesFirewall::reconcile_hook(
    const char* command,
    const char* table,
    const char* builtin_chain,
    const char* target_chain) {
    const std::vector<std::string> inspect_args{
        command, "-t", table, "-S", builtin_chain};
    ExecCaptureResult last_result;

    // Never retry a mutation blindly: it may have succeeded just before the
    // process observed a timeout or a concurrent NDMS replacement. Every
    // attempt starts with a fresh snapshot and succeeds only after observing
    // exactly one hook.
    for (std::size_t attempt = 0;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        last_result = run_iptables_control(inspect_args);
        const auto inspect_outcome =
            classify_iptables_command(last_result);
        if (inspect_outcome ==
            IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(inspect_args, last_result);
            throw FirewallError(keen_pbr3::format(
                "failed to inspect {} {}/{} hook",
                command, table, builtin_chain));
        }
        if (inspect_outcome ==
            IptablesCommandOutcome::TransientFailure) {
            if (last_result.timed_out ||
                attempt == iptables_control_retry_delays.size()) {
                record_iptables_control_failure(
                    inspect_args, last_result);
                throw TransientFirewallError(
                    keen_pbr3::format(
                        "temporarily failed to inspect {} {}/{} hook",
                        command, table, builtin_chain));
            }
            std::this_thread::sleep_for(
                iptables_control_retry_delays[attempt]);
            continue;
        }

        const size_t count = count_exact_jump(
            last_result.stdout_output, builtin_chain, target_chain);
        if (count == 1) {
            return;
        }
        if (attempt == iptables_control_retry_delays.size()) {
            break;
        }

        const std::vector<std::string> mutate_args =
            count == 0
                ? std::vector<std::string>{
                      command,
                      "-t",
                      table,
                      "-A",
                      builtin_chain,
                      "-j",
                      target_chain}
                : std::vector<std::string>{
                      command,
                      "-t",
                      table,
                      "-D",
                      builtin_chain,
                      "-j",
                      target_chain};
        const auto mutation = run_iptables_control(mutate_args);
        const auto mutation_outcome =
            classify_iptables_command(mutation);
        if (mutation_outcome ==
            IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(mutate_args, mutation);
            // KeeneticOS can replace the firewall scaffold after the
            // successful snapshot above but before this mutation. In that
            // publication window xtables commonly reports exit 2 together
            // with "No chain/target/match by that name". The builtin chain
            // still exists; it is our target chain that vanished. Retrying
            // only this append/delete cannot recreate the target, so surface
            // the recognized race as transient and let the outer runtime
            // reconciler rebuild the complete owned generation.
            if (command_reports_chain_missing(mutation)) {
                throw TransientFirewallError(keen_pbr3::format(
                    "{} {}/{} hook target changed during reconciliation",
                    command,
                    table,
                    builtin_chain));
            }
            throw FirewallError(keen_pbr3::format(
                "failed to reconcile {} {}/{} hook",
                command, table, builtin_chain));
        }

        // A successful mutation still needs verification. A transient result
        // is also re-read because the kernel may have committed the change
        // before userspace observed the failure.
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }

    throw TransientFirewallError(keen_pbr3::format(
        "{} {}/{} hook did not converge",
        command, table, builtin_chain));
}

void IptablesFirewall::remove_all_hooks(
    const char* command,
    const char* table,
    const char* builtin_chain,
    const char* target_chain) {
    const auto result = safe_exec_capture(
        {command, "-t", table, "-S", builtin_chain},
        /*suppress_stderr=*/true,
        /*max_bytes=*/256U * 1024U);
    if (result.exit_code != 0 || result.truncated || result.timed_out) {
        return;
    }
    const size_t observed = count_exact_jump(
        result.stdout_output, builtin_chain, target_chain);
    for (size_t i = 0; i < observed; ++i) {
        if (safe_exec(
                {command, "-t", table, "-D", builtin_chain, "-j", target_chain},
                /*suppress_output=*/true) != 0) {
            break;
        }
    }
}

bool IptablesFirewall::ipv6_nat_table_available() {
    const std::vector<std::string> inspect_args{
        "ip6tables", "-t", "nat", "-S"};
    ExecCaptureResult last_result;
    for (std::size_t attempt = 0;
         attempt <= iptables_control_retry_delays.size();
        ++attempt) {
        last_result = run_iptables_control(inspect_args);
        // BusyBox/Entware installations are allowed to be IPv4-only. The
        // child exits with 127 when execvp cannot find ip6tables; for this
        // read-only capability probe that means the IPv6 NAT family is
        // absent, not that the IPv4 transaction failed.
        if (last_result.exit_code == 127 &&
            !last_result.timed_out) {
            return false;
        }
        if (command_reports_table_unavailable(last_result)) {
            return false;
        }
        const auto outcome = classify_iptables_command(last_result);
        if (outcome == IptablesCommandOutcome::Success) {
            return true;
        }
        if (outcome == IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(inspect_args, last_result);
            throw FirewallError("failed to inspect IPv6 nat table");
        }
        if (last_result.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            break;
        }
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }
    record_iptables_control_failure(inspect_args, last_result);
    throw TransientFirewallError(
        "temporarily failed to inspect IPv6 nat table");
}

void IptablesFirewall::remove_nat_chain_checked(
    const char* command,
    const char* builtin_chain,
    const char* target_chain) {
    const std::vector<std::string> inspect_hook_args{
        command, "-t", "nat", "-S", builtin_chain};
    ExecCaptureResult last_result;
    bool hooks_removed = false;

    // Removal follows the same inspect-mutate-verify contract as hook
    // creation. An xtables timeout may happen after the kernel committed a
    // mutation, so every retry starts from a fresh snapshot.
    for (std::size_t attempt = 0;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        last_result = run_iptables_control(inspect_hook_args);
        if (command_reports_table_unavailable(last_result) ||
            command_reports_chain_missing(last_result)) {
            return;
        }
        const auto inspect_outcome =
            classify_iptables_command(last_result);
        if (inspect_outcome == IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(
                inspect_hook_args, last_result);
            throw FirewallError(keen_pbr3::format(
                "failed to inspect {} nat/{} hook removal",
                command, builtin_chain));
        }
        if (inspect_outcome == IptablesCommandOutcome::Success) {
            const size_t observed = count_exact_jump(
                last_result.stdout_output,
                builtin_chain,
                target_chain);
            if (observed == 0) {
                hooks_removed = true;
                break;
            }
            if (attempt == iptables_control_retry_delays.size()) {
                break;
            }

            const std::vector<std::string> remove_args{
                command,
                "-t",
                "nat",
                "-D",
                builtin_chain,
                "-j",
                target_chain};
            for (size_t index = 0; index < observed; ++index) {
                const auto mutation =
                    run_iptables_control(remove_args);
                if (command_reports_table_unavailable(mutation) ||
                    command_reports_chain_missing(mutation)) {
                    break;
                }
                const auto mutation_outcome =
                    classify_iptables_command(mutation);
                if (mutation_outcome ==
                    IptablesCommandOutcome::PermanentFailure) {
                    record_iptables_control_failure(
                        remove_args, mutation);
                    throw FirewallError(keen_pbr3::format(
                        "failed to remove {} nat/{} hook",
                        command, builtin_chain));
                }
                if (mutation_outcome ==
                    IptablesCommandOutcome::TransientFailure) {
                    break;
                }
            }
            std::this_thread::sleep_for(
                iptables_control_retry_delays[attempt]);
            continue;
        }

        if (last_result.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            break;
        }
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }
    if (!hooks_removed) {
        record_iptables_control_failure(
            inspect_hook_args, last_result);
        throw TransientFirewallError(keen_pbr3::format(
            "{} nat/{} hook removal did not converge",
            command, builtin_chain));
    }

    const std::vector<std::string> inspect_chain_args{
        command, "-t", "nat", "-S", target_chain};
    for (std::size_t attempt = 0;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        last_result = run_iptables_control(inspect_chain_args);
        if (command_reports_table_unavailable(last_result) ||
            command_reports_chain_missing(last_result)) {
            return;
        }
        const auto inspect_outcome =
            classify_iptables_command(last_result);
        if (inspect_outcome == IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(
                inspect_chain_args, last_result);
            throw FirewallError(keen_pbr3::format(
                "failed to inspect {} nat chain {} removal",
                command, target_chain));
        }
        if (inspect_outcome == IptablesCommandOutcome::Success) {
            if (attempt == iptables_control_retry_delays.size()) {
                break;
            }
            const std::vector<std::string> flush_args{
                command, "-t", "nat", "-F", target_chain};
            const auto flush = run_iptables_control(flush_args);
            if (!command_reports_chain_missing(flush) &&
                !command_reports_table_unavailable(flush)) {
                const auto flush_outcome =
                    classify_iptables_command(flush);
                if (flush_outcome ==
                    IptablesCommandOutcome::PermanentFailure) {
                    record_iptables_control_failure(flush_args, flush);
                    throw FirewallError(keen_pbr3::format(
                        "failed to flush {} nat chain {}",
                        command, target_chain));
                }
                if (flush_outcome ==
                    IptablesCommandOutcome::Success) {
                    const std::vector<std::string> delete_args{
                        command, "-t", "nat", "-X", target_chain};
                    const auto deletion =
                        run_iptables_control(delete_args);
                    if (command_reports_chain_missing(deletion) ||
                        command_reports_table_unavailable(deletion)) {
                        return;
                    }
                    const auto delete_outcome =
                        classify_iptables_command(deletion);
                    if (delete_outcome ==
                        IptablesCommandOutcome::PermanentFailure) {
                        record_iptables_control_failure(
                            delete_args, deletion);
                        throw FirewallError(keen_pbr3::format(
                            "failed to delete {} nat chain {}",
                            command, target_chain));
                    }
                }
            } else {
                return;
            }
        }

        if (last_result.timed_out ||
            attempt == iptables_control_retry_delays.size()) {
            break;
        }
        std::this_thread::sleep_for(
            iptables_control_retry_delays[attempt]);
    }
    record_iptables_control_failure(inspect_chain_args, last_result);
    throw TransientFirewallError(keen_pbr3::format(
        "{} nat chain {} removal did not converge",
        command, target_chain));
}

void IptablesFirewall::cleanup_nat_family_checked(
    const char* command,
    bool ipv6) {
    remove_nat_chain_checked(
        command, "PREROUTING", DNS_NAT_CHAIN_NAME);
    remove_nat_chain_checked(
        command, "POSTROUTING", SNAT_CHAIN_NAME);
    if (ipv6) {
        dns_nat_v6_created_ = false;
    } else {
        dns_nat_v4_created_ = false;
    }
}

void IptablesFirewall::reconcile_hooks(bool ipv6) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    reconcile_hook(
        command,
        prerouting_table_name(ipv6),
        "PREROUTING",
        prerouting_dispatcher_chain_name(ipv6));
    reconcile_hook(command, "mangle", "OUTPUT", OUTPUT_CHAIN_NAME);
    if (use_raw_prerouting_ && !ipv6) {
        reconcile_hook(
            command,
            "mangle",
            "PREROUTING",
            RAW_CONNTRACK_CHAIN_NAME);
    }
}

void IptablesFirewall::verify_applied_generation(
    bool ipv6,
    FirewallSetGeneration target) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    const auto expected = target == FirewallSetGeneration::A
        ? LiveGenerationState::A
        : LiveGenerationState::B;

    const std::string primary_dispatcher =
        prerouting_dispatcher_chain_name(ipv6);
    const std::vector<std::string> primary_args{
        command, "-t", prerouting_table_name(ipv6), "-S"};
    const std::vector<std::string> output_args{
        command, "-t", "mangle", "-S"};

    // KeeneticOS can replace a table immediately after our atomic publish.
    // Verify one coherent pair of fresh snapshots instead of turning that
    // short publication window into a permanent service failure.
    for (std::size_t attempt = 0;
         attempt <= iptables_control_retry_delays.size();
         ++attempt) {
        const auto primary = run_iptables_control(primary_args);
        const auto primary_outcome =
            classify_iptables_command(primary);
        if (primary_outcome ==
            IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(primary_args, primary);
            throw FirewallError(
                "iptables PREROUTING dispatcher verification failed");
        }
        if (primary_outcome ==
            IptablesCommandOutcome::TransientFailure) {
            if (primary.timed_out ||
                attempt == iptables_control_retry_delays.size()) {
                record_iptables_control_failure(primary_args, primary);
                throw TransientFirewallError(
                    "iptables PREROUTING verification was temporarily unavailable");
            }
            std::this_thread::sleep_for(
                iptables_control_retry_delays[attempt]);
            continue;
        }

        const auto output = run_iptables_control(output_args);
        const auto output_outcome =
            classify_iptables_command(output);
        if (output_outcome ==
            IptablesCommandOutcome::PermanentFailure) {
            record_iptables_control_failure(output_args, output);
            throw FirewallError(
                "iptables OUTPUT or companion hook verification failed");
        }
        if (output_outcome ==
            IptablesCommandOutcome::TransientFailure) {
            if (output.timed_out ||
                attempt == iptables_control_retry_delays.size()) {
                record_iptables_control_failure(output_args, output);
                throw TransientFirewallError(
                    "iptables OUTPUT verification was temporarily unavailable");
            }
            std::this_thread::sleep_for(
                iptables_control_retry_delays[attempt]);
            continue;
        }

        const bool primary_matches =
            parse_live_generation(
                primary.stdout_output,
                primary_dispatcher,
                prerouting_generation_chain(
                    FirewallSetGeneration::A, ipv6),
                prerouting_generation_chain(
                    FirewallSetGeneration::B, ipv6)) == expected &&
            count_exact_jump(
                primary.stdout_output,
                "PREROUTING",
                primary_dispatcher) == 1;
        const bool output_matches =
            parse_live_generation(
                output.stdout_output,
                OUTPUT_CHAIN_NAME,
                generation_output_chain(FirewallSetGeneration::A),
                generation_output_chain(FirewallSetGeneration::B)) ==
                expected &&
            count_exact_jump(
                output.stdout_output,
                "OUTPUT",
                OUTPUT_CHAIN_NAME) == 1 &&
            (!use_raw_prerouting_ || ipv6 ||
             count_exact_jump(
                 output.stdout_output,
                 "PREROUTING",
                 RAW_CONNTRACK_CHAIN_NAME) == 1);
        if (primary_matches && output_matches) {
            return;
        }

        if (attempt != iptables_control_retry_delays.size()) {
            Logger::instance().verbose(
                "iptables generation verification raced with a firmware "
                "firewall update; retrying in {} ms ({}/{})",
                iptables_control_retry_delays[attempt].count(),
                attempt + 1,
                iptables_control_retry_delays.size());
            std::this_thread::sleep_for(
                iptables_control_retry_delays[attempt]);
        }
    }

    throw TransientFirewallError(
        "iptables generation changed before verification completed");
}

std::map<std::string, IptablesFirewall::PublishedUdpPeerClassifier>
IptablesFirewall::build_pending_udp_peer_classifiers(
    const FirewallGlobalPrefilter& prefilter,
    bool effective_ipv6) const {
    std::map<std::string, PublishedUdpPeerClassifier> published;
    const auto is_exact_udp_peer_classifier = [](
        const PendingRule& rule,
        const std::string& set_name,
        bool ipv6) {
        const auto& criteria = rule.criteria;
        return rule.action == PendingRule::Mark && !rule.output &&
               rule.ipv6 == ipv6 &&
               !criteria.dst_set_name.has_value() &&
               criteria.src_udp_peer_set_name == set_name &&
               !criteria.dscp.has_value() &&
               criteria.proto == L4Proto::Udp &&
               !criteria.persist_conntrack_mark &&
               criteria.src_port.empty() && criteria.dst_port.empty() &&
               criteria.src_addr.empty() && criteria.dst_addr.empty() &&
               !criteria.negate_src_port && !criteria.negate_dst_port &&
               !criteria.negate_src_addr && !criteria.negate_dst_addr;
    };

    for (const auto& set : pending_sets_) {
        if (!set.source_udp_peer) {
            continue;
        }
        const bool ipv6 = set.family_str == "inet6";
        if ((ipv6 && !effective_ipv6) ||
            (!ipv6 && set.family_str != "inet")) {
            continue;
        }

        const PendingRule* classifier = nullptr;
        bool ambiguous = false;
        for (const auto& rule : pending_rules_) {
            if (!is_exact_udp_peer_classifier(rule, set.name, ipv6)) {
                continue;
            }
            if (classifier != nullptr) {
                ambiguous = true;
                break;
            }
            classifier = &rule;
        }
        if (classifier == nullptr || ambiguous) {
            continue;
        }

        PublishedUdpPeerClassifier state;
        state.family = ipv6 ? AF_INET6 : AF_INET;
        state.timeout = set.timeout;
        state.generation = ipv6
            ? target_v6_generation_
            : target_v4_generation_;
        const std::string active_chain =
            prerouting_generation_chain(state.generation, ipv6);
        const bool allow_conntrack = !(use_raw_prerouting_ && !ipv6);
        bool valid = true;
        for (auto line : build_rule_lines(
                 *classifier, prefilter, allow_conntrack)) {
            while (!line.empty() &&
                   (line.back() == '\n' || line.back() == '\r')) {
                line.pop_back();
            }
            const std::string prefix =
                std::string("-A ") + CHAIN_NAME + " ";
            if (line.rfind(prefix, 0) != 0) {
                valid = false;
                break;
            }
            line.replace(3U, std::strlen(CHAIN_NAME), active_chain);
            state.expected_rules.push_back(std::move(line));
        }
        if (valid && !state.expected_rules.empty()) {
            if (use_raw_prerouting_ && !ipv6) {
                state.expected_raw_conntrack_bypass_rule =
                    keen_pbr3::format(
                        "-A {} -p udp -m set --match-set {} "
                        "src,dst,dst -j RETURN",
                        RAW_CONNTRACK_CHAIN_NAME,
                        set.name);
            }
            published.emplace(set.name, std::move(state));
        }
    }
    return published;
}

bool IptablesFirewall::classifier_rules_present(
    const std::string& rules,
    const std::string& set_name,
    const std::vector<std::string>& expected_rules) {
    if (set_name.empty() || expected_rules.empty()) {
        return false;
    }

    const auto tokenize = [](const std::string& line) {
        std::vector<std::string> tokens;
        std::istringstream input(line);
        std::string token;
        while (input >> token) {
            tokens.push_back(std::move(token));
        }
        return tokens;
    };
    const auto canonical_rule_key = [&tokenize](const std::string& line)
        -> std::optional<std::string> {
        auto tokens = tokenize(line);
        if (tokens.size() < 5U || tokens[0] != "-A" ||
            tokens[1].empty()) {
            return std::nullopt;
        }
        const auto jump = std::find(
            tokens.begin() + 2, tokens.end(), "-j");
        if (jump == tokens.end() || jump + 1 == tokens.end() ||
            std::find(jump + 1, tokens.end(), "-j") != tokens.end()) {
            return std::nullopt;
        }

        // Match predicates before -j form a conjunction, so iptables may
        // render them in a different canonical order than iptables-restore
        // received. Compare their exact token multisets while retaining the
        // chain and target boundary. Inputs here are kernel-rendered valid
        // rules or our own valid builder output, never arbitrary shell text.
        std::vector<std::string> matches(tokens.begin() + 2, jump);
        std::sort(matches.begin(), matches.end());
        const std::string target = *(jump + 1);
        std::vector<std::string> target_options(jump + 2, tokens.end());
        std::sort(target_options.begin(), target_options.end());

        std::string key = tokens[1];
        const auto append = [&key](const std::string& value) {
            key += "\x1f" + std::to_string(value.size()) + ":" + value;
        };
        append("matches");
        for (const auto& token : matches) {
            append(token);
        }
        append("target");
        append(target);
        for (const auto& token : target_options) {
            append(token);
        }
        return key;
    };
    const auto references_set = [&tokenize, &set_name](
                                    const std::string& line) {
        const auto tokens = tokenize(line);
        for (std::size_t index = 0U; index + 1U < tokens.size(); ++index) {
            if (tokens[index] == "--match-set" &&
                tokens[index + 1U] == set_name) {
                return true;
            }
        }
        return false;
    };

    std::map<std::string, std::size_t> expected_counts;
    for (const auto& expected : expected_rules) {
        const auto key = canonical_rule_key(expected);
        if (!key.has_value() ||
            !expected_counts.emplace(*key, 0U).second) {
            return false;
        }
    }

    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const auto key = canonical_rule_key(line);
        if (key.has_value()) {
            const auto expected = expected_counts.find(*key);
            if (expected != expected_counts.end()) {
                ++expected->second;
                continue;
            }
        }
        if (references_set(line)) {
            // Any extra rule referencing the same authority is drift: it may
            // alter the mark, omit the RETURN, or broaden the protocol.
            return false;
        }
    }
    return std::all_of(
        expected_counts.begin(), expected_counts.end(),
        [](const auto& item) { return item.second == 1U; });
}

bool IptablesFirewall::udp_peer_classifier_is_published(
    const std::string& set_name,
    const PublishedUdpPeerClassifier& classifier) const noexcept {
    try {
        const bool ipv6 = classifier.family == AF_INET6;
        if (!ipv6 && classifier.family != AF_INET) {
            return false;
        }
        verify_applied_generation(ipv6, classifier.generation);
        const char* command = ipv6 ? "ip6tables" : "iptables";
        const std::string chain =
            prerouting_generation_chain(classifier.generation, ipv6);
        const std::vector<std::string> args{
            command,
            "-t",
            prerouting_table_name(ipv6),
            "-S",
            chain};
        const auto result = run_iptables_control(args);
        if (classify_iptables_command(result) !=
            IptablesCommandOutcome::Success) {
            return false;
        }
        if (!classifier_rules_present(
                result.stdout_output,
                set_name,
                classifier.expected_rules)) {
            return false;
        }
        if (!classifier.expected_raw_conntrack_bypass_rule.has_value()) {
            return true;
        }

        const std::vector<std::string> companion_args{
            "iptables", "-t", "mangle", "-S", RAW_CONNTRACK_CHAIN_NAME};
        const auto companion = run_iptables_control(companion_args);
        if (classify_iptables_command(companion) !=
            IptablesCommandOutcome::Success) {
            return false;
        }
        return raw_conntrack_bypass_precedes_save(
            companion.stdout_output,
            set_name,
            *classifier.expected_raw_conntrack_bypass_rule);
    } catch (...) {
        return false;
    }
}

bool IptablesFirewall::raw_conntrack_bypass_precedes_save(
    const std::string& rules,
    const std::string& set_name,
    const std::string& expected_rule) {
    if (!classifier_rules_present(
            rules, set_name, {expected_rule})) {
        return false;
    }

    bool saw_bypass = false;
    std::istringstream input(rules);
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream tokens(line);
        std::vector<std::string> values;
        std::string value;
        while (tokens >> value) {
            values.push_back(std::move(value));
        }

        bool references_set = false;
        bool saves_conntrack_mark = false;
        for (std::size_t index = 0U; index < values.size(); ++index) {
            if (index + 1U < values.size() &&
                values[index] == "--match-set" &&
                values[index + 1U] == set_name) {
                references_set = true;
            }
            if (index + 1U < values.size() && values[index] == "-j" &&
                values[index + 1U] == "CONNMARK" &&
                std::find(
                    values.begin() + static_cast<std::ptrdiff_t>(index + 2U),
                    values.end(),
                    "--save-mark") != values.end()) {
                saves_conntrack_mark = true;
            }
        }
        if (saves_conntrack_mark && !saw_bypass) {
            return false;
        }
        if (references_set) {
            saw_bypass = true;
        }
    }
    return saw_bypass;
}

std::vector<std::string> IptablesFirewall::build_proto_port_fragments(
    L4Proto proto,
    const PortSpec& src_port,
    const PortSpec& dst_port,
    bool negate_src_port,
    bool negate_dst_port) {
    if (proto == L4Proto::Any && src_port.empty() && dst_port.empty()) {
        return {""};
    }

    const std::string proto_fragment =
        proto == L4Proto::Any
            ? ""
            : " -p " + std::string(l4_proto_name(proto));

    auto chunk_multiport_spec = [](const PortSpec& spec) {
        std::vector<PortSpec> chunks;
        PortSpec chunk;
        size_t slots = 0;
        for (const auto& range : spec.ranges) {
            // xt_multiport accepts at most 15 ports. A range consumes two
            // slots because both endpoints are passed to the matcher.
            const size_t range_slots = range.from == range.to ? 1 : 2;
            if (!chunk.ranges.empty() && slots + range_slots > 15) {
                chunks.push_back(std::move(chunk));
                chunk = PortSpec{};
                slots = 0;
            }
            chunk.ranges.push_back(range);
            slots += range_slots;
        }
        if (!chunk.ranges.empty()) {
            chunks.push_back(std::move(chunk));
        }
        return chunks;
    };

    auto build_side_fragments =
        [&](const PortSpec& spec, bool source, bool negated) {
            if (spec.empty()) {
                return std::vector<std::string>{""};
            }

            const bool is_list =
                classify_port_spec(spec) == PortSpecKind::List;
            const std::string singular =
                source ? " --sport " : " --dport ";
            const std::string plural =
                source ? " --sports " : " --dports ";
            if (!is_list) {
                return std::vector<std::string>{
                    std::string(negated ? " !" : "") +
                    singular +
                    spec.to_iptables_string()};
            }

            const auto chunks = chunk_multiport_spec(spec);
            if (negated) {
                // !(A union B) is expressed as !A AND !B in one rule.
                std::string fragment;
                for (const auto& chunk : chunks) {
                    fragment += " -m multiport !" +
                                plural +
                                chunk.to_iptables_string();
                }
                return std::vector<std::string>{std::move(fragment)};
            }

            std::vector<std::string> fragments;
            fragments.reserve(chunks.size());
            for (const auto& chunk : chunks) {
                fragments.push_back(
                    " -m multiport" +
                    plural +
                    chunk.to_iptables_string());
            }
            return fragments;
        };

    const auto src_fragments =
        build_side_fragments(src_port, /*source=*/true, negate_src_port);
    const auto dst_fragments =
        build_side_fragments(dst_port, /*source=*/false, negate_dst_port);

    std::vector<std::string> fragments;
    fragments.reserve(src_fragments.size() * dst_fragments.size());
    for (const auto& src : src_fragments) {
        for (const auto& dst : dst_fragments) {
            fragments.push_back(proto_fragment + src + dst);
        }
    }
    return fragments;
}

std::string IptablesFirewall::build_prefilter_lines(
    const FirewallGlobalPrefilter& prefilter,
    const std::string& chain,
    bool allow_conntrack,
    bool ipv6) {
    std::string lines =
        build_bypass_inbound_interface_lines(prefilter, chain);
    lines += build_bypass_source_lines(prefilter, chain, ipv6);
    lines += build_bypass_bridge_source_lines(
        prefilter, chain, ipv6);
    // The raw table runs before conntrack. Classify every forwarded packet
    // there instead of emitting a matcher that cannot be valid at this hook.
    if (allow_conntrack) {
        lines += build_conntrack_prefilter_lines(prefilter, chain);
    }
    if (allow_conntrack && prefilter.skip_established_or_dnat) {
        lines += keen_pbr3::format(
            "-A {} -m conntrack --ctstate DNAT -j RETURN\n",
            chain);
    }

    lines += build_skip_marked_packet_line(prefilter, chain);

    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()
        && prefilter.inbound_interfaces->size() == 1
        && (ipv6
                ? prefilter.include_source_cidrs_v6.empty()
                : prefilter.include_source_cidrs_v4.empty())) {
        lines += keen_pbr3::format(
            "-A {} ! -i {} -j RETURN\n",
            chain,
            prefilter.inbound_interfaces->front());
    }

    return lines;
}

std::string IptablesFirewall::build_conntrack_prefilter_lines(
    const FirewallGlobalPrefilter& prefilter,
    const std::string& chain) {
    if (!prefilter.restore_conntrack_mark ||
        prefilter.conntrack_mark_mask == 0) {
        return {};
    }

    const std::string mask =
        keen_pbr3::format("{:#x}", prefilter.conntrack_mark_mask);
    return keen_pbr3::format(
        "-A {} -m conntrack --ctdir ORIGINAL -m connmark ! --mark 0/{} "
        "-j CONNMARK --restore-mark --nfmask {} --ctmask {}\n"
        "-A {} -m conntrack --ctdir ORIGINAL -m connmark ! --mark 0/{} "
        "-j RETURN\n",
        chain,
        mask,
        mask,
        mask,
        chain,
        mask);
}

std::string IptablesFirewall::build_skip_marked_packet_line(
    const FirewallGlobalPrefilter& prefilter,
    const std::string& chain) {
    if (!prefilter.skip_marked_packets) {
        return {};
    }

    // This public setting protects marks owned by NDMS and other firewall
    // policies: any pre-existing skb mark must bypass keen-pbr entirely.
    // conntrack_mark_mask is deliberately not used here; it scopes only the
    // bits restored and written by keen-pbr's own flow-stickiness rules.
    return keen_pbr3::format(
        "-A {} -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n",
        chain);
}

std::string IptablesFirewall::build_bypass_inbound_interface_lines(
    const FirewallGlobalPrefilter& prefilter,
    const std::string& chain) {
    std::string lines;
    for (const auto& interface : prefilter.bypass_inbound_interfaces) {
        lines += keen_pbr3::format(
            "-A {} -i {} -j RETURN\n",
            chain,
            interface);
    }
    return lines;
}

std::string IptablesFirewall::build_bypass_source_lines(
    const FirewallGlobalPrefilter& prefilter,
    const std::string& chain,
    bool ipv6) {
    const auto& selectors = ipv6
        ? prefilter.bypass_source_selectors_v6
        : prefilter.bypass_source_selectors_v4;
    std::string lines;
    for (const auto& selector : selectors) {
        if (selector.interface.empty()) {
            // Fail closed: a source pool is not sufficient proof that the
            // packet arrived from the native VPN server.
            continue;
        }
        lines += keen_pbr3::format(
            "-A {} -i {} -s {} -j RETURN\n",
            chain,
            selector.interface,
            selector.cidr);
    }
    return lines;
}

std::string IptablesFirewall::build_bypass_bridge_source_lines(
    const FirewallGlobalPrefilter& prefilter,
    const std::string& chain,
    bool ipv6) {
    const auto& selectors = ipv6
        ? prefilter.bypass_bridge_source_selectors_v6
        : prefilter.bypass_bridge_source_selectors_v4;
    std::string lines;
    for (const auto& selector : selectors) {
        if (selector.interface.empty() ||
            selector.bridge_port.empty()) {
            continue;
        }
        lines += keen_pbr3::format(
            "-A {} -i {} -m physdev --physdev-in {} "
            "-s {} -j RETURN\n",
            chain,
            selector.interface,
            selector.bridge_port,
            selector.cidr);
    }
    return lines;
}

std::vector<std::string> IptablesFirewall::build_rule_lines(
    const PendingRule& pr,
    const FirewallGlobalPrefilter& prefilter,
    bool allow_conntrack) {
    // OUTPUT-scoped rules live in KeenPbrOutput and match router-originated
    // packets, which never carry an input interface.
    const char* chain = pr.output ? OUTPUT_CHAIN_NAME : CHAIN_NAME;
    // iptables cannot express a multi-value negated -i guard in one rule, so
    // multi-interface allowlists are expanded into one positive -i match per rule.
    std::vector<std::string> iface_frags;
    if (!pr.output
        && prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()) {
        const auto& source_cidrs = pr.ipv6
            ? prefilter.include_source_cidrs_v6
            : prefilter.include_source_cidrs_v4;
        const bool needs_explicit_scope =
            prefilter.inbound_interfaces->size() > 1 ||
            !source_cidrs.empty();
        if (!needs_explicit_scope) {
            iface_frags.push_back("");
        } else {
            iface_frags.reserve(
                prefilter.inbound_interfaces->size() +
                source_cidrs.size());
        }
        for (const auto& iface : *prefilter.inbound_interfaces) {
            if (needs_explicit_scope) {
                iface_frags.push_back(" -i " + iface);
            }
        }
        for (const auto& cidr : source_cidrs) {
            iface_frags.push_back(" -s " + cidr);
        }
    } else {
        iface_frags.push_back("");
    }

    std::string addr_frag;
    if (!pr.criteria.src_addr.empty())
        addr_frag += std::string(pr.criteria.negate_src_addr ? " !" : "") + " -s " + pr.criteria.src_addr[0];
    if (!pr.criteria.dst_addr.empty())
        addr_frag += std::string(pr.criteria.negate_dst_addr ? " !" : "") + " -d " + pr.criteria.dst_addr[0];
    std::string dscp_frag;
    if (pr.criteria.dscp.has_value()) {
        dscp_frag = keen_pbr3::format(" -m dscp --dscp {}", static_cast<int>(*pr.criteria.dscp));
    }
    std::vector<std::string> lines;
    lines.reserve(iface_frags.size() * 2);
    auto append_mark_and_save = [&](std::string mark_line) {
        lines.push_back(mark_line);
        if (!pr.criteria.persist_conntrack_mark || !allow_conntrack ||
            !prefilter.restore_conntrack_mark ||
            prefilter.conntrack_mark_mask == 0) {
            return;
        }
        const auto target = mark_line.find(" -j MARK ");
        if (target == std::string::npos) {
            return;
        }
        mark_line.replace(
            target,
            mark_line.size() - target,
            keen_pbr3::format(
                " -j CONNMARK --save-mark --nfmask {:#x} --ctmask {:#x}\n",
                prefilter.conntrack_mark_mask,
                prefilter.conntrack_mark_mask));
        lines.push_back(std::move(mark_line));
    };
    for (const auto proto : expand_l4_protos_for_iptables(pr.criteria)) {
        const auto port_fragments = build_proto_port_fragments(
            proto,
            pr.criteria.src_port,
            pr.criteria.dst_port,
            pr.criteria.negate_src_port,
            pr.criteria.negate_dst_port);

        for (const auto& pp : port_fragments) {
            for (const auto& iface_frag : iface_frags) {
                const auto& set_name =
                    pr.criteria.src_udp_peer_set_name.has_value()
                    ? pr.criteria.src_udp_peer_set_name
                    : pr.criteria.dst_set_name;
                const char* set_dimensions =
                    pr.criteria.src_udp_peer_set_name.has_value()
                    ? "src,dst,dst"
                    : "dst";
                if (!set_name.has_value()) {
                    if (pr.action == PendingRule::Mark) {
                        const std::string mark_target = keen_pbr3::format(
                            "-j MARK --set-xmark {:#x}/{:#x}",
                            pr.fwmark,
                            pr.fwmark_mask);
                        append_mark_and_save(keen_pbr3::format(
                            "-A {}{}{}{}{} {}\n",
                            chain,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp,
                            mark_target));
                        lines.push_back(keen_pbr3::format(
                            "-A {}{}{}{}{} -j RETURN\n",
                            chain,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    } else if (pr.action == PendingRule::Drop) {
                        lines.push_back(keen_pbr3::format(
                            "-A {}{}{}{}{} -j DROP\n",
                            chain,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    } else {
                        lines.push_back(keen_pbr3::format(
                            "-A {}{}{}{}{} -j RETURN\n",
                            chain,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    }
                } else {
                    if (pr.action == PendingRule::Mark) {
                        const std::string mark_target = keen_pbr3::format(
                            "-j MARK --set-xmark {:#x}/{:#x}",
                            pr.fwmark,
                            pr.fwmark_mask);
                        append_mark_and_save(keen_pbr3::format(
                            "-A {} -m set --match-set {} {}{}{}{}{} {}\n",
                            chain,
                            *set_name,
                            set_dimensions,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp,
                            mark_target));
                        lines.push_back(keen_pbr3::format(
                            "-A {} -m set --match-set {} {}{}{}{}{} "
                            "-j RETURN\n",
                            chain,
                            *set_name,
                            set_dimensions,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    } else if (pr.action == PendingRule::Drop) {
                        lines.push_back(keen_pbr3::format(
                            "-A {} -m set --match-set {} {}{}{}{}{} "
                            "-j DROP\n",
                            chain,
                            *set_name,
                            set_dimensions,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    } else {
                        lines.push_back(keen_pbr3::format(
                            "-A {} -m set --match-set {} {}{}{}{}{} "
                            "-j RETURN\n",
                            chain,
                            *set_name,
                            set_dimensions,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    }
                }
            }
        }
    }

    return lines;
}

std::string IptablesFirewall::build_ipt_script(bool ipv6,
                                                const std::vector<PendingRule>& rules,
                                                const FirewallGlobalPrefilter& prefilter) {
    std::string s;
    s += keen_pbr3::format("*mangle\n:{} - [0:0]\n-A PREROUTING -j {}\n",
                           CHAIN_NAME, CHAIN_NAME);
    s += build_prefilter_lines(
        prefilter, CHAIN_NAME, /*allow_conntrack=*/true, ipv6);
    for (const auto& pr : rules) {
        if (pr.ipv6 != ipv6 || pr.output) continue;
        for (const auto& line : build_rule_lines(
                 pr, prefilter, /*allow_conntrack=*/true)) {
            s += line;
        }
    }
    // Router-originated traffic hook. The scaffold is always materialized so
    // cleanup and diagnostics stay deterministic; the inbound-interface
    // prefilter is intentionally omitted (OUTPUT packets carry no in-iface).
    s += keen_pbr3::format(":{} - [0:0]\n-A OUTPUT -j {}\n",
                           OUTPUT_CHAIN_NAME, OUTPUT_CHAIN_NAME);
    s += build_conntrack_prefilter_lines(prefilter, OUTPUT_CHAIN_NAME);
    s += build_skip_marked_packet_line(prefilter, OUTPUT_CHAIN_NAME);
    for (const auto& pr : rules) {
        if (pr.ipv6 != ipv6 || !pr.output) continue;
        for (const auto& line : build_rule_lines(
                 pr, prefilter, /*allow_conntrack=*/true)) {
            s += line;
        }
    }
    s += "COMMIT\n";
    return s;
}

std::string IptablesFirewall::build_forward_udp_reject_script(
    bool ipv6,
    const std::string& generation_chain,
    const std::vector<PendingForwardUdpReject>& rules) {
    std::string script = "*filter\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n",
        generation_chain,
        generation_chain);
    for (const auto& rule : rules) {
        if (rule.ipv6 != ipv6) {
            continue;
        }
        script += keen_pbr3::format(
            "-A {} -m mark --mark {:#x}/{:#x} -p udp --dport {} "
            "-m set --match-set {} dst -j REJECT --reject-with {}\n",
            generation_chain,
            rule.fwmark,
            rule.fwmark_mask,
            rule.destination_port,
            rule.set_name,
            ipv6 ? "icmp6-port-unreachable" : "icmp-port-unreachable");
    }
    script += "COMMIT\n";
    return script;
}

std::string IptablesFirewall::build_exact_tcp_reset_rule_line(
    const FirewallExactTcpResetRule& rule) {
    std::string line = keen_pbr3::format(
        "-A {}", EXACT_TCP_RESET_CHAIN_NAME);
    for (const auto& argument : build_exact_tcp_reset_rule_spec(rule)) {
        line += " " + argument;
    }
    line.push_back('\n');
    return line;
}

std::vector<std::string>
IptablesFirewall::build_exact_tcp_reset_rule_spec(
    const FirewallExactTcpResetRule& rule) {
    return {
        "-s",
        rule.source,
        "-d",
        rule.destination,
        "-p",
        "tcp",
        "-m",
        "tcp",
        "--sport",
        std::to_string(rule.source_port),
        "--dport",
        std::to_string(rule.destination_port),
        "-m",
        "mark",
        "--mark",
        keen_pbr3::format("{:#x}/0xffffffff", rule.full_mark),
        "--tcp-flags",
        "SYN,RST,ACK",
        "ACK",
        "-j",
        "REJECT",
        "--reject-with",
        "tcp-reset",
    };
}

std::string IptablesFirewall::build_exact_tcp_reset_script(
    bool chain_exists,
    std::size_t hook_count,
    const std::vector<FirewallExactTcpResetRule>& rules) {
    std::string script = "*filter\n";
    if (!chain_exists && !rules.empty()) {
        script += keen_pbr3::format(
            ":{} - [0:0]\n", EXACT_TCP_RESET_CHAIN_NAME);
    }
    if (chain_exists) {
        script += keen_pbr3::format(
            "-F {}\n", EXACT_TCP_RESET_CHAIN_NAME);
    }
    for (const auto& rule : rules) {
        script += build_exact_tcp_reset_rule_line(rule);
    }
    for (std::size_t index = 0U; index < hook_count; ++index) {
        script += keen_pbr3::format(
            "-D FORWARD -j {}\n", EXACT_TCP_RESET_CHAIN_NAME);
    }
    if (rules.empty()) {
        if (chain_exists) {
            script += keen_pbr3::format(
                "-X {}\n", EXACT_TCP_RESET_CHAIN_NAME);
        }
    } else {
        // Rule one is deliberate: firmware commonly accepts ESTABLISHED TCP
        // later in FORWARD, which would otherwise hide the exact reset rule.
        script += keen_pbr3::format(
            "-I FORWARD 1 -j {}\n", EXACT_TCP_RESET_CHAIN_NAME);
    }
    script += "COMMIT\n";
    return script;
}

void IptablesFirewall::stage_forward_reject_generation(
    bool ipv6,
    FirewallSetGeneration generation) const {
    const char* command = ipv6 ? "ip6tables" : "iptables";
    const std::vector<std::string> inspect_args{
        command, "-t", "filter", "-S"};
    const auto live = run_iptables_control(inspect_args);
    if (classify_iptables_command(live) !=
        IptablesCommandOutcome::Success) {
        record_iptables_control_failure(inspect_args, live);
        throw TransientFirewallError(
            "could not inspect the inactive Meta UDP/443 generation "
            "immediately before staging");
    }
    const char* target = forward_reject_generation_chain(generation);
    const auto dispatcher_state = parse_live_generation(
        live.stdout_output,
        META_UDP_443_CHAIN_NAME,
        forward_reject_generation_chain(FirewallSetGeneration::A),
        forward_reject_generation_chain(FirewallSetGeneration::B));
    const auto target_state = generation == FirewallSetGeneration::A
        ? LiveGenerationState::A
        : LiveGenerationState::B;
    if (dispatcher_state == LiveGenerationState::Invalid ||
        dispatcher_state == target_state ||
        jump_reference_count(live.stdout_output, target) != 0U ||
        jump_reference_count(
            live.stdout_output, META_UDP_443_CHAIN_NAME) !=
            exact_jump_positions(
                live.stdout_output,
                "FORWARD",
                META_UDP_443_CHAIN_NAME).size() ||
        !forward_reject_generation_references_are_owned(
            live.stdout_output,
            dispatcher_state,
            forward_reject_generation_chain(FirewallSetGeneration::A),
            forward_reject_generation_chain(FirewallSetGeneration::B))) {
        throw TransientFirewallError(
            "the inactive Meta UDP/443 generation has an unexpected live "
            "reference; refusing to flush it");
    }
    pipe_to_cmd(
        {ipv6 ? "ip6tables-restore" : "iptables-restore",
         "--noflush",
         "--counters"},
        build_forward_udp_reject_script(
            ipv6,
            forward_reject_generation_chain(generation),
            pending_forward_udp_rejects_));
}

std::string IptablesFirewall::build_generation_ipt_script(
    bool ipv6,
    const std::string& prerouting_chain,
    const std::string& output_chain,
    bool replace_active_chains,
    const std::vector<PendingRule>& rules,
    const FirewallGlobalPrefilter& prefilter) {
    (void)replace_active_chains;
    std::string script = "*mangle\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n"
        ":{} - [0:0]\n-F {}\n"
        ":{} - [0:0]\n-F {}\n"
        ":{} - [0:0]\n-F {}\n"
        "-A {} -j {}\n-A {} -j {}\n",
        prerouting_chain, prerouting_chain,
        output_chain, output_chain,
        CHAIN_NAME, CHAIN_NAME,
        OUTPUT_CHAIN_NAME, OUTPUT_CHAIN_NAME,
        CHAIN_NAME, prerouting_chain,
        OUTPUT_CHAIN_NAME, output_chain);

    auto retarget_line = [&](std::string line) {
        size_t pos = 0;
        while ((pos = line.find(OUTPUT_CHAIN_NAME, pos)) != std::string::npos) {
            line.replace(pos, std::strlen(OUTPUT_CHAIN_NAME), output_chain);
            pos += output_chain.size();
        }
        pos = 0;
        while ((pos = line.find(CHAIN_NAME, pos)) != std::string::npos) {
            line.replace(pos, std::strlen(CHAIN_NAME), prerouting_chain);
            pos += prerouting_chain.size();
        }
        return line;
    };

    std::istringstream prefilter_input(build_prefilter_lines(
        prefilter,
        CHAIN_NAME,
        /*allow_conntrack=*/true,
        ipv6));
    std::string line;
    while (std::getline(prefilter_input, line)) {
        if (!line.empty()) {
            script += retarget_line(line) + "\n";
        }
    }

    script += build_conntrack_prefilter_lines(prefilter, output_chain);
    script += build_skip_marked_packet_line(prefilter, output_chain);
    for (const auto& rule : rules) {
        if (rule.ipv6 != ipv6) {
            continue;
        }
        for (auto rule_line : build_rule_lines(
                 rule, prefilter, /*allow_conntrack=*/true)) {
            script += retarget_line(std::move(rule_line));
        }
    }
    script += "COMMIT\n";
    return script;
}

std::string IptablesFirewall::build_raw_prerouting_script(
    const std::string& prerouting_chain,
    bool replace_active_chain,
    const std::vector<PendingRule>& rules,
    const FirewallGlobalPrefilter& prefilter) {
    (void)replace_active_chain;
    std::string script = "*raw\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n"
        ":{} - [0:0]\n-F {}\n"
        "-A {} -j {}\n",
        prerouting_chain, prerouting_chain,
        RAW_CHAIN_NAME, RAW_CHAIN_NAME,
        RAW_CHAIN_NAME, prerouting_chain);

    script += build_prefilter_lines(
        prefilter,
        prerouting_chain,
        /*allow_conntrack=*/false,
        /*ipv6=*/false);

    for (const auto& rule : rules) {
        if (rule.ipv6 || rule.output) {
            continue;
        }
        for (auto line : build_rule_lines(
                 rule, prefilter, /*allow_conntrack=*/false)) {
            size_t position = 0;
            while ((position = line.find(CHAIN_NAME, position)) !=
                   std::string::npos) {
                line.replace(position, std::strlen(CHAIN_NAME),
                             prerouting_chain);
                position += prerouting_chain.size();
            }
            script += line;
        }
    }
    script += "COMMIT\n";
    return script;
}

std::string IptablesFirewall::build_raw_conntrack_script(
    bool replace_active_chain,
    const FirewallGlobalPrefilter& prefilter,
    const std::vector<PendingRule>& rules) {
    (void)replace_active_chain;
    std::string script = "*mangle\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n",
        RAW_CONNTRACK_CHAIN_NAME,
        RAW_CONNTRACK_CHAIN_NAME);

    script += build_bypass_inbound_interface_lines(
        prefilter, RAW_CONNTRACK_CHAIN_NAME);
    script += build_bypass_source_lines(
        prefilter, RAW_CONNTRACK_CHAIN_NAME, /*ipv6=*/false);
    script += build_bypass_bridge_source_lines(
        prefilter, RAW_CONNTRACK_CHAIN_NAME, /*ipv6=*/false);
    script += build_conntrack_prefilter_lines(
        prefilter, RAW_CONNTRACK_CHAIN_NAME);
    std::set<std::string> transient_udp_peer_sets;
    for (const auto& rule : rules) {
        if (!rule.ipv6 && !rule.output &&
            rule.action == PendingRule::Mark &&
            !rule.criteria.persist_conntrack_mark &&
            rule.criteria.proto == L4Proto::Udp &&
            rule.criteria.src_udp_peer_set_name.has_value()) {
            transient_udp_peer_sets.insert(
                *rule.criteria.src_udp_peer_set_name);
        }
    }
    // raw PREROUTING runs before conntrack exists. Its small mangle companion
    // normally copies every owned packet mark into ctmark; skip that copy for
    // expiring call-affinity tuples so their authority really ends with the
    // set lease.
    for (const auto& set_name : transient_udp_peer_sets) {
        script += keen_pbr3::format(
            "-A {} -p udp -m set --match-set {} src,dst,dst -j RETURN\n",
            RAW_CONNTRACK_CHAIN_NAME,
            set_name);
    }
    if (prefilter.restore_conntrack_mark &&
        prefilter.conntrack_mark_mask != 0) {
        const std::string mask =
            keen_pbr3::format("{:#x}", prefilter.conntrack_mark_mask);
        script += keen_pbr3::format(
            "-A {} -m conntrack --ctdir ORIGINAL "
            "-m mark ! --mark 0/{} "
            "-j CONNMARK --save-mark --nfmask {} --ctmask {}\n",
            RAW_CONNTRACK_CHAIN_NAME,
            mask,
            mask,
            mask);
    }
    script += "COMMIT\n";
    return script;
}

std::string IptablesFirewall::build_output_generation_script(
    const std::string& output_chain,
    bool replace_active_chain,
    const std::vector<PendingRule>& rules,
    const FirewallGlobalPrefilter& prefilter) {
    (void)replace_active_chain;
    std::string script = "*mangle\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n"
        ":{} - [0:0]\n-F {}\n"
        "-A {} -j {}\n",
        output_chain, output_chain,
        OUTPUT_CHAIN_NAME, OUTPUT_CHAIN_NAME,
        OUTPUT_CHAIN_NAME, output_chain);

    script += build_conntrack_prefilter_lines(prefilter, output_chain);
    script += build_skip_marked_packet_line(prefilter, output_chain);

    for (const auto& rule : rules) {
        if (rule.ipv6 || !rule.output) {
            continue;
        }
        for (auto line : build_rule_lines(
                 rule, prefilter, /*allow_conntrack=*/true)) {
            size_t position = 0;
            while ((position = line.find(OUTPUT_CHAIN_NAME, position)) !=
                   std::string::npos) {
                line.replace(position, std::strlen(OUTPUT_CHAIN_NAME),
                             output_chain);
                position += output_chain.size();
            }
            script += line;
        }
    }
    script += "COMMIT\n";
    return script;
}

void IptablesFirewall::apply_nat_rules(
    bool effective_ipv6,
    FirewallApplyMode mode,
    const FirewallGlobalPrefilter& prefilter) {
    const bool snat_expected = router_origin_snat_requested_;
    const auto expected_snat_interfaces = snat_interfaces_;
    const auto expected_source_egress_snat_selectors_v4 =
        filter_source_egress_snat_selectors_by_family(
            source_egress_snat_selectors_, /*ipv6=*/false);
    const auto expected_source_egress_snat_selectors_v6 =
        filter_source_egress_snat_selectors_by_family(
            source_egress_snat_selectors_, /*ipv6=*/true);
    const uint32_t expected_snat_fwmark_mask = fwmark_mask();
    const bool nat_requested =
        dns_redirect_requested_ || router_origin_snat_requested_;
    const std::string nat_script_v4 =
        nat_requested
            ? build_dns_nat_script(
                  prefilter,
                  dns_redirect_requested_,
                  router_origin_snat_requested_,
                  snat_interfaces_,
                  /*ipv6=*/false,
                  fwmark_mask(),
                  source_egress_snat_selectors_,
                  udp_peer_sets_)
            : std::string{};
    const std::string nat_script_v6 =
        nat_requested
            ? build_dns_nat_script(
                  prefilter,
                  dns_redirect_requested_,
                  router_origin_snat_requested_,
                  snat_interfaces_,
                  /*ipv6=*/true,
                  fwmark_mask(),
                  source_egress_snat_selectors_,
                  udp_peer_sets_)
            : std::string{};

    bool ipv6_nat_backend_available = false;
    if (nat_requested) {
        // Determine absence of the IPv6 NAT table with a read-only capability
        // probe even when IPv6 is disabled: an available backend may still
        // contain stale chains from an earlier IPv6-enabled generation.
        // Restore, lock and hook failures are not capability failures and
        // must reach the outer reconciler instead of being downgraded to an
        // IPv4-only success.
        ipv6_nat_backend_available = ipv6_nat_table_available();
        if (effective_ipv6 && !ipv6_nat_backend_available) {
            Logger::instance().warn(
                "IPv6 nat table is unavailable; continuing IPv4-only");
        }
    } else {
        // Absence is also part of the applied contract. Remember an
        // inspectable IPv6 NAT family so a later firmware rebuild cannot
        // leave an old keen-pbr SNAT chain unnoticed merely because SNAT is
        // currently disabled.
        ipv6_nat_backend_available = ipv6_nat_table_available();
    }
    const bool apply_ipv6_nat =
        effective_ipv6 && ipv6_nat_backend_available;
    if (mode == FirewallApplyMode::PreserveSets && nat_requested) {
        // Phase 2 has converged, but the currently working NAT state is still
        // live. Validate both transactions before removing any active DNS
        // redirect or tunnel masquerade chain.
        preflight_nat_restore("iptables-restore", nat_script_v4);
        if (apply_ipv6_nat) {
            preflight_nat_restore("ip6tables-restore", nat_script_v6);
        }
    }

    if (!nat_requested && mode == FirewallApplyMode::PreserveSets) {
        // Removing NAT is intentional when both features are disabled. For a
        // replacement, never tear down the live chains before the new atomic
        // restore transaction has committed.
        cleanup_nat_rules_impl();
    }

    const auto reconcile_nat_hooks =
        [this](const char* command, bool ipv6) {
            if (dns_redirect_requested_) {
                reconcile_hook(
                    command,
                    "nat",
                    "PREROUTING",
                    DNS_NAT_CHAIN_NAME);
            } else {
                remove_nat_chain_checked(
                    command,
                    "PREROUTING",
                    DNS_NAT_CHAIN_NAME);
            }

            if (router_origin_snat_requested_) {
                reconcile_hook(
                    command,
                    "nat",
                    "POSTROUTING",
                    SNAT_CHAIN_NAME);
            } else {
                remove_nat_chain_checked(
                    command,
                    "POSTROUTING",
                    SNAT_CHAIN_NAME);
            }

            if (ipv6) {
                dns_nat_v6_created_ =
                    dns_redirect_requested_ ||
                    router_origin_snat_requested_;
            } else {
                dns_nat_v4_created_ =
                    dns_redirect_requested_ ||
                    router_origin_snat_requested_;
            }
        };

    if (nat_requested) {
        pipe_to_cmd(
            {"iptables-restore", "--noflush", "--counters"},
            nat_script_v4);
        reconcile_nat_hooks("iptables", /*ipv6=*/false);
        verify_owned_snat_after_apply(
            "iptables",
            snat_expected,
            expected_snat_interfaces,
            expected_source_egress_snat_selectors_v4,
            expected_snat_fwmark_mask);
        if (apply_ipv6_nat) {
            pipe_to_cmd(
                {"ip6tables-restore", "--noflush", "--counters"},
                nat_script_v6);
            reconcile_nat_hooks("ip6tables", /*ipv6=*/true);
            verify_owned_snat_after_apply(
                "ip6tables",
                snat_expected,
                expected_snat_interfaces,
                expected_source_egress_snat_selectors_v6,
                expected_snat_fwmark_mask);
        } else if (ipv6_nat_backend_available) {
            // IPv6 was explicitly disabled while its NAT backend remains
            // available. Remove any generation retained from an earlier
            // IPv6-enabled process only after IPv4 converged. Inspect live
            // state even when this fresh daemon has no in-memory ownership
            // flag for the old chains.
            cleanup_nat_family_checked("ip6tables", /*ipv6=*/true);
        } else {
            // No executable/table means there cannot be live IPv6 NAT state
            // reachable through this backend. Do not turn a valid IPv4-only
            // apply into a permanent failure.
            dns_nat_v6_created_ = false;
        }
    } else {
        verify_owned_snat_after_apply(
            "iptables",
            /*expected=*/false,
            {},
            {},
            expected_snat_fwmark_mask);
        if (ipv6_nat_backend_available) {
            verify_owned_snat_after_apply(
                "ip6tables",
                /*expected=*/false,
                {},
                {},
                expected_snat_fwmark_mask);
        }
    }

    last_applied_snat_v4_expected_ = snat_expected;
    last_applied_snat_v6_expected_ =
        snat_expected && apply_ipv6_nat;
    last_applied_snat_v6_managed_ =
        ipv6_nat_backend_available;
    last_applied_snat_interfaces_ = expected_snat_interfaces;
    last_applied_source_egress_snat_selectors_v4_ =
        expected_source_egress_snat_selectors_v4;
    last_applied_source_egress_snat_selectors_v6_ =
        expected_source_egress_snat_selectors_v6;
    last_applied_snat_fwmark_mask_ = expected_snat_fwmark_mask;
    dns_redirect_requested_ = false;
    router_origin_snat_requested_ = false;
    snat_interfaces_.clear();
    source_egress_snat_selectors_.clear();
}

void IptablesFirewall::apply_nat_rules(
    bool effective_ipv6,
    FirewallApplyMode mode) {
    apply_nat_rules(
        effective_ipv6,
        mode,
        iptables_effective_prefilter(
            global_prefilter_, effective_ipv6));
}

void IptablesFirewall::apply(FirewallApplyMode mode) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    if (!apply_prepared_) {
        throw FirewallError("iptables apply was not prepared");
    }
    apply_prepared_ = false;

    bool effective_ipv6 = ipv6_enabled();
    if (effective_ipv6 && !ipv6_backend_available()) {
        Logger::instance().error(
            "IPv6 iptables backend is unavailable; skipping IPv6 firewall state and continuing IPv4-only");
        effective_ipv6 = false;
    }
    const auto effective_prefilter =
        iptables_effective_prefilter(
            global_prefilter_, effective_ipv6);
    const auto candidate_udp_peer_classifiers =
        build_pending_udp_peer_classifiers(
            effective_prefilter, effective_ipv6);
    const bool forward_reject_v4_requested = std::any_of(
        pending_forward_udp_rejects_.begin(),
        pending_forward_udp_rejects_.end(),
        [](const PendingForwardUdpReject& rule) { return !rule.ipv6; });
    const bool forward_reject_v6_requested = effective_ipv6 && std::any_of(
        pending_forward_udp_rejects_.begin(),
        pending_forward_udp_rejects_.end(),
        [](const PendingForwardUdpReject& rule) { return rule.ipv6; });
    if (forward_reject_v4_requested) {
        target_forward_reject_v4_generation_ =
            mode == FirewallApplyMode::Destructive
                ? FirewallSetGeneration::A
                : select_forward_reject_target_generation(false);
    }
    if (forward_reject_v6_requested) {
        target_forward_reject_v6_generation_ =
            mode == FirewallApplyMode::Destructive
                ? FirewallSetGeneration::A
                : select_forward_reject_target_generation(true);
    }

    // `create -exist` rejects incompatible existing set schemas. Detect a
    // dnsmasq-owned mismatch before cleanup or inactive-slot staging mutates
    // any live firewall state.
    if (mode != FirewallApplyMode::Destructive ||
        !clear_dynamic_sets_on_apply()) {
        preflight_dynamic_set_schemas(effective_ipv6);
    }

    if (mode != FirewallApplyMode::Destructive) {
        // Re-check the live dispatchers before any cleanup mutates live state.
        // prepare_apply() selected the opposite A/B slot, but another actor or
        // a partial prior apply may have changed the active generation since
        // then.  In that case fail before even the independent NAT chains are
        // removed.
        ensure_target_generation_inactive(false, target_v4_generation_);
        if (effective_ipv6) {
            ensure_target_generation_inactive(true, target_v6_generation_);
        }
        if (forward_reject_v4_requested) {
            ensure_forward_reject_target_generation_inactive(
                false, target_forward_reject_v4_generation_);
        }
        if (forward_reject_v6_requested) {
            ensure_forward_reject_target_generation_inactive(
                true, target_forward_reject_v6_generation_);
        }
    }

    if (mode == FirewallApplyMode::Destructive) {
        cleanup_live_impl(
            /*preserve_dynamic_sets=*/!clear_dynamic_sets_on_apply(),
            /*sweep_live_state=*/true);
    }

    // Phase 1: ipsets via 'ipset restore -exist'
    {
        std::string ipset_script;
        std::set<std::string> disabled_ipv6_sets;
        for (const auto& ps : pending_sets_) {
            if (ps.family_str == "inet6" && !effective_ipv6) {
                disabled_ipv6_sets.insert(ps.name);
                continue;
            }
            if (is_dynamic_set_name(ps.name)) {
                // dnsmasq owns these entries. Preserve-set applies never touch
                // their contents, but still re-create a missing set so an
                // out-of-band deletion cannot make the rule transaction fail.
                ipset_script += build_ipset_create_line(ps);
                if (mode == FirewallApplyMode::Destructive &&
                    clear_dynamic_sets_on_apply()) {
                    ipset_script += keen_pbr3::format("flush {}\n", ps.name);
                }
                continue;
            }
            ipset_script += build_ipset_create_line(ps);
            ipset_script += keen_pbr3::format("flush {}\n", ps.name);
        }
        for (auto& [set_name, buf] : pending_elements_) {
            if (disabled_ipv6_sets.find(set_name) != disabled_ipv6_sets.end()) {
                continue;
            }
            std::string elements = buf.str();
            if (!elements.empty()) {
                ipset_script += elements;
            }
        }
        if (!ipset_script.empty()) {
            pipe_to_cmd({"ipset", "restore", "-exist"}, ipset_script);
        }
    }

    // Stage only requested inactive filter generations while the previously
    // published dispatcher remains authoritative. Balanced first install
    // performs no filter mutation at all.
    if (forward_reject_v4_requested) {
        stage_forward_reject_generation(
            /*ipv6=*/false,
            target_forward_reject_v4_generation_);
    }
    if (forward_reject_v6_requested) {
        stage_forward_reject_generation(
            /*ipv6=*/true,
            target_forward_reject_v6_generation_);
    }

    // Phase 2: iptables rules via iptables-restore / ip6tables-restore.
    // Always materialize the KeenPbrTable scaffold for both protocols so
    // diagnostics can verify chain/jump presence even when no rules are needed.
    bool has_v4 = true;
    bool has_v6 = effective_ipv6;
    for (const auto& pr : pending_rules_) {
        if (pr.ipv6) has_v6 = true;
        else has_v4 = true;
    }

    if (has_v4) {
        const std::string output_chain =
            generation_output_chain(target_v4_generation_);
        if (use_raw_prerouting_) {
            // The small mangle companion restores/saves ctmark after
            // conntrack attaches to packets classified in raw PREROUTING.
            // Publish it before switching the raw generation; it is generic
            // for both A/B generations.
            pipe_to_cmd(
                {"iptables-restore", "--noflush", "--counters"},
                build_raw_conntrack_script(
                    /*replace_active_chain=*/true,
                    effective_prefilter,
                    pending_rules_));
            pipe_to_cmd(
                {"iptables-restore", "--noflush", "--counters"},
                build_output_generation_script(
                    output_chain,
                    /*replace_active_chain=*/true,
                    pending_rules_,
                    effective_prefilter));
            pipe_to_cmd(
                {"iptables-restore", "--noflush", "--counters"},
                build_raw_prerouting_script(
                    raw_generation_prerouting_chain(target_v4_generation_),
                    /*replace_active_chain=*/true,
                    pending_rules_,
                    effective_prefilter));
        } else {
            const std::string prerouting_chain =
                generation_prerouting_chain(target_v4_generation_);
            pipe_to_cmd({"iptables-restore", "--noflush", "--counters"},
                        build_generation_ipt_script(
                            false, prerouting_chain, output_chain,
                            /*replace_active_chains=*/true,
                            pending_rules_, effective_prefilter));
        }
        chain_v4_created_ = true;
    }
    if (has_v6) {
        const std::string prerouting_chain =
            generation_prerouting_chain(target_v6_generation_);
        const std::string output_chain =
            generation_output_chain(target_v6_generation_);
        pipe_to_cmd({"ip6tables-restore", "--noflush", "--counters"},
                    build_generation_ipt_script(
                        true, prerouting_chain, output_chain,
                        /*replace_active_chains=*/true,
                        pending_rules_, effective_prefilter));
        chain_v6_created_ = true;
    }

    // Builtin hooks are reconciled separately so repeated --noflush restores
    // cannot accumulate duplicate jumps.
    reconcile_hooks(false);
    if (has_v6) {
        reconcile_hooks(true);
    }

    // The kernel is the source of truth. Do not report success until both
    // stable dispatchers and their builtin hooks point at the target slot.
    verify_applied_generation(false, target_v4_generation_);
    if (has_v6) {
        verify_applied_generation(true, target_v6_generation_);
    }

    // Phase 3: nat rules — client DNS enforcement and the masquerade that keeps
    // router-originated detour traffic usable. Preserve-set applies validate
    // the replacement first and only then remove the active NAT generation.
    apply_nat_rules(effective_ipv6, mode, effective_prefilter);

    // Phase 4: publish the staged Meta UDP/443 policy only after mangle and
    // NAT have converged. Dispatcher replacement and first-hook placement are
    // one atomic filter transaction, so a restore failure leaves the previous
    // policy authoritative. Disabling similarly removes the hook and every
    // owned filter chain in one verified transaction.
    if (forward_reject_v4_requested) {
        ensure_forward_reject_target_generation_inactive(
            false, target_forward_reject_v4_generation_);
        publish_and_verify_forward_reject_generation(
            false, target_forward_reject_v4_generation_);
    } else if (mode != FirewallApplyMode::Destructive) {
        disable_forward_reject_scaffold(false);
        forward_reject_v4_created_ = false;
    }
    if (forward_reject_v6_requested) {
        ensure_forward_reject_target_generation_inactive(
            true, target_forward_reject_v6_generation_);
        publish_and_verify_forward_reject_generation(
            true, target_forward_reject_v6_generation_);
    } else if (mode != FirewallApplyMode::Destructive &&
               (effective_ipv6 || forward_reject_v6_created_ ||
                ipv6_backend_available())) {
        disable_forward_reject_scaffold(true);
        forward_reject_v6_created_ = false;
    }

    // Pending declarations become live authority only after rules, hooks, and
    // the independent NAT contract have all converged successfully.
    published_udp_peer_classifiers_ = candidate_udp_peer_classifiers;
    last_applied_forward_reject_v4_expected_ =
        forward_reject_v4_requested;
    last_applied_forward_reject_v6_expected_ =
        forward_reject_v6_requested;
    last_applied_forward_reject_v6_managed_ =
        last_applied_forward_reject_v6_managed_ || effective_ipv6 ||
        forward_reject_v6_requested;
    if (forward_reject_v4_requested) {
        last_applied_forward_reject_v4_generation_ =
            target_forward_reject_v4_generation_;
    }
    if (forward_reject_v6_requested) {
        last_applied_forward_reject_v6_generation_ =
            target_forward_reject_v6_generation_;
    }
    last_applied_forward_udp_rejects_ =
        pending_forward_udp_rejects_;

    // Clear pending buffers
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    pending_forward_udp_rejects_.clear();
}

void IptablesFirewall::cleanup_rules_impl(bool sweep_live_state) {
    auto& log = Logger::instance();
    const bool owned_v4 = chain_v4_created_;
    const bool owned_v6 = chain_v6_created_;

    auto remove_chain = [](const char* command,
                           const char* table,
                           const char* builtin,
                           const char* chain) {
        IptablesFirewall::remove_all_hooks(
            command, table, builtin, chain);
        safe_exec({command, "-t", table, "-F", chain},
                  /*suppress_output=*/true);
        safe_exec({command, "-t", table, "-X", chain},
                  /*suppress_output=*/true);
    };
    auto remove_generation = [](const char* command,
                                const char* table,
                                const char* chain) {
        safe_exec({command, "-t", table, "-F", chain},
                  /*suppress_output=*/true);
        safe_exec({command, "-t", table, "-X", chain},
                  /*suppress_output=*/true);
    };

    if (exact_tcp_reset_chain_created_ ||
        exact_tcp_reset_publication_uncertain_ || sweep_live_state) {
        // A daemon restart can outlive the short runtime timer. Sweep the
        // dedicated chain by its owned name before rebuilding normal policy;
        // no system chain is ever flushed.
        const auto exact_cleanup = replace_exact_tcp_reset_rules_locked(
            {}, /*cleanup_on_verification_failure=*/false);
        if (exact_cleanup != FirewallExactTcpResetResult::installed &&
            (exact_tcp_reset_chain_created_ ||
             exact_tcp_reset_publication_uncertain_)) {
            log.warn(
                "iptables cleanup could not prove the exact TCP reset "
                "chain absent; retaining ownership for retry");
        }
    }

    if (forward_reject_v4_created_ || sweep_live_state) {
        // Unlike legacy best-effort teardown, a still-live messages-first
        // hook is user-visible packet blocking. Remove its first hook,
        // dispatcher and both A/B generations in one checked transaction;
        // stop/prerm must fail loudly if that contract cannot be proved gone.
        disable_forward_reject_scaffold(/*ipv6=*/false);
        forward_reject_v4_created_ = false;
    }
    if (forward_reject_v6_created_ ||
        (sweep_live_state && ipv6_backend_available())) {
        disable_forward_reject_scaffold(/*ipv6=*/true);
        forward_reject_v6_created_ = false;
    }
    last_applied_forward_reject_v4_expected_ = false;
    last_applied_forward_reject_v6_expected_ = false;
    last_applied_forward_udp_rejects_.clear();

    if (owned_v4 || sweep_live_state) {
        log.verbose(
            "iptables cleanup: removing IPv4 {} PREROUTING and mangle OUTPUT chains",
            use_raw_prerouting_ ? "raw" : "mangle");
        remove_chain(
            "iptables",
            use_raw_prerouting_ ? "raw" : "mangle",
            "PREROUTING",
            use_raw_prerouting_ ? RAW_CHAIN_NAME : CHAIN_NAME);
        remove_chain(
            "iptables", "mangle", "OUTPUT", OUTPUT_CHAIN_NAME);
        if (use_raw_prerouting_ || sweep_live_state) {
            remove_chain(
                "iptables",
                "mangle",
                "PREROUTING",
                RAW_CONNTRACK_CHAIN_NAME);
        }

        for (const auto generation : {FirewallSetGeneration::A,
                                      FirewallSetGeneration::B}) {
            remove_generation(
                "iptables",
                use_raw_prerouting_ ? "raw" : "mangle",
                use_raw_prerouting_
                    ? raw_generation_prerouting_chain(generation)
                    : generation_prerouting_chain(generation));
            remove_generation(
                "iptables", "mangle",
                generation_output_chain(generation));
        }

        // A restart can switch between the two modes. During a startup sweep,
        // delete only our named chains from the inactive mode; never flush an
        // entire system table.
        if (sweep_live_state) {
            if (use_raw_prerouting_) {
                remove_chain(
                    "iptables", "mangle", "PREROUTING", CHAIN_NAME);
                for (const auto generation : {FirewallSetGeneration::A,
                                              FirewallSetGeneration::B}) {
                    remove_generation(
                        "iptables", "mangle",
                        generation_prerouting_chain(generation));
                }
            } else {
                remove_chain(
                    "iptables", "raw", "PREROUTING", RAW_CHAIN_NAME);
                for (const auto generation : {FirewallSetGeneration::A,
                                              FirewallSetGeneration::B}) {
                    remove_generation(
                        "iptables", "raw",
                        raw_generation_prerouting_chain(generation));
                }
            }
        }
        chain_v4_created_ = false;
    }

    if (owned_v6 || sweep_live_state) {
        log.verbose(
            "iptables cleanup: removing IPv6 mangle chains {} and {}",
            CHAIN_NAME,
            OUTPUT_CHAIN_NAME);
        remove_chain(
            "ip6tables", "mangle", "PREROUTING", CHAIN_NAME);
        remove_chain(
            "ip6tables", "mangle", "OUTPUT", OUTPUT_CHAIN_NAME);
        for (const auto generation : {FirewallSetGeneration::A,
                                      FirewallSetGeneration::B}) {
            remove_generation(
                "ip6tables", "mangle",
                generation_prerouting_chain(generation));
            remove_generation(
                "ip6tables", "mangle",
                generation_output_chain(generation));
        }
        chain_v6_created_ = false;
    }

    if (sweep_live_state) {
        cleanup_legacy_generation_chains("iptables");
        cleanup_legacy_generation_chains("ip6tables");
    }
}

void IptablesFirewall::cleanup_nat_rules_impl(bool sweep_live_state) {
    if (!sweep_live_state) {
        // Process-local ownership flags are only an optimization hint. After a
        // daemon restart, named keen-pbr NAT chains may still be live while
        // both flags are false. Checked live reconciliation makes ordinary
        // cleanup and "NAT disabled" applies idempotent across restarts.
        cleanup_nat_family_checked("iptables", /*ipv6=*/false);
        if (ipv6_nat_table_available()) {
            cleanup_nat_family_checked("ip6tables", /*ipv6=*/true);
        } else {
            dns_nat_v6_created_ = false;
        }
        return;
    }

    // DNS redirect and tunnel masquerade NAT chains.
    if (dns_nat_v4_created_) {
        // Ownership is cleared only after hooks and chains are observed gone.
        // A failed stop/apply can therefore be retried without losing track of
        // a still-live redirect or masquerade rule.
        cleanup_nat_family_checked("iptables", /*ipv6=*/false);
    } else if (sweep_live_state) {
        remove_all_hooks(
            "iptables", "nat", "PREROUTING", DNS_NAT_CHAIN_NAME);
        safe_exec({"iptables", "-t", "nat", "-F", DNS_NAT_CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"iptables", "-t", "nat", "-X", DNS_NAT_CHAIN_NAME}, /*suppress_output=*/true);
        remove_all_hooks(
            "iptables", "nat", "POSTROUTING", SNAT_CHAIN_NAME);
        safe_exec({"iptables", "-t", "nat", "-F", SNAT_CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"iptables", "-t", "nat", "-X", SNAT_CHAIN_NAME}, /*suppress_output=*/true);
        dns_nat_v4_created_ = false;
    }
    const bool ipv6_nat_backend_available =
        ipv6_nat_table_available();
    if (!ipv6_nat_backend_available) {
        dns_nat_v6_created_ = false;
    } else if (dns_nat_v6_created_) {
        cleanup_nat_family_checked("ip6tables", /*ipv6=*/true);
    } else if (sweep_live_state) {
        remove_all_hooks(
            "ip6tables", "nat", "PREROUTING", DNS_NAT_CHAIN_NAME);
        safe_exec({"ip6tables", "-t", "nat", "-F", DNS_NAT_CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"ip6tables", "-t", "nat", "-X", DNS_NAT_CHAIN_NAME}, /*suppress_output=*/true);
        remove_all_hooks(
            "ip6tables", "nat", "POSTROUTING", SNAT_CHAIN_NAME);
        safe_exec({"ip6tables", "-t", "nat", "-F", SNAT_CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"ip6tables", "-t", "nat", "-X", SNAT_CHAIN_NAME}, /*suppress_output=*/true);
        dns_nat_v6_created_ = false;
    }
}

void IptablesFirewall::cleanup_legacy_generation_chains(const char* command) {
    const auto result = safe_exec_capture(
        {command, "-t", "mangle", "-S"}, /*suppress_stderr=*/true);
    if (result.exit_code != 0) {
        return;
    }

    std::istringstream input(result.stdout_output);
    std::string line;
    constexpr std::string_view prefix = "-N KeenPbrTable_";
    while (std::getline(input, line)) {
        if (line.rfind(prefix, 0) != 0) {
            continue;
        }
        const std::string chain = line.substr(prefix.size());
        if (chain.empty() ||
            !std::all_of(chain.begin(), chain.end(), [](unsigned char ch) {
                return std::isdigit(ch) != 0;
            })) {
            continue;
        }
        const std::string full_name = std::string("KeenPbrTable_") + chain;
        safe_exec({command, "-t", "mangle", "-F", full_name},
                  /*suppress_output=*/true);
        safe_exec({command, "-t", "mangle", "-X", full_name},
                  /*suppress_output=*/true);
    }
}

bool IptablesFirewall::is_dynamic_set_name(const std::string& set_name) {
    return set_name.rfind("kpbr4d_", 0) == 0 ||
           set_name.rfind("kpbr6d_", 0) == 0;
}

void IptablesFirewall::cleanup_saved_sets(bool preserve_dynamic_sets) {
    const auto result = safe_exec_capture({"ipset", "save"}, /*suppress_stderr=*/true);
    if (result.exit_code != 0) {
        return;
    }

    std::istringstream input(result.stdout_output);
    std::string verb;
    std::string name;
    std::string rest;
    while (input >> verb >> name) {
        std::getline(input, rest);
        if (verb != "create") {
            continue;
        }
        const bool managed =
            name.rfind("kpbr4_", 0) == 0 || name.rfind("kpbr6_", 0) == 0 ||
            name.rfind("kpbr4s_", 0) == 0 || name.rfind("kpbr6s_", 0) == 0 ||
            name.rfind("kpbr4S_", 0) == 0 || name.rfind("kpbr6S_", 0) == 0 ||
            name.rfind("kpbr4d_", 0) == 0 || name.rfind("kpbr6d_", 0) == 0 ||
            name.rfind("kpbr4m_", 0) == 0 || name.rfind("kpbr6m_", 0) == 0;
        if (!managed) {
            continue;
        }
        if (preserve_dynamic_sets && is_dynamic_set_name(name)) {
            continue;
        }
        safe_exec({"ipset", "flush", name}, /*suppress_output=*/true);
        safe_exec({"ipset", "destroy", name}, /*suppress_output=*/true);
    }
}

void IptablesFirewall::cleanup_live_impl(bool preserve_dynamic_sets,
                                         bool sweep_live_state) {
    auto& log = Logger::instance();

    cleanup_rules_impl(sweep_live_state);
    cleanup_nat_rules_impl(sweep_live_state);

    // Destroy all created ipsets
    for (const auto& [name, _] : created_sets_) {
        if (preserve_dynamic_sets && is_dynamic_set_name(name)) {
            continue;
        }
        log.verbose("iptables cleanup: destroying ipset {}", name);
        safe_exec({"ipset", "flush", name}, /*suppress_output=*/true);
        safe_exec({"ipset", "destroy", name}, /*suppress_output=*/true);
    }
    if (sweep_live_state) {
        cleanup_saved_sets(preserve_dynamic_sets);
    }
}

void IptablesFirewall::cleanup_impl() {
    cleanup_live_impl(/*preserve_dynamic_sets=*/false);

    last_applied_snat_v4_expected_ = false;
    last_applied_snat_v6_expected_ = false;
    last_applied_snat_v6_managed_ = false;
    last_applied_snat_interfaces_.clear();
    last_applied_source_egress_snat_selectors_v4_.clear();
    last_applied_source_egress_snat_selectors_v6_.clear();
    last_applied_snat_fwmark_mask_ = 0xFFFFFFFFu;
    created_sets_.clear();
    udp_peer_sets_.clear();
    published_udp_peer_classifiers_.clear();

    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    pending_forward_udp_rejects_.clear();
    source_egress_snat_selectors_.clear();
}

void IptablesFirewall::cleanup() {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    cleanup_impl();
}

FirewallBackend IptablesFirewall::backend() const {
    return FirewallBackend::iptables;
}

std::unique_ptr<Firewall> create_iptables_firewall(
    bool use_raw_prerouting) {
    return std::make_unique<IptablesFirewall>(use_raw_prerouting);
}

} // namespace keen_pbr3
