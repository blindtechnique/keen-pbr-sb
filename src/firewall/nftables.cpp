#include "nftables.hpp"
#include "nft_batch_pipe.hpp"
#include "port_spec_util.hpp"
#include "../log/logger.hpp"
#include "../util/format_compat.hpp"
#include "../util/safe_exec.hpp"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <sys/socket.h>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr const char* kNftTableName = "KeenPbrTable";

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

std::vector<L4Proto> expand_l4_protos(L4Proto proto) {
    if (proto == L4Proto::TcpUdp) {
        return {L4Proto::Tcp, L4Proto::Udp};
    }
    return {proto};
}

bool needs_family_specific_rule(const FirewallRuleCriteria& criteria) {
    return criteria.dst_set_name.has_value()
        || criteria.src_udp_peer_set_name.has_value()
        || criteria.dscp.has_value()
        || !criteria.src_addr.empty()
        || !criteria.dst_addr.empty();
}

bool exact_udp_peer_matches_family(const std::string& source,
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

nlohmann::json interface_name_rhs(
    const std::vector<std::string>& interfaces) {
    if (interfaces.size() == 1) {
        return interfaces.front();
    }

    nlohmann::json rhs = {{"set", nlohmann::json::array()}};
    for (const auto& interface : interfaces) {
        rhs["set"].push_back(interface);
    }
    return rhs;
}

// Single CIDR -> prefix expression. Multiple CIDRs -> nft set expression.
nlohmann::json cidr_list_to_nft_rhs(
    const std::vector<std::string>& addrs) {
    auto addr_to_rhs = [](const std::string& addr) -> nlohmann::json {
        const auto slash = addr.find('/');
        if (slash != std::string::npos) {
            return {{"prefix", {
                {"addr", addr.substr(0, slash)},
                {"len", std::stoi(addr.substr(slash + 1))}
            }}};
        }
        const bool ipv6 = addr.find(':') != std::string::npos;
        return {{"prefix", {
            {"addr", addr},
            {"len", ipv6 ? 128 : 32}
        }}};
    };

    if (addrs.size() == 1U) return addr_to_rhs(addrs.front());
    nlohmann::json values = nlohmann::json::array();
    for (const auto& address : addrs) {
        values.push_back(addr_to_rhs(address));
    }
    return {{"set", values}};
}

void append_named_set_match(nlohmann::json& expressions,
                            const std::string& ip_proto,
                            const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value() &&
        criteria.src_udp_peer_set_name.has_value()) {
        throw FirewallError(
            "a rule cannot match both destination and UDP peer sets");
    }
    if (criteria.src_udp_peer_set_name.has_value()) {
        const nlohmann::json left = {{
            "concat",
            nlohmann::json::array({
                {{"payload",
                  {{"protocol", ip_proto}, {"field", "saddr"}}}},
                {{"payload",
                  {{"protocol", "udp"}, {"field", "dport"}}}},
                {{"payload",
                  {{"protocol", ip_proto}, {"field", "daddr"}}}},
            })}};
        expressions.push_back({{"match",
                                {{"op", "=="},
                                 {"left", left},
                                 {"right", "@" +
                                     *criteria.src_udp_peer_set_name}}}});
    } else if (criteria.dst_set_name.has_value()) {
        expressions.push_back({{"match",
                                {{"op", "=="},
                                 {"left",
                                  {{"payload",
                                    {{"protocol", ip_proto},
                                     {"field", "daddr"}}}}},
                                 {"right", "@" +
                                     *criteria.dst_set_name}}}});
    }
}

nlohmann::json source_address_match(
    const char* protocol,
    const char* operation,
    const std::vector<std::string>& cidrs) {
    return {{"match", {
        {"op", operation},
        {"left", {{"payload", {
            {"protocol", protocol},
            {"field", "saddr"}
        }}}},
        {"right", cidr_list_to_nft_rhs(cidrs)}
    }}};
}

void append_source_bypass_rules(
    nlohmann::json& commands,
    const char* chain,
    const std::vector<FirewallIngressSourceSelector>& selectors_v4,
    const std::vector<FirewallIngressSourceSelector>& selectors_v6) {
    const auto append_family =
        [&commands, chain](
            const char* protocol,
            const std::vector<FirewallIngressSourceSelector>& selectors) {
            for (const auto& selector : selectors) {
                if (selector.interface.empty()) {
                    // Fail closed: source-address ownership is not enough to
                    // grant a native-VPN bypass.
                    continue;
                }
                nlohmann::json expr = nlohmann::json::array();
                expr.push_back({{"match", {
                    {"op", "=="},
                    {"left", {{"meta", {{"key", "iifname"}}}}},
                    {"right", selector.interface}
                }}});
                expr.push_back(source_address_match(
                    protocol, "==", {selector.cidr}));
                expr.push_back({{"counter", nullptr}});
                expr.push_back({{"accept", nullptr}});
                commands.push_back({{"add", {{"rule", {
                    {"family", "inet"},
                    {"table", kNftTableName},
                    {"chain", chain},
                    {"expr", expr}
                }}}}});
            }
        };
    append_family("ip", selectors_v4);
    append_family("ip6", selectors_v6);
}

void append_local_dns_destination_bypass_rules(
    nlohmann::json& commands,
    const char* chain,
    const std::vector<FirewallIngressDestinationSelector>& selectors_v4,
    const std::vector<FirewallIngressDestinationSelector>& selectors_v6) {
    const auto append_family =
        [&commands, chain](
            const char* protocol,
            const std::vector<FirewallIngressDestinationSelector>&
                selectors) {
            for (const auto& selector : selectors) {
                if (selector.interface.empty() ||
                    selector.destination.empty()) {
                    continue;
                }
                for (const char* transport : {"udp", "tcp"}) {
                    nlohmann::json expr = nlohmann::json::array();
                    expr.push_back({{"match", {
                        {"op", "=="},
                        {"left", {{"meta", {{"key", "iifname"}}}}},
                        {"right", selector.interface}
                    }}});
                    expr.push_back({{"match", {
                        {"op", "=="},
                        {"left", {{"payload", {
                            {"protocol", protocol},
                            {"field", "daddr"}
                        }}}},
                        {"right", cidr_list_to_nft_rhs(
                            {selector.destination})}
                    }}});
                    expr.push_back({{"match", {
                        {"op", "=="},
                        {"left", {{"meta", {{"key", "l4proto"}}}}},
                        {"right", transport}
                    }}});
                    expr.push_back({{"match", {
                        {"op", "=="},
                        {"left", {{"payload", {
                            {"protocol", transport},
                            {"field", "dport"}
                        }}}},
                        {"right", 53}
                    }}});
                    expr.push_back({{"counter", nullptr}});
                    expr.push_back({{"accept", nullptr}});
                    commands.push_back({{"add", {{"rule", {
                        {"family", "inet"},
                        {"table", kNftTableName},
                        {"chain", chain},
                        {"expr", expr}
                    }}}}});
                }
            }
        };
    append_family("ip", selectors_v4);
    append_family("ip6", selectors_v6);
}

void append_extended_inbound_guard_rules(
    nlohmann::json& commands,
    const FirewallGlobalPrefilter& prefilter,
    const char* chain) {
    if (!prefilter.has_inbound_interfaces() ||
        !prefilter.inbound_interfaces.has_value() ||
        !prefilter.has_include_source_cidrs()) {
        return;
    }

    const auto append_family =
        [&commands, &prefilter, chain](
            const char* nfproto,
            const char* protocol,
            const std::vector<std::string>& include_cidrs) {
            nlohmann::json expr = nlohmann::json::array();
            expr.push_back({{"match", {
                {"op", "=="},
                {"left", {{"meta", {{"key", "nfproto"}}}}},
                {"right", nfproto}
            }}});
            expr.push_back({{"match", {
                {"op", "!="},
                {"left", {{"meta", {{"key", "iifname"}}}}},
                {"right", interface_name_rhs(
                    *prefilter.inbound_interfaces)}
            }}});
            if (!include_cidrs.empty()) {
                expr.push_back(source_address_match(
                    protocol, "!=", include_cidrs));
            }
            expr.push_back({{"counter", nullptr}});
            expr.push_back({{"accept", nullptr}});
            commands.push_back({{"add", {{"rule", {
                {"family", "inet"},
                {"table", kNftTableName},
                {"chain", chain},
                {"expr", expr}
            }}}}});
        };
    append_family(
        "ipv4", "ip", prefilter.include_source_cidrs_v4);
    append_family(
        "ipv6", "ip6", prefilter.include_source_cidrs_v6);
}

} // namespace

NftablesFirewall::NftablesFirewall()
    : NftablesFirewall([] {
          return NftablesFirewall::probe_register_merge_capability();
      }) {}

NftablesFirewall::NftablesFirewall(CapabilityProbe capability_probe)
    : mark_merge_capability_probe_(std::move(capability_probe)) {}

nlohmann::json NftablesFirewall::build_register_merge_probe_document() {
    constexpr const char* probe_table = "KeenPbrMarkProbe";
    constexpr const char* probe_chain = "probe";
    constexpr uint32_t owned_mask = 0x00FF0000u;
    constexpr uint32_t inverse_mask = ~owned_mask;

    nlohmann::json doc;
    auto& commands = doc["nftables"];
    commands = nlohmann::json::array();
    commands.push_back({{"metainfo", {{"json_schema_version", 1}}}});
    commands.push_back({{"add", {{"table", {
        {"family", "inet"},
        {"name", probe_table}
    }}}}});
    commands.push_back({{"add", {{"chain", {
        {"family", "inet"},
        {"table", probe_table},
        {"name", probe_chain}
    }}}}});

    nlohmann::json expr = nlohmann::json::array();
    expr.push_back({{"mangle", {
        {"key", {{"meta", {{"key", "mark"}}}}},
        {"value", {{"|", nlohmann::json::array({
            {{"&", nlohmann::json::array({
                {{"meta", {{"key", "mark"}}}},
                inverse_mask
            })}},
            {{"&", nlohmann::json::array({
                {{"ct", {{"key", "mark"}}}},
                owned_mask
            })}}
        })}}}
    }}});
    expr.push_back({{"mangle", {
        {"key", {{"ct", {{"key", "mark"}}}}},
        {"value", {{"|", nlohmann::json::array({
            {{"&", nlohmann::json::array({
                {{"ct", {{"key", "mark"}}}},
                inverse_mask
            })}},
            {{"&", nlohmann::json::array({
                {{"meta", {{"key", "mark"}}}},
                owned_mask
            })}}
        })}}}
    }}});
    commands.push_back({{"add", {{"rule", {
        {"family", "inet"},
        {"table", probe_table},
        {"chain", probe_chain},
        {"expr", expr}
    }}}}});
    return doc;
}

bool NftablesFirewall::probe_register_merge_capability() {
    std::string error_output;
    const int status = safe_exec_pipe_stdin(
        {"nft", "-c", "-j", "-f", "-"},
        build_register_merge_probe_document().dump(),
        &error_output,
        SafeExecFailureLog::Suppressed);
    if (status != 0) {
        Logger::instance().verbose(
            "nft register-mark merge is unavailable; using constant fallback: {}",
            error_output.empty()
                ? keen_pbr3::format("nft check exited with status {}", status)
                : error_output);
        return false;
    }
    return true;
}

NftablesFirewall::MarkMergeMode NftablesFirewall::resolve_mark_merge_mode(
    std::optional<MarkMergeMode>& cached_mode,
    const CapabilityProbe& capability_probe) {
    if (cached_mode.has_value()) {
        return *cached_mode;
    }

    bool register_merge = false;
    try {
        register_merge = capability_probe && capability_probe();
    } catch (const std::exception& e) {
        Logger::instance().warn(
            "nft mark-merge capability probe failed; using constant fallback: {}",
            e.what());
    } catch (...) {
        Logger::instance().warn(
            "nft mark-merge capability probe failed; using constant fallback");
    }
    cached_mode = register_merge
        ? MarkMergeMode::RegisterMerge
        : MarkMergeMode::LegacyConstant;
    return *cached_mode;
}

NftablesFirewall::MarkMergeMode NftablesFirewall::mark_merge_mode() {
    return resolve_mark_merge_mode(
        mark_merge_mode_,
        mark_merge_capability_probe_);
}

void NftablesFirewall::prepare_apply(FirewallApplyMode /*mode*/) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    udp_peer_sets_.clear();
    dns_redirect_requested_ = false;
    router_origin_snat_requested_ = false;
    snat_interfaces_.clear();
    source_egress_snat_selectors_.clear();
}

NftablesFirewall::~NftablesFirewall() {
    try {
        cleanup_impl();
    } catch (const std::exception& e) {
        Logger::instance().error("NftablesFirewall cleanup failed during destruction: {}",
                                 e.what());
    } catch (...) {
        Logger::instance().error(
            "NftablesFirewall cleanup failed during destruction: unknown error");
    }
}

void NftablesFirewall::create_ipset(const std::string& set_name, int family,
                                     uint32_t timeout) {
    if (family == AF_INET6 && !ipv6_enabled()) {
        return;
    }

    PendingSet ps;
    ps.name = set_name;
    ps.type = (family == AF_INET6) ? "ipv6_addr" : "ipv4_addr";
    ps.timeout = timeout;
    const auto existing = std::find_if(
        pending_sets_.begin(), pending_sets_.end(),
        [&set_name](const PendingSet& pending) { return pending.name == set_name; });
    if (existing == pending_sets_.end()) {
        pending_sets_.push_back(std::move(ps));
    } else if (existing->type != ps.type ||
               existing->timeout != ps.timeout ||
               existing->source_udp_peer != ps.source_udp_peer) {
        throw FirewallError("conflicting nft set declaration for " + set_name);
    }
    created_sets_[set_name] = family;
}

void NftablesFirewall::create_udp_peer_set(const std::string& set_name,
                                            int family,
                                            uint32_t timeout) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    if (timeout == 0U) {
        throw FirewallError("UDP peer set requires a non-zero timeout");
    }
    if (family == AF_INET6 && !ipv6_enabled()) {
        return;
    }
    if (family != AF_INET && family != AF_INET6) {
        throw FirewallError("invalid UDP peer set family");
    }

    PendingSet ps;
    ps.name = set_name;
    ps.type = family == AF_INET6 ? "ipv6_addr" : "ipv4_addr";
    ps.timeout = timeout;
    ps.source_udp_peer = true;
    const auto existing = std::find_if(
        pending_sets_.begin(), pending_sets_.end(),
        [&set_name](const PendingSet& pending) {
            return pending.name == set_name;
        });
    if (existing == pending_sets_.end()) {
        pending_sets_.push_back(std::move(ps));
    } else if (existing->type != ps.type ||
               existing->timeout != ps.timeout ||
               !existing->source_udp_peer) {
        throw FirewallError("conflicting nft set declaration for " + set_name);
    }
    created_sets_[set_name] = family;
    udp_peer_sets_[set_name] = {family, timeout};
}

bool NftablesFirewall::add_udp_peer(const std::string& set_name,
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

    const bool already_present = safe_exec(
            {"nft",
             "get",
             "element",
             "inet",
             std::string(TABLE_NAME),
             set_name,
             "{",
             source,
             ".",
             std::to_string(destination_port),
             ".",
             destination,
             "}"},
            /*suppress_output=*/true) == 0;

    const bool inserted = safe_exec_pipe_stdin(
            {"nft", "-j", "-f", "-"},
            build_udp_peer_update_document(
                set_name, source, destination_port, destination,
                already_present).dump(),
            nullptr,
            SafeExecFailureLog::Suppressed) == 0;
    if (!inserted) {
        return false;
    }
    if (udp_peer_classifier_is_published(set_name, set->second)) {
        return true;
    }

    // Do not leave an unproved element waiting for an out-of-band chain
    // restore. The daemon will keep the original conntrack flow when false is
    // returned, so this rollback is strictly fail-closed.
    (void)safe_exec(
        {"nft",
         "delete",
         "element",
         "inet",
         std::string(TABLE_NAME),
         set_name,
         "{",
         source,
         ".",
         std::to_string(destination_port),
         ".",
         destination,
         "}"},
        /*suppress_output=*/true);
    return false;
}

void NftablesFirewall::append_rules_for_family(int family,
                                               PendingRule::Action action,
                                               uint32_t fwmark,
                                               const FirewallRuleCriteria& criteria,
                                               bool output_scope) {
    if (family == AF_INET6 && !ipv6_enabled()) {
        return;
    }

    const bool ipv6 = family == AF_INET6;
    const auto filtered_src_addrs = criteria.src_addr.empty()
        ? std::vector<std::string>{}
        : filter_addrs_by_family(criteria.src_addr, ipv6);
    const auto filtered_dst_addrs = criteria.dst_addr.empty()
        ? std::vector<std::string>{}
        : filter_addrs_by_family(criteria.dst_addr, ipv6);
    if ((!criteria.src_addr.empty() && filtered_src_addrs.empty())
        || (!criteria.dst_addr.empty() && filtered_dst_addrs.empty())) {
        return;
    }

    for (const auto proto : expand_l4_protos(criteria.proto)) {
        PendingRule pr;
        pr.family = family;
        pr.action = action;
        pr.fwmark = fwmark;
        pr.fwmark_mask = fwmark_mask();
        pr.criteria = criteria;
        pr.criteria.proto = proto;
        if (!criteria.src_addr.empty()) {
            pr.criteria.src_addr = filtered_src_addrs;
        }
        if (!criteria.dst_addr.empty()) {
            pr.criteria.dst_addr = filtered_dst_addrs;
        }
        if (output_scope && action == PendingRule::Mark) {
            pr.fwmark |= kRouterOriginMark;
            pr.fwmark_mask |= kRouterOriginMark;
        }
        pr.output = output_scope;
        pending_rules_.push_back(std::move(pr));
    }
}

void NftablesFirewall::create_mark_rule(uint32_t fwmark,
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
        int family = (it != created_sets_.end()) ? it->second : AF_INET;
        append_rules_for_family(family, PendingRule::Mark, fwmark, criteria);
        return;
    }
    if (!needs_family_specific_rule(criteria)) {
        append_rules_for_family(AF_INET, PendingRule::Mark, fwmark, criteria);
        return;
    }
    append_rules_for_family(AF_INET, PendingRule::Mark, fwmark, criteria);
    append_rules_for_family(AF_INET6, PendingRule::Mark, fwmark, criteria);
}

void NftablesFirewall::create_output_mark_rule(uint32_t fwmark,
                                               const FirewallRuleCriteria& criteria) {
    router_origin_snat_requested_ = true;
    // Router-originated traffic (dnsmasq upstream queries with detour) never
    // traverses the prerouting hook; these marks live in the output chain.
    append_rules_for_family(AF_INET, PendingRule::Mark, fwmark, criteria,
                            /*output_scope=*/true);
    append_rules_for_family(AF_INET6, PendingRule::Mark, fwmark, criteria,
                            /*output_scope=*/true);
}

void NftablesFirewall::create_tunnel_snat_rules(
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

void NftablesFirewall::create_source_egress_snat_rules(
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

void NftablesFirewall::create_dns_redirect_rules() {
    dns_redirect_requested_ = true;
}

void NftablesFirewall::create_drop_rule(const FirewallRuleCriteria& criteria) {
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
        int family = (it != created_sets_.end()) ? it->second : AF_INET;
        append_rules_for_family(family, PendingRule::Drop, 0, criteria);
        return;
    }
    if (!needs_family_specific_rule(criteria)) {
        append_rules_for_family(AF_INET, PendingRule::Drop, 0, criteria);
        return;
    }
    append_rules_for_family(AF_INET, PendingRule::Drop, 0, criteria);
    append_rules_for_family(AF_INET6, PendingRule::Drop, 0, criteria);
}

void NftablesFirewall::create_pass_rule(const FirewallRuleCriteria& criteria) {
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
        int family = (it != created_sets_.end()) ? it->second : AF_INET;
        append_rules_for_family(family, PendingRule::Pass, 0, criteria);
        return;
    }
    if (!needs_family_specific_rule(criteria)) {
        append_rules_for_family(AF_INET, PendingRule::Pass, 0, criteria);
        return;
    }
    append_rules_for_family(AF_INET, PendingRule::Pass, 0, criteria);
    append_rules_for_family(AF_INET6, PendingRule::Pass, 0, criteria);
}

std::unique_ptr<ListEntryVisitor> NftablesFirewall::create_batch_loader(
    const std::string& set_name) {
    // Ensure an entry exists in pending_elements_ for this set (as an empty array)
    auto& buf = pending_elements_[set_name];
    if (!buf.is_array()) {
        buf = nlohmann::json::array();
    }
    return std::make_unique<NftBatchVisitor>(buf, set_name);
}

// --- Port spec helpers ---

// Parse a port spec into an nftables JSON right-hand side value.
// "443"       → 443  (integer)
// "8000-9000" → {"range": [8000, 9000]}
// "80,443"    → {"set": [80, 443]}
static nlohmann::json port_spec_to_nft_rhs(const PortSpec& spec) {
    PortSpecKind kind = classify_port_spec(spec);
    if (kind == PortSpecKind::List) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& range : spec.ranges) {
            if (range.from != range.to) {
                arr.push_back({{"range", nlohmann::json::array({range.from, range.to})}});
            } else {
                arr.push_back(range.from);
            }
        }
        return {{"set", arr}};
    }

    if (kind == PortSpecKind::Range) {
        return {{"range", nlohmann::json::array({spec.ranges[0].from, spec.ranges[0].to})}};
    }

    return spec.ranges[0].from;
}

// --- Private static helpers ---

nlohmann::json NftablesFirewall::build_table_json() {
    return {{"add", {{"table", {{"family", "inet"}, {"name", TABLE_NAME}}}}}};
}

nlohmann::json NftablesFirewall::build_set_json(const PendingSet& ps) {
    nlohmann::json flags = ps.source_udp_peer
        ? nlohmann::json::array()
        : nlohmann::json::array({"interval"});
    if (ps.timeout > 0) {
        flags.push_back("timeout");
    }
    nlohmann::json type = ps.type;
    if (ps.source_udp_peer) {
        type = nlohmann::json::array(
            {ps.type, "inet_service", ps.type});
    }
    nlohmann::json set = {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", ps.name},
        {"type", type},
        {"flags", flags}
    };
    if (!ps.source_udp_peer) {
        set["auto-merge"] = true;
    }
    if (ps.timeout > 0) {
        set["timeout"] = ps.timeout;
    }
    return {{"add", {{"set", set}}}};
}

nlohmann::json NftablesFirewall::build_chain_json() {
    return {{"add", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", CHAIN_NAME},
        {"type", "filter"},
        {"hook", "prerouting"},
        {"prio", -150},
        {"policy", "accept"}
    }}}}};
}

nlohmann::json NftablesFirewall::build_delete_chain_json() {
    return {{"delete", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", CHAIN_NAME}
    }}}}};
}

nlohmann::json NftablesFirewall::build_output_chain_json() {
    // type "route" is required: it makes the kernel re-evaluate the routing
    // decision for locally generated packets after the mark is applied.
    return {{"add", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", OUTPUT_CHAIN_NAME},
        {"type", "route"},
        {"hook", "output"},
        {"prio", -150},
        {"policy", "accept"}
    }}}}};
}

nlohmann::json NftablesFirewall::build_delete_output_chain_json() {
    return {{"delete", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", OUTPUT_CHAIN_NAME}
    }}}}};
}

nlohmann::json NftablesFirewall::build_flush_set_json(
    const std::string& set_name) {
    return {{"flush", {{"set", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", set_name}
    }}}}};
}

nlohmann::json NftablesFirewall::build_delete_set_json(
    const std::string& set_name) {
    return {{"delete", {{"set", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", set_name}
    }}}}};
}

bool NftablesFirewall::is_dynamic_set_name(const std::string& set_name) {
    return set_name.rfind("kpbr4d_", 0) == 0 ||
           set_name.rfind("kpbr6d_", 0) == 0;
}

bool NftablesFirewall::is_managed_set_name(const std::string& set_name) {
    return set_name.rfind("kpbr4_", 0) == 0 ||
           set_name.rfind("kpbr6_", 0) == 0 ||
           set_name.rfind("kpbr4s_", 0) == 0 ||
           set_name.rfind("kpbr6s_", 0) == 0 ||
           set_name.rfind("kpbr4S_", 0) == 0 ||
           set_name.rfind("kpbr6S_", 0) == 0 ||
           set_name.rfind("kpbr4m_", 0) == 0 ||
           set_name.rfind("kpbr6m_", 0) == 0 ||
           is_dynamic_set_name(set_name);
}

std::string NftablesFirewall::set_schema_key(const PendingSet& set) {
    return set.type +
           (set.source_udp_peer
                ? ".inet_service." + set.type
                : "") +
           ":" + std::to_string(set.timeout);
}

nlohmann::json NftablesFirewall::build_dns_nat_chain_json() {
    return {{"add", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", DNS_NAT_CHAIN_NAME},
        {"type", "nat"},
        {"hook", "prerouting"},
        {"prio", -100},
        {"policy", "accept"}
    }}}}};
}

nlohmann::json NftablesFirewall::build_delete_dns_nat_chain_json() {
    return {{"delete", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", DNS_NAT_CHAIN_NAME}
    }}}}};
}

nlohmann::json NftablesFirewall::build_snat_chain_json() {
    return {{"add", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", SNAT_CHAIN_NAME},
        {"type", "nat"},
        {"hook", "postrouting"},
        {"prio", 100},
        {"policy", "accept"}
    }}}}};
}

nlohmann::json NftablesFirewall::build_delete_snat_chain_json() {
    return {{"delete", {{"chain", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", SNAT_CHAIN_NAME}
    }}}}};
}

nlohmann::json NftablesFirewall::build_snat_rule_json() {
    nlohmann::json expr = nlohmann::json::array();
    expr.push_back({{"match", {
        {"op", "=="},
        {"left", {{"&", nlohmann::json::array({
            {{"meta", {{"key", "mark"}}}},
            kRouterOriginMark
        })}}},
        {"right", kRouterOriginMark}
    }}});
    expr.push_back({{"counter", nullptr}});
    expr.push_back({{"masquerade", nlohmann::json::object()}});
    return {{"add", {{"rule", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"chain", SNAT_CHAIN_NAME},
        {"expr", expr}
    }}}}};
}

nlohmann::json NftablesFirewall::build_interface_snat_rule_json(
    const std::string& interface,
    uint32_t fwmark_mask) {
    nlohmann::json expr = nlohmann::json::array();
    expr.push_back({{"match", {
        {"op", "=="},
        {"left", {{"meta", {{"key", "oifname"}}}}},
        {"right", interface}
    }}});
    expr.push_back({{"match", {
        {"op", "!="},
        {"left", {{"&", nlohmann::json::array({
            {{"meta", {{"key", "mark"}}}},
            fwmark_mask
        })}}},
        {"right", 0}
    }}});
    expr.push_back({{"counter", nullptr}});
    expr.push_back({{"masquerade", nlohmann::json::object()}});
    return {{"add", {{"rule", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"chain", SNAT_CHAIN_NAME},
        {"expr", expr}
    }}}}};
}

nlohmann::json NftablesFirewall::build_source_egress_snat_rule_json(
    const FirewallSourceEgressSnatSelector& selector) {
    const std::string ip_proto =
        is_ipv6_addr(selector.cidr) ? "ip6" : "ip";
    nlohmann::json expr = nlohmann::json::array();
    expr.push_back({{"match", {
        {"op", "=="},
        {"left", {{"payload", {
            {"protocol", ip_proto},
            {"field", "saddr"}
        }}}},
        {"right", cidr_list_to_nft_rhs({selector.cidr})}
    }}});
    expr.push_back({{"match", {
        {"op", "=="},
        {"left", {{"meta", {{"key", "oifname"}}}}},
        {"right", selector.interface}
    }}});
    expr.push_back({{"counter", nullptr}});
    expr.push_back({{"masquerade", nlohmann::json::object()}});
    return {{"add", {{"rule", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"chain", SNAT_CHAIN_NAME},
        {"expr", expr}
    }}}}};
}

nlohmann::json NftablesFirewall::build_dns_redirect_rules_json(
    const FirewallGlobalPrefilter& prefilter,
    const std::map<std::string, std::pair<int, uint32_t>>&
        udp_peer_sets) {
    nlohmann::json commands = nlohmann::json::array();

    if (prefilter.has_bypass_inbound_interfaces()) {
        nlohmann::json bypass_expr = nlohmann::json::array();
        bypass_expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"meta", {{"key", "iifname"}}}}},
            {"right", interface_name_rhs(
                prefilter.bypass_inbound_interfaces)}
        }}});
        bypass_expr.push_back({{"counter", nullptr}});
        bypass_expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", DNS_NAT_CHAIN_NAME},
            {"expr", bypass_expr}
        }}}}});
    }
    append_source_bypass_rules(
        commands,
        DNS_NAT_CHAIN_NAME,
        prefilter.bypass_source_selectors_v4,
        prefilter.bypass_source_selectors_v6);
    append_source_bypass_rules(
        commands,
        DNS_NAT_CHAIN_NAME,
        prefilter.dns_redirect_bypass_source_selectors_v4,
        prefilter.dns_redirect_bypass_source_selectors_v6);
    append_local_dns_destination_bypass_rules(
        commands,
        DNS_NAT_CHAIN_NAME,
        prefilter.dns_redirect_local_destination_selectors_v4,
        prefilter.dns_redirect_local_destination_selectors_v6);
    append_extended_inbound_guard_rules(
        commands, prefilter, DNS_NAT_CHAIN_NAME);

    for (const auto& [set_name, declaration] : udp_peer_sets) {
        const char* ip_proto = declaration.first == AF_INET6 ? "ip6" : "ip";
        nlohmann::json expr = nlohmann::json::array();
        expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"meta", {{"key", "l4proto"}}}}},
            {"right", "udp"}
        }}});
        expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"payload", {{"protocol", "udp"}, {"field", "dport"}}}}},
            {"right", 53}
        }}});
        expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"concat", nlohmann::json::array({
                {{"payload", {{"protocol", ip_proto}, {"field", "saddr"}}}},
                {{"payload", {{"protocol", "udp"}, {"field", "dport"}}}},
                {{"payload", {{"protocol", ip_proto}, {"field", "daddr"}}}}
            })}}},
            {"right", "@" + set_name}
        }}});
        expr.push_back({{"counter", nullptr}});
        expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", DNS_NAT_CHAIN_NAME},
            {"expr", expr}
        }}}}});
    }

    nlohmann::json iface_match = nullptr;
    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()
        && !prefilter.has_include_source_cidrs()) {
        iface_match = {{"match", {
            {"op", "=="},
            {"left", {{"meta", {{"key", "iifname"}}}}},
            {"right", interface_name_rhs(*prefilter.inbound_interfaces)}
        }}};
    }

    for (const char* proto : {"udp", "tcp"}) {
        nlohmann::json expr = nlohmann::json::array();
        if (!iface_match.is_null()) {
            expr.push_back(iface_match);
        }
        expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"meta", {{"key", "l4proto"}}}}},
            {"right", proto}
        }}});
        expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"payload", {{"protocol", proto}, {"field", "dport"}}}}},
            {"right", 53}
        }}});
        expr.push_back({{"counter", nullptr}});
        expr.push_back({{"redirect", {{"port", 53}}}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", DNS_NAT_CHAIN_NAME},
            {"expr", expr}
        }}}}});
    }

    return commands;
}

nlohmann::json NftablesFirewall::build_rule_add_commands(
    const FirewallGlobalPrefilter& prefilter,
    const std::vector<PendingRule>& rules,
    MarkMergeMode mark_merge_mode) {
    nlohmann::json commands = nlohmann::json::array();

    if (prefilter.has_bypass_inbound_interfaces()) {
        nlohmann::json bypass_expr = nlohmann::json::array();
        bypass_expr.push_back({{"match", {
            {"op", "=="},
            {"left", {{"meta", {{"key", "iifname"}}}}},
            {"right", interface_name_rhs(
                prefilter.bypass_inbound_interfaces)}
        }}});
        bypass_expr.push_back({{"counter", nullptr}});
        bypass_expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", CHAIN_NAME},
            {"expr", bypass_expr}
        }}}}});
    }
    append_source_bypass_rules(
        commands,
        CHAIN_NAME,
        prefilter.bypass_source_selectors_v4,
        prefilter.bypass_source_selectors_v6);
    const auto append_conntrack_restore =
        [&commands, &prefilter, &rules, mark_merge_mode](
            const char* chain,
            bool output_scope) {
            if (!prefilter.restore_conntrack_mark ||
                prefilter.conntrack_mark_mask == 0) {
                return;
            }

            const uint32_t mask = prefilter.conntrack_mark_mask;
            const uint32_t inverse_mask = ~mask;

            if (mark_merge_mode == MarkMergeMode::RegisterMerge) {
                nlohmann::json restore_expr = nlohmann::json::array();
                restore_expr.push_back({{"match", {
                    {"op", "=="},
                    {"left", {{"ct", {{"key", "direction"}}}}},
                    {"right", 0}
                }}});
                restore_expr.push_back({{"match", {
                    {"op", "!="},
                    {"left", {{"&", nlohmann::json::array({
                        {{"ct", {{"key", "mark"}}}},
                        mask
                    })}}},
                    {"right", 0}
                }}});
                restore_expr.push_back({{"mangle", {
                    {"key", {{"meta", {{"key", "mark"}}}}},
                    {"value", {{"|", nlohmann::json::array({
                        {{"&", nlohmann::json::array({
                            {{"meta", {{"key", "mark"}}}},
                            inverse_mask
                        })}},
                        {{"&", nlohmann::json::array({
                            {{"ct", {{"key", "mark"}}}},
                            mask
                        })}}
                    })}}}
                }}});
                commands.push_back({{"add", {{"rule", {
                    {"family", "inet"},
                    {"table", TABLE_NAME},
                    {"chain", chain},
                    {"expr", restore_expr}
                }}}}});

                nlohmann::json restored_expr = nlohmann::json::array();
                restored_expr.push_back({{"match", {
                    {"op", "=="},
                    {"left", {{"ct", {{"key", "direction"}}}}},
                    {"right", 0}
                }}});
                restored_expr.push_back({{"match", {
                    {"op", "!="},
                    {"left", {{"&", nlohmann::json::array({
                        {{"meta", {{"key", "mark"}}}},
                        mask
                    })}}},
                    {"right", 0}
                }}});
                restored_expr.push_back({{"counter", nullptr}});
                restored_expr.push_back({{"accept", nullptr}});
                commands.push_back({{"add", {{"rule", {
                    {"family", "inet"},
                    {"table", TABLE_NAME},
                    {"chain", chain},
                    {"expr", restored_expr}
                }}}}});
                return;
            }

            // Older nftables accepts only a constant as the right operand of
            // a binary expression used as a mangle value. Emit one rule per
            // unique owned mark so both packet-mark and ctmark foreign bits
            // survive without a register-to-register merge.
            std::set<uint32_t> owned_marks;
            for (const auto& rule : rules) {
                if (rule.output != output_scope ||
                    rule.action != PendingRule::Mark) {
                    continue;
                }
                const uint32_t owned_mark = rule.fwmark & mask;
                if (owned_mark != 0) {
                    owned_marks.insert(owned_mark);
                }
            }

            for (const uint32_t owned_mark : owned_marks) {
                nlohmann::json restore_expr = nlohmann::json::array();
                restore_expr.push_back({{"match", {
                    {"op", "=="},
                    {"left", {{"ct", {{"key", "direction"}}}}},
                    {"right", 0}
                }}});
                restore_expr.push_back({{"match", {
                    {"op", "=="},
                    {"left", {{"&", nlohmann::json::array({
                        {{"ct", {{"key", "mark"}}}},
                        mask
                    })}}},
                    {"right", owned_mark}
                }}});
                restore_expr.push_back({{"mangle", {
                    {"key", {{"meta", {{"key", "mark"}}}}},
                    {"value", {{"|", nlohmann::json::array({
                        {{"&", nlohmann::json::array({
                            {{"meta", {{"key", "mark"}}}},
                            inverse_mask
                        })}},
                        owned_mark
                    })}}}
                }}});
                restore_expr.push_back({{"counter", nullptr}});
                restore_expr.push_back({{"accept", nullptr}});
                commands.push_back({{"add", {{"rule", {
                    {"family", "inet"},
                    {"table", TABLE_NAME},
                    {"chain", chain},
                    {"expr", restore_expr}
                }}}}});
            }
        };

    append_conntrack_restore(CHAIN_NAME, /*output_scope=*/false);

    if (prefilter.skip_established_or_dnat) {
        nlohmann::json dnat_expr = nlohmann::json::array();
        dnat_expr.push_back({{"match", {
            {"op", "in"},
            {"left", {{"ct", {{"key", "status"}}}}},
            {"right", "dnat"}
        }}});
        dnat_expr.push_back({{"counter", nullptr}});
        dnat_expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", CHAIN_NAME},
            {"expr", dnat_expr}
        }}}}});
    }

    if (prefilter.skip_marked_packets) {
        nlohmann::json marked_expr = nlohmann::json::array();
        nlohmann::json mark_value = {{"meta", {{"key", "mark"}}}};
        if (prefilter.conntrack_mark_mask != 0) {
            mark_value = {{"&", nlohmann::json::array({
                {{"meta", {{"key", "mark"}}}},
                prefilter.conntrack_mark_mask
            })}};
        }
        marked_expr.push_back({{"match", {
            {"op", "!="},
            {"left", mark_value},
            {"right", 0}
        }}});
        marked_expr.push_back({{"counter", nullptr}});
        marked_expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", CHAIN_NAME},
            {"expr", marked_expr}
        }}}}});
    }

    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()
        && !prefilter.has_include_source_cidrs()) {
        nlohmann::json iface_expr = nlohmann::json::array();
        iface_expr.push_back({{"match", {
            {"op", "!="},
            {"left", {{"meta", {{"key", "iifname"}}}}},
            {"right", interface_name_rhs(*prefilter.inbound_interfaces)}
        }}});
        iface_expr.push_back({{"counter", nullptr}});
        iface_expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", CHAIN_NAME},
            {"expr", iface_expr}
        }}}}});
    } else {
        append_extended_inbound_guard_rules(
            commands, prefilter, CHAIN_NAME);
    }

    for (const auto& pr : rules) {
        if (pr.output) continue;
        if (pr.action == PendingRule::Mark) {
            commands.push_back(build_mark_rule_json(
                pr,
                prefilter.restore_conntrack_mark
                    ? prefilter.conntrack_mark_mask
                    : 0,
                mark_merge_mode));
        } else if (pr.action == PendingRule::Drop) {
            commands.push_back(build_drop_rule_json(pr));
        } else {
            commands.push_back(build_pass_rule_json(pr));
        }
    }

    append_conntrack_restore(OUTPUT_CHAIN_NAME, /*output_scope=*/true);

    // Output-chain prefilter: skip already-marked packets. The DNAT and
    // inbound-interface guards do not apply to router-originated traffic.
    if (prefilter.skip_marked_packets) {
        nlohmann::json marked_expr = nlohmann::json::array();
        nlohmann::json mark_value = {{"meta", {{"key", "mark"}}}};
        if (prefilter.conntrack_mark_mask != 0) {
            mark_value = {{"&", nlohmann::json::array({
                {{"meta", {{"key", "mark"}}}},
                prefilter.conntrack_mark_mask
            })}};
        }
        marked_expr.push_back({{"match", {
            {"op", "!="},
            {"left", mark_value},
            {"right", 0}
        }}});
        marked_expr.push_back({{"counter", nullptr}});
        marked_expr.push_back({{"accept", nullptr}});
        commands.push_back({{"add", {{"rule", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"chain", OUTPUT_CHAIN_NAME},
            {"expr", marked_expr}
        }}}}});
    }

    for (const auto& pr : rules) {
        if (!pr.output) continue;
        if (pr.action == PendingRule::Mark) {
            commands.push_back(build_mark_rule_json(
                pr,
                prefilter.restore_conntrack_mark
                    ? prefilter.conntrack_mark_mask
                    : 0,
                mark_merge_mode));
        } else if (pr.action == PendingRule::Drop) {
            commands.push_back(build_drop_rule_json(pr));
        } else {
            commands.push_back(build_pass_rule_json(pr));
        }
    }

    return commands;
}

nlohmann::json NftablesFirewall::build_port_match_exprs(L4Proto proto,
                                                          const PortSpec& src_port,
                                                          const PortSpec& dst_port,
                                                          bool negate_src_port,
                                                          bool negate_dst_port) {
    nlohmann::json exprs = nlohmann::json::array();
    if (proto == L4Proto::Any && src_port.empty() && dst_port.empty()) {
        return exprs;
    }
    // proto match (next-header) — never negated
    if (proto != L4Proto::Any) {
        exprs.push_back({{"match", {{"op", "=="}, {"left", {{"meta", {{"key", "l4proto"}}}}}, {"right", l4_proto_name(proto)}}}});
    }
    // For port payload fields, nft expects a transport-header payload protocol.
    // When proto is unspecified, use "th" (transport header) so expressions like
    // dport/sport are still valid.
    const std::string payload_proto = proto == L4Proto::Any ? "th" : l4_proto_name(proto);
    // src_port match
    if (!src_port.empty()) {
        std::string op = negate_src_port ? "!=" : "==";
        exprs.push_back({{"match", {{"op", op}, {"left", {{"payload", {{"protocol", payload_proto}, {"field", "sport"}}}}}, {"right", port_spec_to_nft_rhs(src_port)}}}});
    }
    // dst_port match
    if (!dst_port.empty()) {
        std::string op = negate_dst_port ? "!=" : "==";
        exprs.push_back({{"match", {{"op", op}, {"left", {{"payload", {{"protocol", payload_proto}, {"field", "dport"}}}}}, {"right", port_spec_to_nft_rhs(dst_port)}}}});
    }
    return exprs;
}

nlohmann::json NftablesFirewall::build_addr_match_exprs(const std::string& ip_proto,
                                                         const std::vector<std::string>& src_addr,
                                                         const std::vector<std::string>& dst_addr,
                                                         bool negate_src_addr,
                                                         bool negate_dst_addr) {
    nlohmann::json exprs = nlohmann::json::array();
    if (!src_addr.empty()) {
        std::string op = negate_src_addr ? "!=" : "==";
        exprs.push_back({{"match", {{"op", op}, {"left", {{"payload", {{"protocol", ip_proto}, {"field", "saddr"}}}}}, {"right", cidr_list_to_nft_rhs(src_addr)}}}});
    }
    if (!dst_addr.empty()) {
        std::string op = negate_dst_addr ? "!=" : "==";
        exprs.push_back({{"match", {{"op", op}, {"left", {{"payload", {{"protocol", ip_proto}, {"field", "daddr"}}}}}, {"right", cidr_list_to_nft_rhs(dst_addr)}}}});
    }
    return exprs;
}

nlohmann::json NftablesFirewall::build_dscp_match_exprs(const std::string& ip_proto,
                                                        std::optional<uint8_t> dscp) {
    nlohmann::json exprs = nlohmann::json::array();
    if (!dscp.has_value()) {
        return exprs;
    }

    exprs.push_back({{"match", {
        {"op", "=="},
        {"left", {{"payload", {{"protocol", ip_proto}, {"field", "dscp"}}}}},
        {"right", static_cast<int>(*dscp)}
    }}});
    return exprs;
}

nlohmann::json NftablesFirewall::build_mark_rule_json(
    const PendingRule& pr,
    uint32_t conntrack_mark_mask,
    MarkMergeMode mark_merge_mode) {
    std::string ip_proto = (pr.family == AF_INET6) ? "ip6" : "ip";
    nlohmann::json expr = nlohmann::json::array();
    append_named_set_match(expr, ip_proto, pr.criteria);
    for (const auto& e : build_dscp_match_exprs(ip_proto, pr.criteria.dscp)) {
        expr.push_back(e);
    }
    // Append src/dst address constraints
    for (const auto& e : build_addr_match_exprs(ip_proto, pr.criteria.src_addr, pr.criteria.dst_addr,
                                                 pr.criteria.negate_src_addr, pr.criteria.negate_dst_addr)) {
        expr.push_back(e);
    }
    // The exact UDP peer concat already contains an `udp dport` payload. nft
    // canonicalizes away a separate meta-l4proto match, so emitting both would
    // make the post-publication proof differ from the live JSON document.
    if (!pr.criteria.src_udp_peer_set_name.has_value()) {
        for (const auto& e : build_port_match_exprs(
                 pr.criteria.proto,
                 pr.criteria.src_port,
                 pr.criteria.dst_port,
                 pr.criteria.negate_src_port,
                 pr.criteria.negate_dst_port)) {
            expr.push_back(e);
        }
    }
    expr.push_back({{"counter", nullptr}});
    if (pr.fwmark_mask == 0xFFFFFFFFu) {
        expr.push_back({{"mangle", {
            {"key", {{"meta", {{"key", "mark"}}}}},
            {"value", pr.fwmark}
        }}});
    } else {
        expr.push_back({{"mangle", {
            {"key", {{"meta", {{"key", "mark"}}}}},
            {"value", {{"|", nlohmann::json::array({
                {{"&", nlohmann::json::array({
                    {{"meta", {{"key", "mark"}}}},
                    static_cast<uint32_t>(~pr.fwmark_mask) | pr.fwmark
                })}},
                pr.fwmark
            })}}}
        }}});
    }
    if (conntrack_mark_mask != 0 &&
        pr.criteria.persist_conntrack_mark) {
        nlohmann::json saved_value;
        if (mark_merge_mode == MarkMergeMode::RegisterMerge) {
            saved_value = {{"|", nlohmann::json::array({
                {{"&", nlohmann::json::array({
                    {{"ct", {{"key", "mark"}}}},
                    static_cast<uint32_t>(~conntrack_mark_mask)
                })}},
                {{"&", nlohmann::json::array({
                    {{"meta", {{"key", "mark"}}}},
                    conntrack_mark_mask
                })}}
            })}};
        } else {
            saved_value = {{"|", nlohmann::json::array({
                {{"&", nlohmann::json::array({
                    {{"ct", {{"key", "mark"}}}},
                    static_cast<uint32_t>(~conntrack_mark_mask)
                })}},
                pr.fwmark & conntrack_mark_mask
            })}};
        }
        expr.push_back({{"mangle", {
            {"key", {{"ct", {{"key", "mark"}}}}},
            {"value", saved_value}
        }}});
    }
    expr.push_back({{"accept", nullptr}});
    return {{"add", {{"rule", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"chain", pr.output ? OUTPUT_CHAIN_NAME : CHAIN_NAME},
        {"expr", expr}
    }}}}};
}

nlohmann::json NftablesFirewall::build_drop_rule_json(const PendingRule& pr) {
    std::string ip_proto = (pr.family == AF_INET6) ? "ip6" : "ip";
    nlohmann::json expr = nlohmann::json::array();
    append_named_set_match(expr, ip_proto, pr.criteria);
    for (const auto& e : build_dscp_match_exprs(ip_proto, pr.criteria.dscp)) {
        expr.push_back(e);
    }
    // Append src/dst address constraints
    for (const auto& e : build_addr_match_exprs(ip_proto, pr.criteria.src_addr, pr.criteria.dst_addr,
                                                 pr.criteria.negate_src_addr, pr.criteria.negate_dst_addr)) {
        expr.push_back(e);
    }
    // Append proto/port match expressions
    for (const auto& e : build_port_match_exprs(pr.criteria.proto, pr.criteria.src_port, pr.criteria.dst_port,
                                                  pr.criteria.negate_src_port, pr.criteria.negate_dst_port)) {
        expr.push_back(e);
    }
    expr.push_back({{"counter", nullptr}});
    expr.push_back({{"drop", nullptr}});
    return {{"add", {{"rule", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"chain", pr.output ? OUTPUT_CHAIN_NAME : CHAIN_NAME},
        {"expr", expr}
    }}}}};
}

nlohmann::json NftablesFirewall::build_pass_rule_json(const PendingRule& pr) {
    std::string ip_proto = (pr.family == AF_INET6) ? "ip6" : "ip";
    nlohmann::json expr = nlohmann::json::array();
    append_named_set_match(expr, ip_proto, pr.criteria);
    for (const auto& e : build_dscp_match_exprs(ip_proto, pr.criteria.dscp)) {
        expr.push_back(e);
    }
    for (const auto& e : build_addr_match_exprs(ip_proto, pr.criteria.src_addr, pr.criteria.dst_addr,
                                                 pr.criteria.negate_src_addr, pr.criteria.negate_dst_addr)) {
        expr.push_back(e);
    }
    for (const auto& e : build_port_match_exprs(pr.criteria.proto, pr.criteria.src_port, pr.criteria.dst_port,
                                                  pr.criteria.negate_src_port, pr.criteria.negate_dst_port)) {
        expr.push_back(e);
    }
    expr.push_back({{"counter", nullptr}});
    expr.push_back({{"accept", nullptr}});
    return {{"add", {{"rule", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"chain", pr.output ? OUTPUT_CHAIN_NAME : CHAIN_NAME},
        {"expr", expr}
    }}}}};
}

nlohmann::json NftablesFirewall::build_elements_json(const std::string& set_name,
                                                      const nlohmann::json& elems) {
    return {{"add", {{"element", {
        {"family", "inet"},
        {"table", TABLE_NAME},
        {"name", set_name},
        {"elem", elems}
    }}}}};
}

nlohmann::json NftablesFirewall::build_udp_peer_update_document(
    const std::string& set_name,
    const std::string& source,
    std::uint16_t destination_port,
    const std::string& destination,
    bool already_present) {
    const nlohmann::json elements = nlohmann::json::array({
        {{"concat", nlohmann::json::array(
            {source, destination_port, destination})}},
    });
    nlohmann::json document;
    auto& commands = document["nftables"];
    commands = nlohmann::json::array({
        {{"metainfo", {{"json_schema_version", 1}}}},
    });
    if (already_present) {
        commands.push_back({{"delete", {{"element", {
            {"family", "inet"},
            {"table", TABLE_NAME},
            {"name", set_name},
            {"elem", elements},
        }}}}});
    }
    commands.push_back(build_elements_json(set_name, elements));
    return document;
}

std::optional<nlohmann::json> NftablesFirewall::normalize_rule_expr(
    nlohmann::json expr) {
    if (!expr.is_array()) {
        return std::nullopt;
    }
    for (auto& expression : expr) {
        if (!expression.is_object() || expression.size() != 1U) {
            return std::nullopt;
        }
        if (expression.contains("counter")) {
            // `nft list` expands a counter to packets/bytes while builders use
            // null. Placement is contractual; volatile values are not.
            const auto& counter = expression["counter"];
            bool canonical = counter.is_null() || counter.is_object();
            if (counter.is_object()) {
                for (auto it = counter.begin(); it != counter.end(); ++it) {
                    if (it.key() != "packets" && it.key() != "bytes") {
                        canonical = false;
                        break;
                    }
                }
            }
            if (!canonical) {
                return std::nullopt;
            }
            expression["counter"] = nullptr;
        } else if (expression.contains("masquerade")) {
            // Different nft releases render a flag-less masquerade as either
            // null or an empty object.
            const auto& masquerade = expression["masquerade"];
            if (!masquerade.is_null() &&
                (!masquerade.is_object() || !masquerade.empty())) {
                return std::nullopt;
            }
            expression["masquerade"] = nlohmann::json::object();
        }
    }
    return expr;
}

bool NftablesFirewall::udp_peer_classifier_document_matches(
    const std::string& document,
    const std::string& set_name,
    const PublishedUdpPeerClassifier& classifier) {
    if (set_name.empty() || classifier.timeout == 0U ||
        (classifier.family != AF_INET && classifier.family != AF_INET6)) {
        return false;
    }

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(document);
    } catch (...) {
        return false;
    }
    const auto nftables = doc.find("nftables");
    if (nftables == doc.end() || !nftables->is_array()) {
        return false;
    }

    const auto expected_expr = normalize_rule_expr(classifier.expected_expr);
    if (!expected_expr.has_value()) {
        return false;
    }
    const std::string address_type =
        classifier.family == AF_INET6 ? "ipv6_addr" : "ipv4_addr";
    const std::string concatenated_type =
        address_type + ".inet_service." + address_type;
    const std::string authority = "@" + set_name;
    std::size_t table_count = 0U;
    std::size_t chain_count = 0U;
    std::size_t set_count = 0U;
    std::size_t classifier_count = 0U;
    bool chain_valid = false;
    bool set_valid = false;

    try {
        for (const auto& item : *nftables) {
            if (!item.is_object()) {
                continue;
            }
            if (const auto table = item.find("table");
                table != item.end() && table->is_object()) {
                if (table->value("family", "") == "inet" &&
                    table->value("name", "") == TABLE_NAME) {
                    ++table_count;
                }
                continue;
            }
            if (const auto chain = item.find("chain");
                chain != item.end() && chain->is_object()) {
                if (chain->value("family", "") == "inet" &&
                    chain->value("table", "") == TABLE_NAME &&
                    chain->value("name", "") == CHAIN_NAME) {
                    ++chain_count;
                    chain_valid =
                        chain_count == 1U &&
                        chain->value("type", "") == "filter" &&
                        chain->value("hook", "") == "prerouting" &&
                        chain->value(
                            "prio", std::numeric_limits<int>::min()) == -150 &&
                        chain->value("policy", "") == "accept";
                }
                continue;
            }
            if (const auto set = item.find("set");
                set != item.end() && set->is_object()) {
                if (set->value("family", "") != "inet" ||
                    set->value("table", "") != TABLE_NAME ||
                    set->value("name", "") != set_name) {
                    continue;
                }
                ++set_count;
                bool type_valid = false;
                const auto type = set->find("type");
                if (type != set->end() && type->is_array() &&
                    type->size() == 3U) {
                    type_valid = (*type)[0] == address_type &&
                                 (*type)[1] == "inet_service" &&
                                 (*type)[2] == address_type;
                } else if (type != set->end() && type->is_string()) {
                    std::string value = type->get<std::string>();
                    value.erase(
                        std::remove_if(
                            value.begin(), value.end(),
                            [](unsigned char ch) {
                                return std::isspace(ch) != 0;
                            }),
                        value.end());
                    type_valid = value == concatenated_type;
                }
                std::set<std::string> flags;
                const auto live_flags = set->find("flags");
                if (live_flags != set->end() && live_flags->is_array()) {
                    for (const auto& flag : *live_flags) {
                        if (!flag.is_string()) {
                            flags.clear();
                            break;
                        }
                        flags.insert(flag.get<std::string>());
                    }
                }
                set_valid =
                    set_count == 1U && type_valid &&
                    flags == std::set<std::string>{"timeout"} &&
                    set->value("timeout", 0U) == classifier.timeout;
                continue;
            }
            if (const auto rule = item.find("rule");
                rule != item.end() && rule->is_object()) {
                if (rule->value("family", "") != "inet" ||
                    rule->value("table", "") != TABLE_NAME ||
                    rule->value("chain", "") != CHAIN_NAME) {
                    continue;
                }
                const auto expr = rule->find("expr");
                if (expr == rule->end()) {
                    continue;
                }
                const bool references_udp_peer_authority =
                    expr->dump().find(authority) != std::string::npos;
                if (!references_udp_peer_authority) {
                    continue;
                }
                const auto normalized = normalize_rule_expr(*expr);
                if (!normalized.has_value() ||
                    *normalized != *expected_expr) {
                    // A second or altered classifier for the same peer set is
                    // drift even if the expected rule also survives.
                    return false;
                }
                ++classifier_count;
            }
        }
    } catch (...) {
        return false;
    }

    return table_count == 1U && chain_count == 1U && chain_valid &&
           set_count == 1U && set_valid && classifier_count == 1U;
}

std::map<std::string, NftablesFirewall::PublishedUdpPeerClassifier>
NftablesFirewall::build_pending_udp_peer_classifiers(
    MarkMergeMode mark_merge_mode) const {
    std::map<std::string, PublishedUdpPeerClassifier> published;
    const auto is_exact_udp_peer_classifier = [](
        const PendingRule& rule,
        const std::string& set_name,
        int family) {
        const auto& criteria = rule.criteria;
        return rule.action == PendingRule::Mark && !rule.output &&
               rule.family == family &&
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
    const uint32_t conntrack_mark_mask =
        global_prefilter_.restore_conntrack_mark
        ? global_prefilter_.conntrack_mark_mask
        : 0U;

    for (const auto& set : pending_sets_) {
        if (!set.source_udp_peer) {
            continue;
        }
        const int family = set.type == "ipv6_addr" ? AF_INET6 : AF_INET;
        if (set.type != "ipv4_addr" && set.type != "ipv6_addr") {
            continue;
        }
        const PendingRule* classifier = nullptr;
        bool ambiguous = false;
        for (const auto& rule : pending_rules_) {
            if (!is_exact_udp_peer_classifier(rule, set.name, family)) {
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
        const auto command = build_mark_rule_json(
            *classifier, conntrack_mark_mask, mark_merge_mode);
        const auto expected = normalize_rule_expr(
            command["add"]["rule"]["expr"]);
        if (!expected.has_value()) {
            continue;
        }
        published.emplace(
            set.name,
            PublishedUdpPeerClassifier{family, set.timeout, *expected});
    }
    return published;
}

bool NftablesFirewall::udp_peer_classifier_is_published(
    const std::string& set_name,
    const PublishedUdpPeerClassifier& classifier) const noexcept {
    try {
        const auto result = safe_exec_capture(
            {"nft", "-j", "-t", "list", "table", "inet",
             std::string(TABLE_NAME)},
            /*suppress_stderr=*/true,
            /*max_bytes=*/256U * 1024U,
            /*capture_stderr=*/false,
            /*drain_after_limit=*/true,
            SafeExecFailureLog::Suppressed);
        return result.exit_code == 0 && !result.timed_out &&
               !result.truncated &&
               udp_peer_classifier_document_matches(
                   result.stdout_output, set_name, classifier);
    } catch (...) {
        return false;
    }
}

// --- apply / cleanup ---

bool NftablesFirewall::table_exists() const {
    return safe_exec({"nft", "list", "table", "inet", std::string(TABLE_NAME)},
                     /*suppress_output=*/true) == 0;
}

OwnedSnatState NftablesFirewall::parse_owned_snat_state(
    const std::string& document,
    bool expected,
    const std::vector<std::string>& expected_interfaces,
    const std::vector<FirewallSourceEgressSnatSelector>&
        expected_source_egress_selectors,
    uint32_t expected_fwmark_mask) {
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(document);
    } catch (const nlohmann::json::parse_error&) {
        return OwnedSnatState::unknown;
    }

    const auto nftables_it = doc.find("nftables");
    if (nftables_it == doc.end() || !nftables_it->is_array()) {
        return OwnedSnatState::unknown;
    }

    bool table_found = false;
    size_t snat_chain_count = 0U;
    bool snat_chain_valid = false;
    bool owned_rule_invalid = false;
    std::vector<nlohmann::json> observed_rule_exprs;

    const auto normalize_rule_expr = [](
        nlohmann::json expr) -> std::optional<nlohmann::json> {
        if (!expr.is_array()) {
            return std::nullopt;
        }
        for (auto& expression : expr) {
            if (!expression.is_object() || expression.size() != 1U) {
                return std::nullopt;
            }
            if (expression.contains("counter")) {
                // `nft list` expands a counter to packets/bytes while the
                // builder uses null. Counter placement is contractual; only
                // its volatile values are ignored.
                const auto& counter = expression["counter"];
                bool counter_is_canonical =
                    counter.is_null() || counter.is_object();
                if (counter.is_object()) {
                    for (auto it = counter.begin();
                         it != counter.end();
                         ++it) {
                        if (it.key() != "packets" &&
                            it.key() != "bytes") {
                            counter_is_canonical = false;
                            break;
                        }
                    }
                }
                if (!counter_is_canonical) {
                    return std::nullopt;
                }
                expression["counter"] = nullptr;
            } else if (expression.contains("masquerade")) {
                // Different nft releases render a flag-less masquerade as
                // either null or an empty object.
                const auto& masquerade = expression["masquerade"];
                if (!masquerade.is_null() &&
                    (!masquerade.is_object() ||
                     !masquerade.empty())) {
                    return std::nullopt;
                }
                expression["masquerade"] =
                    nlohmann::json::object();
            }
        }
        return expr;
    };

    for (const auto& item : *nftables_it) {
        if (!item.is_object()) {
            continue;
        }
        if (const auto table_it = item.find("table");
            table_it != item.end() && table_it->is_object()) {
            const auto& table = *table_it;
            table_found =
                table_found ||
                (table.value("family", "") == "inet" &&
                 table.value("name", "") == TABLE_NAME);
            continue;
        }
        if (const auto chain_it = item.find("chain");
            chain_it != item.end() && chain_it->is_object()) {
            const auto& chain = *chain_it;
            if (chain.value("family", "") == "inet" &&
                chain.value("table", "") == TABLE_NAME &&
                chain.value("name", "") == SNAT_CHAIN_NAME) {
                ++snat_chain_count;
                snat_chain_valid =
                    snat_chain_count == 1U &&
                    chain.value("type", "") == "nat" &&
                    chain.value("hook", "") == "postrouting" &&
                    chain.value("prio", std::numeric_limits<int>::min()) ==
                        100 &&
                    chain.value("policy", "") == "accept";
            }
            continue;
        }
        if (const auto rule_it = item.find("rule");
            rule_it != item.end() && rule_it->is_object()) {
            const auto& rule = *rule_it;
            if (rule.value("family", "") != "inet" ||
                rule.value("table", "") != TABLE_NAME ||
                rule.value("chain", "") != SNAT_CHAIN_NAME) {
                continue;
            }
            const auto expr_it = rule.find("expr");
            if (expr_it == rule.end()) {
                owned_rule_invalid = true;
                continue;
            }
            const auto normalized = normalize_rule_expr(*expr_it);
            if (!normalized.has_value()) {
                owned_rule_invalid = true;
                continue;
            }
            observed_rule_exprs.push_back(*normalized);
        }
    }

    // A successful `nft list table` response must identify the requested
    // table. Treat a structurally valid but unrelated/empty document as an
    // inspection failure, not as evidence that owned state is absent.
    if (!table_found) {
        return OwnedSnatState::unknown;
    }

    if (!expected) {
        return snat_chain_count == 0U &&
               observed_rule_exprs.empty() &&
               !owned_rule_invalid
            ? OwnedSnatState::healthy
            : OwnedSnatState::stale;
    }

    std::vector<nlohmann::json> expected_rule_exprs;
    const auto append_expected =
        [&expected_rule_exprs, &normalize_rule_expr](
            const nlohmann::json& command) {
            const auto normalized = normalize_rule_expr(
                command["add"]["rule"]["expr"]);
            if (normalized.has_value()) {
                expected_rule_exprs.push_back(*normalized);
            }
        };
    append_expected(build_snat_rule_json());
    for (const auto& interface : expected_interfaces) {
        append_expected(build_interface_snat_rule_json(
            interface, expected_fwmark_mask));
    }
    for (const auto& selector : expected_source_egress_selectors) {
        append_expected(build_source_egress_snat_rule_json(selector));
    }

    return snat_chain_count == 1U &&
           snat_chain_valid &&
           !owned_rule_invalid &&
           observed_rule_exprs == expected_rule_exprs
        ? OwnedSnatState::healthy
        : OwnedSnatState::missing;
}

OwnedSnatState NftablesFirewall::inspect_owned_snat_state(
    bool expected,
    const std::vector<std::string>& expected_interfaces,
    const std::vector<FirewallSourceEgressSnatSelector>&
        expected_source_egress_selectors,
    uint32_t expected_fwmark_mask) const {
    const auto result = safe_exec_capture(
        {"nft", "-j", "-t", "list", "table", "inet",
         std::string(TABLE_NAME)},
        /*suppress_stderr=*/false,
        /*max_bytes=*/256U * 1024U,
        /*capture_stderr=*/true,
        /*drain_after_limit=*/true,
        SafeExecFailureLog::DiagnosticOnly,
        SafeExecTimeouts{
            owned_snat_inspect_timeout(),
            owned_snat_inspect_kill_grace()});
    if (result.timed_out || result.truncated) {
        return OwnedSnatState::unknown;
    }
    if (result.exit_code != 0) {
        const bool absent =
            result.stdout_output.find("No such file or directory") !=
                std::string::npos ||
            result.stdout_output.find("does not exist") != std::string::npos ||
            result.stdout_output.find("not found") != std::string::npos;
        return absent
            ? (expected
                   ? OwnedSnatState::missing
                   : OwnedSnatState::healthy)
            : OwnedSnatState::unknown;
    }
    return parse_owned_snat_state(
        result.stdout_output,
        expected,
        expected_interfaces,
        expected_source_egress_selectors,
        expected_fwmark_mask);
}

std::chrono::milliseconds
NftablesFirewall::owned_snat_inspect_timeout() {
    return std::chrono::seconds{2};
}

std::chrono::milliseconds
NftablesFirewall::owned_snat_inspect_kill_grace() {
    return std::chrono::milliseconds{500};
}

OwnedSnatState NftablesFirewall::inspect_owned_snat_state() const {
    return inspect_owned_snat_state(
        last_applied_snat_expected_,
        last_applied_snat_interfaces_,
        last_applied_source_egress_snat_selectors_,
        last_applied_snat_fwmark_mask_);
}

NftablesFirewall::LiveTableState NftablesFirewall::read_live_table_state() const {
    LiveTableState state;
    const auto result = safe_exec_capture(
        {"nft", "-j", "-t", "list", "table", "inet", std::string(TABLE_NAME)},
        /*suppress_stderr=*/true);
    if (result.exit_code != 0 || result.stdout_output.empty()) {
        return state;
    }

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(result.stdout_output);
    } catch (const nlohmann::json::parse_error& e) {
        Logger::instance().warn("Failed to parse nft table state: {}", e.what());
        return state;
    }

    const auto nftables_it = doc.find("nftables");
    if (nftables_it == doc.end() || !nftables_it->is_array()) {
        return state;
    }

    for (const auto& item : *nftables_it) {
        if (!item.is_object()) {
            continue;
        }

        if (const auto table_it = item.find("table");
            table_it != item.end() && table_it->is_object()) {
            const auto& table = *table_it;
            if (table.value("family", "") == "inet"
                && table.value("name", "") == TABLE_NAME) {
                state.table_exists = true;
            }
            continue;
        }

        if (const auto chain_it = item.find("chain");
            chain_it != item.end() && chain_it->is_object()) {
            const auto& chain = *chain_it;
            if (chain.value("family", "") == "inet"
                && chain.value("table", "") == TABLE_NAME
                && chain.value("name", "") == CHAIN_NAME) {
                state.chain_exists = true;
            }
            if (chain.value("family", "") == "inet"
                && chain.value("table", "") == TABLE_NAME
                && chain.value("name", "") == OUTPUT_CHAIN_NAME) {
                state.output_chain_exists = true;
            }
            if (chain.value("family", "") == "inet"
                && chain.value("table", "") == TABLE_NAME
                && chain.value("name", "") == DNS_NAT_CHAIN_NAME) {
                state.dns_nat_chain_exists = true;
            }
            if (chain.value("family", "") == "inet"
                && chain.value("table", "") == TABLE_NAME
                && chain.value("name", "") == SNAT_CHAIN_NAME) {
                state.snat_chain_exists = true;
            }
            continue;
        }

        if (const auto set_it = item.find("set");
            set_it != item.end() && set_it->is_object()) {
            const auto& set = *set_it;
            if (set.value("family", "") == "inet"
                && set.value("table", "") == TABLE_NAME) {
                const std::string name = set.value("name", "");
                if (!name.empty()) {
                    state.set_names.insert(name);
                    std::string type;
                    const auto type_it = set.find("type");
                    if (type_it != set.end() && type_it->is_string()) {
                        type = type_it->get<std::string>();
                    } else if (type_it != set.end() &&
                               type_it->is_array()) {
                        for (const auto& component : *type_it) {
                            if (!component.is_string()) {
                                type.clear();
                                break;
                            }
                            if (!type.empty()) {
                                type += ".";
                            }
                            type += component.get<std::string>();
                        }
                    }
                    const uint32_t timeout = set.value("timeout", 0U);
                    state.set_schemas[name] = type + ":" + std::to_string(timeout);
                }
            }
        }
    }

    return state;
}

nlohmann::json NftablesFirewall::build_apply_document(const LiveTableState& live_state,
                                                      bool emit_full_table,
                                                      bool destructive_apply,
                                                      bool clear_dynamic_sets,
                                                      MarkMergeMode mark_merge_mode) {
    nlohmann::json doc;
    auto& arr = doc["nftables"];
    arr = nlohmann::json::array();

    // metainfo
    arr.push_back({{"metainfo", {{"json_schema_version", 1}}}});

    if (emit_full_table) {
        arr.push_back(build_table_json());
    }

    // Remove rule chains first. The complete JSON document is one nft
    // transaction, so the live rules remain active until the replacement is
    // valid and committed.
    if (!emit_full_table && live_state.chain_exists) {
        arr.push_back(build_delete_chain_json());
    }
    if (!emit_full_table && live_state.output_chain_exists) {
        arr.push_back(build_delete_output_chain_json());
    }
    if (!emit_full_table && live_state.dns_nat_chain_exists) {
        arr.push_back(build_delete_dns_nat_chain_json());
    }
    if (!emit_full_table && live_state.snat_chain_exists) {
        arr.push_back(build_delete_snat_chain_json());
    }

    std::set<std::string> pending_set_names;
    for (const auto& ps : pending_sets_) {
        pending_set_names.insert(ps.name);
    }

    if (destructive_apply && !emit_full_table) {
        for (const auto& live_name : live_state.set_names) {
            if (is_managed_set_name(live_name) &&
                pending_set_names.find(live_name) == pending_set_names.end() &&
                (clear_dynamic_sets || !is_dynamic_set_name(live_name))) {
                arr.push_back(build_delete_set_json(live_name));
            }
        }
    }

    // Dynamic dnsmasq sets retain learned elements during a live refresh.
    // Static sets are refreshed in this same transaction.
    for (const auto& ps : pending_sets_) {
        const bool existing = !emit_full_table &&
            live_state.set_names.find(ps.name) != live_state.set_names.end();
        if (existing && is_dynamic_set_name(ps.name)) {
            if (clear_dynamic_sets) {
                arr.push_back(build_flush_set_json(ps.name));
            }
            continue;
        }
        const auto schema_it = live_state.set_schemas.find(ps.name);
        if (existing && schema_it != live_state.set_schemas.end() &&
            schema_it->second == set_schema_key(ps)) {
            if (ps.source_udp_peer) {
                // Affinity belongs to the current runtime generation and must
                // never retain a mark after policy/outbound changes.
                arr.push_back(build_flush_set_json(ps.name));
            }
            continue;
        }
        if (existing) {
            arr.push_back(build_delete_set_json(ps.name));
        }
        arr.push_back(build_set_json(ps));
    }

    // Chain with prerouting hook
    arr.push_back(build_chain_json());

    // Chain with output hook (router-originated traffic, e.g. DNS detour)
    arr.push_back(build_output_chain_json());

    // An exact bridge-port equivalent of xt_physdev is not available in our
    // inet/prerouting nftables pipeline. `ibrname` is a bridge-family-only
    // expression and `sdifname` is not a safe replacement at this hook.
    // Keep bridged SSTP bypass fail-closed instead of weakening it to a shared
    // bridge name plus a forgeable source address.
    auto effective_prefilter = global_prefilter_;
    effective_prefilter.bypass_bridge_source_selectors_v4.clear();
    effective_prefilter.bypass_bridge_source_selectors_v6.clear();

    // DNS redirect nat chain (client DNS enforcement)
    if (dns_redirect_requested_) {
        arr.push_back(build_dns_nat_chain_json());
        for (const auto& cmd :
             build_dns_redirect_rules_json(
                 effective_prefilter, udp_peer_sets_)) {
            arr.push_back(cmd);
        }
    }

    // Masquerade for router-originated detour traffic: its source address was
    // chosen before the mark existed, so without this the tunnel peer drops it.
    if (router_origin_snat_requested_) {
        arr.push_back(build_snat_chain_json());
        arr.push_back(build_snat_rule_json());
        // Forwarded traffic from networks the firmware does not masquerade for
        // this interface, such as clients of a VPN server on the router.
        for (const auto& iface : snat_interfaces_) {
            arr.push_back(
                build_interface_snat_rule_json(iface, fwmark_mask()));
        }
        for (const auto& selector : source_egress_snat_selectors_) {
            arr.push_back(
                build_source_egress_snat_rule_json(selector));
        }
    }

    // Rules
    for (const auto& cmd : build_rule_add_commands(
             effective_prefilter, pending_rules_, mark_merge_mode)) {
        arr.push_back(cmd);
    }

    // Elements
    for (const auto& [set_name, elems] : pending_elements_) {
        if (!emit_full_table && live_state.set_names.find(set_name) != live_state.set_names.end()) {
            if (is_dynamic_set_name(set_name)) {
                continue;
            }
            const auto pending_it = std::find_if(
                pending_sets_.begin(), pending_sets_.end(),
                [&set_name](const PendingSet& set) { return set.name == set_name; });
            const auto schema_it = live_state.set_schemas.find(set_name);
            const bool recreated =
                pending_it != pending_sets_.end() &&
                (schema_it == live_state.set_schemas.end() ||
                 schema_it->second != set_schema_key(*pending_it));
            if (!recreated) {
                arr.push_back(build_flush_set_json(set_name));
            }
        }
        if (!elems.empty()) {
            arr.push_back(build_elements_json(set_name, elems));
        }
    }

    return doc;
}

void NftablesFirewall::apply(FirewallApplyMode mode) {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    const bool snat_expected = router_origin_snat_requested_;
    const auto expected_snat_interfaces = snat_interfaces_;
    const auto expected_source_egress_snat_selectors =
        source_egress_snat_selectors_;
    const uint32_t expected_snat_fwmark_mask = fwmark_mask();
    const MarkMergeMode active_mark_merge_mode = mark_merge_mode();
    const auto candidate_udp_peer_classifiers =
        build_pending_udp_peer_classifiers(active_mark_merge_mode);
    if (!global_prefilter_.bypass_bridge_source_selectors_v4.empty() ||
        !global_prefilter_.bypass_bridge_source_selectors_v6.empty()) {
        Logger::instance().verbose(
            "nftables has no safe inet/prerouting bridge-port selector; "
            "keeping bridged SSTP bypass fail-closed");
    }
    const LiveTableState live_state = read_live_table_state();
    const bool emit_full_table = !live_state.table_exists;
    const bool destructive_apply = mode == FirewallApplyMode::Destructive;
    const bool clear_dynamic_sets =
        destructive_apply && clear_dynamic_sets_on_apply();
    nlohmann::json doc =
        build_apply_document(
            live_state, emit_full_table, destructive_apply, clear_dynamic_sets,
            active_mark_merge_mode);

    std::string json_str = doc.dump();
    Logger::instance().verbose("nft json:\n{}", json_str);

    // Apply atomically via nft -j -f -
    std::string error_output;
    int status = safe_exec_pipe_stdin(
        {"nft", "-j", "-f", "-"},
        json_str,
        &error_output,
        SafeExecFailureLog::Suppressed);
    if (status != 0 && mode == FirewallApplyMode::PreserveSets &&
        !emit_full_table && !table_exists()) {
        Logger::instance().info(
            "nft preserve apply failed after KeenPbrTable disappeared; retrying full table restore");
        cleanup_live_impl();
        doc = build_apply_document(
            LiveTableState{}, /*emit_full_table=*/true,
            /*destructive_apply=*/false,
            /*clear_dynamic_sets=*/false,
            active_mark_merge_mode);
        json_str = doc.dump();
        Logger::instance().verbose("nft recovery json:\n{}", json_str);
        error_output.clear();
        status = safe_exec_pipe_stdin(
            {"nft", "-j", "-f", "-"},
            json_str,
            &error_output,
            SafeExecFailureLog::Suppressed);
    }
    if (status != 0) {
        record_safe_exec_pipe_failure(
            {"nft", "-j", "-f", "-"},
            status,
            json_str,
            error_output,
            status < 0 ? "execution_failed" : "nonzero_exit");
        // nft names the offending expression on stderr; without it the status
        // code alone told us nothing.
        throw FirewallError(
            error_output.empty()
                ? keen_pbr3::format("nft -j -f - exited with status {}", status)
                : keen_pbr3::format("nft -j -f - exited with status {}: {}",
                                    status, error_output));
    }

    const auto snat_state = inspect_owned_snat_state(
        snat_expected,
        expected_snat_interfaces,
        expected_source_egress_snat_selectors,
        expected_snat_fwmark_mask);
    if (snat_state == OwnedSnatState::missing ||
        snat_state == OwnedSnatState::stale) {
        throw TransientFirewallError(
            "nftables SNAT state does not match the applied contract");
    }
    if (snat_state == OwnedSnatState::unknown) {
        throw TransientFirewallError(
            "nftables SNAT state could not be inspected after apply");
    }

    last_applied_snat_expected_ = snat_expected;
    last_applied_snat_interfaces_ = expected_snat_interfaces;
    last_applied_source_egress_snat_selectors_ =
        expected_source_egress_snat_selectors;
    last_applied_snat_fwmark_mask_ = expected_snat_fwmark_mask;
    published_udp_peer_classifiers_ = candidate_udp_peer_classifiers;
    // Clear pending buffers
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    dns_redirect_requested_ = false;
    router_origin_snat_requested_ = false;
    snat_interfaces_.clear();
    source_egress_snat_selectors_.clear();
    table_created_ = true;
}

void NftablesFirewall::cleanup_live_impl() {
    if (table_created_ || table_exists()) {
        Logger::instance().verbose("nft delete table inet {}", TABLE_NAME);
        safe_exec({"nft", "delete", "table", "inet", std::string(TABLE_NAME)}, /*suppress_output=*/true);
        table_created_ = false;
    }
}

void NftablesFirewall::cleanup_impl() {
    cleanup_live_impl();

    last_applied_snat_expected_ = false;
    last_applied_snat_interfaces_.clear();
    last_applied_source_egress_snat_selectors_.clear();
    last_applied_snat_fwmark_mask_ = 0xFFFFFFFFu;
    created_sets_.clear();
    udp_peer_sets_.clear();
    published_udp_peer_classifiers_.clear();
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    source_egress_snat_selectors_.clear();
}

void NftablesFirewall::cleanup() {
    std::lock_guard<std::mutex> lock(pair_state_mutex_);
    cleanup_impl();
}

FirewallBackend NftablesFirewall::backend() const {
    return FirewallBackend::nftables;
}

std::unique_ptr<Firewall> create_nftables_firewall() {
    return std::make_unique<NftablesFirewall>();
}

} // namespace keen_pbr3
