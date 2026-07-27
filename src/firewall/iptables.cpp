#include "iptables.hpp"
#include "ipset_restore_pipe.hpp"
#include "port_spec_util.hpp"
#include "../log/logger.hpp"
#include "../util/format_compat.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/safe_exec.hpp"
#include <rapidxml.hpp>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstring>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>

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

void IptablesFirewall::prepare_apply(FirewallApplyMode mode) {
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    dns_redirect_requested_ = false;
    router_origin_snat_requested_ = false;
    snat_interfaces_.clear();

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
    } else if (existing->family_str != ps.family_str || existing->timeout != ps.timeout) {
        throw FirewallError("conflicting ipset declaration for " + set_name);
    }
    created_sets_[set_name] = family;
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
    if (criteria.dst_set_name.has_value()) {
        auto it = created_sets_.find(*criteria.dst_set_name);
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
    if (criteria.dst_set_name.has_value()) {
        auto it = created_sets_.find(*criteria.dst_set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Drop, 0, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Drop, 0, criteria);
    append_rules_for_family(true, PendingRule::Drop, 0, criteria);
}

void IptablesFirewall::create_pass_rule(const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value()) {
        auto it = created_sets_.find(*criteria.dst_set_name);
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

void IptablesFirewall::create_dns_redirect_rules() {
    dns_redirect_requested_ = true;
}

std::string IptablesFirewall::build_dns_nat_script(
    const FirewallGlobalPrefilter& prefilter,
    bool dns_redirect,
    bool router_origin_snat,
    const std::vector<std::string>& snat_interfaces) {
    std::vector<std::string> iface_frags;
    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()) {
        for (const auto& iface : *prefilter.inbound_interfaces) {
            iface_frags.push_back(" -i " + iface);
        }
    } else {
        iface_frags.push_back("");
    }

    std::string s;
    s += "*nat\n";
    if (dns_redirect) {
        s += keen_pbr3::format(":{} - [0:0]\n-A PREROUTING -j {}\n",
                               DNS_NAT_CHAIN_NAME, DNS_NAT_CHAIN_NAME);
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
        s += keen_pbr3::format(":{} - [0:0]\n-A POSTROUTING -j {}\n",
                               SNAT_CHAIN_NAME, SNAT_CHAIN_NAME);
        s += keen_pbr3::format(
            "-A {} -m mark --mark {:#x}/{:#x} -j MASQUERADE\n",
            SNAT_CHAIN_NAME, kRouterOriginMark, kRouterOriginMark);
        // Forwarded traffic from networks the firmware does not masquerade for
        // this interface - clients of a VPN server running on the router, guest
        // segments, anything routed here by policy rather than by the firmware.
        // Flows the firmware already translated keep their conntrack entry and
        // are unaffected, so this only fills the gap.
        for (const auto& iface : snat_interfaces) {
            s += keen_pbr3::format("-A {} -o {} -j MASQUERADE\n",
                                   SNAT_CHAIN_NAME, iface);
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

// Whether the local iptables-restore understands -w. Probed once: busybox and
// older builds reject the option outright, newer ones need it to avoid blocking
// forever on the xtables lock.
static int xtables_wait_supported = -1; // -1 unknown, 0 no, 1 yes

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

static bool restore_wait_option_supported(const std::string& program) {
    if (xtables_wait_supported >= 0) {
        return xtables_wait_supported == 1;
    }

    // Probe the option without feeding the real transaction to the tool.
    // Entware's legacy iptables-restore rejects -w, and using the actual rules
    // as the capability probe logs a scary failure even though the subsequent
    // unguarded fallback succeeds.
    const auto probe = safe_exec_capture(
        {program, "-w", "0", "--test"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/1024);
    xtables_wait_supported =
        !probe.timed_out && !probe.truncated && probe.exit_code == 0 ? 1 : 0;
    Logger::instance().verbose(
        "{} xtables wait option support: {}",
        program,
        xtables_wait_supported == 1 ? "yes" : "no");
    return xtables_wait_supported == 1;
}

#ifdef KEEN_PBR3_TESTING
namespace testing {

bool restore_wait_option_supported_for_test(const std::string& program) {
    return restore_wait_option_supported(program);
}

void reset_restore_wait_option_probe_for_test() {
    xtables_wait_supported = -1;
}

} // namespace testing
#endif

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
    const auto marker = error_output.find("line");
    if (marker != std::string::npos) {
        try {
            auto cursor = marker + 4;
            while (cursor < error_output.size() &&
                   (error_output[cursor] == ':' || error_output[cursor] == ' ')) {
                ++cursor;
            }
            const auto line_number = std::stoul(error_output.substr(cursor));
            std::istringstream script_stream(script);
            std::string line;
            for (unsigned long index = 1;
                 index <= line_number && std::getline(script_stream, line);
                 ++index) {
                if (index == line_number) {
                    message += keen_pbr3::format(" (rule: {})", line);
                    break;
                }
            }
        } catch (const std::exception&) {
            // No line number to quote; the tool's own text still stands.
        }
    }

    return message;
}

static void pipe_to_cmd(const std::vector<std::string>& args, const std::string& input) {
    Logger::instance().verbose("{} script:\n{}", args[0], input);

    // The Keenetic firmware reconfigures iptables dozens of times a second while
    // it brings interfaces up at boot. Without -w our restore call waits on the
    // xtables lock indefinitely and the daemon never reaches its event loop.
    if (is_restore_tool(args[0]) && restore_wait_option_supported(args[0])) {
        std::string error_output;
        const int status = safe_exec_pipe_stdin(with_wait_option(args), input, &error_output);
        if (status == 0) {
            return;
        }
        // Support was established by an empty --test transaction. A failure
        // here is therefore a real ruleset/lock error and must not be hidden by
        // replaying the same mutation without locking.
        throw FirewallError(describe_restore_failure(args[0], status, error_output, input));
    }

    std::string error_output;
    int status = safe_exec_pipe_stdin(args, input, &error_output);
    if (status != 0) {
        throw FirewallError(describe_restore_failure(args[0], status, error_output, input));
    }
}

std::string IptablesFirewall::build_ipset_create_line(const PendingSet& ps) {
    if (ps.timeout > 0) {
        return keen_pbr3::format("create {} hash:net family {} timeout {} -exist\n",
                                 ps.name, ps.family_str, ps.timeout);
    } else {
        return keen_pbr3::format("create {} hash:net family {} -exist\n",
                                 ps.name, ps.family_str);
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
           live_type == "hash:net" &&
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
    const auto result = safe_exec_capture(
        {command, "-t", table, "-S"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/256U * 1024U);
    if (result.exit_code != 0 || result.truncated || result.timed_out) {
        throw FirewallError("failed to inspect live iptables dispatcher " +
                            dispatcher);
    }
    return parse_live_generation(
        result.stdout_output, dispatcher, generation_a, generation_b);
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
                throw FirewallError(
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
                throw FirewallError(
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
        throw FirewallError(
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
    throw FirewallError(
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

void IptablesFirewall::reconcile_hook(
    const char* command,
    const char* table,
    const char* builtin_chain,
    const char* target_chain) {
    const auto result = safe_exec_capture(
        {command, "-t", table, "-S", builtin_chain},
        /*suppress_stderr=*/true,
        /*max_bytes=*/256U * 1024U);
    if (result.exit_code != 0 || result.truncated || result.timed_out) {
        throw FirewallError(keen_pbr3::format(
            "failed to inspect {} {}/{} hook",
            command, table, builtin_chain));
    }
    size_t count = count_exact_jump(
        result.stdout_output, builtin_chain, target_chain);
    if (count == 0) {
        if (safe_exec(
                {command, "-t", table, "-A", builtin_chain, "-j", target_chain},
                /*suppress_output=*/true) != 0) {
            throw FirewallError(keen_pbr3::format(
                "failed to add {} {}/{} hook",
                command, table, builtin_chain));
        }
        return;
    }
    while (count > 1) {
        if (safe_exec(
                {command, "-t", table, "-D", builtin_chain, "-j", target_chain},
                /*suppress_output=*/true) != 0) {
            throw FirewallError(keen_pbr3::format(
                "failed to remove duplicate {} {}/{} hook",
                command, table, builtin_chain));
        }
        --count;
    }
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
    const auto primary = safe_exec_capture(
        {command, "-t", prerouting_table_name(ipv6), "-S"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/256U * 1024U);
    if (primary.exit_code != 0 || primary.truncated || primary.timed_out ||
        parse_live_generation(
            primary.stdout_output,
            primary_dispatcher,
            prerouting_generation_chain(FirewallSetGeneration::A, ipv6),
            prerouting_generation_chain(FirewallSetGeneration::B, ipv6)) !=
            expected ||
        count_exact_jump(
            primary.stdout_output, "PREROUTING", primary_dispatcher) != 1) {
        throw FirewallError(
            "iptables PREROUTING dispatcher verification failed");
    }

    const auto output = safe_exec_capture(
        {command, "-t", "mangle", "-S"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/256U * 1024U);
    if (output.exit_code != 0 || output.truncated || output.timed_out ||
        parse_live_generation(
            output.stdout_output,
            OUTPUT_CHAIN_NAME,
            generation_output_chain(FirewallSetGeneration::A),
            generation_output_chain(FirewallSetGeneration::B)) != expected ||
        count_exact_jump(
            output.stdout_output, "OUTPUT", OUTPUT_CHAIN_NAME) != 1 ||
        (use_raw_prerouting_ && !ipv6 &&
         count_exact_jump(
             output.stdout_output,
             "PREROUTING",
             RAW_CONNTRACK_CHAIN_NAME) != 1)) {
        throw FirewallError(
            "iptables OUTPUT or companion hook verification failed");
    }
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
    bool allow_conntrack) {
    std::string lines;
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

    if (prefilter.skip_marked_packets) {
        lines += keen_pbr3::format(
            "-A {} -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n",
            chain);
    }

    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()
        && prefilter.inbound_interfaces->size() == 1) {
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
        && prefilter.inbound_interfaces.has_value()
        && prefilter.inbound_interfaces->size() > 1) {
        iface_frags.reserve(prefilter.inbound_interfaces->size());
        for (const auto& iface : *prefilter.inbound_interfaces) {
            iface_frags.push_back(" -i " + iface);
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
        if (!allow_conntrack || !prefilter.restore_conntrack_mark ||
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
                if (!pr.criteria.dst_set_name.has_value()) {
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
                            "-A {} -m set --match-set {} dst{}{}{}{} {}\n",
                            chain,
                            *pr.criteria.dst_set_name,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp,
                            mark_target));
                        lines.push_back(keen_pbr3::format(
                            "-A {} -m set --match-set {} dst{}{}{}{} "
                            "-j RETURN\n",
                            chain,
                            *pr.criteria.dst_set_name,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    } else if (pr.action == PendingRule::Drop) {
                        lines.push_back(keen_pbr3::format(
                            "-A {} -m set --match-set {} dst{}{}{}{} "
                            "-j DROP\n",
                            chain,
                            *pr.criteria.dst_set_name,
                            iface_frag,
                            addr_frag,
                            dscp_frag,
                            pp));
                    } else {
                        lines.push_back(keen_pbr3::format(
                            "-A {} -m set --match-set {} dst{}{}{}{} "
                            "-j RETURN\n",
                            chain,
                            *pr.criteria.dst_set_name,
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
    s += build_prefilter_lines(prefilter);
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
    if (prefilter.skip_marked_packets) {
        s += keen_pbr3::format(
            "-A {} -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n",
            OUTPUT_CHAIN_NAME);
    }
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

    std::istringstream prefilter_input(build_prefilter_lines(prefilter));
    std::string line;
    while (std::getline(prefilter_input, line)) {
        if (!line.empty()) {
            script += retarget_line(line) + "\n";
        }
    }

    script += build_conntrack_prefilter_lines(prefilter, output_chain);
    if (prefilter.skip_marked_packets) {
        script += keen_pbr3::format(
            "-A {} -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n",
            output_chain);
    }
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
        prefilter, prerouting_chain, /*allow_conntrack=*/false);

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
    const FirewallGlobalPrefilter& prefilter) {
    (void)replace_active_chain;
    std::string script = "*mangle\n";
    script += keen_pbr3::format(
        ":{} - [0:0]\n-F {}\n",
        RAW_CONNTRACK_CHAIN_NAME,
        RAW_CONNTRACK_CHAIN_NAME);

    script += build_conntrack_prefilter_lines(
        prefilter, RAW_CONNTRACK_CHAIN_NAME);
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
    if (prefilter.skip_marked_packets) {
        script += keen_pbr3::format(
            "-A {} -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n",
            output_chain);
    }

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

void IptablesFirewall::apply(FirewallApplyMode mode) {
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
    }

    if (mode == FirewallApplyMode::Destructive) {
        cleanup_live_impl(
            /*preserve_dynamic_sets=*/!clear_dynamic_sets_on_apply(),
            /*sweep_live_state=*/true);
    } else {
        // Routing chains stay live until their A/B dispatcher is switched.
        // NAT chains are rebuilt separately because they do not reference the
        // generation-scoped list sets.
        cleanup_nat_rules_impl();
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
                    global_prefilter_));
            pipe_to_cmd(
                {"iptables-restore", "--noflush", "--counters"},
                build_output_generation_script(
                    output_chain,
                    /*replace_active_chain=*/true,
                    pending_rules_,
                    global_prefilter_));
            pipe_to_cmd(
                {"iptables-restore", "--noflush", "--counters"},
                build_raw_prerouting_script(
                    raw_generation_prerouting_chain(target_v4_generation_),
                    /*replace_active_chain=*/true,
                    pending_rules_,
                    global_prefilter_));
        } else {
            const std::string prerouting_chain =
                generation_prerouting_chain(target_v4_generation_);
            pipe_to_cmd({"iptables-restore", "--noflush", "--counters"},
                        build_generation_ipt_script(
                            false, prerouting_chain, output_chain,
                            /*replace_active_chains=*/true,
                            pending_rules_, global_prefilter_));
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
                        pending_rules_, global_prefilter_));
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
    // router-originated detour traffic usable.
    if (dns_redirect_requested_ || router_origin_snat_requested_) {
        const std::string nat_script = build_dns_nat_script(
            global_prefilter_, dns_redirect_requested_,
            router_origin_snat_requested_, snat_interfaces_);
        pipe_to_cmd({"iptables-restore", "--noflush", "--counters"}, nat_script);
        dns_nat_v4_created_ = true;
        if (effective_ipv6) {
            try {
                pipe_to_cmd({"ip6tables-restore", "--noflush", "--counters"},
                            nat_script);
                dns_nat_v6_created_ = true;
            } catch (const std::exception& e) {
                // ip6table_nat is missing on some older Keenetic kernels;
                // IPv4 enforcement still applies.
                Logger::instance().warn(
                    "IPv6 DNS redirect unavailable ({}); continuing IPv4-only", e.what());
            }
        }
    }
    dns_redirect_requested_ = false;
    router_origin_snat_requested_ = false;
    snat_interfaces_.clear();

    // Clear pending buffers
    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
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
    // DNS redirect and tunnel masquerade NAT chains.
    if (dns_nat_v4_created_ || sweep_live_state) {
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
    if (dns_nat_v6_created_ || sweep_live_state) {
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
            name.rfind("kpbr4d_", 0) == 0 || name.rfind("kpbr6d_", 0) == 0;
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

    created_sets_.clear();

    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
}

void IptablesFirewall::cleanup() {
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
