#include "ppe_deoffload.hpp"

#include "port_spec_util.hpp"
#include "../util/format_compat.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <map>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace keen_pbr3 {

namespace {

constexpr std::string_view kPpeTagPrefix{"keen-pbr-sb:ppe:"};

std::vector<std::string> tokenize_iptables_rule(std::string_view line) {
    std::vector<std::string> tokens;
    std::string token;
    bool quoted = false;
    char quote = '\0';
    bool escaped = false;
    for (const char ch : line) {
        if (escaped) {
            token.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (quoted) {
            if (ch == quote) {
                quoted = false;
            } else {
                token.push_back(ch);
            }
            continue;
        }
        if (ch == '\'' || ch == '"') {
            quoted = true;
            quote = ch;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            if (!token.empty()) {
                tokens.push_back(std::move(token));
                token.clear();
            }
            continue;
        }
        token.push_back(ch);
    }
    if (escaped || quoted) {
        return {};
    }
    if (!token.empty()) tokens.push_back(std::move(token));
    return tokens;
}

std::optional<std::string> option_value(
    const std::vector<std::string>& tokens,
    std::string_view option) {
    for (std::size_t i = 0; i + 1U < tokens.size(); ++i) {
        if (tokens[i] == option) return tokens[i + 1U];
    }
    return std::nullopt;
}

std::size_t option_count(const std::vector<std::string>& tokens,
                         std::string_view option) {
    return static_cast<std::size_t>(std::count(
        tokens.begin(), tokens.end(), std::string{option}));
}

bool has_match(const std::vector<std::string>& tokens,
               std::string_view match) {
    for (std::size_t i = 0; i + 1U < tokens.size(); ++i) {
        if (tokens[i] == "-m" && tokens[i + 1U] == match) return true;
    }
    return false;
}

bool parse_u64(std::string_view value, std::uint64_t& parsed) {
    if (value.empty()) return false;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    return result.ec == std::errc{} &&
        result.ptr == value.data() + value.size();
}

bool parse_index(std::string_view value, std::size_t& parsed) {
    std::uint64_t numeric = 0;
    if (!parse_u64(value, numeric) ||
        numeric > static_cast<std::uint64_t>(
            std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    parsed = static_cast<std::size_t>(numeric);
    return true;
}

std::string tcp_tag(std::size_t index) {
    return std::string{kPpeDeoffloadTcpTagPrefix} + std::to_string(index);
}

std::string hook_rule(std::string_view tag) {
    return keen_pbr3::format(
        "-m comment --comment {} -j {}", tag, kPpeDeoffloadChain);
}

std::string tcp_rule(std::string_view chain,
                     std::string_view ports,
                     std::size_t index) {
    return keen_pbr3::format(
        "-A {} -p tcp -m multiport --dports {} "
        "-m connskip --connskip {} -m comment --comment {} -j PPE",
        chain,
        ports,
        kPpeDeoffloadConnskipWindow,
        tcp_tag(index));
}

std::string quic_rule(std::string_view chain) {
    return keen_pbr3::format(
        "-A {} -p udp -m udp --dport 443 "
        "-m connskip --connskip {} -m comment --comment {} -j PPE",
        chain,
        kPpeDeoffloadConnskipWindow,
        kPpeDeoffloadQuicTag);
}

std::string return_rule(std::string_view chain) {
    return keen_pbr3::format(
        "-A {} -m comment --comment {} -j RETURN",
        chain,
        kPpeDeoffloadReturnTag);
}

bool exact_hook_normal(const std::vector<std::string>& tokens,
                       std::string_view parent,
                       std::string_view tag) {
    return tokens == std::vector<std::string>{
        "-A", std::string{parent}, "-m", "comment", "--comment",
        std::string{tag}, "-j", kPpeDeoffloadChain};
}

bool only_allowed_rule_tokens(const std::vector<std::string>& tokens,
                              bool tcp,
                              bool quic,
                              std::string_view chain = kPpeDeoffloadChain) {
    // Validate multiplicity as well as values. Unknown/duplicate options are
    // foreign semantics even if the owned comment happens to be copied.
    if (tokens.size() < 8U || tokens[0] != "-A" ||
        tokens[1] != chain ||
        option_count(tokens, "-p") != 1U ||
        option_count(tokens, "--connskip") != 1U ||
        option_count(tokens, "--comment") != 1U ||
        option_count(tokens, "-j") != 1U) {
        return false;
    }
    if (option_value(tokens, "-j") != std::optional<std::string>{"PPE"} ||
        option_value(tokens, "--connskip") !=
            std::optional<std::string>{
                std::to_string(kPpeDeoffloadConnskipWindow)} ||
        !has_match(tokens, "connskip") || !has_match(tokens, "comment")) {
        return false;
    }
    std::map<std::string, std::size_t> modules;
    for (std::size_t i = 0; i + 1U < tokens.size(); ++i) {
        if (tokens[i] == "-m") {
            ++modules[tokens[++i]];
        }
    }
    const auto modules_are = [&modules](
        std::initializer_list<std::pair<const char*, std::size_t>> allowed) {
        std::map<std::string, std::size_t> expected_modules;
        for (const auto& [name, count] : allowed) {
            expected_modules.emplace(name, count);
        }
        return modules == expected_modules;
    };
    if (tcp) {
        const bool normal_modules = modules_are({
            {"multiport", 1U}, {"connskip", 1U}, {"comment", 1U}});
        const bool explicit_tcp_modules = modules_are({
            {"tcp", 1U}, {"multiport", 1U},
            {"connskip", 1U}, {"comment", 1U}});
        return option_value(tokens, "-p") ==
                   std::optional<std::string>{"tcp"} &&
            option_count(tokens, "--dports") == 1U &&
            option_count(tokens, "--dport") == 0U &&
            (normal_modules || explicit_tcp_modules) &&
            tokens.size() == (normal_modules ? 18U : 20U);
    }
    if (quic) {
        const bool normal_modules = modules_are({
            {"udp", 1U}, {"connskip", 1U}, {"comment", 1U}});
        return option_value(tokens, "-p") ==
                   std::optional<std::string>{"udp"} &&
            option_count(tokens, "--dport") == 1U &&
            option_value(tokens, "--dport") ==
                std::optional<std::string>{"443"} &&
            option_count(tokens, "--dports") == 0U &&
            normal_modules && tokens.size() == 18U;
    }
    return false;
}

bool exact_return_rule(
    const std::vector<std::string>& tokens,
    std::string_view chain = kPpeDeoffloadChain) {
    return tokens == std::vector<std::string>{
        "-A", std::string{chain}, "-m", "comment", "--comment",
        kPpeDeoffloadReturnTag, "-j", "RETURN"};
}

std::vector<std::string> flatten_ports(
    const std::vector<std::string>& inputs) {
    std::vector<PortRange> ranges;
    for (const auto& input : inputs) {
        const PortSpec parsed = parse_port_spec(input);
        ranges.insert(ranges.end(), parsed.ranges.begin(), parsed.ranges.end());
    }
    std::sort(ranges.begin(), ranges.end(), [](const PortRange& lhs,
                                                const PortRange& rhs) {
        return lhs.from != rhs.from ? lhs.from < rhs.from : lhs.to < rhs.to;
    });
    std::vector<PortRange> merged;
    for (const auto& range : ranges) {
        if (merged.empty() ||
            static_cast<std::uint32_t>(range.from) >
                static_cast<std::uint32_t>(merged.back().to) + 1U) {
            merged.push_back(range);
            continue;
        }
        merged.back().to = std::max(merged.back().to, range.to);
    }

    std::vector<std::string> tokens;
    tokens.reserve(merged.size());
    for (const auto& range : merged) {
        tokens.push_back(range.from == range.to
            ? std::to_string(range.from)
            : keen_pbr3::format("{}:{}", range.from, range.to));
    }
    return tokens;
}

std::size_t multiport_slot_cost(const PortRange& range) {
    return range.from == range.to ? 1U : 2U;
}

std::string join_ports(const std::vector<std::string>& ports,
                       std::size_t first,
                       std::size_t count) {
    std::string result;
    for (std::size_t i = 0; i < count; ++i) {
        if (i != 0U) result.push_back(',');
        result += ports[first + i];
    }
    return result;
}

std::string canonical_port_chunk(std::string_view input) {
    const auto tokens = flatten_ports({std::string{input}});
    return join_ports(tokens, 0U, tokens.size());
}

std::vector<std::string> expected_chain_rules(
    const PpeDeoffloadGraphSpec& spec,
    std::string_view chain = kPpeDeoffloadChain) {
    std::vector<std::string> rules;
    for (std::size_t i = 0; i < spec.tcp_chunks.size(); ++i) {
        rules.push_back(tcp_rule(chain, spec.tcp_chunks[i], i));
    }
    if (spec.quic) rules.push_back(quic_rule(chain));
    rules.push_back(return_rule(chain));
    return rules;
}

void append_exact_chain_rule_deletions(
    std::string& script,
    const std::vector<std::string>& rules,
    std::string_view chain) {
    const std::string prefix = keen_pbr3::format("-A {} ", chain);
    for (auto rule = rules.rbegin(); rule != rules.rend(); ++rule) {
        if (rule->rfind(prefix, 0U) != 0U) {
            throw std::invalid_argument(
                "PPE inspection supplied a non-owned chain rule");
        }
        std::string deletion = *rule;
        deletion[1] = 'D';
        script += deletion;
        script.push_back('\n');
    }
}

bool line_references_chain(const std::vector<std::string>& tokens) {
    return option_value(tokens, "-j") ==
               std::optional<std::string>{kPpeDeoffloadChain} ||
        option_value(tokens, "-g") ==
               std::optional<std::string>{kPpeDeoffloadChain};
}

std::string strip_counter_prefix(std::string line,
                                 std::uint64_t* packets = nullptr,
                                 std::uint64_t* bytes = nullptr) {
    if (line.empty() || line.front() != '[') return line;
    const auto colon = line.find(':', 1U);
    const auto close = line.find(']', colon == std::string::npos ? 1U : colon);
    if (colon == std::string::npos || close == std::string::npos ||
        close + 1U >= line.size() || line[close + 1U] != ' ') {
        return line;
    }
    std::uint64_t parsed_packets = 0;
    std::uint64_t parsed_bytes = 0;
    if (!parse_u64(std::string_view{line}.substr(1U, colon - 1U),
                   parsed_packets) ||
        !parse_u64(std::string_view{line}.substr(
                       colon + 1U, close - colon - 1U),
                   parsed_bytes)) {
        return line;
    }
    if (packets != nullptr) *packets = parsed_packets;
    if (bytes != nullptr) *bytes = parsed_bytes;
    return line.substr(close + 2U);
}

} // namespace

const char* ppe_deoffload_mode_name(PpeDeoffloadMode mode) noexcept {
    switch (mode) {
        case PpeDeoffloadMode::off: return "off";
        case PpeDeoffloadMode::automatic: return "auto";
    }
    return "unknown";
}

const char* ppe_deoffload_state_name(PpeDeoffloadState state) noexcept {
    switch (state) {
        case PpeDeoffloadState::disabled: return "disabled";
        case PpeDeoffloadState::admissible: return "admissible";
        case PpeDeoffloadState::active: return "active";
        case PpeDeoffloadState::unknown: return "unknown";
        case PpeDeoffloadState::ppe_target_missing:
            return "ppe_target_missing";
        case PpeDeoffloadState::connskip_match_missing:
            return "connskip_match_missing";
        case PpeDeoffloadState::backend_incompatible:
            return "backend_incompatible";
        case PpeDeoffloadState::nfqueue_inactive:
            return "nfqueue_inactive";
        case PpeDeoffloadState::strategy_ports_unavailable:
            return "strategy_ports_unavailable";
        case PpeDeoffloadState::conntrack_accounting_unknown:
            return "conntrack_accounting_unknown";
        case PpeDeoffloadState::conntrack_accounting_disabled:
            return "conntrack_accounting_disabled";
        case PpeDeoffloadState::ppe_state_unknown:
            return "ppe_state_unknown";
        case PpeDeoffloadState::ppe_already_disabled:
            return "ppe_already_disabled";
        case PpeDeoffloadState::userspace_incompatible:
            return "userspace_incompatible";
        case PpeDeoffloadState::graph_conflict: return "graph_conflict";
        case PpeDeoffloadState::reconcile_failed: return "reconcile_failed";
    }
    return "unknown";
}

const char* ppe_graph_state_name(PpeGraphState state) noexcept {
    switch (state) {
        case PpeGraphState::absent: return "absent";
        case PpeGraphState::exact: return "exact";
        case PpeGraphState::owned_drift: return "owned_drift";
        case PpeGraphState::ambiguous: return "ambiguous";
    }
    return "ambiguous";
}

PpeObservationRefreshResult classify_ppe_deoffload_observation(
    PpeGraphState graph_state,
    bool owner_marker_valid,
    bool stored_snapshot_active) noexcept {
    if (graph_state == PpeGraphState::ambiguous) {
        return PpeObservationRefreshResult::unavailable;
    }
    if (!owner_marker_valid || graph_state != PpeGraphState::exact ||
        !stored_snapshot_active) {
        return PpeObservationRefreshResult::semantic_drift;
    }
    return PpeObservationRefreshResult::refreshed;
}

PpeDeoffloadAssessment evaluate_ppe_deoffload(
    const PpeDeoffloadInputs& inputs) {
    PpeDeoffloadAssessment assessment;
    const auto refuse = [&assessment](PpeDeoffloadState state,
                                      std::string detail,
                                      bool supported,
                                      bool degraded) {
        assessment.state = state;
        assessment.detail = std::move(detail);
        assessment.supported = supported;
        assessment.degraded = degraded;
        return assessment;
    };

    if (inputs.desired.mode == PpeDeoffloadMode::off) {
        return refuse(PpeDeoffloadState::disabled,
                      "disabled by configuration", false, false);
    }
    if (!inputs.backend_compatible) {
        return refuse(PpeDeoffloadState::backend_incompatible,
                      "PPE de-offload requires the iptables backend",
                      false, false);
    }
    if (inputs.ppe_target == PpeCapabilityState::unknown) {
        return refuse(PpeDeoffloadState::unknown,
                      "could not inspect the kernel PPE target inventory",
                      false, true);
    }
    if (inputs.ppe_target == PpeCapabilityState::unavailable) {
        return refuse(PpeDeoffloadState::ppe_target_missing,
                      "kernel target 'PPE' is not registered", false, false);
    }
    if (inputs.connskip_match == PpeCapabilityState::unknown) {
        return refuse(PpeDeoffloadState::unknown,
                      "could not inspect the kernel connskip inventory",
                      true, true);
    }
    if (inputs.connskip_match == PpeCapabilityState::unavailable) {
        return refuse(PpeDeoffloadState::connskip_match_missing,
                      "kernel match 'connskip' is not registered", false, true);
    }
    if (inputs.conntrack_accounting == PpeCapabilityState::unknown) {
        return refuse(PpeDeoffloadState::conntrack_accounting_unknown,
                      "could not read nf_conntrack_acct", true, true);
    }
    if (inputs.conntrack_accounting == PpeCapabilityState::unavailable) {
        return refuse(PpeDeoffloadState::conntrack_accounting_disabled,
                      "nf_conntrack_acct is not enabled", false, true);
    }
    if (inputs.ppe_enabled == PpeCapabilityState::unknown) {
        return refuse(PpeDeoffloadState::ppe_state_unknown,
                      "could not read net.hwnat.ppe_enabled", true, true);
    }
    if (inputs.ppe_enabled == PpeCapabilityState::unavailable) {
        return refuse(PpeDeoffloadState::ppe_already_disabled,
                      "hardware PPE is already disabled system-wide",
                      false, false);
    }
    if (!inputs.desired.nfqueue_active) {
        return refuse(PpeDeoffloadState::nfqueue_inactive,
                      inputs.desired.runtime_contract_detail.empty()
                          ? "no active NFQUEUE/nfqws runtime contract"
                          : inputs.desired.runtime_contract_detail,
                      true, false);
    }
    if (!inputs.desired.strategy_ports_available) {
        return refuse(PpeDeoffloadState::strategy_ports_unavailable,
                      inputs.desired.runtime_contract_detail.empty()
                          ? "validated active strategy ports are unavailable"
                          : inputs.desired.runtime_contract_detail,
                      true, true);
    }

    assessment.tcp_eligible = !inputs.desired.tcp_ports.empty();
    assessment.quic_eligible =
        inputs.desired.quic_enabled && inputs.desired.quic_443_active;
    if (!assessment.tcp_eligible && !assessment.quic_eligible) {
        return refuse(PpeDeoffloadState::strategy_ports_unavailable,
                      "the active strategy exposed no eligible TCP or QUIC ports",
                      true, true);
    }
    if (inputs.userspace == PpeCapabilityState::unknown) {
        return refuse(PpeDeoffloadState::unknown,
                      "iptables PPE userspace contract was not verified",
                      true, true);
    }
    if (inputs.userspace == PpeCapabilityState::unavailable) {
        return refuse(PpeDeoffloadState::userspace_incompatible,
                      "iptables userspace rejected the PPE graph syntax",
                      false, true);
    }

    assessment.state = PpeDeoffloadState::admissible;
    assessment.supported = true;
    return assessment;
}

bool ppe_deoffload_desired_semantically_equal(
    const PpeDeoffloadDesired& lhs,
    const PpeDeoffloadDesired& rhs) noexcept {
    return lhs.mode == rhs.mode &&
        lhs.nfqueue_active == rhs.nfqueue_active &&
        lhs.strategy_ports_available == rhs.strategy_ports_available &&
        lhs.nfqueue_number == rhs.nfqueue_number &&
        lhs.tcp_ports == rhs.tcp_ports &&
        lhs.quic_enabled == rhs.quic_enabled &&
        lhs.quic_443_active == rhs.quic_443_active;
}

PpeDeoffloadGraphSpec build_ppe_deoffload_graph_spec(
    const PpeDeoffloadDesired& desired) {
    PpeDeoffloadGraphSpec spec;
    std::vector<PortRange> canonical_ranges;
    const auto canonical_tokens = flatten_ports(desired.tcp_ports);
    for (const auto& token : canonical_tokens) {
        const auto parsed = parse_port_spec(token);
        canonical_ranges.insert(
            canonical_ranges.end(), parsed.ranges.begin(), parsed.ranges.end());
    }
    std::vector<std::string> chunk;
    std::size_t used_slots = 0U;
    const auto flush_chunk = [&spec, &chunk, &used_slots] {
        if (chunk.empty()) return;
        spec.tcp_chunks.push_back(join_ports(chunk, 0U, chunk.size()));
        chunk.clear();
        used_slots = 0U;
        if (spec.tcp_chunks.size() > kPpeDeoffloadMaxTcpChunks) {
            throw std::invalid_argument(
                "PPE TCP port selector exceeds the 16-rule safety bound");
        }
    };
    for (const auto& range : canonical_ranges) {
        const std::size_t cost = multiport_slot_cost(range);
        if (used_slots + cost > kPpeDeoffloadMultiportLimit) {
            flush_chunk();
        }
        chunk.push_back(range.from == range.to
            ? std::to_string(range.from)
            : keen_pbr3::format("{}:{}", range.from, range.to));
        used_slots += cost;
    }
    flush_chunk();
    spec.quic = desired.quic_enabled && desired.quic_443_active;
    return spec;
}

PpeGraphInspection inspect_ppe_deoffload_graph(
    const std::string& iptables_s,
    const PpeDeoffloadGraphSpec* expected,
    bool owner_marker_present) {
    PpeGraphInspection result;
    std::vector<std::vector<std::string>> chain_rules;
    std::vector<std::string> chain_rule_tags;
    std::map<std::size_t, std::string> tcp_chunks;
    bool quic = false;
    bool return_seen = false;
    bool ambiguous = false;
    std::size_t prerouting_position = 0;
    std::size_t forward_position = 0;

    std::istringstream input{iptables_s};
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        line = strip_counter_prefix(std::move(line));
        const auto tokens = tokenize_iptables_rule(line);
        if (tokens.empty()) continue;
        if ((tokens.size() == 2U && tokens[0] == "-N" &&
             tokens[1] == kPpeDeoffloadChain) ||
            (tokens.size() >= 2U &&
             tokens[0] == std::string(":") + kPpeDeoffloadChain)) {
            result.chain_exists = true;
            continue;
        }
        if (tokens.size() >= 2U && tokens[0] == "-A") {
            if (tokens[1] == "PREROUTING") ++prerouting_position;
            if (tokens[1] == "FORWARD") ++forward_position;
        }
        const auto line_tag = option_value(tokens, "--comment");
        if (line_references_chain(tokens)) {
            const auto& tag = line_tag;
            if (tokens.size() >= 2U && tokens[1] == "PREROUTING" &&
                tag == std::optional<std::string>{
                    kPpeDeoffloadPreroutingTag} &&
                exact_hook_normal(tokens, "PREROUTING",
                                  kPpeDeoffloadPreroutingTag)) {
                ++result.prerouting_hook_count;
                result.prerouting_hook_positions.push_back(
                    prerouting_position);
            } else if (tokens.size() >= 2U && tokens[1] == "FORWARD" &&
                       tag == std::optional<std::string>{
                           kPpeDeoffloadForwardTag} &&
                       exact_hook_normal(tokens, "FORWARD",
                                         kPpeDeoffloadForwardTag)) {
                ++result.forward_hook_count;
                result.forward_hook_positions.push_back(forward_position);
            } else {
                ambiguous = true;
                result.detail = "foreign or malformed reference to KeenPbrPpe4";
            }
        }
        if (line_tag.has_value() &&
            line_tag->rfind(kPpeTagPrefix, 0U) == 0U &&
            !(tokens.size() >= 2U && tokens[0] == "-A" &&
              (tokens[1] == kPpeDeoffloadChain ||
               (tokens[1] == "PREROUTING" &&
                *line_tag == kPpeDeoffloadPreroutingTag &&
                line_references_chain(tokens)) ||
               (tokens[1] == "FORWARD" &&
                *line_tag == kPpeDeoffloadForwardTag &&
                line_references_chain(tokens))))) {
            ambiguous = true;
            result.detail = "PPE ownership tag appears on an unexpected rule";
        }
        if (tokens.size() < 2U || tokens[0] != "-A" ||
            tokens[1] != kPpeDeoffloadChain) {
            continue;
        }
        chain_rules.push_back(tokens);
        result.owned_chain_rules.push_back(line);
        const auto tag = option_value(tokens, "--comment");
        if (!tag.has_value()) {
            ambiguous = true;
            result.detail = "untagged rule in KeenPbrPpe4";
            continue;
        }
        chain_rule_tags.push_back(*tag);
        if (tag->rfind(kPpeDeoffloadTcpTagPrefix, 0U) == 0U) {
            std::size_t index = 0;
            const auto suffix = std::string_view{*tag}.substr(
                std::string_view{kPpeDeoffloadTcpTagPrefix}.size());
            const auto ports = option_value(tokens, "--dports");
            if (!parse_index(suffix, index) ||
                index >= kPpeDeoffloadMaxTcpChunks ||
                tcp_chunks.size() >= kPpeDeoffloadMaxTcpChunks ||
                !ports.has_value() ||
                !only_allowed_rule_tokens(tokens, true, false) ||
                tcp_chunks.find(index) != tcp_chunks.end()) {
                ambiguous = true;
                result.detail = "malformed or duplicate owned PPE TCP rule";
                continue;
            }
            try {
                const PortSpec parsed = parse_port_spec(*ports);
                std::size_t slots = 0U;
                for (const auto& range : parsed.ranges) {
                    slots += multiport_slot_cost(range);
                }
                if (parsed.ranges.empty() ||
                    slots > kPpeDeoffloadMultiportLimit ||
                    canonical_port_chunk(*ports) != *ports) {
                    throw std::invalid_argument("non-canonical PPE port chunk");
                }
            } catch (const std::invalid_argument&) {
                ambiguous = true;
                result.detail = "invalid PPE TCP port chunk";
                continue;
            }
            tcp_chunks.emplace(index, *ports);
        } else if (*tag == kPpeDeoffloadQuicTag) {
            if (quic || !only_allowed_rule_tokens(tokens, false, true)) {
                ambiguous = true;
                result.detail = "malformed or duplicate owned PPE QUIC rule";
                continue;
            }
            quic = true;
        } else if (*tag == kPpeDeoffloadReturnTag) {
            if (return_seen || !exact_return_rule(tokens)) {
                ambiguous = true;
                result.detail = "malformed or duplicate PPE return rule";
                continue;
            }
            return_seen = true;
        } else {
            ambiguous = true;
            result.detail = "foreign rule in KeenPbrPpe4";
        }
    }

    const bool any_artifact = result.chain_exists ||
        result.prerouting_hook_count != 0U || result.forward_hook_count != 0U;
    if (!any_artifact && !ambiguous) {
        result.state = PpeGraphState::absent;
        return result;
    }
    if (ambiguous) {
        result.state = PpeGraphState::ambiguous;
        return result;
    }
    if (!result.chain_exists) {
        result.state = PpeGraphState::owned_drift;
        result.detail = "owned PPE hook exists without its chain";
        return result;
    }
    if (chain_rules.empty() && !owner_marker_present &&
        result.prerouting_hook_count == 0U &&
        result.forward_hook_count == 0U) {
        result.state = PpeGraphState::ambiguous;
        result.detail = "empty unreferenced KeenPbrPpe4 has no ownership proof";
        return result;
    }

    for (std::size_t index = 0; index < tcp_chunks.size(); ++index) {
        const auto found = tcp_chunks.find(index);
        if (found == tcp_chunks.end()) {
            result.state = PpeGraphState::ambiguous;
            result.detail = "PPE TCP rule tags are not contiguous";
            return result;
        }
        result.observed.tcp_chunks.push_back(found->second);
    }
    result.observed.quic = quic;

    std::vector<std::string> expected_tags;
    for (std::size_t i = 0; i < result.observed.tcp_chunks.size(); ++i) {
        expected_tags.push_back(tcp_tag(i));
    }
    if (result.observed.quic) expected_tags.push_back(kPpeDeoffloadQuicTag);
    expected_tags.push_back(kPpeDeoffloadReturnTag);
    const bool owned_rule_order_exact = chain_rule_tags == expected_tags;
    const bool hooks_exact = result.prerouting_hook_count == 1U &&
        result.forward_hook_count == 1U &&
        result.prerouting_hook_positions == std::vector<std::size_t>{1U} &&
        result.forward_hook_positions == std::vector<std::size_t>{1U};
    const bool desired_exact = expected == nullptr ||
        result.observed == *expected;
    if (owned_rule_order_exact && hooks_exact && desired_exact) {
        result.state = PpeGraphState::exact;
        return result;
    }
    result.state = PpeGraphState::owned_drift;
    result.detail = !hooks_exact
        ? "owned PPE hooks are missing, duplicated, or no longer first"
        : !owned_rule_order_exact
            ? "owned PPE rule order drifted"
            : "owned PPE ports differ from desired state";
    return result;
}

std::string build_ppe_deoffload_apply_script(
    const PpeGraphInspection& before,
    const PpeDeoffloadGraphSpec& desired) {
    if (before.state == PpeGraphState::ambiguous) {
        throw std::invalid_argument(
            "refusing to replace an ambiguous PPE graph");
    }
    if (desired.empty()) {
        throw std::invalid_argument("refusing to publish an empty PPE graph");
    }
    std::string script{"*mangle\n"};
    for (std::size_t i = 0; i < before.prerouting_hook_count; ++i) {
        script += keen_pbr3::format(
            "-D PREROUTING {}\n",
            hook_rule(kPpeDeoffloadPreroutingTag));
    }
    for (std::size_t i = 0; i < before.forward_hook_count; ++i) {
        script += keen_pbr3::format(
            "-D FORWARD {}\n",
            hook_rule(kPpeDeoffloadForwardTag));
    }
    if (before.chain_exists) {
        append_exact_chain_rule_deletions(
            script, before.owned_chain_rules, kPpeDeoffloadChain);
        // This is the transaction's concurrency fence. A rule/reference that
        // appeared after inspection makes -X fail, so COMMIT cannot erase or
        // adopt foreign state. Recreate only after exact deletion succeeded.
        script += keen_pbr3::format("-X {}\n", kPpeDeoffloadChain);
    } else if (!before.owned_chain_rules.empty()) {
        throw std::invalid_argument(
            "PPE inspection supplied rules without their chain");
    }
    // Create-only syntax also fences the absent -> foreign-create race.
    script += keen_pbr3::format("-N {}\n", kPpeDeoffloadChain);
    for (const auto& rule : expected_chain_rules(desired)) {
        script += rule;
        script.push_back('\n');
    }
    script += keen_pbr3::format(
        "-I PREROUTING 1 {}\n-I FORWARD 1 {}\nCOMMIT\n",
        hook_rule(kPpeDeoffloadPreroutingTag),
        hook_rule(kPpeDeoffloadForwardTag));
    return script;
}

std::string build_ppe_deoffload_cleanup_script(
    const PpeGraphInspection& before) {
    if (before.state == PpeGraphState::ambiguous) {
        throw std::invalid_argument(
            "refusing to remove an ambiguous PPE graph");
    }
    if (before.state == PpeGraphState::absent) return {};
    std::string script{"*mangle\n"};
    for (std::size_t i = 0; i < before.prerouting_hook_count; ++i) {
        script += keen_pbr3::format(
            "-D PREROUTING {}\n",
            hook_rule(kPpeDeoffloadPreroutingTag));
    }
    for (std::size_t i = 0; i < before.forward_hook_count; ++i) {
        script += keen_pbr3::format(
            "-D FORWARD {}\n",
            hook_rule(kPpeDeoffloadForwardTag));
    }
    if (before.chain_exists) {
        append_exact_chain_rule_deletions(
            script, before.owned_chain_rules, kPpeDeoffloadChain);
        script += keen_pbr3::format("-X {}\n", kPpeDeoffloadChain);
    } else if (!before.owned_chain_rules.empty()) {
        throw std::invalid_argument(
            "PPE inspection supplied rules without their chain");
    }
    script += "COMMIT\n";
    return script;
}

std::string build_ppe_deoffload_validation_script(
    const PpeDeoffloadGraphSpec& desired,
    const std::string& validation_chain) {
    if (desired.empty() || validation_chain.empty()) {
        throw std::invalid_argument("invalid empty PPE validation graph");
    }
    std::string script{"*mangle\n"};
    // The legacy preflight creates this collision-free chain with `-N` and
    // proves it exactly empty before this transaction. Never declare or flush
    // it here: a concurrent foreign write must survive and make exact cleanup
    // fail closed, not be erased by validation.
    for (const auto& rule : expected_chain_rules(desired, validation_chain)) {
        script += rule;
        script.push_back('\n');
    }
    script += "COMMIT\n";
    return script;
}

std::string build_ppe_deoffload_validation_cleanup_script(
    const PpeDeoffloadGraphSpec& expected,
    const std::string& validation_chain,
    bool complete_graph) {
    if (expected.empty() || validation_chain.empty()) {
        throw std::invalid_argument("invalid empty PPE validation graph");
    }

    std::string script{"*mangle\n"};
    if (complete_graph) {
        const auto rules = expected_chain_rules(expected, validation_chain);
        append_exact_chain_rule_deletions(
            script, rules, validation_chain);
    }
    // Never flush this temporary chain. If anything changed since semantic
    // inspection, an exact -D or the final -X fails and the restore transaction
    // cannot commit, preserving both owned and foreign rules.
    script += keen_pbr3::format("-X {}\nCOMMIT\n", validation_chain);
    return script;
}

bool ppe_deoffload_validation_chain_is_exact(
    const std::string& chain_rules,
    const PpeDeoffloadGraphSpec& expected,
    const std::string& validation_chain) {
    if (expected.empty() || validation_chain.empty()) return false;

    std::vector<std::vector<std::string>> rules;
    bool declaration_seen = false;
    std::istringstream input{chain_rules};
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto tokens = tokenize_iptables_rule(line);
        if (tokens == std::vector<std::string>{"-N", validation_chain}) {
            if (declaration_seen || !rules.empty()) return false;
            declaration_seen = true;
            continue;
        }
        if (!declaration_seen || tokens.size() < 2U ||
            tokens[0] != "-A" || tokens[1] != validation_chain) {
            return false;
        }
        rules.push_back(tokens);
    }
    if (!declaration_seen) return false;

    const std::size_t expected_rule_count = expected.tcp_chunks.size() +
        (expected.quic ? 1U : 0U) + 1U;
    if (rules.size() != expected_rule_count) return false;

    std::size_t position = 0U;
    for (std::size_t index = 0U;
         index < expected.tcp_chunks.size();
         ++index, ++position) {
        const auto& tokens = rules[position];
        if (!only_allowed_rule_tokens(
                tokens, true, false, validation_chain) ||
            option_value(tokens, "--comment") !=
                std::optional<std::string>{tcp_tag(index)} ||
            option_value(tokens, "--dports") !=
                std::optional<std::string>{expected.tcp_chunks[index]}) {
            return false;
        }
    }
    if (expected.quic) {
        const auto& tokens = rules[position++];
        if (!only_allowed_rule_tokens(
                tokens, false, true, validation_chain) ||
            option_value(tokens, "--comment") !=
                std::optional<std::string>{kPpeDeoffloadQuicTag}) {
            return false;
        }
    }
    return exact_return_rule(rules[position], validation_chain);
}

PpeDeoffloadCounters parse_ppe_deoffload_counters(
    const std::string& iptables_save,
    const PpeDeoffloadGraphSpec& expected,
    std::uint64_t observed_at_unix_seconds) {
    PpeDeoffloadCounters counters;
    std::string normalized;
    struct RuleCounter {
        std::string tag;
        std::uint64_t packets{0};
        std::uint64_t bytes{0};
    };
    std::vector<RuleCounter> observed;
    std::istringstream input{iptables_save};
    std::string line;
    while (std::getline(input, line)) {
        std::uint64_t packets = 0;
        std::uint64_t bytes = 0;
        const std::string stripped = strip_counter_prefix(
            line, &packets, &bytes);
        normalized += stripped;
        normalized.push_back('\n');
        const auto tokens = tokenize_iptables_rule(stripped);
        if (tokens.size() >= 2U && tokens[0] == "-A") {
            if (const auto tag = option_value(tokens, "--comment");
                tag.has_value()) {
                observed.push_back(RuleCounter{*tag, packets, bytes});
            }
        }
    }
    const auto graph = inspect_ppe_deoffload_graph(
        normalized, &expected, /*owner_marker_present=*/true);
    if (graph.state != PpeGraphState::exact) return counters;

    for (const auto& rule : observed) {
        if (rule.tag == kPpeDeoffloadPreroutingTag) {
            counters.prerouting_packets += rule.packets;
            counters.prerouting_bytes += rule.bytes;
        } else if (rule.tag == kPpeDeoffloadForwardTag) {
            counters.forward_packets += rule.packets;
            counters.forward_bytes += rule.bytes;
        } else if (rule.tag.rfind(kPpeDeoffloadTcpTagPrefix, 0U) == 0U) {
            counters.tcp_packets += rule.packets;
            counters.tcp_bytes += rule.bytes;
        } else if (rule.tag == kPpeDeoffloadQuicTag) {
            counters.quic_packets += rule.packets;
            counters.quic_bytes += rule.bytes;
        }
    }
    counters.available = true;
    counters.observed_at_unix_seconds = observed_at_unix_seconds;
    return counters;
}

} // namespace keen_pbr3
