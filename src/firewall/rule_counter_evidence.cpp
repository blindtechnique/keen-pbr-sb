#include "rule_counter_evidence.hpp"
#include "iptables_verifier.hpp"
#include "nftables_verifier.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace keen_pbr3 {
namespace {

using Clock = std::chrono::steady_clock;
constexpr std::size_t max_capture = 256U * 1024U;
constexpr std::size_t max_rows = 4096U;
constexpr std::size_t response_limit = 32U;

struct CounterRow {
    FirewallClassifierCounter counter;
    bool complete{false};
    std::vector<std::size_t> owners;
};

struct CounterSnapshot {
    bool available{false};
    std::int64_t snapshot_at{0};
    std::vector<CounterRow> rows;
};

void check_deadline(Clock::time_point deadline) {
    if (Clock::now() >= deadline) throw std::runtime_error("counter read deadline");
}

void check_expected_size(const std::vector<RuleState>& rules,
                         Clock::time_point deadline) {
    std::size_t total = 0;
    for (const auto& rule : rules) {
        check_deadline(deadline);
        if (rule.action_type == RuleActionType::Skip ||
            (rule.set_names.empty() &&
             (!rule.list_names.empty() || !rule.criteria.has_rule_selector()))) continue;
        std::size_t count = rule.set_names.empty() ? 2U : rule.set_names.size();
        for (const auto factor : {
                 std::max<std::size_t>(1U, rule.criteria.src_addr.size()),
                 std::max<std::size_t>(1U, rule.criteria.dst_addr.size()), std::size_t{2}}) {
            if (count > max_rows / factor) throw std::runtime_error("counter expansion limit");
            count *= factor;
        }
        if (count > max_rows - total) throw std::runtime_error("counter expansion limit");
        total += count;
    }
}

std::int64_t unix_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::vector<std::string> words(const std::string& line) {
    std::istringstream input(line);
    std::vector<std::string> result;
    std::string token;
    while (input >> token) result.push_back(std::move(token));
    return result;
}

bool decimal_u64(std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

bool token_u32(std::string_view text, std::uint32_t& value) {
    if (text.empty() || text.front() == '-' || text.front() == '+') return false;
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    } else if (text.size() > 1 && text.front() == '0') {
        base = 8;
    }
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        number > std::numeric_limits<std::uint32_t>::max()) return false;
    value = static_cast<std::uint32_t>(number);
    return true;
}

bool json_u64(const nlohmann::json& value, std::uint64_t& output) {
    if (value.is_number_unsigned()) {
        output = value.get<std::uint64_t>();
        return true;
    }
    if (value.is_number_integer() && value.get<std::int64_t>() >= 0) {
        output = static_cast<std::uint64_t>(value.get<std::int64_t>());
        return true;
    }
    return false;
}

bool json_u32(const nlohmann::json& value, std::uint32_t& output) {
    std::uint64_t parsed = 0;
    if (!json_u64(value, parsed) || parsed > std::numeric_limits<std::uint32_t>::max()) return false;
    output = static_cast<std::uint32_t>(parsed);
    return true;
}

// Preserve the complete rule text for the existing selector parser. No command
// string is evaluated by a shell; these tokens come only from captured stdout.
struct SavedRule {
    std::string line, chain;
    std::size_t position{0};
    std::uint64_t packets{0}, bytes{0};
    bool counters_present{false};
};

bool strip_save_counters(std::string& line, std::uint64_t& packets,
                         std::uint64_t& bytes) {
    if (line.empty() || line.front() != '[') return false;
    const auto end = line.find(']');
    const auto colon = line.find(':');
    if (end == std::string::npos || colon == std::string::npos || colon >= end) return false;
    const bool valid = decimal_u64(std::string_view(line).substr(1, colon - 1), packets) &&
        decimal_u64(std::string_view(line).substr(colon + 1, end - colon - 1), bytes);
    line.erase(0, end + 1);
    const auto start = line.find_first_not_of(" \t");
    line = start == std::string::npos ? "" : line.substr(start);
    return valid;
}

bool iptables_identity_complete(const std::vector<std::string>& tokens) {
    if (tokens.size() < 4 || tokens[0] != "-A") return false;
    bool negated = false, action_seen = false;
    std::set<std::string> seen;
    for (std::size_t i = 2; i < tokens.size(); ++i) {
        const auto& token = tokens[i];
        if (token == "!") {
            if (negated) return false;
            negated = true;
            continue;
        }
        if (token == "-m") {
            if (negated || ++i == tokens.size()) return false;
            const auto& module = tokens[i];
            if (module != "set" && module != "tcp" && module != "udp" &&
                module != "multiport" && module != "dscp") return false;
            continue;
        }
        if (token == "--match-set") {
            if (negated || i + 2 >= tokens.size() || tokens[i + 2] != "dst" ||
                !seen.insert("set").second) return false;
            i += 2;
        } else if (token == "-s" || token == "-d" ||
                   token == "--sport" || token == "--sports" ||
                   token == "--dport" || token == "--dports" ||
                   token == "--dscp" || token == "-p" || token == "-i") {
            std::string key = token;
            if (token == "--sports") key = "--sport";
            if (token == "--dports") key = "--dport";
            if (!seen.insert(key).second || i + 1 >= tokens.size()) return false;
            if (negated && (token == "-p" || token == "-i" || token == "--dscp")) return false;
            if (token == "-p" && tokens[i + 1] != "tcp" && tokens[i + 1] != "udp" &&
                tokens[i + 1] != "all" && tokens[i + 1] != "0") return false;
            if (token == "--dscp") {
                std::uint32_t value = 0;
                if (!token_u32(tokens[i + 1], value) || value > 63) return false;
            }
            ++i;
        } else if (token == "-j") {
            if (negated || action_seen || i + 1 >= tokens.size()) return false;
            action_seen = true;
            const auto& action = tokens[++i];
            if (action == "MARK") {
                if (i + 2 >= tokens.size() ||
                    (tokens[i + 1] != "--set-mark" && tokens[i + 1] != "--set-xmark")) return false;
                const std::string_view value = tokens[i + 2];
                const auto slash = value.find('/');
                std::uint32_t mark = 0, mask = 0;
                if (tokens[i + 1] == "--set-mark") {
                    if (!token_u32(value, mark)) return false;
                } else if (slash == std::string_view::npos ||
                           !token_u32(value.substr(0, slash), mark) ||
                           !token_u32(value.substr(slash + 1), mask)) return false;
                i += 2;
            } else if (action != "DROP" && action != "RETURN") {
                return false;
            }
            if (i + 1 != tokens.size()) return false;
        } else {
            return false;
        }
        negated = false;
    }
    return action_seen && !negated;
}

CounterSnapshot parse_iptables_snapshot(const std::string& output, int family,
    const std::string& table, const std::vector<RuleState>& realized,
    std::uint32_t mark_mask, Clock::time_point deadline) {
    CounterSnapshot snapshot;
    const std::string root = table == "raw" ? "KeenPbrRaw" : "KeenPbrTable";
    std::vector<SavedRule> saved;
    std::map<std::string, std::size_t> positions;
    std::set<std::string> chains;
    std::istringstream input(output);
    std::string line;
    bool in_table = false, committed = false;
    while (std::getline(input, line)) {
        check_deadline(deadline);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.front() == '#') continue;
        if (line.front() == '*') {
            if (in_table || committed || line != "*" + table) throw std::runtime_error("counter table shape");
            in_table = true;
            continue;
        }
        if (line == "COMMIT") {
            if (!in_table || committed) throw std::runtime_error("counter table completion");
            committed = true;
            in_table = false;
            continue;
        }
        if (!in_table) throw std::runtime_error("counter data outside table");
        if (line.front() == ':') {
            const auto end = line.find(' ');
            chains.insert(line.substr(1, end == std::string::npos ? end : end - 1));
            continue;
        }
        SavedRule row;
        row.counters_present = strip_save_counters(line, row.packets, row.bytes);
        const auto tokens = words(line);
        if (tokens.size() < 2 || tokens[0] != "-A") throw std::runtime_error("counter rule shape");
        row.line = std::move(line);
        row.chain = tokens[1];
        row.position = ++positions[row.chain];
        saved.push_back(std::move(row));
        if (saved.size() > max_rows) throw std::runtime_error("counter rule limit");
    }
    if (!committed || in_table) throw std::runtime_error("incomplete counter dump");
    if (!chains.count(root)) return snapshot;

    std::optional<std::string> active_child;
    for (const auto& row : saved) {
        if (row.chain != root) continue;
        const auto tokens = words(row.line);
        if (tokens.size() == 4 && tokens[2] == "-j" &&
            (tokens[3] == root + "_A" || tokens[3] == root + "_B")) {
            if (active_child) throw std::runtime_error("ambiguous counter dispatcher");
            active_child = tokens[3];
        }
    }
    if (active_child && !chains.count(*active_child)) throw std::runtime_error("counter generation missing");

    std::vector<ParsedIptablesRule> parsed;
    std::map<std::string, std::string> preceding_mark;
    for (const auto& row : saved) {
        check_deadline(deadline);
        if (row.chain != root && (!active_child || row.chain != *active_child)) continue;
        const auto target = row.line.find(" -j ");
        if (target == std::string::npos) continue;
        const auto shape = row.line.substr(0, target);
        const auto target_tokens = words(row.line.substr(target + 4));
        if (target_tokens.empty()) continue;
        const auto& action = target_tokens[0];
        const bool mark_tail = preceding_mark[row.chain] == shape;
        if (action == "CONNMARK" && mark_tail) continue;
        if (action == "RETURN" && mark_tail) {
            preceding_mark[row.chain].clear();
            continue;
        }
        preceding_mark[row.chain] = action == "MARK" ? shape : "";
        if (action != "MARK" && action != "DROP" && action != "RETURN") continue;
        const auto first_space = row.line.find(' ', 3);
        if (first_space == std::string::npos) continue;
        const auto normalized = "-A KeenPbrTable" + row.line.substr(first_space);
        auto state = parse_iptables_s(normalized);
        if (state.rules.size() != 1) continue;
        auto rule = std::move(state.rules[0]);
        rule.ipv6 = family == AF_INET6;
        CounterRow counter;
        counter.counter.family = family;
        counter.counter.table = table;
        counter.counter.chain = row.chain;
        counter.counter.position = row.position;
        counter.counter.action = rule.is_mark ? "mark" : rule.is_drop ? "drop" : "pass";
        counter.counter.set_name = rule.set_name;
        if (rule.is_mark) {
            counter.counter.fwmark = rule.fwmark;
            counter.counter.fwmask = rule.xmark_mask;
        }
        counter.counter.packets = row.packets;
        counter.counter.bytes = row.bytes;
        counter.complete = row.counters_present && iptables_identity_complete(words(row.line));
        parsed.push_back(std::move(rule));
        snapshot.rows.push_back(std::move(counter));
    }
    const auto matches = match_iptables_counter_rules(parsed, realized, mark_mask, deadline);
    check_deadline(deadline);
    for (std::size_t i = 0; i < matches.size(); ++i) snapshot.rows[i].owners = matches[i];
    snapshot.available = true;
    return snapshot;
}

bool is_mark_key(const nlohmann::json& key, const char* kind) {
    return key.is_object() && key.size() == 1 && key.contains(kind) &&
        key[kind].is_object() && key[kind].size() == 1 && key[kind].value("key", "") == "mark";
}

// Recognize the production meta-mark assignment, including nft's harmless
// canonicalization of set bits inside the AND operand. Do not report the
// application mask as observed unless this semantic equivalence is established.
bool nft_mark_assignment(const nlohmann::json& value, std::uint32_t expected_mask,
                         std::uint32_t& mark) {
    if (json_u32(value, mark)) return expected_mask == 0xffffffffU;
    if (!value.is_object() || value.size() != 1 || !value.contains("|") ||
        !value["|"].is_array() || value["|"].size() != 2) return false;
    const auto& args = value["|"];
    const nlohmann::json* and_expr = &args[0];
    if (!json_u32(args[1], mark)) {
        if (!json_u32(args[0], mark)) return false;
        and_expr = &args[1];
    }
    if (!and_expr->is_object() || and_expr->size() != 1 || !and_expr->contains("&") ||
        !(*and_expr)["&"].is_array() || (*and_expr)["&"].size() != 2) return false;
    const auto& terms = (*and_expr)["&"];
    std::uint32_t keep = 0;
    if (!((is_mark_key(terms[0], "meta") && json_u32(terms[1], keep)) ||
          (is_mark_key(terms[1], "meta") && json_u32(terms[0], keep)))) return false;
    return (keep | mark) == (~expected_mask | mark);
}

bool nft_address_complete(const nlohmann::json& value, int family) {
    const auto one = [family](const nlohmann::json& item) {
        std::string address;
        std::optional<std::uint64_t> prefix;
        if (item.is_string()) {
            address = item.get<std::string>();
            const auto slash = address.find('/');
            if (slash != std::string::npos) {
                std::uint64_t length = 0;
                if (!decimal_u64(std::string_view(address).substr(slash + 1), length)) return false;
                prefix = length;
                address.resize(slash);
            }
        } else if (item.is_object() && item.size() == 1 && item.contains("prefix") &&
                   item["prefix"].is_object() && item["prefix"].size() == 2 &&
                   item["prefix"].contains("addr") && item["prefix"]["addr"].is_string() &&
                   item["prefix"].contains("len")) {
            address = item["prefix"]["addr"].get<std::string>();
            std::uint64_t length = 0;
            if (!json_u64(item["prefix"]["len"], length)) return false;
            prefix = length;
        } else return false;
        if (address.find('\0') != std::string::npos ||
            (prefix && *prefix > (family == AF_INET6 ? 128U : 32U))) return false;
        std::array<unsigned char, 16> parsed{};
        return ::inet_pton(family, address.c_str(), parsed.data()) == 1;
    };
    if (value.is_object() && value.size() == 1 && value.contains("set")) {
        if (!value["set"].is_array() || value["set"].empty()) return false;
        return std::all_of(value["set"].begin(), value["set"].end(), one);
    }
    return one(value);
}

bool nft_port_complete(const nlohmann::json& value, unsigned depth = 0) {
    std::uint64_t number = 0;
    if (json_u64(value, number)) return number <= 65535U;
    if (!value.is_object() || value.size() != 1 || depth > 1) return false;
    if (value.contains("range") && value["range"].is_array() && value["range"].size() == 2) {
        std::uint64_t first = 0, last = 0;
        return json_u64(value["range"][0], first) && json_u64(value["range"][1], last) &&
            first <= last && last <= 65535U;
    }
    if (value.contains("set") && value["set"].is_array() && !value["set"].empty()) {
        return std::all_of(value["set"].begin(), value["set"].end(),
            [depth](const nlohmann::json& item) { return nft_port_complete(item, depth + 1); });
    }
    return false;
}

bool nft_match_complete(const nlohmann::json& match) {
    if (!match.is_object() || !match.contains("left") || !match.contains("right")) return false;
    const auto op = match.value("op", "==");
    if (op != "==" && op != "!=") return false;
    const auto& left = match["left"];
    if (!left.is_object() || left.size() != 1) return false;
    if (left.contains("meta")) {
        const auto& meta = left["meta"];
        if (!meta.is_object() || meta.size() != 1 || op != "==") return false;
        const auto key = meta.value("key", "");
        if (key == "nfproto") return match["right"] == "ipv4" || match["right"] == "ipv6" ||
            match["right"] == AF_INET || match["right"] == AF_INET6;
        if (key == "l4proto") return match["right"] == "tcp" || match["right"] == "udp";
        // Generated global ingress expansion is a known extra restriction. Its
        // count still belongs to this physical classifier, not one client.
        if (key != "iifname") return false;
        if (match["right"].is_string()) return !match["right"].get<std::string>().empty();
        if (!match["right"].is_object() || match["right"].size() != 1 ||
            !match["right"].contains("set") || !match["right"]["set"].is_array()) return false;
        return std::all_of(match["right"]["set"].begin(), match["right"]["set"].end(),
            [](const nlohmann::json& name) { return name.is_string() && !name.get<std::string>().empty(); });
    }
    if (!left.contains("payload") || !left["payload"].is_object()) return false;
    const auto& payload = left["payload"];
    if (payload.size() != 2) return false;
    const auto protocol = payload.value("protocol", "");
    const auto field = payload.value("field", "");
    if (protocol == "ip" || protocol == "ip6") {
        if (field == "dscp") return op == "==" && !match["right"].is_null();
        if (field != "saddr" && field != "daddr") return false;
        if (match["right"].is_string() && match["right"].get<std::string>().rfind("@", 0) == 0) {
            return field == "daddr" && op == "==";
        }
        if (match["right"].is_object() && match["right"].contains("set") &&
            match["right"]["set"].is_string()) return field == "daddr" && op == "==";
        return nft_address_complete(match["right"], protocol == "ip6" ? AF_INET6 : AF_INET);
    }
    return (protocol == "tcp" || protocol == "udp" || protocol == "th") &&
        (field == "sport" || field == "dport") && nft_port_complete(match["right"]);
}

CounterSnapshot parse_nft_snapshot(const std::string& output,
    const std::vector<RuleState>& realized, std::uint32_t mark_mask,
    Clock::time_point deadline) {
    CounterSnapshot snapshot;
    const auto document = nlohmann::json::parse(output);
    if (!document.is_object() || !document.contains("nftables") ||
        !document["nftables"].is_array()) throw std::runtime_error("invalid nft counter inventory");
    std::vector<ParsedNftRule> parsed;
    std::size_t position = 0, seen_rules = 0;
    bool chain_present = false;
    for (const auto& element : document["nftables"]) {
        check_deadline(deadline);
        if (!element.is_object()) throw std::runtime_error("invalid nft counter entry");
        if (element.contains("chain")) {
            const auto& chain = element["chain"];
            if (chain.is_object() && chain.value("family", "") == "inet" &&
                chain.value("table", "") == "KeenPbrTable" &&
                chain.value("name", "") == "prerouting") chain_present = true;
        }
        if (!element.contains("rule")) continue;
        if (++seen_rules > max_rows) throw std::runtime_error("nft counter rule limit");
        const auto& original = element["rule"];
        if (!original.is_object() || original.value("family", "") != "inet" ||
            original.value("table", "") != "KeenPbrTable" ||
            original.value("chain", "") != "prerouting") continue;
        ++position;
        if (!original.contains("expr") || !original["expr"].is_array()) throw std::runtime_error("nft counter expression missing");
        auto state = parse_nft_json(nlohmann::json{{"nftables", nlohmann::json::array({element})}}.dump());
        if (state.rules.size() != 1) continue;
        auto rule = std::move(state.rules[0]);
        if (rule.is_mark || rule.is_drop) rule.is_pass = false;
        CounterRow row;
        row.counter.family = rule.criteria.family;
        row.counter.table = "KeenPbrTable";
        row.counter.chain = "prerouting";
        row.counter.position = position;
        row.counter.action = rule.is_mark ? "mark" : rule.is_drop ? "drop" : "pass";
        row.counter.set_name = rule.set_name;
        if (rule.is_mark) row.counter.fwmark = rule.fwmark;
        bool complete = true, counted = false, action_seen = false, terminal_seen = false;
        std::set<std::string> selectors;
        for (const auto& expression : original["expr"]) {
            if (!expression.is_object() || expression.size() != 1 || terminal_seen) {
                complete = false;
                continue;
            }
            if (expression.contains("match")) {
                complete = complete && !counted && !action_seen && nft_match_complete(expression["match"]);
                const auto& match = expression["match"];
                if (match.is_object() && match.contains("left") &&
                    match["left"].is_object() && match["left"].contains("payload") &&
                    match["left"]["payload"].is_object()) {
                    const auto field = match["left"]["payload"].value("field", "");
                    const auto protocol = match["left"]["payload"].value("protocol", "");
                    const auto& right = match["right"];
                    const bool named_set = (right.is_string() && right.get<std::string>().rfind("@", 0) == 0) ||
                        (right.is_object() && right.contains("set") && right["set"].is_string());
                    if (!selectors.insert("payload:" + field + (named_set ? ":set" : ":value")).second) complete = false;
                    if ((protocol == "ip" && rule.criteria.family != AF_INET) ||
                        (protocol == "ip6" && rule.criteria.family != AF_INET6) ||
                        (protocol == "tcp" && rule.criteria.proto != L4Proto::Tcp) ||
                        (protocol == "udp" && rule.criteria.proto != L4Proto::Udp)) complete = false;
                    if (field == "dscp" && !rule.criteria.dscp) complete = false;
                    if (field == "saddr" && rule.criteria.src_addr.empty()) complete = false;
                    if (field == "daddr" && rule.criteria.dst_addr.empty() && rule.set_name.empty()) complete = false;
                    if (field == "sport" && rule.criteria.src_port.empty()) complete = false;
                    if (field == "dport" && rule.criteria.dst_port.empty()) complete = false;
                } else if (match.is_object() && match.contains("left") &&
                           match["left"].is_object() && match["left"].contains("meta") &&
                           match["left"]["meta"].is_object()) {
                    const auto key = match["left"]["meta"].value("key", "");
                    if (!selectors.insert("meta:" + key).second) complete = false;
                    if (key == "l4proto" && ((match["right"] == "tcp" && rule.criteria.proto != L4Proto::Tcp) ||
                        (match["right"] == "udp" && rule.criteria.proto != L4Proto::Udp))) complete = false;
                    if (key == "nfproto" && ((match["right"] == "ipv4" && rule.criteria.family != AF_INET) ||
                        (match["right"] == "ipv6" && rule.criteria.family != AF_INET6))) complete = false;
                }
            } else if (expression.contains("counter")) {
                const auto& counter = expression["counter"];
                complete = complete && !counted && !action_seen && counter.is_object() && counter.size() == 2 &&
                    counter.contains("packets") && counter.contains("bytes") &&
                    json_u64(counter["packets"], row.counter.packets) &&
                    json_u64(counter["bytes"], row.counter.bytes);
                counted = true;
            } else if (expression.contains("mangle")) {
                const auto& mangle = expression["mangle"];
                if (!mangle.is_object() || !mangle.contains("key") || !mangle.contains("value")) {
                    complete = false;
                } else if (is_mark_key(mangle["key"], "meta")) {
                    std::uint32_t mark = 0;
                    const bool equivalent = !action_seen && counted &&
                        nft_mark_assignment(mangle["value"], mark_mask, mark) && mark == rule.fwmark;
                    complete = complete && equivalent;
                    if (equivalent) row.counter.fwmask = mark_mask;
                    action_seen = true;
                } else if (!is_mark_key(mangle["key"], "ct")) {
                    complete = false;
                }
            } else if (expression.contains("accept") || expression.contains("return") || expression.contains("drop")) {
                complete = complete && counted;
                if (rule.is_mark && !expression.contains("accept")) complete = false;
                if (rule.is_drop && !expression.contains("drop")) complete = false;
                terminal_seen = true;
            } else {
                complete = false;
            }
        }
        row.complete = complete && counted && terminal_seen &&
            (row.counter.family == AF_INET || row.counter.family == AF_INET6);
        parsed.push_back(std::move(rule));
        snapshot.rows.push_back(std::move(row));
    }
    if (!chain_present) return snapshot;
    const auto matches = match_nft_counter_rules(parsed, realized, deadline);
    check_deadline(deadline);
    for (std::size_t i = 0; i < matches.size(); ++i) snapshot.rows[i].owners = matches[i];
    snapshot.available = true;
    return snapshot;
}

} // namespace

std::vector<FirewallClassifierEvidence> collect_firewall_counter_evidence(
    FirewallBackend backend, RawPreroutingMode raw_prerouting,
    const std::vector<RuleState>& realized_rules,
    const std::vector<FirewallClassifierQuery>& queries,
    std::uint32_t fwmark_mask, std::optional<Clock::time_point> deadline,
    CommandRunner runner) {
    const auto stop = std::min(deadline.value_or(Clock::time_point::max()),
        Clock::now() + std::chrono::seconds(2));
    std::vector<FirewallClassifierEvidence> result(queries.size());
    std::map<std::pair<int, std::string>, CounterSnapshot> snapshots;
    for (std::size_t index = 0; index < queries.size(); ++index) {
        const auto& query = queries[index];
        if (query.family != AF_INET && query.family != AF_INET6) continue;
        const auto captured = std::find_if(realized_rules.begin(), realized_rules.end(),
            [&](const RuleState& rule) { return rule.rule_index == query.rule_index; });
        if (captured == realized_rules.end()) {
            result[index].status = FirewallCounterStatus::Unavailable;
            continue;
        }
        if (captured->action_type == RuleActionType::Skip) continue;
        auto& evidence = result[index];
        evidence.status = FirewallCounterStatus::Unavailable;
        const std::string table = backend == FirewallBackend::nftables ? "KeenPbrTable" :
            ((query.family == AF_INET6 ? raw_prerouting.ipv6 : raw_prerouting.ipv4) ? "raw" : "mangle");
        const auto key = std::make_pair(backend == FirewallBackend::nftables ? AF_UNSPEC : query.family, table);
        auto inserted = snapshots.emplace(key, CounterSnapshot{});
        auto& snapshot = inserted.first->second;
        if (inserted.second) {
            snapshot.snapshot_at = unix_seconds();
            try {
                check_deadline(stop);
                check_expected_size(realized_rules, stop);
                const std::vector<std::string> args = backend == FirewallBackend::nftables
                    ? std::vector<std::string>{"nft", "-j", "list", "chain", "inet", "KeenPbrTable", "prerouting"}
                    : std::vector<std::string>{query.family == AF_INET6 ? "ip6tables-save" : "iptables-save", "-c", "-t", table};
                CommandResult output;
                if (runner) {
                    output = runner(args);
                } else {
                    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(stop - Clock::now());
                    const auto cleanup = std::chrono::milliseconds(100);
                    if (remaining <= cleanup) throw std::runtime_error("counter deadline before command");
                    const auto captured_output = safe_exec_capture(args, true, max_capture, false,
                        false, SafeExecFailureLog::Suppressed, SafeExecTimeouts{remaining - cleanup, cleanup});
                    output = {captured_output.stdout_output, captured_output.exit_code,
                        captured_output.truncated || captured_output.timed_out || captured_output.termination_uncertain};
                }
                check_deadline(stop);
                if (output.exit_code != 0 || output.truncated || output.stdout_output.size() > max_capture) {
                    throw std::runtime_error("incomplete firewall counter read");
                }
                auto parsed = backend == FirewallBackend::nftables
                    ? parse_nft_snapshot(output.stdout_output, realized_rules, fwmark_mask, stop)
                    : parse_iptables_snapshot(output.stdout_output, query.family, table, realized_rules, fwmark_mask, stop);
                parsed.snapshot_at = snapshot.snapshot_at;
                snapshot = std::move(parsed);
            } catch (...) {
                snapshot.available = false;
                snapshot.rows.clear();
            }
        }
        evidence.snapshot_at = snapshot.snapshot_at;
        if (!snapshot.available) continue;
        bool ambiguous = false;
        for (const auto& row : snapshot.rows) {
            if (row.counter.family != AF_UNSPEC && row.counter.family != query.family) continue;
            if (std::find(row.owners.begin(), row.owners.end(), query.rule_index) == row.owners.end()) continue;
            if (!row.complete || row.owners.size() != 1) {
                ambiguous = true;
                continue;
            }
            ++evidence.total;
            if (evidence.rules.size() < response_limit) evidence.rules.push_back(row.counter);
        }
        if (ambiguous) {
            evidence.status = FirewallCounterStatus::Ambiguous;
            evidence.rules.clear();
            evidence.total = 0;
        } else if (evidence.total != 0) {
            evidence.status = FirewallCounterStatus::Observed;
            evidence.truncated = evidence.total > response_limit;
        }
    }
    return result;
}

} // namespace keen_pbr3
