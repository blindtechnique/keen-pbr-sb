#include "nfqws_validator.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <map>
#include <sstream>
#include <string_view>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kOwnedWritable =
    "--writable=/var/run/keen-pbr-nfqws";

struct ParsedCandidate {
    std::map<std::string, std::string> values;
    std::vector<ConfigValidationIssue> issues;
};

bool name_start(char ch) {
    const auto value = static_cast<unsigned char>(ch);
    return std::isalpha(value) != 0 || ch == '_';
}

bool name_char(char ch) {
    const auto value = static_cast<unsigned char>(ch);
    return std::isalnum(value) != 0 || ch == '_';
}

bool horizontal_space(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\r';
}

bool supported_assignment(const std::string& name) {
    // nfqws2.conf is sourced by the upstream init script. Keep this list
    // deliberately closed so a candidate cannot smuggle shell/process
    // environment changes (PATH, IFS, LD_PRELOAD, ... ) past the dry run.
    static constexpr std::array<std::string_view, 21> names = {
        "CONFIG_VERSION",    "IPV6_ENABLED",       "ISP_INTERFACE",
        "LOG_DEBUG_PATH",    "LOG_LEVEL",          "MODE_ALL",
        "MODE_AUTO",         "MODE_LIST",          "NFQUEUE_NUM",
        "NFQWS_ARGS",        "NFQWS_ARGS_CUSTOM",  "NFQWS_ARGS_IPSET",
        "NFQWS_ARGS_QUIC",   "NFQWS_ARGS_UDP",     "NFQWS_BASE_ARGS",
        "NFQWS_EXTRA_ARGS",  "POLICY_EXCLUDE",     "POLICY_NAME",
        "TCP_PORTS",         "UDP_PORTS",          "USER",
    };
    return std::find(names.begin(), names.end(), name) != names.end();
}

void skip_line(const std::string& content, std::size_t& index) {
    const auto end = content.find('\n', index);
    index = end == std::string::npos ? content.size() : end + 1;
}

void parser_issue(ParsedCandidate& parsed,
                  const std::string& path,
                  const std::string& message) {
    parsed.issues.push_back({path, message});
}

// Expand one shell parameter reference without consulting the daemon
// environment.  The value map contains assignments that completed earlier in
// the same candidate, matching shell top-to-bottom assignment evaluation.
bool append_expansion(const std::string& content,
                      std::size_t& index,
                      const std::map<std::string, std::string>& values,
                      std::string& output,
                      ParsedCandidate& parsed,
                      const std::string& variable) {
    const std::size_t dollar = index++;
    if (index >= content.size()) {
        output.push_back('$');
        return true;
    }
    if (content[index] == '(' || content[index] == '`') {
        parser_issue(parsed, variable,
                     "command substitution is not allowed in an nfqws candidate");
        return false;
    }

    bool braced = false;
    if (content[index] == '{') {
        braced = true;
        ++index;
    }
    if (index >= content.size() || !name_start(content[index])) {
        output.push_back('$');
        index = dollar + 1;
        return true;
    }

    const std::size_t begin = index;
    while (index < content.size() && name_char(content[index])) ++index;
    const auto name = content.substr(begin, index - begin);
    if (braced) {
        if (index >= content.size() || content[index] != '}') {
            parser_issue(parsed, variable,
                         "only simple ${NAME} expansion is allowed in an nfqws candidate");
            return false;
        }
        ++index;
    }
    const auto found = values.find(name);
    if (found == values.end()) {
        parser_issue(parsed, variable,
                     "undefined variable $" + name +
                         " must not depend on the service environment");
        return false;
    }
    output += found->second;
    return true;
}

ParsedCandidate parse_candidate(const std::string& content) {
    ParsedCandidate parsed;
    std::size_t index = 0;
    while (index < content.size()) {
        while (index < content.size() && horizontal_space(content[index])) ++index;
        if (index >= content.size()) break;
        if (content[index] == '\n') {
            ++index;
            continue;
        }
        if (content[index] == '#') {
            skip_line(content, index);
            continue;
        }

        const std::size_t line_start = index;
        if (!name_start(content[index])) {
            parser_issue(parsed, "nfqws2.conf",
                         "only shell variable assignments and comments are allowed");
            skip_line(content, index);
            continue;
        }
        const std::size_t name_begin = index++;
        while (index < content.size() && name_char(content[index])) ++index;
        const auto name = content.substr(name_begin, index - name_begin);
        if (!supported_assignment(name)) {
            parser_issue(parsed, name,
                         "unsupported assignment in nfqws2.conf");
            skip_line(content, index);
            continue;
        }
        if (index >= content.size() || content[index] != '=') {
            parser_issue(parsed, name,
                         "only NAME=value assignments are allowed");
            skip_line(content, index);
            continue;
        }
        ++index;
        if (index < content.size() && horizontal_space(content[index])) {
            parser_issue(parsed, name,
                         "whitespace after '=' would execute a shell command instead of assigning the value");
            skip_line(content, index);
            continue;
        }

        enum class Quote { none, single, double_quote };
        Quote quote = Quote::none;
        std::string value;
        bool valid = true;
        bool finished = false;
        while (index < content.size() && !finished) {
            const char ch = content[index];
            if (quote == Quote::single) {
                ++index;
                if (ch == '\'') {
                    quote = Quote::none;
                } else {
                    value.push_back(ch);
                }
                continue;
            }
            if (quote == Quote::double_quote) {
                if (ch == '"') {
                    quote = Quote::none;
                    ++index;
                    continue;
                }
                if (ch == '`') {
                    parser_issue(parsed, name,
                                 "command substitution is not allowed in an nfqws candidate");
                    valid = false;
                    ++index;
                    continue;
                }
                if (ch == '$') {
                    if (!append_expansion(content, index, parsed.values, value,
                                          parsed, name)) {
                        valid = false;
                    }
                    continue;
                }
                if (ch == '\\') {
                    ++index;
                    if (index >= content.size()) {
                        value.push_back('\\');
                        break;
                    }
                    const char escaped = content[index++];
                    if (escaped == '\n') continue;
                    if (escaped == '$' || escaped == '`' || escaped == '"' ||
                        escaped == '\\') {
                        value.push_back(escaped);
                    } else {
                        value.push_back('\\');
                        value.push_back(escaped);
                    }
                    continue;
                }
                value.push_back(ch);
                ++index;
                continue;
            }

            if (ch == '\n') {
                ++index;
                finished = true;
                continue;
            }
            if (horizontal_space(ch)) {
                while (index < content.size() && horizontal_space(content[index])) {
                    ++index;
                }
                if (index < content.size() && content[index] != '\n' &&
                    content[index] != '#') {
                    parser_issue(parsed, name,
                                 "unquoted whitespace would execute a shell command");
                    valid = false;
                }
                skip_line(content, index);
                finished = true;
                continue;
            }
            if (ch == '#') {
                // In a shell assignment '#' only starts a comment when it is
                // a new token (handled by the whitespace branch above).
                // In A=foo#bar and A=#bar it is literal data.
                value.push_back(ch);
                ++index;
                continue;
            }
            if (ch == '\'') {
                quote = Quote::single;
                ++index;
                continue;
            }
            if (ch == '"') {
                quote = Quote::double_quote;
                ++index;
                continue;
            }
            if (ch == '$') {
                if (!append_expansion(content, index, parsed.values, value,
                                      parsed, name)) {
                    valid = false;
                }
                continue;
            }
            if (ch == '\\') {
                ++index;
                if (index < content.size() && content[index] == '\n') {
                    ++index;
                } else if (index < content.size()) {
                    value.push_back(content[index++]);
                } else {
                    value.push_back('\\');
                }
                continue;
            }
            if (ch == '`' || ch == ';' || ch == '&' || ch == '|' ||
                ch == '<' || ch == '>' || ch == '(' || ch == ')') {
                parser_issue(parsed, name,
                             "shell commands and control operators are not allowed in an nfqws candidate");
                valid = false;
            }
            value.push_back(ch);
            ++index;
        }

        if (quote != Quote::none) {
            parser_issue(parsed, name, "unterminated quoted assignment");
            valid = false;
        }
        if (valid) parsed.values[name] = std::move(value);

        // A malformed line must still make progress even if it ended at EOF.
        if (index == line_start) ++index;
    }
    return parsed;
}

std::vector<std::string> split_fields(const std::string& value) {
    std::vector<std::string> result;
    std::istringstream input(value);
    std::string field;
    while (input >> field) result.push_back(std::move(field));
    return result;
}

const std::string& value_of(const ParsedCandidate& parsed,
                            const char* name) {
    static const std::string empty;
    const auto found = parsed.values.find(name);
    return found == parsed.values.end() ? empty : found->second;
}

bool is_new_boundary(const std::string& token) {
    return token == "--new" || token.rfind("--new=", 0) == 0;
}

bool contains_new(const std::vector<std::string>& tokens) {
    return std::any_of(tokens.begin(), tokens.end(), is_new_boundary);
}

void validate_port_number(const std::string& variable,
                          const std::string& flag,
                          const std::string& text,
                          std::vector<ConfigValidationIssue>& issues,
                          int& value,
                          bool& valid) {
    if (text.empty()) {
        issues.push_back({variable + "/" + flag, "empty port"});
        valid = false;
        return;
    }
    int parsed = 0;
    const auto converted =
        std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (converted.ec != std::errc{} ||
        converted.ptr != text.data() + text.size()) {
        issues.push_back(
            {variable + "/" + flag, "port '" + text + "' is not a number"});
        valid = false;
        return;
    }
    if (parsed < 1 || parsed > 65535) {
        issues.push_back({variable + "/" + flag,
                          "port " + text + " is out of range 1-65535"});
        valid = false;
        return;
    }
    value = parsed;
    valid = true;
}

void validate_port_spec(const std::string& variable,
                        const std::string& flag,
                        const std::string& spec,
                        std::vector<ConfigValidationIssue>& issues) {
    if (spec.empty()) {
        issues.push_back(
            {variable + "/" + flag, "port filter must not be empty"});
        return;
    }
    std::size_t begin = 0;
    while (begin <= spec.size()) {
        const auto comma = spec.find(',', begin);
        const auto end = comma == std::string::npos ? spec.size() : comma;
        const auto item = spec.substr(begin, end - begin);
        if (item.empty()) {
            issues.push_back(
                {variable + "/" + flag, "port filter contains an empty item"});
        } else {
            const auto dash = item.find('-');
            if (dash == std::string::npos) {
                int port = 0;
                bool valid = false;
                validate_port_number(variable, flag, item, issues, port, valid);
            } else if (item.find('-', dash + 1) != std::string::npos) {
                issues.push_back({variable + "/" + flag,
                                  "port range '" + item + "' is malformed"});
            } else {
                int low = 0;
                int high = 0;
                bool low_valid = false;
                bool high_valid = false;
                validate_port_number(variable, flag, item.substr(0, dash),
                                     issues, low, low_valid);
                validate_port_number(variable, flag, item.substr(dash + 1),
                                     issues, high, high_valid);
                if (low_valid && high_valid && low > high) {
                    issues.push_back({variable + "/" + flag,
                                      "port range " + item +
                                          " is inverted (low > high)"});
                }
            }
        }
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
}

struct PathReference {
    std::string flag;
    std::string path;
    std::string prefix;
};

std::optional<std::string> resolve_input_path(
    const PathReference& reference,
    const NfqwsPathResolver& resolve_path) {
    if (!resolve_path) return std::nullopt;
    if (auto resolved = resolve_path(reference.path)) return resolved;

    // nfqws2 treats a logical foo.lua reference as foo.lua.gz when only the
    // compressed sibling is installed.  Keep the logical path in the dry-run
    // argv so verification exactly mirrors the init-script/runtime argv.
    // Other input types must continue to resolve their exact path.
    if (reference.flag == "--lua-init" && reference.path.size() > 4U &&
        reference.path.compare(reference.path.size() - 4U, 4U, ".lua") == 0 &&
        resolve_path(reference.path + ".gz").has_value()) {
        return reference.path;
    }
    return std::nullopt;
}

std::optional<PathReference> input_path_reference(const std::string& token) {
    const auto direct = [&token](std::string_view flag)
        -> std::optional<PathReference> {
        if (token.rfind(flag, 0) != 0) return std::nullopt;
        return PathReference{std::string(flag.substr(0, flag.size() - 1)),
                             token.substr(flag.size()),
                             std::string(flag)};
    };
    for (const auto flag : {"--hostlist=", "--hostlist-exclude=", "--ipset=",
                            "--ipset-exclude="}) {
        if (auto result = direct(flag)) return result;
    }
    constexpr std::string_view lua = "--lua-init=@";
    if (token.rfind(lua, 0) == 0) {
        return PathReference{"--lua-init", token.substr(lua.size()),
                             std::string(lua)};
    }
    if (token.rfind("--blob=", 0) == 0) {
        const auto separator = token.find(":@");
        if (separator != std::string::npos) {
            return PathReference{"--blob", token.substr(separator + 2),
                                 token.substr(0, separator + 2)};
        }
    }
    return std::nullopt;
}

void validate_token(const std::string& variable,
                    const std::string& token,
                    const NfqwsPathResolver& resolve_path,
                    std::vector<ConfigValidationIssue>& issues) {
    if (token.rfind("--writable", 0) == 0 &&
        (variable != "NFQWS_BASE_ARGS" || token != kOwnedWritable)) {
        issues.push_back(
            {variable + "/--writable",
             "only the package-owned nfqws rotator writable directory is allowed"});
    }
    if (token.rfind("--filter-tcp=", 0) == 0) {
        validate_port_spec(variable, "--filter-tcp",
                           token.substr(std::string("--filter-tcp=").size()),
                           issues);
    } else if (token.rfind("--filter-udp=", 0) == 0) {
        validate_port_spec(variable, "--filter-udp",
                           token.substr(std::string("--filter-udp=").size()),
                           issues);
    }
    if (token.find('$') != std::string::npos) {
        issues.push_back({variable,
                          "literal shell variable reference would reach nfqws2; "
                          "single-quoted values are not expanded"});
    }
    if (token.find_first_of("*?[") != std::string::npos) {
        issues.push_back(
            {variable,
             "shell wildcard is not allowed because the init script would expand it differently from the dry run"});
    }
    const auto reference = input_path_reference(token);
    if (!reference.has_value()) return;
    if (reference->path.empty()) {
        issues.push_back(
            {variable + "/" + reference->flag, "empty file path"});
        return;
    }
    if (resolve_path &&
        !resolve_input_path(*reference, resolve_path).has_value()) {
        issues.push_back({variable + "/" + reference->flag,
                          "referenced file does not exist: " + reference->path});
    }
}

void validate_tokens(const ParsedCandidate& parsed,
                     const std::string& variable,
                     bool forbid_new,
                     const NfqwsPathResolver& resolve_path,
                     std::vector<ConfigValidationIssue>& issues) {
    const auto tokens = split_fields(value_of(parsed, variable.c_str()));
    if (forbid_new && contains_new(tokens)) {
        issues.push_back(
            {variable,
             "--new is not allowed here; use NFQWS_ARGS_CUSTOM for additional profiles"});
    }
    if (variable == "NFQWS_BASE_ARGS" &&
        std::count(tokens.begin(), tokens.end(), kOwnedWritable) > 1) {
        issues.push_back(
            {variable + "/--writable",
             "the package-owned writable directory may be declared only once"});
    }
    for (const auto& token : tokens) {
        validate_token(variable, token, resolve_path, issues);
    }
}

bool is_strategy_action(const std::string& token) {
    return token.rfind("--lua-desync=", 0) == 0 ||
           token.rfind("--dpi-desync=", 0) == 0;
}

bool contains_strategy_action(const std::vector<std::string>& tokens) {
    return std::any_of(tokens.begin(), tokens.end(), is_strategy_action);
}

void validate_custom_boundaries(const std::vector<std::string>& tokens,
                                std::vector<ConfigValidationIssue>& issues) {
    if (tokens.empty()) return;
    if (is_new_boundary(tokens.front()) || is_new_boundary(tokens.back())) {
        issues.push_back({"NFQWS_ARGS_CUSTOM",
                          "--new must separate two non-empty custom profiles"});
    }
    for (std::size_t index = 0; index < tokens.size(); ++index) {
        if (tokens[index] == "--new=") {
            issues.push_back({"NFQWS_ARGS_CUSTOM",
                              "a named --new boundary must have a name"});
        }
        if (index > 0 && is_new_boundary(tokens[index]) &&
            is_new_boundary(tokens[index - 1])) {
            issues.push_back({"NFQWS_ARGS_CUSTOM",
                              "consecutive --new tokens create an empty custom profile"});
            break;
        }
    }
}

void validate_strategy_actions(const ParsedCandidate& parsed,
                               std::vector<ConfigValidationIssue>& issues) {
    bool has_profile = false;
    for (const auto* variable : {"NFQWS_ARGS", "NFQWS_ARGS_QUIC",
                                 "NFQWS_ARGS_UDP"}) {
        const auto tokens = split_fields(value_of(parsed, variable));
        if (tokens.empty()) continue;
        has_profile = true;
        if (!contains_strategy_action(tokens)) {
            issues.push_back(
                {variable,
                 "profile has no supported action (--lua-desync= or --dpi-desync=); filters and selectors alone do not process traffic"});
        }
    }

    const auto custom = split_fields(value_of(parsed, "NFQWS_ARGS_CUSTOM"));
    std::vector<std::string> segment;
    std::string segment_boundary;
    std::size_t segment_number = 1;
    const auto validate_segment = [&] {
        if (segment.empty()) return;
        has_profile = true;
        if (segment_boundary == "--new=webrtc_passthrough") {
            const bool exact =
                segment.size() == 2U &&
                std::count(segment.begin(), segment.end(),
                           "--filter-udp=49152-65535") == 1 &&
                std::count(segment.begin(), segment.end(),
                           "--filter-l7=stun") == 1;
            if (!exact) {
                issues.push_back(
                    {"NFQWS_ARGS_CUSTOM",
                     "webrtc_passthrough must contain exactly --filter-udp=49152-65535 and --filter-l7=stun"});
            }
            return;
        }
        if (!contains_strategy_action(segment)) {
            issues.push_back(
                {"NFQWS_ARGS_CUSTOM",
                 "custom profile " + std::to_string(segment_number) +
                     " has no supported action (--lua-desync= or --dpi-desync=)"});
        }
    };
    for (const auto& token : custom) {
        if (is_new_boundary(token)) {
            validate_segment();
            segment.clear();
            segment_boundary = token;
            ++segment_number;
        } else {
            segment.push_back(token);
        }
    }
    validate_segment();

    if (!has_profile) {
        issues.push_back(
            {"NFQWS_ARGS",
             "the candidate has no strategy profile; IPSET and mode selectors alone do not process traffic"});
    }
}

std::vector<ConfigValidationIssue> validate_parsed_candidate(
    const ParsedCandidate& parsed,
    const NfqwsPathResolver& resolve_path) {
    auto issues = parsed.issues;

    for (const auto* variable : {"NFQWS_BASE_ARGS", "NFQWS_ARGS",
                                 "NFQWS_ARGS_QUIC", "NFQWS_ARGS_UDP",
                                 "NFQWS_ARGS_IPSET", "NFQWS_EXTRA_ARGS",
                                 "MODE_LIST", "MODE_ALL", "MODE_AUTO"}) {
        validate_tokens(parsed, variable, true, resolve_path, issues);
    }
    validate_tokens(parsed, "NFQWS_ARGS_CUSTOM", false, resolve_path, issues);

    const auto custom = split_fields(value_of(parsed, "NFQWS_ARGS_CUSTOM"));
    validate_custom_boundaries(custom, issues);
    validate_strategy_actions(parsed, issues);

    const auto& queue = value_of(parsed, "NFQUEUE_NUM");
    if (!queue.empty()) {
        int number = 0;
        const auto converted =
            std::from_chars(queue.data(), queue.data() + queue.size(), number);
        if (converted.ec != std::errc{} ||
            converted.ptr != queue.data() + queue.size() || number < 0 ||
            number > 65535) {
            issues.push_back(
                {"NFQUEUE_NUM", "queue number must be an integer from 0 to 65535"});
        }
    }

    const auto& user = value_of(parsed, "USER");
    if (!user.empty() &&
        !std::all_of(user.begin(), user.end(), [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '_' || ch == '-' || ch == '.';
        })) {
        issues.push_back({"USER", "nfqws user name contains unsafe characters"});
    }
    return issues;
}

int parsed_queue_number(const ParsedCandidate& parsed, int fallback) {
    const auto& value = value_of(parsed, "NFQUEUE_NUM");
    if (value.empty()) return fallback;
    int queue = fallback;
    const auto converted =
        std::from_chars(value.data(), value.data() + value.size(), queue);
    if (converted.ec != std::errc{} ||
        converted.ptr != value.data() + value.size() || queue < 0 ||
        queue > 65535) {
        return fallback;
    }
    return queue;
}

std::optional<std::vector<NfqwsPpePortRange>> parse_ppe_port_ranges(
    const std::string& spec,
    bool allow_colon) {
    if (spec.empty()) return std::nullopt;

    std::vector<NfqwsPpePortRange> ranges;
    std::size_t begin = 0;
    while (begin <= spec.size()) {
        const auto comma = spec.find(',', begin);
        const auto end = comma == std::string::npos ? spec.size() : comma;
        const auto item = spec.substr(begin, end - begin);
        if (item.empty()) return std::nullopt;

        const auto dash = item.find('-');
        const auto colon = allow_colon ? item.find(':') : std::string::npos;
        if (dash != std::string::npos && colon != std::string::npos)
            return std::nullopt;
        const auto separator =
            dash != std::string::npos ? dash : colon;
        if (separator != std::string::npos &&
            (item.find(item[separator], separator + 1) != std::string::npos ||
             separator == 0 || separator + 1 == item.size())) {
            return std::nullopt;
        }

        const auto parse_port = [](const std::string& text,
                                   std::uint16_t& output) {
            int value = 0;
            const auto converted =
                std::from_chars(text.data(), text.data() + text.size(), value);
            if (converted.ec != std::errc{} ||
                converted.ptr != text.data() + text.size() || value < 1 ||
                value > 65535) {
                return false;
            }
            output = static_cast<std::uint16_t>(value);
            return true;
        };

        NfqwsPpePortRange range;
        if (separator == std::string::npos) {
            if (!parse_port(item, range.first)) return std::nullopt;
            range.last = range.first;
        } else {
            if (!parse_port(item.substr(0, separator), range.first) ||
                !parse_port(item.substr(separator + 1), range.last) ||
                range.first > range.last) {
                return std::nullopt;
            }
        }
        ranges.push_back(range);

        if (comma == std::string::npos) break;
        begin = comma + 1;
    }

    std::sort(ranges.begin(), ranges.end(),
              [](const NfqwsPpePortRange& lhs,
                 const NfqwsPpePortRange& rhs) {
                  return lhs.first != rhs.first ? lhs.first < rhs.first
                                                : lhs.last < rhs.last;
              });
    std::vector<NfqwsPpePortRange> canonical;
    for (const auto& range : ranges) {
        if (canonical.empty() ||
            static_cast<unsigned int>(range.first) >
                static_cast<unsigned int>(canonical.back().last) + 1U) {
            canonical.push_back(range);
        } else if (range.last > canonical.back().last) {
            canonical.back().last = range.last;
        }
    }
    return canonical;
}

void append_canonical_ranges(std::vector<NfqwsPpePortRange>& destination,
                             const std::vector<NfqwsPpePortRange>& source) {
    destination.insert(destination.end(), source.begin(), source.end());
    if (destination.empty()) return;
    std::sort(destination.begin(), destination.end(),
              [](const NfqwsPpePortRange& lhs,
                 const NfqwsPpePortRange& rhs) {
                  return lhs.first != rhs.first ? lhs.first < rhs.first
                                                : lhs.last < rhs.last;
              });
    std::vector<NfqwsPpePortRange> canonical;
    canonical.reserve(destination.size());
    for (const auto& range : destination) {
        if (canonical.empty() ||
            static_cast<unsigned int>(range.first) >
                static_cast<unsigned int>(canonical.back().last) + 1U) {
            canonical.push_back(range);
        } else if (range.last > canonical.back().last) {
            canonical.back().last = range.last;
        }
    }
    destination = std::move(canonical);
}

bool append_tcp_filters(const std::vector<std::string>& tokens,
                        std::vector<NfqwsPpePortRange>& output) {
    bool found = false;
    for (const auto& token : tokens) {
        constexpr std::string_view prefix = "--filter-tcp=";
        if (token.rfind(prefix, 0) != 0) continue;
        const auto parsed = parse_ppe_port_ranges(token.substr(prefix.size()),
                                                  false);
        if (!parsed.has_value()) return false;
        append_canonical_ranges(output, *parsed);
        found = true;
    }
    return found;
}

bool range_set_contains(const std::vector<NfqwsPpePortRange>& ranges,
                        std::uint16_t port) {
    return std::any_of(ranges.begin(), ranges.end(), [port](const auto& range) {
        return range.first <= port && port <= range.last;
    });
}

NfqwsPpePortContract unavailable_ppe_contract(std::string reason,
                                               int queue_number = 300) {
    NfqwsPpePortContract result;
    result.queue_number = queue_number;
    result.reason = std::move(reason);
    return result;
}

std::size_t multiport_slot_cost(const NfqwsPpePortRange& range) {
    return range.first == range.last ? 1U : 2U;
}

std::optional<std::vector<std::vector<NfqwsPpePortRange>>>
chunk_ppe_tcp_ranges(const std::vector<NfqwsPpePortRange>& ranges) {
    std::vector<std::vector<NfqwsPpePortRange>> chunks;
    std::size_t used_slots = 0;
    for (const auto& range : ranges) {
        const auto cost = multiport_slot_cost(range);
        if (chunks.empty() ||
            used_slots + cost > kNfqwsPpeMultiportSlotsPerChunk) {
            if (chunks.size() >= kNfqwsPpeMaxTcpChunks) return std::nullopt;
            chunks.emplace_back();
            used_slots = 0;
        }
        chunks.back().push_back(range);
        used_slots += cost;
    }
    return chunks;
}

std::string rewrite_input_path(const std::string& token,
                               const NfqwsPathResolver& resolve_path) {
    if (!resolve_path) return token;
    const auto reference = input_path_reference(token);
    if (!reference.has_value()) return token;
    const auto resolved = resolve_input_path(*reference, resolve_path);
    if (!resolved.has_value()) return token;
    return reference->prefix + *resolved;
}

void append_tokens(std::vector<std::string>& output,
                   const std::string& value,
                   const NfqwsPathResolver& resolve_path) {
    for (const auto& token : split_fields(value)) {
        // The static validator accepts only this exact package-owned path.
        // nfqws2 initializes --writable even in --dry-run, so forwarding it
        // would let validation chown the live reporter directory before the
        // candidate has been accepted. Lua itself is not initialized by
        // --dry-run, therefore omitting the owned token loses no validation.
        if (token == kOwnedWritable) continue;
        output.push_back(rewrite_input_path(token, resolve_path));
    }
}

} // namespace

std::vector<ConfigValidationIssue> validate_nfqws_candidate(
    const std::string& content,
    const NfqwsPathResolver& resolve_path) {
    return validate_parsed_candidate(parse_candidate(content), resolve_path);
}

NfqwsPpePortContract extract_nfqws_ppe_port_contract(
    const std::string& content,
    const NfqwsPathResolver& resolve_path) {
    const auto parsed = parse_candidate(content);
    const auto issues = validate_parsed_candidate(parsed, resolve_path);
    if (!issues.empty()) {
        const auto& issue = issues.front();
        return unavailable_ppe_contract(
            "candidate validation failed at " + issue.path + ": " +
            issue.message,
            parsed_queue_number(parsed, 300));
    }
    const auto& queue_value = value_of(parsed, "NFQUEUE_NUM");
    if (queue_value.empty()) {
        return unavailable_ppe_contract(
            "NFQUEUE_NUM is missing; the runtime queue cannot be inferred");
    }

    const int queue_number = parsed_queue_number(parsed, 300);
    std::vector<NfqwsPpePortRange> active_tcp;

    const auto collect_action_segment = [&](const std::vector<std::string>& segment,
                                            const std::string& source,
                                            std::string& error) {
        if (!contains_strategy_action(segment)) return true;
        const bool has_tcp = std::any_of(
            segment.begin(), segment.end(), [](const std::string& token) {
                return token.rfind("--filter-tcp=", 0) == 0;
            });
        const bool has_udp = std::any_of(
            segment.begin(), segment.end(), [](const std::string& token) {
                return token.rfind("--filter-udp=", 0) == 0;
            });
        if (!has_tcp && !has_udp) {
            error = source +
                    " has an action without a bounded protocol filter";
            return false;
        }
        if (has_tcp && !append_tcp_filters(segment, active_tcp)) {
            error = source + " has an invalid TCP filter";
            return false;
        }
        return true;
    };

    std::string error;
    const auto main = split_fields(value_of(parsed, "NFQWS_ARGS"));
    if (!main.empty() && !collect_action_segment(main, "NFQWS_ARGS", error)) {
        return unavailable_ppe_contract(std::move(error), queue_number);
    }

    const auto custom = split_fields(value_of(parsed, "NFQWS_ARGS_CUSTOM"));
    std::vector<std::string> segment;
    std::size_t custom_segment = 1;
    const auto collect_custom_segment = [&]() {
        if (segment.empty()) return true;
        return collect_action_segment(
            segment,
            "NFQWS_ARGS_CUSTOM profile " + std::to_string(custom_segment),
            error);
    };
    for (const auto& token : custom) {
        if (is_new_boundary(token)) {
            if (!collect_custom_segment())
                return unavailable_ppe_contract(std::move(error), queue_number);
            segment.clear();
            ++custom_segment;
        } else {
            segment.push_back(token);
        }
    }
    if (!collect_custom_segment())
        return unavailable_ppe_contract(std::move(error), queue_number);

    if (active_tcp.empty()) {
        return unavailable_ppe_contract(
            "active nfqws profiles have no bounded TCP filter", queue_number);
    }

    const auto declared_tcp = parse_ppe_port_ranges(
        value_of(parsed, "TCP_PORTS"), true);
    if (!declared_tcp.has_value()) {
        return unavailable_ppe_contract(
            "TCP_PORTS is missing or invalid", queue_number);
    }
    if (active_tcp != *declared_tcp) {
        return unavailable_ppe_contract(
            "active TCP filters do not exactly match TCP_PORTS", queue_number);
    }

    const auto chunks = chunk_ppe_tcp_ranges(active_tcp);
    if (!chunks.has_value()) {
        return unavailable_ppe_contract(
            "active TCP filters exceed the bounded multiport chunk limit",
            queue_number);
    }

    bool quic_udp_443 = false;
    const auto quic = split_fields(value_of(parsed, "NFQWS_ARGS_QUIC"));
    if (!quic.empty()) {
        std::vector<NfqwsPpePortRange> quic_ports;
        bool has_quic_filter = false;
        bool has_quic_l7 = false;
        for (const auto& token : quic) {
            constexpr std::string_view filter = "--filter-udp=";
            if (token.rfind(filter, 0) == 0) {
                const auto ranges = parse_ppe_port_ranges(
                    token.substr(filter.size()), false);
                if (!ranges.has_value()) {
                    return unavailable_ppe_contract(
                        "NFQWS_ARGS_QUIC has an invalid UDP filter",
                        queue_number);
                }
                append_canonical_ranges(quic_ports, *ranges);
                has_quic_filter = true;
            }
            constexpr std::string_view l7 = "--filter-l7=";
            if (token.rfind(l7, 0) == 0) {
                const auto value = token.substr(l7.size());
                std::size_t begin = 0;
                while (begin <= value.size()) {
                    const auto comma = value.find(',', begin);
                    const auto end = comma == std::string::npos
                                         ? value.size()
                                         : comma;
                    if (value.substr(begin, end - begin) == "quic")
                        has_quic_l7 = true;
                    if (comma == std::string::npos) break;
                    begin = comma + 1;
                }
            }
        }
        if (!contains_strategy_action(quic) || !has_quic_filter ||
            !has_quic_l7 || quic_ports.size() != 1U ||
            quic_ports.front() != NfqwsPpePortRange{443, 443}) {
            return unavailable_ppe_contract(
                "NFQWS_ARGS_QUIC must be an action-bearing exact UDP/443 QUIC profile",
                queue_number);
        }
        const auto declared_udp = parse_ppe_port_ranges(
            value_of(parsed, "UDP_PORTS"), true);
        if (!declared_udp.has_value() ||
            !range_set_contains(*declared_udp, 443)) {
            return unavailable_ppe_contract(
                "UDP_PORTS does not include NFQWS_ARGS_QUIC UDP/443",
                queue_number);
        }
        quic_udp_443 = true;
    }

    NfqwsPpePortContract result;
    result.available = true;
    result.queue_number = queue_number;
    result.tcp_ranges = active_tcp;
    result.tcp_chunks = *chunks;
    result.quic_udp_443 = quic_udp_443;
    return result;
}

NfqwsPpePortContract extract_nfqws_ppe_port_contract_from_argv(
    const std::vector<std::string>& argv) {
    int queue_number = -1;
    std::size_t queue_tokens = 0;
    for (std::size_t index = 0; index < argv.size(); ++index) {
        std::string value;
        if (argv[index].rfind("--qnum=", 0) == 0) {
            value = argv[index].substr(std::string("--qnum=").size());
        } else if (argv[index] == "--qnum" && index + 1U < argv.size()) {
            value = argv[++index];
        } else {
            continue;
        }
        int parsed_queue = -1;
        const auto converted = std::from_chars(
            value.data(), value.data() + value.size(), parsed_queue);
        if (converted.ec != std::errc{} ||
            converted.ptr != value.data() + value.size() || parsed_queue < 0 ||
            parsed_queue > 65535) {
            return unavailable_ppe_contract(
                "live nfqws argv has an invalid --qnum value");
        }
        ++queue_tokens;
        if (queue_number >= 0 && queue_number != parsed_queue) {
            return unavailable_ppe_contract(
                "live nfqws argv has conflicting --qnum values");
        }
        queue_number = parsed_queue;
    }
    if (queue_tokens != 1U || queue_number < 0) {
        return unavailable_ppe_contract(
            "live nfqws argv must contain exactly one --qnum value");
    }

    std::vector<NfqwsPpePortRange> active_tcp;
    bool quic_udp_443 = false;
    std::vector<std::string> segment;
    const auto inspect_segment = [&]() -> std::optional<std::string> {
        if (segment.empty() || !contains_strategy_action(segment))
            return std::nullopt;

        bool has_tcp = false;
        bool has_udp = false;
        bool has_quic_l7 = false;
        std::vector<NfqwsPpePortRange> udp_ranges;
        for (const auto& token : segment) {
            constexpr std::string_view tcp_filter = "--filter-tcp=";
            if (token.rfind(tcp_filter, 0) == 0) has_tcp = true;

            constexpr std::string_view udp_filter = "--filter-udp=";
            if (token.rfind(udp_filter, 0) == 0) {
                const auto parsed = parse_ppe_port_ranges(
                    token.substr(udp_filter.size()), false);
                if (!parsed.has_value())
                    return "live nfqws argv has an invalid UDP filter";
                append_canonical_ranges(udp_ranges, *parsed);
                has_udp = true;
            }

            constexpr std::string_view l7 = "--filter-l7=";
            if (token.rfind(l7, 0) == 0) {
                const auto value = token.substr(l7.size());
                std::size_t begin = 0;
                while (begin <= value.size()) {
                    const auto comma = value.find(',', begin);
                    const auto end = comma == std::string::npos
                                         ? value.size()
                                         : comma;
                    if (value.substr(begin, end - begin) == "quic")
                        has_quic_l7 = true;
                    if (comma == std::string::npos) break;
                    begin = comma + 1;
                }
            }
        }
        if (!has_tcp && !has_udp)
            return "live nfqws argv has an action without a bounded protocol filter";
        if (has_tcp && !append_tcp_filters(segment, active_tcp))
            return "live nfqws argv has an invalid TCP filter";
        if (has_udp && has_quic_l7 && udp_ranges.size() == 1U &&
            udp_ranges.front() == NfqwsPpePortRange{443, 443}) {
            quic_udp_443 = true;
        }
        return std::nullopt;
    };

    for (const auto& token : argv) {
        if (is_new_boundary(token)) {
            if (const auto error = inspect_segment())
                return unavailable_ppe_contract(*error, queue_number);
            segment.clear();
        } else {
            segment.push_back(token);
        }
    }
    if (const auto error = inspect_segment())
        return unavailable_ppe_contract(*error, queue_number);

    if (active_tcp.empty()) {
        return unavailable_ppe_contract(
            "live nfqws argv has no bounded TCP filter", queue_number);
    }
    const auto chunks = chunk_ppe_tcp_ranges(active_tcp);
    if (!chunks.has_value()) {
        return unavailable_ppe_contract(
            "live nfqws argv exceeds the bounded multiport chunk limit",
            queue_number);
    }

    NfqwsPpePortContract result;
    result.available = true;
    result.queue_number = queue_number;
    result.tcp_ranges = active_tcp;
    result.tcp_chunks = *chunks;
    result.quic_udp_443 = quic_udp_443;
    return result;
}

std::vector<std::string> build_nfqws_dry_run_args(
    const std::string& content,
    int fallback_queue_number,
    const NfqwsPathResolver& resolve_path) {
    const auto parsed = parse_candidate(content);
    std::vector<std::string> args;
    args.push_back("--dry-run");

    if (value_of(parsed, "LOG_LEVEL") == "1") {
        const auto& destination = value_of(parsed, "LOG_DEBUG_PATH");
        args.push_back("--debug=" +
                       (destination.empty() ? std::string("syslog") : destination));
    }
    const auto& user = value_of(parsed, "USER");
    args.push_back("--user=" + (user.empty() ? std::string("nobody") : user));
    args.push_back("--qnum=" +
                   std::to_string(parsed_queue_number(parsed, fallback_queue_number)));
    append_tokens(args, value_of(parsed, "NFQWS_BASE_ARGS"), resolve_path);

    if (split_fields(value_of(parsed, "ISP_INTERFACE")).size() > 1U) {
        args.push_back("--bind-fix4");
        const auto& ipv6 = value_of(parsed, "IPV6_ENABLED");
        if (!ipv6.empty() && ipv6 != "0") args.push_back("--bind-fix6");
    }

    const auto append_profile = [&](const std::string& value) {
        if (split_fields(value).empty()) return;
        append_tokens(args, value, resolve_path);
        args.push_back("--new");
    };
    append_profile(value_of(parsed, "NFQWS_ARGS_CUSTOM"));
    append_profile(value_of(parsed, "NFQWS_ARGS_UDP"));

    const auto& quic = value_of(parsed, "NFQWS_ARGS_QUIC");
    const auto& main = value_of(parsed, "NFQWS_ARGS");
    const auto& ipset = value_of(parsed, "NFQWS_ARGS_IPSET");
    const auto& extra = value_of(parsed, "NFQWS_EXTRA_ARGS");
    if (!split_fields(quic).empty()) {
        if (!split_fields(ipset).empty()) {
            append_tokens(args, quic, resolve_path);
            append_tokens(args, ipset, resolve_path);
            args.push_back("--ipset-ip=0.0.0.0");
            args.push_back("--new");
        }
        append_tokens(args, quic, resolve_path);
        append_tokens(args, extra, resolve_path);
        args.push_back("--new");
    }
    if (!split_fields(ipset).empty()) {
        append_tokens(args, main, resolve_path);
        append_tokens(args, ipset, resolve_path);
        args.push_back("--ipset-ip=0.0.0.0");
        args.push_back("--new");
    }
    append_tokens(args, main, resolve_path);
    append_tokens(args, extra, resolve_path);
    return args;
}

bool NfqwsBinaryIdentity::operator==(
    const NfqwsBinaryIdentity& other) const noexcept {
    return device == other.device && inode == other.inode && size == other.size &&
           mtime_seconds == other.mtime_seconds &&
           mtime_nanoseconds == other.mtime_nanoseconds &&
           ctime_seconds == other.ctime_seconds &&
           ctime_nanoseconds == other.ctime_nanoseconds;
}

NfqwsDryRunCapability NfqwsDryRunCapabilityCache::detect(
    const std::string& binary,
    const NfqwsBinaryIdentityReader& read_identity,
    const NfqwsHelpProbe& probe_help) {
    if (!read_identity || !probe_help) return NfqwsDryRunCapability::unavailable;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto before = read_identity(binary);
        if (!before.has_value()) return NfqwsDryRunCapability::unavailable;
        {
            const std::lock_guard lock(mutex_);
            if (identity_.has_value() && binary_ == binary &&
                *identity_ == *before) {
                return capability_;
            }
        }

        const auto help = probe_help(binary);
        if (!help.has_value()) return NfqwsDryRunCapability::unavailable;
        const auto after = read_identity(binary);
        if (!after.has_value() || *after != *before) continue;

        const auto detected = help->find("--dry-run") != std::string::npos
                                  ? NfqwsDryRunCapability::supported
                                  : NfqwsDryRunCapability::unsupported;
        const std::lock_guard lock(mutex_);
        binary_ = binary;
        identity_ = after;
        capability_ = detected;
        return detected;
    }
    return NfqwsDryRunCapability::unavailable;
}

} // namespace keen_pbr3
