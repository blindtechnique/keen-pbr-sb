#include "nfqws_config.hpp"

#include <sstream>

namespace keen_pbr3 {
namespace {

constexpr const char* kRotatorWritablePrefix =
    "NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws ";
constexpr const char* kBaseArgsPrefix = "NFQWS_BASE_ARGS=\"";
constexpr const char* kRotatorReporterLine =
    "\n                 --lua-init=@/opt/var/lib/keen-pbr/"
    "nfqws-rotator-telemetry-v1.lua";

std::string trim_copy(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r");
    return value.substr(begin, end - begin + 1);
}

bool assignment_line(const std::string& line, const std::string& key) {
    const auto trimmed = trim_copy(line);
    if (trimmed.rfind(key, 0) != 0) return false;
    const auto suffix = trimmed.substr(key.size());
    const auto first = suffix.find_first_not_of(" \t");
    return first != std::string::npos && suffix[first] == '=';
}

std::size_t anchored_occurrence(const std::string& content,
                                const std::string& needle) {
    auto found = content.find(needle);
    while (found != std::string::npos) {
        if (found == 0U || content[found - 1U] == '\n') return found;
        found = content.find(needle, found + 1U);
    }
    return std::string::npos;
}

struct OwnedTelemetrySpan {
    std::size_t writable{std::string::npos};
    std::size_t reporter{std::string::npos};
};

OwnedTelemetrySpan owned_telemetry_span(const std::string& content) {
    OwnedTelemetrySpan span;
    span.writable = anchored_occurrence(content, kRotatorWritablePrefix);
    if (span.writable == std::string::npos) return span;

    const auto value_begin = span.writable + std::string(kBaseArgsPrefix).size();
    const auto value_end = content.find('"', value_begin);
    if (value_end == std::string::npos) return {};
    span.reporter = content.find(kRotatorReporterLine, value_begin);
    if (span.reporter == std::string::npos || span.reporter >= value_end) {
        return {};
    }
    return span;
}

std::string join_interfaces(const std::vector<std::string>& interfaces) {
    std::ostringstream result;
    for (std::size_t index = 0; index < interfaces.size(); ++index) {
        if (index != 0) result << ' ';
        result << interfaces[index];
    }
    return result.str();
}

} // namespace

std::string nfqws_config_without_ipv6_toggle(const std::string& content) {
    std::istringstream input(content);
    std::ostringstream output;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!assignment_line(line, "IPV6_ENABLED")) output << line << '\n';
    }
    return output.str();
}

std::string nfqws_config_strategy_identity(const std::string& content) {
    const auto span = owned_telemetry_span(content);
    if (span.writable == std::string::npos ||
        span.reporter == std::string::npos) {
        return content;
    }

    std::string identity = content;
    identity.erase(span.reporter, std::string(kRotatorReporterLine).size());
    identity.replace(
        span.writable,
        std::string(kRotatorWritablePrefix).size(),
        kBaseArgsPrefix);
    return identity;
}

bool nfqws_config_has_owned_rotator_telemetry(const std::string& content) {
    const auto span = owned_telemetry_span(content);
    return span.writable != std::string::npos &&
           span.reporter != std::string::npos;
}

std::string nfqws_config_with_isp_interfaces(
    const std::string& content, const std::vector<std::string>& interfaces) {
    if (interfaces.empty()) return content;

    std::istringstream input(content);
    std::ostringstream output;
    std::string line;
    bool replaced = false;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!replaced && assignment_line(line, "ISP_INTERFACE")) {
            output << "ISP_INTERFACE=\"" << join_interfaces(interfaces) << "\"\n";
            replaced = true;
        } else {
            output << line << '\n';
        }
    }
    return output.str();
}

} // namespace keen_pbr3
