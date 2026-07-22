#include "nfqws_config.hpp"

#include <sstream>

namespace keen_pbr3 {
namespace {

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
