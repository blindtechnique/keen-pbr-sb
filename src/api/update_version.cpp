#include "update_version.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>
#include <vector>

namespace keen_pbr3 {
namespace {

struct ForkVersion {
    std::vector<unsigned int> upstream;
    unsigned int release{0};
};

std::optional<ForkVersion> parse_fork_version(std::string value) {
    if (!value.empty() && value.front() == 'v') value.erase(value.begin());
    const auto marker = value.find("-sb");
    if (marker == std::string::npos) return std::nullopt;
    auto release = value.substr(marker + 3);
    if (!release.empty() && release.front() == '.') release.erase(release.begin());
    if (release.empty() ||
        !std::all_of(release.begin(), release.end(), [](unsigned char ch) { return std::isdigit(ch); }))
        return std::nullopt;

    ForkVersion result;
    const auto upstream = value.substr(0, marker);
    std::size_t begin = 0;
    while (begin <= upstream.size()) {
        const auto end = upstream.find('.', begin);
        const auto token = upstream.substr(begin, end == std::string::npos
                                                      ? std::string::npos : end - begin);
        if (token.empty() ||
            !std::all_of(token.begin(), token.end(), [](unsigned char ch) { return std::isdigit(ch); }))
            return std::nullopt;
        try {
            const auto number = std::stoul(token);
            if (number > std::numeric_limits<unsigned int>::max()) return std::nullopt;
            result.upstream.push_back(static_cast<unsigned int>(number));
        } catch (const std::exception&) {
            return std::nullopt;
        }
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    try {
        const auto number = std::stoul(release);
        if (number > std::numeric_limits<unsigned int>::max()) return std::nullopt;
        result.release = static_cast<unsigned int>(number);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return result;
}

} // namespace

bool is_newer_fork_version(const std::string& candidate, const std::string& current) {
    const auto lhs = parse_fork_version(candidate);
    const auto rhs = parse_fork_version(current);
    if (!lhs || !rhs) return false;
    const auto count = std::max(lhs->upstream.size(), rhs->upstream.size());
    for (std::size_t index = 0; index < count; ++index) {
        const auto left = index < lhs->upstream.size() ? lhs->upstream[index] : 0U;
        const auto right = index < rhs->upstream.size() ? rhs->upstream[index] : 0U;
        if (left != right) return left > right;
    }
    return lhs->release > rhs->release;
}

bool safe_github_tag(const std::string& value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](unsigned char ch) {
               return std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-';
           });
}

} // namespace keen_pbr3
