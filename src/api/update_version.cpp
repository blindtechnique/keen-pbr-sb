#include "update_version.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>
#include <array>
#include <string_view>
#include <nlohmann/json.hpp>

namespace keen_pbr3 {
namespace {

struct ForkVersion {
    std::vector<unsigned int> upstream;
    std::uint64_t release{0};
};

std::optional<ForkVersion> parse_fork_version(std::string value) {
    if (!value.empty() && value.front() == 'v') value.erase(value.begin());
    auto marker = value.find("-sb");
    std::size_t release_begin = std::string::npos;
    if (marker != std::string::npos) {
        release_begin = marker + 3;
        if (release_begin < value.size() && value[release_begin] == '.') {
            ++release_begin;
        }
    } else {
        marker = value.rfind('-');
        if (marker != std::string::npos) release_begin = marker + 1;
    }
    if (marker == std::string::npos) return std::nullopt;
    const auto release = value.substr(release_begin);
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
        const auto number = std::stoull(release);
        result.release = static_cast<std::uint64_t>(number);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return result;
}

} // namespace

std::string format_fork_version(const std::string& version,
                                const std::string& release) {
    return "v" + version + "-" + release;
}

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

std::string published_fork_version(const nlohmann::json& release) {
    if (!release.is_object()) return {};
    const auto tag_field = release.find("tag_name");
    const auto tag = tag_field != release.end() && tag_field->is_string()
                         ? tag_field->get<std::string>() : std::string{};
    const auto assets = release.find("assets");
    std::string package_version;
    if (assets != release.end() && assets->is_array()) {
        constexpr std::string_view prefix = "keen-pbr_";
        constexpr std::array<std::string_view, 3> suffixes = {
            "_keenetic_aarch64-3.10.ipk", "_keenetic_mips-3.4.ipk",
            "_keenetic_mipsel-3.4.ipk"};
        for (const auto& asset : *assets) {
            if (!asset.is_object()) continue;
            const auto name_field = asset.find("name");
            if (name_field == asset.end() || !name_field->is_string()) continue;
            const auto name = name_field->get<std::string>();
            if (name.compare(0, prefix.size(), prefix) != 0) continue;
            for (const auto suffix : suffixes) {
                if (name.size() <= prefix.size() + suffix.size() ||
                    name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0)
                    continue;
                const auto version = "v" + name.substr(
                    prefix.size(), name.size() - prefix.size() - suffix.size());
                if (!parse_fork_version(version)) continue;
                // A partially replaced multi-architecture release must not
                // advertise whichever package happens to be listed first.
                if (!package_version.empty() && package_version != version) return {};
                package_version = version;
                break;
            }
        }
    }
    if (!package_version.empty()) return package_version;
    return parse_fork_version(tag) ? tag : std::string{};
}

bool safe_github_tag(const std::string& value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](unsigned char ch) {
               return std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-';
           });
}

} // namespace keen_pbr3
