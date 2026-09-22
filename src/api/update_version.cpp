#include "update_version.hpp"
#include "../config/config_writer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>
#include <array>
#include <string_view>
#include <utility>
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

struct ForkVersion {
    std::vector<unsigned int> upstream;
    std::uint64_t release{0};
};

std::optional<std::pair<std::uint64_t, std::uint64_t>> alpha_release_order(
    const std::string& tag) {
    if (tag.compare(0, 6, "alpha-") != 0) return std::nullopt;
    const auto separator = tag.find('-', 6);
    if (separator == std::string::npos) return std::nullopt;
    const auto run = tag.substr(6, separator - 6);
    const auto attempt = tag.substr(separator + 1);
    for (const auto* number : {&run, &attempt}) {
        if (number->empty() || !std::all_of(number->begin(), number->end(),
                [](unsigned char ch) { return ch >= '0' && ch <= '9'; }))
            return std::nullopt;
    }
    try {
        return std::make_pair(std::stoull(run), std::stoull(attempt));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

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

bool valid_update_channel(const std::string& channel) {
    return channel == "stable" || channel == "alpha";
}

std::optional<std::string> read_update_channel(const std::filesystem::path& path) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        (!ec && status.type() == std::filesystem::file_type::not_found))
        return std::nullopt;
    if (ec || !std::filesystem::is_regular_file(status))
        throw std::runtime_error("Update channel setting is unreadable");
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > 7) throw std::runtime_error("Update channel setting is invalid");
    std::ifstream input(path, std::ios::binary);
    std::string content{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (!input || input.bad()) throw std::runtime_error("Update channel setting is unreadable");
    if (!content.empty() && content.back() == '\n') content.pop_back();
    if (!valid_update_channel(content))
        throw std::runtime_error("Update channel setting is invalid");
    return content;
}

void save_update_channel(const std::filesystem::path& path, const std::string& channel) {
    if (!valid_update_channel(channel)) throw std::invalid_argument("Invalid update channel");
    (void)read_update_channel(path);
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0700;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    write_file_atomically(path, channel + "\n", options);
}

bool channel_release_installable(const std::string& current,
                                 const std::string& latest,
                                 const std::string& installed_channel,
                                 const std::string& selected_channel) {
    if (!valid_update_channel(installed_channel) || !valid_update_channel(selected_channel) ||
        !parse_fork_version(current) || !parse_fork_version(latest) ||
        is_newer_fork_version(current, latest)) return false;
    return is_newer_fork_version(latest, current) || installed_channel != selected_channel;
}

bool release_matches_channel(const nlohmann::json& release,
                             const std::string& channel) {
    if (!release.is_object()) return false;
    const auto draft = release.find("draft");
    const auto tag = release.find("tag_name");
    if (draft == release.end() || !draft->is_boolean() || draft->get<bool>() ||
        tag == release.end() || !tag->is_string()) return false;
    if (channel == "alpha")
        return alpha_release_order(tag->get<std::string>()).has_value();
    const auto prerelease = release.find("prerelease");
    return channel == "stable" && prerelease != release.end() &&
        prerelease->is_boolean() && !prerelease->get<bool>() &&
        parse_fork_version(tag->get<std::string>()).has_value();
}

nlohmann::json select_channel_release(const nlohmann::json& metadata,
                                      const std::string& channel) {
    if (channel == "stable")
        return release_matches_channel(metadata, channel)
            ? metadata : nlohmann::json::object();
    nlohmann::json selected = nlohmann::json::object();
    if (channel != "alpha" || !metadata.is_array()) return selected;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> latest;
    for (const auto& release : metadata) {
        if (!release_matches_channel(release, channel)) continue;
        const auto order = alpha_release_order(release["tag_name"].get<std::string>());
        if (!latest || *order > *latest) {
            latest = order;
            selected = release;
        }
    }
    return selected;
}

bool release_cache_matches_channel(const nlohmann::json& cache,
                                   const std::string& channel) {
    if (!cache.is_object()) return false;
    const auto cached_channel = cache.find("channel");
    const auto release = cache.find("release");
    return cached_channel != cache.end() && cached_channel->is_string() &&
        cached_channel->get<std::string>() == channel &&
        release != cache.end() && release_matches_channel(*release, channel) &&
        !published_fork_version(*release).empty();
}

} // namespace keen_pbr3
