#include "component_feed_index.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace keen_pbr3 {

namespace {

std::string trim(std::string value) {
    const auto not_space = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    return value;
}

bool is_hex_digest(const std::string& value) {
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::string lower(std::string value) {
    for (auto& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return value;
}

} // namespace

std::vector<FeedPackageEntry> parse_opkg_packages_index(
    const std::string& text) {
    std::vector<FeedPackageEntry> entries;
    FeedPackageEntry current;
    bool in_stanza = false;

    const auto flush = [&]() {
        if (in_stanza && current.identifies_ipk()) {
            entries.push_back(current);
        }
        current = FeedPackageEntry{};
        in_stanza = false;
    };

    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (trim(line).empty()) {
            flush();
            continue;
        }
        // Continuation lines (leading space) belong to multi-line fields
        // such as Description; nothing identifying lives there.
        if (line.front() == ' ' || line.front() == '\t') continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        const auto key = line.substr(0, colon);
        const auto value = trim(line.substr(colon + 1));
        in_stanza = true;
        if (key == "Package") {
            current.package = value;
        } else if (key == "Version") {
            current.version = value;
        } else if (key == "Filename") {
            current.filename = value;
        } else if (key == "Size") {
            std::uint64_t size = 0;
            bool valid = !value.empty();
            for (const unsigned char c : value) {
                if (!std::isdigit(c)) { valid = false; break; }
                size = size * 10 + (c - '0');
            }
            current.size = valid ? size : 0;
        } else if (key == "SHA256sum") {
            const auto digest = lower(value);
            current.sha256 = is_hex_digest(digest) ? digest : std::string{};
        }
    }
    flush();
    return entries;
}

std::string gunzip_to_string(const std::string& compressed,
                             std::size_t max_bytes) {
    z_stream stream{};
    // 16 + MAX_WBITS: accept gzip framing, not bare zlib.
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        throw std::runtime_error("gzip inflate could not be initialised");
    }
    struct Guard {
        z_stream* stream;
        ~Guard() { inflateEnd(stream); }
    } guard{&stream};

    stream.next_in = reinterpret_cast<Bytef*>(
        const_cast<char*>(compressed.data()));
    stream.avail_in = static_cast<uInt>(compressed.size());

    std::string output;
    char chunk[16 * 1024];
    for (;;) {
        stream.next_out = reinterpret_cast<Bytef*>(chunk);
        stream.avail_out = static_cast<uInt>(sizeof(chunk));
        const int status = inflate(&stream, Z_NO_FLUSH);
        if (status != Z_OK && status != Z_STREAM_END) {
            throw std::runtime_error("gzip stream is corrupt");
        }
        const std::size_t produced = sizeof(chunk) - stream.avail_out;
        if (output.size() + produced > max_bytes) {
            throw std::runtime_error("gzip stream exceeds the size budget");
        }
        output.append(chunk, produced);
        if (status == Z_STREAM_END) break;
        if (stream.avail_in == 0 && produced == 0) {
            throw std::runtime_error("gzip stream ended early");
        }
    }
    return output;
}

std::optional<FeedPackageEntry> find_feed_entry(
    const std::vector<FeedPackageEntry>& entries,
    const std::string& package,
    const std::string& version) {
    for (const auto& entry : entries) {
        if (entry.package == package && entry.version == version) {
            return entry;
        }
    }
    return std::nullopt;
}

IpkRetentionAction decide_ipk_retention(
    const std::string& installed_version,
    const std::optional<RetainedIpk>& retained_current,
    const std::optional<FeedPackageEntry>& feed_entry) {
    // Retained bytes are trusted only when they are the installed version.
    // A store holding an older version is a rollback target, not a reason
    // to skip retaining the one that is actually running.
    if (retained_current.has_value() &&
        retained_current->version == installed_version) {
        // Same version but a different digest means the feed republished
        // the version with other bytes. What is installed came from the
        // earlier bytes, which the store holds; refetching would replace the
        // exact copy with an inexact one.
        return IpkRetentionAction::already_retained;
    }
    if (feed_entry.has_value() && feed_entry->version == installed_version) {
        return IpkRetentionAction::retain_now;
    }
    return IpkRetentionAction::unavailable;
}

namespace {

std::array<unsigned long, 3> semantic_version(
    const std::string& value) noexcept {
    std::array<unsigned long, 3> result{};
    auto cursor = value.find_first_of("0123456789");
    for (std::size_t index = 0;
         index < result.size() && cursor != std::string::npos; ++index) {
        const auto end = value.find_first_not_of("0123456789", cursor);
        const auto stop = end == std::string::npos ? value.size() : end;
        unsigned long component = 0;
        for (std::size_t i = cursor; i < stop; ++i) {
            if (component > 99999999UL) return {};
            component = component * 10 +
                        static_cast<unsigned long>(value[i] - '0');
        }
        result[index] = component;
        if (index + 1 == result.size() || end == std::string::npos ||
            value[end] != '.') {
            break;
        }
        cursor = end + 1;
    }
    return result;
}

} // namespace

bool feed_version_newer(const std::string& candidate,
                        const std::string& installed) noexcept {
    return semantic_version(candidate) > semantic_version(installed);
}

} // namespace keen_pbr3
