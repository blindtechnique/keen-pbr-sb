#include "list_streamer.hpp"
#include "list_source_decoder.hpp"
#include "../config/list_parser.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

ListStreamer::ListStreamer(const CacheManager& cache)
    : cache_(&cache)
    , max_file_size_bytes_(cache.max_file_size()) {}

ListStreamer::ListStreamer(
    const CacheManager& cache,
    std::shared_ptr<const ListCacheGenerationSnapshot> cache_snapshot)
    : ListStreamer(cache.max_file_size(), std::move(cache_snapshot)) {}

ListStreamer::ListStreamer(
    std::size_t max_file_size_bytes,
    std::shared_ptr<const ListCacheGenerationSnapshot> cache_snapshot)
    : max_file_size_bytes_(max_file_size_bytes)
    , cache_snapshot_(std::move(cache_snapshot)) {
    if (!cache_snapshot_) {
        throw std::invalid_argument("cache snapshot must not be null");
    }
}

void ListStreamer::stream_list(const std::string& name, const ListConfig& config, ListEntryVisitor& visitor) {
    // Retain the snapshot lease until every cached byte has been streamed.
    // Local-only lists neither need nor inspect a URL-cache snapshot entry.
    const auto operation_snapshot = config.url.has_value()
        ? operation_cache_snapshot(name) : nullptr;
    const auto cached = operation_snapshot
        ? cache_source_path(name, operation_snapshot, config.url,
                            config.source_format.value_or("text")) : std::nullopt;
    stream_all_sources(name, config, visitor, cached);
}

void ListStreamer::stream_all_sources(const std::string& name,
                                      const ListConfig& config,
                                      ListEntryVisitor& visitor,
                                      const std::optional<std::filesystem::path>&
                                          cache_path) {
    // 1. Cached URL file
    if (cache_path.has_value()) {
        stream_file(*cache_path, visitor, false);
    }

    // 2. Local file (if configured)
    if (config.file.has_value()) {
        stream_file(config.file.value(), visitor, true, config.source_format.value_or("text"));
    }

    // Inline values follow the same normalization and validation path as file
    // and URL sources.
    const std::string inline_source = "inline list '" + name + "'";
    std::size_t inline_line_number = 1;
    ListParser::ParseContext inline_context;
    for (const auto& entry : config.ip_cidrs.value_or(std::vector<std::string>{})) {
        ListParser::parse_line(
            entry, visitor, inline_source, inline_line_number++, &inline_context);
    }

    for (const auto& domain : config.domains.value_or(std::vector<std::string>{})) {
        ListParser::parse_line(
            domain, visitor, inline_source, inline_line_number++, &inline_context);
    }

    // Signal that all sources for this list have been processed
    visitor.on_list_complete(name);
}

void ListStreamer::stream_cache(const std::string& name, ListEntryVisitor& visitor) {
    const auto operation_snapshot = operation_cache_snapshot(name);
    if (const auto cached = cache_source_path(name, operation_snapshot)) {
        stream_file(*cached, visitor, false);
    }
}

std::shared_ptr<const ListCacheGenerationSnapshot>
ListStreamer::operation_cache_snapshot(const std::string& name) const {
    if (cache_snapshot_) {
        if (!cache_snapshot_->contains(name)) {
            throw std::invalid_argument(
                "cache snapshot does not contain list '" + name + "'");
        }
        return cache_snapshot_;
    }
    if (cache_ == nullptr) {
        throw std::logic_error(
            "live cache access is unavailable without a pinned snapshot");
    }
    return cache_->capture_generation({name});
}

std::optional<std::filesystem::path> ListStreamer::cache_source_path(
    const std::string& name,
    const std::shared_ptr<const ListCacheGenerationSnapshot>& snapshot,
    const std::optional<std::string>& expected_url,
    const std::string& source_format) {
    if (!snapshot) {
        throw std::invalid_argument("cache snapshot must not be null");
    }
    if (!snapshot->contains(name)) {
        throw std::invalid_argument(
            "cache snapshot does not contain list '" + name + "'");
    }
    const auto* generation = snapshot->find(name);
    if (generation == nullptr) return std::nullopt;
    if (expected_url && !generation->matches_source(*expected_url, source_format)) {
        return std::nullopt;
    }
    return generation->path();
}

void ListStreamer::stream_file(const std::filesystem::path& path,
                               ListEntryVisitor& visitor,
                               bool log_invalid_entries,
                               const std::string& source_format) {
    if (!valid_list_source_format(source_format))
        throw std::runtime_error("Unknown list source format");
    const bool structured = source_format != "text";
    const int fd =
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        throw std::runtime_error(
            "Failed to open list file " + path.string() + ": " +
            std::strerror(errno));
    }
    const auto close_fd = [&]() { ::close(fd); };

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        const std::string error = std::strerror(errno);
        close_fd();
        throw std::runtime_error(
            "Failed to inspect list file " + path.string() + ": " + error);
    }
    if (!S_ISREG(st.st_mode)) {
        close_fd();
        throw std::runtime_error(
            "List source is not a regular file: " + path.string());
    }
    if (st.st_size < 0 ||
        static_cast<std::uintmax_t>(st.st_size) > max_file_size_bytes_ ||
        (structured && static_cast<std::uintmax_t>(st.st_size) > kListSourceMaxBytes)) {
        close_fd();
        throw std::runtime_error(
            "List file exceeds configured size limit: " + path.string());
    }

    std::array<char, 4096> buffer {};
    std::string line;
    std::string structured_body;
    line.reserve(256);
    std::size_t total_bytes = 0;
    std::size_t line_number = 1;
    ListParser::ParseContext context{log_invalid_entries};
    while (true) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            const std::string error = std::strerror(errno);
            close_fd();
            throw std::runtime_error(
                "Failed to read list file " + path.string() + ": " + error);
        }
        if (count == 0) break;
        total_bytes += static_cast<std::size_t>(count);
        if (total_bytes > max_file_size_bytes_ ||
            (structured && total_bytes > kListSourceMaxBytes)) {
            close_fd();
            throw std::runtime_error(
                "List file exceeds configured size limit: " + path.string());
        }
        if (structured) {
            structured_body.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        for (ssize_t index = 0; index < count; ++index) {
            const char ch = buffer[static_cast<std::size_t>(index)];
            if (ch == '\n') {
                ListParser::parse_line(
                    line, visitor, path.string(), line_number++, &context);
                line.clear();
                continue;
            }
            if (line.size() >= kMaxLineBytes) {
                close_fd();
                throw std::runtime_error(
                    "List line exceeds 4096-byte limit in " + path.string() +
                    " at line " + std::to_string(line_number));
            }
            line.push_back(ch);
        }
    }
    close_fd();
    if (structured) {
        const auto decoded = decode_list_source(structured_body, source_format);
        if (!decoded.complete) {
            const auto detail = decoded.errors.empty() ? decoded.limit_reason :
                decoded.errors.front().code + " at line " + std::to_string(decoded.errors.front().line);
            throw std::runtime_error("Invalid list source " + path.string() + ": " + detail);
        }
        // A malformed structured file must not feed its valid prefix to routing.
        for (const auto& entry : decoded.entries)
            ListParser::classify_entry(entry.value, visitor);
        return;
    }
    if (!line.empty()) {
        ListParser::parse_line(
            line, visitor, path.string(), line_number, &context);
    }
}

} // namespace keen_pbr3
