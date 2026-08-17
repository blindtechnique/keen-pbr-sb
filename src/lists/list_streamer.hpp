#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "list_entry_visitor.hpp"

#include <memory>
#include <optional>
#include <string>

namespace keen_pbr3 {

class ListStreamer {
public:
    static constexpr std::size_t kMaxLineBytes = 4096;
    explicit ListStreamer(const CacheManager& cache);
    // The supplied snapshot must come from the single-writer CacheManager
    // owned by ListService and must explicitly contain every cache-backed list
    // this streamer will read. An uncaptured name is a caller error; an entry
    // captured as missing remains missing without a live fallback.
    ListStreamer(
        const CacheManager& cache,
        std::shared_ptr<const ListCacheGenerationSnapshot> cache_snapshot);

    // Stream all sources for a named list (cache file, local file, inline entries)
    // through the visitor. Calls visitor.on_list_complete(name) when done.
    void stream_list(const std::string& name, const ListConfig& config, ListEntryVisitor& visitor);

    // Stream all sources for a named list, the same as stream_list(), but use
    // the cached file whenever it exists — even if the list no longer declares
    // a URL source. Calls visitor.on_list_complete(name) when done.
    void stream_list_preferring_cache(const std::string& name,
                                     const ListConfig& config,
                                     ListEntryVisitor& visitor);

    // Stream only the cached file for a named list through the visitor.
    void stream_cache(const std::string& name, ListEntryVisitor& visitor);

private:
    // Stream a list's local file and inline entries through the visitor,
    // optionally preceded by the cached file. Calls on_list_complete(name).
    void stream_all_sources(const std::string& name,
                            const ListConfig& config,
                            ListEntryVisitor& visitor,
                            const std::optional<std::filesystem::path>&
                                cache_path);

    // Open a file and stream its entries through the visitor.
    void stream_file(const std::filesystem::path& path,
                     ListEntryVisitor& visitor,
                     bool log_invalid_entries);

    // Resolve a cache body from the immutable transaction snapshot. Explicit
    // misses never fall back to live state; uncaptured names are rejected.
    std::shared_ptr<const ListCacheGenerationSnapshot>
    operation_cache_snapshot(const std::string& name) const;
    static std::optional<std::filesystem::path> cache_source_path(
        const std::string& name,
        const std::shared_ptr<const ListCacheGenerationSnapshot>& snapshot);

    const CacheManager& cache_;
    std::size_t max_file_size_bytes_;
    std::shared_ptr<const ListCacheGenerationSnapshot> cache_snapshot_;
};

} // namespace keen_pbr3
