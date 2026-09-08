#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::size_t kListPreviewMaxBytes = 2U * 1024U * 1024U;
inline constexpr std::size_t kListPreviewMaxLines = 50000U;
inline constexpr std::size_t kListPreviewSampleSize = 50U;

struct ListPreviewEntry {
    std::int64_t line{0};
    std::string value;
    std::string type;
};
struct ListPreviewError {
    std::int64_t line{0};
    std::string code;
    std::string value;
};
struct ListPreviewResult {
    std::string status{"ok"};
    bool complete{true};
    std::int64_t lines{0};
    std::int64_t valid_entries{0};
    std::int64_t unique_entries{0};
    std::int64_t duplicates{0};
    std::int64_t invalid_entries{0};
    std::int64_t ignored_lines{0};
    // Family counts are unique canonical entries, not repeated source rows.
    std::int64_t ipv4{0};
    std::int64_t ipv6{0};
    std::int64_t domains{0};
    std::vector<ListPreviewEntry> entries;
    std::vector<ListPreviewError> errors;
    bool entries_limited{false};
    bool errors_limited{false};
    std::string limit_reason;
};

// Syntax-only preview: no resolution, persistence, cache, or runtime changes.
// Classification and IP/CIDR canonicalization belong to ListParser.
ListPreviewResult preview_list_text(std::string_view text);

} // namespace keen_pbr3
