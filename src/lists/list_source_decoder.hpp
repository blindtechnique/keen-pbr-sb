#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::int64_t kListSourceDecoderRevision = 1;
inline constexpr std::size_t kListSourceMaxBytes = 2U * 1024U * 1024U;
inline constexpr std::size_t kListSourceMaxEntries = 50000U;
inline constexpr std::size_t kListSourceMaxLineBytes = 4096U;
inline constexpr std::size_t kListSourceMaxErrors = 50U;

struct ListSourceEntry {
    std::int64_t line{0};
    std::string value;
    std::string type;
};

struct ListSourceError {
    std::int64_t line{0};
    std::string code;
    std::string value;
};

struct ListSourceDecodeResult {
    bool complete{true};
    // Published output is available only when the whole source is valid.
    // It contains unique canonical ListParser entries, one per LF-ended line.
    std::string text;
    // All unique accepted entries (not a UI sample), including a useful prefix
    // on failure. These must not be applied unless complete is true.
    std::vector<ListSourceEntry> entries;
    std::vector<ListSourceError> errors;
    std::int64_t lines{0};
    std::int64_t input_entries{0};
    std::int64_t valid_entries{0};
    std::int64_t duplicates{0};
    std::int64_t invalid_entries{0};
    std::int64_t ignored_lines{0};
    std::int64_t ipv4{0};
    std::int64_t ipv6{0};
    std::int64_t domains{0};
    bool errors_limited{false};
    std::string limit_reason;
};

inline bool valid_list_source_format(std::string_view format) noexcept {
    return format == "text" || format == "json-array" || format == "yaml-payload";
}

// Explicit formats only: text, json-array, yaml-payload. Domains retain native
// keen-pbr root-and-subdomain semantics; this is not a Clash/sing-box rule
// interpreter. JSON accepts only a string array; YAML accepts one payload block
// sequence of single-line plain/single-quoted/double-quoted string scalars.
// JSON limits decoded scalar bytes, not the physical minified document line.
// Text/YAML additionally limit each raw physical line. No external effects.
ListSourceDecodeResult decode_list_source(std::string_view body,
                                         std::string_view format = "text");

} // namespace keen_pbr3
