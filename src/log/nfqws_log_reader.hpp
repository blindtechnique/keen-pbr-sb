#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace keen_pbr3 {

struct NfqwsLogTail {
    std::string content;
    bool truncated{false};
};

// Reorder records without one allocation per line: a bounded 2 MiB tail can
// contain millions of empty/short records on a memory-constrained router.
inline void reverse_nfqws_log_lines(std::string& content) {
    if (content.empty()) return;
    if (content.back() == '\n') content.pop_back();
    std::reverse(content.begin(), content.end());
    auto begin = content.begin();
    for (auto current = content.begin(); current != content.end(); ++current) {
        if (*current == '\n') {
            std::reverse(begin, current);
            begin = current + 1;
        }
    }
    std::reverse(begin, content.end());
    content.push_back('\n');
}

// Read only the tail of the opened file, not a growing stream up to EOF.
// Keep chronological order here; the API presents the newest records first.
inline NfqwsLogTail read_nfqws_log_tail(const std::filesystem::path& path,
                                      std::size_t maximum_bytes) {
    if (maximum_bytes == 0U) throw std::invalid_argument("nfqws log read limit is zero");
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("failed to read nfqws log");
    const auto end = static_cast<std::streamoff>(input.tellg());
    if (end < 0) throw std::runtime_error("failed to determine nfqws log size");
    const bool truncated = static_cast<std::uintmax_t>(end) > maximum_bytes;
    const auto begin = truncated ? end - static_cast<std::streamoff>(maximum_bytes) : 0;
    input.seekg(begin > 0 ? begin - 1 : begin);
    char previous = '\n';
    if (begin > 0) input.get(previous);
    if (!input) throw std::runtime_error("failed to seek nfqws log");

    NfqwsLogTail result;
    result.truncated = truncated;
    result.content.resize(static_cast<std::size_t>(end - begin));
    if (!result.content.empty()) {
        input.read(&result.content[0], static_cast<std::streamsize>(result.content.size()));
        if (input.bad()) throw std::runtime_error("failed to read nfqws log");
        // The log can be truncated concurrently. Do not expose zero padding or
        // chase new writes beyond the size observed on this open descriptor.
        result.content.resize(static_cast<std::size_t>(input.gcount()));
    }
    if (truncated && previous != '\n') {
        const auto newline = result.content.find('\n');
        if (newline != std::string::npos && newline + 1U < result.content.size()) {
            result.content.erase(0U, newline + 1U);
        } else {
            // One oversized record must still be visible as a marked tail.
            // Skip any UTF-8 continuation bytes cut off at the left boundary.
            std::size_t first = 0U;
            while (first < result.content.size() &&
                   (static_cast<unsigned char>(result.content[first]) & 0xc0U) == 0x80U) ++first;
            result.content.erase(0U, first);
        }
    }
    return result;
}

} // namespace keen_pbr3
