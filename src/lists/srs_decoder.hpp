#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

// Increment whenever the binary-to-text mapping changes. Cached SRS metadata
// uses this value to force one unconditional re-download and reconversion.
constexpr std::int64_t kSrsDecoderRevision = 1;

enum class SrsDecodeErrorKind {
    InvalidData,
    UnsupportedVersion,
};

class SrsDecodeError final : public std::runtime_error {
public:
    explicit SrsDecodeError(std::string message,
                            SrsDecodeErrorKind kind = SrsDecodeErrorKind::InvalidData,
                            std::uint8_t version = 0)
        : std::runtime_error(std::move(message))
        , kind_(kind)
        , version_(version) {}

    SrsDecodeErrorKind kind() const noexcept {
        return kind_;
    }

    std::uint8_t version() const noexcept {
        return version_;
    }

private:
    SrsDecodeErrorKind kind_;
    std::uint8_t version_;
};

struct SrsDecodeLimits {
    std::size_t max_compressed_bytes = 16U * 1024U * 1024U;
    std::size_t max_decompressed_bytes = 64U * 1024U * 1024U;
    std::size_t max_rules = 100000U;
    std::size_t max_logical_depth = 32U;
    std::size_t max_rule_items = 64U;
    std::size_t max_values = 1000000U;
    std::size_t max_string_bytes = 4096U;
    std::size_t max_total_string_bytes = 16U * 1024U * 1024U;
    std::size_t max_trie_words = 262144U;
    std::size_t max_trie_labels = 4000000U;
    std::size_t max_trie_nodes = 4000001U;
    std::size_t max_ip_ranges = 1000000U;
    std::size_t max_output_entries = 1000000U;
    std::size_t max_output_string_bytes = 16U * 1024U * 1024U;
};

struct SrsDecodeResult {
    std::uint8_t version = 0;
    std::vector<std::string> domains;
    std::vector<std::string> domain_suffixes;
    std::vector<std::string> ip_cidrs;

    // Fields that cannot be represented by a keen-pbr domain/IP list.
    std::size_t unsupported_fields = 0;
    // Rules deliberately omitted because their boolean semantics cannot be
    // represented without broadening the match.
    std::size_t skipped_rules = 0;
    std::size_t inverted_rules = 0;
};

SrsDecodeResult decode_srs(std::istream& input,
                           const SrsDecodeLimits& limits = {});

SrsDecodeResult decode_srs_file(const std::filesystem::path& path,
                                const SrsDecodeLimits& limits = {});

} // namespace keen_pbr3
