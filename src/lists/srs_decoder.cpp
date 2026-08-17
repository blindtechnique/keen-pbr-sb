#include "srs_decoder.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

#include <zlib.h>

namespace keen_pbr3 {

namespace {

// The binary layout follows SagerNet/sing-box common/srs and
// SagerNet/sing common/domain, copyright (C) 2022 nekohasekai and
// contributors, GPL-3.0-or-later. This is an independent bounded C++ decoder;
// it intentionally implements only the fields keen-pbr can represent.

constexpr std::array<std::uint8_t, 3> kMagic{{0x53, 0x52, 0x53}};
constexpr std::uint8_t kMinVersion = 1;
constexpr std::uint8_t kMaxVersion = 5;

enum class RuleItem : std::uint8_t {
    QueryType = 0,
    Network = 1,
    Domain = 2,
    DomainKeyword = 3,
    DomainRegex = 4,
    SourceIpCidr = 5,
    IpCidr = 6,
    SourcePort = 7,
    SourcePortRange = 8,
    Port = 9,
    PortRange = 10,
    ProcessName = 11,
    ProcessPath = 12,
    PackageName = 13,
    WifiSsid = 14,
    WifiBssid = 15,
    AdGuardDomain = 16,
    ProcessPathRegex = 17,
    NetworkType = 18,
    NetworkIsExpensive = 19,
    NetworkIsConstrained = 20,
    NetworkInterfaceAddress = 21,
    DefaultInterfaceAddress = 22,
    PackageNameRegex = 23,
    Final = 0xFF,
};

constexpr char kDomainPrefixLabel = '\r';
constexpr char kDomainRootLabel = '\n';

[[noreturn]] void fail(const std::string& message) {
    throw SrsDecodeError(message);
}

std::size_t checked_size(std::uint64_t value,
                         std::size_t limit,
                         std::string_view what) {
    if (value > static_cast<std::uint64_t>(limit)) {
        fail(std::string(what) + " exceeds limit (" + std::to_string(value) +
             " > " + std::to_string(limit) + ")");
    }
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        fail(std::string(what) + " does not fit in memory");
    }
    return static_cast<std::size_t>(value);
}

class InflateReader {
public:
    InflateReader(std::istream& source, const SrsDecodeLimits& limits)
        : source_(source), limits_(limits) {
        std::memset(&stream_, 0, sizeof(stream_));
        const int status = inflateInit(&stream_);
        if (status != Z_OK) {
            fail("failed to initialize zlib decoder");
        }
        initialized_ = true;
    }

    ~InflateReader() {
        if (initialized_) {
            inflateEnd(&stream_);
        }
    }

    InflateReader(const InflateReader&) = delete;
    InflateReader& operator=(const InflateReader&) = delete;

    std::uint8_t read_byte(std::string_view what) {
        std::uint8_t value = 0;
        read_exact(&value, 1, what);
        return value;
    }

    void read_exact(void* destination, std::size_t size, std::string_view what) {
        auto* output = static_cast<std::uint8_t*>(destination);
        std::size_t copied = 0;
        while (copied < size) {
            if (output_offset_ == output_size_ && !fill_output()) {
                fail(std::string(what) + " is truncated");
            }
            const std::size_t available = output_size_ - output_offset_;
            const std::size_t amount = std::min(available, size - copied);
            std::memcpy(output + copied, output_.data() + output_offset_, amount);
            output_offset_ += amount;
            copied += amount;
        }
    }

    bool try_read_byte(std::uint8_t& value) {
        if (output_offset_ == output_size_ && !fill_output()) {
            return false;
        }
        value = output_[output_offset_++];
        return true;
    }

    void require_clean_end() {
        std::uint8_t extra = 0;
        if (try_read_byte(extra)) {
            fail("SRS payload contains trailing decompressed data");
        }
        if (!stream_finished_) {
            fail("SRS zlib stream is truncated");
        }
        if (stream_.avail_in != 0 || source_.peek() != std::char_traits<char>::eof()) {
            fail("SRS file contains trailing compressed data");
        }
    }

private:
    bool load_input() {
        if (input_eof_) {
            return false;
        }
        if (compressed_bytes_ >= limits_.max_compressed_bytes) {
            fail("SRS compressed payload exceeds limit");
        }

        const std::size_t remaining = limits_.max_compressed_bytes - compressed_bytes_;
        const std::size_t request = std::min(input_.size(), remaining);
        if (request == 0) {
            fail("SRS compressed payload exceeds limit");
        }
        source_.read(reinterpret_cast<char*>(input_.data()),
                     static_cast<std::streamsize>(request));
        const auto count = source_.gcount();
        if (count <= 0) {
            input_eof_ = true;
            return false;
        }
        compressed_bytes_ += static_cast<std::size_t>(count);
        stream_.next_in = input_.data();
        stream_.avail_in = static_cast<uInt>(count);
        return true;
    }

    bool fill_output() {
        if (stream_finished_) {
            return false;
        }
        output_offset_ = 0;
        output_size_ = 0;

        for (;;) {
            if (stream_.avail_in == 0 && !load_input()) {
                fail("SRS zlib stream is truncated");
            }

            stream_.next_out = output_.data();
            stream_.avail_out = static_cast<uInt>(output_.size());
            const int status = inflate(&stream_, Z_NO_FLUSH);
            const std::size_t produced = output_.size() - stream_.avail_out;

            if (produced > limits_.max_decompressed_bytes - decompressed_bytes_) {
                fail("SRS decompressed payload exceeds limit");
            }
            decompressed_bytes_ += produced;
            output_size_ = produced;

            if (status == Z_STREAM_END) {
                stream_finished_ = true;
            } else if (status != Z_OK) {
                const std::string detail =
                    stream_.msg != nullptr ? std::string(": ") + stream_.msg : std::string{};
                fail("invalid SRS zlib stream" + detail);
            }

            if (produced != 0) {
                return true;
            }
            if (stream_finished_) {
                return false;
            }
        }
    }

    std::istream& source_;
    const SrsDecodeLimits& limits_;
    z_stream stream_{};
    bool initialized_ = false;
    bool input_eof_ = false;
    bool stream_finished_ = false;
    std::size_t compressed_bytes_ = 0;
    std::size_t decompressed_bytes_ = 0;
    std::array<std::uint8_t, 8192> input_{};
    std::array<std::uint8_t, 8192> output_{};
    std::size_t output_offset_ = 0;
    std::size_t output_size_ = 0;
};

struct IpAddress {
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t size = 0;
};

bool address_less(const IpAddress& lhs, const IpAddress& rhs) {
    return std::lexicographical_compare(
        lhs.bytes.begin(), lhs.bytes.begin() + lhs.size,
        rhs.bytes.begin(), rhs.bytes.begin() + rhs.size);
}

bool address_equal(const IpAddress& lhs, const IpAddress& rhs) {
    return lhs.size == rhs.size &&
           std::equal(lhs.bytes.begin(), lhs.bytes.begin() + lhs.size, rhs.bytes.begin());
}

std::size_t address_trailing_zero_bits(const IpAddress& address) {
    std::size_t result = 0;
    for (std::size_t index = address.size; index > 0; --index) {
        const std::uint8_t value = address.bytes[index - 1];
        if (value == 0) {
            result += 8;
            continue;
        }
        std::uint8_t copy = value;
        while ((copy & 1U) == 0U) {
            ++result;
            copy >>= 1U;
        }
        return result;
    }
    return result;
}

IpAddress block_end(IpAddress address, std::size_t host_bits) {
    for (std::size_t offset = 0; offset < host_bits; ++offset) {
        const std::size_t byte_from_end = offset / 8U;
        const std::size_t bit = offset % 8U;
        const std::size_t index = static_cast<std::size_t>(address.size) - 1U - byte_from_end;
        address.bytes[index] =
            static_cast<std::uint8_t>(address.bytes[index] | (1U << bit));
    }
    return address;
}

bool increment_address(IpAddress& address) {
    for (std::size_t index = address.size; index > 0; --index) {
        auto& value = address.bytes[index - 1];
        if (value != 0xFFU) {
            ++value;
            return true;
        }
        value = 0;
    }
    return false;
}

std::string format_ipv4(const IpAddress& address) {
    std::ostringstream output;
    output << static_cast<unsigned>(address.bytes[0]) << '.'
           << static_cast<unsigned>(address.bytes[1]) << '.'
           << static_cast<unsigned>(address.bytes[2]) << '.'
           << static_cast<unsigned>(address.bytes[3]);
    return output.str();
}

std::string format_ipv6(const IpAddress& address) {
    std::array<std::uint16_t, 8> groups{};
    for (std::size_t index = 0; index < groups.size(); ++index) {
        groups[index] = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address.bytes[index * 2U]) << 8U) |
            address.bytes[index * 2U + 1U]);
    }

    std::size_t best_start = groups.size();
    std::size_t best_length = 0;
    for (std::size_t index = 0; index < groups.size();) {
        if (groups[index] != 0) {
            ++index;
            continue;
        }
        std::size_t end = index;
        while (end < groups.size() && groups[end] == 0) {
            ++end;
        }
        if (end - index > best_length && end - index >= 2) {
            best_start = index;
            best_length = end - index;
        }
        index = end;
    }

    std::ostringstream output;
    output << std::hex << std::nouppercase;
    for (std::size_t index = 0; index < groups.size();) {
        if (index == best_start) {
            output << "::";
            index += best_length;
            continue;
        }
        if (index != 0 && index != best_start + best_length) {
            output << ':';
        }
        output << groups[index];
        ++index;
    }
    return output.str();
}

std::string format_address(const IpAddress& address) {
    return address.size == 4 ? format_ipv4(address) : format_ipv6(address);
}

bool bit_is_set(const std::vector<std::uint64_t>& words, std::size_t bit) {
    return (words[bit / 64U] & (std::uint64_t{1} << (bit % 64U))) != 0;
}

bool any_bits_set_from(const std::vector<std::uint64_t>& words, std::size_t start_bit) {
    if (words.empty() || start_bit >= words.size() * 64U) {
        return false;
    }
    const std::size_t word = start_bit / 64U;
    const std::size_t offset = start_bit % 64U;
    if ((words[word] & (~std::uint64_t{0} << offset)) != 0) {
        return true;
    }
    return std::any_of(words.begin() + static_cast<std::ptrdiff_t>(word + 1U),
                       words.end(),
                       [](std::uint64_t value) { return value != 0; });
}

std::string reverse_utf8_codepoints(const std::string& input) {
    std::vector<std::pair<std::size_t, std::size_t>> codepoints;
    codepoints.reserve(input.size());
    for (std::size_t index = 0; index < input.size();) {
        const auto first = static_cast<std::uint8_t>(input[index]);
        std::size_t length = 0;
        std::uint32_t value = 0;
        if (first <= 0x7FU) {
            length = 1;
            value = first;
        } else if (first >= 0xC2U && first <= 0xDFU) {
            length = 2;
            value = first & 0x1FU;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            length = 3;
            value = first & 0x0FU;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            length = 4;
            value = first & 0x07U;
        } else {
            fail("SRS domain trie contains invalid UTF-8");
        }
        if (index + length > input.size()) {
            fail("SRS domain trie contains truncated UTF-8");
        }
        for (std::size_t part = 1; part < length; ++part) {
            const auto continuation = static_cast<std::uint8_t>(input[index + part]);
            if ((continuation & 0xC0U) != 0x80U) {
                fail("SRS domain trie contains invalid UTF-8 continuation");
            }
            value = (value << 6U) | (continuation & 0x3FU);
        }
        if ((length == 3 && value < 0x800U) ||
            (length == 4 && value < 0x10000U) ||
            (value >= 0xD800U && value <= 0xDFFFU) ||
            value > 0x10FFFFU) {
            fail("SRS domain trie contains non-canonical UTF-8");
        }
        codepoints.emplace_back(index, length);
        index += length;
    }

    std::string result;
    result.reserve(input.size());
    for (auto iterator = codepoints.rbegin(); iterator != codepoints.rend(); ++iterator) {
        result.append(input, iterator->first, iterator->second);
    }
    return result;
}

void validate_domain_text(std::string_view domain) {
    if (domain.empty()) {
        fail("SRS domain trie contains an empty domain");
    }
    for (const unsigned char value : domain) {
        if (value < 0x20U || value == 0x7FU) {
            fail("SRS domain trie contains a control character");
        }
    }
}

struct RuleExtraction {
    std::vector<std::string> domains;
    std::vector<std::string> suffixes;
    std::vector<std::string> cidrs;
};

void append_move(std::vector<std::string>& destination,
                 std::vector<std::string>& source) {
    destination.reserve(destination.size() + source.size());
    std::move(source.begin(), source.end(), std::back_inserter(destination));
    source.clear();
}

class Decoder {
public:
    Decoder(InflateReader& reader, const SrsDecodeLimits& limits, std::uint8_t version)
        : reader_(reader), limits_(limits), version_(version) {}

    SrsDecodeResult decode() {
        const std::size_t top_level_rules =
            read_count(limits_.max_rules, "top-level rule count");
        RuleExtraction collected;
        for (std::size_t index = 0; index < top_level_rules; ++index) {
            auto rule = read_rule(0, "rule[" + std::to_string(index) + "]");
            append_move(collected.domains, rule.domains);
            append_move(collected.suffixes, rule.suffixes);
            append_move(collected.cidrs, rule.cidrs);
        }
        reader_.require_clean_end();

        sort_unique(collected.domains);
        sort_unique(collected.suffixes);
        sort_unique(collected.cidrs);
        result_.domains = std::move(collected.domains);
        result_.domain_suffixes = std::move(collected.suffixes);
        result_.ip_cidrs = std::move(collected.cidrs);
        result_.version = version_;
        return result_;
    }

private:
    std::uint64_t read_uvarint(std::string_view what) {
        std::uint64_t value = 0;
        for (unsigned index = 0; index < 10; ++index) {
            const std::uint8_t byte = reader_.read_byte(what);
            if (index == 9 && byte > 1U) {
                fail(std::string(what) + " has an overflowing varint");
            }
            value |= static_cast<std::uint64_t>(byte & 0x7FU) << (index * 7U);
            if ((byte & 0x80U) == 0) {
                if (index != 0 && (byte & 0x7FU) == 0) {
                    fail(std::string(what) + " has a non-canonical varint");
                }
                return value;
            }
        }
        fail(std::string(what) + " has an overflowing varint");
    }

    std::size_t read_count(std::size_t limit, std::string_view what) {
        return checked_size(read_uvarint(what), limit, what);
    }

    std::uint64_t read_be_u64(std::string_view what) {
        std::array<std::uint8_t, 8> bytes{};
        reader_.read_exact(bytes.data(), bytes.size(), what);
        std::uint64_t value = 0;
        for (const auto byte : bytes) {
            value = (value << 8U) | byte;
        }
        return value;
    }

    std::uint16_t read_be_u16(std::string_view what) {
        std::array<std::uint8_t, 2> bytes{};
        reader_.read_exact(bytes.data(), bytes.size(), what);
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[0]) << 8U) | bytes[1]);
    }

    bool read_bool(std::string_view what) {
        const auto value = reader_.read_byte(what);
        if (value > 1U) {
            fail(std::string(what) + " is not a canonical boolean");
        }
        return value != 0;
    }

    void account_values(std::size_t count, std::string_view what) {
        if (count > limits_.max_values - total_values_) {
            fail(std::string(what) + " makes total value count exceed limit");
        }
        total_values_ += count;
    }

    void account_string_bytes(std::size_t count) {
        if (count > limits_.max_total_string_bytes - total_string_bytes_) {
            fail("SRS total string data exceeds limit");
        }
        total_string_bytes_ += count;
    }

    void account_output(std::size_t count) {
        if (count > limits_.max_output_entries - decoded_output_entries_) {
            fail("SRS decoded output entry count exceeds limit");
        }
        decoded_output_entries_ += count;
    }

    void account_output_string_bytes(std::size_t count) {
        if (count >
            limits_.max_output_string_bytes - decoded_output_string_bytes_) {
            fail("SRS decoded output string data exceeds limit");
        }
        decoded_output_string_bytes_ += count;
    }

    void skip_string_list(std::string_view context) {
        const auto count = read_count(limits_.max_values, std::string(context) + " count");
        account_values(count, context);
        std::array<std::uint8_t, 1024> discard{};
        for (std::size_t index = 0; index < count; ++index) {
            const auto length =
                read_count(limits_.max_string_bytes,
                           std::string(context) + "[" + std::to_string(index) + "] length");
            account_string_bytes(length);
            std::size_t remaining = length;
            while (remaining != 0) {
                const auto amount = std::min(remaining, discard.size());
                reader_.read_exact(discard.data(), amount, context);
                remaining -= amount;
            }
        }
    }

    void skip_u16_list(std::string_view context) {
        const auto count = read_count(limits_.max_values, std::string(context) + " count");
        account_values(count, context);
        for (std::size_t index = 0; index < count; ++index) {
            (void)read_be_u16(context);
        }
    }

    void skip_u8_list(std::string_view context) {
        const auto count = read_count(limits_.max_values, std::string(context) + " count");
        account_values(count, context);
        std::array<std::uint8_t, 1024> discard{};
        std::size_t remaining = count;
        while (remaining != 0) {
            const auto amount = std::min(remaining, discard.size());
            reader_.read_exact(discard.data(), amount, context);
            remaining -= amount;
        }
    }

    IpAddress read_address(std::string_view context) {
        const auto length = read_count(16, std::string(context) + " address length");
        if (length != 4 && length != 16) {
            fail(std::string(context) + " address length must be 4 or 16 bytes");
        }
        IpAddress address;
        address.size = static_cast<std::uint8_t>(length);
        reader_.read_exact(address.bytes.data(), length, context);
        return address;
    }

    void skip_prefix(std::string_view context) {
        const auto address = read_address(context);
        const auto bits = reader_.read_byte(std::string(context) + " prefix length");
        const auto maximum = static_cast<std::uint8_t>(address.size * 8U);
        if (bits > maximum) {
            fail(std::string(context) + " prefix length is out of range");
        }
    }

    std::vector<std::uint64_t> read_word_vector(std::string_view context) {
        const auto count =
            read_count(limits_.max_trie_words, std::string(context) + " word count");
        std::vector<std::uint64_t> words;
        words.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            words.push_back(read_be_u64(context));
        }
        return words;
    }

    std::vector<std::uint8_t> read_byte_vector(std::size_t limit,
                                               std::string_view context) {
        const auto count = read_count(limit, std::string(context) + " byte count");
        std::vector<std::uint8_t> bytes(count);
        if (!bytes.empty()) {
            reader_.read_exact(bytes.data(), bytes.size(), context);
        }
        return bytes;
    }

    struct Trie {
        std::vector<std::uint64_t> leaves;
        std::vector<std::uint64_t> bitmap;
        std::vector<std::uint8_t> labels;
        std::vector<std::uint32_t> first_child;
        std::vector<std::uint32_t> child_count;
    };

    Trie read_trie(std::string_view context) {
        const auto trie_version = reader_.read_byte(std::string(context) + " trie version");
        if (trie_version != 0) {
            fail(std::string(context) + " uses unsupported trie version " +
                 std::to_string(trie_version));
        }

        Trie trie;
        trie.leaves = read_word_vector(std::string(context) + " leaves");
        trie.bitmap = read_word_vector(std::string(context) + " label bitmap");
        trie.labels = read_byte_vector(limits_.max_trie_labels,
                                       std::string(context) + " labels");

        if (trie.labels.size() >= limits_.max_trie_nodes) {
            fail(std::string(context) + " trie node count exceeds limit");
        }
        const std::size_t node_count = trie.labels.size() + 1U;
        if (trie.leaves.size() > std::numeric_limits<std::size_t>::max() / 64U ||
            trie.bitmap.size() > std::numeric_limits<std::size_t>::max() / 64U) {
            fail(std::string(context) + " trie bitmap size overflows");
        }
        if (trie.leaves.size() * 64U < node_count) {
            fail(std::string(context) + " trie leaves bitmap is too short");
        }
        const std::size_t meaningful_bitmap_bits =
            trie.labels.size() + node_count;
        if (trie.bitmap.size() * 64U < meaningful_bitmap_bits) {
            fail(std::string(context) + " trie label bitmap is too short");
        }

        trie.first_child.resize(node_count);
        trie.child_count.resize(node_count);
        std::size_t bit = 0;
        std::size_t label = 0;
        std::size_t next_child = 1;
        for (std::size_t node = 0; node < node_count; ++node) {
            trie.first_child[node] = static_cast<std::uint32_t>(next_child);
            std::size_t children = 0;
            for (;;) {
                if (bit >= trie.bitmap.size() * 64U) {
                    fail(std::string(context) + " trie label bitmap is truncated");
                }
                if (bit_is_set(trie.bitmap, bit++)) {
                    break;
                }
                if (label >= trie.labels.size() || next_child >= node_count) {
                    fail(std::string(context) + " trie has more edges than labels");
                }
                ++label;
                ++next_child;
                ++children;
            }
            trie.child_count[node] = static_cast<std::uint32_t>(children);
        }
        if (label != trie.labels.size() || next_child != node_count) {
            fail(std::string(context) + " trie edge count is inconsistent");
        }
        if (any_bits_set_from(trie.bitmap, bit)) {
            fail(std::string(context) + " trie label bitmap has non-zero padding");
        }
        if (any_bits_set_from(trie.leaves, node_count)) {
            fail(std::string(context) + " trie leaves bitmap has non-zero padding");
        }
        return trie;
    }

    RuleExtraction read_domain_matcher(std::string_view context) {
        const auto trie = read_trie(context);
        std::vector<std::string> exact_domains;
        std::vector<std::string> legacy_prefixes;
        std::vector<std::string> root_suffixes;

        struct Frame {
            std::uint32_t node = 0;
            std::uint32_t next = 0;
            bool visited = false;
        };
        std::vector<Frame> stack;
        stack.push_back(Frame{});
        std::string reversed_key;

        while (!stack.empty()) {
            auto& frame = stack.back();
            if (!frame.visited) {
                frame.visited = true;
                if (bit_is_set(trie.leaves, frame.node)) {
                    if (reversed_key.empty()) {
                        fail(std::string(context) + " trie contains an empty key");
                    }
                    const auto key = reverse_utf8_codepoints(reversed_key);
                    account_output(1);
                    account_output_string_bytes(key.size());
                    if (key.front() == kDomainPrefixLabel) {
                        const auto value = key.substr(1);
                        validate_domain_text(value);
                        legacy_prefixes.push_back(value);
                    } else if (key.front() == kDomainRootLabel) {
                        const auto value = key.substr(1);
                        validate_domain_text(value);
                        root_suffixes.push_back(value);
                    } else {
                        validate_domain_text(key);
                        exact_domains.push_back(key);
                    }
                }
            }

            if (frame.next < trie.child_count[frame.node]) {
                const std::size_t child =
                    static_cast<std::size_t>(trie.first_child[frame.node]) + frame.next;
                ++frame.next;
                if (reversed_key.size() >= limits_.max_string_bytes) {
                    fail(std::string(context) + " trie key exceeds string limit");
                }
                reversed_key.push_back(static_cast<char>(trie.labels[child - 1U]));
                stack.push_back(Frame{static_cast<std::uint32_t>(child), 0, false});
                continue;
            }

            stack.pop_back();
            if (!stack.empty()) {
                reversed_key.pop_back();
            }
        }

        sort_unique(exact_domains);
        sort_unique(legacy_prefixes);
        sort_unique(root_suffixes);

        std::vector<std::string> promoted_suffix_roots;
        for (const auto& raw_prefix : legacy_prefixes) {
            if (raw_prefix.size() > 1U && raw_prefix.front() == '.') {
                const auto root = raw_prefix.substr(1);
                if (std::binary_search(
                        exact_domains.begin(), exact_domains.end(), root)) {
                    promoted_suffix_roots.push_back(root);
                    root_suffixes.push_back(root);
                    continue;
                }
            }
            // prefixLabel without a matching exact root means
            // "subdomains only". keen-pbr lists intentionally normalize
            // suffixes to include the root, so importing it would broaden the
            // match. Keep the rest of the destination alternatives and omit
            // this one.
            ++result_.unsupported_fields;
        }
        sort_unique(promoted_suffix_roots);
        std::size_t destination = 0;
        for (std::size_t source = 0; source < exact_domains.size(); ++source) {
            const auto& domain = exact_domains[source];
            if (!std::binary_search(promoted_suffix_roots.begin(),
                                    promoted_suffix_roots.end(),
                                    domain)) {
                if (destination != source) {
                    exact_domains[destination] =
                        std::move(exact_domains[source]);
                }
                ++destination;
            }
        }
        exact_domains.resize(destination);

        RuleExtraction extraction;
        extraction.domains = std::move(exact_domains);
        sort_unique(root_suffixes);
        extraction.suffixes = std::move(root_suffixes);
        return extraction;
    }

    std::vector<std::string> read_ip_set(std::string_view context, bool extract) {
        const auto set_version = reader_.read_byte(std::string(context) + " set version");
        if (set_version != 1) {
            fail(std::string(context) + " uses unsupported IP set version " +
                 std::to_string(set_version));
        }
        const auto range_count =
            checked_size(read_be_u64(std::string(context) + " range count"),
                         limits_.max_ip_ranges,
                         std::string(context) + " range count");
        account_values(range_count, context);

        std::vector<std::string> cidrs;
        IpAddress previous_end;
        bool has_previous = false;
        for (std::size_t index = 0; index < range_count; ++index) {
            const auto item = std::string(context) + " range[" + std::to_string(index) + "]";
            auto from = read_address(item + " start");
            const auto to = read_address(item + " end");
            if (from.size != to.size) {
                fail(item + " mixes IPv4 and IPv6");
            }
            if (address_less(to, from)) {
                fail(item + " ends before it starts");
            }
            if (has_previous) {
                if (previous_end.size > from.size ||
                    (previous_end.size == from.size && !address_less(previous_end, from))) {
                    fail(item + " is not strictly ordered");
                }
            }
            previous_end = to;
            has_previous = true;

            if (!extract) {
                continue;
            }
            while (!address_less(to, from)) {
                const std::size_t address_bits = static_cast<std::size_t>(from.size) * 8U;
                std::size_t host_bits = address_trailing_zero_bits(from);
                while (host_bits > 0U && address_less(to, block_end(from, host_bits))) {
                    --host_bits;
                }
                const auto end = block_end(from, host_bits);
                const auto cidr =
                    format_address(from) + "/" +
                    std::to_string(address_bits - host_bits);
                account_output(1);
                account_output_string_bytes(cidr.size());
                cidrs.push_back(cidr);
                if (address_equal(end, to)) {
                    break;
                }
                from = end;
                if (!increment_address(from)) {
                    fail(item + " overflows while converting to CIDRs");
                }
            }
        }
        return cidrs;
    }

    void skip_interface_address_map(std::string_view context) {
        const auto count = read_count(256, std::string(context) + " map size");
        account_values(count, context);
        std::array<bool, 256> seen{};
        for (std::size_t index = 0; index < count; ++index) {
            const auto key = reader_.read_byte(std::string(context) + " key");
            if (seen[key]) {
                fail(std::string(context) + " contains a duplicate interface type");
            }
            seen[key] = true;
            const auto prefix_count =
                read_count(limits_.max_values,
                           std::string(context) + " prefix count");
            account_values(prefix_count, context);
            for (std::size_t prefix = 0; prefix < prefix_count; ++prefix) {
                skip_prefix(std::string(context) + " prefix[" +
                            std::to_string(prefix) + "]");
            }
        }
    }

    void skip_prefix_list(std::string_view context) {
        const auto count =
            read_count(limits_.max_values, std::string(context) + " prefix count");
        account_values(count, context);
        for (std::size_t index = 0; index < count; ++index) {
            skip_prefix(std::string(context) + "[" + std::to_string(index) + "]");
        }
    }

    void require_item_version(std::uint8_t minimum,
                              std::string_view item,
                              std::string_view context) const {
        if (version_ < minimum) {
            fail(std::string(context) + " contains " + std::string(item) +
                 " which requires SRS v" + std::to_string(minimum));
        }
    }

    RuleExtraction read_default_rule(std::string_view context) {
        std::array<bool, 256> seen{};
        RuleExtraction extracted;
        std::size_t supported_destination_fields = 0;
        std::size_t blocking_constraints = 0;
        std::size_t item_count = 0;
        bool has_condition = false;

        for (;;) {
            const auto raw_item = reader_.read_byte(std::string(context) + " item type");
            if (raw_item == static_cast<std::uint8_t>(RuleItem::Final)) {
                const bool invert = read_bool(std::string(context) + " invert");
                if (invert) {
                    ++result_.inverted_rules;
                    ++result_.skipped_rules;
                    return {};
                }
                const bool has_extracted_destination =
                    !extracted.domains.empty() || !extracted.suffixes.empty() ||
                    !extracted.cidrs.empty();
                if (!has_condition || blocking_constraints != 0 ||
                    supported_destination_fields == 0 ||
                    !has_extracted_destination) {
                    ++result_.skipped_rules;
                    return {};
                }
                return extracted;
            }
            if (++item_count > limits_.max_rule_items) {
                fail(std::string(context) + " item count exceeds limit");
            }
            if (seen[raw_item]) {
                fail(std::string(context) + " contains duplicate item type " +
                     std::to_string(raw_item));
            }
            seen[raw_item] = true;
            has_condition = true;

            const auto item = static_cast<RuleItem>(raw_item);
            const auto field = std::string(context) + " item " + std::to_string(raw_item);
            switch (item) {
            case RuleItem::Domain:
                {
                    auto domains = read_domain_matcher(field);
                    append_move(extracted.domains, domains.domains);
                    append_move(extracted.suffixes, domains.suffixes);
                }
                ++supported_destination_fields;
                break;
            case RuleItem::IpCidr:
                {
                    auto cidrs = read_ip_set(field, true);
                    append_move(extracted.cidrs, cidrs);
                }
                ++supported_destination_fields;
                break;
            case RuleItem::QueryType:
                skip_u16_list(field);
                ++blocking_constraints;
                break;
            case RuleItem::Network:
            case RuleItem::SourcePortRange:
            case RuleItem::PortRange:
            case RuleItem::ProcessName:
            case RuleItem::ProcessPath:
            case RuleItem::PackageName:
            case RuleItem::WifiSsid:
            case RuleItem::WifiBssid:
            case RuleItem::ProcessPathRegex:
                skip_string_list(field);
                ++blocking_constraints;
                break;
            case RuleItem::DomainKeyword:
            case RuleItem::DomainRegex:
                // Domain matchers share one OR group in sing-box. Omitting an
                // unrepresentable alternative narrows the list but never
                // broadens it, so exact domains and suffixes remain safe.
                skip_string_list(field);
                break;
            case RuleItem::PackageNameRegex:
                require_item_version(5, "package_name_regex", context);
                skip_string_list(field);
                ++blocking_constraints;
                break;
            case RuleItem::SourceIpCidr:
                (void)read_ip_set(field, false);
                ++blocking_constraints;
                break;
            case RuleItem::SourcePort:
            case RuleItem::Port:
                skip_u16_list(field);
                ++blocking_constraints;
                break;
            case RuleItem::AdGuardDomain:
                require_item_version(2, "adguard_domain", context);
                (void)read_trie(field);
                // Same destination-address OR group as domain/regex.
                break;
            case RuleItem::NetworkType:
                require_item_version(3, "network_type", context);
                skip_u8_list(field);
                ++blocking_constraints;
                break;
            case RuleItem::NetworkIsExpensive:
                require_item_version(3, "network_is_expensive", context);
                ++blocking_constraints;
                break;
            case RuleItem::NetworkIsConstrained:
                require_item_version(3, "network_is_constrained", context);
                ++blocking_constraints;
                break;
            case RuleItem::NetworkInterfaceAddress:
                require_item_version(4, "network_interface_address", context);
                skip_interface_address_map(field);
                ++blocking_constraints;
                break;
            case RuleItem::DefaultInterfaceAddress:
                require_item_version(4, "default_interface_address", context);
                skip_prefix_list(field);
                ++blocking_constraints;
                break;
            default:
                fail(std::string(context) + " contains unknown rule item type " +
                     std::to_string(raw_item));
            }
            ++result_.unsupported_fields;
            if (item == RuleItem::Domain || item == RuleItem::IpCidr) {
                --result_.unsupported_fields;
            }
        }
    }

    RuleExtraction read_logical_rule(std::size_t depth, std::string_view context) {
        const auto mode = reader_.read_byte(std::string(context) + " logical mode");
        if (mode > 1U) {
            fail(std::string(context) + " has unknown logical mode " +
                 std::to_string(mode));
        }
        const auto child_count =
            read_count(limits_.max_rules, std::string(context) + " child count");
        if (child_count == 0) {
            fail(std::string(context) + " has no child rules");
        }

        RuleExtraction combined;
        for (std::size_t index = 0; index < child_count; ++index) {
            auto child = read_rule(depth + 1U,
                                   std::string(context) + ".rules[" +
                                       std::to_string(index) + "]");
            if (mode == 1U || child_count == 1U) {
                append_move(combined.domains, child.domains);
                append_move(combined.suffixes, child.suffixes);
                append_move(combined.cidrs, child.cidrs);
            }
        }
        const bool invert = read_bool(std::string(context) + " invert");
        if (invert) {
            ++result_.inverted_rules;
            ++result_.skipped_rules;
            return {};
        }
        if (mode == 0U && child_count != 1U) {
            ++result_.skipped_rules;
            return {};
        }
        return combined;
    }

    RuleExtraction read_rule(std::size_t depth, std::string_view context) {
        if (depth > limits_.max_logical_depth) {
            fail(std::string(context) + " exceeds logical nesting limit");
        }
        if (total_rules_ >= limits_.max_rules) {
            fail("SRS total rule count exceeds limit");
        }
        ++total_rules_;
        const auto type = reader_.read_byte(std::string(context) + " type");
        if (type == 0U) {
            return read_default_rule(context);
        }
        if (type == 1U) {
            return read_logical_rule(depth, context);
        }
        fail(std::string(context) + " has unknown rule type " + std::to_string(type));
    }

    static void sort_unique(std::vector<std::string>& values) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    }

    InflateReader& reader_;
    const SrsDecodeLimits& limits_;
    std::uint8_t version_;
    SrsDecodeResult result_;
    std::size_t total_rules_ = 0;
    std::size_t total_values_ = 0;
    std::size_t total_string_bytes_ = 0;
    std::size_t decoded_output_entries_ = 0;
    std::size_t decoded_output_string_bytes_ = 0;
};

} // namespace

SrsDecodeResult decode_srs(std::istream& input, const SrsDecodeLimits& limits) {
    std::array<std::uint8_t, 4> header{};
    input.read(reinterpret_cast<char*>(header.data()),
               static_cast<std::streamsize>(header.size()));
    if (input.gcount() != static_cast<std::streamsize>(header.size())) {
        fail("SRS header is truncated");
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin())) {
        fail("invalid SRS magic");
    }
    const auto version = header[3];
    if (version < kMinVersion) {
        fail("invalid SRS version " + std::to_string(version) +
             " (supported: 1-5)");
    }
    if (version > kMaxVersion) {
        throw SrsDecodeError(
            "unsupported SRS version " + std::to_string(version) +
                " (supported: 1-5)",
            SrsDecodeErrorKind::UnsupportedVersion,
            version);
    }
    if (limits.max_compressed_bytes == 0 || limits.max_decompressed_bytes == 0 ||
        limits.max_rules == 0 || limits.max_logical_depth == 0 ||
        limits.max_rule_items == 0 || limits.max_values == 0 ||
        limits.max_string_bytes == 0 || limits.max_total_string_bytes == 0 ||
        limits.max_trie_words == 0 || limits.max_trie_labels == 0 ||
        limits.max_trie_nodes == 0 || limits.max_ip_ranges == 0 ||
        limits.max_output_entries == 0 ||
        limits.max_output_string_bytes == 0) {
        fail("SRS decode limits must be greater than zero");
    }
    if (limits.max_trie_nodes >
        static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        fail("SRS trie node limit exceeds decoder index range");
    }

    InflateReader compressed(input, limits);
    Decoder decoder(compressed, limits, version);
    return decoder.decode();
}

SrsDecodeResult decode_srs_file(const std::filesystem::path& path,
                                const SrsDecodeLimits& limits) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        fail("failed to open SRS file: " + path.string());
    }
    try {
        return decode_srs(input, limits);
    } catch (const SrsDecodeError& error) {
        throw SrsDecodeError(
            "failed to decode SRS file '" + path.string() + "': " + error.what(),
            error.kind(),
            error.version());
    }
}

} // namespace keen_pbr3
