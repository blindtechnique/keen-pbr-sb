#include "nfqws_rotator_state.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <limits>
#include <set>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::uint32_t kMaxSlot = 4096U;
constexpr std::uint32_t kMaxPendingFailures = 65535U;
constexpr std::size_t kMaxPoolKeyBytes = 128U;
constexpr std::int64_t kMaxFutureSkewSeconds = 5;
constexpr std::size_t kMaxProcStatSize = 4096U;

class FileDescriptor {
public:
    explicit FileDescriptor(int descriptor = -1) noexcept
        : descriptor_(descriptor) {}
    ~FileDescriptor() {
        if (descriptor_ >= 0) ::close(descriptor_);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    int get() const noexcept { return descriptor_; }
    explicit operator bool() const noexcept { return descriptor_ >= 0; }

private:
    int descriptor_;
};

std::optional<std::string> read_descriptor_bounded(int descriptor,
                                                   std::size_t limit) {
    std::string content;
    content.reserve(std::min<std::size_t>(limit, 4096U));
    std::array<char, 4096U> buffer{};
    for (;;) {
        const auto count = ::read(descriptor, buffer.data(), buffer.size());
        if (count == 0) return content;
        if (count < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        const auto added = static_cast<std::size_t>(count);
        if (added > limit - content.size()) return std::nullopt;
        content.append(buffer.data(), added);
    }
}

std::vector<std::string_view> split_exact(std::string_view input,
                                          char delimiter) {
    std::vector<std::string_view> result;
    std::size_t start = 0;
    while (start <= input.size()) {
        const auto end = input.find(delimiter, start);
        result.push_back(input.substr(
            start, end == std::string_view::npos ? input.size() - start
                                                 : end - start));
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return result;
}

template <typename Integer>
bool parse_integer(std::string_view value, Integer& output,
                   Integer minimum, Integer maximum) {
    if (value.empty()) return false;
    Integer parsed{};
    const auto converted = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (converted.ec != std::errc{} ||
        converted.ptr != value.data() + value.size() ||
        parsed < minimum || parsed > maximum) {
        return false;
    }
    output = parsed;
    return true;
}

bool checked_add(std::uint64_t& total, std::uint64_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max() - total) {
        return false;
    }
    total += value;
    return true;
}

bool decode_hex_key(std::string_view encoded, std::string& decoded) {
    if (encoded.empty() || encoded.size() > kMaxPoolKeyBytes * 2U ||
        encoded.size() % 2U != 0U) {
        return false;
    }
    decoded.clear();
    decoded.reserve(encoded.size() / 2U);
    for (std::size_t index = 0; index < encoded.size(); index += 2U) {
        unsigned int byte = 0;
        const auto converted = std::from_chars(
            encoded.data() + index, encoded.data() + index + 2U, byte, 16);
        if (converted.ec != std::errc{} ||
            converted.ptr != encoded.data() + index + 2U ||
            byte < 0x21U || byte > 0x7eU) {
            return false;
        }
        decoded.push_back(static_cast<char>(byte));
    }
    return !decoded.empty();
}

bool parse_histogram(std::string_view text,
                     std::uint32_t maximum_value,
                     std::map<std::uint32_t, std::uint64_t>& histogram,
                     std::uint64_t& total) {
    histogram.clear();
    total = 0;
    if (text.empty()) return false;
    const auto entries = split_exact(text, ',');
    if (entries.empty() || entries.size() > kMaxNfqwsRotatorTargets) {
        return false;
    }
    for (const auto entry : entries) {
        const auto equals = entry.find('=');
        if (equals == std::string_view::npos || equals == 0U ||
            equals + 1U >= entry.size() ||
            entry.find('=', equals + 1U) != std::string_view::npos) {
            return false;
        }
        std::uint32_t value = 0;
        std::uint64_t count = 0;
        if (!parse_integer<std::uint32_t>(
                entry.substr(0, equals), value, 0U, maximum_value) ||
            !parse_integer<std::uint64_t>(
                entry.substr(equals + 1U), count, 1U,
                kMaxNfqwsRotatorTargets) ||
            histogram.count(value) != 0U || !checked_add(total, count) ||
            total > kMaxNfqwsRotatorTargets) {
            return false;
        }
        histogram.emplace(value, count);
    }
    return true;
}

std::optional<std::uint32_t> unanimous_value(
    const std::map<std::uint32_t, std::uint64_t>& histogram) noexcept {
    if (histogram.size() != 1U) return std::nullopt;
    return histogram.begin()->first;
}

} // namespace

std::optional<std::uint32_t>
NfqwsRotatorPoolState::unanimous_slot() const noexcept {
    return unanimous_value(slot_histogram);
}

std::optional<std::uint32_t>
NfqwsRotatorPoolState::unanimous_slot_count() const noexcept {
    return unanimous_value(slot_count_histogram);
}

std::optional<std::uint32_t>
NfqwsRotatorPoolState::unanimous_pending_failures() const noexcept {
    return unanimous_value(pending_failure_histogram);
}

std::uint32_t NfqwsRotatorPoolState::max_pending_failures() const noexcept {
    return pending_failure_histogram.empty()
               ? 0U
               : pending_failure_histogram.rbegin()->first;
}

NfqwsRotatorSnapshotParseResult parse_nfqws_rotator_snapshot(
    const std::string& content) {
    const auto reject = [](std::string message) {
        return NfqwsRotatorSnapshotParseResult{
            std::nullopt, std::move(message)};
    };
    if (content.empty() || content.size() > kMaxNfqwsRotatorSnapshotSize) {
        return reject("snapshot is empty or too large");
    }

    std::vector<std::string_view> lines;
    std::size_t start = 0;
    while (start < content.size()) {
        const auto end = content.find('\n', start);
        auto line = std::string_view(content).substr(
            start, end == std::string::npos ? content.size() - start
                                            : end - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1U);
        if (line.empty()) return reject("snapshot contains an empty line");
        lines.push_back(line);
        if (end == std::string::npos) break;
        start = end + 1U;
    }
    if (lines.size() < 2U || lines.size() > kMaxNfqwsRotatorPools + 2U) {
        return reject("snapshot has an invalid line count");
    }

    const auto header = split_exact(lines.front(), '\t');
    if (header.size() != 6U || header[0] != "V1") {
        return reject("snapshot header is invalid");
    }
    NfqwsRotatorSnapshot snapshot;
    std::int64_t pid = 0;
    std::uint32_t truncated = 0;
    if (!parse_integer<std::uint64_t>(
            header[1], snapshot.sequence, 1U,
            std::numeric_limits<std::uint64_t>::max()) ||
        !parse_integer<std::int64_t>(
            header[2], pid, 1,
            static_cast<std::int64_t>(std::numeric_limits<int>::max())) ||
        !parse_integer<std::uint64_t>(
            header[3], snapshot.generation.start_ticks, 1U,
            static_cast<std::uint64_t>(9007199254740991ULL)) ||
        !parse_integer<std::int64_t>(
            header[4], snapshot.observed_at_unix, 1,
            std::numeric_limits<std::int64_t>::max()) ||
        !parse_integer<std::uint32_t>(header[5], truncated, 0U, 1U)) {
        return reject("snapshot header values are invalid");
    }
    snapshot.generation.pid = pid;
    snapshot.truncated = truncated != 0U;

    std::set<std::string> keys;
    std::uint64_t tracked_total = 0;
    for (std::size_t index = 1U; index + 1U < lines.size(); ++index) {
        const auto fields = split_exact(lines[index], '\t');
        if (fields.size() != 6U || fields[0] != "P") {
            return reject("snapshot pool line is invalid");
        }
        NfqwsRotatorPoolState pool;
        if (!decode_hex_key(fields[1], pool.key) ||
            !keys.insert(pool.key).second ||
            !parse_integer<std::uint64_t>(
                fields[2], pool.tracked_targets, 1U,
                kMaxNfqwsRotatorTargets)) {
            return reject("snapshot pool identity is invalid");
        }
        std::uint64_t slot_total = 0;
        std::uint64_t slot_count_total = 0;
        std::uint64_t failure_total = 0;
        if (!parse_histogram(
                fields[3], kMaxSlot, pool.slot_histogram, slot_total) ||
            pool.slot_histogram.begin()->first == 0U ||
            !parse_histogram(
                fields[4], kMaxSlot, pool.slot_count_histogram,
                slot_count_total) ||
            pool.slot_count_histogram.begin()->first == 0U ||
            !parse_histogram(
                fields[5], kMaxPendingFailures,
                pool.pending_failure_histogram, failure_total) ||
            slot_total != pool.tracked_targets ||
            slot_count_total != pool.tracked_targets ||
            failure_total != pool.tracked_targets ||
            !checked_add(tracked_total, pool.tracked_targets) ||
            tracked_total > kMaxNfqwsRotatorTargets) {
            return reject("snapshot pool histograms are invalid");
        }
        snapshot.pools.push_back(std::move(pool));
    }

    const auto footer = split_exact(lines.back(), '\t');
    std::uint64_t footer_sequence = 0;
    std::uint64_t footer_pools = 0;
    std::uint64_t footer_targets = 0;
    if (footer.size() != 4U || footer[0] != "END" ||
        !parse_integer<std::uint64_t>(
            footer[1], footer_sequence, 1U,
            std::numeric_limits<std::uint64_t>::max()) ||
        !parse_integer<std::uint64_t>(
            footer[2], footer_pools, 0U, kMaxNfqwsRotatorPools) ||
        !parse_integer<std::uint64_t>(
            footer[3], footer_targets, 0U,
            kMaxNfqwsRotatorTargets) ||
        footer_sequence != snapshot.sequence ||
        footer_pools != snapshot.pools.size() ||
        footer_targets != tracked_total) {
        return reject("snapshot footer is invalid");
    }
    return {std::move(snapshot), {}};
}

std::optional<NfqwsProcessGeneration> parse_nfqws_process_stat(
    std::string_view content, std::int64_t expected_pid) noexcept {
    if (content.empty() || content.size() > kMaxProcStatSize ||
        expected_pid <= 0) {
        return std::nullopt;
    }
    const auto first_space = content.find(' ');
    if (first_space == std::string_view::npos) return std::nullopt;
    std::int64_t parsed_pid = 0;
    if (!parse_integer<std::int64_t>(
            content.substr(0, first_space), parsed_pid, 1,
            static_cast<std::int64_t>(std::numeric_limits<int>::max())) ||
        parsed_pid != expected_pid) {
        return std::nullopt;
    }

    const auto comm_begin = content.find('(', first_space + 1U);
    const auto comm_end = content.rfind(')');
    if (comm_begin == std::string_view::npos ||
        comm_end == std::string_view::npos || comm_end <= comm_begin) {
        return std::nullopt;
    }

    std::istringstream fields{
        std::string(content.substr(comm_end + 1U))};
    std::string field;
    for (std::size_t index = 0; index < 20U; ++index) {
        if (!(fields >> field)) return std::nullopt;
    }
    std::uint64_t start_ticks = 0;
    if (!parse_integer<std::uint64_t>(
            field, start_ticks, 1U,
            static_cast<std::uint64_t>(9007199254740991ULL))) {
        return std::nullopt;
    }
    return NfqwsProcessGeneration{parsed_pid, start_ticks};
}

std::optional<NfqwsProcessGeneration> read_nfqws_process_generation(
    std::int64_t pid, const std::string& proc_root) {
    if (pid <= 0 || proc_root.empty()) return std::nullopt;
    const auto path = proc_root + "/" + std::to_string(pid) + "/stat";
    FileDescriptor descriptor(::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (!descriptor) return std::nullopt;
    struct stat metadata {};
    if (::fstat(descriptor.get(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode)) {
        return std::nullopt;
    }
    const auto content =
        read_descriptor_bounded(descriptor.get(), kMaxProcStatSize);
    return content.has_value()
               ? parse_nfqws_process_stat(*content, pid)
               : std::nullopt;
}

std::vector<std::string> read_nfqws_rotator_snapshot_candidates(
    const std::string& directory) {
    std::vector<std::string> result;
    FileDescriptor directory_descriptor(::open(
        directory.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_DIRECTORY));
    if (!directory_descriptor) return result;

    struct stat directory_metadata {};
    if (::fstat(directory_descriptor.get(), &directory_metadata) != 0 ||
        !S_ISDIR(directory_metadata.st_mode) ||
        (directory_metadata.st_mode & 0022) != 0) {
        return result;
    }

    for (const auto* name : {"rotator-state.0", "rotator-state.1"}) {
        FileDescriptor descriptor(::openat(
            directory_descriptor.get(), name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (!descriptor) continue;

        struct stat before {};
        if (::fstat(descriptor.get(), &before) != 0 ||
            !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
            (before.st_mode & 0022) != 0 || before.st_size <= 0 ||
            static_cast<std::uint64_t>(before.st_size) >
                kMaxNfqwsRotatorSnapshotSize) {
            continue;
        }
        auto content = read_descriptor_bounded(
            descriptor.get(), kMaxNfqwsRotatorSnapshotSize);
        if (!content.has_value()) continue;

        struct stat after {};
        if (::fstat(descriptor.get(), &after) != 0 ||
            before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            before.st_size != after.st_size ||
            before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
            before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
            !S_ISREG(after.st_mode) || after.st_nlink != 1 ||
            (after.st_mode & 0022) != 0 || after.st_size <= 0 ||
            static_cast<std::uint64_t>(after.st_size) >
                kMaxNfqwsRotatorSnapshotSize ||
            content->size() != static_cast<std::size_t>(after.st_size)) {
            continue;
        }
        result.push_back(std::move(*content));
    }
    return result;
}

const char* nfqws_rotator_state_status_name(
    NfqwsRotatorStateStatus status) noexcept {
    switch (status) {
    case NfqwsRotatorStateStatus::ready:
        return "ready";
    case NfqwsRotatorStateStatus::warming_up:
        return "warming";
    case NfqwsRotatorStateStatus::stale:
        return "stale";
    case NfqwsRotatorStateStatus::unsupported:
    default:
        return "unsupported";
    }
}

NfqwsRotatorStateView select_nfqws_rotator_state(
    const NfqwsRotatorStateSelection& selection) {
    if (!selection.reporter_expected) {
        return {NfqwsRotatorStateStatus::unsupported, std::nullopt};
    }
    if (!selection.process_generation.has_value()) {
        return {NfqwsRotatorStateStatus::stale, std::nullopt};
    }

    std::optional<NfqwsRotatorSnapshot> selected;
    for (const auto& content : selection.snapshot_candidates) {
        auto parsed = parse_nfqws_rotator_snapshot(content);
        if (!parsed.snapshot.has_value() ||
            parsed.snapshot->generation != *selection.process_generation ||
            parsed.snapshot->observed_at_unix >
                selection.now_unix + kMaxFutureSkewSeconds) {
            continue;
        }
        if (!selected.has_value() ||
            parsed.snapshot->sequence > selected->sequence) {
            selected = std::move(parsed.snapshot);
        }
    }

    if (!selected.has_value()) {
        return {selection.process_age_seconds <= selection.warming_seconds
                    ? NfqwsRotatorStateStatus::warming_up
                    : NfqwsRotatorStateStatus::stale,
                std::nullopt};
    }
    const auto age = selection.now_unix >= selected->observed_at_unix
                         ? static_cast<std::uint64_t>(
                               selection.now_unix - selected->observed_at_unix)
                         : 0U;
    return {age <= selection.stale_seconds
                ? NfqwsRotatorStateStatus::ready
                : NfqwsRotatorStateStatus::stale,
            std::move(selected)};
}

} // namespace keen_pbr3
