#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

enum class LogTailState { unavailable, within_limit, compacted, failed };
struct LogTailResult {
    LogTailState state{LogTailState::unavailable};
    std::uintmax_t observed_size{0U};
    int error_number{0};
};

// Keep recent bytes on the same inode, including for an external O_APPEND
// writer. As with copytruncate, writes concurrent with compaction can be lost;
// this is bounded best-effort diagnostics, not a lossless audit stream.
// No replacement path is followed and no absent file is created.
inline LogTailResult compact_log_tail(const std::string& path,
                                     std::uintmax_t maximum_bytes,
                                     std::uintmax_t retained_bytes) noexcept {
    const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {LogTailState::unavailable, 0U, errno};
    struct CloseFd {
        int fd;
        ~CloseFd() { (void)::close(fd); }
    } descriptor{fd};
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        return {LogTailState::unavailable, 0U, errno};
    }
    if (!S_ISREG(info.st_mode) || info.st_size < 0 || maximum_bytes == 0U ||
        retained_bytes == 0U || retained_bytes > maximum_bytes) {
        return {LogTailState::unavailable, 0U, EINVAL};
    }
    const auto size = static_cast<std::uintmax_t>(info.st_size);
    if (size <= maximum_bytes) return {LogTailState::within_limit, size, 0};
    const auto retain = std::min(size, retained_bytes);
    auto source = static_cast<off_t>(size - retain);
    off_t destination = 0;
    std::array<char, 64U * 1024U> buffer{};
    // Avoid a partial first record when the retained region contains complete
    // lines; a single oversized line still retains its bounded recent tail.
    bool first = true;
    while (source < info.st_size) {
        const auto want = static_cast<std::size_t>(std::min<std::uintmax_t>(
            buffer.size(), static_cast<std::uintmax_t>(info.st_size - source)));
        const auto count = ::pread(fd, buffer.data(), want, source);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return {LogTailState::failed, size, count < 0 ? errno : EIO};
        std::size_t begin = 0U;
        if (first) {
            char previous = '\n';
            if (source > 0 && ::pread(fd, &previous, 1U, source - 1) == 1 &&
                previous != '\n') {
                const auto newline = std::find(buffer.begin(), buffer.begin() + count, '\n');
                if (newline != buffer.begin() + count && newline + 1 != buffer.begin() + count) {
                    begin = static_cast<std::size_t>(newline - buffer.begin()) + 1U;
                } else {
                    while (begin < static_cast<std::size_t>(count) &&
                           (static_cast<unsigned char>(buffer[begin]) & 0xc0U) == 0x80U) ++begin;
                }
            }
            first = false;
        }
        auto written = begin;
        while (written < static_cast<std::size_t>(count)) {
            const auto copied = ::pwrite(fd, buffer.data() + written,
                                        static_cast<std::size_t>(count) - written,
                                        destination);
            if (copied < 0 && errno == EINTR) continue;
            if (copied <= 0) return {LogTailState::failed, size, copied < 0 ? errno : EIO};
            written += static_cast<std::size_t>(copied);
            destination += copied;
        }
        source += count;
    }
    if (::ftruncate(fd, destination) != 0) return {LogTailState::failed, size, errno};
    return {LogTailState::compacted, size, 0};
}

// Only the timestamp forms written by keen-pbr and nfqws auto-hostlist logs.
// Unknown dates, clock-normalized invalid dates and future records are kept.
inline bool log_record_expired(std::string_view line, std::time_t cutoff) noexcept {
    if (line.size() < 20U ||
        (line[19] != ' ' && line[19] != '\t' && line[19] != '.')) return false;
    const bool iso = line[4] == '-' && line[7] == '-';
    const bool european = line[2] == '.' && line[5] == '.';
    if ((!iso && !european) || line[10] != ' ' || line[13] != ':' || line[16] != ':') return false;
    auto digits = [&](std::size_t at, std::size_t count) {
        int result = 0;
        for (std::size_t n = 0; n < count; ++n) {
            const char value = line[at + n];
            if (value < '0' || value > '9') return -1;
            result = result * 10 + value - '0';
        }
        return result;
    };
    const int year = digits(iso ? 0U : 6U, 4U);
    const int month = digits(iso ? 5U : 3U, 2U);
    const int day = digits(iso ? 8U : 0U, 2U);
    const int hour = digits(11U, 2U);
    const int minute = digits(14U, 2U);
    const int second = digits(17U, 2U);
    if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) return false;
    std::tm date{};
    date.tm_year = year - 1900; date.tm_mon = month - 1; date.tm_mday = day;
    date.tm_hour = hour; date.tm_min = minute; date.tm_sec = second; date.tm_isdst = -1;
    const auto timestamp = std::mktime(&date);
    if (timestamp == static_cast<std::time_t>(-1) || date.tm_year != year - 1900 ||
        date.tm_mon != month - 1 || date.tm_mday != day || date.tm_hour != hour ||
        date.tm_min != minute || date.tm_sec != second) return false;
    return timestamp < cutoff;
}

// Streams records through fixed buffers. Untimestamped lines are deliberately
// preserved, rather than guessing their age from the file's mutable mtime.
inline LogTailResult prune_log_age(const std::string& path, std::time_t cutoff) noexcept {
    const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {LogTailState::unavailable, 0U, errno};
    struct CloseFd { int fd; ~CloseFd() { (void)::close(fd); } } descriptor{fd};
    struct stat info{};
    if (::fstat(fd, &info) != 0) return {LogTailState::unavailable, 0U, errno};
    if (!S_ISREG(info.st_mode) || info.st_size < 0) return {LogTailState::unavailable, 0U, EINVAL};
    const auto size = static_cast<std::uintmax_t>(info.st_size);
    std::array<char, 32U * 1024U> input{};
    std::array<char, 32U * 1024U> output{};
    std::array<char, 24U> prefix{};
    std::size_t prefix_size = 0U, output_size = 0U;
    off_t source = 0, destination = 0;
    bool decided = false, keep = true, removed = false;
    auto flush = [&]() {
        std::size_t done = 0U;
        while (done < output_size && removed) {
            const auto count = ::pwrite(fd, output.data() + done, output_size - done, destination + done);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return false;
            done += static_cast<std::size_t>(count);
        }
        destination += static_cast<off_t>(output_size);
        output_size = 0U;
        return true;
    };
    auto emit = [&](char value) {
        output[output_size++] = value;
        return output_size != output.size() || flush();
    };
    while (source < info.st_size) {
        const auto want = static_cast<std::size_t>(std::min<off_t>(input.size(), info.st_size - source));
        const auto count = ::pread(fd, input.data(), want, source);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return {LogTailState::failed, size, count < 0 ? errno : EIO};
        source += count;
        for (ssize_t n = 0; n < count; ++n) {
            const char value = input[static_cast<std::size_t>(n)];
            if (!decided) {
                prefix[prefix_size++] = value;
                if (prefix_size == prefix.size() || value == '\n') {
                    keep = !log_record_expired(std::string_view(prefix.data(), prefix_size), cutoff);
                    if (!keep && !removed) {
                        // Existing bytes before the first deletion need no rewrite.
                        if (!flush()) return {LogTailState::failed, size, errno};
                        removed = true;
                    }
                    if (keep) for (std::size_t p = 0; p < prefix_size; ++p) {
                        if (!emit(prefix[p])) return {LogTailState::failed, size, errno};
                    }
                    decided = true;
                }
            } else if (keep && !emit(value)) return {LogTailState::failed, size, errno};
            if (value == '\n') { decided = false; prefix_size = 0U; }
        }
    }
    // A short/incomplete final line cannot be assigned an age reliably.
    if (!decided) for (std::size_t p = 0; p < prefix_size; ++p) {
        if (!emit(prefix[p])) return {LogTailState::failed, size, errno};
    }
    if (!flush()) return {LogTailState::failed, size, errno};
    if (!removed) return {LogTailState::within_limit, size, 0};
    if (::ftruncate(fd, destination) != 0) return {LogTailState::failed, size, errno};
    return {LogTailState::compacted, size, 0};
}

} // namespace keen_pbr3
