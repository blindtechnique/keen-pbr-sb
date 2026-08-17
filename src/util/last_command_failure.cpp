#include "last_command_failure.hpp"

#include "../config/config_writer.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::string_view kRedacted = "[REDACTED]";
constexpr std::size_t kRedactionLookaheadBytes = 1024U;
constexpr std::size_t kCommandMaxBytes = 16U * 1024U;
constexpr std::size_t kReasonMaxBytes = 4U * 1024U;
constexpr std::size_t kInputMaxBytes = 48U * 1024U;
constexpr std::size_t kResponseMaxBytes = 48U * 1024U;
constexpr std::array<std::string_view, 27> kSecretKeys{{
    "password",
    "passwd",
    "passphrase",
    "password-file",
    "token",
    "access-token",
    "access_token",
    "refresh-token",
    "refresh_token",
    "secret",
    "client-secret",
    "client_secret",
    "api-key",
    "api_key",
    "apikey",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "private-key",
    "private_key",
    "reality-private-key",
    "reality_private_key",
    "pre-shared-key",
    "pre_shared_key",
    "psk",
    "uuid",
}};

class ErrnoGuard {
public:
    ErrnoGuard() noexcept : saved_(errno) {}
    ~ErrnoGuard() { errno = saved_; }

private:
    int saved_;
};

std::mutex& recorder_mutex() {
    static std::mutex mutex;
    return mutex;
}

#ifdef KEEN_PBR3_TESTING
std::optional<std::string>& test_path_override() {
    static std::optional<std::string> value;
    return value;
}

bool& post_commit_failure_enabled() {
    static bool value = false;
    return value;
}
#endif

std::string production_path() {
#ifdef KEEN_PBR_DEFAULT_LOG_FILE
    std::filesystem::path path(KEEN_PBR_DEFAULT_LOG_FILE);
    path.replace_filename("keen-pbr-command-failure.log");
    return path.string();
#else
    return "/var/log/keen-pbr-command-failure.log";
#endif
}

std::string destination_path_locked() {
#ifdef KEEN_PBR3_TESTING
    if (test_path_override().has_value()) {
        return *test_path_override();
    }
#endif
    return production_path();
}

char ascii_lower(char value) {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value - 'A' + 'a');
    }
    return value;
}

bool ascii_iequals(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (ascii_lower(left[index]) != ascii_lower(right[index])) {
            return false;
        }
    }
    return true;
}

bool ascii_imatches_at(std::string_view text,
                       std::size_t offset,
                       std::string_view expected) {
    if (offset > text.size() || expected.size() > text.size() - offset) {
        return false;
    }
    return ascii_iequals(text.substr(offset, expected.size()), expected);
}

bool is_ascii_alnum(char value) {
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9');
}

bool is_key_continuation(char value) {
    return is_ascii_alnum(value) || value == '_' || value == '-';
}

bool is_ascii_space(char value) {
    return value == ' ' || value == '\t' || value == '\n' ||
           value == '\r' || value == '\f' || value == '\v';
}

bool is_secret_key(std::string_view value) {
    while (!value.empty() && value.front() == '-') {
        value.remove_prefix(1);
    }
    return std::any_of(
        kSecretKeys.begin(),
        kSecretKeys.end(),
        [value](std::string_view key) { return ascii_iequals(value, key); });
}

std::size_t saturating_add(std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        return std::numeric_limits<std::size_t>::max();
    }
    return left + right;
}

void redact_uri_userinfo(std::string& text, bool prefix_was_truncated) {
    std::size_t cursor = 0;
    while ((cursor = text.find("://", cursor)) != std::string::npos) {
        const std::size_t userinfo_start = cursor + 3U;
        std::size_t position = userinfo_start;
        bool redacted = false;
        for (; position < text.size(); ++position) {
            const char value = text[position];
            if (value == '@') {
                if (position > userinfo_start) {
                    text.replace(userinfo_start,
                                 position - userinfo_start,
                                 kRedacted);
                    cursor = userinfo_start + kRedacted.size() + 1U;
                    redacted = true;
                }
                break;
            }
            if (value == '/' || value == '?' || value == '#' ||
                is_ascii_space(value)) {
                break;
            }
        }
        if (redacted) continue;

        // If the bounded scan stopped in URL authority, assume credentials
        // rather than exposing a user-info value whose '@' fell just outside
        // the diagnostics budget.
        if (prefix_was_truncated && position == text.size() &&
            userinfo_start < text.size()) {
            text.replace(
                userinfo_start, text.size() - userinfo_start, kRedacted);
            cursor = userinfo_start + kRedacted.size();
            continue;
        }
        cursor = userinfo_start;
    }
}

bool is_value_terminator(char value) {
    switch (value) {
        case '\n':
        case '\r':
        case ',':
        case '&':
        case ';':
        case '}':
        case ']':
            return true;
        default:
            return false;
    }
}

void redact_key_values(std::string& text) {
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        bool replacement_made = false;
        for (const auto key : kSecretKeys) {
            if (!ascii_imatches_at(text, cursor, key)) continue;
            if (cursor > 0 && is_ascii_alnum(text[cursor - 1U])) continue;

            std::size_t after_key = cursor + key.size();
            if (after_key < text.size() &&
                is_key_continuation(text[after_key])) {
                continue;
            }
            if (after_key < text.size() &&
                (text[after_key] == '"' || text[after_key] == '\'')) {
                ++after_key;
            }
            while (after_key < text.size() &&
                   is_ascii_space(text[after_key])) {
                ++after_key;
            }
            if (after_key >= text.size() ||
                (text[after_key] != ':' && text[after_key] != '=')) {
                continue;
            }
            ++after_key;
            while (after_key < text.size() &&
                   is_ascii_space(text[after_key])) {
                ++after_key;
            }

            const std::size_t value_start = after_key;
            std::size_t value_end = value_start;
            if (value_start < text.size() &&
                (text[value_start] == '"' || text[value_start] == '\'')) {
                const char quote = text[value_start];
                const std::size_t quoted_value_start = value_start + 1U;
                value_end = quoted_value_start;
                bool escaped = false;
                while (value_end < text.size()) {
                    const char value = text[value_end];
                    if (value == quote && !escaped) break;
                    if (value == '\\') {
                        escaped = !escaped;
                    } else {
                        escaped = false;
                    }
                    ++value_end;
                }
                text.replace(quoted_value_start,
                             value_end - quoted_value_start,
                             kRedacted);
                cursor = quoted_value_start + kRedacted.size();
            } else {
                while (value_end < text.size() &&
                       !is_value_terminator(text[value_end])) {
                    ++value_end;
                }
                text.replace(value_start, value_end - value_start, kRedacted);
                cursor = value_start + kRedacted.size();
            }
            replacement_made = true;
            break;
        }
        if (!replacement_made) ++cursor;
    }
}

bool is_utf8_continuation(unsigned char value) {
    return (value & 0xC0U) == 0x80U;
}

std::size_t valid_utf8_sequence_length(
    std::string_view text,
    std::size_t offset) {
    const auto lead = static_cast<unsigned char>(text[offset]);
    const std::size_t remaining = text.size() - offset;
    if (lead < 0x80U) return 1U;
    if (lead >= 0xC2U && lead <= 0xDFU) {
        return remaining >= 2U &&
                       is_utf8_continuation(
                           static_cast<unsigned char>(text[offset + 1U]))
                   ? 2U
                   : 0U;
    }
    if (lead >= 0xE0U && lead <= 0xEFU) {
        if (remaining < 3U) return 0U;
        const auto second =
            static_cast<unsigned char>(text[offset + 1U]);
        const auto third =
            static_cast<unsigned char>(text[offset + 2U]);
        if (!is_utf8_continuation(second) ||
            !is_utf8_continuation(third)) {
            return 0U;
        }
        if ((lead == 0xE0U && second < 0xA0U) ||
            (lead == 0xEDU && second >= 0xA0U)) {
            return 0U;
        }
        return 3U;
    }
    if (lead >= 0xF0U && lead <= 0xF4U) {
        if (remaining < 4U) return 0U;
        const auto second =
            static_cast<unsigned char>(text[offset + 1U]);
        if (!is_utf8_continuation(second) ||
            !is_utf8_continuation(
                static_cast<unsigned char>(text[offset + 2U])) ||
            !is_utf8_continuation(
                static_cast<unsigned char>(text[offset + 3U]))) {
            return 0U;
        }
        if ((lead == 0xF0U && second < 0x90U) ||
            (lead == 0xF4U && second >= 0x90U)) {
            return 0U;
        }
        return 4U;
    }
    return 0U;
}

std::string sanitize_text(std::string text) {
    std::string sanitized;
    sanitized.reserve(text.size());
    for (std::size_t offset = 0; offset < text.size();) {
        const char value = text[offset];
        const auto byte = static_cast<unsigned char>(value);
        if (value == '\0') {
            sanitized += "\\0";
            ++offset;
        } else if (byte < 0x20U && value != '\n' && value != '\r' &&
                   value != '\t') {
            sanitized.push_back('?');
            ++offset;
        } else if (byte < 0x80U) {
            sanitized.push_back(value);
            ++offset;
        } else {
            const auto length =
                valid_utf8_sequence_length(text, offset);
            if (length == 0U) {
                sanitized.push_back('?');
                ++offset;
            } else {
                sanitized.append(text, offset, length);
                offset += length;
            }
        }
    }
    return sanitized;
}

std::size_t utf8_prefix_bytes(std::string_view text,
                              std::size_t max_bytes) {
    const std::size_t limit = std::min(text.size(), max_bytes);
    std::size_t offset = 0;
    while (offset < limit) {
        const auto length = valid_utf8_sequence_length(text, offset);
        if (length == 0U || length > limit - offset) break;
        offset += length;
    }
    return offset;
}

std::string truncate_with_marker(std::string value,
                                 std::size_t max_bytes,
                                 std::size_t original_bytes,
                                 bool source_was_truncated) {
    if (!source_was_truncated && value.size() <= max_bytes) return value;

    const std::string marker =
        "\n...[truncated; original_bytes=" +
        std::to_string(original_bytes) + "]\n";
    if (marker.size() >= max_bytes) {
        return marker.substr(0, max_bytes);
    }
    if (value.size() > max_bytes - marker.size()) {
        value.resize(utf8_prefix_bytes(
            value, max_bytes - marker.size()));
    }
    value += marker;
    return value;
}

std::string redact_bounded_text(std::string_view source,
                                std::size_t max_bytes) {
    const std::size_t scan_limit =
        saturating_add(max_bytes, kRedactionLookaheadBytes);
    const std::size_t scanned_bytes = std::min(source.size(), scan_limit);
    const bool prefix_was_truncated = scanned_bytes < source.size();
    std::string redacted(source.substr(0, scanned_bytes));
    redact_uri_userinfo(redacted, prefix_was_truncated);
    redact_key_values(redacted);
    redacted = sanitize_text(std::move(redacted));
    return truncate_with_marker(std::move(redacted),
                                max_bytes,
                                source.size(),
                                prefix_was_truncated);
}

std::string redact_command_argument(std::string_view argument,
                                    bool& redact_next) {
    if (redact_next) {
        redact_next = false;
        return std::string(kRedacted);
    }

    const std::size_t equals = argument.find('=');
    const std::string_view name =
        equals == std::string_view::npos ? argument
                                        : argument.substr(0, equals);
    if (equals != std::string_view::npos && is_secret_key(name)) {
        return std::string(argument.substr(0, equals + 1U)) +
               std::string(kRedacted);
    }
    if (!argument.empty() && argument.front() == '-' &&
        is_secret_key(argument)) {
        redact_next = true;
        return std::string(argument);
    }
    return redact_bounded_text(argument, kCommandMaxBytes);
}

std::string render_command(const std::vector<std::string>& command) {
    std::size_t original_bytes = 0;
    for (std::size_t index = 0; index < command.size(); ++index) {
        if (index != 0) original_bytes = saturating_add(original_bytes, 1U);
        original_bytes =
            saturating_add(original_bytes, command[index].size());
    }

    std::string rendered;
    rendered.reserve(std::min(original_bytes, kCommandMaxBytes));
    bool redact_next = false;
    for (std::size_t index = 0; index < command.size(); ++index) {
        if (index != 0) rendered.push_back(' ');
        rendered += redact_command_argument(command[index], redact_next);
        if (rendered.size() >
            saturating_add(kCommandMaxBytes, kRedactionLookaheadBytes)) {
            break;
        }
    }
    if (rendered.empty()) rendered = "(empty)";
    const bool truncated = rendered.size() > kCommandMaxBytes;
    return truncate_with_marker(std::move(rendered),
                                kCommandMaxBytes,
                                original_bytes,
                                truncated);
}

std::string utc_timestamp() {
    const auto now = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    std::tm timestamp{};
    if (::gmtime_r(&now, &timestamp) == nullptr) {
        return "unknown";
    }
    char buffer[32]{};
    if (std::strftime(buffer,
                      sizeof(buffer),
                      "%Y-%m-%dT%H:%M:%SZ",
                      &timestamp) == 0) {
        return "unknown";
    }
    return buffer;
}

void append_section(std::string& output,
                    std::string_view heading,
                    std::string value) {
    output.append(heading.data(), heading.size());
    output += value;
    if (output.empty() || output.back() != '\n') output.push_back('\n');
}

std::string serialize(const LastCommandFailureView& failure) {
    std::string output;
    output.reserve(kLastCommandFailureMaxBytes);
    output += "=== keen-pbr last command failure ===\n";
    output += "timestamp_utc: " + utc_timestamp() + "\n";
    append_section(output, "command: ", render_command(failure.command));
    output += "exit_code: " + std::to_string(failure.exit_code) + "\n";
    if (!failure.reason.empty()) {
        append_section(output,
                       "reason: ",
                       redact_bounded_text(failure.reason, kReasonMaxBytes));
    }
    output += "stdin_bytes: " + std::to_string(failure.input.size()) +
              "\n--- stdin ---\n";
    append_section(output,
                   "",
                   redact_bounded_text(failure.input, kInputMaxBytes));
    output += "response_bytes: " + std::to_string(failure.response.size()) +
              "\n--- response ---\n";
    append_section(output,
                   "",
                   redact_bounded_text(failure.response, kResponseMaxBytes));
    output += "=== end ===\n";
    if (output.size() > kLastCommandFailureMaxBytes) {
        output.resize(utf8_prefix_bytes(
            output, kLastCommandFailureMaxBytes));
    }
    return output;
}

bool read_all_bounded(int fd,
                      std::size_t expected_size,
                      std::string& output) {
    output.assign(expected_size, '\0');
    std::size_t offset = 0;
    while (offset < expected_size) {
        const ssize_t count =
            ::read(fd, output.data() + offset, expected_size - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

} // namespace

bool write_last_command_failure(
    const LastCommandFailureView& failure) noexcept {
    const ErrnoGuard errno_guard;
    try {
        const std::lock_guard<std::mutex> lock(recorder_mutex());

        bool committed = false;
        AtomicFileWriteOptions options;
        options.file_mode = static_cast<mode_t>(0600);
        options.owner = ::geteuid();
        options.group = ::getegid();
        options.committed_result = &committed;
#ifdef KEEN_PBR3_TESTING
        if (post_commit_failure_enabled()) {
            options.fault_injector = [](AtomicFileWriteStage stage) {
                if (stage == AtomicFileWriteStage::directory_fsync) {
                    throw std::runtime_error(
                        "injected post-commit diagnostics failure");
                }
            };
        }
#endif
        try {
            write_file_atomically(destination_path_locked(),
                                  serialize(failure),
                                  options);
            return true;
        } catch (const AtomicFileWriteError& error) {
            // rename(2) already made the private snapshot visible; a later
            // directory fsync failure must not make diagnostics claim that no
            // record was published.
            return committed || error.committed();
        }
    } catch (...) {
        return false;
    }
}

std::optional<std::string> read_last_command_failure() noexcept {
    const ErrnoGuard errno_guard;
    try {
        const std::lock_guard<std::mutex> lock(recorder_mutex());
        const auto path = destination_path_locked();

        const int fd = ::open(
            path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return std::nullopt;

        struct stat before {};
        if (::fstat(fd, &before) != 0 ||
            !S_ISREG(before.st_mode) ||
            before.st_size < 0 ||
            static_cast<std::uint64_t>(before.st_size) >
                kLastCommandFailureMaxBytes) {
            ::close(fd);
            return std::nullopt;
        }

        std::string content;
        const auto size = static_cast<std::size_t>(before.st_size);
        if (!read_all_bounded(fd, size, content)) {
            ::close(fd);
            return std::nullopt;
        }

        // Atomic publication never changes the opened inode. Reject a
        // concurrently modified regular file instead of returning a partial
        // or attacker-controlled record.
        struct stat after {};
        const bool stable =
            ::fstat(fd, &after) == 0 &&
            S_ISREG(after.st_mode) &&
            after.st_dev == before.st_dev &&
            after.st_ino == before.st_ino &&
            after.st_size == before.st_size &&
            after.st_mtim.tv_sec == before.st_mtim.tv_sec &&
            after.st_mtim.tv_nsec == before.st_mtim.tv_nsec;
        const bool closed = ::close(fd) == 0;
        if (!stable || !closed) return std::nullopt;
        return content;
    } catch (...) {
        return std::nullopt;
    }
}

#ifdef KEEN_PBR3_TESTING
void set_last_command_failure_path_for_testing(
    std::optional<std::string> path) noexcept {
    const ErrnoGuard errno_guard;
    try {
        const std::lock_guard<std::mutex> lock(recorder_mutex());
        test_path_override() = std::move(path);
    } catch (...) {
        // Test seams must keep the same best-effort contract as production.
    }
}

void set_last_command_failure_post_commit_failure_for_testing(
    bool enabled) noexcept {
    const ErrnoGuard errno_guard;
    try {
        const std::lock_guard<std::mutex> lock(recorder_mutex());
        post_commit_failure_enabled() = enabled;
    } catch (...) {
        // Test seams must keep the same best-effort contract as production.
    }
}
#endif

} // namespace keen_pbr3
