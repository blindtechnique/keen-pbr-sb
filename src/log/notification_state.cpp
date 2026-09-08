#include "notification_state.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace keen_pbr3 {
namespace {

bool valid_id(const std::string& id) {
    return !id.empty() && id.size() <= kNotificationIdLengthLimit &&
        std::all_of(id.begin(), id.end(), [](unsigned char ch) {
            return ch >= 0x20 && ch != 0x7f;
        });
}

std::vector<std::string> read_ids(const nlohmann::json& value, std::size_t limit) {
    if (!value.is_array() || value.size() > limit) {
        throw std::runtime_error("Invalid notification ID collection");
    }
    std::vector<std::string> ids;
    ids.reserve(value.size());
    for (const auto& item : value) {
        auto id = item.get<std::string>();
        if (!valid_id(id) || std::find(ids.begin(), ids.end(), id) != ids.end()) {
            throw std::runtime_error("Invalid notification ID");
        }
        ids.push_back(std::move(id));
    }
    return ids;
}

NotificationDismissalState read_state(const std::string& path, std::string& error) {
    error.clear();
    try {
        std::error_code status_error;
        const auto status = std::filesystem::status(path, status_error);
        if (status.type() == std::filesystem::file_type::not_found &&
            (!status_error || status_error == std::errc::no_such_file_or_directory)) return {};
        if (status_error || !std::filesystem::is_regular_file(status)) {
            throw std::runtime_error("Notification state is not readable");
        }
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("Notification state is not readable");
        std::string body;
        std::array<char, 4096> buffer{};
        while (input && body.size() <= kNotificationStateReadMaxBytes) {
            const auto count = std::min(buffer.size(), kNotificationStateReadMaxBytes + 1 - body.size());
            input.read(buffer.data(), static_cast<std::streamsize>(count));
            body.append(buffer.data(), static_cast<std::size_t>(input.gcount()));
        }
        if (input.bad() || body.size() > kNotificationStateReadMaxBytes) {
            throw std::runtime_error("Notification state exceeds its read limit");
        }
        const auto document = nlohmann::json::parse(body);
        if (!document.is_object() || document.at("version") != 1) {
            throw std::runtime_error("Unknown notification state format");
        }
        const auto& revision = document.at("revision");
        if (!revision.is_number_integer() ||
            (!revision.is_number_unsigned() && revision.get<std::int64_t>() < 0)) {
            throw std::runtime_error("Invalid notification revision");
        }
        NotificationDismissalState state;
        state.revision = revision.get<std::uint64_t>();
        state.log_ids = read_ids(document.at("log_ids"), kNotificationLogIdLimit);
        state.update_ids = read_ids(document.at("update_ids"), kNotificationUpdateIdLimit);
        return state;
    } catch (const std::exception&) {
        error = "Could not read notification dismissal state";
        return {};
    }
}

void merge_ids(std::vector<std::string>& current,
               const std::vector<std::string>& requested,
               std::size_t limit) {
    for (const auto& id : requested) {
        const auto existing = std::find(current.begin(), current.end(), id);
        if (existing != current.end()) current.erase(existing);
        current.push_back(id);
        if (current.size() > limit) current.erase(current.begin());
    }
}

std::string encode(const NotificationDismissalState& state) {
    return nlohmann::json{{"version", 1}, {"revision", state.revision},
                          {"log_ids", state.log_ids}, {"update_ids", state.update_ids}}.dump();
}

} // namespace

bool valid_notification_dismissal(const std::vector<std::string>& log_ids,
                                  const std::vector<std::string>& update_ids) {
    return log_ids.size() <= 200 && update_ids.size() <= kNotificationUpdateIdLimit &&
        std::all_of(log_ids.begin(), log_ids.end(), valid_id) &&
        std::all_of(update_ids.begin(), update_ids.end(), valid_id);
}

NotificationStateStore::NotificationStateStore(std::string path, std::string* load_error)
    : path_(std::move(path)) {
    std::string error;
    state_ = read_state(path_, error);
    if (load_error) *load_error = std::move(error);
}

NotificationDismissalState NotificationStateStore::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

bool NotificationStateStore::dismiss(const std::vector<std::string>& log_ids,
                                     const std::vector<std::string>& update_ids,
                                     std::string& error) {
    error.clear();
    if (!valid_notification_dismissal(log_ids, update_ids)) {
        error = "Invalid notification dismissal IDs";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        auto candidate = state_;
        merge_ids(candidate.log_ids, log_ids, kNotificationLogIdLimit);
        merge_ids(candidate.update_ids, update_ids, kNotificationUpdateIdLimit);
        if (candidate.log_ids == state_.log_ids && candidate.update_ids == state_.update_ids) return true;
        if (candidate.revision < std::numeric_limits<std::uint64_t>::max()) ++candidate.revision;
        auto body = encode(candidate);
        // Escaped/UTF-8 opaque IDs may cost more JSON bytes than their length.
        // Keep the most recent dismissals within the independent byte bound.
        while (body.size() > kNotificationStateMaxBytes) {
            if (!candidate.log_ids.empty()) candidate.log_ids.erase(candidate.log_ids.begin());
            else if (!candidate.update_ids.empty()) candidate.update_ids.erase(candidate.update_ids.begin());
            else throw std::runtime_error("Notification state exceeds size limit");
            body = encode(candidate);
        }
        AtomicFileWriteOptions options;
        options.file_mode = 0600;
        try {
            write_file_atomically(path_, body, options);
        } catch (const AtomicFileWriteError& failure) {
            if (!failure.committed()) throw;
            state_ = std::move(candidate);
            error = "Notification dismissal applied, but directory sync was not confirmed";
            return true;
        }
        state_ = std::move(candidate);
        return true;
    } catch (const std::exception&) {
        error = "Could not save notification dismissal state";
        return false;
    }
}

std::string notification_log_id(std::string_view line,
                                std::uint64_t file_device,
                                std::uint64_t file_inode,
                                std::uint64_t byte_offset) {
    (void)byte_offset;
    Sha256 hash;
    constexpr char domain[] = "keen-pbr-notification-log-v2";
    hash.update(domain, sizeof(domain) - 1);
    // Age-based compaction keeps the inode but shifts all retained offsets.
    // The line already includes millisecond time: a later occurrence has a
    // different ID. Exactly identical lines in the same millisecond coalesce.
    std::array<std::uint8_t, 16> identity{};
    const std::array<std::uint64_t, 2> values{file_device, file_inode};
    for (std::size_t word = 0; word < values.size(); ++word) {
        for (std::size_t byte = 0; byte < 8; ++byte) {
            identity[word * 8 + byte] = static_cast<std::uint8_t>(values[word] >> ((7 - byte) * 8));
        }
    }
    hash.update(identity.data(), identity.size());
    hash.update(line.data(), line.size());
    return "log:" + hash.hex_digest();
}

} // namespace keen_pbr3
