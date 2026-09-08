#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::size_t kNotificationLogIdLimit = 512;
inline constexpr std::size_t kNotificationUpdateIdLimit = 512;
inline constexpr std::size_t kNotificationIdLengthLimit = 128;
inline constexpr std::size_t kNotificationStateMaxBytes = 160 * 1024;
inline constexpr std::size_t kNotificationStateReadMaxBytes = 192 * 1024;

struct NotificationDismissalState {
    std::uint64_t revision{0};
    std::vector<std::string> log_ids;
    std::vector<std::string> update_ids;
};

bool valid_notification_dismissal(const std::vector<std::string>& log_ids,
                                  const std::vector<std::string>& update_ids);

// One process-wide instance, owned by the API. Only dismissal requests write;
// snapshots and log ingestion never reread or rewrite the state file.
class NotificationStateStore final {
public:
    explicit NotificationStateStore(std::string path, std::string* load_error = nullptr);
    NotificationDismissalState snapshot() const;
    // Merge, never replace, so a stale phone view cannot undo a PC dismissal.
    // A pre-rename failure leaves the old state intact. If rename succeeded
    // but its directory sync failed, the visible state is adopted and true is
    // returned with a warning in error; no automatic retry/rollback is added.
    bool dismiss(const std::vector<std::string>& log_ids,
                 const std::vector<std::string>& update_ids,
                 std::string& error);

private:
    std::string path_;
    mutable std::mutex mutex_;
    NotificationDismissalState state_;
};

// Whole timestamped line plus file identity; offsets may change when old lines
// are compacted in place. byte_offset remains only for caller compatibility.
std::string notification_log_id(std::string_view line,
                                std::uint64_t file_device,
                                std::uint64_t file_inode,
                                std::uint64_t byte_offset);

} // namespace keen_pbr3
