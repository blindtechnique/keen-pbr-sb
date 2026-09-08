#pragma once

// Persistent log file for the daemon.
//
// The router starts keen-pbr from an init script, so stderr goes nowhere and
// syslog(3) is a dead end as well: Entware has no syslogd listening on
// /dev/log, which is why crashes during boot used to leave no trace at all.
// Writing to a file of our own is the only place a post-mortem can be read
// from after the fact.

#include <cstddef>
#include <atomic>
#include <ctime>
#include <fstream>
#include <mutex>
#include <string>

namespace keen_pbr3 {

class FileLogSink {
public:
    // Rotation keeps exactly one previous generation. Flash storage on these
    // routers is small and slow, so the budget is deliberately modest.
    static constexpr std::size_t kDefaultMaxBytes = 1024 * 1024;

    FileLogSink(std::string path, std::size_t max_bytes = kDefaultMaxBytes);

    // Returns false when the file could not be opened; the caller keeps
    // running with console logging only rather than refusing to start.
    bool ok() const { return ok_; }
    const std::string& path() const { return path_; }
    const std::string& error() const { return error_; }

    void write(const std::string& line);
    // The new cap is enforced by the next write, without reopening the sink.
    void set_max_bytes(std::size_t max_bytes);
    void set_size_limit_enabled(bool enabled);
    void maintain_age(std::time_t cutoff);

private:
    bool rotate();

    std::string path_;
    std::atomic<std::size_t> max_bytes_;
    std::atomic<bool> size_limit_enabled_{true};
    std::ofstream stream_;
    std::size_t written_bytes_{0};
    std::size_t previous_limit_{0};
    bool ok_{false};
    std::string error_;
    std::mutex mutex_;
};

// Installs a file sink as the logger sink and records a startup banner.
// Ownership stays with the returned object, which must outlive the logger use.
bool install_file_log_sink(const std::string& path, std::string* error_out = nullptr);

// Turns file logging on and off at runtime. The sink stays installed either
// way, so the setting takes effect without restarting the service - which
// matters, because restarting is exactly what you cannot do while chasing a
// problem that only shows up at boot.
void set_file_logging_enabled(bool enabled);
bool file_logging_enabled();

inline constexpr std::size_t kMinLogFileBytes = 64U * 1024U;
inline constexpr std::size_t kMaxLogFileBytes = 16U * 1024U * 1024U;
bool valid_log_file_max_bytes(std::size_t value);
void set_file_logging_max_bytes(std::size_t max_bytes);
std::size_t file_logging_max_bytes();
inline constexpr unsigned kDefaultLogMaxAgeDays = 7U;
inline constexpr unsigned kMaximumLogAgeDays = 365U;
void set_file_log_retention(bool size_enabled, bool age_enabled, unsigned max_age_days);
bool file_log_size_limit_enabled();
bool file_log_age_limit_enabled();
unsigned file_log_max_age_days();
void maintain_file_logs() noexcept;

} // namespace keen_pbr3
