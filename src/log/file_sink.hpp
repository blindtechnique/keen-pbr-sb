#pragma once

// Persistent log file for the daemon.
//
// The router starts keen-pbr from an init script, so stderr goes nowhere and
// syslog(3) is a dead end as well: Entware has no syslogd listening on
// /dev/log, which is why crashes during boot used to leave no trace at all.
// Writing to a file of our own is the only place a post-mortem can be read
// from after the fact.

#include <cstddef>
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

private:
    void rotate_if_needed();

    std::string path_;
    std::size_t max_bytes_;
    std::ofstream stream_;
    std::size_t written_bytes_{0};
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

} // namespace keen_pbr3
