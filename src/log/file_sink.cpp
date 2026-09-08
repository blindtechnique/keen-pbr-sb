#include "file_sink.hpp"

#include "logger.hpp"
#include "log_tail.hpp"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

namespace keen_pbr3 {

namespace {

std::atomic<std::size_t> g_file_logging_max_bytes{FileLogSink::kDefaultMaxBytes};
std::atomic<FileLogSink*> g_file_sink{nullptr};
std::atomic<bool> g_size_limit_enabled{true};
std::atomic<bool> g_age_limit_enabled{false};
std::atomic<unsigned> g_max_age_days{kDefaultLogMaxAgeDays};

std::string timestamp_now() {
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()) % std::chrono::seconds(1);
    const std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
    localtime_r(&time, &tm);

    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(3)
        << std::setfill('0') << ms.count();
    return out.str();
}

// Creates the parent directory when it is missing. On a fresh install
// /opt/var/log may not exist yet, and failing to log because of that would
// defeat the point of the file.
void ensure_parent_directory(const std::string& path) {
    const auto slash = path.rfind('/');
    if (slash == std::string::npos || slash == 0) {
        return;
    }
    const std::string parent = path.substr(0, slash);
    struct stat st{};
    if (stat(parent.c_str(), &st) == 0) {
        return;
    }
    ::mkdir(parent.c_str(), 0755);
}

} // namespace

FileLogSink::FileLogSink(std::string path, std::size_t max_bytes)
    : path_(std::move(path)), max_bytes_(std::max<std::size_t>(1U, max_bytes)) {
    ensure_parent_directory(path_);

    stream_.open(path_, std::ios::out | std::ios::app);
    if (!stream_.is_open()) {
        error_ = "cannot open " + path_;
        return;
    }

    struct stat st{};
    if (stat(path_.c_str(), &st) == 0) {
        written_bytes_ = static_cast<std::size_t>(st.st_size);
    }
    ok_ = true;
}

bool FileLogSink::rotate() {
    stream_.close();
    const std::string previous = path_ + ".1";
    // POSIX rename replaces the previous generation atomically. If it fails,
    // keep the current file; opening it with trunc would destroy diagnostics.
    if (std::rename(path_.c_str(), previous.c_str()) != 0) {
        stream_.open(path_, std::ios::out | std::ios::app);
        ok_ = stream_.is_open();
        error_ = "cannot rotate " + path_;
        return false;
    }
    const auto limit = max_bytes_.load(std::memory_order_relaxed);
    (void)compact_log_tail(previous, limit, limit);

    stream_.open(path_, std::ios::out | std::ios::trunc);
    written_bytes_ = 0;
    ok_ = stream_.is_open();
    return ok_;
}

void FileLogSink::set_max_bytes(std::size_t max_bytes) {
    max_bytes_.store(std::max<std::size_t>(1U, max_bytes),
                     std::memory_order_relaxed);
}

void FileLogSink::set_size_limit_enabled(bool enabled) {
    size_limit_enabled_.store(enabled, std::memory_order_relaxed);
}

void FileLogSink::maintain_age(std::time_t cutoff) {
    const std::lock_guard<std::mutex> lock(mutex_);
    (void)prune_log_age(path_, cutoff);
    (void)prune_log_age(path_ + ".1", cutoff);
    struct stat info{};
    if (::stat(path_.c_str(), &info) == 0 && info.st_size >= 0) {
        written_bytes_ = static_cast<std::size_t>(info.st_size);
    }
}

void FileLogSink::write(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ok_) {
        return;
    }

    const auto max_bytes = max_bytes_.load(std::memory_order_relaxed);
    const bool size_enabled = size_limit_enabled_.load(std::memory_order_relaxed);
    // Also bound a generation left by a previous, larger setting. The check
    // is only needed after a cap change, not on every written line.
    if (size_enabled && previous_limit_ != max_bytes) {
        (void)compact_log_tail(path_ + ".1", max_bytes, max_bytes);
        previous_limit_ = max_bytes;
    }
    std::string stamped = timestamp_now() + " " + line + "\n";
    if (size_enabled && stamped.size() > max_bytes) {
        const std::string suffix = " [line truncated]\n";
        auto end = max_bytes > suffix.size() ? max_bytes - suffix.size() : 0U;
        // Do not leave a UTF-8 sequence half-written at the size boundary.
        while (end > 0U &&
               (static_cast<unsigned char>(stamped[end]) & 0xc0U) == 0x80U) {
            --end;
        }
        stamped.resize(end);
        stamped += suffix.substr(0U, max_bytes - end);
    }
    if (size_enabled && written_bytes_ > max_bytes - stamped.size() && !rotate()) {
        return;
    }
    stream_ << stamped;
    // Flushing every line costs throughput but is the whole point here: a
    // process that dies during boot must not lose its last message.
    stream_.flush();
    written_bytes_ += stamped.size();
}

namespace {
std::atomic<bool> g_file_logging_enabled{true};
} // namespace

void set_file_logging_enabled(bool enabled) {
    g_file_logging_enabled.store(enabled, std::memory_order_relaxed);
}

bool file_logging_enabled() {
    return g_file_logging_enabled.load(std::memory_order_relaxed);
}

bool valid_log_file_max_bytes(std::size_t value) {
    return value >= kMinLogFileBytes && value <= kMaxLogFileBytes;
}

void set_file_logging_max_bytes(std::size_t max_bytes) {
    if (!valid_log_file_max_bytes(max_bytes)) return;
    g_file_logging_max_bytes.store(max_bytes, std::memory_order_relaxed);
    if (auto* sink = g_file_sink.load(std::memory_order_acquire)) {
        sink->set_max_bytes(max_bytes);
    }
}

std::size_t file_logging_max_bytes() {
    return g_file_logging_max_bytes.load(std::memory_order_relaxed);
}

void set_file_log_retention(bool size_enabled, bool age_enabled, unsigned days) {
    if (days < 1U || days > kMaximumLogAgeDays) return;
    g_size_limit_enabled.store(size_enabled, std::memory_order_relaxed);
    g_age_limit_enabled.store(age_enabled, std::memory_order_relaxed);
    g_max_age_days.store(days, std::memory_order_relaxed);
    if (auto* sink = g_file_sink.load(std::memory_order_acquire)) sink->set_size_limit_enabled(size_enabled);
}
bool file_log_size_limit_enabled() { return g_size_limit_enabled.load(std::memory_order_relaxed); }
bool file_log_age_limit_enabled() { return g_age_limit_enabled.load(std::memory_order_relaxed); }
unsigned file_log_max_age_days() { return g_max_age_days.load(std::memory_order_relaxed); }

void maintain_file_logs() noexcept {
    if (!file_log_age_limit_enabled()) return;
    try {
        if (auto* sink = g_file_sink.load(std::memory_order_acquire)) {
            sink->maintain_age(std::time(nullptr) - static_cast<std::time_t>(file_log_max_age_days()) * 86400);
        }
    } catch (...) { }
}

bool install_file_log_sink(const std::string& path, std::string* error_out) {
    // Deliberately leaked: the logger sink may fire from atexit paths and
    // fatal signal handlers, after ordinary static destructors have run.
    static FileLogSink* sink = nullptr;
    if (sink != nullptr) {
        return sink->ok();
    }
    sink = new FileLogSink(path, file_logging_max_bytes());
    sink->set_size_limit_enabled(file_log_size_limit_enabled());
    g_file_sink.store(sink, std::memory_order_release);

    if (!sink->ok()) {
        if (error_out != nullptr) {
            *error_out = sink->error();
        }
        return false;
    }

    Logger::instance().set_sink([](const std::string& line) {
        if (file_logging_enabled()) {
            sink->write(line);
        }
    });
    return true;
}

} // namespace keen_pbr3
