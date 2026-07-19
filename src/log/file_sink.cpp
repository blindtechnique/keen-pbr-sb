#include "file_sink.hpp"

#include "logger.hpp"

#include <atomic>
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
    : path_(std::move(path)), max_bytes_(max_bytes) {
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

void FileLogSink::rotate_if_needed() {
    if (written_bytes_ < max_bytes_) {
        return;
    }

    stream_.close();
    const std::string previous = path_ + ".1";
    std::remove(previous.c_str());
    std::rename(path_.c_str(), previous.c_str());

    stream_.open(path_, std::ios::out | std::ios::trunc);
    written_bytes_ = 0;
    ok_ = stream_.is_open();
}

void FileLogSink::write(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ok_) {
        return;
    }

    const std::string stamped = timestamp_now() + " " + line + "\n";
    stream_ << stamped;
    // Flushing every line costs throughput but is the whole point here: a
    // process that dies during boot must not lose its last message.
    stream_.flush();
    written_bytes_ += stamped.size();

    rotate_if_needed();
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

bool install_file_log_sink(const std::string& path, std::string* error_out) {
    // Deliberately leaked: the logger sink may fire from atexit paths and
    // fatal signal handlers, after ordinary static destructors have run.
    static FileLogSink* sink = nullptr;
    if (sink != nullptr) {
        return sink->ok();
    }
    sink = new FileLogSink(path);

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
