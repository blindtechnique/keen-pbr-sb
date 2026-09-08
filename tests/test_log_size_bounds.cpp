#include <doctest/doctest.h>
#include "log/file_sink.hpp"
#include "log/nfqws_log_maintenance.hpp"

#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace keen_pbr3;
namespace {
struct LogSizeTempDirectory {
    std::filesystem::path path;
    LogSizeTempDirectory() {
        char pattern[] = "/tmp/keen-pbr-log-size-XXXXXX";
        auto* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~LogSizeTempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};
std::string contents(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
void put(const std::filesystem::path& path, const std::string& value) {
    std::ofstream file(path, std::ios::binary);
    file << value;
}
std::time_t local_time(int year, int month, int day) {
    std::tm value{};
    value.tm_year = year - 1900; value.tm_mon = month - 1; value.tm_mday = day; value.tm_isdst = -1;
    return std::mktime(&value);
}
}

TEST_CASE("file sink bounds the active and single previous generation") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "keen-pbr.log";
    FileLogSink sink(path.string(), 128U);
    REQUIRE(sink.ok());
    for (int n = 0; n < 12; ++n) sink.write("message " + std::to_string(n));
    CHECK(std::filesystem::file_size(path) <= 128U);
    CHECK(std::filesystem::file_size(path.string() + ".1") <= 128U);
    CHECK_FALSE(std::filesystem::exists(path.string() + ".2"));
    CHECK(contents(path).find("message 11") != std::string::npos);
    CHECK(contents(path.string() + ".1").find("message 11") == std::string::npos);
}

TEST_CASE("file sink clips a single oversized line at a UTF8 boundary") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "keen-pbr.log";
    FileLogSink sink(path.string(), 128U);
    std::string message;
    for (int n = 0; n < 150; ++n) message += "\xe2\x82\xac";
    sink.write(message);
    const auto text = contents(path);
    CHECK(text.size() <= 128U);
    CHECK(text.find("[line truncated]") != std::string::npos);
    CHECK_NOTHROW(nlohmann::json(text).dump());
}

TEST_CASE("file sink applies a lower runtime cap to both generations") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "keen-pbr.log";
    FileLogSink sink(path.string(), 512U);
    for (int n = 0; n < 28; ++n) sink.write("before limit change " + std::to_string(n));
    REQUIRE(std::filesystem::file_size(path.string() + ".1") > 128U);
    sink.set_max_bytes(128U);
    sink.write("after limit change");
    CHECK(std::filesystem::file_size(path) <= 128U);
    CHECK(std::filesystem::file_size(path.string() + ".1") <= 128U);
    CHECK(contents(path).find("after limit change") != std::string::npos);
}

TEST_CASE("file sink never truncates its current log after failed rotation") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "keen-pbr.log";
    FileLogSink sink(path.string(), 80U);
    sink.write("retained message");
    const auto before = contents(path);
    std::filesystem::create_directory(path.string() + ".1");
    sink.write(std::string(100U, 'x'));
    CHECK(contents(path) == before);
    CHECK(sink.ok());
}

TEST_CASE("log cap runtime setters retain valid bounds and ignore invalid values") {
    const auto old_sink = file_logging_max_bytes();
    const auto old_nfqws = nfqws_log_max_bytes();
    CHECK(valid_log_file_max_bytes(kMinLogFileBytes));
    CHECK(valid_log_file_max_bytes(kMaxLogFileBytes));
    CHECK_FALSE(valid_log_file_max_bytes(kMinLogFileBytes - 1U));
    CHECK_FALSE(valid_log_file_max_bytes(kMaxLogFileBytes + 1U));
    set_file_logging_max_bytes(kMinLogFileBytes);
    set_nfqws_log_max_bytes(kMaxLogFileBytes);
    CHECK(file_logging_max_bytes() == kMinLogFileBytes);
    CHECK(nfqws_log_max_bytes() == kMaxLogFileBytes);
    set_file_logging_max_bytes(0U);
    set_nfqws_log_max_bytes(0U);
    CHECK(file_logging_max_bytes() == kMinLogFileBytes);
    CHECK(nfqws_log_max_bytes() == kMaxLogFileBytes);
    set_file_logging_max_bytes(old_sink);
    set_nfqws_log_max_bytes(old_nfqws);
}

TEST_CASE("nfqws retention only targets exact configured nfqws log paths") {
    const auto paths = nfqws_managed_log_paths(
        "# LOG_DEBUG_PATH=\"@/opt/var/log/nfqws-obsolete.log\"\n"
        "LOG_DEBUG_PATH=\"@/opt/var/log/nfqws2-debug.log\"\n"
        "MODE_AUTO=\"--hostlist-auto-debug=/opt/var/log/nfqws-custom.log\"\n");
    CHECK(paths == std::vector<std::string>{"/opt/var/log/nfqws2.log",
          "/opt/var/log/nfqws2-debug.log", "/opt/var/log/nfqws-custom.log"});
    CHECK(nfqws_managed_log_paths(
        "LOG_DEBUG_PATH=\"@/opt/var/log/keen-pbr.log\"\n"
        "MODE_AUTO=\"--hostlist-auto-debug=/opt/var/log/nfqws/../secrets.log\"") ==
        std::vector<std::string>{"/opt/var/log/nfqws2.log"});
    CHECK(nfqws_managed_log_paths(
        "LOG_DEBUG_PATH=\"@/opt/var/log/nfqws2.log\"\n"
        "MODE_AUTO=\"--hostlist-auto-debug=/tmp/nfqws2.log\"").size() == 1U);
}

TEST_CASE("log tail keeps recent records and the inode behind a live append fd") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "nfqws2.log";
    put(path, "old-one\nold-two\nrecent-one\nrecent-two\n");
    struct stat before {};
    REQUIRE(::stat(path.c_str(), &before) == 0);
    const int writer = ::open(path.c_str(), O_WRONLY | O_APPEND);
    REQUIRE(writer >= 0);
    const auto result = compact_log_tail(path.string(), 30U, 22U);
    CHECK(result.state == LogTailState::compacted);
    CHECK(contents(path) == "recent-one\nrecent-two\n");
    REQUIRE(::write(writer, "new\n", 4U) == 4);
    (void)::close(writer);
    CHECK(contents(path) == "recent-one\nrecent-two\nnew\n");
    struct stat after {};
    REQUIRE(::stat(path.c_str(), &after) == 0);
    CHECK(before.st_ino == after.st_ino);
    CHECK_FALSE(std::filesystem::exists(path.string() + ".1"));
}

TEST_CASE("log tail leaves bounded missing symlink and nonregular files untouched") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "bounded.log";
    put(path, "bounded\n");
    CHECK(compact_log_tail(path.string(), 8U, 4U).state == LogTailState::within_limit);
    CHECK(contents(path) == "bounded\n");
    const auto link = temp.path / "link.log";
    REQUIRE(::symlink(path.c_str(), link.c_str()) == 0);
    CHECK(compact_log_tail(link.string(), 1U, 1U).state == LogTailState::unavailable);
    CHECK(contents(path) == "bounded\n");
    const auto missing = temp.path / "missing.log";
    CHECK(compact_log_tail(missing.string(), 8U, 4U).state == LogTailState::unavailable);
    CHECK_FALSE(std::filesystem::exists(missing));
    CHECK(compact_log_tail(temp.path.string(), 8U, 4U).state == LogTailState::unavailable);
}

TEST_CASE("log tail streams a large file through a fixed-size buffer") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "nfqws2.log";
    put(path, std::string(800000U, 'a') + "\nlatest record\n");
    CHECK(compact_log_tail(path.string(), 256000U, 128000U).state == LogTailState::compacted);
    const auto tail = contents(path);
    CHECK(tail.size() <= 128000U);
    CHECK(tail.substr(tail.size() - 14U) == "latest record\n");
}

TEST_CASE("log age recognizes only valid local timestamps and retains future records") {
    const auto cutoff = local_time(2026, 9, 1);
    CHECK(log_record_expired("2026-08-01 12:13:14.123 old", cutoff));
    CHECK(log_record_expired("01.08.2026 12:13:14\told", cutoff));
    CHECK_FALSE(log_record_expired("2026-09-01 00:00:00.000 boundary", cutoff));
    CHECK_FALSE(log_record_expired("2027-08-01 12:13:14.123 future", cutoff));
    CHECK_FALSE(log_record_expired("2026-02-31 12:13:14.123 invalid day", cutoff));
    CHECK_FALSE(log_record_expired("01.08.2026 25:13:14 invalid hour", cutoff));
    CHECK_FALSE(log_record_expired("no timestamp", cutoff));
    CHECK_FALSE(log_record_expired("2026-08-01 12:13:14Xnot a timestamp field", cutoff));
}

TEST_CASE("log age removes expired records while preserving unknown lines and active inode") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "nfqws2.log";
    const std::string retained = "untimestamped header\n2026-09-02 00:00:00.123 current\n"
                                 "malformed date\n2027-09-02 00:00:00.123 future\npartial";
    put(path, "untimestamped header\n01.08.2026 12:13:14\told\n2026-09-02 00:00:00.123 current\n"
              "2026-08-01 12:13:14.123 old\nmalformed date\n2027-09-02 00:00:00.123 future\npartial");
    struct stat before{};
    REQUIRE(::stat(path.c_str(), &before) == 0);
    const int writer = ::open(path.c_str(), O_WRONLY | O_APPEND);
    REQUIRE(writer >= 0);
    CHECK(prune_log_age(path.string(), local_time(2026, 9, 1)).state == LogTailState::compacted);
    CHECK(contents(path) == retained);
    REQUIRE(::write(writer, " append\n", 8U) == 8);
    (void)::close(writer);
    CHECK(contents(path) == retained + " append\n");
    struct stat after{};
    REQUIRE(::stat(path.c_str(), &after) == 0);
    CHECK(after.st_ino == before.st_ino);
}

TEST_CASE("age scanning handles oversized lines with bounded buffers") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "nfqws2.log";
    const std::string unknown(100000U, 'u');
    const std::string recent = "02.09.2026 12:13:14\trecent\n";
    put(path, "01.08.2026 12:13:14\t" + std::string(100000U, 'o') + "\n" + unknown + "\n" + recent);
    CHECK(prune_log_age(path.string(), local_time(2026, 9, 1)).state == LogTailState::compacted);
    CHECK(contents(path) == unknown + "\n" + recent);
    const auto modified = std::filesystem::last_write_time(path);
    CHECK(prune_log_age(path.string(), local_time(2026, 9, 1)).state == LogTailState::within_limit);
    CHECK(std::filesystem::last_write_time(path) == modified);
}

TEST_CASE("disabled sink size retention permits explicit unbounded logging") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "keen-pbr.log";
    FileLogSink sink(path.string(), 128U);
    sink.set_size_limit_enabled(false);
    sink.write(std::string(1000U, 'x'));
    CHECK(std::filesystem::file_size(path) > 128U);
    CHECK_FALSE(std::filesystem::exists(path.string() + ".1"));
    sink.set_size_limit_enabled(true);
    sink.write("bounded again");
    CHECK(std::filesystem::file_size(path) <= 128U);
    CHECK(std::filesystem::file_size(path.string() + ".1") <= 128U);
}

TEST_CASE("sink age maintenance updates writer size and preserves future append") {
    LogSizeTempDirectory temp;
    const auto path = temp.path / "keen-pbr.log";
    FileLogSink sink(path.string(), 128U);
    sink.write("old current record");
    sink.maintain_age(local_time(2099, 1, 1));
    CHECK(std::filesystem::exists(path));
    CHECK(contents(path).empty());
    sink.write("new record after maintenance");
    CHECK(contents(path).find("new record after maintenance") != std::string::npos);
    CHECK_FALSE(std::filesystem::exists(path.string() + ".1"));
}
