#include <doctest/doctest.h>

#include "dns/dns_query_log_maintenance.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace keen_pbr3;

namespace {

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::array<char, 64> path_template{};
        const std::string pattern = "/tmp/keen-pbr-dns-log-test-XXXXXX";
        std::copy(pattern.begin(), pattern.end(), path_template.begin());
        char* path = ::mkdtemp(path_template.data());
        if (path == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = path;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    std::filesystem::path file(const char* name) const {
        return path_ / name;
    }

private:
    std::filesystem::path path_;
};

class UniqueFd {
public:
    explicit UniqueFd(int value) noexcept : value_(value) {}
    ~UniqueFd() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    int get() const noexcept { return value_; }

private:
    int value_{-1};
};

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("DNS query log maintenance leaves a bounded file untouched") {
    TemporaryDirectory directory;
    const auto path = directory.file("queries.log");
    const auto native_path = path.string();
    {
        std::ofstream output(path, std::ios::binary);
        output << "bounded";
    }

    const auto result = maintain_dns_query_log(native_path.c_str(), 7U);

    CHECK(result.state == DnsQueryLogMaintenanceState::within_limit);
    CHECK(result.observed_size == 7U);
    CHECK(result.error_number == 0);
    CHECK(read_file(path) == "bounded");
}

TEST_CASE("DNS query log maintenance truncates the inode behind a live append fd") {
    TemporaryDirectory directory;
    const auto path = directory.file("queries.log");
    const auto native_path = path.string();
    {
        std::ofstream output(path, std::ios::binary);
        output << "oversized-query-log";
    }

    struct stat before {};
    REQUIRE(::stat(native_path.c_str(), &before) == 0);
    UniqueFd append_fd(::open(native_path.c_str(), O_WRONLY | O_APPEND));
    REQUIRE(append_fd.get() >= 0);

    const auto result = maintain_dns_query_log(native_path.c_str(), 8U);

    struct stat after {};
    REQUIRE(::stat(native_path.c_str(), &after) == 0);
    CHECK(result.state == DnsQueryLogMaintenanceState::truncated);
    CHECK(result.observed_size > 8U);
    CHECK(result.error_number == 0);
    CHECK(after.st_ino == before.st_ino);
    CHECK(after.st_size == 0);

    constexpr char appended[] = "after";
    CHECK(::write(append_fd.get(), appended, sizeof(appended) - 1U) ==
          static_cast<ssize_t>(sizeof(appended) - 1U));
    CHECK(read_file(path) == "after");
}

TEST_CASE("DNS query log maintenance never creates a missing path") {
    TemporaryDirectory directory;
    const auto path = directory.file("missing.log");
    const auto native_path = path.string();

    const auto result = maintain_dns_query_log(native_path.c_str(), 1U);

    CHECK(result.state == DnsQueryLogMaintenanceState::unavailable);
    CHECK(result.error_number != 0);
    CHECK_FALSE(std::filesystem::exists(path));
}

TEST_CASE("DNS query log maintenance does not follow a replacement symlink") {
    TemporaryDirectory directory;
    const auto target = directory.file("target.log");
    const auto link = directory.file("queries.log");
    const auto native_target = target.string();
    const auto native_link = link.string();
    {
        std::ofstream output(target, std::ios::binary);
        output << "oversized-query-log";
    }
    REQUIRE(::symlink(native_target.c_str(), native_link.c_str()) == 0);

    const auto result = maintain_dns_query_log(native_link.c_str(), 8U);

    CHECK(result.state == DnsQueryLogMaintenanceState::unavailable);
    CHECK(result.error_number != 0);
    CHECK(read_file(target) == "oversized-query-log");
}
