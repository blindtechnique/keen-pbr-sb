#include "dns_query_log_maintenance.hpp"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

class ScopedFd {
public:
    explicit ScopedFd(int value) noexcept : value_(value) {}
    ~ScopedFd() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const noexcept { return value_; }

private:
    int value_{-1};
};

} // namespace

DnsQueryLogMaintenanceResult maintain_dns_query_log(
    const char* path,
    std::uintmax_t maximum_size) noexcept {
    if (path == nullptr || path[0] == '\0') {
        return {
            DnsQueryLogMaintenanceState::unavailable, 0U, EINVAL};
    }

    ScopedFd descriptor(
        ::open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (descriptor.get() < 0) {
        return {
            DnsQueryLogMaintenanceState::unavailable,
            0U,
            errno};
    }

    struct stat file_status {};
    if (::fstat(descriptor.get(), &file_status) != 0) {
        return {
            DnsQueryLogMaintenanceState::unavailable,
            0U,
            errno};
    }
    if (!S_ISREG(file_status.st_mode) || file_status.st_size < 0) {
        return {
            DnsQueryLogMaintenanceState::unavailable, 0U, EINVAL};
    }

    const auto size = static_cast<std::uintmax_t>(file_status.st_size);
    if (size <= maximum_size) {
        return {
            DnsQueryLogMaintenanceState::within_limit, size, 0};
    }

    // ftruncate(2) mutates the exact inode observed above and kept open here.
    // It preserves dnsmasq's live O_APPEND descriptor and neither creates nor
    // follows a replacement path during maintenance.
    if (::ftruncate(descriptor.get(), 0) != 0) {
        return {
            DnsQueryLogMaintenanceState::truncate_failed,
            size,
            errno};
    }
    return {DnsQueryLogMaintenanceState::truncated, size, 0};
}

} // namespace keen_pbr3
