#include "ndms_native_writer_lease.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr mode_t kDirectoryMode = 0700;
constexpr mode_t kLockFileMode = 0600;
constexpr std::string_view kLockFilename{"writer.lock"};

class FileDescriptor final {
public:
    explicit FileDescriptor(const int value = -1) noexcept : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this == &other) return *this;
        if (value_ >= 0) (void)::close(value_);
        value_ = std::exchange(other.value_, -1);
        return *this;
    }
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }

private:
    int value_{-1};
};

enum class PathErrorKind { unsafe, io };

class PathError final : public std::runtime_error {
public:
    PathError(PathErrorKind kind, std::string message)
        : std::runtime_error(std::move(message)), kind_(kind) {}
    PathErrorKind kind() const noexcept { return kind_; }

private:
    PathErrorKind kind_;
};

struct LeasePolicy final {
    uid_t owner{0};
    gid_t group{0};
    bool require_root_process{true};
};

std::string errno_message(const std::string& prefix) {
    const int error = errno;
    return prefix + ": " + std::strerror(error);
}

[[noreturn]] void throw_io(const std::string& message) {
    throw PathError(PathErrorKind::io, errno_message(message));
}

int directory_flags() {
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    return flags;
}

void set_cloexec(const int descriptor) {
#ifndef O_CLOEXEC
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        throw_io("cannot mark native writer descriptor close-on-exec");
    }
#else
    (void)descriptor;
#endif
}

void fsync_exact(const int descriptor, const std::string& what) {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) continue;
        throw_io("cannot fsync " + what);
    }
}

std::vector<std::string> path_components(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.empty() || path == path.root_path() ||
        path.lexically_normal() != path) {
        throw PathError(
            PathErrorKind::unsafe,
            "native writer lease requires a normalized absolute state directory");
    }
    std::vector<std::string> result;
    for (const auto& raw : path.relative_path()) {
        const auto component = raw.string();
        if (component.empty() || component == "." || component == "..") {
            throw PathError(
                PathErrorKind::unsafe,
                "native writer state path contains an unsafe component");
        }
        result.push_back(component);
    }
    if (result.empty()) {
        throw PathError(
            PathErrorKind::unsafe,
            "native writer lease requires a dedicated state directory");
    }
    return result;
}

bool exact_directory(const struct stat& status,
                     const LeasePolicy& policy) noexcept {
    return S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_uid == policy.owner && status.st_gid == policy.group &&
           (status.st_mode & 07777) == kDirectoryMode;
}

bool exact_lock_file(const struct stat& status,
                     const LeasePolicy& policy) noexcept {
    return S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_uid == policy.owner && status.st_gid == policy.group &&
           (status.st_mode & 07777) == kLockFileMode && status.st_nlink == 1;
}

FileDescriptor open_state_directory(const std::filesystem::path& path,
                                    const bool create,
                                    const LeasePolicy& policy) {
    if (policy.require_root_process &&
        (::geteuid() != 0 || ::getegid() != 0)) {
        throw PathError(
            PathErrorKind::unsafe,
            "native writer lease requires a root process");
    }

    FileDescriptor current(::open("/", directory_flags()));
    if (current.get() < 0) throw_io("cannot open native writer path root");
    set_cloexec(current.get());

    const auto components = path_components(path);
    for (std::size_t index = 0U; index < components.size(); ++index) {
        const bool final = index + 1U == components.size();
        const auto& component = components[index];
        struct stat before {};
        bool created = false;
        if (::fstatat(current.get(), component.c_str(), &before,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT || !create || !final) {
                throw_io("cannot inspect native writer state directory");
            }
            if (::mkdirat(current.get(), component.c_str(), kDirectoryMode) !=
                0) {
                if (errno != EEXIST) {
                    throw_io("cannot create native writer state directory");
                }
            } else {
                created = true;
            }
            if (::fstatat(current.get(), component.c_str(), &before,
                          AT_SYMLINK_NOFOLLOW) != 0) {
                throw_io("cannot inspect created native writer directory");
            }
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw PathError(
                PathErrorKind::unsafe,
                "native writer path contains a symlink or non-directory");
        }

        FileDescriptor child(
            ::openat(current.get(), component.c_str(), directory_flags()));
        if (child.get() < 0) {
            throw_io("cannot open native writer state directory");
        }
        set_cloexec(child.get());
        struct stat opened {};
        if (::fstat(child.get(), &opened) != 0) {
            throw_io("cannot inspect opened native writer directory");
        }
        if (!S_ISDIR(opened.st_mode) || opened.st_dev != before.st_dev ||
            opened.st_ino != before.st_ino) {
            throw PathError(
                PathErrorKind::unsafe,
                "native writer directory changed while opening");
        }

        if (final) {
            if (created) {
                if (::fchown(child.get(), policy.owner, policy.group) != 0 ||
                    ::fchmod(child.get(), kDirectoryMode) != 0) {
                    throw_io("cannot protect native writer state directory");
                }
                fsync_exact(child.get(), "native writer state directory");
                fsync_exact(current.get(), "native writer parent directory");
                if (::fstat(child.get(), &opened) != 0) {
                    throw_io("cannot reinspect native writer directory");
                }
            }
            if (!exact_directory(opened, policy)) {
                throw PathError(
                    PathErrorKind::unsafe,
                    "native writer directory is not exact owner-only 0700");
            }
        } else if (policy.require_root_process &&
                   (opened.st_uid != 0 || (opened.st_mode & 0022) != 0)) {
            throw PathError(
                PathErrorKind::unsafe,
                "native writer parent directory is not root protected");
        }
        current = std::move(child);
    }
    return current;
}

FileDescriptor open_lock_file(const int directory,
                              const LeasePolicy& policy) {
    int create_flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    create_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    create_flags |= O_NOFOLLOW;
#endif
    bool created = false;
    int descriptor = ::openat(
        directory, kLockFilename.data(), create_flags, kLockFileMode);
    if (descriptor >= 0) {
        created = true;
    } else if (errno == EEXIST) {
        int open_flags = O_RDWR;
#ifdef O_CLOEXEC
        open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        open_flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
        open_flags |= O_NONBLOCK;
#endif
        descriptor = ::openat(directory, kLockFilename.data(), open_flags);
    }
    if (descriptor < 0) throw_io("cannot open native writer lock file");
    FileDescriptor lock(descriptor);
    set_cloexec(lock.get());
    if (created &&
        (::fchown(lock.get(), policy.owner, policy.group) != 0 ||
         ::fchmod(lock.get(), kLockFileMode) != 0)) {
        throw_io("cannot protect native writer lock file");
    }
    struct stat opened {};
    struct stat named {};
    if (::fstat(lock.get(), &opened) != 0 ||
        ::fstatat(directory, kLockFilename.data(), &named,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        throw_io("cannot inspect native writer lock file");
    }
    if (!exact_lock_file(opened, policy) ||
        !exact_lock_file(named, policy) || opened.st_dev != named.st_dev ||
        opened.st_ino != named.st_ino) {
        throw PathError(
            PathErrorKind::unsafe,
            "native writer lock file metadata or identity is unsafe");
    }
    if (created) fsync_exact(directory, "native writer state directory");
    return lock;
}

LeasePolicy production_policy() noexcept { return {}; }

} // namespace

NdmsNativeWriterAdmission NdmsNativeWriterLease::admit_with_policy(
    std::filesystem::path state_directory,
    std::unique_ptr<MaintenanceLease> maintenance,
    RuntimeMutationAdmission::Lease runtime,
    const std::uint32_t owner,
    const std::uint32_t group,
    const bool require_root_process) {
    NdmsNativeWriterAdmission admission;
    LeasePolicy policy;
    policy.owner = static_cast<uid_t>(owner);
    policy.group = static_cast<gid_t>(group);
    policy.require_root_process = require_root_process;
    if (!maintenance || !static_cast<bool>(runtime)) {
        admission.state =
            NdmsNativeWriterAdmissionState::outer_guard_missing;
        return admission;
    }
    try {
        maintenance->verify_held();
    } catch (...) {
        admission.state = NdmsNativeWriterAdmissionState::outer_guard_lost;
        return admission;
    }

    try {
        auto directory = open_state_directory(
            state_directory, true, policy);
        auto lock = open_lock_file(directory.get(), policy);
        if (::flock(lock.get(), LOCK_EX | LOCK_NB) != 0) {
            admission.state =
                (errno == EWOULDBLOCK || errno == EAGAIN)
                    ? NdmsNativeWriterAdmissionState::lease_busy
                    : NdmsNativeWriterAdmissionState::lease_io_error;
            return admission;
        }

        // The potentially blocking filesystem setup happened between the two
        // checks. Never adopt a native descriptor under an outer lease that
        // was lost during that window.
        try {
            maintenance->verify_held();
        } catch (...) {
            admission.state =
                NdmsNativeWriterAdmissionState::outer_guard_lost;
            return admission;
        }

        admission.lease = NdmsNativeWriterLease(
            std::move(state_directory), std::move(maintenance),
            std::move(runtime), directory.release(), lock.release(),
            static_cast<std::uint32_t>(policy.owner),
            static_cast<std::uint32_t>(policy.group));
        admission.state = NdmsNativeWriterAdmissionState::admitted;
        return admission;
    } catch (const PathError& error) {
        admission.state = error.kind() == PathErrorKind::unsafe
            ? NdmsNativeWriterAdmissionState::state_directory_unsafe
            : NdmsNativeWriterAdmissionState::lease_io_error;
        return admission;
    } catch (...) {
        admission.state = NdmsNativeWriterAdmissionState::lease_io_error;
        return admission;
    }
}

NdmsNativeWriterLease::NdmsNativeWriterLease(
    std::filesystem::path state_directory,
    std::unique_ptr<MaintenanceLease> maintenance,
    RuntimeMutationAdmission::Lease runtime,
    const int directory_descriptor,
    const int lock_descriptor,
    const std::uint32_t owner,
    const std::uint32_t group) noexcept
    : maintenance_(std::move(maintenance)),
      runtime_(std::move(runtime)),
      state_directory_(std::move(state_directory)),
      directory_descriptor_(directory_descriptor),
      lock_descriptor_(lock_descriptor),
      owner_(owner),
      group_(group) {}

NdmsNativeWriterLease::NdmsNativeWriterLease(
    NdmsNativeWriterLease&& other) noexcept
    : maintenance_(std::move(other.maintenance_)),
      runtime_(std::move(other.runtime_)),
      state_directory_(std::move(other.state_directory_)),
      directory_descriptor_(
          std::exchange(other.directory_descriptor_, -1)),
      lock_descriptor_(std::exchange(other.lock_descriptor_, -1)),
      owner_(std::exchange(other.owner_, 0U)),
      group_(std::exchange(other.group_, 0U)) {}

NdmsNativeWriterLease& NdmsNativeWriterLease::operator=(
    NdmsNativeWriterLease&& other) noexcept {
    if (this == &other) return *this;
    release_native_noexcept();
    // Reverse acquisition order for the old lease.
    runtime_ = RuntimeMutationAdmission::Lease{};
    maintenance_.reset();

    maintenance_ = std::move(other.maintenance_);
    runtime_ = std::move(other.runtime_);
    state_directory_ = std::move(other.state_directory_);
    directory_descriptor_ = std::exchange(other.directory_descriptor_, -1);
    lock_descriptor_ = std::exchange(other.lock_descriptor_, -1);
    owner_ = std::exchange(other.owner_, 0U);
    group_ = std::exchange(other.group_, 0U);
    return *this;
}

NdmsNativeWriterLease::~NdmsNativeWriterLease() noexcept {
    release_native_noexcept();
}

void NdmsNativeWriterLease::release_native_noexcept() noexcept {
    if (lock_descriptor_ >= 0) {
        (void)::flock(lock_descriptor_, LOCK_UN);
        (void)::close(lock_descriptor_);
        lock_descriptor_ = -1;
    }
    if (directory_descriptor_ >= 0) {
        (void)::close(directory_descriptor_);
        directory_descriptor_ = -1;
    }
}

bool NdmsNativeWriterLease::held() const noexcept {
    return maintenance_ && static_cast<bool>(runtime_) &&
           directory_descriptor_ >= 0 && lock_descriptor_ >= 0;
}

NdmsNativeWriterLeaseScope NdmsNativeWriterLease::scope() const noexcept {
    return NdmsNativeWriterLeaseScope::keen_pbr_cooperative;
}

std::uint32_t
NdmsNativeWriterLease::maintenance_base_generation() const noexcept {
    return maintenance_ ? maintenance_->base_generation() : 0U;
}

std::uint32_t NdmsNativeWriterLease::reserve_maintenance_generation(
    const std::uint32_t expected_generation) {
    verify_held();
    return maintenance_->reserve(expected_generation);
}

std::uint64_t NdmsNativeWriterLease::runtime_token() const noexcept {
    return runtime_.token();
}

const std::filesystem::path&
NdmsNativeWriterLease::state_directory() const noexcept {
    return state_directory_;
}

void NdmsNativeWriterLease::verify_held() {
    if (!held()) {
        throw std::runtime_error("native cooperative writer lease is not held");
    }
    maintenance_->verify_held();

    LeasePolicy policy;
    policy.owner = static_cast<uid_t>(owner_);
    policy.group = static_cast<gid_t>(group_);
    policy.require_root_process = false;

    struct stat directory_status {};
    struct stat lock_status {};
    struct stat named_lock_status {};
    if (::fstat(directory_descriptor_, &directory_status) != 0 ||
        ::fstat(lock_descriptor_, &lock_status) != 0 ||
        ::fstatat(directory_descriptor_, kLockFilename.data(),
                  &named_lock_status, AT_SYMLINK_NOFOLLOW) != 0) {
        throw std::runtime_error(
            errno_message("cannot verify native writer lease descriptors"));
    }
    if (!exact_directory(directory_status, policy) ||
        !exact_lock_file(lock_status, policy) ||
        !exact_lock_file(named_lock_status, policy) ||
        lock_status.st_dev != named_lock_status.st_dev ||
        lock_status.st_ino != named_lock_status.st_ino) {
        throw std::runtime_error(
            "native writer lease descriptor identity changed");
    }

    auto named_directory = open_state_directory(
        state_directory_, false, policy);
    struct stat named_directory_status {};
    if (::fstat(named_directory.get(), &named_directory_status) != 0 ||
        named_directory_status.st_dev != directory_status.st_dev ||
        named_directory_status.st_ino != directory_status.st_ino) {
        throw std::runtime_error(
            "native writer state directory was rebound");
    }
    if (::flock(lock_descriptor_, LOCK_EX | LOCK_NB) != 0) {
        throw std::runtime_error(
            errno_message("native cooperative writer flock was lost"));
    }
    maintenance_->verify_held();
}

NdmsNativeWriterAdmission admit_ndms_native_writer(
    std::filesystem::path state_directory,
    std::unique_ptr<MaintenanceLease> maintenance,
    RuntimeMutationAdmission::Lease runtime) {
    const auto policy = production_policy();
    return NdmsNativeWriterLease::admit_with_policy(
        std::move(state_directory), std::move(maintenance),
        std::move(runtime), static_cast<std::uint32_t>(policy.owner),
        static_cast<std::uint32_t>(policy.group),
        policy.require_root_process);
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeWriterAdmission admit_ndms_native_writer(
    std::filesystem::path state_directory,
    std::unique_ptr<MaintenanceLease> maintenance,
    RuntimeMutationAdmission::Lease runtime,
    NdmsNativeWriterLeaseTestHooks hooks) {
    const auto owner = hooks.allow_current_process_owner
        ? static_cast<std::uint32_t>(::geteuid()) : 0U;
    const auto group = hooks.allow_current_process_owner
        ? static_cast<std::uint32_t>(::getegid()) : 0U;
    return NdmsNativeWriterLease::admit_with_policy(
        std::move(state_directory), std::move(maintenance),
        std::move(runtime), owner, group,
        !hooks.allow_current_process_owner);
}
#endif

const char* ndms_native_writer_lease_scope_name(
    const NdmsNativeWriterLeaseScope scope) noexcept {
    switch (scope) {
    case NdmsNativeWriterLeaseScope::keen_pbr_cooperative:
        return "keen_pbr_cooperative";
    }
    return "keen_pbr_cooperative";
}

const char* ndms_native_writer_admission_state_name(
    const NdmsNativeWriterAdmissionState state) noexcept {
    switch (state) {
    case NdmsNativeWriterAdmissionState::admitted:
        return "admitted";
    case NdmsNativeWriterAdmissionState::outer_guard_missing:
        return "outer_guard_missing";
    case NdmsNativeWriterAdmissionState::outer_guard_lost:
        return "outer_guard_lost";
    case NdmsNativeWriterAdmissionState::state_directory_unsafe:
        return "state_directory_unsafe";
    case NdmsNativeWriterAdmissionState::lease_busy:
        return "lease_busy";
    case NdmsNativeWriterAdmissionState::lease_io_error:
        return "lease_io_error";
    }
    return "lease_io_error";
}

} // namespace keen_pbr3
