#include "maintenance_lock.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kProductionHelper =
    "/opt/usr/lib/keen-pbr/update-lock.sh";
constexpr std::size_t kMaxCommandOutput = 1024;
constexpr std::size_t kMaxReadyRecord = 512;
constexpr std::uint32_t kMaxGeneration = 2147483646U;

using Clock = std::chrono::steady_clock;

class FileDescriptor {
public:
    explicit FileDescriptor(int value = -1) noexcept : value_(value) {}
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
    void reset(int value = -1) noexcept {
        if (value_ >= 0) (void)::close(value_);
        value_ = value;
    }

private:
    int value_;
};

std::string errno_message(const std::string& prefix, int error = errno) {
    return prefix + ": " + std::strerror(error);
}

void make_pipe(int descriptors[2]) {
    bool cloexec_at_creation = false;
#ifdef O_CLOEXEC
    if (::pipe2(descriptors, O_CLOEXEC) == 0) {
        cloexec_at_creation = true;
    } else if (errno != ENOSYS) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            errno_message("Cannot create maintenance helper pipe"));
    }
#endif
    if (!cloexec_at_creation && ::pipe(descriptors) != 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            errno_message("Cannot create maintenance helper pipe"));
    }
    if (!cloexec_at_creation) {
        for (int index = 0; index < 2; ++index) {
            const int flags = ::fcntl(descriptors[index], F_GETFD);
            if (flags < 0 ||
                ::fcntl(descriptors[index],
                        F_SETFD,
                        flags | FD_CLOEXEC) != 0) {
                const int error = errno;
                ::close(descriptors[0]);
                ::close(descriptors[1]);
                descriptors[0] = descriptors[1] = -1;
                throw MaintenanceLockError(
                    MaintenanceLockErrorKind::system_error,
                    errno_message(
                        "Cannot protect maintenance helper pipe", error));
            }
        }
    }
    for (int index = 0; index < 2; ++index) {
        if (descriptors[index] > STDERR_FILENO) continue;
#ifdef F_DUPFD_CLOEXEC
        const int duplicate =
            ::fcntl(descriptors[index], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
#else
        const int duplicate =
            ::fcntl(descriptors[index], F_DUPFD, STDERR_FILENO + 1);
#endif
        if (duplicate < 0) {
            const int error = errno;
            ::close(descriptors[0]);
            ::close(descriptors[1]);
            descriptors[0] = descriptors[1] = -1;
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::system_error,
                errno_message(
                    "Cannot protect maintenance helper pipe", error));
        }
#ifndef F_DUPFD_CLOEXEC
        const int duplicate_flags = ::fcntl(duplicate, F_GETFD);
        if (duplicate_flags < 0 ||
            ::fcntl(duplicate,
                    F_SETFD,
                    duplicate_flags | FD_CLOEXEC) != 0) {
            const int error = errno;
            ::close(duplicate);
            ::close(descriptors[0]);
            ::close(descriptors[1]);
            descriptors[0] = descriptors[1] = -1;
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::system_error,
                errno_message(
                    "Cannot protect maintenance helper pipe", error));
        }
#endif
        (void)::close(descriptors[index]);
        descriptors[index] = duplicate;
    }
}

void make_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 ||
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            errno_message(
                "Cannot make maintenance helper pipe nonblocking"));
    }
}

FileDescriptor open_devnull(int flags) {
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    FileDescriptor descriptor(::open("/dev/null", flags));
    if (descriptor.get() < 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            errno_message("Cannot open /dev/null for maintenance helper"));
    }

    if (descriptor.get() <= STDERR_FILENO) {
#ifdef F_DUPFD_CLOEXEC
        const int duplicate =
            ::fcntl(descriptor.get(),
                    F_DUPFD_CLOEXEC,
                    STDERR_FILENO + 1);
#else
        const int duplicate =
            ::fcntl(descriptor.get(), F_DUPFD, STDERR_FILENO + 1);
#endif
        if (duplicate < 0) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::system_error,
                errno_message(
                    "Cannot protect /dev/null for maintenance helper"));
        }
#ifndef F_DUPFD_CLOEXEC
        const int duplicate_flags = ::fcntl(duplicate, F_GETFD);
        if (duplicate_flags < 0 ||
            ::fcntl(duplicate,
                    F_SETFD,
                    duplicate_flags | FD_CLOEXEC) != 0) {
            const int error = errno;
            (void)::close(duplicate);
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::system_error,
                errno_message(
                    "Cannot protect /dev/null for maintenance helper",
                    error));
        }
#endif
        descriptor.reset(duplicate);
    }
    return descriptor;
}

class PreparedEnvironment {
public:
    explicit PreparedEnvironment(const std::string& rescue_root) {
        values_.emplace_back(
            "PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin");
        values_.emplace_back("LC_ALL=C");
        values_.emplace_back("LANG=C");
        values_.emplace_back("HOME=/root");
        if (!rescue_root.empty()) {
            values_.push_back(
                "KEEN_PBR_RESCUE_ROOT=" + rescue_root);
#ifdef KEEN_PBR3_TESTING
            // Fault injection is accepted only with an explicit alternate
            // root. Production helpers receive a fixed, minimal environment.
            for (const char* name : {
                     "KEEN_PBR_UPDATE_LOCK_TEST_FAIL_BEFORE_COMMIT",
                     "KEEN_PBR_UPDATE_LOCK_TEST_FAIL_GENERATION_BEFORE_COMMIT",
                     "KEEN_PBR_UPDATE_LOCK_TEST_FAIL_GENERATION_AFTER_COMMIT",
                     "KEEN_PBR_UPDATE_LOCK_TEST_FAIL_SYNC_GENERATION",
                     "KEEN_PBR_UPDATE_LOCK_TEST_PAUSE_BEFORE_READY",
                 }) {
                if (const char* value = ::getenv(name)) {
                    values_.push_back(
                        std::string(name) + "=" + value);
                }
            }
#endif
        }

        pointers_.reserve(values_.size() + 1);
        for (auto& value : values_) {
            pointers_.push_back(value.data());
        }
        pointers_.push_back(nullptr);
    }

    char* const* data() noexcept { return pointers_.data(); }

private:
    std::vector<std::string> values_;
    std::vector<char*> pointers_;
};

class PreparedArguments {
public:
    PreparedArguments(const std::string& helper_path,
                      const std::vector<std::string>& arguments) {
        values_.reserve(arguments.size() + 1);
        values_.push_back(helper_path);
        values_.insert(
            values_.end(), arguments.begin(), arguments.end());

        pointers_.reserve(values_.size() + 1);
        for (auto& value : values_) {
            pointers_.push_back(value.data());
        }
        pointers_.push_back(nullptr);
    }

    char* const* data() noexcept { return pointers_.data(); }

private:
    std::vector<std::string> values_;
    std::vector<char*> pointers_;
};

struct DescriptorMapping {
    int source;
    int target;
};

int spawn_helper(
    pid_t& pid,
    const std::string& helper_path,
    const std::string& rescue_root,
    const std::vector<std::string>& arguments,
    const std::vector<DescriptorMapping>& mappings,
    const std::vector<int>& close_descriptors) {
    PreparedArguments prepared_arguments(helper_path, arguments);
    PreparedEnvironment prepared_environment(rescue_root);

    posix_spawn_file_actions_t actions;
    int error = ::posix_spawn_file_actions_init(&actions);
    if (error != 0) return error;

    for (const auto& mapping : mappings) {
        error = ::posix_spawn_file_actions_adddup2(
            &actions, mapping.source, mapping.target);
        if (error != 0) break;
    }
    if (error == 0) {
        for (const int descriptor : close_descriptors) {
            error = ::posix_spawn_file_actions_addclose(
                &actions, descriptor);
            if (error != 0) break;
        }
    }

    posix_spawnattr_t attributes;
    bool attributes_initialized = false;
    if (error == 0) {
        error = ::posix_spawnattr_init(&attributes);
        attributes_initialized = error == 0;
    }
    if (error == 0) {
        sigset_t defaults;
        ::sigemptyset(&defaults);
        for (const int signal_number :
             {SIGHUP, SIGINT, SIGTERM, SIGPIPE}) {
            ::sigaddset(&defaults, signal_number);
        }
        sigset_t empty_mask;
        ::sigemptyset(&empty_mask);

        error = ::posix_spawnattr_setpgroup(&attributes, 0);
        if (error == 0) {
            error = ::posix_spawnattr_setsigdefault(
                &attributes, &defaults);
        }
        if (error == 0) {
            error = ::posix_spawnattr_setsigmask(
                &attributes, &empty_mask);
        }
        if (error == 0) {
            constexpr short flags =
                POSIX_SPAWN_SETPGROUP |
                POSIX_SPAWN_SETSIGDEF |
                POSIX_SPAWN_SETSIGMASK;
            error = ::posix_spawnattr_setflags(
                &attributes, flags);
        }
    }

    if (error == 0) {
        error = ::posix_spawn(
            &pid,
            helper_path.c_str(),
            &actions,
            &attributes,
            prepared_arguments.data(),
            prepared_environment.data());
    }

    if (attributes_initialized) {
        (void)::posix_spawnattr_destroy(&attributes);
    }
    (void)::posix_spawn_file_actions_destroy(&actions);
    return error;
}

[[noreturn]] void throw_spawn_error(
    const std::string& context,
    int error) {
    if (error == ENOENT || error == EACCES || error == ENOEXEC) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::helper_execution,
            context + ": maintenance helper could not execute",
            127);
    }
    throw MaintenanceLockError(
        MaintenanceLockErrorKind::system_error,
        errno_message(context, error));
}

bool process_group_exists(pid_t pid) noexcept {
    if (pid <= 1) return false;
    if (::kill(-pid, 0) == 0) return true;
    return errno == EPERM;
}

void signal_process_group(pid_t pid, int signal_number) noexcept {
    if (pid <= 1) return;
    (void)::kill(-pid, signal_number);
}

bool reap_until(pid_t pid,
                Clock::time_point deadline,
                int& status) noexcept {
    while (true) {
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) return true;
        if (waited < 0 && errno != EINTR) return errno == ECHILD;
        if (Clock::now() >= deadline) return false;
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - Clock::now());
        const int delay = static_cast<int>(
            std::max<std::int64_t>(
                1, std::min<std::int64_t>(20, remaining.count())));
        (void)::poll(nullptr, 0, delay);
    }
}

void terminate_and_reap(
    pid_t pid,
    std::chrono::milliseconds grace) noexcept {
    if (pid <= 1) return;
    int status = 0;
    bool leader_reaped = false;
    signal_process_group(pid, SIGTERM);
    const auto deadline = Clock::now() + grace;
    while (Clock::now() < deadline) {
        if (!leader_reaped) {
            const pid_t waited = ::waitpid(pid, &status, WNOHANG);
            if (waited == pid ||
                (waited < 0 && errno == ECHILD)) {
                leader_reaped = true;
            }
        }
        if (leader_reaped && !process_group_exists(pid)) {
            return;
        }
        (void)::poll(nullptr, 0, 10);
    }
    if (process_group_exists(pid)) {
        signal_process_group(pid, SIGKILL);
    }
    if (!leader_reaped) {
        while (::waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) break;
        }
    }
}

int decoded_exit_code(int status) noexcept {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

struct CommandResult {
    std::string output;
    int exit_code{-1};
    bool timed_out{false};
    bool output_overflow{false};
};

CommandResult run_helper_command(
    const std::string& helper_path,
    const std::string& rescue_root,
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout,
    std::chrono::milliseconds terminate_grace) {
    int output_pipe[2] = {-1, -1};
    make_pipe(output_pipe);
    FileDescriptor output_read(output_pipe[0]);
    FileDescriptor output_write(output_pipe[1]);
    FileDescriptor devnull = open_devnull(O_RDWR);

    pid_t pid = -1;
    const int spawn_error = spawn_helper(
        pid,
        helper_path,
        rescue_root,
        arguments,
        {
            {devnull.get(), STDIN_FILENO},
            {output_write.get(), STDOUT_FILENO},
            {devnull.get(), STDERR_FILENO},
        },
        {
            output_read.get(),
            output_write.get(),
            devnull.get(),
        });
    if (spawn_error != 0) {
        throw_spawn_error(
            "Cannot spawn maintenance helper", spawn_error);
    }

    output_write.reset();
    devnull.reset();
    try {
        make_nonblocking(output_read.get());
    } catch (...) {
        terminate_and_reap(pid, terminate_grace);
        throw;
    }

    CommandResult result;
    const auto deadline = Clock::now() + timeout;
    bool output_open = true;
    bool child_reaped = false;
    int status = 0;
    std::array<char, 256> buffer{};
    while (output_open || !child_reaped) {
        if (output_open) {
            while (true) {
                const ssize_t count =
                    ::read(output_read.get(), buffer.data(), buffer.size());
                if (count > 0) {
                    const auto received = static_cast<std::size_t>(count);
                    const auto available =
                        result.output.size() < kMaxCommandOutput
                            ? kMaxCommandOutput - result.output.size()
                            : 0;
                    result.output.append(
                        buffer.data(), std::min(received, available));
                    if (received > available) {
                        result.output_overflow = true;
                    }
                    continue;
                }
                if (count == 0) {
                    output_read.reset();
                    output_open = false;
                } else if (errno == EINTR) {
                    continue;
                }
                break;
            }
        }

        if (!child_reaped) {
            const pid_t waited = ::waitpid(pid, &status, WNOHANG);
            if (waited == pid) {
                child_reaped = true;
            } else if (waited < 0 && errno != EINTR) {
                child_reaped = true;
                status = -1;
            }
        }
        if (result.output_overflow) {
            terminate_and_reap(pid, terminate_grace);
            child_reaped = true;
            status = -1;
            if (output_open) {
                output_read.reset();
                output_open = false;
            }
            break;
        }
        if (output_open || !child_reaped) {
            if (Clock::now() >= deadline) {
                result.timed_out = true;
                terminate_and_reap(pid, terminate_grace);
                child_reaped = true;
                status = -1;
                if (output_open) {
                    output_read.reset();
                    output_open = false;
                }
                break;
            }
            pollfd descriptor{
                output_open ? output_read.get() : -1,
                static_cast<short>(POLLIN | POLLHUP),
                0,
            };
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - Clock::now());
            const int delay = static_cast<int>(
                std::max<std::int64_t>(
                    1,
                    std::min<std::int64_t>(
                        20, remaining.count())));
            (void)::poll(&descriptor, 1, delay);
        }
    }
    if (!result.timed_out && !result.output_overflow && status != -1) {
        result.exit_code = decoded_exit_code(status);
    }
    return result;
}

struct OrphanedMaintenanceLease {
    std::string helper_path;
    std::string rescue_root;
    pid_t owner_pid{-1};
    std::string token;
    std::chrono::milliseconds timeout;
    std::chrono::milliseconds terminate_grace;
};

std::mutex orphaned_leases_mutex;
std::vector<OrphanedMaintenanceLease> orphaned_leases;

bool command_succeeded_without_output(
    const CommandResult& result) noexcept {
    return !result.timed_out && !result.output_overflow &&
           result.exit_code == 0 && result.output.empty();
}

bool release_or_confirm_absent(
    const OrphanedMaintenanceLease& lease) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        try {
            const auto release = run_helper_command(
                lease.helper_path,
                lease.rescue_root,
                {
                    "release",
                    std::to_string(
                        static_cast<long>(lease.owner_pid)),
                    lease.token,
                },
                lease.timeout,
                lease.terminate_grace);
            if (command_succeeded_without_output(release)) {
                return true;
            }

            const auto held = run_helper_command(
                lease.helper_path,
                lease.rescue_root,
                {
                    "held",
                    std::to_string(
                        static_cast<long>(lease.owner_pid)),
                    lease.token,
                },
                lease.timeout,
                lease.terminate_grace);
            if (!held.timed_out && !held.output_overflow &&
                held.exit_code == 1 && held.output.empty()) {
                return true;
            }
        } catch (...) {
        }
        (void)::poll(nullptr, 0, 25);
    }
    return false;
}

void retain_orphaned_lease(
    OrphanedMaintenanceLease lease) noexcept {
    try {
        std::lock_guard<std::mutex> lock(orphaned_leases_mutex);
        const auto duplicate = std::find_if(
            orphaned_leases.begin(),
            orphaned_leases.end(),
            [&lease](const OrphanedMaintenanceLease& existing) {
                return existing.owner_pid == lease.owner_pid &&
                       existing.token == lease.token &&
                       existing.helper_path == lease.helper_path &&
                       existing.rescue_root == lease.rescue_root;
            });
        if (duplicate == orphaned_leases.end()) {
            orphaned_leases.push_back(std::move(lease));
        }
    } catch (...) {
        // Losing credentials could leave a live-PID lock forever. A process
        // restart is the only safe fallback when memory allocation itself
        // failed, so terminate instead of silently continuing unlocked.
        std::terminate();
    }
}

void drain_orphaned_leases() {
    std::lock_guard<std::mutex> lock(orphaned_leases_mutex);
    auto next = orphaned_leases.begin();
    for (auto current = orphaned_leases.begin();
         current != orphaned_leases.end();
         ++current) {
        if (!release_or_confirm_absent(*current)) {
            if (next != current) *next = std::move(*current);
            ++next;
        }
    }
    orphaned_leases.erase(next, orphaned_leases.end());
    if (!orphaned_leases.empty()) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "A previous maintenance lease could not be released");
    }
}

bool canonical_decimal(std::string_view text,
                       std::uint32_t maximum,
                       std::uint32_t& value) {
    if (text.empty()) return false;
    if (text.size() > 1 && text.front() == '0') return false;
    std::uint64_t parsed = 0;
    for (const char character : text) {
        if (character < '0' || character > '9') return false;
        parsed = parsed * 10 +
                 static_cast<unsigned int>(character - '0');
        if (parsed > maximum) return false;
    }
    value = static_cast<std::uint32_t>(parsed);
    return true;
}

bool valid_operation(const std::string& operation) {
    if (operation.empty() || operation.size() > 32 ||
        operation.front() < 'a' || operation.front() > 'z') {
        return false;
    }
    return std::all_of(
        operation.begin() + 1,
        operation.end(),
        [](unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9') ||
                   character == '-';
        });
}

void validate_helper_metadata(const std::string& helper_path,
                              bool production_helper) {
    struct stat helper {};
    if (::lstat(helper_path.c_str(), &helper) != 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::helper_execution,
            errno_message("Cannot inspect maintenance helper"),
            127);
    }
    const uid_t required_owner =
        production_helper ? static_cast<uid_t>(0) : ::geteuid();
    if (!S_ISREG(helper.st_mode) || S_ISLNK(helper.st_mode) ||
        helper.st_uid != required_owner ||
        (helper.st_mode & 0022) != 0 ||
        (helper.st_mode & S_IXUSR) == 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "Maintenance helper metadata is unsafe");
    }
    if (!production_helper) return;

    std::string current{"/"};
    std::size_t offset = 1;
    while (offset < helper_path.size()) {
        const auto separator = helper_path.find('/', offset);
        if (separator == std::string::npos) break;
        const auto component =
            helper_path.substr(offset, separator - offset);
        offset = separator + 1;
        if (component.empty()) continue;
        if (current.size() > 1) current.push_back('/');
        current += component;

        struct stat directory {};
        if (::lstat(current.c_str(), &directory) != 0 ||
            !S_ISDIR(directory.st_mode) ||
            S_ISLNK(directory.st_mode) ||
            directory.st_uid != 0 ||
            (directory.st_mode & 0022) != 0) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::unsafe_state,
                "Maintenance helper parent metadata is unsafe");
        }
    }
}

std::string make_owner_token(const std::string& operation,
                             pid_t owner_pid) {
    std::array<unsigned char, 16> random_bytes{};
#ifdef O_CLOEXEC
    FileDescriptor random_source(
        ::open("/dev/urandom", O_RDONLY | O_CLOEXEC));
#else
    FileDescriptor random_source(::open("/dev/urandom", O_RDONLY));
#endif
    if (random_source.get() < 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            errno_message("Cannot open maintenance token source"));
    }
#ifndef O_CLOEXEC
    const int descriptor_flags =
        ::fcntl(random_source.get(), F_GETFD);
    if (descriptor_flags < 0 ||
        ::fcntl(random_source.get(),
                F_SETFD,
                descriptor_flags | FD_CLOEXEC) != 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            errno_message("Cannot protect maintenance token source"));
    }
#endif

    std::size_t offset = 0;
    while (offset < random_bytes.size()) {
        const ssize_t count = ::read(
            random_source.get(),
            random_bytes.data() + offset,
            random_bytes.size() - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::system_error,
            count == 0
                ? "Maintenance token source ended unexpectedly"
                : errno_message("Cannot read maintenance token source"));
    }

    constexpr char hex[] = "0123456789abcdef";
    std::string token =
        operation + "." +
        std::to_string(static_cast<long>(owner_pid)) + ".";
    token.reserve(token.size() + random_bytes.size() * 2);
    for (const unsigned char byte : random_bytes) {
        token.push_back(hex[byte >> 4U]);
        token.push_back(hex[byte & 0x0fU]);
    }
    return token;
}

bool valid_token(const std::string& token,
                  const std::string& operation) {
    if (token.empty() || token.size() > 192 ||
        token.rfind(operation + ".", 0) != 0) {
        return false;
    }
    return std::all_of(
        token.begin(), token.end(), [](unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') ||
                   character == '.' || character == '_' ||
                   character == '-';
        });
}

MaintenanceLockError command_failure(
    const std::string& context,
    const CommandResult& result) {
    if (result.timed_out) {
        return {
            MaintenanceLockErrorKind::timeout,
            context + " timed out",
        };
    }
    if (result.output_overflow) {
        return {
            MaintenanceLockErrorKind::malformed_response,
            context + " produced too much output",
        };
    }
    if (result.exit_code == 75) {
        return {
            MaintenanceLockErrorKind::busy,
            context + ": maintenance lock is busy",
            result.exit_code,
        };
    }
    if (result.exit_code == 73) {
        return {
            MaintenanceLockErrorKind::stale_generation,
            context + ": maintenance generation is stale",
            result.exit_code,
        };
    }
    if (result.exit_code == 126 || result.exit_code == 127 ||
        result.exit_code < 0) {
        return {
            MaintenanceLockErrorKind::helper_execution,
            context + ": maintenance helper could not execute",
            result.exit_code,
        };
    }
    return {
        MaintenanceLockErrorKind::unsafe_state,
        context + ": maintenance helper rejected unsafe state",
        result.exit_code,
    };
}

std::string require_single_line(const std::string& context,
                                const CommandResult& result) {
    if (result.exit_code != 0 || result.timed_out ||
        result.output_overflow) {
        throw command_failure(context, result);
    }
    if (result.output.empty() || result.output.back() != '\n' ||
        result.output.find('\n') != result.output.size() - 1 ||
        result.output.find('\0') != std::string::npos ||
        result.output.find('\r') != std::string::npos) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::malformed_response,
            context + " returned a malformed response");
    }
    return result.output.substr(0, result.output.size() - 1);
}

} // namespace

struct MaintenanceCoordinator::RuntimeOptions {
    std::string helper_path;
    std::string rescue_root;
    std::chrono::milliseconds command_timeout;
    std::chrono::milliseconds durability_timeout;
    std::chrono::milliseconds ready_timeout;
    std::chrono::milliseconds terminate_grace;
    bool production_helper{false};
};

MaintenanceLockError::MaintenanceLockError(
    MaintenanceLockErrorKind kind,
    std::string message,
    int helper_exit_code)
    : std::runtime_error(std::move(message)),
      kind_(kind),
      helper_exit_code_(helper_exit_code) {}

MaintenanceLockErrorKind MaintenanceLockError::kind() const noexcept {
    return kind_;
}

int MaintenanceLockError::helper_exit_code() const noexcept {
    return helper_exit_code_;
}

MaintenanceCoordinator::MaintenanceCoordinator(
    std::string operation) {
    start(
        std::move(operation),
        {
            std::string(kProductionHelper),
            {},
            std::chrono::seconds{3},
            std::chrono::seconds{15},
            std::chrono::seconds{3},
            std::chrono::milliseconds{250},
            true,
        });
}

#ifdef KEEN_PBR3_TESTING
MaintenanceCoordinator::MaintenanceCoordinator(
    std::string operation,
    MaintenanceCoordinatorTestOptions options) {
    start(
        std::move(operation),
        {
            options.helper_path.string(),
            options.rescue_root.has_value()
                ? options.rescue_root->string()
                : std::string{},
            options.command_timeout,
            options.durability_timeout,
            options.ready_timeout,
            options.terminate_grace,
            false,
        });
}
#endif

MaintenanceCoordinator::~MaintenanceCoordinator() noexcept {
    release_noexcept();
}

void MaintenanceCoordinator::start(
    std::string operation,
    RuntimeOptions options) {
    if (!valid_operation(operation)) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "Invalid maintenance operation");
    }
    if (options.helper_path.empty() ||
        options.helper_path.front() != '/') {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "Maintenance helper path must be absolute");
    }
    if (options.command_timeout.count() <= 0 ||
        options.durability_timeout.count() <= 0 ||
        options.ready_timeout.count() <= 0 ||
        options.terminate_grace.count() < 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "Maintenance helper timeouts are invalid");
    }

    operation_ = std::move(operation);
    owner_pid_ = ::getpid();
    if (owner_pid_ <= 1) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "Maintenance owner PID is invalid");
    }
    token_ = make_owner_token(operation_, owner_pid_);
    helper_path_ = std::move(options.helper_path);
    rescue_root_ = std::move(options.rescue_root);
    command_timeout_ms_ = options.command_timeout.count();
    durability_timeout_ms_ =
        options.durability_timeout.count();
    ready_timeout_ms_ = options.ready_timeout.count();
    terminate_grace_ms_ = options.terminate_grace.count();
    validate_helper_metadata(
        helper_path_, options.production_helper);

    const auto protocol_result = run_helper_command(
        helper_path_,
        rescue_root_,
        {"protocol"},
        options.command_timeout,
        options.terminate_grace);
    const std::string protocol =
        require_single_line("Maintenance protocol check", protocol_result);
    if (protocol != "3") {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::protocol_mismatch,
            "Maintenance helper protocol 3 is required");
    }
    drain_orphaned_leases();

    int control_pipe[2] = {-1, -1};
    int status_pipe[2] = {-1, -1};
    make_pipe(control_pipe);
    FileDescriptor control_read(control_pipe[0]);
    FileDescriptor control_write(control_pipe[1]);
    try {
        make_pipe(status_pipe);
    } catch (...) {
        throw;
    }
    FileDescriptor status_read(status_pipe[0]);
    FileDescriptor status_write(status_pipe[1]);
    FileDescriptor devnull = open_devnull(O_WRONLY);

    const int spawn_error = spawn_helper(
        guardian_pid_,
        helper_path_,
        rescue_root_,
        {
            "guard",
            operation_,
            std::to_string(static_cast<long>(owner_pid_)),
            token_,
        },
        {
            {control_read.get(), STDIN_FILENO},
            {status_write.get(), STDOUT_FILENO},
            {devnull.get(), STDERR_FILENO},
        },
        {
            control_read.get(),
            control_write.get(),
            status_read.get(),
            status_write.get(),
            devnull.get(),
        });
    if (spawn_error != 0) {
        guardian_pid_ = -1;
        throw_spawn_error(
            "Cannot spawn maintenance guardian", spawn_error);
    }

    control_read.reset();
    status_write.reset();
    devnull.reset();
    control_fd_ = control_write.release();
    try {
        make_nonblocking(status_read.get());

        const auto deadline = Clock::now() + options.ready_timeout;
        std::string line;
        bool newline = false;
        while (!newline) {
            std::array<char, 64> buffer{};
            while (true) {
                const ssize_t count =
                    ::read(status_read.get(), buffer.data(), buffer.size());
                if (count > 0) {
                    for (ssize_t index = 0; index < count; ++index) {
                        const char character =
                            buffer[static_cast<std::size_t>(index)];
                        if (newline || character == '\0' ||
                            character == '\r') {
                            throw MaintenanceLockError(
                                MaintenanceLockErrorKind::
                                    malformed_response,
                                "Maintenance guardian returned a malformed "
                                "ready record");
                        }
                        if (character == '\n') {
                            newline = true;
                            continue;
                        }
                        if (line.size() >= kMaxReadyRecord) {
                            throw MaintenanceLockError(
                                MaintenanceLockErrorKind::
                                    malformed_response,
                                "Maintenance guardian ready record is too "
                                "large");
                        }
                        line.push_back(character);
                    }
                    continue;
                }
                if (count == 0) {
                    int status = 0;
                    const bool reaped =
                        reap_until(guardian_pid_, deadline, status);
                    const int exit_code =
                        reaped ? decoded_exit_code(status) : -1;
                    if (!reaped) {
                        terminate_and_reap(
                            guardian_pid_, options.terminate_grace);
                    }
                    guardian_pid_ = -1;
                    if (control_fd_ >= 0) {
                        (void)::close(control_fd_);
                        control_fd_ = -1;
                    }
                    CommandResult result;
                    result.exit_code = exit_code;
                    result.timed_out = !reaped;
                    throw command_failure(
                        "Maintenance guardian startup", result);
                }
                if (errno == EINTR) continue;
                break;
            }
            if (newline) break;

            int status = 0;
            const pid_t waited =
                ::waitpid(guardian_pid_, &status, WNOHANG);
            if (waited == guardian_pid_) {
                const int exit_code = decoded_exit_code(status);
                guardian_pid_ = -1;
                if (control_fd_ >= 0) {
                    (void)::close(control_fd_);
                    control_fd_ = -1;
                }
                CommandResult result;
                result.exit_code = exit_code;
                throw command_failure(
                    "Maintenance guardian startup", result);
            }
            if (Clock::now() >= deadline) {
                throw MaintenanceLockError(
                    MaintenanceLockErrorKind::timeout,
                    "Maintenance guardian ready record timed out");
            }
            pollfd descriptor{
                status_read.get(),
                static_cast<short>(POLLIN | POLLHUP),
                0,
            };
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - Clock::now());
            const int delay = static_cast<int>(
                std::max<std::int64_t>(
                    1,
                    std::min<std::int64_t>(
                        20, remaining.count())));
            (void)::poll(&descriptor, 1, delay);
        }

        const std::size_t first_space = line.find(' ');
        const std::size_t second_space =
            first_space == std::string::npos
                ? std::string::npos
                : line.find(' ', first_space + 1);
        if (first_space == std::string::npos ||
            second_space == std::string::npos ||
            line.find(' ', second_space + 1) != std::string::npos ||
            first_space == 0 || second_space == first_space + 1 ||
            second_space + 1 >= line.size()) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::malformed_response,
                "Maintenance guardian returned a malformed ready record");
        }
        const std::string pid_text = line.substr(0, first_space);
        const std::string ready_token = line.substr(
            first_space + 1, second_space - first_space - 1);
        const std::string generation_text =
            line.substr(second_space + 1);
        std::uint32_t parsed_pid = 0;
        if (!canonical_decimal(
                pid_text,
                static_cast<std::uint32_t>(
                    std::numeric_limits<pid_t>::max()),
                parsed_pid) ||
            parsed_pid <= 1 ||
            static_cast<pid_t>(parsed_pid) != owner_pid_ ||
            ready_token != token_ ||
            !valid_token(ready_token, operation_) ||
            !canonical_decimal(
                generation_text,
                kMaxGeneration,
                base_generation_)) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::malformed_response,
                "Maintenance guardian returned a malformed ready record");
        }
        verify_held();
    } catch (...) {
        status_read.reset();
        release_noexcept();
        throw;
    }
}

const std::string& MaintenanceCoordinator::operation() const noexcept {
    return operation_;
}

std::uint32_t MaintenanceCoordinator::base_generation() const noexcept {
    return base_generation_;
}

void MaintenanceCoordinator::verify_held() {
    if (guardian_pid_ <= 1 || control_fd_ < 0) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::guardian_died,
            "Maintenance guardian is not running");
    }
    int status = 0;
    const pid_t waited =
        ::waitpid(guardian_pid_, &status, WNOHANG);
    if (waited == guardian_pid_ ||
        (waited < 0 && errno != EINTR)) {
        if (control_fd_ >= 0) {
            (void)::close(control_fd_);
            control_fd_ = -1;
        }
        guardian_pid_ = -1;
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::guardian_died,
            "Maintenance guardian died");
    }

    const auto result = run_helper_command(
        helper_path_,
        rescue_root_,
        {
            "held",
            std::to_string(static_cast<long>(owner_pid_)),
            token_,
        },
        std::chrono::milliseconds{command_timeout_ms_},
        std::chrono::milliseconds{terminate_grace_ms_});
    if (result.exit_code != 0 || result.timed_out ||
        result.output_overflow) {
        status = 0;
        const bool guardian_reaped = reap_until(
            guardian_pid_,
            Clock::now() + std::chrono::milliseconds{20},
            status);
        if (guardian_reaped) {
            if (control_fd_ >= 0) {
                (void)::close(control_fd_);
                control_fd_ = -1;
            }
            guardian_pid_ = -1;
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::guardian_died,
                "Maintenance guardian died while verifying ownership");
        }
        throw command_failure(
            "Maintenance ownership verification", result);
    }
    if (!result.output.empty()) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::malformed_response,
            "Maintenance ownership verification returned output");
    }
}

std::uint32_t MaintenanceCoordinator::reserve(
    std::uint32_t expected_generation) {
    std::lock_guard<std::mutex> reserve_lock(reserve_mutex_);
    if (expected_generation > kMaxGeneration) {
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            "Expected maintenance generation is out of range");
    }
    verify_held();
    const auto result = run_helper_command(
        helper_path_,
        rescue_root_,
        {
            "reserve",
            std::to_string(static_cast<long>(owner_pid_)),
            token_,
            std::to_string(expected_generation),
        },
        std::chrono::milliseconds{command_timeout_ms_},
        std::chrono::milliseconds{terminate_grace_ms_});

    const auto reconcile_generation =
        [&](MaintenanceLockError original_error) -> std::uint32_t {
        const auto generation_result = run_helper_command(
            helper_path_,
            rescue_root_,
            {"generation"},
            std::chrono::milliseconds{command_timeout_ms_},
            std::chrono::milliseconds{terminate_grace_ms_});
        std::string generation_text;
        try {
            generation_text = require_single_line(
                "Maintenance generation reconciliation",
                generation_result);
        } catch (const MaintenanceLockError& reconciliation_error) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::unsafe_state,
                std::string(original_error.what()) +
                    "; current generation cannot be reconciled: " +
                    reconciliation_error.what(),
                original_error.helper_exit_code());
        }

        std::uint32_t current_generation = 0;
        if (!canonical_decimal(
                generation_text,
                kMaxGeneration,
                current_generation)) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::unsafe_state,
                std::string(original_error.what()) +
                    "; current generation response is malformed",
                original_error.helper_exit_code());
        }
        if (current_generation == expected_generation + 1U) {
            const auto durability_result = run_helper_command(
                helper_path_,
                rescue_root_,
                {
                    "sync-generation",
                    std::to_string(
                        static_cast<long>(owner_pid_)),
                    token_,
                    std::to_string(current_generation),
                },
                std::chrono::milliseconds{
                    durability_timeout_ms_},
                std::chrono::milliseconds{
                    terminate_grace_ms_});
            try {
                const auto durable_generation =
                    require_single_line(
                        "Maintenance generation durability "
                        "reconciliation",
                        durability_result);
                std::uint32_t confirmed = 0;
                if (!canonical_decimal(
                        durable_generation,
                        kMaxGeneration,
                        confirmed) ||
                    confirmed != current_generation) {
                    throw MaintenanceLockError(
                        MaintenanceLockErrorKind::
                            malformed_response,
                        "Maintenance generation durability "
                        "reconciliation returned an unexpected "
                        "generation");
                }
            } catch (const MaintenanceLockError& durability_error) {
                throw MaintenanceLockError(
                    MaintenanceLockErrorKind::unsafe_state,
                    std::string(original_error.what()) +
                        "; visible generation could not be made "
                        "durable: " + durability_error.what(),
                    original_error.helper_exit_code());
            }
            return current_generation;
        }
        if (current_generation == expected_generation) {
            throw original_error;
        }
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::unsafe_state,
            std::string(original_error.what()) +
                "; current generation moved to an unexpected value " +
                std::to_string(current_generation),
            original_error.helper_exit_code());
    };

    if (result.exit_code != 0 || result.timed_out ||
        result.output_overflow) {
        if (!result.timed_out && !result.output_overflow &&
            (result.exit_code == 73 || result.exit_code == 75)) {
            throw command_failure(
                "Maintenance generation reservation", result);
        }
        int status = 0;
        const bool check_guardian =
            result.exit_code != 73 && guardian_pid_ > 1;
        if (check_guardian &&
            reap_until(
                guardian_pid_,
                Clock::now() + std::chrono::milliseconds{20},
                status)) {
            if (control_fd_ >= 0) {
                (void)::close(control_fd_);
                control_fd_ = -1;
            }
            guardian_pid_ = -1;
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::guardian_died,
                "Maintenance guardian died while reserving generation");
        }
        return reconcile_generation(command_failure(
            "Maintenance generation reservation", result));
    }
    std::string output;
    try {
        output = require_single_line(
            "Maintenance generation reservation", result);
    } catch (const MaintenanceLockError& error) {
        return reconcile_generation(error);
    }
    std::uint32_t generation = 0;
    if (!canonical_decimal(output, kMaxGeneration, generation) ||
        generation != expected_generation + 1U) {
        return reconcile_generation(MaintenanceLockError(
            MaintenanceLockErrorKind::malformed_response,
            "Maintenance generation reservation returned an unexpected "
            "generation"));
    }
    return generation;
}

pid_t MaintenanceCoordinator::guardian_pid() const noexcept {
    return guardian_pid_;
}

void MaintenanceCoordinator::release_noexcept() noexcept {
    if (control_fd_ >= 0) {
        (void)::close(control_fd_);
        control_fd_ = -1;
    }
    if (guardian_pid_ > 1) {
        const pid_t pid = std::exchange(guardian_pid_, -1);
        int status = 0;
        const auto timeout =
            std::chrono::milliseconds{
                std::max<std::int64_t>(1, command_timeout_ms_)};
        if (!reap_until(pid, Clock::now() + timeout, status)) {
            terminate_and_reap(
                pid,
                std::chrono::milliseconds{
                    std::max<std::int64_t>(0, terminate_grace_ms_)});
        }
    }

    // The guardian normally releases on EOF. An explicit idempotent fallback
    // is required when it died or startup failed after the parent-owned lock
    // record had already been committed.
    if (owner_pid_ > 1 && !token_.empty() &&
        !helper_path_.empty()) {
        OrphanedMaintenanceLease lease{
            helper_path_,
            rescue_root_,
            owner_pid_,
            token_,
            std::chrono::milliseconds{
                std::max<std::int64_t>(1, command_timeout_ms_)},
            std::chrono::milliseconds{
                std::max<std::int64_t>(0, terminate_grace_ms_)},
        };
        bool released = false;
        try {
            released = release_or_confirm_absent(lease);
        } catch (...) {
        }
        if (!released) {
            retain_orphaned_lease(std::move(lease));
        }
    }
    token_.clear();
    owner_pid_ = -1;
}

} // namespace keen_pbr3
