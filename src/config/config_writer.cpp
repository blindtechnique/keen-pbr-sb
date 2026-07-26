#include "config_writer.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

std::runtime_error errno_error(const std::string& prefix) {
    const int error = errno;
    return std::runtime_error(prefix + ": " + std::strerror(error));
}

void write_all(int fd, const std::string& body) {
    size_t offset = 0;
    while (offset < body.size()) {
        const ssize_t written = ::write(fd, body.data() + offset, body.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw errno_error("Cannot write atomic file");
        }
        if (written == 0) {
            throw std::runtime_error("Cannot write atomic file: short write");
        }
        offset += static_cast<size_t>(written);
    }
}

void fsync_fd(int fd, const std::string& what) {
    if (::fsync(fd) != 0) throw errno_error("Cannot fsync " + what);
}

void require_directory(const std::filesystem::path& path) {
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0) {
        throw errno_error("Cannot inspect atomic file directory");
    }
    if (!S_ISDIR(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
        throw std::runtime_error(
            "Refusing to use a non-directory or symbolic-link parent");
    }
}

int open_directory(const std::filesystem::path& directory);

void ensure_parent_directory(
    const std::filesystem::path& directory,
    const AtomicFileWriteOptions& options) {
    struct stat metadata {};
    if (::lstat(directory.c_str(), &metadata) == 0) {
        require_directory(directory);
        return;
    }
    if (errno != ENOENT) {
        throw errno_error("Cannot inspect atomic file directory");
    }
    if (!options.create_parent_directories) {
        throw errno_error("Cannot open atomic file directory");
    }

    std::vector<std::filesystem::path> missing;
    auto current = directory;
    while (true) {
        if (current.empty()) current = ".";
        if (::lstat(current.c_str(), &metadata) == 0) {
            require_directory(current);
            break;
        }
        if (errno != ENOENT) {
            throw errno_error("Cannot inspect atomic file directory");
        }
        missing.push_back(current);
        auto parent = current.parent_path();
        if (parent.empty()) parent = ".";
        if (parent == current) {
            throw std::runtime_error(
                "Cannot locate an existing atomic file parent directory");
        }
        current = std::move(parent);
    }

    for (auto component = missing.rbegin(); component != missing.rend();
         ++component) {
        bool created = false;
        if (::mkdir(component->c_str(), options.created_directory_mode) == 0) {
            created = true;
        } else if (errno != EEXIST) {
            throw errno_error("Cannot create atomic file directory");
        }
        require_directory(*component);
        if (created) {
            int directory_fd = open_directory(*component);
            if (::fchmod(directory_fd, options.created_directory_mode) != 0) {
                const int error = errno;
                ::close(directory_fd);
                errno = error;
                throw errno_error("Cannot set atomic file directory mode");
            }
            if (::close(directory_fd) != 0) {
                throw errno_error(
                    "Cannot close newly created atomic file directory");
            }
        }
    }
}

int open_directory(const std::filesystem::path& directory) {
    struct stat before {};
    if (::lstat(directory.c_str(), &before) != 0) {
        throw errno_error("Cannot inspect atomic file directory");
    }
    if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
        throw std::runtime_error(
            "Refusing to use a non-directory or symbolic-link parent");
    }

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
    const int fd = ::open(directory.c_str(), flags);
    if (fd < 0) throw errno_error("Cannot open atomic file directory");

#ifndef O_CLOEXEC
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        const int error = errno;
        ::close(fd);
        errno = error;
        throw errno_error("Cannot mark atomic file directory close-on-exec");
    }
#endif

    struct stat after {};
    if (::fstat(fd, &after) != 0) {
        const int error = errno;
        ::close(fd);
        errno = error;
        throw errno_error("Cannot inspect opened atomic file directory");
    }
    if (!S_ISDIR(after.st_mode) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino) {
        ::close(fd);
        throw std::runtime_error(
            "Atomic file directory changed while it was being opened");
    }
    return fd;
}

bool inspect_destination(int directory_fd,
                         const std::string& filename,
                         [[maybe_unused]] const std::string& path,
                         struct stat& metadata) {
#ifdef AT_SYMLINK_NOFOLLOW
    const int result = ::fstatat(
        directory_fd, filename.c_str(), &metadata, AT_SYMLINK_NOFOLLOW);
#else
    const int result = ::lstat(path.c_str(), &metadata);
#endif
    if (result == 0) {
        if (!S_ISREG(metadata.st_mode)) {
            throw std::runtime_error(
                "Refusing to replace non-regular atomic file destination");
        }
        return true;
    }
    if (errno == ENOENT) return false;
    throw errno_error("Cannot inspect atomic file destination");
}

// A process-local 32-bit sequence plus PID is sufficient because O_EXCL is
// still the authority. Keeping it 32-bit avoids a libatomic dependency on
// mips/mipsel.
std::atomic<unsigned int> temporary_sequence{0};

int create_temporary(int directory_fd, std::string& name) {
    for (unsigned int attempt = 0; attempt < 128; ++attempt) {
        const auto sequence =
            temporary_sequence.fetch_add(1, std::memory_order_relaxed);
        name = ".keen-pbr-atomic." + std::to_string(::getpid()) + "." +
               std::to_string(sequence);

        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        const int fd =
            ::openat(directory_fd, name.c_str(), flags, S_IRUSR | S_IWUSR);
        if (fd >= 0) {
#ifndef O_CLOEXEC
            if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
                const int error = errno;
                ::close(fd);
                ::unlinkat(directory_fd, name.c_str(), 0);
                errno = error;
                throw errno_error(
                    "Cannot mark temporary atomic file close-on-exec");
            }
#endif
            return fd;
        }
        if (errno != EEXIST) {
            throw errno_error("Cannot create temporary atomic file");
        }
    }
    throw std::runtime_error(
        "Cannot create temporary atomic file: name space exhausted");
}

} // namespace

AtomicFileWriteError::AtomicFileWriteError(std::string message,
                                           bool committed)
    : std::runtime_error(std::move(message)), committed_(committed) {}

bool AtomicFileWriteError::committed() const noexcept {
    return committed_;
}

void write_file_atomically(const std::string& destination,
                           const std::string& body,
                           const AtomicFileWriteOptions& options) {
    if (options.committed_result != nullptr) {
        *options.committed_result = false;
    }
    const std::filesystem::path path(destination);
    const auto filename = path.filename().string();
    if (filename.empty() || filename == "." || filename == "..") {
        throw std::runtime_error("Invalid atomic file destination");
    }
    const auto directory = path.has_parent_path() ? path.parent_path()
                                                   : std::filesystem::path(".");
    ensure_parent_directory(directory, options);

    struct stat existing {};
    int directory_fd = open_directory(directory);
    int temporary_fd = -1;
    std::string temporary_name;
    bool temporary_exists = false;
    bool committed = false;

    try {
        const bool exists = inspect_destination(
            directory_fd, filename, destination, existing);
        const mode_t mode =
            (options.file_mode.has_value()
                 ? *options.file_mode
                 : exists
                       ? (existing.st_mode &
                          options.preserved_file_mode_mask)
                       : options.default_file_mode) |
            options.additional_file_mode_bits;
        const uid_t owner = options.owner.value_or(
            exists ? existing.st_uid : ::geteuid());
        const gid_t group = options.group.value_or(
            exists ? existing.st_gid : ::getegid());

        temporary_fd = create_temporary(directory_fd, temporary_name);
        temporary_exists = true;
        if ((exists || options.owner.has_value() ||
             options.group.has_value()) &&
            ::fchown(temporary_fd, owner, group) != 0) {
            throw errno_error("Cannot preserve atomic file ownership");
        }
        if (::fchmod(temporary_fd, mode & 07777) != 0) {
            throw errno_error("Cannot set atomic file mode");
        }
#ifdef KEEN_PBR3_TESTING
        if (options.fault_injector) {
            options.fault_injector(AtomicFileWriteStage::write);
        }
#endif
        write_all(temporary_fd, body);
#ifdef KEEN_PBR3_TESTING
        if (options.fault_injector) {
            options.fault_injector(AtomicFileWriteStage::file_fsync);
        }
#endif
        fsync_fd(temporary_fd, "temporary atomic file");
        if (::close(temporary_fd) != 0) {
            temporary_fd = -1;
            throw errno_error("Cannot close temporary atomic file");
        }
        temporary_fd = -1;

#ifdef KEEN_PBR3_TESTING
        if (options.fault_injector) {
            options.fault_injector(AtomicFileWriteStage::rename);
        }
#endif
        if (::renameat(directory_fd,
                       temporary_name.c_str(),
                       directory_fd,
                       filename.c_str()) != 0) {
            throw errno_error("Cannot replace atomic file");
        }
        temporary_exists = false;
        committed = true;
        if (options.committed_result != nullptr) {
            *options.committed_result = true;
        }

#ifdef KEEN_PBR3_TESTING
        if (options.fault_injector) {
            options.fault_injector(AtomicFileWriteStage::directory_fsync);
        }
#endif
        fsync_fd(directory_fd, "atomic file directory");
        if (::close(directory_fd) != 0) {
            directory_fd = -1;
            throw errno_error(
                "Cannot close atomic file directory after fsync");
        }
        directory_fd = -1;
    } catch (const std::exception& error) {
        if (temporary_fd >= 0) ::close(temporary_fd);
        if (temporary_exists && directory_fd >= 0) {
            ::unlinkat(directory_fd, temporary_name.c_str(), 0);
        }
        if (directory_fd >= 0) ::close(directory_fd);
        throw AtomicFileWriteError(error.what(), committed);
    } catch (...) {
        if (temporary_fd >= 0) ::close(temporary_fd);
        if (temporary_exists && directory_fd >= 0) {
            ::unlinkat(directory_fd, temporary_name.c_str(), 0);
        }
        if (directory_fd >= 0) ::close(directory_fd);
        throw AtomicFileWriteError(
            "Unknown atomic file write failure", committed);
    }
}

void write_config_atomically(const std::string& config_path,
                             const std::string& body) {
    write_file_atomically(config_path, body);
}

} // namespace keen_pbr3
