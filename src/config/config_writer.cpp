#include "config_writer.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

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
    while (::fsync(fd) != 0) {
        if (errno == EINTR) continue;
        throw errno_error("Cannot fsync " + what);
    }
}

int open_directory(const std::filesystem::path& directory);

struct DirectoryEntryKey {
    dev_t parent_device{};
    ino_t parent_inode{};
    std::string name;

    bool operator<(const DirectoryEntryKey& other) const noexcept {
        if (parent_device != other.parent_device) {
            return parent_device < other.parent_device;
        }
        if (parent_inode != other.parent_inode) {
            return parent_inode < other.parent_inode;
        }
        return name < other.name;
    }
};

std::mutex& parent_directory_mutex() {
    static std::mutex mutex;
    return mutex;
}

// A failed fsync must not become a false success merely because mkdir(2)
// already made the directory visible. Remember only those exceptional paths;
// ordinary cache/config writes do not fsync every ancestor on every call.
std::map<DirectoryEntryKey, mode_t>& uncertain_parent_entries() {
    static std::map<DirectoryEntryKey, mode_t> entries;
    return entries;
}

#ifdef KEEN_PBR3_TESTING
void inject_parent_directory_fault(
    const AtomicFileWriteOptions& options,
    AtomicParentDirectoryStage stage) {
    if (options.parent_directory_fault_injector) {
        options.parent_directory_fault_injector(stage);
    }
}
#else
void inject_parent_directory_fault(
    const AtomicFileWriteOptions&,
    AtomicParentDirectoryStage) {}
#endif

int open_child_directory(int parent_fd,
                         const std::string& name,
                         const struct stat& expected) {
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
    const int descriptor = ::openat(parent_fd, name.c_str(), flags);
    if (descriptor < 0) {
        throw errno_error("Cannot open atomic file directory component");
    }
#ifndef O_CLOEXEC
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        const int error = errno;
        ::close(descriptor);
        errno = error;
        throw errno_error(
            "Cannot mark atomic file directory component close-on-exec");
    }
#endif
    struct stat opened {};
    if (::fstat(descriptor, &opened) != 0) {
        const int error = errno;
        ::close(descriptor);
        errno = error;
        throw errno_error("Cannot inspect atomic file directory component");
    }
    if (!S_ISDIR(opened.st_mode) || opened.st_dev != expected.st_dev ||
        opened.st_ino != expected.st_ino) {
        ::close(descriptor);
        throw std::runtime_error(
            "Atomic file directory component changed while it was opened");
    }
    return descriptor;
}

int open_parent_directory(
    const std::filesystem::path& requested_directory,
    const AtomicFileWriteOptions& options) {
    std::lock_guard<std::mutex> lock(parent_directory_mutex());
    const auto raw_directory = requested_directory.empty()
                                   ? std::filesystem::path(".")
                                   : requested_directory;
    const auto raw_relative = raw_directory.is_absolute()
                                  ? raw_directory.relative_path()
                                  : raw_directory;
    for (const auto& part : raw_relative) {
        if (part == "..") {
            throw std::runtime_error(
                "Refusing an atomic file parent containing '..'");
        }
    }
    const auto directory = raw_directory.lexically_normal();
    int current_fd = open_directory(
        directory.is_absolute() ? std::filesystem::path("/")
                                : std::filesystem::path("."));

    try {
        const auto relative = directory.is_absolute()
                                  ? directory.relative_path()
                                  : directory;
        for (const auto& part : relative) {
            const auto name = part.string();
            if (name.empty() || name == ".") continue;
            if (name == "..") {
                throw std::runtime_error(
                    "Refusing an atomic file parent containing '..'");
            }

            struct stat parent_metadata {};
            if (::fstat(current_fd, &parent_metadata) != 0) {
                throw errno_error("Cannot inspect atomic file parent");
            }
            const DirectoryEntryKey key{
                parent_metadata.st_dev,
                parent_metadata.st_ino,
                name,
            };

            struct stat child_metadata {};
            bool created = false;
            const int inspect_result = ::fstatat(
                current_fd,
                name.c_str(),
                &child_metadata,
#ifdef AT_SYMLINK_NOFOLLOW
                AT_SYMLINK_NOFOLLOW
#else
                0
#endif
            );
            if (inspect_result != 0) {
                if (errno != ENOENT) {
                    throw errno_error(
                        "Cannot inspect atomic file directory component");
                }
                if (!options.create_parent_directories) {
                    throw errno_error("Cannot open atomic file directory");
                }
                if (::mkdirat(
                        current_fd,
                        name.c_str(),
                        options.created_directory_mode) != 0) {
                    if (errno != EEXIST) {
                        throw errno_error(
                            "Cannot create atomic file directory");
                    }
                } else {
                    created = true;
                    uncertain_parent_entries()[key] =
                        options.created_directory_mode;
                }
                if (::fstatat(
                        current_fd,
                        name.c_str(),
                        &child_metadata,
#ifdef AT_SYMLINK_NOFOLLOW
                        AT_SYMLINK_NOFOLLOW
#else
                        0
#endif
                        ) != 0) {
                    throw errno_error(
                        "Cannot inspect created atomic file directory");
                }
            }
            if (!S_ISDIR(child_metadata.st_mode) ||
                S_ISLNK(child_metadata.st_mode)) {
                throw std::runtime_error(
                    "Refusing a non-directory or symbolic-link parent component");
            }

            int child_fd = open_child_directory(
                current_fd, name, child_metadata);
            try {
                const auto uncertain = uncertain_parent_entries().find(key);
                if (created || uncertain != uncertain_parent_entries().end()) {
                    const mode_t mode =
                        uncertain != uncertain_parent_entries().end()
                            ? uncertain->second
                            : options.created_directory_mode;
                    inject_parent_directory_fault(
                        options, AtomicParentDirectoryStage::mode);
                    if (::fchmod(child_fd, mode) != 0) {
                        throw errno_error(
                            "Cannot set atomic file directory mode");
                    }
                    inject_parent_directory_fault(
                        options,
                        AtomicParentDirectoryStage::directory_fsync);
                    fsync_fd(
                        child_fd, "newly created atomic file directory");
                    inject_parent_directory_fault(
                        options,
                        AtomicParentDirectoryStage::parent_fsync);
                    fsync_fd(current_fd, "atomic file directory parent");
                    uncertain_parent_entries().erase(key);
                }
            } catch (...) {
                ::close(child_fd);
                throw;
            }

            if (::close(current_fd) != 0) {
                const int error = errno;
                current_fd = -1;
                ::close(child_fd);
                errno = error;
                throw errno_error(
                    "Cannot close atomic file directory parent");
            }
            current_fd = child_fd;
        }
        return current_fd;
    } catch (...) {
        if (current_fd >= 0) ::close(current_fd);
        throw;
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

void write_file_atomically_with(const std::string& destination,
                                const AtomicFilePopulate& populate,
                                const AtomicFileWriteOptions& options) {
    if (!populate) {
        throw std::invalid_argument("Atomic file populate callback is empty");
    }
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
    struct stat existing {};
    int directory_fd = open_parent_directory(directory, options);
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
        populate(temporary_fd);
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
        if (options.replace_existing) {
            if (::renameat(directory_fd,
                           temporary_name.c_str(),
                           directory_fd,
                           filename.c_str()) != 0) {
                throw errno_error("Cannot replace atomic file");
            }
            temporary_exists = false;
        } else {
            // linkat(2) is the portable no-replace commit primitive available
            // on the older Keenetic kernels we support. EEXIST leaves the
            // existing destination and our private temporary inode untouched.
            if (::linkat(directory_fd,
                         temporary_name.c_str(),
                         directory_fd,
                         filename.c_str(),
                         0) != 0) {
                throw errno_error("Cannot create atomic file exclusively");
            }
            committed = true;
            if (options.committed_result != nullptr) {
                *options.committed_result = true;
            }
            if (::unlinkat(directory_fd, temporary_name.c_str(), 0) != 0) {
                throw errno_error(
                    "Cannot unlink committed atomic temporary file");
            }
            temporary_exists = false;
        }
        if (!committed) {
            committed = true;
            if (options.committed_result != nullptr) {
                *options.committed_result = true;
            }
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

void write_file_atomically(const std::string& destination,
                           const std::string& body,
                           const AtomicFileWriteOptions& options) {
    write_file_atomically_with(
        destination,
        [&body](int descriptor) { write_all(descriptor, body); },
        options);
}

void write_config_atomically(const std::string& config_path,
                             const std::string& body) {
    write_file_atomically(config_path, body);
}

} // namespace keen_pbr3
