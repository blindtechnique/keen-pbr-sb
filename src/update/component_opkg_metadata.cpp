#include "component_opkg_metadata.hpp"

#include "package_footprint.hpp"
#include "../config/config_writer.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {
namespace fs = std::filesystem;

bool valid_package(const std::string& package) {
    return !package.empty() && package.size() <= 128U &&
           std::isalnum(static_cast<unsigned char>(package.front())) != 0 &&
           std::all_of(package.begin(), package.end(), [](unsigned char ch) {
               return (ch >= 'a' && ch <= 'z') ||
                      (ch >= 'A' && ch <= 'Z') ||
                      (ch >= '0' && ch <= '9') || ch == '+' || ch == '.' || ch == '-';
           });
}

bool valid_absolute(const fs::path& path) {
    const auto text = path.string();
    return path.is_absolute() && path != path.root_path() &&
           path.lexically_normal().string() == text &&
           text.size() <= kComponentMaxPathLength &&
           std::none_of(text.begin(), text.end(), [](unsigned char ch) {
               return ch < 0x20U || ch == 0x7fU;
           });
}

std::string trim_field(std::string value) {
    const auto first = value.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r");
    return value.substr(first, last - first + 1U);
}

struct Paragraph {
    std::size_t begin{0};
    std::size_t end{0};
    std::string package;
    std::string version;
    std::string status;
    unsigned versions{0};
    unsigned statuses{0};
};

bool parse_database(const std::string& body, const std::string& package,
                    std::optional<Paragraph>& target, std::string& error) {
    if (body.size() > kComponentMaxFileBytes ||
        body.find('\0') != std::string::npos) {
        error = "opkg status database is oversized or contains a NUL byte";
        return false;
    }
    std::optional<Paragraph> paragraph;
    bool previous_field = false;
    const auto finish = [&]() {
        if (!paragraph) return true;
        if (paragraph->package.empty()) {
            error = "opkg status contains an unidentifiable paragraph";
            return false;
        }
        if (paragraph->package == package) {
            if (target) {
                error = "opkg status contains duplicate component paragraphs";
                return false;
            }
            target = *paragraph;
        }
        paragraph.reset();
        previous_field = false;
        return true;
    };
    for (std::size_t cursor = 0; cursor < body.size();) {
        const auto newline = body.find('\n', cursor);
        const auto after = newline == std::string::npos ? body.size() : newline + 1U;
        const auto line = body.substr(cursor, (newline == std::string::npos ?
                                                   body.size() : newline) - cursor);
        if (trim_field(line).empty()) {
            if (!finish()) return false;
            cursor = after;
            continue;
        }
        if (!paragraph) paragraph = Paragraph{cursor, after, {}, {}, {}, 0U, 0U};
        paragraph->end = after;
        if (line.front() == ' ' || line.front() == '\t') {
            if (!previous_field) {
                error = "opkg status contains a continuation without a field";
                return false;
            }
        } else {
            const auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0U ||
                !std::all_of(line.begin(), line.begin() + colon,
                    [](unsigned char ch) {
                        return (ch >= 'a' && ch <= 'z') ||
                               (ch >= 'A' && ch <= 'Z') ||
                               (ch >= '0' && ch <= '9') || ch == '-';
                    })) {
                error = "opkg status contains a malformed field";
                return false;
            }
            const auto field = line.substr(0, colon);
            const auto value = trim_field(line.substr(colon + 1U));
            if (field == "Package") {
                if (!paragraph->package.empty() || !valid_package(value)) {
                    error = "opkg status contains an ambiguous package identity";
                    return false;
                }
                paragraph->package = value;
            } else if (field == "Version") {
                paragraph->version = value;
                ++paragraph->versions;
            } else if (field == "Status") {
                paragraph->status = value;
                ++paragraph->statuses;
            }
            previous_field = true;
        }
        cursor = after;
    }
    return finish();
}

bool installed_paragraph(const Paragraph& paragraph) {
    if (paragraph.versions != 1U || paragraph.version.empty() ||
        paragraph.statuses != 1U) return false;
    std::istringstream fields(paragraph.status);
    std::string wanted, flags, state, extra;
    return static_cast<bool>(fields >> wanted >> flags >> state) &&
           !(fields >> extra) && state == "installed";
}

bool usable_current_paragraph(const Paragraph& paragraph) {
    if (paragraph.versions != 1U || paragraph.version.empty() ||
        paragraph.statuses != 1U ||
        std::any_of(paragraph.version.begin(), paragraph.version.end(), [](unsigned char ch) {
            return ch <= 0x20U || ch == 0x7fU;
        })) return false;
    std::istringstream fields(paragraph.status);
    std::string wanted, flags, state, extra;
    // Interrupted but valid opkg states such as unpacked/half-installed do
    // not need to be rewritten before the exact retained IPK is installed.
    return static_cast<bool>(fields >> wanted >> flags >> state) && !(fields >> extra);
}

bool same_named_inode(int descriptor, const fs::path& path) noexcept {
    struct stat opened {}, named {};
    return ::fstat(descriptor, &opened) == 0 && S_ISREG(opened.st_mode) &&
           ::lstat(path.c_str(), &named) == 0 && S_ISREG(named.st_mode) &&
           opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

int open_parent_no_symlink(const fs::path& path) {
    // /opt alone may be Entware's trusted platform mount alias. As in the
    // existing component capture, only that anchor is followed; every
    // descendant and every private fixture path remains no-follow.
    const bool entware = path.string().rfind("/opt/", 0) == 0;
    const fs::path anchor = entware ? fs::path("/opt") : path.root_path();
    int directory = ::open(anchor.c_str(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                 (entware ? 0 : O_NOFOLLOW));
    if (directory < 0) return -1;
    const auto parents = path.parent_path().lexically_relative(anchor);
    for (const auto& component : parents) {
        if (component == ".") continue;
        const int next = ::openat(directory, component.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ::close(directory);
        if (next < 0) return -1;
        directory = next;
    }
    return directory;
}

std::optional<std::string> read_current_status(
    const fs::path& path, struct stat& state, std::string& error,
    bool* missing = nullptr) {
    if (missing) *missing = false;
    const int parent = open_parent_no_symlink(path);
    if (parent < 0) {
        error = "current opkg status parent is missing, unreadable, or symlinked";
        return std::nullopt;
    }
    const int descriptor = ::openat(parent, path.filename().c_str(),
                                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    const int open_error = errno;
    ::close(parent);
    if (descriptor < 0) {
        if (missing) *missing = open_error == ENOENT;
        error = "current opkg status database is missing or unreadable";
        return std::nullopt;
    }
    if (::fstat(descriptor, &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size < 0 ||
        static_cast<std::uintmax_t>(state.st_size) > kComponentMaxFileBytes) {
        ::close(descriptor);
        error = "current opkg status database is not a bounded regular file";
        return std::nullopt;
    }
    std::string body(static_cast<std::size_t>(state.st_size), '\0');
    std::size_t offset = 0;
    bool complete = true;
    while (offset < body.size()) {
        const auto count = ::read(descriptor, &body[offset], body.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { complete = false; break; }
        offset += static_cast<std::size_t>(count);
    }
    char extra = '\0';
    if (complete && ::read(descriptor, &extra, 1U) != 0) complete = false;
    if (!same_named_inode(descriptor, path)) complete = false;
    if (::close(descriptor) != 0) complete = false;
    if (!complete) {
        error = "current opkg status database changed or could not be read completely";
        return std::nullopt;
    }
    return body;
}

bool publish_status(const fs::path& path, const std::string& body,
                    const struct stat& state, std::string& error) {
    try {
        AtomicFileWriteOptions options;
        options.create_parent_directories = false;
        options.file_mode = static_cast<mode_t>(state.st_mode & 07777);
        options.owner = state.st_uid;
        options.group = state.st_gid;
        // Keep the shared writer's existing directory confinement policy.
        write_file_atomically(path.string(), body, options);
    } catch (const std::exception& failure) {
        error = std::string("opkg status merge could not be published durably: ") +
                failure.what();
        return false;
    }
    return true;
}

// Recovery is deliberately narrower than opkg's general parser: the damaged
// record must start with its intact exact Package field. Blank-line boundaries
// are retained verbatim, and every other paragraph must parse without repair.
std::optional<Paragraph> identifiable_damaged_target(
    const std::string& body, const std::string& package, std::string& error) {
    std::optional<Paragraph> target;
    std::optional<Paragraph> current;
    bool target_identity = false;
    const auto finish = [&]() {
        if (!current) return true;
        if (target_identity) {
            if (target) {
                error = "damaged opkg status has duplicate component paragraphs";
                return false;
            }
            target = *current;
        } else {
            std::optional<Paragraph> other_target;
            if (!parse_database(body.substr(current->begin, current->end - current->begin),
                                package, other_target, error)) return false;
            if (other_target) {
                error = "damaged opkg component identity is not an intact leading field";
                return false;
            }
        }
        current.reset();
        target_identity = false;
        return true;
    };
    for (std::size_t cursor = 0; cursor < body.size();) {
        const auto newline = body.find('\n', cursor);
        const auto after = newline == std::string::npos ? body.size() : newline + 1U;
        const auto line = body.substr(cursor, (newline == std::string::npos ? body.size() : newline) - cursor);
        if (trim_field(line).empty()) {
            if (!finish()) return std::nullopt;
        } else if (!current) {
            current = Paragraph{cursor, after, {}, {}, {}, 0U, 0U};
            target_identity = line.rfind("Package:", 0) == 0 &&
                              trim_field(line.substr(8U)) == package;
        } else {
            current->end = after;
            // A missing separator must not let repair swallow another
            // package. Even a damaged second Package field is ambiguous.
            if (target_identity && line.rfind("Package", 0) == 0) {
                error = "damaged opkg component paragraph has an ambiguous package boundary";
                return std::nullopt;
            }
        }
        cursor = after;
    }
    if (!finish()) return std::nullopt;
    if (!target) error = "damaged opkg status has no identifiable component paragraph";
    return target;
}

// Validate evidence only on shared reconstruction paths; the existing target
// merge/parser semantics remain unchanged. These are opkg-lede's persisted
// want/status names and comma-separated state flags (libopkg/pkg.c).
bool healthy_shared_paragraph(const Paragraph& paragraph) {
    if (!usable_current_paragraph(paragraph)) return false;
    std::istringstream fields(paragraph.status);
    std::string want, flags, state;
    fields >> want >> flags >> state;
    const auto contains = [](const std::string& value,
                             std::initializer_list<const char*> choices) {
        return std::any_of(choices.begin(), choices.end(),
                           [&](const char* choice) { return value == choice; });
    };
    if (!contains(want, {"unknown", "install", "deinstall", "purge"}) ||
        !contains(state, {"not-installed", "unpacked", "half-configured", "installed",
                          "half-installed", "config-files", "post-inst-failed", "removal-failed"}))
        return false;
    for (std::size_t cursor = 0; cursor < flags.size();) {
        const auto comma = flags.find(',', cursor);
        const auto after = comma == std::string::npos ? flags.size() : comma;
        if (!contains(flags.substr(cursor, after - cursor),
                      {"ok", "reinstreq", "hold", "replace", "noprune", "prefer", "obsolete", "user"}))
            return false;
        if (comma == flags.size() - 1U) return false;
        cursor = comma == std::string::npos ? flags.size() : comma + 1U;
    }
    return true;
}

struct StatusRecord {
    Paragraph fields;
    std::string_view body;
    bool healthy{false};
    bool scalar_continuation{false};
    bool version_continuation{false};
};

// Keep paragraph bytes, including separators, instead of serializing foreign
// fields. This path is used only after ordinary no-op/target repair failed.
bool status_records(const std::string& body, bool require_parseable,
                    std::vector<StatusRecord>& records, std::string& error) {
    if (body.size() > kComponentMaxFileBytes || std::any_of(body.begin(), body.end(),
        [](unsigned char ch) { return (ch < 0x20U && ch != '\n' && ch != '\r' && ch != '\t') || ch == 0x7fU; })) {
        error = "opkg status reconstruction source is oversized or binary";
        return false;
    }
    std::vector<std::size_t> starts;
    bool inside = false;
    for (std::size_t cursor = 0; cursor < body.size();) {
        const auto newline = body.find('\n', cursor);
        const auto end = newline == std::string::npos ? body.size() : newline;
        const auto line = body.substr(cursor, end - cursor);
        if (trim_field(line).empty()) inside = false;
        else if (!inside) {
            if (starts.size() >= kComponentMaxPathCount) {
                error = "opkg status reconstruction exceeds the package count limit";
                return false;
            }
            starts.push_back(cursor);
            inside = true;
        }
        cursor = end == body.size() ? end : end + 1U;
    }
    std::set<std::string> packages;
    for (std::size_t index = 0; index < starts.size(); ++index) {
        const auto begin = starts[index];
        const auto end = index + 1U == starts.size() ? body.size() : starts[index + 1U];
        StatusRecord record;
        record.body = std::string_view(body).substr(begin, end - begin);
        unsigned identities = 0;
        bool scalar_field = false;
        bool version_field = false;
        for (std::size_t cursor = 0; cursor < record.body.size();) {
            const auto newline = record.body.find('\n', cursor);
            const auto stop = newline == std::string::npos ? record.body.size() : newline;
            const std::string line(record.body.substr(cursor, stop - cursor));
            if (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
                if (scalar_field) record.scalar_continuation = true;
                if (version_field) record.version_continuation = true;
            } else {
                scalar_field = line.rfind("Package:", 0) == 0 ||
                    line.rfind("Version:", 0) == 0 || line.rfind("Status:", 0) == 0;
                version_field = line.rfind("Version:", 0) == 0;
                // Keep scalar evidence even if a later malformed field makes
                // the full paragraph parser fail. A newer visible version
                // must never disappear merely because another field is torn.
                if (version_field) {
                    record.fields.version = trim_field(line.substr(8U));
                    ++record.fields.versions;
                } else if (line.rfind("Status:", 0) == 0) {
                    record.fields.status = trim_field(line.substr(7U));
                    ++record.fields.statuses;
                }
            }
            if (line.rfind("Package", 0) == 0) {
                if (line.rfind("Package:", 0) != 0 || ++identities != 1U ||
                    !valid_package(trim_field(line.substr(8U)))) {
                    error = "opkg status reconstruction found an ambiguous package boundary";
                    return false;
                }
                record.fields.package = trim_field(line.substr(8U));
            }
            cursor = stop == record.body.size() ? stop : stop + 1U;
        }
        if (identities != 1U || !packages.insert(record.fields.package).second) {
            error = "opkg status reconstruction found an unidentified or duplicate package";
            return false;
        }
        std::optional<Paragraph> parsed;
        std::string parse_error;
        const bool parseable = parse_database(std::string(record.body), record.fields.package, parsed, parse_error);
        if (parseable && parsed) {
            record.fields = *parsed;
            record.healthy = !record.scalar_continuation && healthy_shared_paragraph(*parsed);
        }
        if ((require_parseable && !parseable) ||
            (!require_parseable && !record.healthy && record.body.rfind("Package:", 0) != 0)) {
            error = "opkg status reconstruction source has unsafe paragraph structure";
            return false;
        }
        records.push_back(std::move(record));
    }
    return true;
}

bool foreign_info_names(const ComponentOpkgMetadataPaths& paths,
                        std::set<std::string>& packages, std::string& error) {
    const int descriptor = open_parent_no_symlink(paths.info_directory / "inventory");
    if (descriptor < 0) {
        error = "foreign opkg info directory is missing, unreadable, or symlinked";
        return false;
    }
    DIR* const directory = ::fdopendir(descriptor);
    if (!directory) {
        ::close(descriptor);
        error = "foreign opkg info directory could not be read";
        return false;
    }
    bool complete = true;
    std::size_t count = 0;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory);
        if (!entry) {
            complete = errno == 0;
            break;
        }
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        if (++count > kComponentMaxPathCount * 16U) { complete = false; break; }
        std::size_t suffix_size = 0;
        if (name.size() > 8U && name.compare(name.size() - 8U, 8U, ".control") == 0) suffix_size = 8U;
        else if (name.size() > 5U && name.compare(name.size() - 5U, 5U, ".list") == 0) suffix_size = 5U;
        if (suffix_size == 0U) continue;
        const auto package = name.substr(0, name.size() - suffix_size);
        if (!valid_package(package)) { complete = false; break; }
        if (package != paths.package) packages.insert(package);
        if (packages.size() > kComponentMaxPathCount) { complete = false; break; }
    }
    if (::closedir(directory) != 0) complete = false;
    if (!complete) error = "foreign opkg info inventory is unreadable or exceeds its bounds";
    return complete;
}

// A list is existence/type evidence, not a request to scan payloads or retain
// every installed file name in memory. Empty lists are valid for meta-packages.
bool regular_info_file(const fs::path& path, struct stat& state) {
    const int parent = open_parent_no_symlink(path);
    if (parent < 0) return false;
    const int descriptor = ::openat(parent, path.filename().c_str(),
                                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    ::close(parent);
    if (descriptor < 0) return false;
    const bool complete = ::fstat(descriptor, &state) == 0 && S_ISREG(state.st_mode) &&
        state.st_size >= 0 && static_cast<std::uintmax_t>(state.st_size) <= kComponentMaxFileBytes &&
        same_named_inode(descriptor, path);
    const bool closed = ::close(descriptor) == 0;
    return complete && closed;
}

bool matching_foreign_info(const ComponentOpkgMetadataPaths& paths,
                           const StatusRecord& saved, std::uintmax_t& read_bytes,
                           std::string& error) {
    if (!saved.healthy || !installed_paragraph(saved.fields)) {
        error = "saved foreign opkg record lacks a unique usable version and status";
        return false;
    }
    struct stat control_state {}, list_state {};
    if (!regular_info_file(paths.info_directory / (saved.fields.package + ".control"), control_state) ||
        static_cast<std::uintmax_t>(control_state.st_size) > kComponentMaxTotalBytes - read_bytes) {
        error = "foreign package control evidence is unsafe or exceeds the total read limit";
        return false;
    }
    const auto control = read_current_status(paths.info_directory /
        (saved.fields.package + ".control"), control_state, error);
    const bool list = regular_info_file(paths.info_directory /
        (saved.fields.package + ".list"), list_state);
    if (!control || !list) {
        error = "foreign package control/list evidence is missing, unsafe, or unreadable";
        return false;
    }
    const auto bytes = control->size() + static_cast<std::uintmax_t>(list_state.st_size);
    if (bytes > kComponentMaxTotalBytes - read_bytes) {
        error = "foreign opkg metadata exceeds the total read limit";
        return false;
    }
    read_bytes += bytes;
    std::vector<StatusRecord> controls;
    if (!status_records(*control, true, controls, error) || controls.size() != 1U ||
        controls.front().fields.package != saved.fields.package ||
        controls.front().fields.versions != 1U || controls.front().scalar_continuation ||
        controls.front().fields.version != saved.fields.version) {
        error = "foreign package version differs from or cannot verify the captured status record";
        return false;
    }
    return true;
}

// Called only in failed/boot recovery, never before ordinary updates. An
// intact foreign control/list pair absent from the status is positive evidence
// of boundary-aligned truncation. Unreadable inventory alone proves no loss.
bool shared_status_damage_evidence(const ComponentOpkgMetadataPaths& paths,
                                   const std::string& current) {
    std::vector<StatusRecord> records;
    std::string error;
    if (!status_records(current, true, records, error)) return true;
    std::set<std::string> present, inventory;
    for (const auto& record : records) {
        present.insert(record.fields.package);
        if (record.fields.package != paths.package && !record.healthy) return true;
    }
    if (!foreign_info_names(paths, inventory, error)) return false;
    std::uintmax_t read_bytes = 0;
    for (const auto& package : inventory) {
        if (present.count(package) != 0U) continue;
        struct stat list_state {}, control_state {};
        if (!regular_info_file(paths.info_directory / (package + ".list"), list_state)) continue;
        if (!regular_info_file(paths.info_directory / (package + ".control"), control_state)) continue;
        if (static_cast<std::uintmax_t>(control_state.st_size) > kComponentMaxTotalBytes - read_bytes)
            return false;
        const auto control = read_current_status(paths.info_directory / (package + ".control"),
                                                 control_state, error);
        if (!control) continue;
        if (control->size() > kComponentMaxTotalBytes - read_bytes) return false;
        read_bytes += control->size();
        std::vector<StatusRecord> parsed;
        if (status_records(*control, true, parsed, error) && parsed.size() == 1U &&
            parsed.front().fields.package == package && parsed.front().fields.versions == 1U &&
            !parsed.front().scalar_continuation &&
            !parsed.front().fields.version.empty() &&
            std::none_of(parsed.front().fields.version.begin(), parsed.front().fields.version.end(),
                         [](unsigned char ch) { return ch <= 0x20U || ch == 0x7fU; })) return true;
    }
    return false;
}

ComponentOpkgStatusMergeResult reconstruct_shared_status(
    const ComponentOpkgMetadataPaths& paths, const std::string& saved,
    const std::string& current, const std::string& expected_version) {
    ComponentOpkgStatusMergeResult result;
    std::vector<StatusRecord> old_records, live_records;
    if (!status_records(saved, true, old_records, result.error) ||
        !status_records(current, false, live_records, result.error)) return result;
    std::map<std::string, const StatusRecord*> old_by_name, healthy;
    const StatusRecord* target = nullptr;
    for (const auto& record : old_records) {
        old_by_name.emplace(record.fields.package, &record);
        if (record.fields.package == paths.package) target = &record;
    }
    if (!target || !installed_paragraph(target->fields) ||
        !target->healthy ||
        (!expected_version.empty() && target->fields.version != expected_version)) {
        result.error = "shared opkg reconstruction requires the exact captured installed component version";
        return result;
    }
    for (const auto& record : live_records) {
        if (record.fields.package != paths.package && record.healthy)
            healthy.emplace(record.fields.package, &record);
        else if (record.fields.package != paths.package &&
                 old_by_name.count(record.fields.package) == 0U) {
            result.error = "damaged foreign package has no recoverable captured status record";
            return result;
        }
    }
    std::set<std::string> inventory;
    if (!foreign_info_names(paths, inventory, result.error)) return result;
    for (const auto& package : inventory) {
        if (healthy.count(package) == 0U && old_by_name.count(package) == 0U) {
            result.error = "foreign package was added after capture and its current status is unavailable";
            return result;
        }
    }
    std::uintmax_t read_bytes = 0;
    for (const auto& record : old_records) {
        if (record.fields.package == paths.package || healthy.count(record.fields.package) != 0U) continue;
        for (const auto& live : live_records) {
            if (live.fields.package != record.fields.package) continue;
            if (live.fields.versions > 1U || live.fields.statuses > 1U ||
                live.version_continuation) {
                result.error = "damaged foreign record contains ambiguous scalar evidence";
                return result;
            }
            if (live.fields.versions == 1U && !live.fields.version.empty() &&
                live.fields.version != record.fields.version) {
                result.error = "damaged foreign record indicates a version change after capture";
                return result;
            }
        }
        if (inventory.count(record.fields.package) == 0U ||
            !matching_foreign_info(paths, record, read_bytes, result.error)) {
            if (result.error.empty()) result.error = "foreign package removal cannot be distinguished from lost metadata";
            return result;
        }
    }
    std::size_t output_records = 0;
    const auto append = [&](std::string_view record) {
        if (++output_records > kComponentMaxPathCount) return false;
        std::string separator;
        if (!result.body.empty()) {
            if (result.body.back() != '\n') separator += '\n';
            if (!separator.empty() || result.body.size() < 2U ||
                result.body[result.body.size() - 2U] != '\n') separator += '\n';
        }
        if (separator.size() > kComponentMaxFileBytes - result.body.size() ||
            record.size() > kComponentMaxFileBytes - result.body.size() - separator.size()) return false;
        result.body += separator;
        result.body.append(record.data(), record.size());
        return true;
    };
    bool bounded = true;
    for (const auto& record : live_records)
        if (record.fields.package != paths.package && record.healthy) bounded = bounded && append(record.body);
    for (const auto& record : old_records)
        if (record.fields.package != paths.package && healthy.count(record.fields.package) == 0U)
            bounded = bounded && append(record.body);
    bounded = bounded && append(target->body);
    if (!bounded) {
        result.body.clear();
        result.error = "reconstructed opkg status exceeds the database size or package count limit";
        return result;
    }
    result.complete = true;
    return result;
}
} // namespace

bool valid_component_opkg_metadata_paths(const ComponentOpkgMetadataPaths& paths) {
    return valid_package(paths.package) && valid_absolute(paths.status_file) &&
           valid_absolute(paths.info_directory) && valid_absolute(paths.lock_file) &&
           paths.status_file.filename() == "status" &&
           paths.info_directory.filename() == "info" &&
           paths.status_file.parent_path() == paths.info_directory.parent_path() &&
           paths.status_file.parent_path() != paths.status_file.root_path() &&
           paths.lock_file.filename() == "opkg.lock";
}

std::vector<std::string> component_opkg_metadata_files(
    const ComponentOpkgMetadataPaths& paths) {
    if (!valid_component_opkg_metadata_paths(paths)) return {};
    std::vector<std::string> result{paths.status_file.string()};
    for (const auto* suffix : {"control", "list", "conffiles", "md5sums",
                               "preinst", "postinst", "prerm", "postrm"}) {
        result.push_back((paths.info_directory /
                          (paths.package + "." + suffix)).string());
    }
    return result;
}

ComponentOpkgStatusMergeResult merge_component_opkg_status(
    const std::string& saved, const std::string& current,
    const std::string& package, const std::string& expected_version) {
    ComponentOpkgStatusMergeResult result;
    if (!valid_package(package)) {
        result.error = "invalid opkg component package name";
        return result;
    }
    if (current.find_first_not_of(" \t\r\n") == std::string::npos) {
        result.error = "current opkg status database is empty; unrelated records cannot be reconstructed";
        return result;
    }
    std::optional<Paragraph> old_target, live_target;
    if (!parse_database(saved, package, old_target, result.error) ||
        !parse_database(current, package, live_target, result.error)) return result;
    if (!old_target || !installed_paragraph(*old_target)) {
        result.error = "saved opkg status has no unique installed component version";
        return result;
    }
    if (!expected_version.empty() && old_target->version != expected_version) {
        result.error = "saved opkg component version does not match the interrupted transaction";
        return result;
    }
    const auto restored = saved.substr(old_target->begin,
                                       old_target->end - old_target->begin);
    if (live_target) {
        result.body = current.substr(0, live_target->begin) + restored;
        // A final saved paragraph need not have a terminating newline; it
        // still needs one before the current database's next separator.
        if (live_target->end < current.size() &&
            !result.body.empty() && result.body.back() != '\n') result.body += '\n';
        result.body += current.substr(live_target->end);
    } else {
        result.body = current;
        if (!result.body.empty()) {
            if (result.body.back() != '\n') result.body += '\n';
            if (result.body.size() < 2U ||
                result.body[result.body.size() - 2U] != '\n') result.body += '\n';
        }
        result.body += restored;
    }
    if (result.body.size() > kComponentMaxFileBytes) {
        result.body.clear();
        result.error = "merged opkg status database exceeds the size limit";
        return result;
    }
    result.complete = true;
    return result;
}

ComponentOpkgMetadataLock::ComponentOpkgMetadataLock(const fs::path& lock_file)
    : path_(lock_file) {
    if (!valid_absolute(path_) || path_.filename() != "opkg.lock") {
        error_ = "invalid native opkg lock path";
        return;
    }
    const int parent = open_parent_no_symlink(path_);
    if (parent < 0) {
        error_ = "native opkg lock parent is missing, unreadable, or symlinked";
        return;
    }
    descriptor_ = ::openat(parent, path_.filename().c_str(),
                            O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    ::close(parent);
    if (descriptor_ < 0) {
        error_ = std::string("cannot open native opkg lock: ") + std::strerror(errno);
        return;
    }
    if (::lockf(descriptor_, F_TLOCK, 0) != 0 ||
        !same_named_inode(descriptor_, path_)) {
        error_ = "native opkg lock is busy, unsafe, or was replaced";
        ::close(descriptor_);
        descriptor_ = -1;
    }
}

ComponentOpkgMetadataLock::~ComponentOpkgMetadataLock() {
    if (descriptor_ >= 0) ::close(descriptor_);
}

bool ComponentOpkgMetadataLock::locked() const noexcept {
    // Native opkg may unlink its own lock at exit. An fd referring to that
    // old inode must never be mistaken for ownership of the new pathname.
    return descriptor_ >= 0 && same_named_inode(descriptor_, path_);
}

ComponentOpkgStatusMergeResult restore_component_opkg_status(
    const ComponentOpkgMetadataPaths& paths, const std::string& saved_status,
    const std::string& expected_version) {
    ComponentOpkgStatusMergeResult result;
    if (!valid_component_opkg_metadata_paths(paths)) {
        result.error = "invalid opkg metadata layout";
        return result;
    }
    struct stat state {};
    const auto current = read_current_status(paths.status_file, state, result.error);
    if (!current) return result;
    result = merge_component_opkg_status(saved_status, *current, paths.package,
                                        expected_version);
    if (!result.complete) return result;
    result.complete = publish_status(paths.status_file, result.body, state, result.error);
    return result;
}

ComponentOpkgStatusPreparationResult prepare_component_opkg_status_for_reinstall(
    const ComponentOpkgMetadataPaths& paths, const std::string& saved_status,
    const std::string& expected_version,
    std::optional<ComponentOpkgStatusFileAttributes> saved_attributes) {
    ComponentOpkgStatusPreparationResult result;
    if (!valid_component_opkg_metadata_paths(paths)) {
        result.error = "invalid opkg metadata layout";
        return result;
    }
    struct stat state {};
    bool missing = false;
    const auto current = read_current_status(paths.status_file, state, result.error, &missing);
    if (!current && !missing) return result;
    const auto reconstruct = [&]() {
        if (missing) {
            if (!saved_attributes || saved_attributes->mode > 07777U) {
                result.error = "missing opkg status requires verified saved file attributes";
                return;
            }
            state.st_mode = static_cast<mode_t>(saved_attributes->mode);
            state.st_uid = static_cast<uid_t>(saved_attributes->owner);
            state.st_gid = static_cast<gid_t>(saved_attributes->group);
        }
        const std::string empty;
        const auto rebuilt = reconstruct_shared_status(paths, saved_status, current ? *current : empty, expected_version);
        result.error = rebuilt.error;
        if (!rebuilt.complete) return;
        result.complete = publish_status(paths.status_file, rebuilt.body, state, result.error);
        result.changed = result.complete;
        result.shared_database_reconstructed = result.complete;
    };
    if (!current || current->find_first_not_of(" \t\r\n") == std::string::npos) {
        reconstruct();
        return result;
    }
    if (current->find('\0') != std::string::npos) {
        result.error = "current opkg status is empty or binary; unrelated records cannot be reconstructed";
        return result;
    }
    std::optional<Paragraph> live_target;
    if (parse_database(*current, paths.package, live_target, result.error) &&
        (!live_target || usable_current_paragraph(*live_target))) {
        if (shared_status_damage_evidence(paths, *current)) {
            reconstruct();
            return result;
        }
        result.error.clear();
        result.complete = true;
        return result;
    }
    result.error.clear();
    const auto damaged = identifiable_damaged_target(*current, paths.package, result.error);
    if (!damaged) {
        reconstruct();
        return result;
    }
    std::optional<Paragraph> saved_target;
    if (!parse_database(saved_status, paths.package, saved_target, result.error)) return result;
    if (!saved_target || !installed_paragraph(*saved_target)) {
        result.error = "saved opkg status has no unique installed component version";
        return result;
    }
    if (!expected_version.empty() && saved_target->version != expected_version) {
        result.error = "saved opkg component version does not match the interrupted transaction";
        return result;
    }
    auto repaired = current->substr(0, damaged->begin) +
        saved_status.substr(saved_target->begin, saved_target->end - saved_target->begin);
    if (damaged->end < current->size() && !repaired.empty() && repaired.back() != '\n') repaired += '\n';
    repaired += current->substr(damaged->end);
    std::optional<Paragraph> repaired_target;
    if (!parse_database(repaired, paths.package, repaired_target, result.error)) return result;
    if (shared_status_damage_evidence(paths, repaired)) {
        reconstruct();
        return result;
    }
    result.complete = publish_status(paths.status_file, repaired, state, result.error);
    result.changed = result.complete;
    return result;
}

} // namespace keen_pbr3
