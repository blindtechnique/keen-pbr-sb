#pragma once

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>

#include <sys/stat.h>

namespace keen_pbr3::rescue_integrity {

inline bool regular_file(const std::filesystem::path& path) {
    std::error_code error;
    return !std::filesystem::is_symlink(
               std::filesystem::symlink_status(path, error)) &&
           !error && std::filesystem::is_regular_file(path, error) &&
           !error;
}

inline bool regular_nonempty_file(const std::filesystem::path& path) {
    if (!regular_file(path)) return false;
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    return !error && size > 0;
}

inline std::optional<std::string> sha256_file(
    const std::filesystem::path& path) {
    if (!regular_file(path)) return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    Sha256 hasher;
    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(),
                   static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0)
            hasher.update(buffer.data(), static_cast<std::size_t>(count));
    }
    if (!input.eof()) return std::nullopt;
    return hasher.hex_digest();
}

inline std::optional<std::string> read_strict_single_line(
    const std::filesystem::path& path) {
    if (!regular_nonempty_file(path)) return std::nullopt;
    std::ifstream input(path);
    std::string value;
    std::string extra;
    if (!std::getline(input, value) || value.empty() ||
        std::getline(input, extra)) {
        return std::nullopt;
    }
    return value;
}

inline bool valid_sha256_hex(std::string_view value) {
    return value.size() == 64 &&
           value.find_first_not_of("0123456789abcdef") ==
               std::string_view::npos;
}

inline bool verified_ipk_file(const std::filesystem::path& path) {
    if (!regular_nonempty_file(path)) return false;
    const auto sidecar = std::filesystem::path(path.string() + ".sha256");
    const auto expected = read_strict_single_line(sidecar);
    const auto actual = sha256_file(path);
    return expected && actual && valid_sha256_hex(*expected) &&
           *actual == *expected;
}

inline constexpr std::array<std::string_view, 10> kManagedFiles = {
    "config.json",
    "transports.json",
    "auth.json",
    "local.lst",
    "defaults",
    "dnsmasq-fallback.conf",
    "hook.sh",
    "catalog-source.json",
    "logging.json",
    "remote-access.json",
};

inline bool managed_file(std::string_view name) {
    return std::find(kManagedFiles.begin(), kManagedFiles.end(), name) !=
           kManagedFiles.end();
}

inline bool file_mode_matches(const std::filesystem::path& path,
                              const std::string& declared) {
    if (declared.size() < 3 || declared.size() > 4 ||
        declared.find_first_not_of("01234567") != std::string::npos) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const auto expected = std::strtoul(declared.c_str(), &end, 8);
    if (errno != 0 || end == nullptr || *end != '\0') return false;
    struct stat status {};
    return ::lstat(path.c_str(), &status) == 0 &&
           S_ISREG(status.st_mode) &&
           (status.st_mode & 07777) == expected;
}

inline bool verified_snapshot(const std::filesystem::path& path) {
    std::error_code error;
    if (std::filesystem::is_symlink(
            std::filesystem::symlink_status(path, error)) ||
        error || !std::filesystem::is_directory(path, error) || error) {
        return false;
    }
    const auto manifest = path / ".snapshot-manifest";
    const auto ready = path / ".snapshot-ready";
    const auto expected_manifest_hash = read_strict_single_line(ready);
    const auto actual_manifest_hash = sha256_file(manifest);
    if (!expected_manifest_hash || !actual_manifest_hash ||
        !valid_sha256_hex(*expected_manifest_hash) ||
        *actual_manifest_hash != *expected_manifest_hash) {
        return false;
    }

    std::ifstream input(manifest);
    std::string line;
    if (!std::getline(input, line) ||
        line != "keen-pbr-snapshot-v2") {
        return false;
    }
    std::set<std::string> seen;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string state;
        std::string name;
        std::string mode;
        std::string declared_hash;
        std::string extra;
        if (!(fields >> state >> name >> mode >> declared_hash) ||
            (fields >> extra) || !managed_file(name) ||
            !seen.insert(name).second) {
            return false;
        }
        const auto entry = path / name;
        if (state == "present") {
            const auto actual_hash = sha256_file(entry);
            if (!actual_hash || !valid_sha256_hex(declared_hash) ||
                *actual_hash != declared_hash ||
                !file_mode_matches(entry, mode)) {
                return false;
            }
        } else if (state == "absent") {
            if (mode != "-" || declared_hash != "-") return false;
            struct stat status {};
            errno = 0;
            if (::lstat(entry.c_str(), &status) == 0 || errno != ENOENT)
                return false;
        } else {
            return false;
        }
    }
    if (!input.eof() || seen.size() != kManagedFiles.size())
        return false;
    for (const auto expected : kManagedFiles) {
        if (seen.find(std::string(expected)) == seen.end()) return false;
    }

    for (std::filesystem::directory_iterator iterator(path, error), end;
         !error && iterator != end;
         iterator.increment(error)) {
        const auto name = iterator->path().filename().string();
        if (name != ".snapshot-manifest" &&
            name != ".snapshot-ready" &&
            !managed_file(name)) {
            return false;
        }
    }
    return !error;
}

} // namespace keen_pbr3::rescue_integrity
