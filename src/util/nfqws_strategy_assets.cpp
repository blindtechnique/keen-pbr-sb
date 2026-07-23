#include "nfqws_strategy_assets.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <set>
#include <stdexcept>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;
constexpr std::size_t kMaxManifestBytes = 64U * 1024U;
constexpr std::size_t kMaxAssetBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaxAssets = 64U;

std::string trim(std::string value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
    if (first >= last) return {};
    return {first, last};
}

bool valid_asset_name(const std::string& name) {
    if (name.empty() || name.size() > 128 || fs::path(name).filename() != fs::path(name) ||
        fs::path(name).extension() != ".bin") {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.';
    });
}

std::vector<std::string> read_manifest(const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return {};
    if (ec || fs::is_symlink(fs::symlink_status(path, ec)) ||
        !fs::is_regular_file(path, ec) || fs::file_size(path, ec) > kMaxManifestBytes) {
        throw std::runtime_error("invalid nfqws strategy asset manifest");
    }

    std::ifstream input(path);
    if (!input) throw std::runtime_error("cannot read nfqws strategy asset manifest");

    std::vector<std::string> result;
    std::set<std::string> unique;
    std::string line;
    while (std::getline(input, line)) {
        line = trim(std::move(line));
        if (line.empty() || line.front() == '#') continue;
        if (!valid_asset_name(line)) {
            throw std::runtime_error("invalid nfqws strategy asset name: " + line);
        }
        if (unique.insert(line).second) result.push_back(line);
        if (result.size() > kMaxAssets) {
            throw std::runtime_error("too many nfqws strategy assets");
        }
    }
    return result;
}

void require_regular_file(const fs::path& path, const char* kind) {
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status)) {
        throw std::runtime_error(std::string("invalid nfqws strategy ") + kind +
                                 ": " + path.filename().string());
    }
}

void write_all(int fd, const char* data, std::size_t size) {
    while (size > 0) {
        const auto written = ::write(fd, data, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            throw std::runtime_error(
                std::string("cannot write nfqws strategy asset: ") + std::strerror(errno));
        }
        data += written;
        size -= static_cast<std::size_t>(written);
    }
}

bool target_is_safe_regular_file(const fs::path& path) {
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    return !ec && !fs::is_symlink(status) && fs::is_regular_file(status);
}

bool install_missing_asset(const fs::path& source, const fs::path& target) {
    if (fs::exists(fs::symlink_status(target))) {
        if (!target_is_safe_regular_file(target)) {
            throw std::runtime_error(
                "nfqws strategy asset target is not a regular file: " +
                target.filename().string());
        }
        return false;
    }

    std::ifstream input(source, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot read nfqws strategy asset: " +
                                 source.filename().string());
    }

    auto pattern = (target.parent_path() /
                    (".keen-pbr-sb-" + target.filename().string() + ".XXXXXX")).string();
    std::vector<char> temporary(pattern.begin(), pattern.end());
    temporary.push_back('\0');
    int fd = ::mkstemp(temporary.data());
    if (fd < 0) {
        throw std::runtime_error(
            std::string("cannot create temporary nfqws strategy asset: ") +
            std::strerror(errno));
    }
    const fs::path temporary_path(temporary.data());

    try {
        std::array<char, 16U * 1024U> buffer{};
        while (input) {
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const auto count = input.gcount();
            if (count > 0) {
                write_all(fd, buffer.data(), static_cast<std::size_t>(count));
            }
        }
        if (!input.eof()) throw std::runtime_error("cannot read nfqws strategy asset");
        if (::fchmod(fd, 0644) != 0 || ::fsync(fd) != 0) {
            throw std::runtime_error(
                std::string("cannot sync nfqws strategy asset: ") + std::strerror(errno));
        }
        if (::close(fd) != 0) {
            fd = -1;
            throw std::runtime_error(
                std::string("cannot close nfqws strategy asset: ") + std::strerror(errno));
        }
        fd = -1;

        if (::link(temporary_path.c_str(), target.c_str()) != 0) {
            const int error = errno;
            ::unlink(temporary_path.c_str());
            if (error == EEXIST && target_is_safe_regular_file(target)) return false;
            throw std::runtime_error(
                std::string("cannot install nfqws strategy asset: ") +
                std::strerror(error));
        }
        ::unlink(temporary_path.c_str());

        const int directory_fd =
            ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory_fd >= 0) {
            (void)::fsync(directory_fd);
            ::close(directory_fd);
        }
        return true;
    } catch (...) {
        if (fd >= 0) (void)::close(fd);
        (void)::unlink(temporary_path.c_str());
        throw;
    }
}

} // namespace

NfqwsStrategyAssetSync sync_nfqws_strategy_assets(
    const fs::path& manifest,
    const fs::path& source_directory,
    const fs::path& destination_directory) {
    const auto names = read_manifest(manifest);
    NfqwsStrategyAssetSync result;
    if (names.empty()) return result;

    std::error_code ec;
    const auto destination_status = fs::symlink_status(destination_directory, ec);
    if (!ec && fs::exists(destination_status) &&
        (fs::is_symlink(destination_status) || !fs::is_directory(destination_status))) {
        throw std::runtime_error("nfqws strategy blob directory is unsafe");
    }
    ec.clear();
    fs::create_directories(destination_directory, ec);
    if (ec || ::chmod(destination_directory.c_str(), 0755) != 0) {
        throw std::runtime_error("cannot create nfqws strategy blob directory");
    }

    for (const auto& name : names) {
        const auto source = source_directory / name;
        require_regular_file(source, "asset");
        ec.clear();
        const auto size = fs::file_size(source, ec);
        if (ec || size > kMaxAssetBytes) {
            throw std::runtime_error("nfqws strategy asset is too large: " + name);
        }
        if (install_missing_asset(source, destination_directory / name)) {
            result.installed.push_back(name);
        } else {
            result.preserved.push_back(name);
        }
    }
    return result;
}

} // namespace keen_pbr3
