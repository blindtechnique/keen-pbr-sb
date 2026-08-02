#include "nfqws_file_writer.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <unistd.h>
#include <zlib.h>

namespace keen_pbr3 {
namespace {

std::runtime_error errno_error(const char* message) {
    return std::runtime_error(
        std::string(message) + ": " + std::strerror(errno));
}

void populate_gzip(int descriptor, const std::string& content) {
    const int gzip_descriptor = ::dup(descriptor);
    if (gzip_descriptor < 0) {
        throw errno_error("failed to duplicate nfqws gzip descriptor");
    }

    gzFile output = ::gzdopen(gzip_descriptor, "wb9");
    if (output == nullptr) {
        const int error = errno;
        ::close(gzip_descriptor);
        errno = error;
        throw errno_error("failed to open compressed nfqws file");
    }

    const int written = ::gzwrite(
        output,
        content.data(),
        static_cast<unsigned int>(content.size()));
    const int close_status = ::gzclose(output);
    if (written != static_cast<int>(content.size()) ||
        close_status != Z_OK) {
        throw std::runtime_error("failed to compress nfqws file");
    }
}

AtomicFileWriteOptions nfqws_write_options(
    AtomicFileWriteOptions options) {
    options.create_parent_directories = true;
    options.created_directory_mode = 0755;
    options.default_file_mode = 0644;
    options.preserved_file_mode_mask = 0777;
    options.additional_file_mode_bits |= 0444;
    return options;
}

} // namespace

NfqwsFileWriteResult write_nfqws_file_atomically(
    const std::filesystem::path& path,
    const std::string& content,
    AtomicFileWriteOptions options) {
    if (content.size() > kMaxNfqwsFileSize) {
        throw std::length_error("nfqws file is too large");
    }

    options = nfqws_write_options(std::move(options));
    try {
        if (path.extension() != ".gz") {
            write_file_atomically(path.string(), content, options);
        } else {
            write_file_atomically_with(
                path.string(),
                [&content](int descriptor) {
                    populate_gzip(descriptor, content);
                },
                options);
        }
    } catch (const AtomicFileWriteError& error) {
        if (error.committed()) return {false};
        throw;
    }
    return {true};
}

} // namespace keen_pbr3
