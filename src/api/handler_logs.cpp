#ifdef WITH_API

#include "handler_logs.hpp"

#include <httplib.h>

#include <algorithm>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr std::size_t kDefaultLines = 300;
constexpr std::size_t kMaxLines = 5000;
// Reading the tail is enough for diagnostics and keeps a rotated 1 MiB file
// from being pulled into memory in full.
constexpr std::size_t kMaxTailBytes = 512U * 1024U;

std::string log_file_path() {
#ifdef KEEN_PBR_DEFAULT_LOG_FILE
    return KEEN_PBR_DEFAULT_LOG_FILE;
#else
    return "/opt/var/log/keen-pbr.log";
#endif
}

std::vector<std::string> read_tail(const std::string& path,
                                   std::size_t max_lines,
                                   bool& exists,
                                   std::uint64_t& size_bytes) {
    exists = false;
    size_bytes = 0;

    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return {};
    }
    exists = true;

    file.seekg(0, std::ios::end);
    const auto file_size = static_cast<std::uint64_t>(file.tellg());
    size_bytes = file_size;

    const auto read_bytes =
        static_cast<std::streamoff>(std::min<std::uint64_t>(file_size, kMaxTailBytes));
    file.seekg(-read_bytes, std::ios::end);

    std::string chunk(static_cast<std::size_t>(read_bytes), '\0');
    file.read(chunk.data(), read_bytes);
    chunk.resize(static_cast<std::size_t>(file.gcount()));

    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < chunk.size()) {
        const auto end = chunk.find('\n', start);
        if (end == std::string::npos) {
            lines.emplace_back(chunk.substr(start));
            break;
        }
        lines.emplace_back(chunk.substr(start, end - start));
        start = end + 1;
    }

    // The first line is usually cut in half by the byte-based seek.
    if (read_bytes > 0 && static_cast<std::uint64_t>(read_bytes) < file_size &&
        !lines.empty()) {
        lines.erase(lines.begin());
    }
    if (lines.size() > max_lines) {
        lines.erase(lines.begin(),
                    lines.begin() + static_cast<std::ptrdiff_t>(lines.size() - max_lines));
    }
    return lines;
}

} // namespace

void register_logs_handler(ApiServer& server, ApiContext& /*ctx*/) {
    // GET /api/logs?lines=N - tail of the daemon log file.
    //
    // The router runs keen-pbr from an init script where stderr is discarded,
    // so without this the only way to read a startup failure is over SSH.
    // get_stream is used only because it is the one registration form that
    // exposes the request, and the tail length comes in as a query parameter.
    server.get_stream("/api/logs", [](const httplib::Request& req,
                                      httplib::Response& res) {
        std::size_t lines = kDefaultLines;
        if (req.has_param("lines")) {
            try {
                lines = std::min<std::size_t>(
                    kMaxLines, std::max<std::size_t>(1, std::stoul(req.get_param_value("lines"))));
            } catch (const std::exception&) {
                lines = kDefaultLines;
            }
        }

        const auto path = log_file_path();
        bool exists = false;
        std::uint64_t size_bytes = 0;
        const auto tail = read_tail(path, lines, exists, size_bytes);

        nlohmann::json response;
        response["path"] = path;
        response["exists"] = exists;
        response["size_bytes"] = size_bytes;
        response["lines"] = tail;
        res.set_content(response.dump(), "application/json");
    });
}

} // namespace keen_pbr3

#endif // WITH_API
