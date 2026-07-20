#ifdef WITH_API

#include "handler_naive.hpp"

#include "../log/logger.hpp"
#include "../util/safe_exec.hpp"

#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/stat.h>

namespace keen_pbr3 {

namespace {

// Обёртка запускает sing-box с --library-path /opt/lib, поэтому библиотеке
// место именно там.
constexpr const char* kLibraryPath = "/opt/lib/libcronet.so";
constexpr const char* kInstallScript =
    "/opt/usr/share/keen-pbr/install-naive-component.sh";

std::mutex& install_mutex() {
    static std::mutex mutex;
    return mutex;
}

bool file_exists(const char* path) {
    struct stat info {};
    return ::stat(path, &info) == 0 && S_ISREG(info.st_mode);
}

long long file_size(const char* path) {
    struct stat info {};
    return ::stat(path, &info) == 0 ? static_cast<long long>(info.st_size) : 0;
}

} // namespace

void register_naive_component_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.get("/api/system/naive-component", []() -> std::string {
        nlohmann::json response;
        response["installed"] = file_exists(kLibraryPath);
        response["size"] = file_size(kLibraryPath);
        response["path"] = kLibraryPath;
        return response.dump();
    });

    server.post("/api/system/naive-component", []() -> std::string {
        // Установка идёт по одной: два одновременных запроса писали бы в один
        // временный файл, и второй забрал бы у первого недописанное.
        std::lock_guard<std::mutex> lock(install_mutex());

        if (file_exists(kLibraryPath)) {
            return nlohmann::json{{"installed", true},
                                  {"size", file_size(kLibraryPath)}}
                .dump();
        }

        if (!file_exists(kInstallScript)) {
            return nlohmann::json{{"installed", false},
                                  {"error", "script_missing"}}
                .dump();
        }

        const auto result =
            safe_exec_capture({"/bin/sh", kInstallScript}, false, 16U * 1024U);

        nlohmann::json response;
        response["installed"] = file_exists(kLibraryPath);
        response["size"] = file_size(kLibraryPath);
        response["log"] = result.stdout_output;
        if (result.exit_code != 0) {
            Logger::instance().warn("Could not fetch the naive component: {}",
                                    result.stdout_output);
            response["error"] = "install_failed";
        }
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
