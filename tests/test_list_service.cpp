#include <doctest/doctest.h>

#include "../src/daemon/list_service.hpp"
#include "../src/log/logger.hpp"
#include "../src/http/curl_runtime.hpp"
#include "../src/lists/srs_decoder.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

std::filesystem::path make_temp_dir() {
    char path_template[] = "/tmp/keen-pbr-list-service-XXXXXX";
    const char* created = mkdtemp(path_template);
    if (created == nullptr) {
        throw std::runtime_error("mkdtemp failed");
    }
    return std::filesystem::path(created);
}

class LoggerCapture {
public:
    LoggerCapture() : previous_level_(Logger::instance().level()) {
        Logger::instance().set_level(LogLevel::debug);
        Logger::instance().set_sink([this](const std::string& line) {
            std::lock_guard<std::mutex> lock(mutex_);
            lines_.push_back(line);
        });
    }

    ~LoggerCapture() {
        Logger::instance().clear_sink();
        Logger::instance().set_level(previous_level_);
    }

    bool contains(const std::string& needle) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::any_of(lines_.begin(), lines_.end(), [&needle](const std::string& line) {
            return line.find(needle) != std::string::npos;
        });
    }

private:
    LogLevel previous_level_;
    mutable std::mutex mutex_;
    std::vector<std::string> lines_;
};

using CurlGlobalGuard = CurlRuntime;

struct HttpResponse {
    int status{200};
    std::string reason{"OK"};
    std::string body;
    bool not_modified_when_conditional{false};
    std::vector<std::string> headers;
    size_t fail_first_requests{0};
    int transient_status{503};
    std::string transient_reason{"Service Unavailable"};
    size_t fail_after_requests{0};
};

class StaticHttpTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        last_request = request;
        ++calls;
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = "example.com\n";
        return response;
    }

    HttpTransportRequest last_request;
    size_t calls{0};
};

class CancelThenSucceedHttpTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        const auto call = calls_.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (call == 1) {
            std::unique_lock<std::mutex> lock(mutex_);
            first_entered_ = true;
            condition_.notify_all();
            condition_.wait(lock, [&] { return release_first_; });
            if (request.cancellation &&
                request.cancellation->load(std::memory_order_acquire)) {
                throw HttpTransportCancelled("injected cancellation");
            }
        }

        HttpTransportResponse response;
        response.status_code = 200;
        response.body = "example.com\n";
        return response;
    }

    bool wait_until_first_entered() {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(
            lock,
            std::chrono::seconds(5),
            [&] { return first_entered_; });
    }

    void release_first() {
        std::lock_guard<std::mutex> lock(mutex_);
        release_first_ = true;
        condition_.notify_all();
    }

    std::size_t calls() const noexcept {
        return calls_.load(std::memory_order_acquire);
    }

private:
    std::atomic<std::size_t> calls_{0};
    std::mutex mutex_;
    std::condition_variable condition_;
    bool first_entered_{false};
    bool release_first_{false};
};

class TestHttpServer {
public:
    explicit TestHttpServer(std::map<std::string, HttpResponse> routes)
        : routes_(std::move(routes)) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) {
            throw std::runtime_error("socket failed");
        }

        int reuse = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(listen_fd_);
            throw std::runtime_error("bind failed");
        }

        socklen_t len = sizeof(addr);
        if (getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) < 0) {
            close(listen_fd_);
            throw std::runtime_error("getsockname failed");
        }
        port_ = ntohs(addr.sin_port);

        if (listen(listen_fd_, 8) < 0) {
            close(listen_fd_);
            throw std::runtime_error("listen failed");
        }

        worker_ = std::thread([this]() { serve(); });
    }

    ~TestHttpServer() {
        running_.store(false);
        if (listen_fd_ >= 0) {
            shutdown(listen_fd_, SHUT_RDWR);
            close(listen_fd_);
            listen_fd_ = -1;
        }
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    std::string url(const std::string& path) const {
        return "http://127.0.0.1:" + std::to_string(port_) + path;
    }

    size_t request_count(const std::string& path) const {
        std::lock_guard<std::mutex> lock(request_counts_mutex_);
        const auto it = request_counts_.find(path);
        return it == request_counts_.end() ? 0 : it->second;
    }

private:
    void serve() {
        while (running_.load()) {
            const int client_fd = accept(listen_fd_, nullptr, nullptr);
            if (client_fd < 0) {
                if (!running_.load()) {
                    break;
                }
                continue;
            }
            handle_client(client_fd);
            close(client_fd);
        }
    }

    void handle_client(int client_fd) {
        std::string request;
        char buffer[1024];
        while (request.find("\r\n\r\n") == std::string::npos) {
            const ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) {
                break;
            }
            request.append(buffer, static_cast<size_t>(n));
            if (request.size() > 8192) {
                break;
            }
        }

        std::string path = "/";
        const auto first_space = request.find(' ');
        if (first_space != std::string::npos) {
            const auto second_space = request.find(' ', first_space + 1);
            if (second_space != std::string::npos) {
                path = request.substr(first_space + 1, second_space - first_space - 1);
            }
        }

        HttpResponse response;
        size_t request_count = 0;
        {
            std::lock_guard<std::mutex> lock(request_counts_mutex_);
            request_count = ++request_counts_[path];
        }
        auto it = routes_.find(path);
        if (it != routes_.end()) {
            response = it->second;
        } else {
            response.status = 404;
            response.reason = "Not Found";
        }
        if (request_count <= response.fail_first_requests ||
            (response.fail_after_requests > 0 &&
             request_count > response.fail_after_requests)) {
            response.status = response.transient_status;
            response.reason = response.transient_reason;
            response.body.clear();
        }
        if (response.not_modified_when_conditional &&
            (request.find("\r\nIf-None-Match:") != std::string::npos ||
             request.find("\r\nIf-Modified-Since:") != std::string::npos)) {
            response.status = 304;
            response.reason = "Not Modified";
            response.body.clear();
        }

        std::ostringstream out;
        out << "HTTP/1.1 " << response.status << ' ' << response.reason << "\r\n"
            << "Content-Length: " << response.body.size() << "\r\n"
            << "Connection: close\r\n";
        for (const auto& header : response.headers) {
            out << header << "\r\n";
        }
        out << "\r\n" << response.body;
        const auto payload = out.str();
        (void)send(client_fd, payload.data(), payload.size(), 0);
    }

    std::map<std::string, HttpResponse> routes_;
    mutable std::mutex request_counts_mutex_;
    std::map<std::string, size_t> request_counts_;
    int listen_fd_{-1};
    uint16_t port_{0};
    std::atomic<bool> running_{true};
    std::thread worker_;
};

std::string empty_srs_file(std::uint8_t version = 2) {
    const std::array<std::uint8_t, 1> payload{0}; // zero rules
    uLongf compressed_size = compressBound(payload.size());
    std::string compressed(compressed_size, '\0');
    REQUIRE(compress2(
                reinterpret_cast<Bytef*>(compressed.data()),
                &compressed_size,
                payload.data(),
                payload.size(),
                Z_BEST_COMPRESSION) == Z_OK);
    compressed.resize(compressed_size);

    std::string result{"SRS", 3};
    result.push_back(static_cast<char>(version));
    result += compressed;
    return result;
}

} // namespace

TEST_CASE("select_remote_list_targets: refresh-all selects only URL-backed lists") {
    Config config;

    ListConfig remote;
    remote.url = "https://example.com/remote.txt";

    ListConfig local_file;
    local_file.file = "/tmp/local.lst";

    ListConfig inline_only;
    inline_only.domains = std::vector<std::string>{"example.com"};

    config.lists = std::map<std::string, ListConfig>{
        {"inline", inline_only},
        {"local", local_file},
        {"remote", remote},
    };

    const auto selection = select_remote_list_targets(config, std::nullopt);

    CHECK(selection.ok());
    CHECK(selection.list_names.size() == 1);
    CHECK(selection.list_names.front() == "remote");
}

TEST_CASE("select_remote_list_targets: single URL-backed list is accepted") {
    Config config;

    ListConfig remote;
    remote.url = "https://example.com/remote.txt";
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto selection = select_remote_list_targets(config, std::string("remote"));

    CHECK(selection.ok());
    CHECK(selection.list_names == std::vector<std::string>{"remote"});
}

TEST_CASE("select_remote_list_targets: unknown list returns not found") {
    Config config;

    ListConfig remote;
    remote.url = "https://example.com/remote.txt";
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto selection = select_remote_list_targets(config, std::string("missing"));

    CHECK(selection.error == RemoteListTargetSelectionError::NotFound);
    CHECK(selection.list_names.empty());
}

TEST_CASE("select_remote_list_targets: non-URL-backed list returns not remote") {
    Config config;

    ListConfig local_file;
    local_file.file = "/tmp/local.lst";
    config.lists = std::map<std::string, ListConfig>{{"local", local_file}};

    const auto selection = select_remote_list_targets(config, std::string("local"));

    CHECK(selection.error == RemoteListTargetSelectionError::NotRemote);
    CHECK(selection.list_names.empty());
}

TEST_CASE("should_reload_runtime_after_list_refresh: only relevant changes reload active runtime") {
    RemoteListsRefreshResult refresh_result;
    refresh_result.changed_lists = {"remote"};
    refresh_result.relevant_changed_lists = {"remote"};

    CHECK(should_reload_runtime_after_list_refresh(true, refresh_result));
    CHECK_FALSE(should_reload_runtime_after_list_refresh(false, refresh_result));

    refresh_result.relevant_changed_lists.clear();
    CHECK_FALSE(should_reload_runtime_after_list_refresh(true, refresh_result));
}

TEST_CASE("build_list_refresh_state_map exposes successful and failed refresh metadata") {
    const auto temp_dir = make_temp_dir();
    CacheManager cache_manager(temp_dir);
    cache_manager.ensure_dir();

    CacheMetadata metadata;
    metadata.url = "https://example.com/remote.txt";
    metadata.download_time = "2026-04-05T12:34:56Z";
    metadata.last_refresh_url = "https://example.com/remote.txt";
    metadata.last_refresh_attempt = "2026-04-06T12:00:00Z";
    metadata.last_refresh_error = "HTTP 403";
    metadata.last_refresh_detour = "backup";
    cache_manager.save_metadata("remote", metadata);

    Config config;

    ListConfig remote;
    remote.url = "https://example.com/remote.txt";

    ListConfig local_file;
    local_file.file = "/tmp/local.lst";

    config.lists = std::map<std::string, ListConfig>{
        {"remote", remote},
        {"local", local_file},
    };

    const auto refresh_state = build_list_refresh_state_map(config, cache_manager);

    auto remote_it = refresh_state.find("remote");
    CHECK(remote_it != refresh_state.end());
    REQUIRE(remote_it->second.last_updated.has_value());
    CHECK(*remote_it->second.last_updated == "2026-04-05T12:34:56Z");
    CHECK(remote_it->second.last_attempt ==
          std::optional<std::string>{"2026-04-06T12:00:00Z"});
    CHECK(remote_it->second.last_error ==
          std::optional<std::string>{"HTTP 403"});
    CHECK(remote_it->second.last_detour ==
          std::optional<std::string>{"backup"});
    CHECK(refresh_state.find("local") == refresh_state.end());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("cache cancellation does not persist refresh failure metadata") {
    const auto temp_dir = make_temp_dir();
    auto transport = std::make_shared<StaticHttpTransport>();
    CacheManager cache_manager(
        temp_dir, kDefaultMaxFileSizeBytes, transport);
    cache_manager.ensure_dir();
    auto cancellation = std::make_shared<std::atomic<bool>>(true);

    const auto result = cache_manager.download(
        "remote",
        "https://example.test/remote.txt",
        CacheDownloadOptions{0, std::nullopt, cancellation});

    CHECK(result.cancelled());
    CHECK(transport->calls == 0);
    const auto metadata = cache_manager.load_metadata("remote");
    CHECK_FALSE(metadata.last_refresh_attempt.has_value());
    CHECK_FALSE(metadata.last_refresh_error.has_value());
    CHECK_FALSE(cache_manager.has_cache("remote"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("list refresh reports bounded per-list progress and cancels distinctly") {
    const auto temp_dir = make_temp_dir();
    auto transport = std::make_shared<StaticHttpTransport>();
    ListService service(temp_dir, kDefaultMaxFileSizeBytes, transport);
    service.ensure_dir();

    Config config;
    ListConfig first;
    first.url = "https://example.test/first.txt";
    ListConfig second;
    second.url = "https://example.test/second.txt";
    config.lists = std::map<std::string, ListConfig>{
        {"first", first},
        {"second", second},
    };

    auto cancellation = std::make_shared<std::atomic<bool>>(false);
    std::vector<RemoteListRefreshProgress> progress;
    RemoteListRefreshControl control;
    control.cancellation = cancellation;
    control.progress = [&](const RemoteListRefreshProgress& update) {
        progress.push_back(update);
        cancellation->store(true, std::memory_order_relaxed);
    };

    try {
        (void)service.refresh_remote_lists(
            config, OutboundMarkMap{}, nullptr, nullptr, nullptr, control);
        FAIL("expected list refresh cancellation");
    } catch (const RemoteListRefreshCancelled& error) {
        CHECK(error.partial_result().changed_lists ==
              std::vector<std::string>{"first"});
    }
    REQUIRE(progress.size() == 1);
    CHECK(progress.front().completed == 1);
    CHECK(progress.front().total == 2);
    CHECK(progress.front().list_name == "first");
    CHECK(progress.front().status == RemoteListRefreshProgressStatus::Updated);
    CHECK(transport->calls == 1);
    CHECK(service.cache_manager().has_cache("first"));
    CHECK_FALSE(service.cache_manager().has_cache("second"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("cancellation racing cache commit preserves relevant changed lists") {
    const auto temp_dir = make_temp_dir();
    auto transport = std::make_shared<StaticHttpTransport>();
    ListService service(temp_dir, kDefaultMaxFileSizeBytes, transport);
    service.ensure_dir();

    Config config;
    ListConfig remote;
    remote.url = "https://example.test/remote.txt";
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};
    const std::set<std::string> relevant{"remote"};
    const std::set<std::string> dns_relevant{"remote"};

    auto cancellation = std::make_shared<std::atomic<bool>>(false);
    RemoteListRefreshControl control;
    control.cancellation = cancellation;
    control.cache_commit = [&](const std::function<void()>& commit) {
        commit();
        cancellation->store(true, std::memory_order_release);
    };

    try {
        (void)service.refresh_remote_lists(
            config,
            OutboundMarkMap{},
            &relevant,
            nullptr,
            &dns_relevant,
            control);
        FAIL("expected list refresh cancellation");
    } catch (const RemoteListRefreshCancelled& error) {
        CHECK(error.partial_result().changed_lists ==
              std::vector<std::string>{"remote"});
        CHECK(error.partial_result().relevant_changed_lists ==
              std::vector<std::string>{"remote"});
        CHECK(error.partial_result().dns_relevant_changed_lists ==
              std::vector<std::string>{"remote"});
    }

    CHECK(service.cache_manager().has_cache("remote"));
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("cancelling an IPC-owned flight does not cancel an independent refresh") {
    const auto temp_dir = make_temp_dir();
    auto transport = std::make_shared<CancelThenSucceedHttpTransport>();
    ListService service(temp_dir, kDefaultMaxFileSizeBytes, transport);
    service.ensure_dir();

    Config config;
    ListConfig remote;
    remote.url = "https://example.test/remote.txt";
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    auto cancellation = std::make_shared<std::atomic<bool>>(false);
    RemoteListRefreshControl cancellable_control;
    cancellable_control.cancellation = cancellation;
    std::exception_ptr cancellable_error;
    std::exception_ptr independent_error;
    std::optional<RemoteListsRefreshResult> independent_result;

    std::thread cancellable_worker([&] {
        try {
            (void)service.refresh_remote_lists(
                config,
                OutboundMarkMap{},
                nullptr,
                nullptr,
                nullptr,
                cancellable_control);
        } catch (...) {
            cancellable_error = std::current_exception();
        }
    });
    if (!transport->wait_until_first_entered()) {
        cancellation->store(true, std::memory_order_release);
        transport->release_first();
        cancellable_worker.join();
        FAIL("cancellable refresh did not reach the transport");
    }

    std::atomic<bool> independent_started{false};
    std::thread independent_worker([&] {
        independent_started.store(true, std::memory_order_release);
        try {
            independent_result = service.refresh_remote_lists(
                config, OutboundMarkMap{});
        } catch (...) {
            independent_error = std::current_exception();
        }
    });
    while (!independent_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    cancellation->store(true, std::memory_order_release);
    transport->release_first();
    cancellable_worker.join();
    independent_worker.join();

    REQUIRE(cancellable_error);
    try {
        std::rethrow_exception(cancellable_error);
    } catch (const RemoteListRefreshCancelled&) {
        CHECK(true);
    } catch (...) {
        FAIL("cancellable owner returned the wrong exception");
    }
    CHECK_FALSE(independent_error);
    REQUIRE(independent_result);
    CHECK(independent_result->changed_lists ==
          std::vector<std::string>{"remote"});
    CHECK(transport->calls() == 2);

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("build_list_refresh_state_map ignores metadata from an old URL") {
    const auto temp_dir = make_temp_dir();
    CacheManager cache_manager(temp_dir);
    cache_manager.ensure_dir();

    CacheMetadata metadata;
    metadata.url = "https://old.example/list.txt";
    metadata.download_time = "2026-04-05T12:34:56Z";
    metadata.last_refresh_url = "https://old.example/list.txt";
    metadata.last_refresh_attempt = "2026-04-06T12:00:00Z";
    metadata.last_refresh_error = "HTTP 403";
    cache_manager.save_metadata("remote", metadata);

    ListConfig remote;
    remote.url = "https://new.example/list.txt";
    Config config;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto refresh_state =
        build_list_refresh_state_map(config, cache_manager);
    REQUIRE(refresh_state.count("remote") == 1);
    CHECK_FALSE(refresh_state.at("remote").last_updated.has_value());
    CHECK_FALSE(refresh_state.at("remote").last_attempt.has_value());
    CHECK_FALSE(refresh_state.at("remote").last_error.has_value());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists: failed HTTP list logs status and refresh continues") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/bad.txt", HttpResponse{404, "Not Found", ""}},
        {"/ok.txt", HttpResponse{200, "OK", "example.com\n"}},
    });
    LoggerCapture logs;

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig bad;
    bad.url = server.url("/bad.txt");
    ListConfig ok;
    ok.url = server.url("/ok.txt");

    Config config;
    config.lists = std::map<std::string, ListConfig>{
        {"bad", bad},
        {"ok", ok},
    };

    const auto result = service.refresh_remote_lists(config, OutboundMarkMap{});

    CHECK(result.failed_lists == std::vector<std::string>{"bad"});
    CHECK(result.changed_lists == std::vector<std::string>{"ok"});
    CHECK(service.cache_manager().has_cache("ok"));
    CHECK_FALSE(service.cache_manager().has_cache("bad"));
    CHECK(logs.contains("List 'bad': failed to refresh " + *bad.url + ": HTTP 404"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists retries network failures through ordered fallbacks") {
    CurlGlobalGuard curl_guard;
    HttpResponse response;
    response.body = "example.com\n";
    response.fail_first_requests = 1;
    response.transient_status = 403;
    response.transient_reason = "Forbidden";
    TestHttpServer server({{"/fallback.txt", response}});

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/fallback.txt");
    remote.detour = "primary";
    remote.fallback_detours =
        std::vector<std::string>{"backup", "unused"};
    Config config;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result = service.refresh_remote_lists(
        config,
        OutboundMarkMap{{"primary", 0}, {"backup", 0}, {"unused", 0}});

    CHECK(result.changed_lists == std::vector<std::string>{"remote"});
    CHECK(result.failed_lists.empty());
    CHECK(server.request_count("/fallback.txt") == 2);
    const auto metadata = service.cache_manager().load_metadata("remote");
    CHECK(metadata.last_refresh_detour ==
          std::optional<std::string>{"backup"});
    CHECK_FALSE(metadata.last_refresh_error.has_value());

    std::filesystem::remove_all(temp_dir);
}

namespace {

// Captures what the refresh actually logged. The level matters beyond the
// journal: the notification bell reads the log tail and renders every warning
// as a current incident, so a warning emitted by a refresh that succeeded is
// an error the operator is shown about a router that is working.
class ListRefreshLogCapture {
public:
    ListRefreshLogCapture() : previous_level_(Logger::instance().level()) {
        Logger::instance().set_level(LogLevel::info);
        Logger::instance().set_sink(
            [this](const std::string& line) { lines_.push_back(line); });
    }

    ~ListRefreshLogCapture() {
        Logger::instance().clear_sink();
        Logger::instance().set_level(previous_level_);
    }

    bool any_contains(const std::string& needle) const {
        return std::any_of(lines_.begin(), lines_.end(),
                           [&needle](const std::string& line) {
                               return line.find(needle) != std::string::npos;
                           });
    }

private:
    LogLevel previous_level_;
    std::vector<std::string> lines_;
};

}  // namespace

TEST_CASE(
    "a refresh that succeeds through a fallback detour warns about nothing") {
    CurlGlobalGuard curl_guard;
    HttpResponse response;
    response.body = "example.com\n";
    response.fail_first_requests = 1;
    response.transient_status = 403;
    response.transient_reason = "Forbidden";
    TestHttpServer server({{"/fallback.txt", response}});

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/fallback.txt");
    remote.detour = "primary";
    remote.fallback_detours = std::vector<std::string>{"backup"};
    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    ListRefreshLogCapture logs;
    const auto result = service.refresh_remote_lists(
        config, OutboundMarkMap{{"primary", 0}, {"backup", 0}});

    REQUIRE(result.failed_lists.empty());
    REQUIRE(result.changed_lists == std::vector<std::string>{"remote"});

    // The dead primary detour is still recorded - the operator can see which
    // route failed - but it is recorded as a step, not as an outcome.
    CHECK(logs.any_contains("refresh through primary failed"));
    CHECK_FALSE(logs.any_contains("[W]"));
    CHECK_FALSE(logs.any_contains("[E]"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("effective_list_refresh_detours preserves legacy per-list overrides") {
    Config legacy_config;
    ListConfig legacy_direct;
    legacy_direct.url = "https://example.com/direct.txt";
    CHECK(effective_list_refresh_detours(legacy_config, legacy_direct).empty());

    Config config;
    ListRefreshConfig global;
    global.detour = "global-primary";
    global.fallback_detours =
        std::vector<std::string>{"global-backup"};
    config.list_refresh = global;

    ListConfig legacy_override;
    legacy_override.url = "https://example.com/legacy.txt";
    legacy_override.detour = "legacy-primary";
    legacy_override.fallback_detours =
        std::vector<std::string>{"legacy-backup"};

    CHECK(effective_list_refresh_detour_mode(legacy_override) ==
          ListRefreshDetourMode::OVERRIDE);
    CHECK(effective_list_refresh_detours(legacy_config, legacy_override) ==
          std::vector<std::string>{"legacy-primary", "legacy-backup"});
    CHECK(effective_list_refresh_detours(config, legacy_override) ==
          std::vector<std::string>{"legacy-primary", "legacy-backup"});

    ListConfig legacy_inherit;
    legacy_inherit.url = "https://example.com/inherit.txt";

    CHECK(effective_list_refresh_detour_mode(legacy_inherit) ==
          ListRefreshDetourMode::INHERIT);
    CHECK(effective_list_refresh_detours(config, legacy_inherit) ==
          std::vector<std::string>{"global-primary", "global-backup"});
}

TEST_CASE("effective_list_refresh_detours honors explicit inherit and override modes") {
    Config config;
    ListRefreshConfig global;
    global.detour = "global-primary";
    global.fallback_detours =
        std::vector<std::string>{"global-backup"};
    config.list_refresh = global;

    ListConfig inherited;
    inherited.url = "https://example.com/inherited.txt";
    inherited.refresh_detour_mode = ListRefreshDetourMode::INHERIT;
    CHECK(effective_list_refresh_detours(config, inherited) ==
          std::vector<std::string>{"global-primary", "global-backup"});

    ListConfig overridden;
    overridden.url = "https://example.com/overridden.txt";
    overridden.refresh_detour_mode = ListRefreshDetourMode::OVERRIDE;
    overridden.detour = "local-primary";
    overridden.fallback_detours =
        std::vector<std::string>{"local-backup"};
    CHECK(effective_list_refresh_detours(config, overridden) ==
          std::vector<std::string>{"local-primary", "local-backup"});
}

TEST_CASE("refresh_remote_lists inherits the ordered global detour chain") {
    CurlGlobalGuard curl_guard;
    HttpResponse response;
    response.body = "example.com\n";
    response.fail_first_requests = 1;
    response.transient_status = 503;
    response.transient_reason = "Service Unavailable";
    TestHttpServer server({{"/global-fallback.txt", response}});

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/global-fallback.txt");
    remote.refresh_detour_mode = ListRefreshDetourMode::INHERIT;

    Config config;
    ListRefreshConfig global;
    global.detour = "global-primary";
    global.fallback_detours =
        std::vector<std::string>{"global-backup", "global-unused"};
    config.list_refresh = global;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result = service.refresh_remote_lists(
        config,
        OutboundMarkMap{{"global-primary", 0},
                        {"global-backup", 0},
                        {"global-unused", 0}});

    CHECK(result.changed_lists == std::vector<std::string>{"remote"});
    CHECK(result.failed_lists.empty());
    CHECK(server.request_count("/global-fallback.txt") == 2);
    const auto metadata = service.cache_manager().load_metadata("remote");
    CHECK(metadata.last_refresh_detour ==
          std::optional<std::string>{"global-backup"});

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists uses an explicit per-list override before the global chain") {
    CurlGlobalGuard curl_guard;
    HttpResponse response;
    response.body = "example.com\n";
    response.fail_first_requests = 1;
    response.transient_status = 503;
    response.transient_reason = "Service Unavailable";
    TestHttpServer server({{"/override-fallback.txt", response}});

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/override-fallback.txt");
    remote.refresh_detour_mode = ListRefreshDetourMode::OVERRIDE;
    remote.detour = "local-primary";
    remote.fallback_detours =
        std::vector<std::string>{"local-backup"};

    Config config;
    ListRefreshConfig global;
    global.detour = "global-primary";
    global.fallback_detours =
        std::vector<std::string>{"global-backup"};
    config.list_refresh = global;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result = service.refresh_remote_lists(
        config,
        OutboundMarkMap{{"local-primary", 0},
                        {"local-backup", 0},
                        {"global-primary", 0},
                        {"global-backup", 0}});

    CHECK(result.changed_lists == std::vector<std::string>{"remote"});
    CHECK(server.request_count("/override-fallback.txt") == 2);
    const auto metadata = service.cache_manager().load_metadata("remote");
    CHECK(metadata.last_refresh_detour ==
          std::optional<std::string>{"local-backup"});

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists never adds direct fallback to a configured global chain") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/global-marked.txt", HttpResponse{200, "OK", "example.com\n"}},
    });

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/global-marked.txt");

    Config config;
    ListRefreshConfig global;
    global.detour = "missing-primary";
    global.fallback_detours =
        std::vector<std::string>{"missing-backup"};
    config.list_refresh = global;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result =
        service.refresh_remote_lists(config, OutboundMarkMap{});

    CHECK(result.failed_lists == std::vector<std::string>{"remote"});
    CHECK(result.changed_lists.empty());
    CHECK(server.request_count("/global-marked.txt") == 0);
    const auto metadata = service.cache_manager().load_metadata("remote");
    REQUIRE(metadata.last_refresh_error.has_value());
    CHECK(metadata.last_refresh_error->find("routing mark") !=
          std::string::npos);
    CHECK_FALSE(metadata.last_refresh_detour.has_value());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists records an unrouteable explicit detour chain") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/marked.txt", HttpResponse{200, "OK", "example.com\n"}},
    });

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    const std::string url = server.url("/marked.txt");
    ListConfig remote;
    remote.url = url;
    Config config;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto initial =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(initial.changed_lists == std::vector<std::string>{"remote"});
    CHECK(server.request_count("/marked.txt") == 1);
    const auto successful =
        service.cache_manager().load_metadata("remote").download_time;
    REQUIRE(successful.has_value());

    config.lists->at("remote").detour = "primary";
    config.lists->at("remote").fallback_detours =
        std::vector<std::string>{"backup"};
    const auto failed =
        service.refresh_remote_lists(config, OutboundMarkMap{});

    CHECK(failed.failed_lists == std::vector<std::string>{"remote"});
    CHECK(server.request_count("/marked.txt") == 1);
    const auto metadata = service.cache_manager().load_metadata("remote");
    CHECK(metadata.download_time == successful);
    CHECK(metadata.last_refresh_url == std::optional<std::string>{url});
    REQUIRE(metadata.last_refresh_attempt.has_value());
    REQUIRE(metadata.last_refresh_error.has_value());
    CHECK(metadata.last_refresh_error->find("routing mark") !=
          std::string::npos);
    CHECK_FALSE(metadata.last_refresh_detour.has_value());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists does not retry local SRS decode failures") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/invalid.srs", HttpResponse{200, "OK", "not-an-srs"}},
    });

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/invalid.srs");
    remote.detour = "primary";
    remote.fallback_detours = std::vector<std::string>{"backup"};
    Config config;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result = service.refresh_remote_lists(
        config, OutboundMarkMap{{"primary", 0}, {"backup", 0}});

    CHECK(result.failed_lists == std::vector<std::string>{"remote"});
    CHECK(server.request_count("/invalid.srs") == 1);
    const auto metadata = service.cache_manager().load_metadata("remote");
    CHECK(metadata.last_refresh_detour ==
          std::optional<std::string>{"primary"});
    REQUIRE(metadata.last_refresh_error.has_value());
    CHECK(metadata.last_refresh_error->find("SRS") != std::string::npos);

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("failed refresh preserves the last successful timestamp") {
    CurlGlobalGuard curl_guard;
    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    HttpResponse response;
    response.body = "example.com\n";
    response.fail_after_requests = 1;
    TestHttpServer server({{"/stable.txt", response}});
    const std::string url = server.url("/stable.txt");
    ListConfig remote;
    remote.url = url;
    Config config;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};
    const auto first =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(first.changed_lists ==
          std::vector<std::string>{"remote"});

    const auto successful =
        service.cache_manager().load_metadata("remote").download_time;
    REQUIRE(successful.has_value());

    const auto failed =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(failed.failed_lists == std::vector<std::string>{"remote"});

    const auto metadata = service.cache_manager().load_metadata("remote");
    CHECK(metadata.download_time == successful);
    REQUIRE(metadata.last_refresh_attempt.has_value());
    REQUIRE(metadata.last_refresh_error.has_value());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("download_uncached: preserves cached lists and tracks DNS-relevant changes") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/route.txt", HttpResponse{200, "OK", "example.com\n"}},
        {"/unused.txt", HttpResponse{200, "OK", "unused.example\n"}},
    });

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig dns_list;
    dns_list.url = server.url("/route.txt");
    ListConfig unused_list;
    unused_list.url = server.url("/unused.txt");

    Config config;
    config.lists = std::map<std::string, ListConfig>{
        {"dns", dns_list},
        {"unused", unused_list},
    };

    const std::set<std::string> relevant_lists{"dns"};
    const std::set<std::string> dns_relevant_lists{"dns"};
    const auto result = service.refresh_remote_lists(
        config, OutboundMarkMap{}, &relevant_lists, nullptr, &dns_relevant_lists);

    CHECK(result.changed_lists == std::vector<std::string>{"dns", "unused"});
    CHECK(result.relevant_changed_lists == std::vector<std::string>{"dns"});
    CHECK(result.dns_relevant_changed_lists == std::vector<std::string>{"dns"});

    const auto second_result = service.download_uncached(
        config, OutboundMarkMap{}, &relevant_lists, &dns_relevant_lists);
    CHECK(second_result.refreshed_lists.empty());
    CHECK(second_result.cached_lists == std::vector<std::string>{"dns", "unused"});
    CHECK(second_result.changed_lists.empty());

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("download_uncached: changed URL invalidates a cache with the same list name") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/old.txt", HttpResponse{200, "OK", "old.example\n"}},
        {"/new.txt", HttpResponse{200, "OK", "new.example\n"}},
    });

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/old.txt");
    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto first =
        service.download_uncached(config, OutboundMarkMap{});
    CHECK(first.changed_lists == std::vector<std::string>{"remote"});

    remote.url = server.url("/new.txt");
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};
    const auto second =
        service.download_uncached(config, OutboundMarkMap{});
    CHECK(second.changed_lists == std::vector<std::string>{"remote"});
    CHECK(second.cached_lists.empty());

    std::ifstream refreshed(service.cache_manager().cache_path("remote"));
    REQUIRE(refreshed.good());
    CHECK(std::string(std::istreambuf_iterator<char>(refreshed), {}) ==
          "new.example\n");

    const auto third =
        service.download_uncached(config, OutboundMarkMap{});
    CHECK(third.refreshed_lists.empty());
    CHECK(third.cached_lists == std::vector<std::string>{"remote"});

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("remote_list_sources_changed ignores non-source list edits") {
    ListConfig remote;
    remote.url = "https://example.com/list.txt";
    remote.detour = "vpn";
    remote.display_name = "Old name";
    remote.ttl_ms = 1000;
    remote.domains = std::vector<std::string>{"old.example"};

    Config current;
    current.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    remote.display_name = "New name";
    remote.ttl_ms = 2000;
    remote.domains = std::vector<std::string>{"new.example"};
    Config next;
    next.lists = std::map<std::string, ListConfig>{{"remote", remote}};
    ApiConfig api;
    api.listen = "127.0.0.1:12121";
    next.api = api;

    CHECK_FALSE(remote_list_sources_changed(current, next));
}

TEST_CASE("remote_list_sources_changed detects URL detour and membership changes") {
    ListConfig remote;
    remote.url = "https://example.com/list.txt";
    remote.detour = "vpn-a";

    Config current;
    current.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    Config changed_url = current;
    changed_url.lists->at("remote").url = "https://example.com/new.txt";
    CHECK(remote_list_sources_changed(current, changed_url));

    Config changed_detour = current;
    changed_detour.lists->at("remote").detour = "vpn-b";
    CHECK(remote_list_sources_changed(current, changed_detour));

    Config changed_fallback = current;
    changed_fallback.lists->at("remote").fallback_detours =
        std::vector<std::string>{"vpn-c"};
    CHECK(remote_list_sources_changed(current, changed_fallback));

    Config removed = current;
    removed.lists = std::map<std::string, ListConfig>{};
    CHECK(remote_list_sources_changed(current, removed));

    Config added = removed;
    added.lists = current.lists;
    CHECK(remote_list_sources_changed(removed, added));
}

TEST_CASE("remote_list_sources_changed compares effective global and override chains") {
    ListConfig inherited;
    inherited.url = "https://example.com/inherited.txt";
    inherited.refresh_detour_mode = ListRefreshDetourMode::INHERIT;

    ListConfig overridden;
    overridden.url = "https://example.com/overridden.txt";
    overridden.refresh_detour_mode = ListRefreshDetourMode::OVERRIDE;
    overridden.detour = "local-primary";

    Config current;
    ListRefreshConfig global;
    global.detour = "global-primary";
    global.fallback_detours =
        std::vector<std::string>{"global-backup"};
    current.list_refresh = global;
    current.lists = std::map<std::string, ListConfig>{
        {"inherited", inherited},
        {"overridden", overridden},
    };

    Config changed_global = current;
    changed_global.list_refresh->fallback_detours =
        std::vector<std::string>{"global-backup-2"};
    CHECK(remote_list_sources_changed(current, changed_global));

    Config override_only = current;
    override_only.lists =
        std::map<std::string, ListConfig>{{"overridden", overridden}};
    Config override_only_changed_global = override_only;
    override_only_changed_global.list_refresh->detour = "other-global";
    CHECK_FALSE(remote_list_sources_changed(
        override_only, override_only_changed_global));

    Config changed_mode = current;
    changed_mode.lists->at("inherited").refresh_detour_mode =
        ListRefreshDetourMode::OVERRIDE;
    changed_mode.lists->at("inherited").detour = "local-primary";
    CHECK(remote_list_sources_changed(current, changed_mode));
}

TEST_CASE("refresh_remote_lists: failed curl request logs clear transport error") {
    CurlGlobalGuard curl_guard;
    LoggerCapture logs;

    const auto temp_dir = make_temp_dir();
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = "http://127.0.0.1:1/missing.txt";

    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result = service.refresh_remote_lists(config, OutboundMarkMap{});

    CHECK(result.failed_lists == std::vector<std::string>{"remote"});
    CHECK(logs.contains("List 'remote': failed to refresh http://127.0.0.1:1/missing.txt:"));
    CHECK_FALSE(logs.contains("HTTP request failed:"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE(
    "download_uncached uses a validated same-source legacy SRS cache when refresh fails") {
    CurlGlobalGuard curl_guard;
    LoggerCapture logs;

    const auto temp_dir = make_temp_dir();
    const std::string url =
        "http://127.0.0.1:1/unavailable.srs";
    {
        CacheManager cache_manager(temp_dir);
        cache_manager.ensure_dir();
        std::ofstream cached(cache_manager.cache_path("remote"));
        REQUIRE(cached.good());
        cached << "example.com\n"
               << "*.example.net\n"
               << "192.0.2.0/24\n";
        CacheMetadata metadata;
        metadata.url = url;
        cache_manager.save_metadata("remote", metadata);
    }

    ListService service(temp_dir);
    service.ensure_dir();
    ListConfig remote;
    remote.url = url;
    Config config;
    config.lists =
        std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result =
        service.download_uncached(config, OutboundMarkMap{});

    CHECK(result.failed_lists.empty());
    CHECK(result.cached_lists ==
          std::vector<std::string>{"remote"});
    CHECK(result.legacy_cached_lists ==
          std::vector<std::string>{"remote"});
    CHECK(logs.contains(
        "continuing with validated same-source cache from an older "
        "decoder revision: remote"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("legacy SRS fallback never accepts another source or malformed text") {
    const auto temp_dir = make_temp_dir();
    CacheManager cache_manager(temp_dir);
    cache_manager.ensure_dir();

    CacheMetadata metadata;
    metadata.url = "https://old.example/list.srs";
    cache_manager.save_metadata("remote", metadata);
    {
        std::ofstream cached(cache_manager.cache_path("remote"));
        REQUIRE(cached.good());
        cached << "example.com\n";
    }

    CHECK_FALSE(cache_manager.has_usable_same_source_cache(
        "remote", "https://new.example/list.srs"));
    CHECK(cache_manager.has_usable_same_source_cache(
        "remote", "https://old.example/list.srs"));

    {
        std::ofstream malformed(
            cache_manager.cache_path("remote"),
            std::ios::trunc);
        REQUIRE(malformed.good());
        malformed << "not/a/valid/list/entry\n";
    }
    CHECK_FALSE(cache_manager.has_usable_same_source_cache(
        "remote", "https://old.example/list.srs"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists: 304 not modified does not log a warning") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/not-modified.txt", HttpResponse{304, "Not Modified", ""}},
    });
    LoggerCapture logs;

    const auto temp_dir = make_temp_dir();
    {
        CacheManager cache_manager(temp_dir);
        cache_manager.ensure_dir();
        CacheMetadata metadata;
        metadata.etag = "\"abc\"";
        metadata.url = server.url("/not-modified.txt");
        cache_manager.save_metadata("remote", metadata);
        std::ofstream cached(cache_manager.cache_path("remote"));
        REQUIRE(cached.good());
        cached << "cached.example\n";
    }

    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/not-modified.txt");

    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result = service.refresh_remote_lists(config, OutboundMarkMap{});

    CHECK(result.failed_lists.empty());
    CHECK(result.changed_lists.empty());
    CHECK_FALSE(logs.contains("failed to refresh"));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists: empty SRS replaces stale cache and decoder revision bypasses 304") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/empty.srs",
         HttpResponse{
             200,
             "OK",
             empty_srs_file(),
             true,
             {"ETag: \"empty-v1\"",
              "Last-Modified: Fri, 25 Jul 2026 00:00:00 GMT"}}},
    });

    const auto temp_dir = make_temp_dir();
    {
        CacheManager cache_manager(temp_dir);
        cache_manager.ensure_dir();
        std::ofstream stale(cache_manager.cache_path("remote"));
        REQUIRE(stale.good());
        stale << "stale.example\n";
        CacheMetadata old_metadata;
        old_metadata.etag = "\"empty-v1\"";
        old_metadata.last_modified = "Fri, 25 Jul 2026 00:00:00 GMT";
        old_metadata.url = server.url("/empty.srs");
        cache_manager.save_metadata("remote", old_metadata);
    }
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/empty.srs");
    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto first =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(first.changed_lists == std::vector<std::string>{"remote"});

    std::ifstream converted(service.cache_manager().cache_path("remote"),
                            std::ios::binary);
    REQUIRE(converted.good());
    CHECK(std::string(std::istreambuf_iterator<char>(converted), {}) == "");

    const auto metadata = service.cache_manager().load_metadata("remote");
    REQUIRE(metadata.srs_decoder_revision.has_value());
    CHECK(*metadata.srs_decoder_revision == kSrsDecoderRevision);

    const auto second =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(second.changed_lists.empty());
    CHECK(second.unchanged_lists == std::vector<std::string>{"remote"});

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists: changing URL never reuses validators from old source") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/new.txt",
         HttpResponse{
             200,
             "OK",
             "new.example\n",
             true,
             {"ETag: \"shared\""}}},
    });

    const auto temp_dir = make_temp_dir();
    {
        CacheManager cache_manager(temp_dir);
        cache_manager.ensure_dir();
        std::ofstream stale(cache_manager.cache_path("remote"));
        REQUIRE(stale.good());
        stale << "old.example\n";
        CacheMetadata old_metadata;
        old_metadata.etag = "\"shared\"";
        old_metadata.url = "https://old.example/list.txt";
        cache_manager.save_metadata("remote", old_metadata);
    }
    ListService service(temp_dir);
    service.ensure_dir();

    ListConfig remote;
    remote.url = server.url("/new.txt");
    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto first =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(first.changed_lists == std::vector<std::string>{"remote"});

    std::ifstream refreshed(service.cache_manager().cache_path("remote"));
    REQUIRE(refreshed.good());
    CHECK(std::string(std::istreambuf_iterator<char>(refreshed), {}) ==
          "new.example\n");

    const auto second =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(second.changed_lists.empty());
    CHECK(second.unchanged_lists == std::vector<std::string>{"remote"});

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("refresh_remote_lists: metadata without cached body forces full download") {
    CurlGlobalGuard curl_guard;
    TestHttpServer server({
        {"/recover.txt",
         HttpResponse{
             200,
             "OK",
             "recovered.example\n",
             true,
             {"ETag: \"same\""}}},
    });

    const auto temp_dir = make_temp_dir();
    {
        CacheManager cache_manager(temp_dir);
        cache_manager.ensure_dir();
        CacheMetadata orphan_metadata;
        orphan_metadata.etag = "\"same\"";
        orphan_metadata.url = server.url("/recover.txt");
        cache_manager.save_metadata("remote", orphan_metadata);
    }

    ListService service(temp_dir);
    service.ensure_dir();
    ListConfig remote;
    remote.url = server.url("/recover.txt");
    Config config;
    config.lists = std::map<std::string, ListConfig>{{"remote", remote}};

    const auto result =
        service.refresh_remote_lists(config, OutboundMarkMap{});
    CHECK(result.changed_lists == std::vector<std::string>{"remote"});

    std::ifstream recovered(service.cache_manager().cache_path("remote"));
    REQUIRE(recovered.good());
    CHECK(std::string(std::istreambuf_iterator<char>(recovered), {}) ==
          "recovered.example\n");

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("collect_relevant_list_names: ignores disabled route and dns rules") {
    Config config;

    ListConfig remote;
    remote.url = "https://example.com/remote.txt";
    config.lists = std::map<std::string, ListConfig>{
        {"route_disabled", remote},
        {"route_enabled", remote},
        {"dns_disabled", remote},
        {"dns_enabled", remote},
    };

    RouteRule route_disabled;
    route_disabled.enabled = false;
    route_disabled.list = std::vector<std::string>{"route_disabled"};
    route_disabled.outbound = "vpn";

    RouteRule route_enabled;
    route_enabled.list = std::vector<std::string>{"route_enabled"};
    route_enabled.outbound = "vpn";

    RouteConfig route_config;
    route_config.rules = std::vector<RouteRule>{route_disabled, route_enabled};
    config.route = route_config;

    DnsRule dns_disabled;
    dns_disabled.enabled = false;
    dns_disabled.list = std::vector<std::string>{"dns_disabled"};
    dns_disabled.server = "dns1";

    DnsRule dns_enabled;
    dns_enabled.list = std::vector<std::string>{"dns_enabled"};
    dns_enabled.server = "dns1";

    DnsConfig dns_config;
    dns_config.rules = std::vector<DnsRule>{dns_disabled, dns_enabled};
    config.dns = dns_config;

    const auto relevant_lists = collect_relevant_list_names(config);

    CHECK(relevant_lists.count("route_disabled") == 0);
    CHECK(relevant_lists.count("dns_disabled") == 0);
    CHECK(relevant_lists.count("route_enabled") == 1);
    CHECK(relevant_lists.count("dns_enabled") == 1);

    const auto dns_relevant_lists = collect_dns_relevant_list_names(config);
    CHECK(dns_relevant_lists.count("route_enabled") == 0);
    CHECK(dns_relevant_lists.count("dns_disabled") == 0);
    CHECK(dns_relevant_lists.count("dns_enabled") == 1);
}
