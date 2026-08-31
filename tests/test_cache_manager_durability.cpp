#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/crypto/sha256.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace keen_pbr3;

namespace {

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        char pattern[] = "/tmp/keen-pbr-cache-durability-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = created;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

class SequenceHttpTransport final : public HttpTransport {
public:
    void enqueue(std::string body,
                 std::string etag = {},
                 long status_code = 200) {
        HttpTransportResponse response;
        response.status_code = status_code;
        response.body = std::move(body);
        if (!etag.empty()) response.headers["etag"] = std::move(etag);
        responses_.push_back(std::move(response));
    }

    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        requests.push_back(request);
        if (responses_.empty()) {
            throw std::runtime_error("no queued HTTP response");
        }
        auto response = std::move(responses_.front());
        responses_.pop_front();
        return response;
    }

    std::vector<HttpTransportRequest> requests;

private:
    std::deque<HttpTransportResponse> responses_;
};

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

bool has_request_header(const HttpTransportRequest& request,
                        const std::string& expected) {
    return std::find(request.headers.begin(), request.headers.end(), expected) !=
           request.headers.end();
}

std::vector<std::filesystem::path> generation_files(
    const std::filesystem::path& directory,
    const std::string& name) {
    std::vector<std::filesystem::path> result;
    const std::string prefix = name + ".g-";
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const auto filename = entry.path().filename().string();
        if (filename.rfind(prefix, 0) == 0 &&
            filename.size() > prefix.size() + 4U &&
            filename.compare(filename.size() - 4U, 4U, ".txt") == 0) {
            result.push_back(entry.path());
        }
    }
    return result;
}

constexpr const char* kUrl = "https://example.test/remote.txt";

} // namespace

TEST_CASE("cache metadata commits immutable current and previous generations") {
    TemporaryDirectory temporary;
    const auto cache_dir = temporary.path() / "nested" / "cache";
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(cache_dir, kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    struct stat directory_metadata {};
    REQUIRE(::lstat(cache_dir.c_str(), &directory_metadata) == 0);
    CHECK(S_ISDIR(directory_metadata.st_mode));
    CHECK_FALSE(S_ISLNK(directory_metadata.st_mode));

    transport->enqueue("one.example\n", "one");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto first = cache.load_metadata("remote");
    REQUIRE(first.current.has_value());
    CHECK_FALSE(first.previous.has_value());
    CHECK(first.current->size == 12);
    CHECK(first.current->sha256 == Sha256::hex("one.example\n"));
    CHECK(read_file(cache.cache_path("remote")) == "one.example\n");

    transport->enqueue("two.example\n", "two");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto second = cache.load_metadata("remote");
    REQUIRE(second.current.has_value());
    REQUIRE(second.previous.has_value());
    CHECK(second.previous->filename == first.current->filename);
    CHECK(read_file(cache.cache_path("remote")) == "two.example\n");
    REQUIRE(transport->requests.size() == 2U);
    CHECK(has_request_header(transport->requests.back(), "If-None-Match: one"));

    const auto foreign_lookalike = cache_dir / "remote.123-4-5.txt";
    {
        std::ofstream foreign(foreign_lookalike, std::ios::binary);
        foreign << "must-not-be-collected\n";
    }

    transport->enqueue("three.example\n", "three");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto third = cache.load_metadata("remote");
    REQUIRE(third.current.has_value());
    REQUIRE(third.previous.has_value());
    CHECK(third.previous->filename == second.current->filename);
    CHECK_FALSE(std::filesystem::exists(
        cache_dir / first.current->filename));
    CHECK(generation_files(cache_dir, "remote").size() == 2U);
    CHECK(std::filesystem::exists(foreign_lookalike));
}

TEST_CASE("cache snapshot pins an obsolete generation until its last lease is released") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("one.example\n", "one");
    REQUIRE(cache.download("remote", kUrl).updated());
    auto snapshot = cache.capture_generation({"remote"});
    const auto* pinned = snapshot->find("remote");
    REQUIRE(pinned != nullptr);
    const auto pinned_path = pinned->path();
    CHECK(read_file(pinned_path) == "one.example\n");

    transport->enqueue("two.example\n", "two");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue("three.example\n", "three");
    REQUIRE(cache.download("remote", kUrl).updated());

    // Ordinarily the first generation is outside current/previous now. Its
    // lease keeps the immutable body readable across the GC pass.
    REQUIRE(std::filesystem::exists(pinned_path));
    CHECK(read_file(pinned_path) == "one.example\n");

    snapshot.reset();
    CHECK_FALSE(std::filesystem::exists(pinned_path));
}

TEST_CASE("cache generation waits for every concurrent snapshot lease") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("one.example\n", "one");
    REQUIRE(cache.download("remote", kUrl).updated());
    auto first_snapshot = cache.capture_generation({"remote"});
    auto second_snapshot = cache.capture_generation({"remote"});
    const auto* pinned = first_snapshot->find("remote");
    REQUIRE(pinned != nullptr);
    const auto pinned_path = pinned->path();
    REQUIRE(second_snapshot->find("remote") != nullptr);
    CHECK(second_snapshot->find("remote")->path() == pinned_path);

    transport->enqueue("two.example\n", "two");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue("three.example\n", "three");
    REQUIRE(cache.download("remote", kUrl).updated());
    REQUIRE(std::filesystem::exists(pinned_path));

    first_snapshot.reset();
    CHECK(std::filesystem::exists(pinned_path));
    second_snapshot.reset();
    CHECK_FALSE(std::filesystem::exists(pinned_path));
}

TEST_CASE("cache lease release preserves a generation restored in metadata") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("one.example\n", "one");
    REQUIRE(cache.download("remote", kUrl).updated());
    auto snapshot = cache.capture_generation({"remote"});
    const auto* pinned = snapshot->find("remote");
    REQUIRE(pinned != nullptr);
    const auto pinned_path = pinned->path();
    const auto pinned_generation = pinned->generation();

    transport->enqueue("two.example\n", "two");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue("three.example\n", "three");
    REQUIRE(cache.download("remote", kUrl).updated());
    REQUIRE(std::filesystem::exists(pinned_path));

    // Simulate a transactional rollback which makes the retired body the
    // verified previous generation again before the old snapshot is released.
    auto restored = cache.load_metadata("remote");
    restored.previous = pinned_generation;
    cache.save_metadata("remote", restored);
    snapshot.reset();
    CHECK(std::filesystem::exists(pinned_path));

    // A later normal commit advances current/previous and GC can reclaim it.
    transport->enqueue("four.example\n", "four");
    REQUIRE(cache.download("remote", kUrl).updated());
    CHECK_FALSE(std::filesystem::exists(pinned_path));
}

TEST_CASE("cache precommit failure preserves the committed generation") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("stable.example\n", "stable");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto before = cache.load_metadata("remote");
    REQUIRE(before.current.has_value());

    transport->enqueue("uncommitted.example\n", "uncommitted");
    CacheDownloadOptions options;
    options.commit = [](const std::function<void()>&) {
        throw std::runtime_error("injected precommit failure");
    };
    const auto result = cache.download("remote", kUrl, options);

    CHECK(result.failed());
    CHECK(result.error_message.find("injected precommit failure") !=
          std::string::npos);
    const auto after = cache.load_metadata("remote");
    REQUIRE(after.current.has_value());
    CHECK(after.current->filename == before.current->filename);
    CHECK(read_file(cache.cache_path("remote")) == "stable.example\n");
    CHECK(generation_files(temporary.path(), "remote").size() == 1U);
}

TEST_CASE("cache frees an uncommitted body before recording commit failure") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("stable.example\n", "stable");
    REQUIRE(cache.download("remote", kUrl).updated());
    REQUIRE(generation_files(temporary.path(), "remote").size() == 1U);

    transport->enqueue("uncommitted.example\n", "uncommitted");
    CacheDownloadOptions options;
    options.metadata_fault_injector = [](AtomicFileWriteStage stage) {
        if (stage == AtomicFileWriteStage::rename) {
            throw std::system_error(
                ENOSPC,
                std::generic_category(),
                "injected metadata ENOSPC");
        }
    };
    std::size_t bodies_before_failure_metadata = 0U;
    options.before_failure_metadata_persist = [&]() {
        bodies_before_failure_metadata =
            generation_files(temporary.path(), "remote").size();
    };

    const auto result = cache.download("remote", kUrl, options);

    CHECK(result.failed());
    CHECK(result.error_message.find("injected metadata ENOSPC") !=
          std::string::npos);
    CHECK(bodies_before_failure_metadata == 1U);
    CHECK(generation_files(temporary.path(), "remote").size() == 1U);
    const auto metadata = cache.load_metadata("remote");
    REQUIRE(metadata.current.has_value());
    REQUIRE(metadata.last_refresh_error.has_value());
    CHECK(metadata.last_refresh_error->find("injected metadata ENOSPC") !=
          std::string::npos);
    CHECK(read_file(cache.cache_path("remote")) == "stable.example\n");
}

TEST_CASE("cache post-rename metadata fsync failure remains an applied update") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("old.example\n", "old");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto before = cache.load_metadata("remote");
    REQUIRE(before.current.has_value());

    transport->enqueue("visible.example\n", "visible");
    CacheDownloadOptions options;
    options.metadata_fault_injector = [](AtomicFileWriteStage stage) {
        if (stage == AtomicFileWriteStage::directory_fsync) {
            throw std::runtime_error("injected metadata directory fsync failure");
        }
    };
    const auto result = cache.download("remote", kUrl, options);

    // Callers continue their runtime apply because the fixed metadata pointer
    // already names a complete and verified immutable body.
    CHECK(result.updated());
    CHECK(result.warning_message.find("durability check failed") !=
          std::string::npos);
    CHECK(read_file(cache.cache_path("remote")) == "visible.example\n");
    const auto after = cache.load_metadata("remote");
    REQUIRE(after.current.has_value());
    REQUIRE(after.previous.has_value());
    CHECK(after.current->filename != before.current->filename);
    CHECK(after.previous->filename == before.current->filename);
}

TEST_CASE("cache corruption falls back to previous and refresh repairs current") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    transport->enqueue("previous.example\n", "previous");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue("current.example\n", "current");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto damaged = cache.load_metadata("remote");
    REQUIRE(damaged.current.has_value());
    REQUIRE(damaged.previous.has_value());

    {
        std::ofstream corrupt(
            temporary.path() / damaged.current->filename,
            std::ios::binary | std::ios::trunc);
        corrupt << "corrupt\n";
    }

    CHECK(cache.has_cache("remote"));
    CHECK_FALSE(cache.has_current_cache("remote", kUrl));
    CHECK(cache.has_usable_same_source_cache("remote", kUrl));
    CHECK(read_file(cache.cache_path("remote")) == "previous.example\n");

    transport->enqueue("repaired.example\n", "repaired");
    REQUIRE(cache.download("remote", kUrl).updated());
    REQUIRE(transport->requests.size() == 3U);
    CHECK(transport->requests.back().headers.empty());
    CHECK(read_file(cache.cache_path("remote")) == "repaired.example\n");
    const auto repaired = cache.load_metadata("remote");
    REQUIRE(repaired.previous.has_value());
    CHECK(repaired.previous->filename == damaged.previous->filename);
    CHECK_FALSE(std::filesystem::exists(
        temporary.path() / damaged.current->filename));
}

TEST_CASE("legacy cache is readable and migrates without losing rollback") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();

    const auto legacy_path = temporary.path() / "remote.txt";
    {
        std::ofstream legacy(legacy_path, std::ios::binary);
        legacy << "legacy.example\n";
    }
    CacheMetadata legacy_metadata;
    legacy_metadata.url = kUrl;
    legacy_metadata.etag = "legacy";
    cache.save_metadata("remote", legacy_metadata);

    CHECK(cache.has_current_cache("remote", kUrl));
    CHECK(cache.cache_path("remote") == legacy_path);

    transport->enqueue("migrated.example\n", "migrated");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto migrated = cache.load_metadata("remote");
    REQUIRE(migrated.current.has_value());
    REQUIRE(migrated.previous.has_value());
    CHECK(migrated.previous->filename == "remote.txt");
    CHECK(read_file(cache.cache_path("remote")) == "migrated.example\n");
}

TEST_CASE("cache metadata write failure is never silent") {
    TemporaryDirectory temporary;
    CacheManager cache(temporary.path());
    cache.ensure_dir();
    std::filesystem::create_directory(cache.meta_path("remote"));

    CacheMetadata metadata;
    metadata.url = kUrl;
    CHECK_THROWS(cache.save_metadata("remote", metadata));
}

namespace {

// A body with `count` distinct hosts, so a test can shrink a list on purpose.
std::string host_list(std::size_t count) {
    std::string body;
    for (std::size_t index = 0; index < count; ++index) {
        body += "host" + std::to_string(index) + ".example\n";
    }
    return body;
}

} // namespace

TEST_CASE("a list that loses most of its entries is refused, and the cache keeps the old one") {
    // The case this guards: the source moved, a CDN served a stub, a generator
    // upstream broke. The download succeeds and the body parses, so nothing
    // else objects - and publishing it would unroute everything the list
    // carried without a word.
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes,
                       transport);
    cache.ensure_dir();

    const auto full = host_list(200);
    transport->enqueue(full, "full");
    REQUIRE(cache.download("remote", kUrl).updated());

    const auto after_first = cache.load_metadata("remote");
    // The counts are recorded, which is what makes the next comparison
    // possible at all.
    REQUIRE(after_first.domains.has_value());
    CHECK(*after_first.domains == 200);

    transport->enqueue(host_list(3), "stub");
    const auto refused = cache.download("remote", kUrl);

    CHECK(refused.failed());
    CHECK(refused.error_message.find("keeping the cached list") !=
          std::string::npos);
    // The body the readers see is still the good one.
    CHECK(read_file(cache.cache_path("remote")) == full);

    const auto after_refusal = cache.load_metadata("remote");
    // And the ETag was not advanced. That is the part that matters most: a
    // stored ETag from a refused body would make the next refresh be told it
    // is already up to date, and the bad update would win by waiting.
    REQUIRE(after_refusal.etag.has_value());
    CHECK(*after_refusal.etag == "full");
    CHECK(*after_refusal.domains == 200);
}

TEST_CASE("an ordinary update is published and its counts are recorded") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes,
                       transport);
    cache.ensure_dir();

    transport->enqueue(host_list(200), "first");
    REQUIRE(cache.download("remote", kUrl).updated());

    // Losing a tenth is ordinary list maintenance, not a broken source.
    const auto trimmed = host_list(180);
    transport->enqueue(trimmed, "second");
    REQUIRE(cache.download("remote", kUrl).updated());

    CHECK(read_file(cache.cache_path("remote")) == trimmed);
    const auto meta = cache.load_metadata("remote");
    CHECK(*meta.domains == 180);
    CHECK(*meta.etag == "second");
}

TEST_CASE("a small list may shrink freely") {
    // Three entries becoming one is an edit. Relative change says almost
    // nothing in the small, and a guard that argued here would be a nuisance
    // rather than a protection.
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes,
                       transport);
    cache.ensure_dir();

    transport->enqueue(host_list(3), "first");
    REQUIRE(cache.download("remote", kUrl).updated());

    transport->enqueue(host_list(1), "second");
    CHECK(cache.download("remote", kUrl).updated());
}
