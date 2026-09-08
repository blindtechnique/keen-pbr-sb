#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/crypto/sha256.hpp"
#include "../src/lists/list_source_decoder.hpp"

#include <algorithm>
#include <atomic>
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

TEST_CASE("cache snapshot reuse fingerprint includes source URL even when bytes stay equal") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    constexpr const char* replacement_url = "https://example.test/replacement.txt";
    constexpr const char* body = "same.example\n";
    transport->enqueue(body);
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto original = cache.capture_generation({"remote", "missing"});
    const auto original_fingerprints = original->fingerprints();
    REQUIRE(original->find("remote") != nullptr);
    CHECK(original_fingerprints.at("remote").size() == 64U);
    CHECK(original_fingerprints.at("missing").empty());

    cache.record_refresh_failure("remote", replacement_url, "provider unavailable");
    CHECK(cache.capture_generation({"remote", "missing"})->fingerprints() ==
          original_fingerprints);
    transport->enqueue(body);
    REQUIRE(cache.download("remote", replacement_url).updated());
    const auto replacement = cache.capture_generation({"remote", "missing"});
    REQUIRE(replacement->find("remote") != nullptr);
    CHECK(replacement->find("remote")->generation().sha256 ==
          original->find("remote")->generation().sha256);
    CHECK(replacement->find("remote")->generation().sha256 == Sha256::hex(body));
    CHECK(replacement->fingerprints().at("remote") !=
          original_fingerprints.at("remote"));
    CHECK(replacement->fingerprints().at("missing").empty());
    CHECK(original->fingerprints() == original_fingerprints);

    transport->enqueue(body);
    REQUIRE(cache.download("remote", replacement_url).updated());
    CHECK(cache.capture_generation({"remote", "missing"})->fingerprints() ==
          replacement->fingerprints());
    transport->enqueue("changed.example\n");
    REQUIRE(cache.download("remote", replacement_url).updated());
    CHECK(cache.capture_generation({"remote", "missing"})->fingerprints() !=
          replacement->fingerprints());
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
    REQUIRE(refused.shrink_rejection.has_value());
    CHECK(refused.shrink_rejection->previous_entries == 200);
    CHECK(refused.shrink_rejection->candidate_entries == 3);
    CHECK(refused.shrink_rejection->previous_sha256 == Sha256::hex(full));
    CHECK(refused.shrink_rejection->candidate_sha256 == Sha256::hex(host_list(3)));
    CHECK(refused.shrink_rejection->min_previous_entries == 50);
    CHECK(refused.shrink_rejection->min_retained_fraction == doctest::Approx(0.5));
    REQUIRE(after_refusal.last_refresh_shrink_rejection.has_value());
    CHECK(after_refusal.last_refresh_shrink_rejection->candidate_sha256 ==
          refused.shrink_rejection->candidate_sha256);
    CHECK(after_refusal.download_time == after_first.download_time);
    CHECK(after_refusal.current->filename == after_first.current->filename);
    CHECK(generation_files(temporary.path() / "cache", "remote").size() == 1);
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

TEST_CASE("force list download skips validators but keeps the source shrink policy") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    auto metadata = cache.load_metadata("remote");
    metadata.last_modified = "Wed, 01 Jan 2025 00:00:00 GMT";
    cache.save_metadata("remote", metadata);

    CacheDownloadOptions options;
    options.force_refresh = true;
    transport->enqueue(host_list(3), "small");
    const auto result = cache.download("remote", kUrl, options);
    CHECK(result.failed());
    REQUIRE(result.shrink_rejection.has_value());
    CHECK(result.shrink_rejection->candidate_entries == 3);
    CHECK_FALSE(has_request_header(transport->requests.back(), "If-None-Match: full"));
    CHECK_FALSE(has_request_header(transport->requests.back(),
                                  "If-Modified-Since: Wed, 01 Jan 2025 00:00:00 GMT"));
    CHECK(read_file(cache.cache_path("remote")) == host_list(200));
}

TEST_CASE("accepting the shown shrink downloads that body once without keeping the permission") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue(host_list(60), "small");
    const auto refusal = cache.download("remote", kUrl);
    REQUIRE(refusal.shrink_rejection.has_value());

    CacheDownloadOptions options;
    auto& accepted = options.accept_shrink.emplace();
    accepted.previous_sha256 = refusal.shrink_rejection->previous_sha256;
    accepted.candidate_sha256 = refusal.shrink_rejection->candidate_sha256;
    transport->enqueue(host_list(60), "small");
    const auto result = cache.download("remote", kUrl, options);
    CHECK(result.updated());
    CHECK_FALSE(result.shrink_rejection.has_value());
    CHECK_FALSE(has_request_header(transport->requests.back(), "If-None-Match: full"));
    const auto metadata = cache.load_metadata("remote");
    CHECK_FALSE(metadata.last_refresh_shrink_rejection.has_value());
    CHECK_FALSE(metadata.last_refresh_error.has_value());
    CHECK(metadata.domains == 60);
    CHECK(metadata.etag == "small");
    CHECK(read_file(cache.cache_path("remote")) == host_list(60));

    transport->enqueue(host_list(1), "smaller");
    const auto later = cache.download("remote", kUrl);
    CHECK(later.failed());
    REQUIRE(later.shrink_rejection.has_value());
    CHECK(later.shrink_rejection->previous_entries == 60);
    CHECK(read_file(cache.cache_path("remote")) == host_list(60));
}

TEST_CASE("accept shrink does not accept different downloaded content with the same entry count") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue(host_list(3), "first-small");
    const auto refusal = cache.download("remote", kUrl);
    REQUIRE(refusal.shrink_rejection.has_value());
    CacheDownloadOptions options;
    auto& accepted = options.accept_shrink.emplace();
    accepted.previous_sha256 = refusal.shrink_rejection->previous_sha256;
    accepted.candidate_sha256 = refusal.shrink_rejection->candidate_sha256;

    const std::string changed = "other1.example\nother2.example\nother3.example\n";
    transport->enqueue(changed, "second-small");
    const auto result = cache.download("remote", kUrl, options);
    CHECK(result.failed());
    REQUIRE(result.shrink_rejection.has_value());
    CHECK(result.shrink_rejection->candidate_entries == 3);
    CHECK(result.shrink_rejection->candidate_sha256 == Sha256::hex(changed));
    CHECK(read_file(cache.cache_path("remote")) == host_list(200));
    CHECK(generation_files(temporary.path() / "cache", "remote").size() == 1);
}

TEST_CASE("accept shrink is compared with the currently cached body rather than an older approval") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue(host_list(3), "small");
    const auto refusal = cache.download("remote", kUrl);
    REQUIRE(refusal.shrink_rejection.has_value());
    CacheDownloadOptions options;
    auto& accepted = options.accept_shrink.emplace();
    accepted.previous_sha256 = refusal.shrink_rejection->previous_sha256;
    accepted.candidate_sha256 = refusal.shrink_rejection->candidate_sha256;

    const auto newer = host_list(220);
    transport->enqueue(newer, "newer");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue(host_list(3), "small");
    const auto result = cache.download("remote", kUrl, options);
    CHECK(result.failed());
    REQUIRE(result.shrink_rejection.has_value());
    CHECK(result.shrink_rejection->previous_entries == 220);
    CHECK(result.shrink_rejection->previous_sha256 == Sha256::hex(newer));
    CHECK(read_file(cache.cache_path("remote")) == newer);
}

TEST_CASE("custom source shrink policy affects this download without changing the defaults") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());

    CacheDownloadOptions lenient;
    lenient.shrink_policy.min_retained_fraction = 0.2;
    transport->enqueue(host_list(60), "small");
    REQUIRE(cache.download("remote", kUrl, lenient).updated());
    transport->enqueue(host_list(10), "smaller");
    const auto result = cache.download("remote", kUrl);
    CHECK(result.failed());
    REQUIRE(result.shrink_rejection.has_value());
    CHECK(result.shrink_rejection->min_retained_fraction == doctest::Approx(0.5));

    CacheDownloadOptions strict;
    strict.shrink_policy.min_previous_entries = 2;
    strict.shrink_policy.min_retained_fraction = 0.9;
    transport->enqueue(host_list(3), "tiny");
    REQUIRE(cache.download("tiny", kUrl).updated());
    transport->enqueue(host_list(1), "tinier");
    const auto tiny = cache.download("tiny", kUrl, strict);
    REQUIRE(tiny.shrink_rejection.has_value());
    CHECK(tiny.shrink_rejection->min_previous_entries == 2);
    CHECK(tiny.shrink_rejection->min_retained_fraction == doctest::Approx(0.9));
}

TEST_CASE("a now ordinary download clears an old shrink rejection even with an obsolete approval") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue(host_list(3), "small");
    const auto refusal = cache.download("remote", kUrl);
    REQUIRE(refusal.shrink_rejection.has_value());
    CacheDownloadOptions options;
    auto& accepted = options.accept_shrink.emplace();
    accepted.previous_sha256 = refusal.shrink_rejection->previous_sha256;
    accepted.candidate_sha256 = refusal.shrink_rejection->candidate_sha256;
    transport->enqueue(host_list(190), "recovered");
    CHECK(cache.download("remote", kUrl, options).updated());
    CHECK_FALSE(cache.load_metadata("remote").last_refresh_shrink_rejection.has_value());
}

TEST_CASE("ordinary failure or not-modified clears the obsolete typed shrink rejection") {
    for (const bool not_modified : {false, true}) {
        TemporaryDirectory temporary;
        auto transport = std::make_shared<SequenceHttpTransport>();
        CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
        cache.ensure_dir();
        transport->enqueue(host_list(200), "full");
        REQUIRE(cache.download("remote", kUrl).updated());
        transport->enqueue(host_list(3), "small");
        REQUIRE(cache.download("remote", kUrl).failed());
        REQUIRE(cache.load_metadata("remote").last_refresh_shrink_rejection.has_value());
        transport->enqueue("", "", not_modified ? 304 : 503);
        const auto result = cache.download("remote", kUrl);
        CHECK(result.not_modified() == not_modified);
        CHECK(result.failed() != not_modified);
        CHECK_FALSE(result.shrink_rejection.has_value());
        const auto metadata = cache.load_metadata("remote");
        CHECK_FALSE(metadata.last_refresh_shrink_rejection.has_value());
        CHECK(metadata.last_refresh_error.has_value() != not_modified);
        CHECK(read_file(cache.cache_path("remote")) == host_list(200));
    }
}

TEST_CASE("not-modified cache metadata uses the guarded commit callback") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue("stable.example\n", "stable");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto before = cache.load_metadata("remote");
    REQUIRE(before.current.has_value());

    std::size_t commits = 0U;
    CacheDownloadOptions options;
    options.detour = "current-detour";
    options.commit = [&](const std::function<void()>& commit) {
        ++commits;
        commit();
    };
    transport->enqueue("", "", 304);
    const auto result = cache.download("remote", kUrl, options);

    CHECK(result.not_modified());
    CHECK(commits == 1U);
    CHECK(result.warning_message.empty());
    const auto after = cache.load_metadata("remote");
    REQUIRE(after.current.has_value());
    CHECK(after.current->filename == before.current->filename);
    CHECK(after.last_refresh_detour == options.detour);
    CHECK(read_file(cache.cache_path("remote")) == "stable.example\n");
}

TEST_CASE("not-modified refresh cancelled at guarded commit leaves metadata unchanged") {
    for (const bool callback_throws : {false, true}) {
        TemporaryDirectory temporary;
        auto transport = std::make_shared<SequenceHttpTransport>();
        CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
        cache.ensure_dir();
        transport->enqueue("stable.example\n", "stable");
        REQUIRE(cache.download("remote", kUrl).updated());
        const auto before = read_file(cache.meta_path("remote"));
        auto cancellation = std::make_shared<std::atomic<bool>>(false);
        std::size_t commits = 0U;
        CacheDownloadOptions options;
        options.cancellation = cancellation;
        options.detour = "must-not-be-published";
        options.commit = [&](const std::function<void()>& commit) {
            ++commits;
            cancellation->store(true, std::memory_order_release);
            if (callback_throws) {
                throw HttpRequestCancelled("foreground operation preempted refresh");
            }
            commit();
        };
        transport->enqueue("", "", 304);
        const auto result = cache.download("remote", kUrl, options);

        CHECK(commits == 1U);
        CHECK(result.cancelled());
        CHECK_FALSE(result.failed());
        CHECK_FALSE(result.not_modified());
        CHECK(result.warning_message.empty());
        CHECK(read_file(cache.meta_path("remote")) == before);
        CHECK(read_file(cache.cache_path("remote")) == "stable.example\n");
        CHECK(generation_files(temporary.path(), "remote").size() == 1U);
    }
}

TEST_CASE("forced refresh cannot report not-modified without sending a validator") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    CacheDownloadOptions options;
    options.force_refresh = true;
    transport->enqueue("", "", 304);
    const auto result = cache.download("remote", kUrl, options);
    CHECK(result.failed());
    CHECK_FALSE(result.not_modified());
    CHECK(result.http_status_code == 304);
    CHECK_FALSE(result.shrink_rejection.has_value());
    CHECK(read_file(cache.cache_path("remote")) == host_list(200));
}

TEST_CASE("missing cached body leaves no shrink baseline even when old metadata has counts") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "full");
    REQUIRE(cache.download("remote", kUrl).updated());
    REQUIRE(std::filesystem::remove(cache.cache_path("remote")));
    transport->enqueue(host_list(3), "replacement");
    const auto result = cache.download("remote", kUrl);
    CHECK(result.updated());
    CHECK_FALSE(result.shrink_rejection.has_value());
    CHECK(read_file(cache.cache_path("remote")) == host_list(3));
    CHECK_FALSE(has_request_header(transport->requests.back(), "If-None-Match: full"));
}

TEST_CASE("shrink rejection counts the recovered previous body rather than missing current metadata") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path() / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    transport->enqueue(host_list(200), "first");
    REQUIRE(cache.download("remote", kUrl).updated());
    transport->enqueue(host_list(180), "current");
    REQUIRE(cache.download("remote", kUrl).updated());
    REQUIRE(std::filesystem::remove(cache.cache_path("remote")));
    REQUIRE(read_file(cache.cache_path("remote")) == host_list(200));
    transport->enqueue(host_list(95), "candidate");
    const auto result = cache.download("remote", kUrl);
    REQUIRE(result.shrink_rejection.has_value());
    CHECK(result.failed());
    CHECK(result.shrink_rejection->previous_entries == 200);
    CHECK(result.shrink_rejection->previous_sha256 == Sha256::hex(host_list(200)));
    CHECK(result.shrink_rejection->candidate_entries == 95);
    CHECK(read_file(cache.cache_path("remote")) == host_list(200));
}

TEST_CASE("structured cache downloads publish only unique normalized plaintext") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    std::string format = "json-array";
    std::string body = R"(["example.com","example.com","192.0.2.1","2001:db8::1"])";
    SUBCASE("JSON string array") {}
    SUBCASE("YAML payload sequence") {
        format = "yaml-payload";
        body = "payload:\n  - example.com\n  - 'example.com'\n"
               "  - 192.0.2.1\n  - \"2001:db8::1\"\n";
    }
    transport->enqueue(body, "structured");
    REQUIRE(cache.download("remote", kUrl, {}, format).updated());
    const auto metadata = cache.load_metadata("remote");
    CHECK(read_file(cache.cache_path("remote")) == "example.com\n192.0.2.1\n2001:db8::1\n");
    CHECK(metadata.source_format == format);
    CHECK(metadata.source_decoder_revision == kListSourceDecoderRevision);
    CHECK(metadata.domains == 1);
    CHECK(metadata.ips == 2);
    CHECK(metadata.cidrs == 0);
    REQUIRE(metadata.current.has_value());
    CHECK(metadata.current->sha256 == Sha256::hex("example.com\n192.0.2.1\n2001:db8::1\n"));
    CHECK(cache.has_current_cache("remote", kUrl, format));
    CHECK_FALSE(cache.has_current_cache("remote", kUrl));
    const auto pinned = cache.capture_generation({"remote"});
    REQUIRE(pinned->find("remote") != nullptr);
    CHECK(pinned->find("remote")->matches_source(kUrl, format));
    CHECK(pinned->find("remote")->source_format() == format);
    CHECK(pinned->find("remote")->source_decoder_revision() == kListSourceDecoderRevision);
    CHECK_FALSE(pinned->find("remote")->matches_source(kUrl));

    transport->enqueue("", "structured", 304);
    CHECK(cache.download("remote", kUrl, {}, format).not_modified());
    CHECK(has_request_header(transport->requests.back(), "If-None-Match: structured"));
}

TEST_CASE("structured HTTP downloads cap input and reset the next text request limit") {
    for (const auto configured_limit :
         {kListSourceMaxBytes / 2U, kListSourceMaxBytes * 4U}) {
        for (const std::string format : {"json-array", "yaml-payload"}) {
            CAPTURE(configured_limit);
            CAPTURE(format);
            TemporaryDirectory temporary;
            auto transport = std::make_shared<SequenceHttpTransport>();
            CacheManager cache(temporary.path(), configured_limit, transport);
            const auto expected_limit =
                std::min(configured_limit, kListSourceMaxBytes);
            transport->enqueue(format == "json-array"
                ? R"(["structured.example"])"
                : "payload:\n  - structured.example\n");
            REQUIRE(cache.download("remote", kUrl, {}, format).updated());
            REQUIRE(transport->requests.size() == 1U);
            CHECK(transport->requests.back().max_response_size == expected_limit);

            transport->enqueue("text.example\n");
            REQUIRE(cache.download("remote", kUrl).updated());
            REQUIRE(transport->requests.size() == 2U);
            CHECK(transport->requests.back().max_response_size == configured_limit);

            transport->enqueue("not a structured list");
            CHECK(cache.download("remote", kUrl, {}, format).failed());
            REQUIRE(transport->requests.size() == 3U);
            CHECK(transport->requests.back().max_response_size == expected_limit);
            CHECK(read_file(cache.cache_path("remote")) == "text.example\n");

            transport->enqueue("next-text.example\n");
            REQUIRE(cache.download("remote", kUrl).updated());
            REQUIRE(transport->requests.size() == 4U);
            CHECK(transport->requests.back().max_response_size == configured_limit);
        }
    }
}

TEST_CASE("explicit structured format overrides SRS URL suffix without changing legacy SRS handling") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    const std::string url = "https://example.test/source.srs";
    transport->enqueue(R"(["json.example"])");
    REQUIRE(cache.download("remote", url, {}, "json-array").updated());
    CHECK(read_file(cache.cache_path("remote")) == "json.example\n");
    CHECK_FALSE(cache.load_metadata("remote").srs_decoder_revision.has_value());
    CHECK(cache.has_current_cache("remote", url, "json-array"));
    CHECK_FALSE(cache.has_current_cache("remote", url));
}

TEST_CASE("same URL format changes invalidate validators fallback and pinned source identity") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    transport->enqueue("same.example\n", "text-etag");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto text_snapshot = cache.capture_generation({"remote"});
    const auto text_fingerprints = text_snapshot->fingerprints();
    const auto* text_handle = text_snapshot->find("remote");
    REQUIRE(text_handle != nullptr);
    CHECK(text_handle->matches_source(kUrl));
    CHECK_FALSE(text_handle->matches_source(kUrl, "json-array"));
    CHECK_FALSE(cache.has_usable_same_source_cache("remote", kUrl, "json-array"));

    transport->enqueue(R"(["same.example"])", "json-etag");
    REQUIRE(cache.download("remote", kUrl, {}, "json-array").updated());
    CHECK_FALSE(has_request_header(transport->requests.back(), "If-None-Match: text-etag"));
    CHECK_FALSE(cache.load_metadata("remote").previous.has_value());
    CHECK_FALSE(cache.has_usable_same_source_cache("remote", kUrl));
    const auto json_snapshot = cache.capture_generation({"remote"});
    const auto* json_handle = json_snapshot->find("remote");
    REQUIRE(json_handle != nullptr);
    CHECK(json_handle->generation().sha256 == text_handle->generation().sha256);
    CHECK(json_snapshot->fingerprints() != text_fingerprints);
    CHECK(text_snapshot->fingerprints() == text_fingerprints);
    CHECK(read_file(text_handle->path()) == "same.example\n");
    CHECK(text_handle->matches_source(kUrl));
    CHECK_FALSE(json_handle->matches_source(kUrl, "yaml-payload"));

    transport->enqueue("payload:\n  - same.example\n", "yaml-etag");
    REQUIRE(cache.download("remote", kUrl, {}, "yaml-payload").updated());
    CHECK_FALSE(has_request_header(transport->requests.back(), "If-None-Match: json-etag"));
    CHECK_FALSE(cache.load_metadata("remote").previous.has_value());
    CHECK(cache.capture_generation({"remote"})->fingerprints() != json_snapshot->fingerprints());
    CHECK(json_handle->matches_source(kUrl, "json-array"));
}

TEST_CASE("stale structured decoder revision cannot validate or masquerade as a fallback") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    transport->enqueue(R"(["same.example"])", "old-decoder");
    REQUIRE(cache.download("remote", kUrl, {}, "json-array").updated());
    const auto original = cache.capture_generation({"remote"});
    auto metadata = cache.load_metadata("remote");
    metadata.source_decoder_revision = kListSourceDecoderRevision - 1;
    cache.save_metadata("remote", metadata);
    CHECK_FALSE(cache.has_current_cache("remote", kUrl, "json-array"));
    CHECK_FALSE(cache.has_usable_same_source_cache("remote", kUrl, "json-array"));
    const auto stale = cache.capture_generation({"remote"});
    REQUIRE(stale->find("remote") != nullptr);
    CHECK_FALSE(stale->find("remote")->matches_source(kUrl, "json-array"));
    CHECK(stale->fingerprints() != original->fingerprints());
    REQUIRE(original->find("remote") != nullptr);
    CHECK(original->find("remote")->matches_source(kUrl, "json-array"));

    transport->enqueue("", "old-decoder", 304);
    CHECK(cache.download("remote", kUrl, {}, "json-array").failed());
    CHECK_FALSE(has_request_header(transport->requests.back(), "If-None-Match: old-decoder"));
    CHECK(cache.load_metadata("remote").source_decoder_revision == kListSourceDecoderRevision - 1);
    transport->enqueue(R"(["same.example"])", "new-decoder");
    REQUIRE(cache.download("remote", kUrl, {}, "json-array").updated());
    CHECK(cache.has_current_cache("remote", kUrl, "json-array"));
    CHECK_FALSE(cache.load_metadata("remote").previous.has_value());
    CHECK(cache.capture_generation({"remote"})->fingerprints() == original->fingerprints());
}

TEST_CASE("structured parse failure retains the previous generation and never publishes its valid prefix") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    std::string format = "json-array";
    std::string invalid = R"(["accepted-prefix.example", false])";
    SUBCASE("JSON non-string scalar") {}
    SUBCASE("JSON truncated document") { invalid = R"(["accepted-prefix.example",)"; }
    SUBCASE("JSON invalid list value") { invalid = R"(["accepted-prefix.example","not a domain"])"; }
    SUBCASE("YAML unsupported rule syntax") {
        format = "yaml-payload";
        invalid = "payload:\n  - accepted-prefix.example\n  - DOMAIN,example.com\n";
    }
    transport->enqueue(format == "json-array" ? R"(["old.example"])" :
                        "payload:\n  - old.example\n", "old-etag");
    REQUIRE(cache.download("remote", kUrl, {}, format).updated());
    const auto before = cache.load_metadata("remote");
    const auto before_generations = generation_files(temporary.path(), "remote");
    transport->enqueue(invalid, "failed-etag");
    const auto failure = cache.download("remote", kUrl, {}, format);
    CHECK(failure.failed());
    CHECK_FALSE(failure.retryable);
    CHECK_FALSE(failure.error_message.empty());
    CHECK_FALSE(failure.shrink_rejection.has_value());
    const auto after = cache.load_metadata("remote");
    REQUIRE(after.current.has_value());
    CHECK(after.current->filename == before.current->filename);
    CHECK(after.etag == before.etag);
    CHECK(after.download_time == before.download_time);
    CHECK(after.source_format == before.source_format);
    CHECK(after.source_decoder_revision == before.source_decoder_revision);
    CHECK(after.last_refresh_error.has_value());
    CHECK(read_file(cache.cache_path("remote")) == "old.example\n");
    CHECK(generation_files(temporary.path(), "remote") == before_generations);
}

TEST_CASE("structured shrink protection compares normalized entries and normalized body hashes") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    auto full = nlohmann::json::array();
    for (int index = 0; index < 100; ++index) {
        full.push_back("host-" + std::to_string(index) + ".example");
        full.push_back("host-" + std::to_string(index) + ".example");
    }
    transport->enqueue(full.dump(), "full");
    REQUIRE(cache.download("remote", kUrl, {}, "json-array").updated());
    CHECK(cache.load_metadata("remote").domains == 100);
    const auto previous = cache.load_metadata("remote");
    transport->enqueue(R"(["host-0.example","host-1.example"])", "small");
    const auto refusal = cache.download("remote", kUrl, {}, "json-array");
    REQUIRE(refusal.shrink_rejection.has_value());
    CHECK(refusal.failed());
    CHECK(refusal.shrink_rejection->previous_entries == 100);
    CHECK(refusal.shrink_rejection->candidate_entries == 2);
    CHECK(refusal.shrink_rejection->candidate_sha256 == Sha256::hex("host-0.example\nhost-1.example\n"));
    CHECK(cache.load_metadata("remote").current->filename == previous.current->filename);

    CacheDownloadOptions accepted;
    accepted.accept_shrink.emplace();
    accepted.accept_shrink->previous_sha256 = refusal.shrink_rejection->previous_sha256;
    accepted.accept_shrink->candidate_sha256 = refusal.shrink_rejection->candidate_sha256;
    transport->enqueue("[\n  \"host-0.example\", \"host-1.example\"\n]\n", "same-small");
    CHECK(cache.download("remote", kUrl, accepted, "json-array").updated());
    CHECK(cache.load_metadata("remote").domains == 2);
    CHECK(read_file(cache.cache_path("remote")) == "host-0.example\nhost-1.example\n");
}

TEST_CASE("unknown explicit cache format fails without downloading or losing an existing source") {
    TemporaryDirectory temporary;
    auto transport = std::make_shared<SequenceHttpTransport>();
    CacheManager cache(temporary.path(), kDefaultMaxFileSizeBytes, transport);
    transport->enqueue("old.example\n", "old");
    REQUIRE(cache.download("remote", kUrl).updated());
    const auto calls = transport->requests.size();
    const auto result = cache.download("remote", kUrl, {}, "auto");
    CHECK(result.failed());
    CHECK_FALSE(result.retryable);
    CHECK(transport->requests.size() == calls);
    CHECK(read_file(cache.cache_path("remote")) == "old.example\n");
    CHECK(cache.has_current_cache("remote", kUrl));
    CHECK_FALSE(cache.has_current_cache("remote", kUrl, "auto"));
}
