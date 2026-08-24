#include <doctest/doctest.h>

#include "../src/lists/list_streamer.hpp"

#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {
namespace {

class ListTempDirectory {
public:
    ListTempDirectory() {
        char pattern[] = "/tmp/keen-pbr-list-streamer-XXXXXX";
        const char* value = ::mkdtemp(pattern);
        if (!value) throw std::runtime_error("mkdtemp failed");
        path_ = value;
    }

    ~ListTempDirectory() { std::filesystem::remove_all(path_); }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

class CountingListVisitor : public ListEntryVisitor {
public:
    void on_entry(EntryType, std::string_view) override { ++count; }
    std::size_t count{0};
};

class CollectingListVisitor : public ListEntryVisitor {
public:
    void on_entry(EntryType, std::string_view entry) override {
        entries.emplace_back(entry);
    }

    std::vector<std::string> entries;
};

class ListSequenceHttpTransport final : public HttpTransport {
public:
    void enqueue(std::string body) {
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = std::move(body);
        responses_.push_back(std::move(response));
    }

    HttpTransportResponse perform(const HttpTransportRequest&) override {
        if (responses_.empty()) {
            throw std::runtime_error("no queued HTTP response");
        }
        auto response = std::move(responses_.front());
        responses_.pop_front();
        return response;
    }

private:
    std::deque<HttpTransportResponse> responses_;
};

void stream_local_list(const std::filesystem::path& path,
                       std::size_t max_size) {
    CacheManager cache(path.parent_path() / "cache", max_size);
    ListStreamer streamer(cache);
    ListConfig config;
    config.file = path.string();
    CountingListVisitor visitor;
    streamer.stream_list("local", config, visitor);
}

} // namespace

TEST_CASE("ListStreamer reads bounded regular local files") {
    ListTempDirectory temp;
    const auto path = temp.path() / "list.txt";
    {
        std::ofstream out(path);
        out << "example.com\n192.0.2.0/24\n";
    }

    CacheManager cache(temp.path() / "cache", 1024);
    ListStreamer streamer(cache);
    ListConfig config;
    config.file = path.string();
    CountingListVisitor visitor;
    streamer.stream_list("local", config, visitor);
    CHECK(visitor.count == 2);
}

TEST_CASE("ListStreamer rejects symlinks and non-regular files") {
    ListTempDirectory temp;
    const auto regular = temp.path() / "regular.txt";
    const auto symlink = temp.path() / "symlink.txt";
    const auto fifo = temp.path() / "fifo";
    {
        std::ofstream out(regular);
        out << "example.com\n";
    }
    std::filesystem::create_symlink(regular, symlink);
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);

    CHECK_THROWS(stream_local_list(symlink, 1024));
    CHECK_THROWS(stream_local_list(fifo, 1024));
    CHECK_THROWS(stream_local_list("/dev/zero", 1024));
}

TEST_CASE("ListStreamer rejects files and lines over configured bounds") {
    ListTempDirectory temp;
    const auto oversized = temp.path() / "oversized.txt";
    const auto long_line = temp.path() / "long-line.txt";
    {
        std::ofstream out(oversized);
        out << std::string(65, 'a');
    }
    {
        std::ofstream out(long_line);
        out << std::string(ListStreamer::kMaxLineBytes + 1, 'a');
    }

    CHECK_THROWS(stream_local_list(oversized, 64));
    CHECK_THROWS(stream_local_list(long_line, 8192));
}

TEST_CASE("ListStreamer snapshot remains on one cache generation") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 1024, transport);
    cache.ensure_dir();
    constexpr const char* url = "https://example.test/list.txt";

    transport->enqueue("old.example\n");
    REQUIRE(cache.download("remote", url).updated());
    const auto snapshot = cache.capture_generation({"remote"});
    REQUIRE(snapshot->find("remote") != nullptr);
    ListStreamer snapshot_streamer(cache, snapshot);

    transport->enqueue("new.example\n");
    REQUIRE(cache.download("remote", url).updated());
    transport->enqueue("newest.example\n");
    REQUIRE(cache.download("remote", url).updated());

    ListConfig config;
    config.url = url;
    CollectingListVisitor snapshot_visitor;
    snapshot_streamer.stream_list("remote", config, snapshot_visitor);
    REQUIRE(snapshot_visitor.entries.size() == 1U);
    CHECK(snapshot_visitor.entries.front() == "old.example");

    ListStreamer live_streamer(cache);
    CollectingListVisitor live_visitor;
    live_streamer.stream_list("remote", config, live_visitor);
    REQUIRE(live_visitor.entries.size() == 1U);
    CHECK(live_visitor.entries.front() == "newest.example");
}

TEST_CASE("ListStreamer pinned snapshot does not retain CacheManager") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    std::shared_ptr<const ListCacheGenerationSnapshot> snapshot;
    {
        CacheManager cache(temp.path() / "cache", 1024, transport);
        cache.ensure_dir();
        transport->enqueue("pinned.example\n");
        REQUIRE(cache.download(
                    "remote", "https://example.test/list.txt")
                    .updated());
        snapshot = cache.capture_generation({"remote"});
    }

    ListStreamer streamer(1024, snapshot);
    ListConfig config;
    config.url = "https://example.test/list.txt";
    CollectingListVisitor visitor;
    streamer.stream_list("remote", config, visitor);

    REQUIRE(visitor.entries.size() == 1U);
    CHECK(visitor.entries.front() == "pinned.example");
}

TEST_CASE("shared routing snapshot keeps multiple lists on one cache view") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 1024, transport);
    cache.ensure_dir();
    constexpr const char* first_url =
        "https://example.test/first.txt";
    constexpr const char* second_url =
        "https://example.test/second.txt";

    transport->enqueue("old-first.example\n");
    REQUIRE(cache.download("first", first_url).updated());
    transport->enqueue("old-second.example\n");
    REQUIRE(cache.download("second", second_url).updated());
    const auto snapshot =
        cache.capture_generation({"first", "second"});
    ListStreamer streamer(cache, snapshot);

    ListConfig first_config;
    first_config.url = first_url;
    CollectingListVisitor first_visitor;
    streamer.stream_list("first", first_config, first_visitor);

    // A refresh commits between list reads. Both reads must still use the
    // cache view captured for the whole routing diagnostic.
    transport->enqueue("new-second.example\n");
    REQUIRE(cache.download("second", second_url).updated());
    ListConfig second_config;
    second_config.url = second_url;
    CollectingListVisitor second_visitor;
    streamer.stream_list("second", second_config, second_visitor);

    REQUIRE(first_visitor.entries.size() == 1U);
    CHECK(first_visitor.entries.front() == "old-first.example");
    REQUIRE(second_visitor.entries.size() == 1U);
    CHECK(second_visitor.entries.front() == "old-second.example");
}

TEST_CASE("ListStreamer snapshot keeps an explicitly missing cache missing") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 1024, transport);
    cache.ensure_dir();
    constexpr const char* url = "https://example.test/list.txt";

    const auto snapshot = cache.capture_generation({"remote"});
    CHECK(snapshot->contains("remote"));
    CHECK(snapshot->find("remote") == nullptr);

    transport->enqueue("late.example\n");
    REQUIRE(cache.download("remote", url).updated());

    ListConfig config;
    config.url = url;
    ListStreamer snapshot_streamer(cache, snapshot);
    CollectingListVisitor snapshot_visitor;
    snapshot_streamer.stream_list("remote", config, snapshot_visitor);
    CHECK(snapshot_visitor.entries.empty());

    ListStreamer live_streamer(cache);
    CollectingListVisitor live_visitor;
    live_streamer.stream_list("remote", config, live_visitor);
    REQUIRE(live_visitor.entries.size() == 1U);
    CHECK(live_visitor.entries.front() == "late.example");
}

TEST_CASE("ListStreamer snapshot rejects a list name that was not captured") {
    ListTempDirectory temp;
    CacheManager cache(temp.path() / "cache", 1024);
    cache.ensure_dir();
    const auto snapshot = cache.capture_generation({"captured"});
    CHECK(snapshot->contains("captured"));
    CHECK_FALSE(snapshot->contains("uncaptured"));

    ListStreamer streamer(cache, snapshot);
    ListConfig config;
    CollectingListVisitor visitor;
    CHECK_THROWS_WITH_AS(
        streamer.stream_list("uncaptured", config, visitor),
        "cache snapshot does not contain list 'uncaptured'",
        std::invalid_argument);
}

} // namespace keen_pbr3
