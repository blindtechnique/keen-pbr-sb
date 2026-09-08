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
    void on_entry(EntryType type, std::string_view entry) override {
        types.push_back(type);
        entries.emplace_back(entry);
    }

    std::vector<EntryType> types;
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

TEST_CASE("ListStreamer canonical IP entries are identical in inline file and URL sources") {
    const std::vector<std::string> input_lines = {
        " 192.168.7.199/24 \r", "10.1.2.3/8", "172.16.9.8",
        "2001:0DB8:0000:0000:ABCD:0000:0000:1234/64",
        "2001:0DB8:0000:0000:0000:0000:0000:0001",
        "192.0.2.8/32", "2001:db8::2/128",
        "192.168.1.8/0", "2001:db8::2/0",
        "  # comment", "", " \t\r", "999.1.2.3", "2001:db8::/129",
    };
    const std::vector<std::string> expected_entries = {
        "192.168.7.0/24", "10.0.0.0/8", "172.16.9.8",
        "2001:db8::/64", "2001:db8::1", "192.0.2.8", "2001:db8::2",
        "0.0.0.0/0", "::/0",
    };
    const std::vector<EntryType> expected_types = {
        EntryType::Cidr, EntryType::Cidr, EntryType::Ip,
        EntryType::Cidr, EntryType::Ip, EntryType::Ip, EntryType::Ip,
        EntryType::Cidr, EntryType::Cidr,
    };
    std::string body;
    for (const auto& line : input_lines) body += line + "\n";

    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 4096, transport);
    ListConfig config;
    SUBCASE("inline values") {
        config.ip_cidrs = input_lines;
    }
    SUBCASE("local file with CRLF and malformed lines") {
        const auto path = temp.path() / "addresses.txt";
        std::ofstream output(path, std::ios::binary);
        REQUIRE(output.is_open());
        output << body;
        output.close();
        REQUIRE(output.good());
        config.file = path.string();
    }
    SUBCASE("URL cache with malformed lines") {
        cache.ensure_dir();
        constexpr const char* url = "https://example.test/addresses.txt";
        transport->enqueue(body);
        REQUIRE(cache.download("addresses", url).updated());
        config.url = url;
    }

    ListStreamer streamer(cache);
    CollectingListVisitor visitor;
    CHECK_NOTHROW(streamer.stream_list("addresses", config, visitor));
    CHECK(visitor.entries == expected_entries);
    CHECK(visitor.types == expected_types);
}

TEST_CASE("ListStreamer structured router files normalize complete input before visiting") {
    ListTempDirectory temp;
    const auto path = temp.path() / "list.json";
    CacheManager cache(temp.path() / "cache", 16384);
    ListStreamer streamer(cache);
    ListConfig config;
    config.file = path.string();
    config.source_format = "json-array";
    { std::ofstream out(path); out << R"(["Example.org","192.0.2.21/24","example.org"])"; }
    CollectingListVisitor visitor;
    streamer.stream_list("local", config, visitor);
    CHECK(visitor.entries == std::vector<std::string>{"example.org", "192.0.2.0/24"});
    { std::ofstream out(path); out << R"(["example.org","192.0.2.21/999"])"; }
    CollectingListVisitor invalid;
    CHECK_THROWS_AS(streamer.stream_list("local", config, invalid), std::runtime_error);
    CHECK(invalid.entries.empty());
    config.source_format = "yaml-payload";
    { std::ofstream out(path); out << "payload:\n  - '*.Example.NET'\n  - 2001:db8::2/64\n"; }
    CollectingListVisitor yaml;
    streamer.stream_list("local", config, yaml);
    CHECK(yaml.entries == std::vector<std::string>{"example.net", "2001:db8::/64"});
}

TEST_CASE("ListStreamer cached normalized structured content is not decoded twice") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    transport->enqueue(R"(["example.org"])");
    CacheManager cache(temp.path() / "cache", 16384, transport);
    REQUIRE(cache.download("remote", "https://example.org/list", {}, "json-array").updated());
    ListConfig config;
    config.url = "https://example.org/list";
    config.source_format = "json-array";
    ListStreamer streamer(cache);
    CollectingListVisitor visitor;
    streamer.stream_list("remote", config, visitor);
    CHECK(visitor.entries == std::vector<std::string>{"example.org"});
    config.source_format = "yaml-payload";
    CollectingListVisitor changed;
    streamer.stream_list("remote", config, changed);
    CHECK(changed.entries.empty());
}

TEST_CASE("ListStreamer remote normalization preserves duplicate occurrence counts") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 8192, transport);
    cache.ensure_dir();
    constexpr const char* url = "https://example.test/duplicates.txt";
    std::string original_body;
    std::string canonical_body;
    for (int index = 0; index < 32; ++index) {
        original_body += "192.0.2.127/24\n2001:0DB8:0000:0000::ABCD/64\n";
        canonical_body += "192.0.2.0/24\n2001:db8::/64\n";
    }

    // More than the existing shrink threshold: canonicalization alone must
    // not make an unchanged remote list look as though 62 entries vanished.
    transport->enqueue(original_body);
    REQUIRE(cache.download("duplicates", url).updated());
    ListConfig config;
    config.url = url;
    ListStreamer streamer(cache);
    CollectingListVisitor before;
    streamer.stream_list("duplicates", config, before);
    REQUIRE(before.entries.size() == 64U);
    for (std::size_t index = 0; index < before.entries.size(); index += 2U) {
        CHECK(before.entries[index] == "192.0.2.0/24");
        CHECK(before.entries[index + 1U] == "2001:db8::/64");
    }
    CHECK(cache.load_metadata("duplicates").cidrs.value_or(0) == 64);

    transport->enqueue(canonical_body);
    CHECK(cache.download("duplicates", url).updated());
    CollectingListVisitor after;
    streamer.stream_cache("duplicates", after);
    CHECK(after.entries == before.entries);
    CHECK(after.types == before.types);
    CHECK(cache.load_metadata("duplicates").cidrs.value_or(0) == 64);
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
    config.url = "https://example.test/uncaptured.txt";
    CollectingListVisitor visitor;
    CHECK_THROWS_WITH_AS(
        streamer.stream_list("uncaptured", config, visitor),
        "cache snapshot does not contain list 'uncaptured'",
        std::invalid_argument);
}

TEST_CASE("ListStreamer binds live and pinned cache bytes to the successful source URL") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 1024, transport);
    cache.ensure_dir();
    constexpr const char* old_url = "https://example.test/old.txt";
    constexpr const char* new_url = "https://example.test/new.txt";
    transport->enqueue("old.example\n");
    REQUIRE(cache.download("remote", old_url).updated());
    const auto old_snapshot = cache.capture_generation({"remote"});
    REQUIRE(old_snapshot->find("remote") != nullptr);
    CHECK(old_snapshot->find("remote")->source_url() == old_url);
    ListStreamer live(cache);
    ListStreamer pinned(cache, old_snapshot);
    const auto entries = [](ListStreamer& streamer, const char* url) {
        ListConfig config;
        config.url = url;
        config.domains = std::vector<std::string>{"inline.example"};
        CollectingListVisitor visitor;
        streamer.stream_list("remote", config, visitor);
        return visitor.entries;
    };

    cache.record_refresh_failure("remote", old_url, "provider unavailable");
    for (auto* streamer : {&live, &pinned}) {
        CHECK(entries(*streamer, old_url) ==
              std::vector<std::string>{"old.example", "inline.example"});
    }
    // A failed attempt against the replacement URL must not relabel the old
    // generation through last_refresh_url or through the shared list name.
    cache.record_refresh_failure("remote", new_url, "replacement unavailable");
    for (auto* streamer : {&live, &pinned}) {
        CHECK(entries(*streamer, new_url) ==
              std::vector<std::string>{"inline.example"});
    }

    transport->enqueue("new.example\n");
    REQUIRE(cache.download("remote", new_url).updated());
    CHECK(entries(live, new_url) ==
          std::vector<std::string>{"new.example", "inline.example"});
    CHECK(entries(live, old_url) == std::vector<std::string>{"inline.example"});
    CHECK(entries(pinned, old_url) ==
          std::vector<std::string>{"old.example", "inline.example"});
    CHECK(entries(pinned, new_url) == std::vector<std::string>{"inline.example"});
    CHECK(old_snapshot->find("remote")->source_url() == old_url);
}

TEST_CASE("ListStreamer URL removal keeps only the current local path and inline sources") {
    ListTempDirectory temp;
    auto transport = std::make_shared<ListSequenceHttpTransport>();
    CacheManager cache(temp.path() / "cache", 1024, transport);
    cache.ensure_dir();
    transport->enqueue("orphan.example\n");
    REQUIRE(cache.download("remote", "https://example.test/list.txt").updated());
    const auto snapshot = cache.capture_generation({"remote"});
    ListStreamer live(cache);
    ListStreamer pinned(cache, snapshot);
    const auto first_path = temp.path() / "first.txt";
    const auto next_path = temp.path() / "next.txt";
    { std::ofstream file(first_path); file << "first.example\n"; }
    { std::ofstream file(next_path); file << "next.example\n"; }
    for (const auto& path : {first_path, next_path}) {
        ListConfig config;
        config.file = path.string();
        config.domains = std::vector<std::string>{"inline.example"};
        for (auto* streamer : {&live, &pinned}) {
            CollectingListVisitor visitor;
            streamer->stream_list("remote", config, visitor);
            CHECK(visitor.entries == std::vector<std::string>{
                path == first_path ? "first.example" : "next.example", "inline.example"});
        }
    }
    CHECK(cache.has_cache("remote"));
    REQUIRE(snapshot->find("remote") != nullptr);
    CHECK(std::filesystem::exists(snapshot->find("remote")->path()));
}

TEST_CASE("ListStreamer local-only sources do not need a captured cache name") {
    ListTempDirectory temp;
    CacheManager cache(temp.path() / "cache", 1024);
    ListStreamer streamer(cache, cache.capture_generation({}));
    ListConfig config;
    config.domains = std::vector<std::string>{"inline.example"};
    CollectingListVisitor visitor;
    CHECK_NOTHROW(streamer.stream_list("local", config, visitor));
    CHECK(visitor.entries == std::vector<std::string>{"inline.example"});
}

TEST_CASE("ListStreamer retains legacy cache only with matching source metadata") {
    ListTempDirectory temp;
    CacheManager cache(temp.path() / "cache", 1024);
    cache.ensure_dir();
    { std::ofstream file(cache.cache_path("legacy")); file << "legacy.example\n"; }
    constexpr const char* url = "https://example.test/list.txt";
    ListConfig config;
    config.url = url;
    ListStreamer live(cache);
    ListStreamer unknown_pinned(cache, cache.capture_generation({"legacy"}));
    CollectingListVisitor unknown;
    live.stream_list("legacy", config, unknown);
    CHECK(unknown.entries.empty());

    CacheMetadata metadata;
    metadata.url = url;
    cache.save_metadata("legacy", metadata);
    ListStreamer known_pinned(cache, cache.capture_generation({"legacy"}));
    for (auto* streamer : {&live, &known_pinned}) {
        CollectingListVisitor visitor;
        streamer->stream_list("legacy", config, visitor);
        CHECK(visitor.entries == std::vector<std::string>{"legacy.example"});
    }
    CollectingListVisitor still_unknown;
    unknown_pinned.stream_list("legacy", config, still_unknown);
    CHECK(still_unknown.entries.empty());
}

} // namespace keen_pbr3
