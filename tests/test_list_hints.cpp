#ifdef WITH_API
#include <doctest/doctest.h>
#include "../src/api/handler_list_hints.hpp"
#include "../src/lists/list_hints.hpp"
#include "../src/cache/cache_manager.hpp"
#include "../src/api/step_up.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <random>
#include <set>
#include <sys/resource.h>
#include <sys/stat.h>

namespace keen_pbr3 {
namespace {
Config hint_config() {
    Config config{};
    config.lists.emplace();
    config.route.emplace();
    config.route->rules.emplace();
    return config;
}
void domain_list(Config& config, const std::string& id, std::vector<std::string> domains) {
    (*config.lists)[id].domains = std::move(domains);
}
RouteRule& hint_rule(Config& config, std::vector<std::string> lists, std::string outbound) {
    RouteRule rule{};
    rule.list = std::move(lists);
    rule.outbound = std::move(outbound);
    config.route->rules->push_back(std::move(rule));
    return config.route->rules->back();
}
std::vector<api::ListHint> hints(const api::ListHintsResponse& report, const std::string& code) {
    std::vector<api::ListHint> found;
    for (const auto& hint : report.items) if (hint.code == code) found.push_back(hint);
    return found;
}
struct HintFiles {
    std::filesystem::path path;
    HintFiles() {
        char pattern[] = "/tmp/keen-pbr-list-hints-XXXXXX";
        auto* created = ::mkdtemp(pattern);
        if (!created) throw std::runtime_error("mkdtemp failed");
        path = created;
    }
    ~HintFiles() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    std::string write(const std::string& name, const std::string& text) const {
        const auto file = path / name;
        std::ofstream(file) << text;
        return file.string();
    }
};
class HintTransport : public HttpTransport {
public:
    int calls{0};
    HttpTransportResponse perform(const HttpTransportRequest&) override {
        ++calls;
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = "child.example.test\n";
        return response;
    }
};
} // namespace

TEST_CASE("list hints retain DNS disabled rule and automation usage") {
    auto config = hint_config();
    for (const auto* id : {"route", "disabled", "dns", "reconnect", "probe", "unused"}) {
        domain_list(config, id, {std::string(id) + ".example"});
    }
    hint_rule(config, {"route"}, "vpn");
    hint_rule(config, {"disabled"}, "vpn").enabled = false;
    config.dns.emplace();
    DnsRule dns{};
    dns.list = {"dns"};
    dns.server = "resolver";
    dns.enabled = false;
    config.dns->rules = {dns};
    config.daemon.emplace();
    config.daemon->reconnect_owned_flows_on_routing_change_lists = {"reconnect"};
    config.tunnel_probe.emplace();
    config.tunnel_probe->enabled = false;
    config.tunnel_probe->list = "probe";
    const auto before = nlohmann::json(config).dump();
    const auto report = build_list_hints(config);
    const auto unused = hints(report, "unused");
    REQUIRE(unused.size() == 1);
    CHECK(unused.front().list == "unused");
    CHECK(nlohmann::json(config).dump() == before);
    CHECK_FALSE(report.scan_limited);
}

TEST_CASE("list hints canonicalize wide networks without treating hosts as broad") {
    auto config = hint_config();
    (*config.lists)["net"].ip_cidrs = {"10.23.1.8/8", "10.0.0.0/8", "192.0.2.0/24",
        "0.0.0.0/0", "2001:db8:abcd::/32", "2001:db8::/64", "203.0.113.5/32", "::1/128",
        "198.51.100.9/16", "198.51.100.9/17", "::/0"};
    const auto broad = hints(build_list_hints(config), "wide_cidr");
    REQUIRE(broad.size() == 5);
    CHECK(broad[0].entry == "10.0.0.0/8");
    CHECK(broad[1].entry == "0.0.0.0/0");
    CHECK(broad[2].entry == "2001:db8::/32");
    CHECK(broad[3].entry == "198.51.0.0/16");
    CHECK(broad[4].entry == "::/0");
}

TEST_CASE("list hints compare domain boundaries and keep actual rule order") {
    auto config = hint_config();
    domain_list(config, "a-child", {"*.API.Example.Test.", "notexample.test"});
    domain_list(config, "z-parent", {"example.test"});
    hint_rule(config, {"z-parent"}, "wan");
    hint_rule(config, {"a-child"}, "vpn");
    const auto overlap = hints(build_list_hints(config), "domain_overlap");
    REQUIRE(overlap.size() == 1);
    CHECK(overlap.front().list == "z-parent");
    CHECK(overlap.front().entry == "example.test");
    CHECK(overlap.front().other_entry == "api.example.test");
    CHECK(overlap.front().rule_index == 0);
    CHECK(overlap.front().other_rule_index == 1);
    CHECK(overlap.front().outbound == "wan");
    config.route->rules->front().outbound = "vpn";
    CHECK(hints(build_list_hints(config), "domain_overlap").empty());
    config.route->rules->front().outbound = "wan";
    config.route->rules->front().enabled = false;
    CHECK(hints(build_list_hints(config), "domain_overlap").empty());
    config.route->rules->front().enabled = true;
    (*config.lists)["a-child"].domains = {"notexample.test"};
    CHECK(hints(build_list_hints(config), "domain_overlap").empty());
}

TEST_CASE("list hints do not label distinct match conditions as conflicts") {
    auto config = hint_config();
    domain_list(config, "a", {"example.test"});
    domain_list(config, "b", {"example.test"});
    hint_rule(config, {"a"}, "one");
    hint_rule(config, {"b"}, "two");
    for (const auto* field : {"proto", "dscp", "src_port", "dest_port", "src_addr", "dest_addr"}) {
        auto document = nlohmann::json(config);
        document["route"]["rules"][0][field] = std::string(field) == "dscp"
            ? nlohmann::json(5) : nlohmann::json("different");
        auto changed = document.get<Config>();
        const auto report = build_list_hints(changed);
        CHECK(report.conditional_rules == 1);
        CHECK(hints(report, "domain_overlap").empty());
        document["route"]["rules"][1][field] = document["route"]["rules"][0][field];
        CHECK(hints(build_list_hints(document.get<Config>()), "domain_overlap").size() == 1);
    }
}

TEST_CASE("list hints compact repeated list owners to earliest different outbounds") {
    auto config = hint_config();
    domain_list(config, "z", {"example.test"});
    domain_list(config, "a", {"example.test"});
    hint_rule(config, {"z"}, "first");
    hint_rule(config, {"a"}, "first");
    hint_rule(config, {"a"}, "second");
    hint_rule(config, {"z"}, "third");
    const auto overlap = hints(build_list_hints(config), "domain_overlap");
    REQUIRE(overlap.size() == 1);
    CHECK(overlap.front().rule_index == 0);
    CHECK(overlap.front().other_rule_index == 2);
}

TEST_CASE("list hints use local text JSON and YAML sources without publishing them") {
    HintFiles files;
    auto config = hint_config();
    for (const auto& format : {"text", "json-array", "yaml-payload"}) {
        const std::string body = std::string(format) == "text" ? " # comment\n example.test\n"
            : std::string(format) == "json-array" ? "[\"example.test\"]"
            : "payload:\n  - example.test\n";
        (*config.lists)[format].file = files.write(format, body);
        (*config.lists)[format].source_format = format;
        hint_rule(config, {format}, format);
    }
    auto report = build_list_hints(config);
    CHECK_FALSE(hints(report, "domain_overlap").empty());
    CHECK(report.source_issues.empty());
    (*config.lists)["bad"].file = files.write("bad", "[\"example.test\", 42]");
    (*config.lists)["bad"].source_format = "json-array";
    hint_rule(config, {"bad"}, "bad");
    (*config.lists)["invalid-text"].file = files.write("invalid-text", "not a domain\n");
    config.route->rules->clear();
    hint_rule(config, {"bad"}, "bad");
    hint_rule(config, {"json-array"}, "good");
    report = build_list_hints(config);
    REQUIRE(report.source_issues.size() == 2);
    CHECK(report.source_issues[0].reason == "invalid_source");
    CHECK(report.source_issues[1].reason == "invalid_source");
    CHECK(hints(report, "domain_overlap").empty());
}

TEST_CASE("list hints skip missing oversized and nonregular local sources") {
    HintFiles files;
    auto config = hint_config();
    (*config.lists)["missing"].file = (files.path / "missing").string();
    (*config.lists)["large"].file = files.write("large", std::string(100, 'x'));
    const auto fifo = files.path / "fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    (*config.lists)["fifo"].file = fifo.string();
    const auto link = files.path / "link";
    std::filesystem::create_symlink(*(*config.lists)["large"].file, link);
    (*config.lists)["link"].file = link.string();
    ListHintsLimits limits;
    limits.file_bytes = 40;
    const auto report = build_list_hints(config, nullptr, limits);
    REQUIRE(report.source_issues.size() == 4);
    CHECK(report.source_issues[1].reason == "size_limit");
    CHECK(nlohmann::json(report).dump().find(files.path.string()) == std::string::npos);
}

TEST_CASE("list hints inspect a pinned matching URL cache without HTTP or cache writes") {
    HintFiles files;
    auto transport = std::make_shared<HintTransport>();
    CacheManager cache(files.path / "cache", kDefaultMaxFileSizeBytes, transport);
    cache.ensure_dir();
    const std::string url = "https://source.example/private-token";
    REQUIRE(cache.download("remote", url).updated());
    const auto metadata_before = nlohmann::json(cache.load_metadata("remote")).dump();
    auto config = hint_config();
    (*config.lists)["remote"].url = url;
    domain_list(config, "local", {"example.test"});
    hint_rule(config, {"local"}, "one");
    hint_rule(config, {"remote"}, "two");
    auto report = build_list_hints(config, &cache);
    CHECK(hints(report, "domain_overlap").size() == 1);
    CHECK(report.source_issues.empty());
    CHECK(transport->calls == 1);
    CHECK(nlohmann::json(cache.load_metadata("remote")).dump() == metadata_before);
    (*config.lists)["remote"].url = "https://new.example/private";
    report = build_list_hints(config, &cache);
    CHECK(hints(report, "domain_overlap").empty());
    REQUIRE(report.source_issues.size() == 1);
    CHECK(report.source_issues.front().reason == "source_changed");
    CHECK(nlohmann::json(report).dump().find("private") == std::string::npos);
    (*config.lists)["remote"].url = url;
    (*config.lists)["remote"].source_format = "json-array";
    CHECK(build_list_hints(config, &cache).source_issues.front().reason == "source_changed");
    CHECK(build_list_hints(config).source_issues.front().reason == "unavailable");
    CHECK(transport->calls == 1);
}

TEST_CASE("list hints budgets disclose partial scans and bound all categories") {
    auto config = hint_config();
    domain_list(config, "a", {"example.test", "child.example.test", "third.test"});
    hint_rule(config, {"a"}, "one");
    hint_rule(config, {"a"}, "two");
    ListHintsLimits limits;
    SUBCASE("entries") { limits.entries = 1; }
    SUBCASE("owner work") { limits.index_owners = 1; }
    SUBCASE("bytes") { limits.input_bytes = 3; }
    SUBCASE("deadline") { limits.elapsed = std::chrono::milliseconds{0}; }
    CHECK(build_list_hints(config, nullptr, limits).scan_limited);
    for (int i = 0; i < 120; ++i) {
        const auto id = "unused" + std::to_string(i);
        (*config.lists)[id].ip_cidrs = {"10.0.0.0/8"};
        (*config.lists)[id].url = "https://example.test/list";
    }
    const auto report = build_list_hints(config);
    CHECK(report.hints_limited);
    CHECK(report.items.size() == 100);
    CHECK_FALSE(hints(report, "unused").empty());
    CHECK_FALSE(hints(report, "wide_cidr").empty());
    CHECK_FALSE(hints(report, "domain_overlap").empty());
    CHECK(report.source_issues.size() == 100);
    CHECK(report.source_issues_limited);
}

TEST_CASE("list hints use one visible snapshot and never enter a mutation") {
    SseBroadcaster broadcaster;
    ApiContext ctx{"/unused/list-hints", broadcaster};
    auto config = hint_config();
    domain_list(config, "a", {"example.test"});
    int reads = 0;
    ctx.get_visible_config_snapshot_fn = [&]() {
        ++reads;
        return VisibleConfigSnapshot{config, true, "draft-revision"};
    };
    ctx.begin_save_operation_fn = []() { throw std::runtime_error("not a save"); };
    ctx.stage_config_fn = [](Config, std::string) { throw std::runtime_error("not a draft edit"); };
    ctx.get_visible_config_fn = []() -> Config { throw std::runtime_error("not a separate read"); };
    const auto report = query_list_hints(ctx);
    CHECK(reads == 1);
    CHECK(report.revision == "draft-revision");
    CHECK(report.is_draft);
}

TEST_CASE("list hints API serializes only the optional report and releases on failure") {
    SseBroadcaster broadcaster;
    ApiContext ctx{"/unused/list-hints", broadcaster};
    auto config = hint_config();
    ctx.get_visible_config_snapshot_fn = [&]() {
        return VisibleConfigSnapshot{config, false, "revision"};
    };
    std::promise<void> started, release;
    const auto released = release.get_future().share();
    auto entered = started.get_future();
    ctx.get_list_hints_fn = [&](const Config& value) {
        started.set_value();
        released.wait_for(std::chrono::seconds{5});
        return build_list_hints(value);
    };
    auto handler = make_list_hints_handler(ctx);
    auto first = std::async(std::launch::async, [&]() { return handler(""); });
    const auto status = entered.wait_for(std::chrono::seconds{2});
    CHECK(status == std::future_status::ready);
    if (status == std::future_status::ready) {
        try {
            handler("");
            FAIL_CHECK("a second optional analysis must not allocate another index");
        } catch (const ApiError& error) {
            CHECK(error.status() == 503);
        }
        // The report worker does not hold a configuration or runtime lock.
        CHECK(ctx.get_visible_config_state().revision == "revision");
    }
    release.set_value();
    CHECK(nlohmann::json::parse(first.get())["revision"] == "revision");
    ctx.get_list_hints_fn = [](const Config&) -> api::ListHintsResponse {
        throw std::runtime_error("injected analysis failure");
    };
    CHECK_THROWS(handler(""));
    ctx.get_list_hints_fn = {};
    CHECK(nlohmann::json::parse(handler(""))["revision"] == "revision");
    CHECK_FALSE(requires_step_up("POST", "/api/lists/hints"));
}

TEST_CASE("list hints representative overlaps agree with a small exhaustive oracle") {
    std::mt19937 random(0x115701);
    const std::vector<std::string> domains{
        "example.test", "a.example.test", "b.a.example.test", "other.test",
        "notexample.test", "b.other.test", "independent.test"};
    const auto intersects = [](const std::string& a, const std::string& b) {
        const auto contains = [](const std::string& parent, const std::string& child) {
            return parent == child || (child.size() > parent.size() &&
                child.compare(child.size() - parent.size(), parent.size(), parent) == 0 &&
                child[child.size() - parent.size() - 1] == '.');
        };
        return contains(a, b) || contains(b, a);
    };
    for (int trial = 0; trial < 128; ++trial) {
        auto config = hint_config();
        for (int i = 0; i < 8; ++i) {
            const auto id = "list" + std::to_string(i);
            domain_list(config, id, {domains[random() % domains.size()], domains[random() % domains.size()]});
            auto& rule = hint_rule(config, {"list" + std::to_string(random() % 8)},
                                   "out" + std::to_string(random() % 3));
            rule.enabled = random() % 4 != 0;
            if (random() % 2) rule.proto = "tcp";
        }
        const auto& rules = *config.route->rules;
        std::set<std::pair<std::size_t, std::size_t>> expected;
        for (std::size_t i = 0; i < rules.size(); ++i) {
            for (std::size_t j = i + 1; j < rules.size(); ++j) {
                if (!route_rule_enabled(rules[i]) || !route_rule_enabled(rules[j]) ||
                    rules[i].proto != rules[j].proto || rules[i].outbound == rules[j].outbound) continue;
                const auto& a = *config.lists->at(rules[i].list->front()).domains;
                const auto& b = *config.lists->at(rules[j].list->front()).domains;
                for (const auto& first : a) for (const auto& second : b) {
                    if (intersects(first, second)) expected.emplace(i, j);
                }
            }
        }
        const auto result = build_list_hints(config);
        CHECK_FALSE(result.scan_limited);
        const auto actual = hints(result, "domain_overlap");
        CHECK(actual.empty() == expected.empty());
        for (const auto& hint : actual) {
            REQUIRE(hint.rule_index);
            REQUIRE(hint.other_rule_index);
            CHECK(expected.count({*hint.rule_index, *hint.other_rule_index}) == 1);
            CHECK(hint.list == rules[*hint.rule_index].list->front());
            CHECK(hint.other_list == rules[*hint.other_rule_index].list->front());
            CHECK(intersects(*hint.entry, *hint.other_entry));
        }
    }
}

TEST_CASE("list hints bounded scale benchmark") {
    for (int size : {1000, 10000, 50000}) {
        auto config = hint_config();
        std::vector<std::string> domains;
        for (int i = 0; i < size; ++i) domains.push_back("d" + std::to_string(i) + ".example.test");
        domain_list(config, "large", std::move(domains));
        // Repeated references must be compressed before indexing each domain.
        for (int i = 0; i < 400; ++i) hint_rule(config, {"large"}, "vpn" + std::to_string(i % 2));
        ListHintsLimits limits;
        limits.elapsed = std::chrono::seconds{20};
        const auto report = build_list_hints(config, nullptr, limits);
        CHECK_FALSE(report.scan_limited);
        CHECK(report.scanned_entries == size);
        CHECK(hints(report, "domain_overlap").size() == 1);
        struct rusage usage{};
        REQUIRE(::getrusage(RUSAGE_SELF, &usage) == 0);
        std::cout << "LIST-01 entries=" << size << " rules=400 elapsed_ms=" << report.elapsed_ms
                  << " process_peak_rss_kib=" << usage.ru_maxrss << '\n';
    }
}

} // namespace keen_pbr3
#endif
