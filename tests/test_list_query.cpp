#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_lists_query.hpp"

#include <limits>

namespace keen_pbr3 {
namespace {

VisibleConfigSnapshot list_snapshot() {
    VisibleConfigSnapshot snapshot{};
    snapshot.config.lists.emplace();
    snapshot.revision = "visible-revision";
    return snapshot;
}

ListConfig named_list(const std::string& name) {
    ListConfig list{};
    list.display_name = name;
    return list;
}

std::vector<std::string> list_ids(const api::ListPage& page) {
    std::vector<std::string> result;
    for (const auto& item : page.items) result.push_back(item.id);
    return result;
}

bool bad_list_query(const std::string& body) {
    try {
        static_cast<void>(parse_list_query_request(body));
    } catch (const ApiError& error) {
        return error.status() == 400;
    }
    return false;
}

} // namespace

TEST_CASE("list query validates bounded page and text options") {
    const auto defaults = parse_list_query_request("{}");
    CHECK(defaults.offset == 0);
    CHECK(defaults.limit == 50);
    CHECK(defaults.search.empty());
    CHECK(defaults.sort == "id");
    CHECK(defaults.order == "asc");

    for (const auto& body : {
             "", "[]", "null", "{", "{\"offset\":-1}",
             "{\"offset\":1.5}", "{\"offset\":\"1\"}",
             "{\"offset\":18446744073709551615}", "{\"limit\":0}",
             "{\"limit\":201}", "{\"limit\":null}", "{\"search\":42}",
             "{\"sort\":\"other\"}", "{\"order\":\"other\"}"}) {
        CAPTURE(body);
        CHECK(bad_list_query(body));
    }
    std::string unicode_search;
    for (int index = 0; index < 256; ++index) unicode_search += "Ё";
    CHECK_NOTHROW(parse_list_query_request(
        nlohmann::json{{"search", unicode_search}, {"limit", 200}}.dump()));
    unicode_search += "Ё";
    CHECK(bad_list_query(nlohmann::json{{"search", unicode_search}}.dump()));
    const auto maximum = parse_list_query_request(
        "{\"offset\":9223372036854775807,\"limit\":1,\"sort\":\"source\",\"order\":\"desc\"}");
    CHECK(maximum.offset == std::numeric_limits<std::int64_t>::max());
    CHECK(maximum.limit == 1);
    CHECK(maximum.sort == "source");
    CHECK(maximum.order == "desc");
}

TEST_CASE("list query pages the complete collection and clamps a deleted last page") {
    auto snapshot = list_snapshot();
    for (int index = 0; index < 123; ++index) {
        (*snapshot.config.lists)["list" + std::to_string(1000 + index)] = ListConfig{};
    }
    ListQueryOptions request;
    auto page = build_list_page(snapshot, request);
    CHECK(page.total == 123);
    CHECK(page.filtered_total == 123);
    CHECK(page.offset == 0);
    CHECK(page.limit == 50);
    REQUIRE(page.items.size() == 50);
    CHECK(page.items.front().id == "list1000");
    CHECK(page.items.back().id == "list1049");

    request.offset = 50;
    page = build_list_page(snapshot, request);
    REQUIRE(page.items.size() == 50);
    CHECK(page.items.front().id == "list1050");
    request.offset = std::numeric_limits<std::int64_t>::max();
    page = build_list_page(snapshot, request);
    CHECK(page.offset == 100);
    REQUIRE(page.items.size() == 23);
    CHECK(page.items.front().id == "list1100");

    request.search = "list112";
    page = build_list_page(snapshot, request);
    CHECK(page.total == 123);
    CHECK(page.filtered_total == 3);
    CHECK(page.offset == 0);
    REQUIRE(page.items.size() == 3);
    CHECK(page.items.front().id == "list1120");
    request.search = "does-not-exist";
    page = build_list_page(snapshot, request);
    CHECK(page.total == 123);
    CHECK(page.filtered_total == 0);
    CHECK(page.offset == 0);
    CHECK(page.items.empty());

    snapshot.config.lists.reset();
    page = build_list_page(snapshot, request);
    CHECK(page.total == 0);
    CHECK(page.filtered_total == 0);
    CHECK(page.offset == 0);
    CHECK(page.limit == 50);
    CHECK_FALSE(page.has_refreshable_lists);
}

TEST_CASE("list query searches Russian and ASCII tokens across names and dependencies") {
    auto snapshot = list_snapshot();
    auto& lists = *snapshot.config.lists;
    lists["catalog_meta"] = named_list("ЁЛКА Meta");
    lists["catalog_meta"].url = "https://lists.example/Service2.txt";
    lists["file_list"] = named_list("ФАЙЛ");
    lists["file_list"].file = "/opt/etc/Rules3.txt";
    lists["inline_list"] = named_list("Локальный");
    lists["unrelated"] = named_list("ДРУГОЙ");
    lists["unrelated"].url = "https://other.example/list.txt";

    Outbound outbound{};
    outbound.tag = "vpn_tag";
    outbound.display_name = "МЁД Европа";
    snapshot.config.outbounds = std::vector<Outbound>{outbound};
    RouteRule named{};
    named.id = "stable-route-id";
    named.display_name = "Социальные сети";
    named.list = std::vector<std::string>{"catalog_meta"};
    named.outbound = outbound.tag;
    RouteRule unnamed{};
    unnamed.list = std::vector<std::string>{"inline_list"};
    unnamed.outbound = "other_vpn";
    snapshot.config.route.emplace();
    snapshot.config.route->rules = std::vector<RouteRule>{named, unnamed};
    DnsServer dns{};
    dns.tag = "dns_tag";
    dns.display_name = "РЕЗЕРВНЫЙ DNS";
    DnsRule rule{};
    rule.list = {"catalog_meta"};
    rule.server = dns.tag;
    snapshot.config.dns.emplace();
    snapshot.config.dns->servers = std::vector<DnsServer>{dns};
    snapshot.config.dns->rules = std::vector<DnsRule>{rule};

    ListQueryOptions request;
    for (const auto& search : {"ёлка META service2", "Социальные ЕВРОПА",
                               "мёд резервный", "stable-route-id dns_TAG",
                               "Социальные сети → МЁД Европа"}) {
        CAPTURE(search);
        request.search = search;
        const auto page = build_list_page(snapshot, request);
        REQUIRE(page.items.size() == 1);
        CHECK(page.items.front().id == "catalog_meta");
    }
    request.search = "  файл\tRULES3  ";
    auto page = build_list_page(snapshot, request);
    REQUIRE(page.items.size() == 1);
    CHECK(page.items.front().id == "file_list");
    for (const auto& search : {"ВСТРОЕННЫЙ #2", "inline RULE #2", "Правило №2"}) {
        CAPTURE(search);
        request.search = search;
        page = build_list_page(snapshot, request);
        REQUIRE(page.items.size() == 1);
        CHECK(page.items.front().id == "inline_list");
    }
    request.search = "Европа ДРУГОЙ";
    CHECK(build_list_page(snapshot, request).items.empty());
}

TEST_CASE("list query natural sorting has stable id ties in either direction") {
    auto snapshot = list_snapshot();
    auto& lists = *snapshot.config.lists;
    lists["z"] = named_list("VPN 2");
    lists["a"] = named_list("vpn 02");
    lists["b"] = named_list("VPN 10");
    lists["c"] = named_list("VPN 99999999999999999999999999");
    lists["d"] = named_list("VPN 100000000000000000000000000");
    lists["a"].url = "https://host2/list";
    lists["z"].url = "https://HOST02/list";
    lists["b"].file = "/opt/source10";
    lists["c"].file = "/opt/source2";
    lists["d"].file = "/opt/source01";

    ListQueryOptions request;
    request.sort = "name";
    CHECK(list_ids(build_list_page(snapshot, request)) ==
          std::vector<std::string>{"a", "z", "b", "c", "d"});
    request.order = "desc";
    CHECK(list_ids(build_list_page(snapshot, request)) ==
          std::vector<std::string>{"d", "c", "b", "a", "z"});
    request.sort = "source";
    request.order = "asc";
    CHECK(list_ids(build_list_page(snapshot, request)) ==
          std::vector<std::string>{"d", "c", "b", "a", "z"});
    request.order = "desc";
    CHECK(list_ids(build_list_page(snapshot, request)) ==
          std::vector<std::string>{"a", "z", "b", "c", "d"});
    request.sort = "id";
    CHECK(list_ids(build_list_page(snapshot, request)) ==
          std::vector<std::string>{"z", "d", "c", "b", "a"});
}

TEST_CASE("list query trims friendly names and falls back to stable ids") {
    auto snapshot = list_snapshot();
    (*snapshot.config.lists)["a2"] = named_list("  \t ");
    (*snapshot.config.lists)["a10"] = named_list(" a10\n");
    ListQueryOptions request;
    request.sort = "name";
    CHECK(list_ids(build_list_page(snapshot, request)) ==
          std::vector<std::string>{"a2", "a10"});
    request.search = "a2";
    const auto page = build_list_page(snapshot, request);
    REQUIRE(page.items.size() == 1);
    CHECK(page.items.front().id == "a2");
}

TEST_CASE("list query returns counts without inline bodies or unrelated secrets") {
    auto snapshot = list_snapshot();
    auto& list = (*snapshot.config.lists)["summary"];
    list.display_name = "Summary";
    list.domains = std::vector<std::string>{"private-list-domain.example", "other.example"};
    list.ip_cidrs = std::vector<std::string>{"192.0.2.20", "198.51.100.0/24",
                                            "2001:db8::1", "2001:db8:1::/48"};
    snapshot.config.api.emplace();
    snapshot.config.api->listen = "hidden-api-listen-value";
    const auto page = build_list_page(snapshot, {});
    REQUIRE(page.items.size() == 1);
    CHECK(page.items.front().domain_count == 2);
    CHECK(page.items.front().ipv4_count == 2);
    CHECK(page.items.front().ipv6_count == 2);
    const nlohmann::json serialized = page;
    const auto& item = serialized.at("items").at(0);
    CHECK_FALSE(item.contains("domains"));
    CHECK_FALSE(item.contains("ip_cidrs"));
    CHECK_FALSE(serialized.contains("config"));
    const auto body = serialized.dump();
    CHECK(body.find("private-list-domain.example") == std::string::npos);
    CHECK(body.find("192.0.2.20") == std::string::npos);
    CHECK(body.find("hidden-api-listen-value") == std::string::npos);
}

TEST_CASE("list query keeps refreshability global outside the filtered page") {
    auto snapshot = list_snapshot();
    (*snapshot.config.lists)["a_inline"] = ListConfig{};
    (*snapshot.config.lists)["z_remote"] = ListConfig{};
    (*snapshot.config.lists)["z_remote"].url = "https://remote.example/list";
    ListQueryOptions request;
    request.limit = 1;
    auto page = build_list_page(snapshot, request);
    REQUIRE(page.items.size() == 1);
    CHECK(page.items.front().id == "a_inline");
    CHECK(page.has_refreshable_lists);
    request.search = "nonexistent";
    page = build_list_page(snapshot, request);
    CHECK(page.items.empty());
    CHECK(page.has_refreshable_lists);
    (*snapshot.config.lists)["z_remote"].url = "";
    CHECK_FALSE(build_list_page(snapshot, request).has_refreshable_lists);
}

TEST_CASE("list query uses one atomic draft-preferred snapshot without mutation admission") {
    SseBroadcaster broadcaster;
    ApiContext context{"/unused/list-query", broadcaster};
    auto draft = list_snapshot();
    draft.is_draft = true;
    draft.revision = "exact-draft-revision";
    (*draft.config.lists)["draft-only"] = named_list("Unsaved list");
    int snapshot_reads = 0;
    context.get_visible_config_snapshot_fn = [&]() {
        ++snapshot_reads;
        return draft;
    };
    context.get_visible_config_fn = []() -> Config {
        throw std::runtime_error("separate config read must not run");
    };
    context.config_is_draft_fn = []() -> bool {
        throw std::runtime_error("separate draft read must not run");
    };
    context.begin_save_operation_fn = []() {
        throw std::runtime_error("query must not acquire write admission");
    };
    context.stage_config_fn = [](Config, std::string) {
        throw std::runtime_error("query must not stage a draft");
    };
    const auto page = query_lists(context, {});
    CHECK(snapshot_reads == 1);
    CHECK(page.is_draft);
    CHECK(page.revision == "exact-draft-revision");
    CHECK(page.total == 1);
    REQUIRE(page.items.size() == 1);
    CHECK(page.items.front().id == "draft-only");
    CHECK(draft.config.lists->size() == 1);
}

} // namespace keen_pbr3

#endif // WITH_API
