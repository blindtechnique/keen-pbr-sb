#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_test_routing.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <string>

namespace keen_pbr3 {

namespace {

const std::string kApiConfigPath = "/tmp/keen-pbr-test-config.json";
constexpr const char* kApiListen = "127.0.0.1:18190";
constexpr const char* kConcurrentApiListen = "127.0.0.1:18191";

struct HttpResponseSnapshot {
    bool connected{false};
    int status{0};
    std::string body;
};

HttpResponseSnapshot post_routing_test(int port) {
    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/routing/test",
        R"({"target":"example.com"})",
        "application/json");
    if (!response) return {};
    return {true, response->status, response->body};
}

class NfqwsCoverageHookReset {
public:
    ~NfqwsCoverageHookReset() {
        reset_nfqws_coverage_scan_hook_for_testing();
    }
};

ApiContext make_test_api_context(SseBroadcaster& broadcaster) {
    return ApiContext{
        kApiConfigPath,
        broadcaster,
        []() { return Config{}; },
        []() { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> { return std::nullopt; },
        []() {},
        [](const Config&) {},
        []() { return ServiceHealthState{}; },
        []() { return RoutingHealthReport{}; },
        []() { return api::RuntimeOutboundsResponse{}; },
        []() { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
        [](const std::string& target) {
            TestRoutingResult result;
            result.target = target;
            result.unapplied_draft = true;
            result.dns_source = "configured_resolver";
            result.dns_server = "127.0.0.1:5353";
            result.fwmark_mask = 0x00ff0000U;
            TestRoutingEntry entry;
            entry.ip = "203.0.113.7";
            entry.expected_outbound = "(unknown)";
            entry.actual_outbound = "(unknown)";
            entry.ok = false;
            entry.evaluation =
                RoutingMatchEvaluation::InsufficientContext;
            entry.unknown_conditions = {
                "source_address", "destination_port"};
            entry.list_match =
                ListMatchInfo{"work", "203.0.113.7"};
            entry.fib.verdict = RoutingFibVerdict::Unavailable;
            entry.fib.detail =
                "packet context is insufficient for a FIB lookup";
            result.entries.push_back(std::move(entry));

            TestRoutingEntry resolved;
            resolved.ip = "203.0.113.8";
            resolved.expected_outbound = "vpn";
            resolved.actual_outbound = "vpn";
            resolved.ok = true;
            resolved.evaluation = RoutingMatchEvaluation::Matched;
            resolved.expected_rule_index = 0;
            resolved.actual_rule_index = 1;
            resolved.fib.verdict = RoutingFibVerdict::Resolved;
            resolved.fib.fwmark = 0x00040000U;
            resolved.fib.table = 152U;
            resolved.fib.interface = "nwg1";
            result.entries.push_back(std::move(resolved));

            RuleDiagnostic rule;
            rule.rule_index = 0;
            rule.rule.outbound = "vpn";
            rule.outbound = "vpn";
            rule.interface_name = "ppp0";
            RuleIpDiagnostic ip;
            ip.ip = "203.0.113.7";
            ip.in_lists = true;
            ip.list_match =
                ListMatchInfo{"work", "203.0.113.7"};
            ip.in_ipset = true;
            ip.evaluation =
                RoutingMatchEvaluation::InsufficientContext;
            ip.unknown_conditions = {"source_address"};
            rule.ip_rows.push_back(std::move(ip));
            result.rule_diagnostics.push_back(std::move(rule));
            return result;
        },
        []() {},
        []() {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        []() {},
        []() {},
        []() {},
        [](const api::ListRefreshRequest&) { return ListRefreshOperationResult{}; },
    };
}

} // namespace

TEST_CASE("register_test_routing_handler: rejects empty target") {
    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kApiListen);

    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    register_test_routing_handler(server, ctx);

    server.start();

    httplib::Client client("127.0.0.1", 18190);
    const auto response =
        client.Post("/api/routing/test", R"({"target":""})", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 400);

    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["error"] == "Field 'target' must not be empty");
}

TEST_CASE("register_test_routing_handler: exposes active scope and honest per-IP detail") {
    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kApiListen);

    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    register_test_routing_handler(server, ctx);
    server.start();

    httplib::Client client("127.0.0.1", 18190);
    const auto response = client.Post(
        "/api/routing/test",
        R"({"target":"example.com"})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("config_scope") == "active");
    CHECK(body.at("unapplied_draft") == true);
    CHECK(body.at("dns_source") == "configured_resolver");
    CHECK(body.at("dns_server") == "127.0.0.1:5353");
    CHECK(body.at("fwmark_mask") == 0x00ff0000U);
    CHECK_FALSE(body.contains("http_probe"));
    REQUIRE(body.at("connections").is_object());
    CHECK(body.at("connections").at("snapshot_available").is_boolean());
    CHECK(body.at("connections").at("items").size() <= 64);
    REQUIRE(body.at("results").size() == 2);
    CHECK_FALSE(body.at("results")[0].contains("expected_rule_index"));
    CHECK_FALSE(body.at("results")[0].contains("actual_rule_index"));
    CHECK(body.at("results")[1].at("expected_rule_index") == 0);
    CHECK(body.at("results")[1].at("actual_rule_index") == 1);
    CHECK(body.at("results")[0].at("evaluation") ==
          "insufficient_context");
    CHECK(body.at("results")[0].at("unknown_conditions") ==
          nlohmann::json{"source_address", "destination_port"});
    const auto& kernel_route = body.at("results")[0].at("kernel_route");
    CHECK(kernel_route.at("route_status") == "unavailable");
    CHECK(kernel_route.at("fwmark").is_null());
    CHECK(kernel_route.at("table").is_null());
    CHECK(kernel_route.at("interface") == "");
    CHECK_FALSE(kernel_route.at("detail").get<std::string>().empty());
    const auto& resolved_route =
        body.at("results")[1].at("kernel_route");
    CHECK(resolved_route.at("route_status") == "resolved");
    CHECK(resolved_route.at("fwmark") == 0x00040000U);
    CHECK(resolved_route.at("table") == 152U);
    CHECK(resolved_route.at("interface") == "nwg1");
    CHECK(resolved_route.at("detail") == "");
    REQUIRE(body.at("rule_diagnostics").size() == 1);
    const auto& row =
        body.at("rule_diagnostics")[0].at("ip_rows")[0];
    CHECK(row.at("in_lists") == true);
    CHECK(row.at("list_match").at("list") == "work");
    CHECK(row.at("evaluation") == "insufficient_context");
}

TEST_CASE("manual routing comparison validates before calling the read-only callback") {
    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kApiListen);
    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    int calls = 0;
    const auto base = ctx.compute_test_routing_fn;
    ctx.compute_test_routing_with_probe_fn = [&](const std::string& target, const RoutingProbeOptions& options) {
        ++calls;
        CHECK(target == "example.com");
        CHECK(options.url == "https://example.com/style.css");
        CHECK(options.family == "ipv6");
        auto result = base(target);
        RoutingHttpProbe probe;
        probe.url = options.url;
        probe.timeout_ms = 4321;
        result.http_probe = probe;
        return result;
    };
    register_test_routing_handler(server, ctx);
    server.start();
    httplib::Client client("127.0.0.1", 18190);
    const nlohmann::json valid = {{"target", "example.com"}, {"http_probe", {
        {"url", "https://example.com/style.css"}, {"family", "ipv6"}, {"path", "policy"}}}};
    auto response = client.Post("/api/routing/test", valid.dump(), "application/json");
    REQUIRE(response);
    CHECK(response->status == 200);
    CHECK(nlohmann::json::parse(response->body).at("http_probe").at("timeout_ms") == 4321);
    for (int case_id = 0; case_id < 8; ++case_id) {
        auto bad = valid;
        if (case_id == 0) bad["http_probe_ip"] = "203.0.113.8";
        if (case_id == 1) bad["http_probe"]["url"] = "https://other.example/";
        if (case_id == 2) bad["http_probe"]["fwmark"] = 1;
        if (case_id == 3) bad["http_probe"]["family"] = "auto";
        if (case_id == 4) bad["http_probe"]["path"] = "all";
        if (case_id == 5) bad["http_probe"]["outbound"] = "vpn";
        if (case_id == 6) bad["http_probe"] = nullptr;
        if (case_id == 7) bad["http_probe"].erase("family");
        response = client.Post("/api/routing/test", bad.dump(), "application/json");
        REQUIRE(response);
        CHECK(response->status == 400);
    }
    CHECK(calls == 1);
    ctx.compute_test_routing_with_probe_fn = {};
    response = client.Post("/api/routing/test", valid.dump(), "application/json");
    REQUIRE(response);
    CHECK(response->status == 501);
    server.stop();
}

TEST_CASE("routing HTTP is an additive explicit callback and serializes optional evidence") {
    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kApiListen);
    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    int explicit_calls = 0;
    SUBCASE("old target-only callback remains offline and returns unavailable HTTP") {}
    SUBCASE("explicit callback receives only target and selected IP") {
        const auto old_callback = ctx.compute_test_routing_fn;
        ctx.compute_test_routing_with_http_fn = [&, old_callback](const std::string& target, const std::string& ip) {
            ++explicit_calls;
            CHECK(target == "example.com");
            CHECK(ip == "203.0.113.8");
            auto result = old_callback(target);
            RoutingHttpProbe probe;
            probe.status = RoutingHttpProbeStatus::Answered;
            probe.reason = RoutingHttpProbeReason::HttpResponse;
            probe.ip = ip;
            probe.url = "https://example.com/";
            probe.interface = "nwg1";
            probe.attempted_at = 123;
            probe.fwmark = 0xffffffffU;
            probe.table = 0xffffffffU;
            probe.http_status = 403;
            probe.elapsed_ms = 34;
            probe.connect_ms = 12;
            probe.tls_ms = 22;
            probe.connected_ip = ip;
            result.http_probe = std::move(probe);
            return result;
        };
    }
    register_test_routing_handler(server, ctx);
    server.start();
    httplib::Client client("127.0.0.1", 18190);
    const auto response = client.Post("/api/routing/test",
        R"({"target":"example.com","http_probe_ip":"203.0.113.8","fwmark":1,"interface":"attacker"})",
        "application/json");
    server.stop();
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    REQUIRE(body.contains("http_probe"));
    const auto& probe = body.at("http_probe");
    CHECK(probe.at("ip") == "203.0.113.8");
    CHECK(probe.at("method") == "HEAD");
    CHECK(probe.at("scope") == "router");
    CHECK(body.at("results").size() == 2);
    if (ctx.compute_test_routing_with_http_fn) {
        CHECK(explicit_calls == 1);
        CHECK(probe.at("status") == "answered");
        CHECK(probe.at("reason") == "http_response");
        CHECK(probe.at("fwmark") == 0xffffffffU);
        CHECK(probe.at("table") == 0xffffffffU);
        CHECK(probe.at("http_status") == 403);
        CHECK(probe.at("interface") == "nwg1");
        CHECK(probe.at("connect_ms") == 12);
        CHECK(probe.at("tls_ms") == 22);
    } else {
        CHECK(explicit_calls == 0);
        CHECK(probe.at("status") == "unavailable");
        CHECK(probe.at("reason") == "transport_error");
        CHECK(probe.at("attempted_at") == 0);
        for (const auto* key : {"fwmark", "table", "http_status", "elapsed_ms", "connect_ms", "tls_ms", "connected_ip"}) {
            CHECK_FALSE(probe.contains(key));
        }
    }
    const auto roundtrip = probe.get<api::RoutingTestHttpProbe>();
    CHECK(roundtrip.ip == "203.0.113.8");
}

TEST_CASE("nfqws list paths are exact direct children of the fixed root") {
    CHECK(nfqws_list_path_confined_for_testing(
        "/opt/etc/nfqws2/lists/user.list"));
    CHECK_FALSE(nfqws_list_path_confined_for_testing(
        "/opt/etc/nfqws2/lists/nested/user.list"));
    CHECK_FALSE(nfqws_list_path_confined_for_testing(
        "/opt/etc/nfqws2/lists/../secret.list"));
    CHECK_FALSE(nfqws_list_path_confined_for_testing(
        "/opt/etc/nfqws2/lists-elsewhere/user.list"));
}

TEST_CASE("the production nfqws cache rejects a four MiB tiny-line bomb") {
    constexpr std::size_t kBombBytes = 4U * 1024U * 1024U;
    std::string bomb;
    bomb.reserve(kBombBytes);
    while (bomb.size() < kBombBytes) bomb.append("a\n");

    // nullopt is the cache-publication contract: the parser keeps no partial
    // vector, list_entries returns unavailable, and no byte charge is added.
    CHECK_FALSE(nfqws_cached_list_footprint_for_testing(bomb).has_value());

    const std::string ordinary =
        "# ignored\nexample.com\n10.0.0.0/8\n";
    const auto footprint =
        nfqws_cached_list_footprint_for_testing(ordinary);
    REQUIRE(footprint.has_value());
    CHECK(*footprint > ordinary.size());
}

TEST_CASE("a concurrent routing test does not enter a second nfqws scan") {
    using namespace std::chrono_literals;

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool first_scan_entered = false;
    bool release_first_scan = false;
    std::atomic<int> scan_entries{0};

    set_nfqws_coverage_scan_hook_for_testing([&]() {
        scan_entries.fetch_add(1, std::memory_order_relaxed);
        std::unique_lock<std::mutex> lock(barrier_mutex);
        first_scan_entered = true;
        barrier_cv.notify_all();
        barrier_cv.wait(lock, [&]() { return release_first_scan; });
    });
    NfqwsCoverageHookReset reset_hook;

    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kConcurrentApiListen);
    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    register_test_routing_handler(server, ctx);
    server.start();

    auto first = std::async(
        std::launch::async, []() { return post_routing_test(18191); });

    bool entered = false;
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        entered = barrier_cv.wait_for(
            lock, 2s, [&]() { return first_scan_entered; });
    }
    if (!entered) {
        {
            std::lock_guard<std::mutex> lock(barrier_mutex);
            release_first_scan = true;
        }
        barrier_cv.notify_all();
        (void)first.get();
        server.stop();
        CHECK_MESSAGE(false, "the first request did not enter the nfqws scan");
        return;
    }

    auto second = std::async(
        std::launch::async, []() { return post_routing_test(18191); });
    const bool second_returned_while_first_was_held =
        second.wait_for(2s) == std::future_status::ready;
    const int entries_before_release =
        scan_entries.load(std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(barrier_mutex);
        release_first_scan = true;
    }
    barrier_cv.notify_all();

    const auto first_response = first.get();
    const auto second_response = second.get();
    server.stop();

    CHECK(first_response.connected);
    CHECK(first_response.status == 200);
    CHECK(second_returned_while_first_was_held);
    CHECK(entries_before_release == 1);
    REQUIRE(second_response.connected);
    REQUIRE(second_response.status == 200);
    const auto body = nlohmann::json::parse(second_response.body);
    REQUIRE(body.at("nfqws").at("available") == false);
    CHECK(body.at("nfqws").at("reason") == "busy");
    CHECK(body.at("nfqws").at("matches").empty());
}

TEST_CASE("nfqws gzip lists are unknown to the bounded text cache") {
    const std::string compressed("\x1f\x8b\x08\x00", 4);
    CHECK_FALSE(nfqws_cached_list_footprint_for_testing(compressed).has_value());
    CHECK(nfqws_cached_list_footprint_for_testing("# empty list\n").has_value());
}

TEST_CASE("nfqws profile evidence retains its boundaries through the API wire format") {
    const nlohmann::json wire = {
        {"available", true}, {"matches", nlohmann::json::array()},
        // The generated serializer emits null for an absent optional reason.
        {"reason", nullptr},
        {"profiles", nlohmann::json::array({
            {{"index", 1}, {"name", "ip"}, {"filters", {"--filter-tcp=443"}},
             {"has_actions", true}, {"hostname_required", false},
             {"auto_hostlist", false}, {"list_result", "matched"},
             {"matches", nlohmann::json::array()}},
            {{"index", 2}, {"name", "domains"}, {"filters", {"--filter-l7=tls"}},
             {"has_actions", true}, {"hostname_required", true},
             {"auto_hostlist", false}, {"list_result", "excluded"},
             {"matches", nlohmann::json::array({
                 {{"list", "--hostlist-exclude-domains"}, {"role", "hostlist_exclude"},
                  {"entry", "^example.test"}, {"matched", "example.test"},
                  {"exact", true}, {"includes", false}}
             })}}
        })}
    };
    const auto parsed = wire.get<api::RoutingTestNfqws>();
    REQUIRE(parsed.profiles);
    REQUIRE(parsed.profiles->size() == 2);
    CHECK(parsed.profiles->at(0).list_result == "matched");
    CHECK(parsed.profiles->at(1).list_result == "excluded");
    CHECK(nlohmann::json(parsed) == wire);
    auto without_reason = wire;
    without_reason.erase("reason");
    CHECK(nlohmann::json(without_reason.get<api::RoutingTestNfqws>()) == wire);
    const auto legacy = nlohmann::json{
        {"available", true}, {"matches", nlohmann::json::array()}
    }.get<api::RoutingTestNfqws>();
    CHECK_FALSE(legacy.profiles);
    CHECK_FALSE(legacy.reason);
}

TEST_CASE("nfqws API evaluation preserves local exclusions and unavailable partial data") {
    TestRoutingResult result;
    result.target = "example.test";
    result.is_domain = true;
    result.resolved_ips = {"203.0.113.7", "203.0.113.7"};
    const auto profiles = nfqws::parse_profile_references({
        "--ipset-ip=203.0.113.0/24", "--lua-desync=fake",
        "--new=domains", "--hostlist-exclude-domains=^example.test",
        "--lua-desync=fake"});
    auto coverage = nfqws_profile_coverage_for_testing(result, profiles, {});
    CHECK(coverage.available);
    REQUIRE(coverage.profiles);
    REQUIRE(coverage.profiles->size() == 2);
    CHECK(coverage.profiles->at(0).list_result == "matched");
    CHECK(coverage.profiles->at(1).list_result == "excluded");
    CHECK(coverage.matches.size() == 2); // duplicate resolved IP is not duplicated
    const nlohmann::json body = coverage;
    CHECK(body.at("profiles").at(1).at("matches").at(0).at("includes") == false);
    CHECK(body.at("profiles").at(1).at("matches").at(0).at("exact") == true);

    auto partial = profiles;
    partial.back().lists = nfqws::parse_list_references({"--hostlist=/lists/unreadable"});
    coverage = nfqws_profile_coverage_for_testing(result, partial, {});
    CHECK_FALSE(coverage.available); // also safe for an old, flat-only UI
    CHECK(coverage.reason == "unavailable");
    REQUIRE(coverage.profiles);
    CHECK(coverage.profiles->at(0).list_result == "matched");
    CHECK(coverage.profiles->at(1).list_result == "unknown");
    CHECK(coverage.profiles->at(1).matches.empty());

    result.is_domain = false;
    result.target = "203.0.113.7";
    coverage = nfqws_profile_coverage_for_testing(result, profiles, {});
    REQUIRE(coverage.profiles);
    CHECK(coverage.profiles->at(1).list_result == "hostname_required");
}

TEST_CASE("nfqws API diagnostic budget never turns truncated evidence into a verdict") {
    TestRoutingResult result;
    result.target = "example.test";
    result.is_domain = true;
    const auto profiles = nfqws::parse_profile_references({
        "--ipset-ip=203.0.113.0/24", "--lua-desync=fake",
        "--new", "--ipset-ip=203.0.113.0/24", "--lua-desync=fake",
        "--new", "--ipset-ip=203.0.113.0/24", "--lua-desync=fake"});
    for (int i = 1; i <= 33; ++i) {
        result.resolved_ips.push_back("203.0.113." + std::to_string(i));
    }
    auto coverage = nfqws_profile_coverage_for_testing(result, profiles, {});
    CHECK_FALSE(coverage.available);
    CHECK_FALSE(coverage.profiles);
    CHECK(coverage.matches.empty());
    result.resolved_ips.pop_back(); // addresses fit, but nested matches do not
    coverage = nfqws_profile_coverage_for_testing(result, profiles, {});
    CHECK_FALSE(coverage.available);
    CHECK_FALSE(coverage.profiles);
    CHECK(coverage.matches.empty());
    CHECK(coverage.reason == "unavailable");
}

} // namespace keen_pbr3

#endif // WITH_API
