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
            result.entries.push_back(std::move(entry));

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
        [](std::optional<std::string>) { return ListRefreshOperationResult{}; },
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
    REQUIRE(body.at("results").size() == 1);
    CHECK(body.at("results")[0].at("evaluation") ==
          "insufficient_context");
    CHECK(body.at("results")[0].at("unknown_conditions") ==
          nlohmann::json{"source_address", "destination_port"});
    REQUIRE(body.at("rule_diagnostics").size() == 1);
    const auto& row =
        body.at("rule_diagnostics")[0].at("ip_rows")[0];
    CHECK(row.at("in_lists") == true);
    CHECK(row.at("list_match").at("list") == "work");
    CHECK(row.at("evaluation") == "insufficient_context");
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

} // namespace keen_pbr3

#endif // WITH_API
