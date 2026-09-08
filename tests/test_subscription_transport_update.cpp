#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/subscription_transport_update.hpp"
#include "../src/log/logger.hpp"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {
namespace {
using json = nlohmann::json;
const std::string old_link = "vless://old-credential@one.example:443#Provider%20name";
const std::string new_link = "vless://new-credential@two.example:8443#Renamed%20provider";
const std::string response_secret = "provider-password-must-not-reach-logs";

json existing_spec(const std::string& tag = "home_proxy", const std::string& link = old_link) {
    return {{"tag", tag}, {"type", "sing-box"}, {"interface", "vless7"},
        {"display_name", "My chosen VPN"}, {"auto_start", true},
        {"mtu", 1380}, {"bootstrap_dns", json::array({"192.0.2.53"})},
        {"tun_address", "172.19.7.1/30"}, {"geo_mode", "manual"},
        {"country_code", "NL"}, {"country", "Netherlands"},
        {"link_fingerprint", subscription_link_fingerprint(link)}};
}

SubscriptionTransportUpdate update_for(const std::string& tag = "home_proxy") {
    return {tag, new_link, subscription_link_fingerprint(old_link),
        "provider:stable-server", subscription_link_fingerprint(new_link)};
}

// Implements only the existing production manager endpoints. Any accidental
// create, validate, bulk import or non-conditional update is a test failure.
class UpdateManager {
public:
    struct Put { std::string tag; std::string revision; json spec; };
    httplib::Server server;
    std::thread thread;
    int port{0};
    std::mutex mutex;
    json specs{json::array()};
    std::string revision{"initial-revision"};
    std::vector<Put> puts;
    unsigned get_count{0};
    unsigned unauthorized_count{0};
    unsigned conflict_on_put{0};
    int get_status{200};
    int put_status{200};
    bool malformed_state{false};
    bool omit_reply_revision{false};

    explicit UpdateManager(json initial_specs) : specs(std::move(initial_specs)) {
        server.Get("/v1/config/transports/state", [this](const httplib::Request& request, httplib::Response& response) {
            std::lock_guard<std::mutex> lock(mutex);
            if (!authorized(request, response)) return;
            ++get_count;
            response.status = get_status;
            if (get_status != 200 || malformed_state) {
                response.set_content(response_secret, "text/plain");
                return;
            }
            response.set_content(json{{"transports", specs}, {"revision", revision}}.dump(), "application/json");
        });
        server.Put(R"(/v1/config/transports/([a-z][a-z0-9_]{0,23}))",
            [this](const httplib::Request& request, httplib::Response& response) {
                std::lock_guard<std::mutex> lock(mutex);
                if (!authorized(request, response)) return;
                const auto tag = request.matches[1].str();
                const auto spec = json::parse(request.body, nullptr, false);
                const auto expected = request.get_header_value("If-Match");
                puts.push_back({tag, expected, spec});
                if (conflict_on_put == puts.size()) revision = "concurrent-user-edit";
                if (expected != "\"" + revision + "\"") {
                    response.status = 412;
                    response.set_content(response_secret, "text/plain");
                    return;
                }
                if (put_status != 200) {
                    response.status = put_status;
                    response.set_content(response_secret, "text/plain");
                    return;
                }
                auto found = std::find_if(specs.begin(), specs.end(), [&](const auto& item) {
                    return item.value("tag", std::string{}) == tag;
                });
                if (found == specs.end() || !spec.is_object() ||
                    spec.value("tag", std::string{}) != tag ||
                    spec.contains("link_fingerprint") || !spec.contains("link")) {
                    response.status = 400;
                    return;
                }
                auto redacted = spec;
                redacted["link_fingerprint"] = subscription_link_fingerprint(spec.at("link").get<std::string>());
                redacted.erase("link");
                *found = std::move(redacted);
                revision = "updated-revision-" + std::to_string(puts.size());
                json reply{{"status", "updated"}, {"tag", tag}};
                if (!omit_reply_revision) reply["config_revision"] = revision;
                response.set_content(reply.dump(), "application/json");
            });
        port = server.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        thread = std::thread([this] { server.listen_after_bind(); });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!server.is_running() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ~UpdateManager() { server.stop(); if (thread.joinable()) thread.join(); }
    TransportManagerEndpoint endpoint() const { return {"127.0.0.1", port, "internal-test-key"}; }

private:
    bool authorized(const httplib::Request& request, httplib::Response& response) {
        if (request.get_header_value("Authorization") == "Bearer internal-test-key") return true;
        ++unauthorized_count;
        response.status = 401;
        return false;
    }
};

struct CaptureLogs {
    std::string text;
    LogLevel previous{Logger::instance().level()};
    CaptureLogs() {
        Logger::instance().set_level(LogLevel::debug);
        Logger::instance().set_sink([this](const std::string& line) { text += line; });
    }
    ~CaptureLogs() { Logger::instance().clear_sink(); Logger::instance().set_level(previous); }
};
}

TEST_CASE("subscription transport update preserves user alias interface and metadata") {
    const auto original = existing_spec();
    UpdateManager manager(json::array({original}));
    const auto result = update_subscription_transports(manager.endpoint(), {update_for()});
    CHECK(result.error_code.empty());
    CHECK(result.applied_tags == std::vector<std::string>{"home_proxy"});
    REQUIRE(manager.puts.size() == 1);
    auto expected = original;
    expected.erase("link_fingerprint");
    expected["link"] = new_link;
    CHECK(manager.puts[0].spec == expected);
    CHECK(manager.puts[0].tag == "home_proxy");
    CHECK(manager.puts[0].revision == "\"initial-revision\"");
    CHECK(manager.get_count == 1);
    CHECK(manager.unauthorized_count == 0);
}

TEST_CASE("subscription transport state uses the same internal fingerprint as the manager") {
    const std::string golden = "6005eaff07bcbb5ec4fb1c8d192197f961c9c369a74b39861a2e5d37d4bffb50";
    // Same published vector as transport-manager/internal/transport/testdata.
    CHECK(subscription_link_fingerprint("  vless://u@a.example:443?security=tls#other  ") == golden);
    auto known = existing_spec();
    known["link_fingerprint"] = golden;
    auto json_only = existing_spec("json_only");
    json_only.erase("link_fingerprint");
    UpdateManager manager(json::array({known, json_only,
        json{{"tag", "native_vpn"}, {"type", "native"}, {"link_fingerprint", "not-a-subscription"}}}));
    const auto state = read_subscription_transports(manager.endpoint());
    REQUIRE(state.size() == 3);
    CHECK(state[0].tag == "home_proxy");
    CHECK(state[0].fingerprint == golden);
    CHECK(state[1].tag == "json_only");
    CHECK(state[1].fingerprint.empty());
    CHECK(state[2].tag == "native_vpn");
    CHECK(state[2].fingerprint.empty());
    CHECK(manager.puts.empty());
    CHECK(manager.unauthorized_count == 0);
}

TEST_CASE("subscription inventory cannot report a partial or unavailable manager as empty") {
    UpdateManager manager(json::array({existing_spec()}));
    SUBCASE("HTTP read error") { manager.get_status = 503; }
    SUBCASE("malformed document") { manager.malformed_state = true; }
    SUBCASE("malformed entry") { manager.specs.push_back(json::object()); }
    CHECK_THROWS_AS(read_subscription_transports(manager.endpoint()), std::runtime_error);
    CHECK(manager.puts.empty());
}

TEST_CASE("subscription already applied next fingerprint does not PUT or restart twice") {
    UpdateManager manager(json::array({existing_spec("home_proxy", new_link)}));
    const auto result = update_subscription_transports(manager.endpoint(), {update_for()});
    CHECK(result.error_code.empty());
    CHECK(result.applied_tags == std::vector<std::string>{"home_proxy"});
    CHECK(manager.puts.empty());
}

TEST_CASE("subscription previous fingerprint mismatch does not overwrite manual VPN changes") {
    UpdateManager manager(json::array({existing_spec("home_proxy", "vless://user-edit@manual.example:443")}));
    const auto before = manager.specs;
    const auto result = update_subscription_transports(manager.endpoint(), {update_for()});
    CHECK(result.error_code == "transport_changed");
    CHECK(result.applied_tags.empty());
    CHECK(manager.puts.empty());
    CHECK(manager.specs == before);
}

TEST_CASE("subscription updates carry each returned revision and report only applied tags on conflict") {
    UpdateManager manager(json::array({existing_spec("first"), existing_spec("second"), existing_spec("third")}));
    manager.conflict_on_put = 2;
    const auto result = update_subscription_transports(manager.endpoint(),
        {update_for("first"), update_for("second"), update_for("third")});
    CHECK(result.error_code == "transport_changed");
    CHECK(result.applied_tags == std::vector<std::string>{"first"});
    REQUIRE(manager.puts.size() == 2);
    CHECK(manager.puts[0].revision == "\"initial-revision\"");
    CHECK(manager.puts[1].revision == "\"updated-revision-1\"");
    CHECK(manager.specs[0].at("link_fingerprint") == subscription_link_fingerprint(new_link));
    CHECK(manager.specs[1].at("link_fingerprint") == subscription_link_fingerprint(old_link));
    CHECK(manager.specs[2].at("link_fingerprint") == subscription_link_fingerprint(old_link));
}

TEST_CASE("subscription update removes alternative source fields before replacing the link") {
    auto original = existing_spec();
    original["outbound_json"] = "redacted";
    original["vless"] = json{{"uuid", "redacted"}};
    UpdateManager manager(json::array({original}));
    const auto result = update_subscription_transports(manager.endpoint(), {update_for()});
    CHECK(result.error_code.empty());
    REQUIRE(manager.puts.size() == 1);
    CHECK_FALSE(manager.puts[0].spec.contains("outbound_json"));
    CHECK_FALSE(manager.puts[0].spec.contains("vless"));
    CHECK_FALSE(manager.puts[0].spec.contains("link_fingerprint"));
    CHECK(manager.puts[0].spec.at("link") == new_link);
}

TEST_CASE("subscription missing reply revision keeps completed tag without guessing another update") {
    UpdateManager manager(json::array({existing_spec("first"), existing_spec("second")}));
    manager.omit_reply_revision = true;
    const auto result = update_subscription_transports(manager.endpoint(),
        {update_for("first"), update_for("second")});
    CHECK(result.error_code == "manager_unavailable");
    CHECK(result.applied_tags == std::vector<std::string>{"first"});
    CHECK(manager.puts.size() == 1);
}

TEST_CASE("subscription manager failures never expose response bodies or credentials in results and logs") {
    CaptureLogs logs;
    UpdateManager manager(json::array({existing_spec()}));
    SUBCASE("HTTP read error") { manager.get_status = 503; }
    SUBCASE("malformed state") { manager.malformed_state = true; }
    SUBCASE("HTTP apply error") { manager.put_status = 500; }
    const auto result = update_subscription_transports(manager.endpoint(), {update_for()});
    CHECK((result.error_code == "manager_unavailable" || result.error_code == "apply_failed"));
    CHECK(result.applied_tags.empty());
    CHECK(result.error_code.find(response_secret) == std::string::npos);
    CHECK(logs.text.find(response_secret) == std::string::npos);
    CHECK(logs.text.find("new-credential") == std::string::npos);
    CHECK(logs.text.find("old-credential") == std::string::npos);
    CHECK(logs.text.find("internal-test-key") == std::string::npos);
}

TEST_CASE("empty subscription update batch does not contact manager") {
    UpdateManager manager(json::array());
    const auto result = update_subscription_transports(manager.endpoint(), {});
    CHECK(result.applied_tags.empty());
    CHECK(result.error_code.empty());
    CHECK(manager.get_count == 0);
    CHECK(manager.puts.empty());
}

} // namespace keen_pbr3
#endif
