#include <doctest/doctest.h>

#include "../src/api/router_info_metadata.hpp"
#include "../src/api/device_inventory.hpp"

#include <chrono>
#include <map>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

struct MetadataFixture {
    std::int64_t seconds{0};
    std::map<std::string, int> calls;
    std::optional<nlohmann::json> internet{
        nlohmann::json{{"internet", true}, {"gateway", {{"interface", "WAN1"}}}}};
    std::optional<nlohmann::json> interface{
        nlohmann::json{{"id", "WAN1"}, {"address", "192.0.2.1"}}};
    std::optional<nlohmann::json> hotspot{
        nlohmann::json{{"host", nlohmann::json::array({
            nlohmann::json{{"active", true}}, nlohmann::json{{"active", false}}})}}};
    bool version_ok{true};
    std::string model{"Router 1"};

    // Model the already-existing shared version resource's 30-second policy;
    // the metadata projection must neither invalidate it nor add a second TTL.
    RouterInfoCache version_cache{
        [this]() -> RouterInfoCache::FetchResult {
            ++calls["/show/version"];
            return {version_ok ? nlohmann::json{{"model", model}}
                               : nlohmann::json::object(), version_ok};
        }, 30s, 30s, [this] { return now(); }};
    RouterInfoMetadata metadata{
        [this](const std::string& path) {
            ++calls[path];
            if (path == "/show/internet/status") return internet;
            if (path == "/show/ip/hotspot") return hotspot;
            if (path.rfind("/show/interface/", 0) == 0) return interface;
            return std::optional<nlohmann::json>{};
        },
        [this] { return version_cache.get(); },
        [this] { return now(); }};

    RouterInfoCache::Clock::time_point now() const {
        return RouterInfoCache::Clock::time_point{std::chrono::seconds(seconds)};
    }

    int total_calls() const {
        int count = 0;
        for (const auto& [path, calls_for_path] : calls) {
            static_cast<void>(path);
            count += calls_for_path;
        }
        return count;
    }
};

} // namespace

TEST_CASE("router metadata frequent reads respect independent observation budgets") {
    MetadataFixture fixture;
    // Eight 15-second Overview polls, including the cold load: five RCI calls
    // per minute (version twice, internet + interface once, hotspot once).
    for (int index = 0; index < 8; ++index) {
        fixture.seconds = index * 15;
        const auto value = fixture.metadata.get();
        CHECK(value.at("model") == "Router 1");
        CHECK(value.at("wan_address") == "192.0.2.1");
    }
    CHECK(fixture.calls["/show/version"] == 4);
    CHECK(fixture.calls["/show/internet/status"] == 2);
    CHECK(fixture.calls["/show/interface/WAN1"] == 2);
    CHECK(fixture.calls["/show/ip/hotspot"] == 2);
    CHECK(fixture.total_calls() == 10);
    CHECK(fixture.calls.count("/show/system") == 0);
}

TEST_CASE("router metadata default route events refresh WAN only without waiting for TTL") {
    MetadataFixture fixture;
    (void)fixture.metadata.get();
    fixture.seconds = 5;
    fixture.internet = nlohmann::json{{"internet", true}, {"gateway", {{"interface", "WAN2"}}}};
    fixture.interface = nlohmann::json{{"id", "WAN2"}, {"address", "198.51.100.2"}};
    InterfaceMonitor::Event event;
    event.route_changed = true;
    const int calls = fixture.total_calls();
    CHECK_FALSE(fixture.metadata.invalidate(event)); // unrelated main-table route
    CHECK(fixture.metadata.get().at("wan_address") == "192.0.2.1");
    event.default_route_changed = true;
    CHECK(fixture.metadata.invalidate(event));
    CHECK(fixture.total_calls() == calls); // no I/O in the callback
    CHECK(fixture.metadata.get().at("wan_address") == "198.51.100.2");
    CHECK(fixture.calls["/show/internet/status"] == 2);
    CHECK(fixture.calls["/show/interface/WAN2"] == 1);
    CHECK(fixture.calls["/show/ip/hotspot"] == 1);
    CHECK(fixture.calls["/show/version"] == 1);
}

TEST_CASE("router metadata neighbor bursts refresh hotspot only with a fixed cooldown") {
    MetadataFixture fixture;
    (void)fixture.metadata.get();
    fixture.seconds = 1;
    fixture.hotspot = nlohmann::json{{"host", nlohmann::json::array()}};
    InterfaceMonitor::Event event;
    event.neighbor_changed = true;
    for (int index = 0; index < 100; ++index) CHECK(fixture.metadata.invalidate(event));
    CHECK(fixture.metadata.get().at("clients_total") == 2);
    fixture.seconds = 5;
    CHECK(fixture.metadata.get().at("clients_total") == 0);
    CHECK(fixture.calls["/show/ip/hotspot"] == 2);
    CHECK(fixture.calls["/show/internet/status"] == 1);
    CHECK(fixture.calls["/show/interface/WAN1"] == 1);
    CHECK(fixture.calls["/show/version"] == 1);
    CHECK(fixture.metadata.get().at("clients_active") == 0);
    CHECK(fixture.calls["/show/ip/hotspot"] == 2);
}

TEST_CASE("router metadata gaps and link changes invalidate observations but not version") {
    MetadataFixture fixture;
    (void)fixture.metadata.get();
    InterfaceMonitor::Event event;
    SUBCASE("netlink gap") { event.observation_gap = true; }
    SUBCASE("link topology") { event.topology_changed = true; }
    SUBCASE("administrative transition") { event.administrative_state_changed = true; }
    fixture.seconds = 5;
    CHECK(fixture.metadata.invalidate(event));
    (void)fixture.metadata.get();
    CHECK(fixture.calls["/show/ip/hotspot"] == 2);
    CHECK(fixture.calls["/show/internet/status"] == 2);
    CHECK(fixture.calls["/show/version"] == 1);
}

TEST_CASE("router metadata address changes and WAN failures do not refetch hotspot") {
    MetadataFixture fixture;
    (void)fixture.metadata.get();
    fixture.seconds = 5;
    InterfaceMonitor::Event event;
    event.address_changed = true;
    fixture.internet.reset();
    CHECK(fixture.metadata.invalidate(event));
    CHECK(fixture.metadata.get().at("wan_address") == "192.0.2.1");
    fixture.seconds = 10;
    CHECK(fixture.metadata.invalidate(event));
    (void)fixture.metadata.get();
    CHECK(fixture.calls["/show/internet/status"] == 2); // retains error retry interval
    CHECK(fixture.calls["/show/ip/hotspot"] == 1);
    CHECK(fixture.calls["/show/version"] == 1);
}

TEST_CASE("router metadata hotspot failure retains only client observations") {
    MetadataFixture fixture;
    const auto first = fixture.metadata.get();
    REQUIRE(first.at("clients_total") == 2);
    fixture.seconds = 60;
    fixture.hotspot.reset();
    fixture.model = "Router 2";
    fixture.internet = nlohmann::json{
        {"internet", true}, {"gateway", {{"interface", "WAN2"}}}};
    fixture.interface = nlohmann::json{{"id", "WAN2"}, {"address", "198.51.100.2"}};
    const auto next = fixture.metadata.get();
    CHECK(next.at("clients_total") == 2);
    CHECK(next.at("clients_active") == 1);
    CHECK(next.at("wan_address") == "198.51.100.2");
    CHECK(next.at("model") == "Router 2");
    fixture.seconds = 75;
    static_cast<void>(fixture.metadata.get());
    CHECK(fixture.calls["/show/ip/hotspot"] == 2);
    CHECK(fixture.calls["/show/interface/WAN2"] == 1);
}

TEST_CASE("router metadata failed WAN address observation does not freeze clients") {
    MetadataFixture fixture;
    static_cast<void>(fixture.metadata.get());
    fixture.seconds = 60;
    // Status alone cannot prove that the former address disappeared; keep the
    // accepted WAN generation while the unrelated hotspot result progresses.
    fixture.internet = nlohmann::json{
        {"internet", false}, {"gateway", {{"interface", "WAN2"}}}};
    fixture.interface = nlohmann::json{{"error", "temporarily unavailable"}};
    fixture.hotspot = nlohmann::json{{"host", nlohmann::json::array()}};
    const auto value = fixture.metadata.get();
    CHECK(value.at("internet") == true);
    CHECK(value.at("wan_address") == "192.0.2.1");
    CHECK(value.at("clients_total") == 0);
    CHECK(value.at("clients_active") == 0);
    CHECK(fixture.calls["/show/interface/WAN2"] == 1);
}

TEST_CASE("router metadata cold unavailable values are unknown with bounded retries") {
    MetadataFixture fixture;
    fixture.version_ok = false;
    fixture.internet = nlohmann::json{{"error", "unsupported"}};
    fixture.hotspot.reset();
    const auto cold = fixture.metadata.get();
    CHECK(cold.is_object());
    CHECK(cold.empty());
    CHECK_FALSE(cold.contains("clients_total"));
    CHECK_FALSE(cold.contains("internet"));
    CHECK_FALSE(cold.contains("model"));
    CHECK(fixture.total_calls() == 3);
    fixture.seconds = 15;
    CHECK(fixture.metadata.get().empty());
    CHECK(fixture.total_calls() == 3);
    fixture.seconds = 30;
    CHECK(fixture.metadata.get().empty());
    CHECK(fixture.total_calls() == 4);
    CHECK(fixture.calls["/show/ip/hotspot"] == 1);
    CHECK(fixture.calls["/show/internet/status"] == 1);
}

TEST_CASE("router metadata authoritative absence clears stale WAN without raw payloads") {
    MetadataFixture fixture;
    static_cast<void>(fixture.metadata.get());
    fixture.seconds = 60;
    SUBCASE("firmware has no default gateway") {
        fixture.internet = nlohmann::json{{"internet", false}, {"private_field", "hidden"}};
        const auto value = fixture.metadata.get();
        CHECK(value.at("internet") == false);
        CHECK_FALSE(value.contains("wan_address"));
        CHECK(fixture.calls["/show/interface/WAN1"] == 1);
        CHECK_FALSE(value.contains("private_field"));
    }
    SUBCASE("known interface has no address") {
        fixture.interface = nlohmann::json{{"id", "WAN1"}, {"state", "down"}};
        const auto value = fixture.metadata.get();
        CHECK_FALSE(value.contains("wan_address"));
        CHECK(fixture.calls["/show/interface/WAN1"] == 2);
        CHECK_FALSE(value.contains("gateway"));
        CHECK_FALSE(value.contains("host"));
        CHECK_FALSE(value.contains("state"));
    }
}

TEST_CASE("device inventory shares the client cache and never fetches WAN or version") {
    MetadataFixture fixture;
    fixture.hotspot = nlohmann::json{{"host", nlohmann::json::array({
        {{"ip", "192.168.7.19"}, {"name", "Laptop"}, {"hostname", "dhcp-name"},
         {"mac", "02:AB:CD:EF:00:01"}, {"active", true}, {"secret", "never expose"}},
        {{"ip", "10.1.2.3"}, {"hostname", "Phone"}, {"active", false}}
    })}};
    const auto devices = fixture.metadata.devices();
    CHECK(devices.at("available") == true);
    REQUIRE(devices.at("devices").size() == 2);
    CHECK(devices.at("devices").at(1).at("name") == "Laptop");
    CHECK(devices.at("devices").at(1).at("mac") == "02:ab:cd:ef:00:01");
    CHECK_FALSE(devices.dump().find("secret") != std::string::npos);
    CHECK(fixture.total_calls() == 1);
    CHECK(fixture.metadata.devices() == devices);
    CHECK(fixture.total_calls() == 1);
    const auto overview = fixture.metadata.get();
    CHECK_FALSE(overview.contains("device_inventory"));
    CHECK(fixture.calls["/show/ip/hotspot"] == 1);
}

TEST_CASE("device suggestions mark retained observations stale and recover to authoritative empty") {
    MetadataFixture fixture;
    fixture.hotspot = nlohmann::json{{"host", nlohmann::json::array({
        {{"ip", "192.168.1.2"}, {"active", "malformed"}}
    })}};
    CHECK(fixture.metadata.devices().at("available") == true);
    fixture.seconds = 61;
    fixture.hotspot.reset();
    const auto stale = fixture.metadata.devices();
    CHECK(stale.at("available") == false);
    CHECK(stale.at("devices").size() == 1);
    CHECK_FALSE(stale.at("devices").at(0).contains("active"));
    fixture.seconds = 122;
    fixture.hotspot = nlohmann::json{{"host", nlohmann::json::array()}};
    const auto empty = fixture.metadata.devices();
    CHECK(empty.at("available") == true);
    CHECK(empty.at("devices").empty());
}

TEST_CASE("device inventory cold failure is not an empty successful inventory") {
    MetadataFixture fixture;
    fixture.hotspot.reset();
    const auto value = fixture.metadata.devices();
    CHECK(value.at("available") == false);
    CHECK(value.at("devices").empty());
    CHECK(fixture.total_calls() == 1);
}

TEST_CASE("device inventory rejects malformed addresses and exposes only allowlisted fields") {
    const auto result = device_inventory(nlohmann::json::array({
        {{"ip", "127.0.0.1"}}, {{"ip", "::1"}}, {{"ip", "0.0.0.0"}},
        {{"ip", "224.0.0.1"}}, {{"ip", "192.168.1.0/24"}}, {{"ip", 12}},
        {{"ip", "192.168.1.3"}, {"name", "bad\nname"}, {"hostname", "valid"},
         {"mac", "not a mac"}, {"password", "secret"}}
    }));
    REQUIRE(result.at("devices").size() == 1);
    const auto device = result.at("devices").at(0);
    CHECK(device.at("name") == "valid");
    CHECK_FALSE(device.contains("mac"));
    CHECK_FALSE(device.contains("password"));
}

TEST_CASE("device inventory deduplicates addresses but marks conflicting identities") {
    auto hosts = nlohmann::json::array();
    SUBCASE("all observations have identities") {}
    SUBCASE("first observation has no identity") {
        hosts.push_back({{"ip", "192.168.1.3"}});
    }
    hosts.push_back({{"ip", "192.168.1.3"}, {"mac", "02:00:00:00:00:01"}});
    hosts.push_back({{"ip", "192.168.1.3"}, {"mac", "02:00:00:00:00:02"}});
    const auto result = device_inventory(hosts);
    REQUIRE(result.at("devices").size() == 1);
    CHECK(result.at("devices").at(0).at("conflict") == true);
}

TEST_CASE("device inventory repeated observations of one identity are not conflicts") {
    const auto result = device_inventory(nlohmann::json::array({
        {{"ip", "192.168.1.3"}},
        {{"ip", "192.168.1.3"}, {"mac", "02:00:00:00:00:01"}},
        {{"ip", "192.168.1.3"}, {"mac", "02:00:00:00:00:01"}}
    }));
    REQUIRE(result.at("devices").size() == 1);
    CHECK_FALSE(result.at("devices").at(0).contains("conflict"));
    CHECK(result.at("devices").at(0).at("mac") == "02:00:00:00:00:01");
}

TEST_CASE("device cache does not call invalidated data fresh during a refresh") {
    auto now = RouterInfoCache::Clock::now();
    RouterInfoCache* shared = nullptr;
    int calls = 0;
    bool fresh_while_refreshing = true;
    RouterInfoCache cache([&] {
        ++calls;
        if (calls == 2) fresh_while_refreshing = shared->get_snapshot().fresh;
        return RouterInfoCache::FetchResult{nlohmann::json{{"generation", calls}}, true};
    }, std::chrono::seconds(60), std::chrono::seconds(60), [&] { return now; },
       std::chrono::seconds(5));
    shared = &cache;
    CHECK(cache.get_snapshot().fresh);
    cache.invalidate();
    CHECK_FALSE(cache.get_snapshot().fresh); // event cooldown, no refetch yet
    now += std::chrono::seconds(5);
    const auto next = cache.get_snapshot();
    CHECK_FALSE(fresh_while_refreshing);
    CHECK(next.fresh);
    CHECK(next.value.at("generation") == 2);
    CHECK(calls == 2);
}

TEST_CASE("device inventory is bounded") {
    auto hosts = nlohmann::json::array();
    for (int i = 0; i < 600; ++i) {
        hosts.push_back({{"ip", "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256)}});
    }
    const auto result = device_inventory(hosts);
    CHECK(result.at("devices").size() == 512);
    CHECK(result.at("truncated") == true);
}

} // namespace keen_pbr3
