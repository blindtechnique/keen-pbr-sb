#include <doctest/doctest.h>

#include "../src/api/router_info_metadata.hpp"

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

} // namespace keen_pbr3
