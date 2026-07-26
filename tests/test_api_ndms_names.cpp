#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_ndms_names.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

std::string ndms_payload(const std::string& label = "Office VPN") {
    return nlohmann::json{
        {"Wireguard2",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard2"},
          {"description", label},
          {"role", "client"},
          {"connected", "yes"},
          {"link", true}}},
    }.dump();
}

} // namespace

TEST_CASE("NDMS handler cache preserves its last good catalog") {
    enum class FetchMode {
        valid,
        transport_failure,
        malformed_json,
        rci_error,
        empty_object,
    };

    auto now = NdmsCatalogCache::Clock::time_point{};
    auto mode = FetchMode::valid;
    auto response = ndms_payload();
    int fetch_count = 0;
    NdmsCatalogCache cache(
        [&]() -> std::string {
            ++fetch_count;
            switch (mode) {
            case FetchMode::valid:
                return response;
            case FetchMode::transport_failure:
                throw std::runtime_error("temporary RCI outage");
            case FetchMode::malformed_json:
                return "{not-json";
            case FetchMode::rci_error:
                return R"({"error":{"code":"temporary","message":"busy"}})";
            case FetchMode::empty_object:
                return "{}";
            }
            throw std::runtime_error("unreachable fetch mode");
        },
        30s,
        5s,
        [&] {
            return now;
        });

    const auto first = cache.get();
    CHECK(first.status == NdmsCatalogCacheStatus::fresh);
    CHECK(first.catalog.firmware_available);
    REQUIRE(first.catalog.tunnels.size() == 1);
    CHECK(first.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 1);

    now += 31s;
    mode = FetchMode::transport_failure;
    const auto transport_failure = cache.get();
    CHECK(transport_failure.status == NdmsCatalogCacheStatus::stale);
    CHECK(transport_failure.catalog.firmware_available);
    CHECK(transport_failure.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 2);

    now += 1s;
    CHECK(cache.get().status == NdmsCatalogCacheStatus::stale);
    CHECK(fetch_count == 2);

    now += 5s;
    mode = FetchMode::malformed_json;
    const auto parse_failure = cache.get();
    CHECK(parse_failure.status == NdmsCatalogCacheStatus::stale);
    CHECK(parse_failure.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 3);

    now += 5s;
    mode = FetchMode::rci_error;
    const auto rci_error = cache.get();
    CHECK(rci_error.status == NdmsCatalogCacheStatus::stale);
    CHECK(rci_error.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 4);

    now += 5s;
    mode = FetchMode::empty_object;
    const auto empty_object = cache.get();
    CHECK(empty_object.status == NdmsCatalogCacheStatus::stale);
    CHECK(empty_object.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 5);

    now += 5s;
    mode = FetchMode::valid;
    response = ndms_payload("Branch VPN");
    const auto recovered = cache.get();
    CHECK(recovered.status == NdmsCatalogCacheStatus::fresh);
    CHECK(recovered.catalog.tunnels.front().label == "Branch VPN");
    CHECK(fetch_count == 6);
}

TEST_CASE("NDMS handler cache returns safe unavailable data without a snapshot") {
    auto now = NdmsCatalogCache::Clock::time_point{};
    auto response =
        std::string(R"({"error":{"code":"not_supported","message":"unknown command"}})");
    int fetch_count = 0;
    NdmsCatalogCache cache(
        [&] {
            ++fetch_count;
            return response;
        },
        30s,
        5s,
        [&] {
            return now;
        });

    const auto unavailable = cache.get();
    CHECK(unavailable.status == NdmsCatalogCacheStatus::unavailable);
    CHECK_FALSE(unavailable.catalog.firmware_available);
    CHECK(unavailable.catalog.tunnels.empty());
    CHECK(unavailable.catalog.names.is_object());
    CHECK(unavailable.catalog.names.empty());
    CHECK(fetch_count == 1);

    now += 1s;
    CHECK(cache.get().status == NdmsCatalogCacheStatus::unavailable);
    CHECK(fetch_count == 1);

    now += 5s;
    response = ndms_payload();
    const auto recovered = cache.get();
    CHECK(recovered.status == NdmsCatalogCacheStatus::fresh);
    CHECK(recovered.catalog.firmware_available);
    CHECK(fetch_count == 2);
}

TEST_CASE("NDMS handler cache coalesces concurrent refreshes") {
    std::atomic<int> fetch_count{0};
    std::mutex fetch_mutex;
    std::condition_variable fetch_condition;
    bool fetch_started = false;
    bool release_fetch = false;

    NdmsCatalogCache cache(
        [&] {
            fetch_count.fetch_add(1, std::memory_order_relaxed);
            std::unique_lock<std::mutex> lock(fetch_mutex);
            fetch_started = true;
            fetch_condition.notify_all();
            fetch_condition.wait(
                lock,
                [&] {
                    return release_fetch;
                });
            return ndms_payload();
        },
        NdmsCatalogCache::Clock::duration::zero(),
        5s);

    auto first = std::async(
        std::launch::async,
        [&] {
            return cache.get();
        });
    {
        std::unique_lock<std::mutex> lock(fetch_mutex);
        fetch_condition.wait(
            lock,
            [&] {
                return fetch_started;
            });
    }

    std::atomic<bool> second_started{false};
    auto second = std::async(
        std::launch::async,
        [&] {
            second_started.store(true, std::memory_order_release);
            return cache.get();
        });
    while (!second_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(20ms);

    {
        std::lock_guard<std::mutex> lock(fetch_mutex);
        release_fetch = true;
    }
    fetch_condition.notify_all();

    const auto first_result = first.get();
    const auto second_result = second.get();
    CHECK(first_result.status == NdmsCatalogCacheStatus::fresh);
    CHECK(second_result.status == NdmsCatalogCacheStatus::fresh);
    CHECK(fetch_count.load(std::memory_order_relaxed) == 1);
}

TEST_CASE("NDMS read-only endpoints share the cache and safety contract") {
    int fetch_count = 0;
    NdmsCatalogCache cache(
        [&] {
            ++fetch_count;
            return ndms_payload();
        });

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18195");
    ApiServer server(config);
    register_ndms_names_handler_for_tests(server, cache, {"nwg2"});
    server.start();

    httplib::Client client("127.0.0.1", 18195);
    const auto names_response = client.Get("/api/system/interface-names");
    const auto inventory_response =
        client.Get("/api/system/ndms/interfaces");
    server.stop();

    REQUIRE(names_response != nullptr);
    REQUIRE(inventory_response != nullptr);
    CHECK(names_response->status == 200);
    CHECK(inventory_response->status == 200);
    CHECK(fetch_count == 1);

    const auto names = nlohmann::json::parse(names_response->body);
    CHECK(names["available"] == true);
    CHECK(names["names"]["nwg2"]["label"] == "Office VPN");
    CHECK(names["names"]["nwg2"]["firmware_interface_name"] ==
          "Wireguard2");

    const auto inventory = nlohmann::json::parse(inventory_response->body);
    CHECK(inventory["available"] == true);
    CHECK(inventory["read_only"] == true);
    CHECK(inventory["mutation_mode"] == "disabled");
    CHECK(inventory["required_guards"] ==
          nlohmann::json::array(
              {"typed_rci",
               "automatic_backup",
               "ownership_check",
               "optimistic_revision"}));
    REQUIRE(inventory["interfaces"].size() == 1);
    CHECK(inventory["interfaces"][0]["id"] == "Wireguard2");
    CHECK(inventory["interfaces"][0]["firmware_interface_name"] ==
          "Wireguard2");
    CHECK(inventory["interfaces"][0]["kernel_name"] == "nwg2");
    CHECK(inventory["interfaces"][0]["kind"] == "wireguard");
    CHECK(inventory["interfaces"][0]["owner"] == "keenetic");
    CHECK(inventory["interfaces"][0]["role"] == "client");
    CHECK(inventory["interfaces"][0]["capabilities"]["can_edit"] == false);
    CHECK(inventory["interfaces"][0]["capabilities"]["can_delete"] == false);
    CHECK(inventory["interfaces"][0]["capabilities"]["can_hide"] == false);
    CHECK(inventory["interfaces"][0]["capabilities"]["backup_required"] ==
          true);
    const auto& readiness =
        inventory["interfaces"][0]["management_readiness"];
    CHECK(readiness["candidate"] == true);
    CHECK(readiness["identity_stable"] == true);
    CHECK(readiness["configuration_snapshot_available"] == false);
    CHECK(
        readiness["observed_revision"].get<std::string>().rfind(
            "ndms-v1-",
            0) == 0);
    CHECK(readiness["blockers"] ==
          nlohmann::json::array(
              {"typed_rci_unavailable",
               "automatic_backup_unavailable",
               "ownership_unknown",
               "optimistic_revision_unavailable"}));
}

} // namespace keen_pbr3

#endif // WITH_API
