#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_ndms_names.hpp"

#include <algorithm>
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

std::string ndms_mutation_payload() {
    return nlohmann::json{
        {"Wireguard5",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard5"},
          {"description", "Panel WG"},
          {"role", "client"}}},
        {"Wireguard6",
         {{"type", "Amnezia WireGuard"},
          {"interface-name", "Wireguard6"},
          {"description", "Deleted AWG"},
          {"role", "client"}}},
        {"Wireguard7",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard7"},
          {"description", "Foreign WG"},
          {"role", "client"}}},
        {"OpenVPN1",
         {{"type", "OpenVPN"},
          {"interface-name", "OpenVPN1"},
          {"description", "Foreign OpenVPN"},
          {"role", "client"}}},
    }.dump();
}

NdmsNativeInventoryProjection valid_native_projection(
    const std::vector<NdmsTunnelInterface>& tunnels,
    const bool catalog_fresh) {
    NdmsNativeOwnershipInspection ownership;
    ownership.readable = true;
    ownership.claims = {
        NdmsNativeOwnershipInspectionItem{
            "Wireguard5",
            NdmsNativeTunnelImportKind::wireguard,
            NdmsNativeOwnershipLifecycle::active_running_only,
            "ndms-native-owner-v3-" + std::string(64U, 'a'),
        },
        NdmsNativeOwnershipInspectionItem{
            "Wireguard6",
            NdmsNativeTunnelImportKind::amnezia_wireguard,
            NdmsNativeOwnershipLifecycle::
                deleted_save_acknowledged_unverified,
            "ndms-native-owner-tombstone-v1-" +
                std::string(64U, 'b'),
        },
        NdmsNativeOwnershipInspectionItem{
            "Wireguard8",
            NdmsNativeTunnelImportKind::wireguard,
            NdmsNativeOwnershipLifecycle::
                deleted_save_acknowledged_unverified,
            "ndms-native-owner-tombstone-v1-" +
                std::string(64U, 'c'),
            true,
        },
    };
    return project_ndms_native_inventory(
        tunnels,
        catalog_fresh,
        ownership,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);
}

nlohmann::json inventory_row(
    const nlohmann::json& inventory,
    const std::string& interface_name) {
    const auto found = std::find_if(
        inventory.at("interfaces").begin(),
        inventory.at("interfaces").end(),
        [&](const auto& row) {
            return row.at("firmware_interface_name") == interface_name;
        });
    REQUIRE(found != inventory.at("interfaces").end());
    return *found;
}

std::string ndms_vpn_services_payload() {
    return nlohmann::json{
        {"message",
         {
             "crypto ike policy VPNL2TPServer",
             "    mode ikev1",
             "crypto ike policy VirtualIPServer",
             "    mode ikev1",
             "crypto ike policy VirtualIPServerIKE2",
             "    mode ikev2",
             "crypto map VPNL2TPServer",
             "    set-profile VPNL2TPServer",
             "    l2tp-server range 172.16.2.33 172.16.2.34",
             "    l2tp-server interface Home",
             "    l2tp-server enable",
             "    enable",
             "crypto map VirtualIPServer",
             "    set-profile VirtualIPServer",
             "    virtual-ip range 172.20.0.1 172.20.0.2",
             "    virtual-ip interface Bridge0",
             "    virtual-ip enable",
             "    enable",
             "crypto map VirtualIPServerIKE2",
             "    set-profile VirtualIPServerIKE2",
             "    virtual-ip range 172.20.8.1 172.20.8.2",
             "    virtual-ip interface Bridge0",
             "    virtual-ip enable",
             "    enable",
             "sstp-server",
             "    interface Home",
             "    pool-range 172.16.1.33 2",
             "service sstp-server",
             "oc-server",
             "    interface Home",
             "    pool-range 172.30.0.17 3",
             "service oc-server",
         }},
    }.dump();
}

} // namespace

TEST_CASE("NDMS catalog cache peek never triggers a fetch") {
    std::atomic<int> fetches{0};
    NdmsCatalogCache cache([&fetches] {
        ++fetches;
        return ndms_payload();
    });

    const auto before_refresh = cache.peek();
    CHECK(
        before_refresh.status ==
        NdmsCatalogCacheStatus::unavailable);
    CHECK_FALSE(before_refresh.refreshed);
    CHECK(before_refresh.observation_generation == 0U);
    CHECK(before_refresh.observation_epoch == 0U);
    CHECK(before_refresh.invalidation_epoch == 0U);
    CHECK(fetches.load() == 0);

    const auto refreshed = cache.get();
    CHECK(refreshed.status == NdmsCatalogCacheStatus::fresh);
    CHECK(refreshed.refreshed);
    CHECK(refreshed.observation_generation == 1U);
    CHECK(refreshed.observation_epoch == 0U);
    CHECK(refreshed.invalidation_epoch == 0U);
    CHECK(fetches.load() == 1);

    const auto cached = cache.peek();
    CHECK(cached.status == NdmsCatalogCacheStatus::fresh);
    CHECK_FALSE(cached.refreshed);
    CHECK(cached.observation_generation ==
          refreshed.observation_generation);
    CHECK(cached.observation_epoch == refreshed.observation_epoch);
    CHECK(cached.invalidation_epoch == refreshed.invalidation_epoch);
    CHECK(fetches.load() == 1);
}

TEST_CASE("NDMS catalog forced refresh bypasses TTL but remains throttled") {
    auto now = NdmsCatalogCache::Clock::time_point{};
    int fetch_count = 0;
    std::string label = "Office VPN";
    NdmsCatalogCache cache(
        [&] {
            ++fetch_count;
            return ndms_payload(label);
        },
        30s,
        5s,
        [&] {
            return now;
        });

    const auto initial = cache.get();
    CHECK(initial.status == NdmsCatalogCacheStatus::fresh);
    CHECK(initial.observation_generation == 1U);
    CHECK(fetch_count == 1);

    label = "Renumbered VPN";
    now += 1s;
    const auto first_forced = cache.force_refresh();
    CHECK(first_forced.refreshed);
    CHECK(first_forced.observation_generation == 2U);
    CHECK(first_forced.catalog.tunnels.front().label == "Renumbered VPN");
    CHECK(fetch_count == 2);

    label = "Too soon";
    now += 1s;
    const auto throttled = cache.force_refresh();
    CHECK_FALSE(throttled.refreshed);
    CHECK(throttled.status == NdmsCatalogCacheStatus::fresh);
    CHECK(throttled.observation_generation == 2U);
    CHECK(throttled.catalog.tunnels.front().label == "Renumbered VPN");
    CHECK(fetch_count == 2);

    now += 5s;
    const auto forced = cache.force_refresh();
    CHECK(forced.status == NdmsCatalogCacheStatus::fresh);
    CHECK(forced.refreshed);
    CHECK(forced.observation_generation == 3U);
    REQUIRE(forced.catalog.tunnels.size() == 1);
    CHECK(forced.catalog.tunnels.front().label == "Too soon");
    CHECK(fetch_count == 3);
}

TEST_CASE("NDMS catalog peek becomes stale when verified TTL expires") {
    auto now = NdmsCatalogCache::Clock::time_point{};
    NdmsCatalogCache cache(
        [] {
            return ndms_payload();
        },
        30s,
        5s,
        [&] {
            return now;
        });

    CHECK(cache.get().status == NdmsCatalogCacheStatus::fresh);
    now += 29s;
    CHECK(cache.peek().status == NdmsCatalogCacheStatus::fresh);
    now += 1s;
    const auto expired = cache.peek();
    CHECK(expired.status == NdmsCatalogCacheStatus::stale);
    CHECK_FALSE(expired.refreshed);
}

TEST_CASE("NDMS catalog invalidation revokes authority and permits immediate refresh") {
    auto now = NdmsCatalogCache::Clock::time_point{};
    int fetch_count = 0;
    std::string label = "Office VPN";
    NdmsCatalogCache cache(
        [&] {
            ++fetch_count;
            return ndms_payload(label);
        },
        30s,
        5s,
        [&] {
            return now;
        });

    const auto initial = cache.force_refresh();
    CHECK(initial.status == NdmsCatalogCacheStatus::fresh);
    CHECK(initial.observation_generation == 1U);
    CHECK(initial.observation_epoch == 0U);
    CHECK(initial.invalidation_epoch == 0U);
    CHECK(fetch_count == 1);

    now += 1s;
    cache.invalidate();
    const auto invalidated = cache.peek();
    CHECK(invalidated.status == NdmsCatalogCacheStatus::stale);
    CHECK_FALSE(invalidated.refreshed);
    CHECK(invalidated.observation_generation == 1U);
    CHECK(invalidated.observation_epoch == 0U);
    CHECK(invalidated.invalidation_epoch == 1U);
    CHECK(fetch_count == 1);

    label = "Renumbered VPN";
    const auto refreshed = cache.force_refresh();
    CHECK(refreshed.status == NdmsCatalogCacheStatus::fresh);
    CHECK(refreshed.refreshed);
    CHECK(refreshed.observation_generation == 2U);
    CHECK(refreshed.observation_epoch == 1U);
    CHECK(refreshed.invalidation_epoch == 1U);
    CHECK(refreshed.catalog.tunnels.front().label == "Renumbered VPN");
    CHECK(fetch_count == 2);
}

TEST_CASE("NDMS catalog invalidation rejects an older in-flight response") {
    std::atomic<int> fetch_count{0};
    std::mutex fetch_mutex;
    std::condition_variable fetch_condition;
    bool first_fetch_started = false;
    bool release_first_fetch = false;

    NdmsCatalogCache cache(
        [&] {
            const auto attempt =
                fetch_count.fetch_add(1, std::memory_order_relaxed) + 1;
            if (attempt == 1) {
                std::unique_lock<std::mutex> lock(fetch_mutex);
                first_fetch_started = true;
                fetch_condition.notify_all();
                fetch_condition.wait(
                    lock,
                    [&] {
                        return release_first_fetch;
                    });
                return ndms_payload("Pre-event catalog");
            }
            return ndms_payload("Post-event catalog");
        });

    auto old_refresh = std::async(
        std::launch::async,
        [&] {
            return cache.force_refresh();
        });
    {
        std::unique_lock<std::mutex> lock(fetch_mutex);
        fetch_condition.wait(
            lock,
            [&] {
                return first_fetch_started;
            });
    }

    cache.invalidate();
    std::atomic<bool> replacement_started{false};
    auto replacement = std::async(
        std::launch::async,
        [&] {
            replacement_started.store(true, std::memory_order_release);
            return cache.force_refresh();
        });
    while (!replacement_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    // The post-invalidation forced caller must join the old single-flight
    // request first, rather than racing a duplicate fetch alongside it.
    CHECK(replacement.wait_for(20ms) == std::future_status::timeout);
    {
        std::lock_guard<std::mutex> lock(fetch_mutex);
        release_first_fetch = true;
    }
    fetch_condition.notify_all();

    const auto rejected = old_refresh.get();
    CHECK(
        rejected.status ==
        NdmsCatalogCacheStatus::unavailable);
    CHECK_FALSE(rejected.refreshed);
    CHECK(rejected.observation_generation == 0U);
    CHECK(rejected.observation_epoch == 0U);
    CHECK(rejected.invalidation_epoch == 1U);
    const auto replacement_result = replacement.get();
    CHECK(replacement_result.status == NdmsCatalogCacheStatus::fresh);
    CHECK(replacement_result.refreshed);
    CHECK(replacement_result.observation_generation == 1U);
    CHECK(replacement_result.observation_epoch == 1U);
    CHECK(replacement_result.invalidation_epoch == 1U);
    CHECK(
        replacement_result.catalog.tunnels.front().label ==
        "Post-event catalog");
    CHECK(fetch_count.load(std::memory_order_relaxed) == 2);
}

TEST_CASE(
    "NDMS catalog invalidation does not inherit an older failed refresh throttle") {
    bool malformed_response = false;
    SUBCASE("transport failure") {
        malformed_response = false;
    }
    SUBCASE("malformed response") {
        malformed_response = true;
    }

    auto now = NdmsCatalogCache::Clock::time_point{};
    std::atomic<int> fetch_count{0};
    std::mutex fetch_mutex;
    std::condition_variable fetch_condition;
    bool stale_fetch_started = false;
    bool release_stale_fetch = false;

    NdmsCatalogCache cache(
        [&]() -> std::string {
            const auto attempt =
                fetch_count.fetch_add(1, std::memory_order_relaxed) + 1;
            if (attempt == 1) {
                return ndms_payload("Initial catalog");
            }
            if (attempt == 2) {
                std::unique_lock<std::mutex> lock(fetch_mutex);
                stale_fetch_started = true;
                fetch_condition.notify_all();
                fetch_condition.wait(
                    lock,
                    [&] {
                        return release_stale_fetch;
                    });
                if (malformed_response) {
                    return "{";
                }
                throw std::runtime_error("simulated transport failure");
            }
            return ndms_payload("Replacement catalog");
        },
        30s,
        5s,
        [&] {
            return now;
        });

    const auto initial = cache.force_refresh();
    CHECK(initial.status == NdmsCatalogCacheStatus::fresh);
    CHECK(initial.observation_generation == 1U);
    CHECK(initial.observation_epoch == 0U);
    CHECK(initial.invalidation_epoch == 0U);
    now += 5s;
    auto stale_refresh = std::async(
        std::launch::async,
        [&] {
            return cache.force_refresh();
        });
    {
        std::unique_lock<std::mutex> lock(fetch_mutex);
        fetch_condition.wait(
            lock,
            [&] {
                return stale_fetch_started;
            });
    }

    cache.invalidate();
    auto replacement_refresh = std::async(
        std::launch::async,
        [&] {
            return cache.force_refresh();
        });
    CHECK(
        replacement_refresh.wait_for(20ms) ==
        std::future_status::timeout);

    {
        std::lock_guard<std::mutex> lock(fetch_mutex);
        release_stale_fetch = true;
    }
    fetch_condition.notify_all();

    const auto stale_result = stale_refresh.get();
    CHECK(stale_result.status == NdmsCatalogCacheStatus::stale);
    CHECK_FALSE(stale_result.refreshed);
    CHECK(stale_result.observation_generation == 1U);
    CHECK(stale_result.observation_epoch == 0U);
    CHECK(stale_result.invalidation_epoch == 1U);

    // No clock advance: the invalidated attempt belongs to the old topology
    // epoch and must not impose its five-second failure throttle on the
    // replacement observation.
    const auto replacement_result = replacement_refresh.get();
    CHECK(replacement_result.status == NdmsCatalogCacheStatus::fresh);
    CHECK(replacement_result.refreshed);
    CHECK(replacement_result.observation_generation == 2U);
    CHECK(replacement_result.observation_epoch == 1U);
    CHECK(replacement_result.invalidation_epoch == 1U);
    CHECK(
        replacement_result.catalog.tunnels.front().label ==
        "Replacement catalog");
    CHECK(fetch_count.load(std::memory_order_relaxed) == 3);
}

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
    CHECK(first.observation_generation == 1U);
    CHECK(first.observation_epoch == 0U);
    CHECK(first.invalidation_epoch == 0U);
    CHECK(first.catalog.firmware_available);
    REQUIRE(first.catalog.tunnels.size() == 1);
    CHECK(first.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 1);

    now += 31s;
    mode = FetchMode::transport_failure;
    const auto transport_failure = cache.get();
    CHECK(transport_failure.status == NdmsCatalogCacheStatus::stale);
    CHECK(transport_failure.observation_generation ==
          first.observation_generation);
    CHECK(transport_failure.observation_epoch == first.observation_epoch);
    CHECK(transport_failure.invalidation_epoch == first.invalidation_epoch);
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
    CHECK(parse_failure.observation_generation ==
          first.observation_generation);
    CHECK(parse_failure.observation_epoch == first.observation_epoch);
    CHECK(parse_failure.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 3);

    now += 5s;
    mode = FetchMode::rci_error;
    const auto rci_error = cache.get();
    CHECK(rci_error.status == NdmsCatalogCacheStatus::stale);
    CHECK(rci_error.observation_generation ==
          first.observation_generation);
    CHECK(rci_error.observation_epoch == first.observation_epoch);
    CHECK(rci_error.catalog.tunnels.front().label == "Office VPN");
    CHECK(fetch_count == 4);

    now += 5s;
    mode = FetchMode::empty_object;
    const auto empty_object = cache.get();
    CHECK(empty_object.status == NdmsCatalogCacheStatus::stale);
    CHECK(empty_object.observation_generation ==
          first.observation_generation);
    CHECK(empty_object.observation_epoch == first.observation_epoch);
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
    CHECK(first_result.refreshed);
    CHECK(second_result.refreshed);
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
    CHECK(inventory_response->get_header_value("Cache-Control") ==
          "no-store");
    CHECK(fetch_count == 1);

    const auto names = nlohmann::json::parse(names_response->body);
    CHECK(names["available"] == true);
    CHECK(names["catalog_status"] == "fresh");
    CHECK(names["names"]["nwg2"]["label"] == "Office VPN");
    CHECK(names["names"]["nwg2"]["firmware_interface_name"] ==
          "Wireguard2");

    const auto inventory = nlohmann::json::parse(inventory_response->body);
    CHECK(inventory["available"] == true);
    CHECK(inventory["catalog_status"] == "fresh");
    CHECK(inventory["read_only"] == true);
    CHECK(inventory["mutation_mode"] == "disabled");
    CHECK(inventory["native_mutation_status"] ==
          nlohmann::json{
              {"advisory", true},
              {"ownership_inventory_available", false},
              {"observed_import_journal_state", "unavailable"},
              {"observed_delete_journal_state", "unavailable"},
          });
    CHECK(inventory["retained_deletions"] == nlohmann::json::array());
    CHECK(inventory["required_guards"] ==
          nlohmann::json::array(
              {"typed_rci",
               "automatic_backup",
               "ownership_check",
               "optimistic_revision"}));
    CHECK(inventory["native_import_readiness"] ==
          nlohmann::json{
              {"preview_only", true},
              {"apply_available", false},
              {"operation", "interface.wireguard.import"},
              {"request_name", ""},
              {"allocator_range",
               {{"prefix", "Wireguard"},
                {"first_index", 0},
                {"last_index", 126}}},
              {"eligible_returned_targets",
               {{"prefix", "Wireguard"},
                {"first_index", 5},
                {"last_index", 98}}},
              {"protected_targets",
                nlohmann::json::array(
                    {nlohmann::json{{"prefix", "Wireguard"},
                                    {"first_index", 0},
                                    {"last_index", 4}},
                     nlohmann::json{{"prefix", "Wireguard"},
                                    {"first_index", 99},
                                    {"last_index", 126}}})},
              {"journal_state", "dormant"},
              {"reconcile_barrier_state", "dormant"},
              {"blockers",
               nlohmann::json::array(
                   {"writer_disabled",
                    "allocator_range_unfenced",
                    "recovery_journal_not_integrated",
                    "reconcile_barrier_not_integrated"})}});
    REQUIRE(inventory["interfaces"].size() == 1);
    CHECK(inventory["interfaces"][0]["id"] == "Wireguard2");
    CHECK(inventory["interfaces"][0]["firmware_interface_name"] ==
          "Wireguard2");
    CHECK(inventory["interfaces"][0]["kernel_name"] == "nwg2");
    CHECK(inventory["interfaces"][0]["kind"] == "wireguard");
    CHECK(inventory["interfaces"][0]["owner"] == "keenetic");
    CHECK(inventory["interfaces"][0]["role"] == "client");
    CHECK(
        inventory["interfaces"][0]["internal_vpn_server_candidate"] ==
        false);
    CHECK(
        inventory["interfaces"][0]
                 ["internal_vpn_server_role_confirmation_required"] ==
        false);
    CHECK(inventory["interfaces"][0]["capabilities"]["can_edit"] == false);
    CHECK(inventory["interfaces"][0]["capabilities"]["can_delete"] == false);
    CHECK(inventory["interfaces"][0]["capabilities"]["can_hide"] == false);
    CHECK(inventory["interfaces"][0]["capabilities"]["backup_required"] ==
          true);
    CHECK(inventory["interfaces"][0]["native_mutation"] ==
          nlohmann::json{
              {"ownership_state", "unavailable"},
              {"delete_candidate", false},
              {"delete_blockers",
               nlohmann::json::array(
                   {"ownership_inventory_unavailable"})},
              {"deferred_authoritative_checks",
               nlohmann::json::array()},
          });
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

TEST_CASE(
    "NDMS public inventories redact exact native import marker labels") {
    const auto private_transaction_id = std::string(32U, 'c');
    const auto private_marker =
        "kpbr-ni-v1-" + private_transaction_id;
    NdmsCatalogCache cache([&] {
        return nlohmann::json{
            {"Wireguard5",
             {{"type", "Wireguard"},
              {"interface-name", "Wireguard5"},
              {"description", private_marker},
              {"role", "client"}}},
            {"Wireguard6",
             {{"type", "Wireguard"},
              {"interface-name", "Wireguard6"},
              {"description", "Normal VPN"},
              {"role", "client"}}},
            {"Wireguard7",
             {{"type", "Wireguard"},
              {"interface-name", "Wireguard7"},
              {"description", "Мой AWG · " + private_marker},
              {"role", "client"}}},
        }.dump();
    });

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18201");
    ApiServer server(config);
    register_ndms_names_handler_for_tests(
        server, cache, {"nwg5", "nwg6", "nwg7"});
    server.start();

    httplib::Client client("127.0.0.1", 18201);
    const auto names_response =
        client.Get("/api/system/interface-names");
    const auto inventory_response =
        client.Get("/api/system/ndms/interfaces");
    server.stop();

    REQUIRE(names_response != nullptr);
    REQUIRE(inventory_response != nullptr);
    REQUIRE(names_response->status == 200);
    REQUIRE(inventory_response->status == 200);
    const auto names = nlohmann::json::parse(names_response->body);
    const auto inventory = nlohmann::json::parse(inventory_response->body);
    CHECK(names["names"]["nwg5"]["label"] == "Wireguard5");
    CHECK(names["names"]["nwg6"]["label"] == "Normal VPN");
    CHECK(names["names"]["nwg7"]["label"] == "Мой AWG");
    CHECK(inventory_row(inventory, "Wireguard5")["label"] ==
          "Wireguard5");
    CHECK(inventory_row(inventory, "Wireguard6")["label"] ==
          "Normal VPN");
    CHECK(inventory_row(inventory, "Wireguard7")["label"] ==
          "Мой AWG");
    CHECK(names_response->body.find(private_marker) == std::string::npos);
    CHECK(names_response->body.find(private_transaction_id) ==
          std::string::npos);
    CHECK(inventory_response->body.find(private_marker) ==
          std::string::npos);
    CHECK(inventory_response->body.find(private_transaction_id) ==
          std::string::npos);
}

TEST_CASE(
    "NDMS native mutation inventory distinguishes active tombstone and foreign advisory rows") {
    bool fail_fetch = false;
    int fetch_count = 0;
    int projection_count = 0;
    std::vector<bool> observed_freshness;
    NdmsCatalogCache cache([&]() -> std::string {
        ++fetch_count;
        if (fail_fetch) {
            throw std::runtime_error("temporary inventory outage");
        }
        return ndms_mutation_payload();
    });

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18199");
    ApiServer server(config);
    register_ndms_names_handler_for_tests(
        server,
        cache,
        {},
        NdmsNativeImportReadinessProvider{},
        [&](const std::vector<NdmsTunnelInterface>& tunnels,
            const bool catalog_fresh) {
            ++projection_count;
            observed_freshness.push_back(catalog_fresh);
            return valid_native_projection(tunnels, catalog_fresh);
        });
    server.start();

    httplib::Client client("127.0.0.1", 18199);
    const auto fresh_response =
        client.Get("/api/system/ndms/interfaces");
    REQUIRE(fresh_response != nullptr);
    REQUIRE(fresh_response->status == 200);
    CHECK(fresh_response->get_header_value("Cache-Control") ==
          "no-store");
    const auto fresh = nlohmann::json::parse(fresh_response->body);
    CHECK(fresh["read_only"] == true);
    CHECK(fresh["mutation_mode"] == "disabled");
    CHECK(fresh["native_mutation_status"] ==
          nlohmann::json{
              {"advisory", true},
              {"ownership_inventory_available", true},
              {"observed_import_journal_state", "clean"},
              {"observed_delete_journal_state", "clean"},
          });
    REQUIRE(fresh["retained_deletions"].size() == 2U);
    CHECK(fresh["retained_deletions"][0] ==
          nlohmann::json{
              {"interface_name", "Wireguard6"},
              {"ownership_revision",
               "ndms-native-owner-tombstone-v1-" +
                   std::string(64U, 'b')},
              {"forget_candidate", false},
              {"forget_blockers",
               nlohmann::json::array(
                   {"target_present",
                    "ownership_schema_not_forget_capable"})},
              {"deferred_authoritative_checks",
               nlohmann::json::array(
                   {"encrypted_snapshot_or_absence",
                    "keen_pbr_dependencies",
                    "retained_kernel_interface_absence",
                    "fresh_dual_scope_absence"})},
          });
    CHECK(fresh["retained_deletions"][1] ==
          nlohmann::json{
              {"interface_name", "Wireguard8"},
              {"ownership_revision",
               "ndms-native-owner-tombstone-v1-" +
                   std::string(64U, 'c')},
              {"forget_candidate", true},
              {"forget_blockers", nlohmann::json::array()},
              {"deferred_authoritative_checks",
               nlohmann::json::array(
                   {"encrypted_snapshot_or_absence",
                    "keen_pbr_dependencies",
                    "retained_kernel_interface_absence",
                    "fresh_dual_scope_absence"})},
          });
    CHECK_FALSE(fresh["retained_deletions"][1].contains("marker"));
    CHECK_FALSE(
        fresh["retained_deletions"][1].contains("transaction_id"));
    CHECK_FALSE(
        fresh["retained_deletions"][1].contains("snapshot_revision"));
    CHECK_FALSE(fresh["retained_deletions"][1].contains("kernel_name"));
    CHECK(fresh.dump().find("nwg8") == std::string::npos);

    const auto active = inventory_row(fresh, "Wireguard5");
    CHECK(active["capabilities"]["can_delete"] == false);
    CHECK(active["native_mutation"]["ownership_state"] ==
          "panel_owned_active");
    CHECK(active["native_mutation"]["ownership_lifecycle"] ==
          "active_running_only");
    CHECK(active["native_mutation"]["ownership_revision"] ==
          "ndms-native-owner-v3-" + std::string(64U, 'a'));
    CHECK(active["native_mutation"]["delete_candidate"] == true);
    CHECK(active["native_mutation"]["delete_blockers"] ==
          nlohmann::json::array());
    CHECK(active["native_mutation"]["deferred_authoritative_checks"] ==
          nlohmann::json::array(
              {"encrypted_snapshot",
               "keen_pbr_dependencies",
               "direct_ndms_state"}));

    const auto tombstone = inventory_row(fresh, "Wireguard6");
    CHECK(tombstone["native_mutation"]["ownership_state"] ==
          "panel_owned_tombstone");
    CHECK(tombstone["native_mutation"]["ownership_lifecycle"] ==
          "deleted_save_acknowledged_unverified");
    CHECK(tombstone["native_mutation"]["delete_candidate"] == false);
    CHECK(tombstone["native_mutation"]["delete_blockers"] ==
          nlohmann::json::array({"ownership_not_active"}));

    const auto foreign = inventory_row(fresh, "Wireguard7");
    CHECK(foreign["native_mutation"]["ownership_state"] == "foreign");
    CHECK_FALSE(
        foreign["native_mutation"].contains("ownership_revision"));
    CHECK(foreign["native_mutation"]["delete_candidate"] == false);
    CHECK(foreign["native_mutation"]["delete_blockers"] ==
          nlohmann::json::array({"ownership_absent"}));

    const auto unsupported = inventory_row(fresh, "OpenVPN1");
    CHECK(unsupported["native_mutation"]["ownership_state"] ==
          "not_applicable");
    CHECK(unsupported["native_mutation"]["delete_candidate"] == false);
    CHECK(unsupported["native_mutation"]["delete_blockers"] ==
          nlohmann::json::array({"unsupported_kind"}));

    fail_fetch = true;
    cache.invalidate();
    const auto stale_response =
        client.Get("/api/system/ndms/interfaces");
    server.stop();

    REQUIRE(stale_response != nullptr);
    REQUIRE(stale_response->status == 200);
    const auto stale = nlohmann::json::parse(stale_response->body);
    CHECK(stale["catalog_status"] == "stale");
    const auto stale_active = inventory_row(stale, "Wireguard5");
    CHECK(stale_active["native_mutation"]["ownership_state"] ==
          "panel_owned_active");
    CHECK(stale_active["native_mutation"]["delete_candidate"] == false);
    CHECK(stale_active["native_mutation"]["delete_blockers"] ==
          nlohmann::json::array({"catalog_not_fresh"}));
    CHECK(stale_active["capabilities"]["can_delete"] == false);
    CHECK(fetch_count == 2);
    CHECK(projection_count == 2);
    CHECK(observed_freshness == std::vector<bool>{true, false});
}

TEST_CASE(
    "NDMS native mutation inventory rejects a malformed callback as one unavailable batch") {
    int mode = 0;
    int projection_count = 0;
    NdmsCatalogCache cache([] { return ndms_mutation_payload(); });

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18200");
    ApiServer server(config);
    register_ndms_names_handler_for_tests(
        server,
        cache,
        {},
        NdmsNativeImportReadinessProvider{},
        [&](const std::vector<NdmsTunnelInterface>& tunnels,
            const bool catalog_fresh) {
            ++projection_count;
            auto projection =
                valid_native_projection(tunnels, catalog_fresh);
            const auto active = std::find_if(
                projection.interfaces.begin(),
                projection.interfaces.end(),
                [](const auto& row) {
                    return row.interface_name == "Wireguard5";
                });
            REQUIRE(active != projection.interfaces.end());
            switch (mode) {
            case 1:
                projection.interfaces.pop_back();
                break;
            case 2:
                REQUIRE(projection.interfaces.size() > 1U);
                std::swap(
                    projection.interfaces[0], projection.interfaces[1]);
                break;
            case 3:
                active->interface_name = "Wireguard98";
                break;
            case 4:
                active->ownership_state = static_cast<
                    NdmsNativeInventoryOwnershipState>(255U);
                break;
            case 5:
                active->ownership_revision =
                    "PRIVATE_CALLBACK_REVISION_MUST_NOT_ESCAPE";
                break;
            case 6:
                active->delete_candidate = false;
                break;
            case 7:
                projection.observed_delete_journal_state = static_cast<
                    NdmsNativeDeleteWalReadiness>(255U);
                break;
            case 8:
                throw std::runtime_error(
                    "PRIVATE_CALLBACK_EXCEPTION_MUST_NOT_ESCAPE");
            case 9:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                while (projection.retained_deletions.size() <= 94U) {
                    projection.retained_deletions.push_back(
                        projection.retained_deletions.back());
                }
                break;
            case 10:
                REQUIRE(projection.retained_deletions.size() == 2U);
                std::swap(
                    projection.retained_deletions[0],
                    projection.retained_deletions[1]);
                break;
            case 11:
                REQUIRE(projection.retained_deletions.size() == 2U);
                projection.retained_deletions[1].interface_name =
                    projection.retained_deletions[0].interface_name;
                break;
            case 12:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                projection.retained_deletions[0].interface_name =
                    "Wireguard4";
                break;
            case 13:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                projection.retained_deletions[0].ownership_revision =
                    "PRIVATE_CALLBACK_REVISION_MUST_NOT_ESCAPE";
                break;
            case 14:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                projection.retained_deletions[0]
                    .forget_blockers.push_back(
                        static_cast<
                            NdmsNativeRetainedDeletionBlocker>(255U));
                break;
            case 15:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                std::reverse(
                    projection.retained_deletions[0]
                        .forget_blockers.begin(),
                    projection.retained_deletions[0]
                        .forget_blockers.end());
                break;
            case 16:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                REQUIRE_FALSE(
                    projection.retained_deletions[0]
                        .deferred_authoritative_checks.empty());
                projection.retained_deletions[0]
                    .deferred_authoritative_checks[0] =
                    static_cast<
                        NdmsNativeRetainedDeletionDeferredCheck>(255U);
                break;
            case 17:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                std::swap(
                    projection.retained_deletions[0]
                        .deferred_authoritative_checks.front(),
                    projection.retained_deletions[0]
                        .deferred_authoritative_checks.back());
                break;
            case 18:
                REQUIRE(projection.retained_deletions.size() == 2U);
                projection.retained_deletions[1].forget_candidate = false;
                break;
            case 19:
                REQUIRE_FALSE(projection.retained_deletions.empty());
                projection.retained_deletions.erase(
                    projection.retained_deletions.begin());
                break;
            case 20:
                projection.retained_deletions.clear();
                break;
            case 21: {
                const auto live_tombstone = std::find_if(
                    projection.interfaces.begin(),
                    projection.interfaces.end(),
                    [](const auto& row) {
                        return row.interface_name == "Wireguard6";
                    });
                REQUIRE(live_tombstone != projection.interfaces.end());
                live_tombstone->ownership_state =
                    NdmsNativeInventoryOwnershipState::foreign;
                live_tombstone->ownership_lifecycle.reset();
                live_tombstone->ownership_revision.reset();
                live_tombstone->delete_candidate = false;
                live_tombstone->delete_blockers = {
                    NdmsNativeInventoryDeleteBlocker::ownership_absent,
                };
                live_tombstone->deferred_authoritative_checks.clear();
                break;
            }
            default:
                break;
            }
            return projection;
        });
    server.start();

    httplib::Client client("127.0.0.1", 18200);
    for (mode = 1; mode <= 21; ++mode) {
        const auto response =
            client.Get("/api/system/ndms/interfaces");
        REQUIRE(response != nullptr);
        REQUIRE(response->status == 200);
        CHECK(response->get_header_value("Cache-Control") == "no-store");
        const auto inventory = nlohmann::json::parse(response->body);
        CHECK(inventory["native_mutation_status"] ==
              nlohmann::json{
                  {"advisory", true},
                  {"ownership_inventory_available", false},
                  {"observed_import_journal_state", "unavailable"},
                  {"observed_delete_journal_state", "unavailable"},
              });
        CHECK(inventory["retained_deletions"] ==
              nlohmann::json::array());
        for (const auto* name :
             {"Wireguard5", "Wireguard6", "Wireguard7"}) {
            const auto row = inventory_row(inventory, name);
            CHECK(row["capabilities"]["can_delete"] == false);
            CHECK(row["native_mutation"]["ownership_state"] ==
                  "unavailable");
            CHECK(row["native_mutation"]["delete_candidate"] == false);
            CHECK(row["native_mutation"]["delete_blockers"] ==
                  nlohmann::json::array(
                      {"ownership_inventory_unavailable"}));
            CHECK_FALSE(
                row["native_mutation"].contains("ownership_revision"));
        }
        CHECK(response->body.find("PRIVATE_CALLBACK") ==
              std::string::npos);
    }
    server.stop();
    CHECK(projection_count == 21);
}

TEST_CASE("NDMS stale endpoint keeps rows but revokes server-candidate authority") {
    bool fail_fetch = false;
    NdmsCatalogCache cache([&]() -> std::string {
        if (fail_fetch) {
            throw std::runtime_error("temporary RCI outage");
        }
        return nlohmann::json{
            {"Wireguard0",
             {
                 {"type", "Wireguard"},
                 {"interface-name", "Wireguard0"},
                 {"description", "Home server"},
                 {"global", false},
                 {"address", "10.10.0.1/24"},
             }},
        }.dump();
    });

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18196");
    ApiServer server(config);
    register_ndms_names_handler_for_tests(server, cache, {"nwg0"});
    server.start();

    httplib::Client client("127.0.0.1", 18196);
    const auto fresh_response =
        client.Get("/api/system/ndms/interfaces");
    REQUIRE(fresh_response != nullptr);
    REQUIRE(fresh_response->status == 200);
    const auto fresh = nlohmann::json::parse(fresh_response->body);
    CHECK(fresh["available"] == true);
    CHECK(fresh["catalog_status"] == "fresh");
    REQUIRE(fresh["interfaces"].size() == 1);
    CHECK(
        fresh["interfaces"][0]["internal_vpn_server_candidate"] ==
        true);
    CHECK(
        fresh["interfaces"][0]
             ["internal_vpn_server_role_confirmation_required"] ==
        true);

    fail_fetch = true;
    cache.invalidate();
    const auto stale_response =
        client.Get("/api/system/ndms/interfaces");
    server.stop();

    REQUIRE(stale_response != nullptr);
    REQUIRE(stale_response->status == 200);
    const auto stale = nlohmann::json::parse(stale_response->body);
    CHECK(stale["available"] == false);
    CHECK(stale["catalog_status"] == "stale");
    CHECK(stale["native_import_readiness"]["preview_only"] == true);
    CHECK(stale["native_import_readiness"]["apply_available"] == false);
    CHECK(stale["native_import_readiness"]["journal_state"] ==
          "dormant");
    REQUIRE(stale["interfaces"].size() == 1);
    CHECK(stale["interfaces"][0]["id"] == "Wireguard0");
    CHECK(
        stale["interfaces"][0]["internal_vpn_server_candidate"] ==
        false);
    CHECK(
        stale["interfaces"][0]
             ["internal_vpn_server_role_confirmation_required"] ==
        false);
}

TEST_CASE("NDMS native import readiness stays report-only for every boot state") {
    std::atomic<int> ndms_fetch_count{0};
    NdmsCatalogCache cache([&] {
        ++ndms_fetch_count;
        return ndms_payload();
    });

    using ReadinessState = NdmsNativeImportJournalReadinessState;
    std::atomic<ReadinessState> cached_boot_state{
        ReadinessState::unavailable};
    std::atomic<int> cached_state_reads{0};
    std::atomic<bool> provider_throws{false};
    std::atomic<int> wal_boot_scans{0};
    const auto scan_wal_at_boot = [&] {
        ++wal_boot_scans;
        return ReadinessState::clean_never_activated;
    };
    // Model production's one startup scan before route registration. HTTP
    // requests below can read only cached_boot_state through the narrow
    // provider; the handler has neither a store nor a scan callback.
    cached_boot_state.store(scan_wal_at_boot());

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18198");
    ApiServer server(config);
    register_ndms_names_handler_for_tests(
        server,
        cache,
        {"nwg2"},
        [&]() -> ReadinessState {
            ++cached_state_reads;
            if (provider_throws.load()) {
                throw std::runtime_error("redacted provider failure");
            }
            return cached_boot_state.load();
        });
    server.start();

    httplib::Client client("127.0.0.1", 18198);
    const auto expected_blockers = nlohmann::json::array(
        {"writer_disabled",
         "allocator_range_unfenced",
         "recovery_journal_not_integrated",
         "reconcile_barrier_not_integrated"});
    const std::vector<std::pair<ReadinessState, std::string>> states{
        {ReadinessState::clean_never_activated,
         "clean_never_activated"},
        {ReadinessState::clean, "clean"},
        {ReadinessState::recovery_required, "recovery_required"},
        {ReadinessState::unsafe, "unsafe"},
        {ReadinessState::unavailable, "unavailable"},
    };

    const auto check_report_only = [&](const httplib::Result& response,
                                       const std::string& journal_state) {
        REQUIRE(response != nullptr);
        REQUIRE(response->status == 200);
        const auto inventory = nlohmann::json::parse(response->body);
        const auto& readiness = inventory["native_import_readiness"];
        CHECK(inventory["read_only"] == true);
        CHECK(inventory["mutation_mode"] == "disabled");
        CHECK(readiness["preview_only"] == true);
        CHECK(readiness["apply_available"] == false);
        CHECK(readiness["journal_state"] == journal_state);
        CHECK(readiness["reconcile_barrier_state"] == "dormant");
        CHECK(readiness["blockers"] == expected_blockers);
        CHECK(readiness["blockers"].size() == 4);
        CHECK(response->body.find("transaction_id") ==
              std::string::npos);
        CHECK(response->body.find("wal_filename") ==
              std::string::npos);
        CHECK(response->body.find("wal-secret-transaction-id") ==
              std::string::npos);
    };

    for (const auto& state : states) {
        cached_boot_state.store(state.first);
        check_report_only(
            client.Get("/api/system/ndms/interfaces"), state.second);
    }

    provider_throws.store(true);
    check_report_only(
        client.Get("/api/system/ndms/interfaces"), "unavailable");
    provider_throws.store(false);

    cached_boot_state.store(ReadinessState::clean);
    check_report_only(
        client.Get("/api/system/ndms/interfaces"), "clean");
    check_report_only(
        client.Get("/api/system/ndms/interfaces"), "clean");

    const auto post = client.Post(
        "/api/system/ndms/interfaces", "{}", "application/json");
    server.stop();

    CHECK(cached_state_reads.load() ==
          static_cast<int>(states.size()) + 3);
    CHECK(ndms_fetch_count.load() == 1);
    CHECK(wal_boot_scans.load() == 1);
    REQUIRE(post != nullptr);
    CHECK(post->status == 404);
}

TEST_CASE("NDMS VPN service endpoint exposes only typed non-secret pools") {
    int fetch_count = 0;
    NdmsVpnServerServiceCache cache([&] {
        ++fetch_count;
        return ndms_vpn_services_payload();
    });

    CHECK(
        cache.peek().status ==
        NdmsCatalogCacheStatus::unavailable);
    CHECK(fetch_count == 0);

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18197");
    ApiServer server(config);
    register_ndms_vpn_server_services_handler_for_tests(
        server, cache);
    server.start();

    httplib::Client client("127.0.0.1", 18197);
    const auto response =
        client.Get("/api/system/ndms/vpn-server-services");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(fetch_count == 1);
    const auto inventory = nlohmann::json::parse(response->body);
    CHECK(inventory["available"] == true);
    CHECK(inventory["catalog_status"] == "fresh");
    CHECK(inventory["read_only"] == true);
    REQUIRE(inventory["services"].size() == 5);

    const auto l2tp = std::find_if(
        inventory["services"].begin(),
        inventory["services"].end(),
        [](const auto& item) {
            return item["kind"] == "l2tp";
        });
    REQUIRE(l2tp != inventory["services"].end());
    CHECK(
        (*l2tp)["id"] ==
        "ndms-crypto-map:l2tp:VPNL2TPServer");
    CHECK((*l2tp)["enabled"] == true);
    CHECK((*l2tp)["bound_interface_id"] == "Home");
    CHECK((*l2tp)["source_cidrs"] ==
          nlohmann::json::array({"172.16.2.33/32",
                                 "172.16.2.34/32"}));
    CHECK(l2tp->find("secret") == l2tp->end());

    const auto ikev1 = std::find_if(
        inventory["services"].begin(),
        inventory["services"].end(),
        [](const auto& item) {
            return item["kind"] == "ikev1";
        });
    REQUIRE(ikev1 != inventory["services"].end());
    CHECK((*ikev1)["source_cidrs"] ==
          nlohmann::json::array({
              "172.20.0.1/32", "172.20.0.2/32"}));

    const auto openconnect = std::find_if(
        inventory["services"].begin(),
        inventory["services"].end(),
        [](const auto& item) {
            return item["kind"] == "openconnect";
        });
    REQUIRE(openconnect != inventory["services"].end());
    CHECK((*openconnect)["id"] == "ndms-service:oc-server");
    CHECK((*openconnect)["source_cidrs"] ==
          nlohmann::json::array({
              "172.30.0.17/32", "172.30.0.18/31"}));
}

} // namespace keen_pbr3

#endif // WITH_API
