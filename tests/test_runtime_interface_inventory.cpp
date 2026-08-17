#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/health/runtime_interface_inventory.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>

namespace keen_pbr3 {

TEST_CASE("build_runtime_interface_inventory_response: empty interfaces returns empty response") {
    const auto response = build_runtime_interface_inventory_response(
        std::vector<DumpedInterface>{});

    CHECK(response.interfaces.empty());
}

TEST_CASE("build_runtime_interface_inventory_response: admin-up interface maps to up") {
    DumpedInterface dumped;
    dumped.name = "br0";
    dumped.admin_up = true;
    dumped.oper_state = std::string("up");
    dumped.carrier = true;
    dumped.ipv4_addresses = {"192.168.1.1/24"};
    dumped.ipv6_addresses = {"fe80::1/64"};

    const auto response = build_runtime_interface_inventory_response(
        std::vector<DumpedInterface>{dumped});

    REQUIRE(response.interfaces.size() == 1);
    const auto& entry = response.interfaces.front();
    CHECK(entry.name == "br0");
    CHECK(entry.status == api::RuntimeInterfaceInventoryStatusEnum::UP);
    REQUIRE(entry.admin_up.has_value());
    CHECK(*entry.admin_up);
    REQUIRE(entry.oper_state.has_value());
    CHECK(*entry.oper_state == "up");
    REQUIRE(entry.carrier.has_value());
    CHECK(*entry.carrier);
    REQUIRE(entry.ipv4_addresses.has_value());
    CHECK(*entry.ipv4_addresses == std::vector<std::string>{"192.168.1.1/24"});
    REQUIRE(entry.ipv6_addresses.has_value());
    CHECK(*entry.ipv6_addresses == std::vector<std::string>{"fe80::1/64"});
}

TEST_CASE("build_runtime_interface_inventory_response: admin-down interface maps to down") {
    DumpedInterface dumped;
    dumped.name = "wg0";
    dumped.admin_up = false;

    const auto response = build_runtime_interface_inventory_response(
        std::vector<DumpedInterface>{dumped});

    REQUIRE(response.interfaces.size() == 1);
    const auto& entry = response.interfaces.front();
    CHECK(entry.name == "wg0");
    CHECK(entry.status == api::RuntimeInterfaceInventoryStatusEnum::DOWN);
    REQUIRE(entry.admin_up.has_value());
    CHECK_FALSE(*entry.admin_up);
    CHECK_FALSE(entry.oper_state.has_value());
    CHECK_FALSE(entry.carrier.has_value());
    CHECK_FALSE(entry.ipv4_addresses.has_value());
    CHECK_FALSE(entry.ipv6_addresses.has_value());
}

TEST_CASE("runtime interface inventory includes bounded sampler statistics") {
    using Clock = InterfaceTrafficSampler::Clock;
    Clock::time_point now{};
    std::unordered_map<std::string, uint64_t> counters;
    counters["/sys/class/net/wg0/statistics/rx_bytes"] = 1000;
    counters["/sys/class/net/wg0/statistics/tx_bytes"] = 2000;
    InterfaceTrafficSampler sampler(
        [&counters](const std::string& path) -> std::optional<uint64_t> {
            const auto it = counters.find(path);
            return it == counters.end()
                ? std::nullopt
                : std::optional<uint64_t>(it->second);
        },
        [&now] { return now; });

    REQUIRE(sampler.sample("wg0").point.has_value());
    now += std::chrono::seconds(2);
    counters["/sys/class/net/wg0/statistics/rx_bytes"] = 2000;
    counters["/sys/class/net/wg0/statistics/tx_bytes"] = 4000;
    REQUIRE(sampler.sample("wg0").point.has_value());

    DumpedInterface dumped;
    dumped.name = "wg0";
    dumped.admin_up = true;
    const auto response = build_runtime_interface_inventory_response(
        std::vector<DumpedInterface>{dumped}, &sampler);

    REQUIRE(response.interfaces.size() == 1);
    REQUIRE(response.interfaces.front().traffic.has_value());
    const auto& traffic = *response.interfaces.front().traffic;
    CHECK(traffic.rx_bytes == 2000);
    CHECK(traffic.tx_bytes == 4000);
    CHECK(traffic.rx_bits_per_second == 4000);
    CHECK(traffic.tx_bits_per_second == 8000);
    REQUIRE(traffic.history.size() == 2);
    CHECK(traffic.history[0].age_ms == 2000);
    CHECK(traffic.history[0].rx_bits_per_second == 0);
    CHECK(traffic.history[1].age_ms == 0);
    CHECK(traffic.history[1].rx_bits_per_second == 4000);
}

} // namespace keen_pbr3

#endif // WITH_API
