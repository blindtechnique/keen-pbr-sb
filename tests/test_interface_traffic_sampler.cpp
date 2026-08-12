#include <doctest/doctest.h>

#include "runtime/interface_traffic_sampler.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace keen_pbr3 {

namespace {

class FakeTrafficSource {
public:
    using TimePoint = InterfaceTrafficSampler::TimePoint;

    std::optional<uint64_t> read(const std::string& path) {
        paths.push_back(path);
        const auto value = counters.find(path);
        if (value == counters.end()) {
            return std::nullopt;
        }
        return value->second;
    }

    void set(std::string_view interface_name,
             uint64_t rx_bytes,
             uint64_t tx_bytes) {
        const std::string base =
            "/sys/class/net/" + std::string(interface_name) + "/statistics/";
        counters[base + "rx_bytes"] = rx_bytes;
        counters[base + "tx_bytes"] = tx_bytes;
    }

    void remove(std::string_view interface_name) {
        const std::string base =
            "/sys/class/net/" + std::string(interface_name) + "/statistics/";
        counters.erase(base + "rx_bytes");
        counters.erase(base + "tx_bytes");
    }

    TimePoint now{};
    // Deliberately independent of `now`: rates must stay on the steady clock
    // while the published stamp comes from the wall clock, and a test that
    // moved them together could not tell which one a value came from.
    InterfaceTrafficSampler::WallTimePoint wall_now{};
    std::unordered_map<std::string, uint64_t> counters;
    std::vector<std::string> paths;
};

InterfaceTrafficSampler make_sampler(FakeTrafficSource& source,
                                     size_t history_limit = 120) {
    return InterfaceTrafficSampler(
        [&source](const std::string& path) {
            return source.read(path);
        },
        [&source] {
            return source.now;
        },
        history_limit,
        [&source] {
            return source.wall_now;
        });
}

} // namespace

TEST_CASE("InterfaceTrafficSampler strictly validates Linux interface names") {
    CHECK(InterfaceTrafficSampler::is_valid_interface_name("wg0"));
    CHECK(InterfaceTrafficSampler::is_valid_interface_name("mooo_vless"));
    CHECK(InterfaceTrafficSampler::is_valid_interface_name("eth0.2"));
    CHECK(InterfaceTrafficSampler::is_valid_interface_name("nwg-1"));
    CHECK(InterfaceTrafficSampler::is_valid_interface_name(
        "123456789012345"));

    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name(""));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name("."));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name(".."));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name(
        "1234567890123456"));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name("../eth0"));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name("eth0/tx"));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name("eth0:1"));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name("eth 0"));
    CHECK_FALSE(InterfaceTrafficSampler::is_valid_interface_name("интерфейс"));
}

TEST_CASE("InterfaceTrafficSampler rejects traversal before invoking reader") {
    FakeTrafficSource source;
    auto sampler = make_sampler(source);

    const auto result = sampler.sample("../../etc/passwd");

    CHECK(result.status ==
          InterfaceTrafficSampler::SampleStatus::InvalidInterfaceName);
    CHECK_FALSE(result.point.has_value());
    CHECK(source.paths.empty());
}

TEST_CASE("InterfaceTrafficSampler first sample establishes a zero-rate baseline") {
    FakeTrafficSource source;
    source.set("wg0", 100, 200);
    auto sampler = make_sampler(source);

    const auto result = sampler.sample("wg0");

    CHECK(result.status == InterfaceTrafficSampler::SampleStatus::Baseline);
    REQUIRE(result.point.has_value());
    CHECK(result.point->rx_bytes == 100);
    CHECK(result.point->tx_bytes == 200);
    CHECK_FALSE(result.point->rx_bits_per_second.has_value());
    CHECK_FALSE(result.point->tx_bits_per_second.has_value());
    CHECK(result.state_changed);
    CHECK(source.paths == std::vector<std::string>{
                              "/sys/class/net/wg0/statistics/rx_bytes",
                              "/sys/class/net/wg0/statistics/tx_bytes"});
}

TEST_CASE("InterfaceTrafficSampler computes rates from steady elapsed time") {
    FakeTrafficSource source;
    source.set("hysteria2", 1000, 2000);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("hysteria2").point.has_value());

    source.now += std::chrono::milliseconds(500);
    source.set("hysteria2", 1125, 2250);
    const auto result = sampler.sample("hysteria2");

    CHECK(result.status == InterfaceTrafficSampler::SampleStatus::Sampled);
    REQUIRE(result.point.has_value());
    REQUIRE(result.point->rx_bits_per_second.has_value());
    REQUIRE(result.point->tx_bits_per_second.has_value());
    CHECK(*result.point->rx_bits_per_second == 2000);
    CHECK(*result.point->tx_bits_per_second == 4000);
    CHECK(result.state_changed);
}

TEST_CASE("InterfaceTrafficSampler resets baseline after interface disappearance") {
    FakeTrafficSource source;
    source.set("nwg2", 1000, 2000);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("nwg2").point.has_value());

    source.now += std::chrono::seconds(1);
    source.remove("nwg2");
    const auto unavailable = sampler.sample("nwg2");
    CHECK(unavailable.status ==
          InterfaceTrafficSampler::SampleStatus::Unavailable);
    CHECK_FALSE(unavailable.point.has_value());
    CHECK(unavailable.state_changed);
    CHECK(sampler.history("nwg2").empty());

    source.now += std::chrono::seconds(1);
    source.set("nwg2", 10, 20);
    const auto reappeared = sampler.sample("nwg2");
    CHECK(reappeared.status ==
          InterfaceTrafficSampler::SampleStatus::Baseline);
    REQUIRE(reappeared.point.has_value());
    CHECK_FALSE(reappeared.point->rx_bits_per_second.has_value());
    CHECK_FALSE(reappeared.point->tx_bits_per_second.has_value());
    CHECK(reappeared.state_changed);
}

TEST_CASE("InterfaceTrafficSampler treats ordinary backwards jumps as counter resets") {
    FakeTrafficSource source;
    source.set("vless0", 1000, 2000);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("vless0").point.has_value());

    source.now += std::chrono::seconds(1);
    source.set("vless0", 10, 2125);
    const auto result = sampler.sample("vless0");

    CHECK(result.status ==
          InterfaceTrafficSampler::SampleStatus::CounterReset);
    REQUIRE(result.point.has_value());
    CHECK_FALSE(result.point->rx_bits_per_second.has_value());
    CHECK_FALSE(result.point->tx_bits_per_second.has_value());
    const auto history = sampler.history("vless0");
    REQUIRE(history.size() == 1);
    CHECK(history.front().rx_bytes == 10);
    CHECK(history.front().tx_bytes == 2125);
}

TEST_CASE("InterfaceTrafficSampler handles a uint64 counter wrap without overflow") {
    FakeTrafficSource source;
    constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();
    source.set("wg0", maximum - 10, maximum - 20);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("wg0").point.has_value());

    source.now += std::chrono::seconds(1);
    source.set("wg0", 5, 9);
    const auto result = sampler.sample("wg0");

    CHECK(result.status == InterfaceTrafficSampler::SampleStatus::Sampled);
    REQUIRE(result.point.has_value());
    CHECK(result.point->rx_counter_wrapped);
    CHECK(result.point->tx_counter_wrapped);
    REQUIRE(result.point->rx_bits_per_second.has_value());
    REQUIRE(result.point->tx_bits_per_second.has_value());
    CHECK(*result.point->rx_bits_per_second == 128);
    CHECK(*result.point->tx_bits_per_second == 240);
}

TEST_CASE("InterfaceTrafficSampler does not divide by a stalled or reversed clock") {
    FakeTrafficSource source;
    source.set("wg0", 100, 200);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("wg0").point.has_value());

    source.set("wg0", 200, 300);
    const auto stalled = sampler.sample("wg0");
    CHECK(stalled.status ==
          InterfaceTrafficSampler::SampleStatus::ClockNotAdvanced);
    CHECK_FALSE(stalled.point.has_value());

    source.now -= std::chrono::seconds(1);
    const auto reversed = sampler.sample("wg0");
    CHECK(reversed.status ==
          InterfaceTrafficSampler::SampleStatus::ClockNotAdvanced);
    CHECK_FALSE(reversed.point.has_value());

    source.now += std::chrono::seconds(3);
    const auto recovered = sampler.sample("wg0");
    CHECK(recovered.status ==
          InterfaceTrafficSampler::SampleStatus::Sampled);
    REQUIRE(recovered.point->rx_bits_per_second.has_value());
    CHECK(*recovered.point->rx_bits_per_second == 400);
}

TEST_CASE("InterfaceTrafficSampler caps in-memory history at 120 points") {
    FakeTrafficSource source;
    source.set("wg0", 0, 0);
    auto sampler = make_sampler(source, 1000);

    for (uint64_t index = 0; index < 150; ++index) {
        source.now += std::chrono::seconds(1);
        source.set("wg0", index, index * 2);
        sampler.sample("wg0");
    }

    const auto history = sampler.history("wg0");
    REQUIRE(history.size() ==
            InterfaceTrafficSampler::kMaxHistoryPoints);
    CHECK(history.front().rx_bytes == 30);
    CHECK(history.back().rx_bytes == 149);
}

TEST_CASE("InterfaceTrafficSampler supports disabling history without disabling samples") {
    FakeTrafficSource source;
    source.set("wg0", 100, 200);
    auto sampler = make_sampler(source, 0);

    const auto result = sampler.sample("wg0");

    REQUIRE(result.point.has_value());
    CHECK(sampler.history("wg0").empty());
}

TEST_CASE("InterfaceTrafficSampler exposes a bounded snapshot and suppresses unchanged state") {
    FakeTrafficSource source;
    source.set("wg0", 100, 200);
    auto sampler = make_sampler(source, 3);

    REQUIRE(sampler.sample("wg0").state_changed);
    source.now += std::chrono::seconds(1);
    REQUIRE(sampler.sample("wg0").state_changed);
    source.now += std::chrono::seconds(1);
    CHECK_FALSE(sampler.sample("wg0").state_changed);

    const auto snapshot = sampler.snapshot("wg0");
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->latest.rx_bytes == 100);
    CHECK(snapshot->latest.rx_bits_per_second == 0);
    CHECK(snapshot->history.size() == 3);

    sampler.clear("wg0");
    CHECK_FALSE(sampler.snapshot("wg0").has_value());
}

TEST_CASE("InterfaceTrafficSampler reports repeated unavailability only once") {
    FakeTrafficSource source;
    source.set("wg0", 100, 200);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("wg0").state_changed);

    source.remove("wg0");
    CHECK(sampler.sample("wg0").state_changed);
    CHECK_FALSE(sampler.sample("wg0").state_changed);
    CHECK_FALSE(sampler.snapshot("wg0").has_value());
}

TEST_CASE("InterfaceTrafficSampler can clear every retained series") {
    FakeTrafficSource source;
    source.set("wg0", 100, 200);
    source.set("nwg2", 300, 400);
    auto sampler = make_sampler(source);
    REQUIRE(sampler.sample("wg0").point.has_value());
    REQUIRE(sampler.sample("nwg2").point.has_value());

    sampler.clear_all();

    CHECK_FALSE(sampler.snapshot("wg0").has_value());
    CHECK_FALSE(sampler.snapshot("nwg2").has_value());
}

TEST_CASE("each interface carries the wall instant of its own reading") {
    FakeTrafficSource source;
    auto sampler = make_sampler(source);

    const InterfaceTrafficSampler::WallTimePoint origin{
        std::chrono::seconds{1'754'812'800}};

    source.set("nwg1", 100, 200);
    source.set("nwg2", 300, 400);

    // One sampling round, but the two interfaces are read a measurable moment
    // apart - which is exactly what a shared batch timestamp erased.
    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{10}};
    source.wall_now = origin;
    const auto first = sampler.sample("nwg1");

    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{10}} +
                 std::chrono::milliseconds{400};
    source.wall_now = origin + std::chrono::milliseconds{400};
    const auto second = sampler.sample("nwg2");

    REQUIRE(first.point.has_value());
    REQUIRE(second.point.has_value());
    CHECK(first.point->observed_at == origin);
    CHECK(second.point->observed_at == origin + std::chrono::milliseconds{400});
    CHECK(first.point->observed_at != second.point->observed_at);
}

TEST_CASE("the published wall stamp advances with every successful reading") {
    FakeTrafficSource source;
    auto sampler = make_sampler(source);

    const InterfaceTrafficSampler::WallTimePoint origin{
        std::chrono::seconds{1'754'812'800}};

    source.set("nwg1", 0, 0);
    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{0}};
    source.wall_now = origin;
    REQUIRE(sampler.sample("nwg1").status ==
            InterfaceTrafficSampler::SampleStatus::Baseline);

    source.set("nwg1", 1'000, 2'000);
    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{2}};
    source.wall_now = origin + std::chrono::seconds{2};
    const auto sampled = sampler.sample("nwg1");

    REQUIRE(sampled.point.has_value());
    CHECK(sampled.point->observed_at == origin + std::chrono::seconds{2});

    const auto snapshot = sampler.snapshot("nwg1");
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->latest.observed_at == origin + std::chrono::seconds{2});
}

TEST_CASE("a wall clock step does not disturb the steady rate calculation") {
    FakeTrafficSource source;
    auto sampler = make_sampler(source);

    source.set("nwg1", 0, 0);
    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{0}};
    source.wall_now =
        InterfaceTrafficSampler::WallTimePoint{std::chrono::seconds{1'000}};
    REQUIRE(sampler.sample("nwg1").status ==
            InterfaceTrafficSampler::SampleStatus::Baseline);

    // NTP steps the wall clock an hour forward between the two readings. The
    // rate must still be computed over the two steady seconds that actually
    // elapsed, or the graph would show a plausible but fabricated collapse.
    source.set("nwg1", 250'000, 0);
    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{2}};
    source.wall_now =
        InterfaceTrafficSampler::WallTimePoint{std::chrono::seconds{4'600}};
    const auto sampled = sampler.sample("nwg1");

    REQUIRE(sampled.point.has_value());
    REQUIRE(sampled.point->rx_bits_per_second.has_value());
    CHECK(*sampled.point->rx_bits_per_second == 1'000'000);
    CHECK(sampled.point->observed_at ==
          InterfaceTrafficSampler::WallTimePoint{std::chrono::seconds{4'600}});
}

TEST_CASE("an unreadable interface publishes no reading to be stamped") {
    FakeTrafficSource source;
    auto sampler = make_sampler(source);

    source.now = InterfaceTrafficSampler::TimePoint{std::chrono::seconds{5}};
    source.wall_now =
        InterfaceTrafficSampler::WallTimePoint{std::chrono::seconds{5}};

    const auto result = sampler.sample("nwg9");

    // No point means no observed_at on the wire, which is what stops a failed
    // read from looking as fresh as a successful one in the same round.
    CHECK(result.status == InterfaceTrafficSampler::SampleStatus::Unavailable);
    CHECK_FALSE(result.point.has_value());
}

} // namespace keen_pbr3
