#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace keen_pbr3 {

class InterfaceTrafficSampler {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    // Rates are derived on the steady clock so an NTP step cannot invent a
    // gigabit spike, but nothing outside this process can read a steady
    // instant. Publication therefore needs a wall stamp taken at the same
    // moment, per interface - not one taken later while serializing, which is
    // exactly what collapses independent measurements into a single batch.
    using WallClock = std::chrono::system_clock;
    using WallTimePoint = WallClock::time_point;
    using CounterReader =
        std::function<std::optional<uint64_t>(const std::string& path)>;
    using NowProvider = std::function<TimePoint()>;
    using WallNowProvider = std::function<WallTimePoint()>;

    static constexpr size_t kMaxHistoryPoints = 120;

    enum class SampleStatus {
        InvalidInterfaceName,
        Unavailable,
        Baseline,
        Sampled,
        ClockNotAdvanced,
        CounterReset,
    };

    struct TrafficPoint {
        TimePoint sampled_at;
        // Wall-clock twin of sampled_at, captured in the same breath. This is
        // what "last measurement" means for THIS interface; it is deliberately
        // not compared by same_public_state, since it differs on every sample
        // and would defeat change detection.
        WallTimePoint observed_at;
        uint64_t rx_bytes{0};
        uint64_t tx_bytes{0};
        std::optional<uint64_t> rx_bits_per_second;
        std::optional<uint64_t> tx_bits_per_second;
        bool rx_counter_wrapped{false};
        bool tx_counter_wrapped{false};
    };

    struct SampleResult {
        SampleStatus status{SampleStatus::Unavailable};
        std::optional<TrafficPoint> point;
        bool state_changed{false};
    };

    struct TrafficSnapshot {
        TrafficPoint latest;
        std::vector<TrafficPoint> history;
    };

    explicit InterfaceTrafficSampler(
        CounterReader reader = {},
        NowProvider now = {},
        size_t history_limit = kMaxHistoryPoints,
        WallNowProvider wall_now = {});

    SampleResult sample(std::string_view interface_name);
    std::optional<TrafficSnapshot> snapshot(
        std::string_view interface_name) const;
    std::vector<TrafficPoint> history(std::string_view interface_name) const;
    void clear(std::string_view interface_name);
    void clear_all();

    static bool is_valid_interface_name(std::string_view interface_name);

private:
    struct PreviousCounters {
        TimePoint sampled_at;
        uint64_t rx_bytes{0};
        uint64_t tx_bytes{0};
    };

    struct InterfaceState {
        std::optional<PreviousCounters> previous;
        std::optional<TrafficPoint> latest;
        bool available{false};
        std::deque<TrafficPoint> history;
    };

    static std::optional<uint64_t> read_counter_file(
        const std::string& path);
    static std::string counter_path(std::string_view interface_name,
                                    std::string_view counter_name);
    static bool same_public_state(const TrafficPoint& lhs,
                                  const TrafficPoint& rhs);
    void append_point(InterfaceState& state, TrafficPoint point);

    CounterReader reader_;
    NowProvider now_;
    WallNowProvider wall_now_;
    size_t history_limit_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, InterfaceState> states_;
};

} // namespace keen_pbr3
