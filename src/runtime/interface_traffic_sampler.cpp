#include "interface_traffic_sampler.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <limits>
#include <system_error>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::string_view kSysClassNet = "/sys/class/net/";
constexpr uint64_t kCounterWrapWindow = uint64_t{1} << 32U;

struct CounterDelta {
    std::optional<uint64_t> bytes;
    bool reset{false};
    bool wrapped{false};
};

CounterDelta counter_delta(uint64_t previous, uint64_t current) {
    if (current >= previous) {
        return CounterDelta{current - previous, false, false};
    }

    constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();
    if (previous >= maximum - kCounterWrapWindow &&
        current <= kCounterWrapWindow) {
        return CounterDelta{
            (maximum - previous) + uint64_t{1} + current,
            false,
            true,
        };
    }

    // Linux resets interface counters when a device is recreated. Treat a
    // backwards jump away from UINT64_MAX as a new baseline, never as a huge
    // traffic spike.
    return CounterDelta{std::nullopt, true, false};
}

uint64_t bits_per_second(uint64_t byte_delta, long double elapsed_seconds) {
    const long double value =
        static_cast<long double>(byte_delta) * 8.0L / elapsed_seconds;
    const long double maximum =
        static_cast<long double>(std::numeric_limits<uint64_t>::max());
    if (value >= maximum) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(value);
}

bool is_ascii_name_character(char character) {
    const unsigned char value = static_cast<unsigned char>(character);
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') ||
           character == '_' || character == '-' || character == '.';
}

bool is_ascii_space(char character) {
    switch (character) {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case '\f':
        case '\v':
            return true;
        default:
            return false;
    }
}

} // namespace

InterfaceTrafficSampler::InterfaceTrafficSampler(CounterReader reader,
                                                 NowProvider now,
                                                 size_t history_limit)
    : reader_(std::move(reader)),
      now_(std::move(now)),
      history_limit_(std::min(history_limit, kMaxHistoryPoints)) {
    if (!reader_) {
        reader_ = read_counter_file;
    }
    if (!now_) {
        now_ = [] { return Clock::now(); };
    }
}

InterfaceTrafficSampler::SampleResult InterfaceTrafficSampler::sample(
    std::string_view interface_name) {
    if (!is_valid_interface_name(interface_name)) {
        return SampleResult{
            SampleStatus::InvalidInterfaceName, std::nullopt, false};
    }

    const std::string name(interface_name);
    const auto rx =
        reader_(counter_path(interface_name, "rx_bytes"));
    const auto tx =
        reader_(counter_path(interface_name, "tx_bytes"));

    if (!rx || !tx) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = states_.find(name);
        bool changed = false;
        if (existing != states_.end()) {
            changed = existing->second.available;
            existing->second.previous.reset();
            existing->second.latest.reset();
            existing->second.available = false;
            // A recreated TUN/WireGuard device starts its counters from a new
            // origin. Keeping points from the vanished device would draw one
            // continuous graph across two unrelated interface lifetimes.
            existing->second.history.clear();
        }
        return SampleResult{
            SampleStatus::Unavailable, std::nullopt, changed};
    }

    const TimePoint sampled_at = now_();
    std::lock_guard<std::mutex> lock(mutex_);
    auto& state = states_[name];

    if (!state.previous) {
        TrafficPoint point;
        point.sampled_at = sampled_at;
        point.rx_bytes = *rx;
        point.tx_bytes = *tx;
        state.previous = PreviousCounters{sampled_at, *rx, *tx};
        state.latest = point;
        state.available = true;
        append_point(state, point);
        return SampleResult{
            SampleStatus::Baseline, std::move(point), true};
    }

    const auto elapsed = sampled_at - state.previous->sampled_at;
    if (elapsed <= Clock::duration::zero()) {
        return SampleResult{
            SampleStatus::ClockNotAdvanced, std::nullopt, false};
    }

    const auto rx_delta = counter_delta(state.previous->rx_bytes, *rx);
    const auto tx_delta = counter_delta(state.previous->tx_bytes, *tx);
    const long double elapsed_seconds =
        std::chrono::duration<long double>(elapsed).count();
    const bool counter_reset = rx_delta.reset || tx_delta.reset;

    TrafficPoint point;
    point.sampled_at = sampled_at;
    point.rx_bytes = *rx;
    point.tx_bytes = *tx;
    point.rx_counter_wrapped = rx_delta.wrapped;
    point.tx_counter_wrapped = tx_delta.wrapped;
    // Treat any backwards non-wrap jump as a new interface lifetime. Mixing a
    // fresh RX counter with the previous TX interval (or vice versa) produces
    // a plausible-looking but semantically false rate.
    if (!counter_reset && rx_delta.bytes) {
        point.rx_bits_per_second =
            bits_per_second(*rx_delta.bytes, elapsed_seconds);
    }
    if (!counter_reset && tx_delta.bytes) {
        point.tx_bits_per_second =
            bits_per_second(*tx_delta.bytes, elapsed_seconds);
    }

    const bool changed =
        !state.available || !state.latest ||
        !same_public_state(*state.latest, point);
    if (counter_reset) {
        state.history.clear();
    }
    state.previous = PreviousCounters{sampled_at, *rx, *tx};
    state.latest = point;
    state.available = true;
    append_point(state, point);
    const auto status = counter_reset
        ? SampleStatus::CounterReset
        : SampleStatus::Sampled;
    return SampleResult{status, std::move(point), changed};
}

std::optional<InterfaceTrafficSampler::TrafficSnapshot>
InterfaceTrafficSampler::snapshot(std::string_view interface_name) const {
    if (!is_valid_interface_name(interface_name)) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto state = states_.find(std::string(interface_name));
    if (state == states_.end() || !state->second.available ||
        !state->second.latest) {
        return std::nullopt;
    }
    return TrafficSnapshot{
        *state->second.latest,
        std::vector<TrafficPoint>(
            state->second.history.begin(),
            state->second.history.end()),
    };
}

std::vector<InterfaceTrafficSampler::TrafficPoint>
InterfaceTrafficSampler::history(std::string_view interface_name) const {
    if (!is_valid_interface_name(interface_name)) {
        return {};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto state = states_.find(std::string(interface_name));
    if (state == states_.end()) {
        return {};
    }
    return std::vector<TrafficPoint>(
        state->second.history.begin(),
        state->second.history.end());
}

void InterfaceTrafficSampler::clear(std::string_view interface_name) {
    if (!is_valid_interface_name(interface_name)) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    states_.erase(std::string(interface_name));
}

void InterfaceTrafficSampler::clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    states_.clear();
}

bool InterfaceTrafficSampler::is_valid_interface_name(
    std::string_view interface_name) {
    // Linux IFNAMSIZ includes the terminating NUL byte.
    if (interface_name.empty() || interface_name.size() > 15 ||
        interface_name == "." || interface_name == "..") {
        return false;
    }
    return std::all_of(
        interface_name.begin(),
        interface_name.end(),
        is_ascii_name_character);
}

std::optional<uint64_t> InterfaceTrafficSampler::read_counter_file(
    const std::string& path) {
    std::ifstream stream(path, std::ios::in | std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }

    std::array<char, 64> buffer{};
    stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto count = static_cast<size_t>(stream.gcount());
    if (count == 0 || count == buffer.size()) {
        return std::nullopt;
    }

    const char* begin = buffer.data();
    const char* end = begin + count;
    while (begin != end && is_ascii_space(*begin)) {
        ++begin;
    }
    while (end != begin && is_ascii_space(*(end - 1))) {
        --end;
    }
    if (begin == end) {
        return std::nullopt;
    }

    uint64_t value = 0;
    const auto parsed = std::from_chars(begin, end, value);
    if (parsed.ec != std::errc{} || parsed.ptr != end) {
        return std::nullopt;
    }
    return value;
}

std::string InterfaceTrafficSampler::counter_path(
    std::string_view interface_name,
    std::string_view counter_name) {
    std::string path;
    path.reserve(
        kSysClassNet.size() + interface_name.size() +
        sizeof("/statistics/") - 1 + counter_name.size());
    path.append(kSysClassNet.data(), kSysClassNet.size());
    path.append(interface_name.data(), interface_name.size());
    path.append("/statistics/");
    path.append(counter_name.data(), counter_name.size());
    return path;
}

bool InterfaceTrafficSampler::same_public_state(const TrafficPoint& lhs,
                                                const TrafficPoint& rhs) {
    return lhs.rx_bytes == rhs.rx_bytes &&
           lhs.tx_bytes == rhs.tx_bytes &&
           lhs.rx_bits_per_second == rhs.rx_bits_per_second &&
           lhs.tx_bits_per_second == rhs.tx_bits_per_second &&
           lhs.rx_counter_wrapped == rhs.rx_counter_wrapped &&
           lhs.tx_counter_wrapped == rhs.tx_counter_wrapped;
}

void InterfaceTrafficSampler::append_point(InterfaceState& state,
                                           TrafficPoint point) {
    if (history_limit_ == 0) {
        return;
    }
    state.history.push_back(std::move(point));
    while (state.history.size() > history_limit_) {
        state.history.pop_front();
    }
}

} // namespace keen_pbr3
