#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

enum class PeriodicTaskOutcome : std::uint8_t {
    Success,
    Noop,
    Failure,
    Skipped,
    Abandoned,
};

const char* periodic_task_outcome_name(PeriodicTaskOutcome outcome) noexcept;

struct PeriodicTaskMetricsSnapshot {
    std::string label;
    std::uint64_t runs{0};
    std::uint64_t success{0};
    std::uint64_t noop{0};
    std::uint64_t failure{0};
    std::uint64_t skipped{0};
    std::uint64_t abandoned{0};
    std::uint64_t in_flight{0};
    std::uint64_t total_duration_ms{0};
    std::uint64_t max_duration_ms{0};
    std::optional<std::uint64_t> last_duration_ms;
    std::optional<std::int64_t> last_started_at_unix_ms;
    std::optional<std::int64_t> last_finished_at_unix_ms;
    std::optional<std::int64_t> last_event_at_unix_ms;
    std::optional<PeriodicTaskOutcome> last_outcome;
    std::string last_error;
};

struct PeriodicTaskMetricsClocks {
    using SteadyNow =
        std::function<std::chrono::steady_clock::time_point()>;
    using WallNowUnixMs = std::function<std::int64_t()>;

    SteadyNow steady_now;
    WallNowUnixMs wall_now_unix_ms;
};

struct PeriodicTaskMetricsOptions {
    std::size_t capacity{32};
    std::uint64_t counter_ceiling{
        std::numeric_limits<std::uint64_t>::max()};
};

namespace periodic_task_metrics_detail {
struct SharedState;
}

class PeriodicTaskRunToken {
public:
    PeriodicTaskRunToken() = default;
    ~PeriodicTaskRunToken() noexcept;

    PeriodicTaskRunToken(PeriodicTaskRunToken&& other) noexcept;
    PeriodicTaskRunToken& operator=(PeriodicTaskRunToken&& other) noexcept;

    PeriodicTaskRunToken(const PeriodicTaskRunToken&) = delete;
    PeriodicTaskRunToken& operator=(const PeriodicTaskRunToken&) = delete;

    bool active() const noexcept;
    bool finish(PeriodicTaskOutcome outcome,
                std::string error = {}) noexcept;
    bool success() noexcept;
    bool noop() noexcept;
    bool failure(std::string error) noexcept;
    bool skipped(std::string reason = {}) noexcept;
    bool abandon(std::string reason = {}) noexcept;

private:
    PeriodicTaskRunToken(
        std::shared_ptr<periodic_task_metrics_detail::SharedState> state,
        std::size_t index,
        std::chrono::steady_clock::time_point started_at,
        std::int64_t started_at_unix_ms,
        bool counted) noexcept;

    void reset() noexcept;

    std::shared_ptr<periodic_task_metrics_detail::SharedState> state_;
    std::size_t index_{0};
    std::chrono::steady_clock::time_point started_at_{};
    std::int64_t started_at_unix_ms_{0};
    bool counted_{false};
    bool active_{false};

    friend class PeriodicTaskMetricsRegistry;
};

class PeriodicTaskMetricsRegistry {
public:
    explicit PeriodicTaskMetricsRegistry(
        std::vector<std::string> stable_labels,
        PeriodicTaskMetricsClocks clocks = {},
        PeriodicTaskMetricsOptions options = {});

    PeriodicTaskRunToken begin(std::string_view stable_label);
    void record_skipped(std::string_view stable_label,
                        std::string reason = {});
    std::vector<PeriodicTaskMetricsSnapshot> snapshot() const;

    std::size_t size() const noexcept;
    std::size_t capacity() const noexcept;

private:
    std::shared_ptr<periodic_task_metrics_detail::SharedState> state_;
};

} // namespace keen_pbr3
