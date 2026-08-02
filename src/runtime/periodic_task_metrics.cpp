#include "periodic_task_metrics.hpp"

#include "../util/traced_mutex.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

namespace periodic_task_metrics_detail {

struct Entry {
    PeriodicTaskMetricsSnapshot metrics;
};

struct SharedState {
    std::vector<Entry> entries;
    PeriodicTaskMetricsClocks::SteadyNow steady_now;
    PeriodicTaskMetricsClocks::WallNowUnixMs wall_now_unix_ms;
    std::size_t capacity{0};
    std::uint64_t counter_ceiling{0};
    mutable TracedMutex mutex;
};

} // namespace periodic_task_metrics_detail

namespace {

using SharedState = periodic_task_metrics_detail::SharedState;

constexpr std::size_t kMaxStableLabelBytes = 64;
constexpr std::size_t kMaxErrorBytes = 256;

std::chrono::steady_clock::time_point steady_now() {
    return std::chrono::steady_clock::now();
}

std::int64_t wall_now_unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool stable_label_is_valid(std::string_view label) {
    if (label.empty() || label.size() > kMaxStableLabelBytes) return false;
    return std::all_of(label.begin(), label.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '.';
    });
}

bool valid_utf8_sequence(std::string_view input,
                         std::size_t offset,
                         std::size_t& length) {
    const auto first = static_cast<unsigned char>(input[offset]);
    if ((first & 0xe0U) == 0xc0U) {
        length = 2;
        if (first < 0xc2U) return false;
    } else if ((first & 0xf0U) == 0xe0U) {
        length = 3;
    } else if ((first & 0xf8U) == 0xf0U) {
        length = 4;
        if (first > 0xf4U) return false;
    } else {
        return false;
    }
    if (offset + length > input.size()) return false;
    for (std::size_t i = 1; i < length; ++i) {
        if ((static_cast<unsigned char>(input[offset + i]) & 0xc0U) !=
            0x80U) {
            return false;
        }
    }
    const auto second = static_cast<unsigned char>(input[offset + 1]);
    if (length == 3 &&
        ((first == 0xe0U && second < 0xa0U) ||
         (first == 0xedU && second >= 0xa0U))) {
        return false;
    }
    if (length == 4 &&
        ((first == 0xf0U && second < 0x90U) ||
         (first == 0xf4U && second >= 0x90U))) {
        return false;
    }
    return true;
}

std::string sanitize_error(std::string_view input) {
    std::string output;
    output.reserve(std::min(input.size(), kMaxErrorBytes));
    bool pending_space = false;

    for (std::size_t i = 0; i < input.size() && output.size() < kMaxErrorBytes;) {
        const auto ch = static_cast<unsigned char>(input[i]);
        if (ch < 0x80U) {
            ++i;
            if (std::isspace(ch) != 0 || std::iscntrl(ch) != 0) {
                pending_space = !output.empty();
                continue;
            }
            if (pending_space && output.size() < kMaxErrorBytes) {
                output.push_back(' ');
            }
            pending_space = false;
            if (output.size() < kMaxErrorBytes) {
                output.push_back(static_cast<char>(ch));
            }
            continue;
        }

        std::size_t sequence_length = 0;
        if (!valid_utf8_sequence(input, i, sequence_length)) {
            ++i;
            if (pending_space && output.size() < kMaxErrorBytes) {
                output.push_back(' ');
            }
            pending_space = false;
            if (output.size() < kMaxErrorBytes) output.push_back('?');
            continue;
        }
        const auto required_bytes = sequence_length + (pending_space ? 1U : 0U);
        if (required_bytes > kMaxErrorBytes - output.size()) break;
        if (pending_space) output.push_back(' ');
        pending_space = false;
        output.append(input.data() + i, sequence_length);
        i += sequence_length;
    }
    return output;
}

std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    return rhs > maximum - lhs ? maximum : lhs + rhs;
}

std::uint64_t elapsed_ms(
    std::chrono::steady_clock::time_point started_at,
    std::chrono::steady_clock::time_point finished_at) noexcept {
    if (finished_at <= started_at) return 0;
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            finished_at - started_at)
            .count());
}

std::size_t find_index(const SharedState& state, std::string_view label) {
    const auto it = std::lower_bound(
        state.entries.begin(),
        state.entries.end(),
        label,
        [](const periodic_task_metrics_detail::Entry& entry,
           std::string_view candidate) {
            return entry.metrics.label < candidate;
        });
    if (it == state.entries.end() || it->metrics.label != label) {
        throw std::out_of_range("periodic task label was not pre-registered");
    }
    return static_cast<std::size_t>(it - state.entries.begin());
}

void update_terminal_metrics(
    periodic_task_metrics_detail::Entry& entry,
    PeriodicTaskOutcome outcome,
    bool counted,
    std::uint64_t counter_ceiling,
    std::uint64_t duration_ms,
    std::int64_t finished_at_unix_ms,
    const std::string& error) {
    auto& metrics = entry.metrics;
    const bool record_duration =
        counted && outcome != PeriodicTaskOutcome::Skipped;
    if (counted && metrics.in_flight > 0) {
        --metrics.in_flight;
        switch (outcome) {
        case PeriodicTaskOutcome::Success: ++metrics.success; break;
        case PeriodicTaskOutcome::Noop: ++metrics.noop; break;
        case PeriodicTaskOutcome::Failure: ++metrics.failure; break;
        case PeriodicTaskOutcome::Abandoned: ++metrics.abandoned; break;
        case PeriodicTaskOutcome::Skipped:
            if (metrics.skipped < counter_ceiling) ++metrics.skipped;
            --metrics.runs;
            break;
        }
    } else if (outcome == PeriodicTaskOutcome::Skipped) {
        if (metrics.skipped < counter_ceiling) ++metrics.skipped;
    }

    if (record_duration) {
        metrics.last_duration_ms = duration_ms;
        metrics.total_duration_ms =
            saturating_add(metrics.total_duration_ms, duration_ms);
        metrics.max_duration_ms =
            std::max(metrics.max_duration_ms, duration_ms);
    }
    metrics.last_finished_at_unix_ms = finished_at_unix_ms;
    metrics.last_event_at_unix_ms = finished_at_unix_ms;
    metrics.last_outcome = outcome;
    if (outcome == PeriodicTaskOutcome::Failure ||
        outcome == PeriodicTaskOutcome::Abandoned ||
        outcome == PeriodicTaskOutcome::Skipped) {
        metrics.last_error = error;
    } else {
        metrics.last_error.clear();
    }
}

} // namespace

const char* periodic_task_outcome_name(PeriodicTaskOutcome outcome) noexcept {
    switch (outcome) {
    case PeriodicTaskOutcome::Success: return "success";
    case PeriodicTaskOutcome::Noop: return "noop";
    case PeriodicTaskOutcome::Failure: return "failure";
    case PeriodicTaskOutcome::Skipped: return "skipped";
    case PeriodicTaskOutcome::Abandoned: return "abandoned";
    }
    return "abandoned";
}

PeriodicTaskRunToken::PeriodicTaskRunToken(
    std::shared_ptr<SharedState> state,
    std::size_t index,
    std::chrono::steady_clock::time_point started_at,
    std::int64_t started_at_unix_ms,
    bool counted) noexcept
    : state_(std::move(state)),
      index_(index),
      started_at_(started_at),
      started_at_unix_ms_(started_at_unix_ms),
      counted_(counted),
      active_(true) {}

PeriodicTaskRunToken::~PeriodicTaskRunToken() noexcept {
    (void)abandon();
}

PeriodicTaskRunToken::PeriodicTaskRunToken(
    PeriodicTaskRunToken&& other) noexcept
    : state_(std::move(other.state_)),
      index_(other.index_),
      started_at_(other.started_at_),
      started_at_unix_ms_(other.started_at_unix_ms_),
      counted_(other.counted_),
      active_(other.active_) {
    other.reset();
}

PeriodicTaskRunToken& PeriodicTaskRunToken::operator=(
    PeriodicTaskRunToken&& other) noexcept {
    if (this == &other) return *this;
    (void)abandon();
    state_ = std::move(other.state_);
    index_ = other.index_;
    started_at_ = other.started_at_;
    started_at_unix_ms_ = other.started_at_unix_ms_;
    counted_ = other.counted_;
    active_ = other.active_;
    other.reset();
    return *this;
}

bool PeriodicTaskRunToken::active() const noexcept {
    return active_;
}

bool PeriodicTaskRunToken::finish(PeriodicTaskOutcome outcome,
                                  std::string error) noexcept {
    if (!active_ || !state_) return false;
    try {
        const auto finished_at = state_->steady_now();
        const auto finished_at_unix_ms = state_->wall_now_unix_ms();
        const auto duration_ms = elapsed_ms(started_at_, finished_at);
        const auto sanitized_error = sanitize_error(error);
        {
            KPBR_LOCK_GUARD(state_->mutex);
            update_terminal_metrics(state_->entries[index_],
                                    outcome,
                                    counted_,
                                    state_->counter_ceiling,
                                    duration_ms,
                                    finished_at_unix_ms,
                                    sanitized_error);
        }
        reset();
        return true;
    } catch (...) {
        // A metrics failure must never escape a periodic task or a noexcept
        // destructor. Keep the token active so its destructor may retry once.
        return false;
    }
}

bool PeriodicTaskRunToken::success() noexcept {
    return finish(PeriodicTaskOutcome::Success);
}

bool PeriodicTaskRunToken::noop() noexcept {
    return finish(PeriodicTaskOutcome::Noop);
}

bool PeriodicTaskRunToken::failure(std::string error) noexcept {
    return finish(PeriodicTaskOutcome::Failure, std::move(error));
}

bool PeriodicTaskRunToken::skipped(std::string reason) noexcept {
    return finish(PeriodicTaskOutcome::Skipped, std::move(reason));
}

bool PeriodicTaskRunToken::abandon(std::string reason) noexcept {
    return finish(PeriodicTaskOutcome::Abandoned, std::move(reason));
}

void PeriodicTaskRunToken::reset() noexcept {
    state_.reset();
    index_ = 0;
    counted_ = false;
    active_ = false;
}

PeriodicTaskMetricsRegistry::PeriodicTaskMetricsRegistry(
    std::vector<std::string> stable_labels,
    PeriodicTaskMetricsClocks clocks,
    PeriodicTaskMetricsOptions options)
    : state_(std::make_shared<SharedState>()) {
    if (options.capacity == 0 || options.counter_ceiling == 0) {
        throw std::invalid_argument(
            "periodic task metrics limits must be greater than zero");
    }
    if (stable_labels.size() > options.capacity) {
        throw std::length_error(
            "periodic task metrics labels exceed fixed capacity");
    }
    for (const auto& label : stable_labels) {
        if (!stable_label_is_valid(label)) {
            throw std::invalid_argument(
                "periodic task metrics label must be a stable ASCII name");
        }
    }
    std::sort(stable_labels.begin(), stable_labels.end());
    if (std::adjacent_find(stable_labels.begin(), stable_labels.end()) !=
        stable_labels.end()) {
        throw std::invalid_argument(
            "periodic task metrics labels must be unique");
    }

    state_->capacity = options.capacity;
    state_->counter_ceiling = options.counter_ceiling;
    state_->steady_now = clocks.steady_now
                             ? std::move(clocks.steady_now)
                             : PeriodicTaskMetricsClocks::SteadyNow(steady_now);
    state_->wall_now_unix_ms =
        clocks.wall_now_unix_ms
            ? std::move(clocks.wall_now_unix_ms)
            : PeriodicTaskMetricsClocks::WallNowUnixMs(wall_now_unix_ms);
    state_->entries.reserve(options.capacity);
    for (auto& label : stable_labels) {
        periodic_task_metrics_detail::Entry entry;
        entry.metrics.label = std::move(label);
        state_->entries.push_back(std::move(entry));
    }
}

PeriodicTaskRunToken PeriodicTaskMetricsRegistry::begin(
    std::string_view stable_label) {
    const auto index = find_index(*state_, stable_label);
    const auto started_at = state_->steady_now();
    const auto started_at_unix_ms = state_->wall_now_unix_ms();
    bool counted = false;
    {
        KPBR_LOCK_GUARD(state_->mutex);
        auto& metrics = state_->entries[index].metrics;
        if (metrics.runs < state_->counter_ceiling) {
            ++metrics.runs;
            ++metrics.in_flight;
            counted = true;
        }
        metrics.last_started_at_unix_ms = started_at_unix_ms;
        metrics.last_event_at_unix_ms = started_at_unix_ms;
    }
    return PeriodicTaskRunToken(
        state_, index, started_at, started_at_unix_ms, counted);
}

void PeriodicTaskMetricsRegistry::record_skipped(
    std::string_view stable_label, std::string reason) {
    const auto index = find_index(*state_, stable_label);
    const auto timestamp = state_->wall_now_unix_ms();
    const auto sanitized_reason = sanitize_error(reason);
    KPBR_LOCK_GUARD(state_->mutex);
    auto& metrics = state_->entries[index].metrics;
    if (metrics.skipped < state_->counter_ceiling) ++metrics.skipped;
    metrics.last_event_at_unix_ms = timestamp;
    metrics.last_outcome = PeriodicTaskOutcome::Skipped;
    metrics.last_error = sanitized_reason;
}

std::vector<PeriodicTaskMetricsSnapshot>
PeriodicTaskMetricsRegistry::snapshot() const {
    std::vector<PeriodicTaskMetricsSnapshot> result;
    KPBR_LOCK_GUARD(state_->mutex);
    result.reserve(state_->entries.size());
    for (const auto& entry : state_->entries) {
        result.push_back(entry.metrics);
    }
    return result;
}

std::size_t PeriodicTaskMetricsRegistry::size() const noexcept {
    return state_->entries.size();
}

std::size_t PeriodicTaskMetricsRegistry::capacity() const noexcept {
    return state_->capacity;
}

} // namespace keen_pbr3
