#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::size_t kMaxNfqwsRotatorSnapshotSize = 128U * 1024U;
inline constexpr std::size_t kMaxNfqwsRotatorPools = 64U;
inline constexpr std::uint64_t kMaxNfqwsRotatorTargets = 4096U;

struct NfqwsProcessGeneration {
    std::int64_t pid{0};
    std::uint64_t start_ticks{0};

    bool operator==(const NfqwsProcessGeneration& other) const noexcept {
        return pid == other.pid && start_ticks == other.start_ticks;
    }
    bool operator!=(const NfqwsProcessGeneration& other) const noexcept {
        return !(*this == other);
    }
};

struct NfqwsRotatorPoolState {
    std::string key;
    std::uint64_t tracked_targets{0};
    std::map<std::uint32_t, std::uint64_t> slot_histogram;
    std::map<std::uint32_t, std::uint64_t> slot_count_histogram;
    std::map<std::uint32_t, std::uint64_t> pending_failure_histogram;

    std::optional<std::uint32_t> unanimous_slot() const noexcept;
    std::optional<std::uint32_t> unanimous_slot_count() const noexcept;
    std::optional<std::uint32_t> unanimous_pending_failures() const noexcept;
    std::uint32_t max_pending_failures() const noexcept;
};

struct NfqwsRotatorSnapshot {
    std::uint64_t sequence{0};
    NfqwsProcessGeneration generation;
    std::int64_t observed_at_unix{0};
    bool truncated{false};
    std::vector<NfqwsRotatorPoolState> pools;
};

struct NfqwsRotatorSnapshotParseResult {
    std::optional<NfqwsRotatorSnapshot> snapshot;
    std::string error;
};

NfqwsRotatorSnapshotParseResult parse_nfqws_rotator_snapshot(
    const std::string& content);

std::optional<NfqwsProcessGeneration> parse_nfqws_process_stat(
    std::string_view content, std::int64_t expected_pid) noexcept;
std::optional<NfqwsProcessGeneration> read_nfqws_process_generation(
    std::int64_t pid, const std::string& proc_root = "/proc");

// Reads only rotator-state.0 and rotator-state.1 below an already protected
// runtime directory. Symlinks, non-regular files, multiply linked files,
// writable-by-group/other files and oversized publications fail closed.
std::vector<std::string> read_nfqws_rotator_snapshot_candidates(
    const std::string& directory);

enum class NfqwsRotatorStateStatus {
    ready,
    warming_up,
    unsupported,
    stale,
};

const char* nfqws_rotator_state_status_name(
    NfqwsRotatorStateStatus status) noexcept;

struct NfqwsRotatorStateView {
    NfqwsRotatorStateStatus status{NfqwsRotatorStateStatus::unsupported};
    std::optional<NfqwsRotatorSnapshot> snapshot;
};

struct NfqwsRotatorStateSelection {
    bool reporter_expected{false};
    std::optional<NfqwsProcessGeneration> process_generation;
    std::uint64_t process_age_seconds{0};
    std::int64_t now_unix{0};
    std::uint64_t warming_seconds{20};
    std::uint64_t stale_seconds{30};
    std::vector<std::string> snapshot_candidates;
};

NfqwsRotatorStateView select_nfqws_rotator_state(
    const NfqwsRotatorStateSelection& selection);

} // namespace keen_pbr3
