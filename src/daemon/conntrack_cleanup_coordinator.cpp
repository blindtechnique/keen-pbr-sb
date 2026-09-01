#include "conntrack_cleanup_coordinator.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::array<std::chrono::milliseconds, 5>
    kOwnedConntrackCleanupRetryDelays{
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{30},
    };

} // namespace

void ConntrackCleanupCoordinator::schedule(
    const OwnedConntrackCleanupSnapshot& source_snapshot,
    std::vector<std::uint32_t> remaining_marks,
    std::size_t no_progress_attempt) {
    if (!source_snapshot.valid() || remaining_marks.empty()) {
        return;
    }

    std::vector<std::uint32_t> filtered_marks;
    std::set<std::uint32_t> seen;
    filtered_marks.reserve(remaining_marks.size());
    for (const auto mark : remaining_marks) {
        if ((mark & source_snapshot.owned_mask) != 0U &&
            seen.insert(mark).second) {
            filtered_marks.push_back(mark);
        }
    }
    if (filtered_marks.empty()) {
        return;
    }

    OwnedConntrackCleanupSnapshot filtered_snapshot = source_snapshot;
    filtered_snapshot.marks = std::set<std::uint32_t>{
        filtered_marks.begin(), filtered_marks.end()};
    for (auto iterator = filtered_snapshot.priority_marks.begin();
         iterator != filtered_snapshot.priority_marks.end();) {
        if (filtered_snapshot.marks.count(*iterator) == 0U) {
            iterator = filtered_snapshot.priority_marks.erase(iterator);
        } else {
            ++iterator;
        }
    }
    OwnedConntrackCleanupRetry candidate{
        std::move(filtered_snapshot),
        std::move(filtered_marks),
        no_progress_attempt};

    if (pending_.has_value() &&
        pending_->snapshot.runtime_generation ==
            candidate.snapshot.runtime_generation &&
        pending_->snapshot.owned_mask == candidate.snapshot.owned_mask) {
        std::set<std::uint32_t> pending_marks{
            pending_->ordered_marks.begin(),
            pending_->ordered_marks.end()};
        for (const auto mark : candidate.ordered_marks) {
            if (pending_marks.insert(mark).second) {
                pending_->ordered_marks.push_back(mark);
                pending_->snapshot.marks.insert(mark);
                if (candidate.snapshot.priority_marks.count(mark) != 0U) {
                    pending_->snapshot.priority_marks.insert(mark);
                }
            }
        }
        pending_->snapshot.ipv6_enabled =
            pending_->snapshot.ipv6_enabled ||
            candidate.snapshot.ipv6_enabled;
        pending_->no_progress_attempt = std::min(
            pending_->no_progress_attempt,
            candidate.no_progress_attempt);
    } else {
        if (pending_.has_value() || retry_task_id_ >= 0) {
            cancel();
        }
        pending_ = std::move(candidate);
    }

    arm();
}

void ConntrackCleanupCoordinator::schedule_remaining(
    const OwnedConntrackCleanupRetry& retry,
    std::vector<std::uint32_t> remaining_marks) {
    if (remaining_marks.empty()) {
        return;
    }
    const bool made_progress =
        remaining_marks.size() < retry.ordered_marks.size();
    schedule(
        retry.snapshot,
        std::move(remaining_marks),
        made_progress ? 0U : retry.no_progress_attempt + 1U);
}

void ConntrackCleanupCoordinator::arm() {
    if (retry_task_id_ >= 0 || !pending_.has_value()) {
        return;
    }
    const auto attempt = pending_->no_progress_attempt;
    if (attempt >= kOwnedConntrackCleanupRetryDelays.size()) {
        if (callbacks_.retry_budget_exhausted) {
            callbacks_.retry_budget_exhausted();
        }
        pending_.reset();
        return;
    }

    const int task_id = callbacks_.schedule_oneshot(
        kOwnedConntrackCleanupRetryDelays[attempt],
        [this]() { on_timer(); },
        "owned-conntrack-cleanup-retry");
    if (task_id >= 0) {
        retry_task_id_ = task_id;
    }
}

std::optional<OwnedConntrackCleanupSnapshot>
ConntrackCleanupCoordinator::pending_remainder(
    std::uint64_t runtime_generation) const {
    if (!pending_.has_value() || !pending_->valid() ||
        pending_->snapshot.runtime_generation != runtime_generation) {
        return std::nullopt;
    }
    return owned_conntrack_cleanup_retry_remainder(*pending_);
}

void ConntrackCleanupCoordinator::cancel() {
    if (retry_task_id_ >= 0) {
        callbacks_.cancel_scheduled(retry_task_id_);
        retry_task_id_ = -1;
    }
    pending_.reset();
}

void ConntrackCleanupCoordinator::clear_after_handoff() noexcept {
    const int task_id = std::exchange(retry_task_id_, -1);
    if (task_id >= 0) {
        try {
            callbacks_.cancel_scheduled(task_id);
        } catch (...) {
        }
    }
    pending_.reset();
}

bool ConntrackCleanupCoordinator::note_command_unavailable() noexcept {
    if (command_unavailable_reported_) {
        return false;
    }
    command_unavailable_reported_ = true;
    return true;
}

void ConntrackCleanupCoordinator::on_timer() {
    retry_task_id_ = -1;
    if (!pending_.has_value()) {
        return;
    }
    auto retry = std::move(*pending_);
    pending_.reset();
    callbacks_.dispatch_retry(std::move(retry));
}

} // namespace keen_pbr3
