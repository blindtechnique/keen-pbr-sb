#include "idle_stall_supervisor.hpp"

#include <exception>
#include <utility>

namespace keen_pbr3 {

void IdleStallSupervisor::reset(
    bool enable,
    std::chrono::seconds initial_delay) noexcept {
    cancel();
    if (!enable) return;
    enabled_.store(true, std::memory_order_release);
    schedule_after(initial_delay, /*runtime_active=*/true);
}

void IdleStallSupervisor::cancel() noexcept {
    enabled_.store(false, std::memory_order_release);
    active_schedule_serial_ = 0U;
    try {
        if (task_id_ >= 0 && callbacks_.cancel_scheduled) {
            callbacks_.cancel_scheduled(task_id_);
        }
    } catch (...) {
    }
    task_id_ = -1;
    reset_detectors();
    clear_scope();
    advance_coverage();
}

void IdleStallSupervisor::schedule_after(
    std::chrono::seconds delay,
    bool runtime_active) noexcept {
    try {
        if (!callbacks_.schedule_oneshot || !enabled() || !runtime_active) {
            return;
        }
        if (task_id_ >= 0) {
            active_schedule_serial_ = 0U;
            if (callbacks_.cancel_scheduled) {
                callbacks_.cancel_scheduled(task_id_);
            }
            task_id_ = -1;
        }
        const auto schedule_serial = ++next_schedule_serial_;
        active_schedule_serial_ = schedule_serial;
        const auto scheduled_task_id = callbacks_.schedule_oneshot(
            std::chrono::duration_cast<std::chrono::milliseconds>(delay),
            [this, schedule_serial]() { on_timer(schedule_serial); },
            "idle-stall-observer");
        if (scheduled_task_id < 0) {
            disable_after_schedule_failure(
                "scheduler returned an invalid task id");
            return;
        }
        // A deterministic fake scheduler may execute inline. In that case
        // on_timer() already consumed this exact serial and no pending timer
        // must be published after the callback returns.
        if (active_schedule_serial_ == schedule_serial) {
            task_id_ = scheduled_task_id;
        }
    } catch (const std::exception& error) {
        disable_after_schedule_failure(error.what());
    } catch (...) {
        disable_after_schedule_failure();
    }
}

void IdleStallSupervisor::invalidate_incomplete_scope() noexcept {
    reset_detectors();
    destination_selectors_.clear();
    affinity_destination_selectors_.clear();
    advance_coverage();
}

bool IdleStallSupervisor::update_observation_scope(
    const std::vector<std::string>& destination_selectors,
    const std::vector<std::string>& affinity_destination_selectors,
    std::optional<std::uint32_t> preventive_owned_mark,
    bool packaged_whatsapp_only_observation) {
    if (destination_selectors == destination_selectors_ &&
        affinity_destination_selectors ==
            affinity_destination_selectors_ &&
        preventive_owned_mark == preventive_owned_mark_ &&
        packaged_whatsapp_only_observation ==
            packaged_whatsapp_only_observation_) {
        return false;
    }

    reset_detectors();
    destination_selectors_ = destination_selectors;
    affinity_destination_selectors_ = affinity_destination_selectors;
    preventive_owned_mark_ = preventive_owned_mark;
    packaged_whatsapp_only_observation_ =
        packaged_whatsapp_only_observation;
    advance_coverage();
    return true;
}

void IdleStallSupervisor::on_timer(
    std::uint64_t schedule_serial) noexcept {
    if (!enabled() || schedule_serial == 0U ||
        active_schedule_serial_ != schedule_serial) {
        return;
    }
    active_schedule_serial_ = 0U;
    task_id_ = -1;
    try {
        if (callbacks_.run_observer) callbacks_.run_observer();
    } catch (...) {
    }
}

void IdleStallSupervisor::clear_scope() noexcept {
    destination_selectors_.clear();
    affinity_destination_selectors_.clear();
    preventive_owned_mark_.reset();
    packaged_whatsapp_only_observation_ = false;
}

void IdleStallSupervisor::disable_after_schedule_failure(
    std::string detail) noexcept {
    active_schedule_serial_ = 0U;
    task_id_ = -1;
    enabled_.store(false, std::memory_order_release);
    reset_detectors();
    clear_scope();
    advance_coverage();
    if (!detail.empty() && callbacks_.schedule_failed) {
        try {
            callbacks_.schedule_failed(std::move(detail));
        } catch (...) {
        }
    }
}

} // namespace keen_pbr3
