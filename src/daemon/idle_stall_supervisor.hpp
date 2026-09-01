#pragma once

#include "../runtime/idle_stall_detector.hpp"
#include "../runtime/udp_call_affinity.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct IdleStallSupervisorCallbacks final {
    std::function<int(
        std::chrono::milliseconds,
        std::function<void()>,
        std::string)> schedule_oneshot;
    std::function<void(int)> cancel_scheduled;
    std::function<void()> run_observer;
    std::function<void(std::string)> schedule_failed;
};

// Owns observer cadence, single-flight/coverage identity and the two
// control-loop-only detectors. Conntrack observation and every physical
// mutation stay in Daemon and the existing typed firewall owner.
class IdleStallSupervisor final {
public:
    class InflightGuard final {
    public:
        explicit InflightGuard(IdleStallSupervisor& owner) noexcept
            : owner_(&owner) {}
        ~InflightGuard() {
            if (owner_) owner_->finish_inflight();
        }

        InflightGuard(const InflightGuard&) = delete;
        InflightGuard& operator=(const InflightGuard&) = delete;

        void release() noexcept { owner_ = nullptr; }

    private:
        IdleStallSupervisor* owner_;
    };

    IdleStallSupervisor() = default;
    explicit IdleStallSupervisor(IdleStallSupervisorCallbacks callbacks)
        : callbacks_(std::move(callbacks)) {}

    IdleStallSupervisor(const IdleStallSupervisor&) = delete;
    IdleStallSupervisor& operator=(const IdleStallSupervisor&) = delete;

    void configure(IdleStallSupervisorCallbacks callbacks) {
        callbacks_ = std::move(callbacks);
    }

    void reset(
        bool enable,
        std::chrono::seconds initial_delay) noexcept;
    void cancel() noexcept;
    void schedule_after(
        std::chrono::seconds delay,
        bool runtime_active) noexcept;

    bool enabled() const noexcept {
        return enabled_.load(std::memory_order_acquire);
    }

    bool inflight() const noexcept {
        return inflight_.load(std::memory_order_acquire);
    }

    bool timer_pending() const noexcept { return task_id_ >= 0; }

    std::uint64_t coverage_generation() const noexcept {
        return coverage_generation_.load(std::memory_order_acquire);
    }

    bool current_coverage(std::uint64_t expected) const noexcept {
        return enabled() && coverage_generation() == expected;
    }

    bool try_begin_inflight() noexcept {
        bool expected = false;
        return inflight_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel);
    }

    void finish_inflight() noexcept {
        inflight_.store(false, std::memory_order_release);
    }

    InflightGuard adopt_inflight() noexcept {
        return InflightGuard{*this};
    }

    void reset_detectors() noexcept {
        idle_detector_.reset();
        affinity_detector_.reset();
    }

    void reset_idle_detector() noexcept { idle_detector_.reset(); }
    void reset_affinity_detector() noexcept { affinity_detector_.reset(); }

    void invalidate_incomplete_scope() noexcept;

    bool update_observation_scope(
        const std::vector<std::string>& destination_selectors,
        const std::vector<std::string>& affinity_destination_selectors,
        std::optional<std::uint32_t> preventive_owned_mark,
        bool packaged_whatsapp_only_observation);

    IdleStallDetector& idle_detector() noexcept { return idle_detector_; }
    const IdleStallDetector& idle_detector() const noexcept {
        return idle_detector_;
    }

    UdpCallAffinityDetector& affinity_detector() noexcept {
        return affinity_detector_;
    }
    const UdpCallAffinityDetector& affinity_detector() const noexcept {
        return affinity_detector_;
    }

    const std::vector<std::string>& destination_selectors() const noexcept {
        return destination_selectors_;
    }
    const std::vector<std::string>& affinity_destination_selectors()
        const noexcept {
        return affinity_destination_selectors_;
    }
    std::optional<std::uint32_t> preventive_owned_mark() const noexcept {
        return preventive_owned_mark_;
    }
    bool packaged_whatsapp_only_observation() const noexcept {
        return packaged_whatsapp_only_observation_;
    }

private:
    void on_timer(std::uint64_t schedule_serial) noexcept;
    void clear_scope() noexcept;
    void disable_after_schedule_failure(std::string detail = {}) noexcept;
    void advance_coverage() noexcept {
        coverage_generation_.fetch_add(1U, std::memory_order_acq_rel);
    }

    IdleStallSupervisorCallbacks callbacks_;
    int task_id_{-1};
    // A cancelled callback may already be queued on the control loop. Its
    // serial must not consume a newer timer slot or dispatch another scan.
    std::uint64_t next_schedule_serial_{0U};
    std::uint64_t active_schedule_serial_{0U};
    IdleStallDetector idle_detector_;
    UdpCallAffinityDetector affinity_detector_;
    std::vector<std::string> destination_selectors_;
    std::vector<std::string> affinity_destination_selectors_;
    std::optional<std::uint32_t> preventive_owned_mark_;
    bool packaged_whatsapp_only_observation_{false};
    std::atomic<bool> enabled_{false};
    std::atomic<bool> inflight_{false};
    std::atomic<std::uint64_t> coverage_generation_{1U};
};

} // namespace keen_pbr3
