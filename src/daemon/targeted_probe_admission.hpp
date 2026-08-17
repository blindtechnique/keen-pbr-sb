#pragma once

#include <cstddef>
#include <mutex>
#include <set>
#include <string>
#include <utility>

namespace keen_pbr3 {

// Admission for probing one named outbound on request.
//
// Deliberately NOT the round gate. `CoalescedManualSingleFlightGate` coalesces
// requests because every full round measures the same thing, so a second one
// arriving mid-flight can be answered by the first. That reasoning does not
// carry here: two targeted requests for different tags measure different
// things, and collapsing them would silently drop one operator's click.
//
// So the rule is per tag: one in flight for a given tag, any number of
// distinct tags at once, bounded so a scripted caller cannot make the daemon
// hold an unbounded set of names.
class TargetedProbeAdmission {
public:
    // Enough for a dashboard where every row is clicked at once, small enough
    // that the set stays trivial. Beyond it new tags are refused rather than
    // queued: a refused click is honest and retryable, a queued one arrives
    // after the operator stopped looking.
    static constexpr std::size_t kMaxConcurrent = 16;

    class Lease {
    public:
        Lease() = default;
        Lease(TargetedProbeAdmission* owner, std::string tag)
            : owner_(owner), tag_(std::move(tag)) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept
            : owner_(other.owner_), tag_(std::move(other.tag_)) {
            other.owner_ = nullptr;
        }
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                release();
                owner_ = other.owner_;
                tag_ = std::move(other.tag_);
                other.owner_ = nullptr;
            }
            return *this;
        }
        ~Lease() { release(); }

        bool admitted() const noexcept { return owner_ != nullptr; }

        // Released on destruction, including when the probe threw or the
        // executor refused the task. A tag left marked in flight would be
        // unprobeable until the daemon restarts.
        void release() noexcept {
            if (owner_ == nullptr) return;
            owner_->release(tag_);
            owner_ = nullptr;
        }

    private:
        TargetedProbeAdmission* owner_{nullptr};
        std::string tag_;
    };

    Lease acquire(const std::string& tag) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (in_flight_.size() >= kMaxConcurrent) return Lease{};
        if (!in_flight_.insert(tag).second) return Lease{};
        return Lease{this, tag};
    }

    std::size_t in_flight() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return in_flight_.size();
    }

private:
    void release(const std::string& tag) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            in_flight_.erase(tag);
        } catch (...) {
        }
    }

    mutable std::mutex mutex_;
    std::set<std::string> in_flight_;
};

} // namespace keen_pbr3
