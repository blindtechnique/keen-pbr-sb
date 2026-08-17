#pragma once

#include "runtime_recovery_policy.hpp"
#include "../runtime/conntrack_manager.hpp"
#include "../runtime/runtime_mutation_admission.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace keen_pbr3 {

enum class OwnedConntrackCleanupOperationStatus : std::uint8_t {
    busy,
    stale,
    completed,
};

struct OwnedConntrackCleanupOperationResult {
    OwnedConntrackCleanupOperationStatus status{
        OwnedConntrackCleanupOperationStatus::stale};
    ConntrackCleanupSummary cleanup;
    std::shared_ptr<RuntimeMutationAdmission::Lease> mutation_lease;
};

// Thread-safe single-result handoff for one exact old-generation cleanup.
// The worker never owns daemon state: it publishes one terminal outcome here,
// while the control loop may cancel and absorb the immutable retry before a
// configuration generation reuses its numerical marks.
class OwnedConntrackCleanupOperation {
public:
    explicit OwnedConntrackCleanupOperation(
        OwnedConntrackCleanupRetry retry)
        : retry_(std::move(retry)) {}

    const OwnedConntrackCleanupRetry& retry() const noexcept {
        return retry_;
    }

    bool cancelled() const noexcept {
        return cancelled_.load(std::memory_order_acquire);
    }

    void cancel() noexcept {
        cancelled_.store(true, std::memory_order_release);
    }

    bool finish(
        OwnedConntrackCleanupOperationStatus status,
        ConntrackCleanupSummary cleanup = {},
        std::shared_ptr<RuntimeMutationAdmission::Lease> mutation_lease = {}) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cancelled_.load(std::memory_order_acquire) || result_.has_value()) {
            return false;
        }
        result_ = OwnedConntrackCleanupOperationResult{
            status,
            std::move(cleanup),
            std::move(mutation_lease)};
        return true;
    }

    std::optional<OwnedConntrackCleanupOperationResult> take_result() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!result_.has_value()) {
            return std::nullopt;
        }
        auto result = std::move(result_);
        result_.reset();
        return result;
    }

    void release_mutation_lease() noexcept {
        std::shared_ptr<RuntimeMutationAdmission::Lease> lease;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (result_.has_value()) {
                lease = std::move(result_->mutation_lease);
            }
        } catch (...) {
            return;
        }
        if (lease) {
            lease->release();
        }
    }

private:
    OwnedConntrackCleanupRetry retry_;
    std::atomic<bool> cancelled_{false};
    std::mutex mutex_;
    std::optional<OwnedConntrackCleanupOperationResult> result_;
};

} // namespace keen_pbr3
