#pragma once

#include <cstdint>
#include <mutex>

namespace keen_pbr3 {

enum class ConfigReloadRequestStatus : std::uint8_t {
    started,
    coalesced,
    stopped,
};

struct ConfigReloadClaim {
    std::uint64_t token{0};

    explicit operator bool() const noexcept {
        return token != 0;
    }
};

struct ConfigReloadRequest {
    ConfigReloadRequestStatus status{ConfigReloadRequestStatus::stopped};
    ConfigReloadClaim claim;
};

struct ConfigReloadCompletion {
    bool owned{false};
    bool rerun_requested{false};
};

enum class ConfigReloadCommitStatus : std::uint8_t {
    claimed,
    superseded,
    stopped,
    lost,
};

// Coordinates asynchronous config preparation with the serialized control
// loop. A monotonic token and an explicit prepare->commit claim make an
// ambiguous post failure safe: either the worker cancels first or the queued
// callback claims commit first, never both.
class ConfigReloadCoordinator {
public:
    ConfigReloadRequest request() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) {
            return {ConfigReloadRequestStatus::stopped, {}};
        }
        if (phase_ != Phase::idle) {
            pending_ = true;
            return {ConfigReloadRequestStatus::coalesced, {}};
        }

        phase_ = Phase::preparing;
        active_token_ = ++next_token_;
        if (active_token_ == 0) {
            active_token_ = ++next_token_;
        }
        return {
            ConfigReloadRequestStatus::started,
            ConfigReloadClaim{active_token_},
        };
    }

    ConfigReloadCommitStatus claim_commit(
        ConfigReloadClaim claim) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!matches_locked(claim) || phase_ != Phase::preparing) {
            return ConfigReloadCommitStatus::lost;
        }
        if (stopped_) {
            phase_ = Phase::cancelled;
            return ConfigReloadCommitStatus::stopped;
        }
        if (pending_) {
            // A newer SIGHUP arrived while the file was being prepared. Do
            // not briefly publish the older bytes; the completion path starts
            // one replacement generation which reads the file again.
            phase_ = Phase::cancelled;
            return ConfigReloadCommitStatus::superseded;
        }
        phase_ = Phase::commit_claimed;
        return ConfigReloadCommitStatus::claimed;
    }

    bool cancel(ConfigReloadClaim claim) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!matches_locked(claim) || phase_ != Phase::preparing) {
            return false;
        }
        phase_ = Phase::cancelled;
        return true;
    }

    ConfigReloadCompletion complete(ConfigReloadClaim claim) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!matches_locked(claim) || phase_ == Phase::preparing) {
            return {};
        }

        const bool rerun = pending_ && !stopped_;
        phase_ = Phase::idle;
        active_token_ = 0;
        pending_ = false;
        return {true, rerun};
    }

    void stop() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        pending_ = false;
    }

private:
    enum class Phase : std::uint8_t {
        idle,
        preparing,
        commit_claimed,
        cancelled,
    };

    bool matches_locked(ConfigReloadClaim claim) const noexcept {
        return claim && active_token_ == claim.token &&
               phase_ != Phase::idle;
    }

    std::mutex mutex_;
    std::uint64_t next_token_{0};
    std::uint64_t active_token_{0};
    Phase phase_{Phase::idle};
    bool pending_{false};
    bool stopped_{false};
};

} // namespace keen_pbr3
