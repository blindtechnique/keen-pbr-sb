#include "auth_runtime.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

AuthSessionRegistry::AuthSessionRegistry(const std::size_t capacity)
    : capacity_(capacity) {
    if (capacity_ == 0) {
        throw std::invalid_argument("session capacity must be positive");
    }
}

void AuthSessionRegistry::remove_expired_locked(const Clock::time_point now) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second <= now) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

bool AuthSessionRegistry::insert(const std::string& token,
                                 const std::chrono::seconds ttl,
                                 const Clock::time_point now) {
    if (token.empty() || ttl <= std::chrono::seconds::zero()) {
        return false;
    }
    std::lock_guard lock(mutex_);
    remove_expired_locked(now);
    if (sessions_.size() >= capacity_) return false;
    return sessions_.emplace(token, now + ttl).second;
}

bool AuthSessionRegistry::contains(const std::string& token,
                                   const Clock::time_point now) {
    if (token.empty()) return false;
    std::lock_guard lock(mutex_);
    remove_expired_locked(now);
    return sessions_.find(token) != sessions_.end();
}

void AuthSessionRegistry::erase(const std::string& token) {
    std::lock_guard lock(mutex_);
    sessions_.erase(token);
}

void AuthSessionRegistry::clear() {
    std::lock_guard lock(mutex_);
    sessions_.clear();
}

std::size_t AuthSessionRegistry::size(const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    remove_expired_locked(now);
    return sessions_.size();
}

AuthLoginRateLimiter::AuthLoginRateLimiter()
    : AuthLoginRateLimiter(Limits{}) {}

AuthLoginRateLimiter::AuthLoginRateLimiter(Limits limits)
    : limits_(limits) {
    if (limits_.max_failures == 0 ||
        limits_.window <= std::chrono::seconds::zero() ||
        limits_.lockout <= std::chrono::seconds::zero() ||
        limits_.max_sources == 0) {
        throw std::invalid_argument("invalid login rate limiter limits");
    }
}

AuthLoginRateLimiter::Permit::Permit(
    AuthLoginRateLimiter& owner, std::string source) noexcept
    : owner_(&owner), source_(std::move(source)) {}

AuthLoginRateLimiter::Permit::Permit(Permit&& other) noexcept
    : owner_(std::exchange(other.owner_, nullptr)),
      source_(std::move(other.source_)) {}

AuthLoginRateLimiter::Permit& AuthLoginRateLimiter::Permit::operator=(
    Permit&& other) noexcept {
    if (this == &other) return *this;
    if (owner_ != nullptr) {
        finish(Verdict::failure, Clock::now());
    }
    owner_ = std::exchange(other.owner_, nullptr);
    source_ = std::move(other.source_);
    return *this;
}

AuthLoginRateLimiter::Permit::~Permit() {
    if (owner_ != nullptr) {
        finish(Verdict::failure, Clock::now());
    }
}

void AuthLoginRateLimiter::Permit::record_success(
    const Clock::time_point now) noexcept {
    finish(Verdict::success, now);
}

void AuthLoginRateLimiter::Permit::record_failure(
    const Clock::time_point now) noexcept {
    finish(Verdict::failure, now);
}

void AuthLoginRateLimiter::Permit::release(
    const Clock::time_point now) noexcept {
    finish(Verdict::neutral, now);
}

void AuthLoginRateLimiter::Permit::finish(
    const Verdict verdict, const Clock::time_point now) noexcept {
    auto* owner = std::exchange(owner_, nullptr);
    if (owner == nullptr) return;
    try {
        std::lock_guard lock(owner->mutex_);
        owner->finish_attempt_locked(source_, verdict, now);
    } catch (...) {
        // Never let authentication cleanup terminate the process. A mutex
        // failure has no safe local recovery; the reservation remains in the
        // fail-closed direction until the limiter is torn down.
    }
}

std::string AuthLoginRateLimiter::source_key(
    const std::string& remote_address) {
    // All unknown/empty peers share one bucket instead of bypassing the
    // limiter by omitting an address.
    if (remote_address.empty()) return "<unknown>";

    in_addr ipv4{};
    if (::inet_pton(AF_INET, remote_address.c_str(), &ipv4) == 1) {
        std::array<char, INET_ADDRSTRLEN> normalized{};
        if (::inet_ntop(
                AF_INET, &ipv4, normalized.data(),
                normalized.size())) {
            return normalized.data();
        }
    }

    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, remote_address.c_str(), &ipv6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
            in_addr mapped{};
            std::memcpy(
                &mapped, ipv6.s6_addr + 12, sizeof(mapped));
            std::array<char, INET_ADDRSTRLEN> normalized{};
            if (::inet_ntop(
                    AF_INET, &mapped, normalized.data(),
                    normalized.size())) {
                return normalized.data();
            }
        }
        std::array<char, INET6_ADDRSTRLEN> normalized{};
        if (::inet_ntop(
                AF_INET6, &ipv6, normalized.data(),
                normalized.size())) {
            return normalized.data();
        }
    }
    return remote_address;
}

void AuthLoginRateLimiter::remove_stale_locked(const Clock::time_point now) {
    const auto retention = limits_.window + limits_.lockout;
    for (auto it = entries_.begin(); it != entries_.end();) {
        const bool lockout_finished = it->second.blocked_until <= now;
        const bool inactive =
            now - it->second.last_seen >= retention;
        if (it->second.reservations == 0 && lockout_finished && inactive) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

std::optional<AuthLoginRateLimiter::Permit>
AuthLoginRateLimiter::reserve_attempt(
    const std::string& remote_address, const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    remove_stale_locked(now);
    const auto key = source_key(remote_address);
    auto found = entries_.find(key);
    if (found == entries_.end()) {
        // Unknown sources fail closed while the bounded table is saturated.
        // Rotating source addresses must not multiply simultaneous checks.
        if (saturated_until_ > now ||
            entries_.size() >= limits_.max_sources) {
            saturated_until_ =
                std::max(saturated_until_, now + limits_.lockout);
            return std::nullopt;
        }
        Entry entry;
        entry.window_started = now;
        entry.last_seen = now;
        found = entries_.emplace(key, entry).first;
    }

    auto& entry = found->second;
    entry.last_seen = now;
    if (entry.blocked_until > now) return std::nullopt;
    if (now - entry.window_started >= limits_.window) {
        entry.failures = 0;
        entry.window_started = now;
        entry.blocked_until = Clock::time_point{};
    }
    if (entry.failures + entry.reservations >= limits_.max_failures) {
        return std::nullopt;
    }
    // Construct the RAII object before mutating the counter. If copying the
    // source key runs out of memory, no invisible reservation is left behind.
    Permit permit(*this, key);
    ++entry.reservations;
    return permit;
}

bool AuthLoginRateLimiter::allow(const std::string& remote_address,
                                 const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    remove_stale_locked(now);
    const auto found = entries_.find(source_key(remote_address));
    if (found == entries_.end()) {
        // Once the bounded table is saturated, unknown sources fail closed
        // until the short lockout expires. Evicting entries here would let an
        // attacker bypass per-source limits by rotating source addresses.
        return saturated_until_ <= now;
    }

    auto& entry = found->second;
    entry.last_seen = now;
    if (entry.blocked_until > now) return false;
    if (now - entry.window_started >= limits_.window) {
        entry.failures = 0;
        entry.window_started = now;
    }
    return entry.failures + entry.reservations < limits_.max_failures;
}

void AuthLoginRateLimiter::record_failure(
    const std::string& remote_address,
    const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    remove_stale_locked(now);
    const auto key = source_key(remote_address);
    auto found = entries_.find(key);
    if (found == entries_.end()) {
        if (entries_.size() >= limits_.max_sources) {
            saturated_until_ =
                std::max(saturated_until_, now + limits_.lockout);
            return;
        }
        Entry entry;
        entry.window_started = now;
        entry.last_seen = now;
        found = entries_.emplace(key, entry).first;
    }

    auto& entry = found->second;
    if (now - entry.window_started >= limits_.window) {
        entry.failures = 0;
        entry.window_started = now;
        entry.blocked_until = Clock::time_point{};
    }
    entry.last_seen = now;
    ++entry.failures;
    if (entry.failures >= limits_.max_failures) {
        entry.blocked_until = now + limits_.lockout;
    }
}

void AuthLoginRateLimiter::record_success(
    const std::string& remote_address) {
    std::lock_guard lock(mutex_);
    const auto found = entries_.find(source_key(remote_address));
    if (found == entries_.end()) return;
    if (found->second.reservations == 0) {
        entries_.erase(found);
        return;
    }
    found->second.failures = 0;
    found->second.blocked_until = Clock::time_point{};
    found->second.window_started = Clock::now();
    found->second.last_seen = found->second.window_started;
}

void AuthLoginRateLimiter::finish_attempt_locked(
    const std::string& source,
    const Permit::Verdict verdict,
    const Clock::time_point now) noexcept {
    const auto found = entries_.find(source);
    if (found == entries_.end()) return;
    auto& entry = found->second;
    if (entry.reservations > 0) --entry.reservations;
    entry.last_seen = now;

    if (verdict == Permit::Verdict::success) {
        entry.failures = 0;
        entry.blocked_until = Clock::time_point{};
        entry.window_started = now;
    } else if (verdict == Permit::Verdict::failure) {
        if (now - entry.window_started >= limits_.window) {
            entry.failures = 0;
            entry.window_started = now;
            entry.blocked_until = Clock::time_point{};
        }
        ++entry.failures;
        if (entry.failures >= limits_.max_failures) {
            entry.blocked_until = now + limits_.lockout;
        }
    }

    // A successful or neutral first attempt should not consume a bounded
    // table slot. Keep the entry while parallel permits still exist so their
    // admission remains accounted for.
    if (entry.reservations == 0 && entry.failures == 0 &&
        entry.blocked_until <= now) {
        entries_.erase(found);
    }
}

std::size_t AuthLoginRateLimiter::tracked_source_count(
    const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    remove_stale_locked(now);
    return entries_.size();
}

std::uint32_t auth_forward_capacity_for(
    const std::uint32_t firmware_threshold) {
    if (firmware_threshold == 0U) return 0U;
    return firmware_threshold - 1U;
}

AuthForwardBudget::AuthForwardBudget(const std::uint32_t capacity,
                                     const std::chrono::seconds window)
    : capacity_(capacity), window_(window) {}

AuthForwardBudget::Permit::Permit(
    AuthForwardBudget& owner,
    std::unique_lock<std::mutex> lock) noexcept
    : owner_(&owner), lock_(std::move(lock)) {}

void AuthForwardBudget::Permit::record_forwarded_failure(
    const Clock::time_point now) {
    if (failure_recorded_ || owner_ == nullptr || !lock_.owns_lock()) return;
    owner_->prune_locked(now);
    owner_->record_forwarded_failure_locked(now);
    failure_recorded_ = true;
}

void AuthForwardBudget::prune_locked(const Clock::time_point now) {
    // The firmware counts failures over a sliding observation window, so a
    // fixed-epoch counter would hand back the whole budget at each boundary
    // and let a patient caller straddle two epochs.
    while (!forwarded_.empty() && now - forwarded_.front() >= window_) {
        forwarded_.pop_front();
    }
}

void AuthForwardBudget::record_forwarded_failure_locked(
    const Clock::time_point now) {
    forwarded_.push_back(now);
    const std::size_t bound = capacity_ > 0U ? capacity_ : 1U;
    while (forwarded_.size() > bound) {
        forwarded_.pop_front();
    }
}

std::optional<AuthForwardBudget::Permit>
AuthForwardBudget::reserve_forward(const Clock::time_point now) {
    std::unique_lock lock(mutex_);
    prune_locked(now);
    if (forwarded_.size() >= capacity_) return std::nullopt;
    return Permit(*this, std::move(lock));
}

bool AuthForwardBudget::may_forward(const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    prune_locked(now);
    return forwarded_.size() < capacity_;
}

void AuthForwardBudget::record_forwarded_failure(const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    prune_locked(now);
    // Recorded even when already at capacity: a caller that raced past
    // may_forward() still spent the firmware's budget. Keeping the newest
    // timestamps and dropping the oldest holds the deque bounded while pushing
    // the refill later, never earlier - the safe direction to round in.
    record_forwarded_failure_locked(now);
}

std::size_t AuthForwardBudget::spent(const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    prune_locked(now);
    return forwarded_.size();
}

std::uint32_t AuthForwardBudget::capacity() {
    std::lock_guard lock(mutex_);
    return capacity_;
}

void AuthForwardBudget::reconfigure(const std::uint32_t capacity,
                                    const std::chrono::seconds window) {
    std::lock_guard lock(mutex_);
    capacity_ = capacity;
    window_ = window;
    // Trimming drops the oldest entries, so the timestamps that survive are
    // the newest. That delays the refill rather than accelerating it, which is
    // the direction to round in when the policy has just become stricter.
    const std::size_t bound = capacity_ > 0U ? capacity_ : 1U;
    while (forwarded_.size() > bound) {
        forwarded_.pop_front();
    }
}

} // namespace keen_pbr3
