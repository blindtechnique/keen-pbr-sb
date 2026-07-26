#include "auth_runtime.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

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
        if (lockout_finished && inactive) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
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
    return true;
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
        found = entries_.emplace(
            key, Entry{0, now, Clock::time_point{}, now}).first;
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
    entries_.erase(source_key(remote_address));
}

std::size_t AuthLoginRateLimiter::tracked_source_count(
    const Clock::time_point now) {
    std::lock_guard lock(mutex_);
    remove_stale_locked(now);
    return entries_.size();
}

} // namespace keen_pbr3
