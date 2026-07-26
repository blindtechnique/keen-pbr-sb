#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace keen_pbr3 {

inline constexpr std::size_t kAuthSessionCapacity = 64;
inline constexpr std::size_t kAuthLoginMaxFailures = 5;
inline constexpr std::size_t kAuthLoginMaxSources = 256;

// Sessions use monotonic time so an NTP correction cannot unexpectedly extend
// or invalidate a web session.
class AuthSessionRegistry {
public:
    using Clock = std::chrono::steady_clock;

    explicit AuthSessionRegistry(
        std::size_t capacity = kAuthSessionCapacity);

    bool insert(const std::string& token,
                std::chrono::seconds ttl,
                Clock::time_point now = Clock::now());
    bool contains(const std::string& token,
                  Clock::time_point now = Clock::now());
    void erase(const std::string& token);
    void clear();
    std::size_t size(Clock::time_point now = Clock::now());

private:
    void remove_expired_locked(Clock::time_point now);

    const std::size_t capacity_;
    std::mutex mutex_;
    std::unordered_map<std::string, Clock::time_point> sessions_;
};

// A bounded per-source limiter. Only failed logins occupy the table, successful
// authentication removes the source immediately.
class AuthLoginRateLimiter {
public:
    using Clock = std::chrono::steady_clock;

    struct Limits {
        std::size_t max_failures{kAuthLoginMaxFailures};
        std::chrono::seconds window{60};
        std::chrono::seconds lockout{60};
        std::size_t max_sources{kAuthLoginMaxSources};
    };

    AuthLoginRateLimiter();
    explicit AuthLoginRateLimiter(Limits limits);

    bool allow(const std::string& remote_address,
               Clock::time_point now = Clock::now());
    void record_failure(const std::string& remote_address,
                        Clock::time_point now = Clock::now());
    void record_success(const std::string& remote_address);
    std::size_t tracked_source_count(
        Clock::time_point now = Clock::now());

private:
    struct Entry {
        std::size_t failures{0};
        Clock::time_point window_started{};
        Clock::time_point blocked_until{};
        Clock::time_point last_seen{};
    };

    static std::string source_key(const std::string& remote_address);
    void remove_stale_locked(Clock::time_point now);

    const Limits limits_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    Clock::time_point saturated_until_{};
};

} // namespace keen_pbr3
