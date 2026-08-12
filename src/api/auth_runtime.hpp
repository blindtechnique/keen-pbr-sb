#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace keen_pbr3 {

inline constexpr std::size_t kAuthSessionCapacity = 64;
// Three attempts, then a hundred seconds. This is a VPN helper on a home
// router, not a bank: the number exists to stop hammering, not to punish
// somebody who mistyped their own password twice.
inline constexpr std::size_t kAuthLoginMaxFailures = 3;
inline constexpr std::chrono::seconds kAuthLoginWindow{100};
inline constexpr std::chrono::seconds kAuthLoginLockout{100};
inline constexpr std::size_t kAuthLoginMaxSources = 256;

// KeeneticOS brute-force policy, measured on a live Keenetic Ultra via
// /rci/show/rc/ip/http and matching the firmware defaults: five failures
// inside a three minute observation window, then a fifteen minute lock.
inline constexpr std::uint32_t kNdmsDefaultLockoutThreshold = 5;
inline constexpr std::chrono::seconds kNdmsDefaultLockoutObservation{180};

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

    // One atomically admitted credential attempt. Outstanding permits count
    // against the per-source ceiling until their verdict is recorded, so a
    // burst of parallel requests cannot all pass allow() before any failure
    // reaches record_failure(). An abandoned/exceptional attempt is a failure
    // in the safe direction.
    class Permit {
    public:
        Permit(Permit&& other) noexcept;
        Permit& operator=(Permit&& other) noexcept;
        Permit(const Permit&) = delete;
        Permit& operator=(const Permit&) = delete;
        ~Permit();

        void record_success(Clock::time_point now = Clock::now()) noexcept;
        void record_failure(Clock::time_point now = Clock::now()) noexcept;
        // Releases an admitted attempt which never reached a credential
        // verdict (for example, an unavailable authentication endpoint).
        void release(Clock::time_point now = Clock::now()) noexcept;

    private:
        Permit(AuthLoginRateLimiter& owner, std::string source) noexcept;
        enum class Verdict { success, failure, neutral };
        void finish(Verdict verdict, Clock::time_point now) noexcept;

        AuthLoginRateLimiter* owner_{nullptr};
        std::string source_;
        friend class AuthLoginRateLimiter;
    };

    struct Limits {
        std::size_t max_failures{kAuthLoginMaxFailures};
        std::chrono::seconds window{kAuthLoginWindow};
        std::chrono::seconds lockout{kAuthLoginLockout};
        std::size_t max_sources{kAuthLoginMaxSources};
    };

    AuthLoginRateLimiter();
    explicit AuthLoginRateLimiter(Limits limits);

    std::optional<Permit> reserve_attempt(
        const std::string& remote_address,
        Clock::time_point now = Clock::now());

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
        std::size_t reservations{0};
        Clock::time_point window_started{};
        Clock::time_point blocked_until{};
        Clock::time_point last_seen{};
    };

    static std::string source_key(const std::string& remote_address);
    void remove_stale_locked(Clock::time_point now);
    void finish_attempt_locked(const std::string& source,
                               Permit::Verdict verdict,
                               Clock::time_point now) noexcept;

    const Limits limits_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    Clock::time_point saturated_until_{};
};

// A router-wide ceiling on failed logins forwarded to the router firmware.
//
// The per-source limiter above is a usability control. It cannot be the
// security control here, because the firmware sees every forwarded attempt as
// arriving from one source - this router - so per-source limits multiply
// straight through by the number of sources that care to show up.
//
// This budget is the thing that actually keeps the router administrator from
// being locked out of KeeneticOS by somebody poking keen-pbr's login form. It
// is deliberately smaller than the firmware threshold: we stop one short and
// refuse locally, so the firmware's own counter is never the one that trips.
class AuthForwardBudget {
public:
    using Clock = std::chrono::steady_clock;

    // One admitted credential forwarding attempt. The permit keeps the
    // router-wide budget locked until the caller has the firmware verdict, so
    // two HTTP workers cannot both observe the last free slot and forward it.
    // This also serializes login, step-up and auth-settings checks when they
    // share one AuthForwardBudget instance.
    class Permit {
    public:
        Permit(Permit&&) noexcept = default;
        Permit& operator=(Permit&&) noexcept = default;
        Permit(const Permit&) = delete;
        Permit& operator=(const Permit&) = delete;

        void record_forwarded_failure(
            Clock::time_point now = Clock::now());

    private:
        Permit(AuthForwardBudget& owner,
               std::unique_lock<std::mutex> lock) noexcept;

        AuthForwardBudget* owner_{nullptr};
        std::unique_lock<std::mutex> lock_;
        bool failure_recorded_{false};
        friend class AuthForwardBudget;
    };

    // `capacity` is how many failures may reach the firmware inside `window`.
    // Callers size it from the firmware's measured policy, one below its
    // threshold.
    AuthForwardBudget(std::uint32_t capacity, std::chrono::seconds window);

    // Blocks behind the current firmware attempt, then atomically reserves
    // the right to forward if budget remains. Empty means the request must be
    // refused locally without sending credentials to KeeneticOS.
    std::optional<Permit> reserve_forward(
        Clock::time_point now = Clock::now());

    // Observation/legacy helpers. Production credential forwarding must use
    // reserve_forward(); a separate may_forward()/record pair is inherently
    // unsuitable as an admission boundary.
    bool may_forward(Clock::time_point now = Clock::now());
    void record_forwarded_failure(Clock::time_point now = Clock::now());
    std::size_t spent(Clock::time_point now = Clock::now());

    // Re-sizes the budget once the firmware's real policy has been read.
    // Failures already forwarded are kept: an administrator tightening the
    // policy must not hand back budget that the firmware's counter has already
    // seen spent.
    void reconfigure(std::uint32_t capacity, std::chrono::seconds window);

    std::uint32_t capacity();

private:
    void prune_locked(Clock::time_point now);
    void record_forwarded_failure_locked(Clock::time_point now);

    std::uint32_t capacity_;
    std::chrono::seconds window_;
    std::mutex mutex_;
    // Bounded by capacity_, which is a firmware threshold - single digits.
    std::deque<Clock::time_point> forwarded_;
};

// One below the firmware threshold, floored at zero. Stopping one short is the
// whole point: reaching the threshold IS the lock.
std::uint32_t auth_forward_capacity_for(std::uint32_t firmware_threshold);

} // namespace keen_pbr3
