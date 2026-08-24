#include <doctest/doctest.h>

#include "../src/api/router_info_cache.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <optional>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

class PromiseRelease {
public:
    explicit PromiseRelease(std::promise<void>& promise)
        : promise_(promise) {}

    ~PromiseRelease() {
        release();
    }

    void release() {
        if (!released_) {
            promise_.set_value();
            released_ = true;
        }
    }

private:
    std::promise<void>& promise_;
    bool released_{false};
};

class ManualClock {
public:
    RouterInfoCache::Clock::time_point now() const {
        return RouterInfoCache::Clock::time_point{
            std::chrono::seconds{seconds_.load(std::memory_order_acquire)}};
    }

    void advance(std::chrono::seconds amount) {
        seconds_.fetch_add(amount.count(), std::memory_order_acq_rel);
    }

private:
    std::atomic<std::int64_t> seconds_{0};
};

RouterInfoCache::FetchResult accepted(int generation) {
    return {
        nlohmann::json{{"generation", generation}, {"available", true}},
        true,
    };
}

RouterInfoCache::FetchResult failed(int generation) {
    return {
        nlohmann::json{{"generation", generation}, {"available", false}},
        false,
    };
}

TEST_CASE("router info cold load is single-flight") {
    ManualClock clock;
    std::atomic<int> calls{0};
    std::promise<void> fetch_started;
    auto fetch_started_future = fetch_started.get_future();
    std::promise<void> concurrent_reader_observed;
    auto concurrent_reader_observed_future =
        concurrent_reader_observed.get_future();
    std::atomic<int> clock_reads{0};
    std::promise<void> release_fetch;
    const auto release_signal = release_fetch.get_future().share();

    RouterInfoCache cache(
        [&]() {
            const int call = calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (call == 1) {
                fetch_started.set_value();
                release_signal.wait();
            }
            return accepted(call);
        },
        30s,
        30s,
        [&]() {
            const int read =
                clock_reads.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (read == 2) {
                concurrent_reader_observed.set_value();
            }
            return clock.now();
        });

    // The guard is declared after the futures: on assertion unwinding it
    // releases the fetch before their destructors wait for worker completion.
    std::optional<std::future<nlohmann::json>> first;
    std::optional<std::future<nlohmann::json>> second;
    PromiseRelease release_fetch_guard(release_fetch);
    first.emplace(std::async(std::launch::async, [&cache] {
        return cache.get();
    }));
    REQUIRE(fetch_started_future.wait_for(2s) == std::future_status::ready);

    second.emplace(std::async(std::launch::async, [&cache] {
        return cache.get();
    }));
    REQUIRE(concurrent_reader_observed_future.wait_for(2s) ==
            std::future_status::ready);
    CHECK(calls.load(std::memory_order_acquire) == 1);

    release_fetch_guard.release();
    CHECK(first->get().at("generation") == 1);
    CHECK(second->get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 1);
}

TEST_CASE("router info readers receive stale LKG while one refresh runs") {
    ManualClock clock;
    std::atomic<int> calls{0};
    std::promise<void> refresh_started;
    auto refresh_started_future = refresh_started.get_future();
    std::promise<void> release_refresh;
    const auto release_signal = release_refresh.get_future().share();

    RouterInfoCache cache(
        [&]() {
            const int call = calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (call == 2) {
                refresh_started.set_value();
                release_signal.wait();
            }
            return accepted(call);
        },
        30s,
        30s,
        [&clock] { return clock.now(); });

    std::optional<std::future<nlohmann::json>> refresh;
    PromiseRelease release_refresh_guard(release_refresh);

    CHECK(cache.get().at("generation") == 1);
    clock.advance(31s);

    refresh.emplace(std::async(std::launch::async, [&cache] {
        return cache.get();
    }));
    REQUIRE(refresh_started_future.wait_for(2s) == std::future_status::ready);

    // This call also proves the fetch callback is not holding the cache mutex:
    // it must return the old snapshot while the RCI stand-in is blocked.
    CHECK(cache.get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 2);

    release_refresh_guard.release();
    CHECK(refresh->get().at("generation") == 2);
    CHECK(cache.get().at("generation") == 2);
    CHECK(calls.load(std::memory_order_acquire) == 2);
}

TEST_CASE("router info refresh failure keeps LKG and retries after bounded delay") {
    ManualClock clock;
    std::atomic<int> calls{0};
    RouterInfoCache cache(
        [&]() {
            const int call = calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (call == 2 || call == 3) {
                return failed(200);
            }
            return accepted(call);
        },
        30s,
        30s,
        [&clock] { return clock.now(); });

    CHECK(cache.get().at("generation") == 1);
    clock.advance(31s);

    CHECK(cache.get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 2);

    clock.advance(29s);
    CHECK(cache.get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 2);

    clock.advance(1s);
    CHECK(cache.get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 3);

    // Persistent RCI absence remains capped at one attempt per 30 seconds,
    // rather than creating an unbounded five-second fan-out.
    clock.advance(29s);
    CHECK(cache.get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 3);

    clock.advance(1s);
    CHECK(cache.get().at("generation") == 4);
    CHECK(calls.load(std::memory_order_acquire) == 4);
}

TEST_CASE("router info cold failure is stale while its retry refreshes") {
    ManualClock clock;
    std::atomic<int> calls{0};
    std::promise<void> retry_started;
    auto retry_started_future = retry_started.get_future();
    std::promise<void> release_retry;
    const auto release_signal = release_retry.get_future().share();

    RouterInfoCache cache(
        [&]() {
            const int call = calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (call == 1) {
                return failed(1);
            }
            retry_started.set_value();
            release_signal.wait();
            return accepted(call);
        },
        30s,
        30s,
        [&clock] { return clock.now(); });

    std::optional<std::future<nlohmann::json>> retry;
    std::optional<std::future<nlohmann::json>> concurrent_reader;
    PromiseRelease release_retry_guard(release_retry);

    CHECK(cache.get().at("generation") == 1);
    clock.advance(30s);

    retry.emplace(std::async(std::launch::async, [&cache] {
        return cache.get();
    }));
    REQUIRE(retry_started_future.wait_for(2s) == std::future_status::ready);

    concurrent_reader.emplace(std::async(std::launch::async, [&cache] {
        return cache.get();
    }));
    REQUIRE(concurrent_reader->wait_for(2s) == std::future_status::ready);
    CHECK(concurrent_reader->get().at("generation") == 1);
    CHECK(calls.load(std::memory_order_acquire) == 2);

    release_retry_guard.release();
    CHECK(retry->get().at("generation") == 2);
}

TEST_CASE("router info clock exception after fetch cannot strand refresh") {
    ManualClock clock;
    std::atomic<int> calls{0};
    std::atomic<int> clock_reads{0};
    RouterInfoCache cache(
        [&]() {
            return accepted(
                calls.fetch_add(1, std::memory_order_acq_rel) + 1);
        },
        30s,
        30s,
        [&]() {
            const int read =
                clock_reads.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (read == 2) {
                throw std::runtime_error("injected clock failure");
            }
            return clock.now();
        });

    CHECK(cache.get().at("generation") == 1);
    clock.advance(30s);
    CHECK(cache.get().at("generation") == 2);
    CHECK(calls.load(std::memory_order_acquire) == 2);
}

} // namespace
} // namespace keen_pbr3
