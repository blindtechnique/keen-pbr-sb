#include <doctest/doctest.h>

#include "../src/daemon/scheduler.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <map>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>

namespace keen_pbr3 {
namespace {

class RecordingFdRegistry {
public:
    SchedulerTestFdHooks hooks() {
        return SchedulerTestFdHooks{
            .add_fd = [this](
                          int fd,
                          std::function<void(std::uint32_t)> callback) {
                last_fd = fd;
                callbacks.emplace(fd, callback);
                if (fire_during_add) {
                    fire_during_add = false;
                    // Invoke a separate snapshot: a one-shot removes its
                    // registry entry while this callback is still running.
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds{10});
                    callback(0U);
                }
                if (throw_after_add) {
                    throw_after_add = false;
                    throw std::runtime_error(
                        "injected fd registrar publication failure");
                }
            },
            .remove_fd = [this](int fd) {
                callbacks.erase(fd);
            },
        };
    }

    bool last_fd_is_closed() const {
        if (last_fd < 0) {
            return false;
        }
        errno = 0;
        return fcntl(last_fd, F_GETFD) == -1 && errno == EBADF;
    }

    bool fire(int fd) {
        const auto it = callbacks.find(fd);
        if (it == callbacks.end()) {
            return false;
        }
        const auto callback = it->second;
        callback(0U);
        return true;
    }

    std::map<int, std::function<void(std::uint32_t)>> callbacks;
    int last_fd{-1};
    bool fire_during_add{false};
    bool throw_after_add{false};
};

TEST_CASE("scheduler rolls back an fd registrar exception after publication") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    registry.throw_after_add = true;

    CHECK_THROWS_AS(
        scheduler.schedule_repeating(
            std::chrono::seconds{30}, []() {}, "registrar-fault"),
        std::runtime_error);
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
    CHECK(registry.last_fd_is_closed());
}

TEST_CASE("scheduler rolls back when its entry cannot be published") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    scheduler.fail_next_entry_publication_for_testing();

    CHECK_THROWS_AS(
        scheduler.schedule_repeating(
            std::chrono::seconds{30}, []() {}, "entry-fault"),
        std::bad_alloc);
    registry.last_fd = scheduler.last_created_fd_for_testing();
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
    CHECK(registry.last_fd_is_closed());
}

TEST_CASE("scheduler rolls back a fault after both ownership records exist") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    scheduler.fail_next_post_registration_for_testing();

    CHECK_THROWS_AS(
        scheduler.schedule_oneshot(
            std::chrono::seconds{30}, []() {}, "post-register-fault"),
        SchedulerError);
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
    CHECK(registry.last_fd_is_closed());
}

TEST_CASE("scheduler publishes a ready one-shot before fd registration") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    registry.fire_during_add = true;
    int calls = 0;

    const int task_id = scheduler.schedule_oneshot(
        std::chrono::milliseconds{1},
        [&calls]() { ++calls; },
        "ready-during-registration");

    CHECK(task_id >= 0);
    CHECK(calls == 1);
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
    CHECK(registry.last_fd_is_closed());
}

TEST_CASE("scheduler keeps a periodic probe alive after a coalesced failure") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    int calls = 0;
    int launches = 0;
    bool round_inflight = true;

    const int task_id = scheduler.schedule_repeating(
        std::chrono::milliseconds{1},
        [&calls, &launches, &round_inflight]() {
            ++calls;
            if (round_inflight) {
                // Models an already-running interface round whose
                // coalescing diagnostic throws unexpectedly.
                throw std::runtime_error(
                    "injected coalesced diagnostic failure");
            }
            ++launches;
        },
        "throwing-repeat");
    const int timer_fd = registry.last_fd;

    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    CHECK_NOTHROW(registry.fire(timer_fd));
    round_inflight = false;
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    CHECK_NOTHROW(registry.fire(timer_fd));
    CHECK(calls == 2);
    CHECK(launches == 1);
    CHECK(scheduler.size() == 1);
    CHECK(registry.callbacks.size() == 1);

    scheduler.cancel(task_id);
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
}

TEST_CASE("scheduler consumes a throwing one-shot before invocation") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    int calls = 0;

    scheduler.schedule_oneshot(
        std::chrono::milliseconds{1},
        [&calls]() {
            ++calls;
            throw std::runtime_error("injected one-shot callback failure");
        },
        "throwing-one-shot");
    const int timer_fd = registry.last_fd;

    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    CHECK_NOTHROW(registry.fire(timer_fd));
    CHECK(calls == 1);
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
    CHECK(registry.last_fd_is_closed());
    CHECK_FALSE(registry.fire(timer_fd));
}

TEST_CASE("scheduler successful registration still returns cancellable id") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());

    const int task_id = scheduler.schedule_repeating(
        std::chrono::seconds{30}, []() {}, "normal");
    CHECK(task_id >= 0);
    CHECK(scheduler.size() == 1);
    CHECK(registry.callbacks.size() == 1);

    scheduler.cancel(task_id);
    CHECK(scheduler.size() == 0);
    CHECK(registry.callbacks.empty());
    CHECK(registry.last_fd_is_closed());
}

} // namespace
} // namespace keen_pbr3
