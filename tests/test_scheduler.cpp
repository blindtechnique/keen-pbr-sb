#include <doctest/doctest.h>

#include "../src/daemon/scheduler.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <map>
#include <new>
#include <poll.h>
#include <stdexcept>
#include <sys/timerfd.h>
#include <thread>
#include <unistd.h>
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

bool wait_timer_readable(int fd, int timeout_ms) {
    pollfd readiness{fd, POLLIN, 0};
    return poll(&readiness, 1, timeout_ms) == 1 &&
           (readiness.revents & POLLIN) != 0;
}

class TimerDescriptorRestore {
public:
    explicit TimerDescriptorRestore(int timer_fd)
        : timer_fd_(timer_fd), saved_fd_(dup(timer_fd)) {}
    ~TimerDescriptorRestore() {
        if (saved_fd_ >= 0) {
            (void)dup2(saved_fd_, timer_fd_);
            close(saved_fd_);
        }
    }
    bool valid() const { return saved_fd_ >= 0; }
private:
    int timer_fd_;
    int saved_fd_;
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

TEST_CASE("scheduler next-run projection matches exact aliases and selects the earliest") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    int calls = 0;
    scheduler.schedule_repeating(std::chrono::hours{2}, [&] { ++calls; }, "periodic");
    scheduler.schedule_oneshot(std::chrono::hours{1}, [&] { ++calls; }, "retry");
    scheduler.schedule_oneshot(std::chrono::milliseconds{1}, [&] { ++calls; }, "retry-extra");
    const auto size = scheduler.size();
    const auto registered = registry.callbacks.size();

    const auto snapshots = scheduler.snapshot_next_runs({
        {"combined", {"periodic", "retry", "retry"}},
        {"exact-only", {"ret"}},
        {"missing", {"not-registered"}},
        {"empty", {}},
    });
    REQUIRE(snapshots.size() == 4);
    CHECK(snapshots[0].label == "combined");
    CHECK(snapshots[0].state == ScheduledTaskState::Scheduled);
    REQUIRE(snapshots[0].remaining_ms.has_value());
    CHECK(*snapshots[0].remaining_ms > 0);
    CHECK(*snapshots[0].remaining_ms <= 3'600'000);
    CHECK(snapshots[1].label == "exact-only");
    CHECK(snapshots[2].label == "missing");
    CHECK(snapshots[3].label == "empty");
    for (std::size_t index = 1; index < snapshots.size(); ++index) {
        CHECK(snapshots[index].state == ScheduledTaskState::NotScheduled);
        CHECK_FALSE(snapshots[index].remaining_ms.has_value());
    }
    CHECK(scheduler.snapshot_next_runs({}).empty());
    CHECK(scheduler.size() == size);
    CHECK(registry.callbacks.size() == registered);
    CHECK(calls == 0);
}

TEST_CASE("scheduler next-run projection does not consume a pending one-shot") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    int calls = 0;
    scheduler.schedule_oneshot(std::chrono::milliseconds{1}, [&] { ++calls; }, "once");
    const int fd = registry.last_fd;
    REQUIRE(wait_timer_readable(fd, 500));

    for (int observation = 0; observation < 2; ++observation) {
        const auto snapshots = scheduler.snapshot_next_runs({{"family", {"once"}}});
        REQUIRE(snapshots.size() == 1);
        CHECK(snapshots[0].state == ScheduledTaskState::Scheduled);
        REQUIRE(snapshots[0].remaining_ms.has_value());
        CHECK(*snapshots[0].remaining_ms == 0);
        CHECK(wait_timer_readable(fd, 0));
        CHECK(scheduler.size() == 1);
        CHECK(calls == 0);
    }
    REQUIRE(registry.fire(fd));
    CHECK(calls == 1);
    CHECK(scheduler.size() == 0);
    const auto after = scheduler.snapshot_next_runs({{"family", {"once"}}});
    REQUIRE(after.size() == 1);
    CHECK(after[0].state == ScheduledTaskState::NotScheduled);
    CHECK_FALSE(after[0].remaining_ms.has_value());
}

TEST_CASE("scheduler pending repeating expiration wins over its future interval") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    int calls = 0;
    scheduler.schedule_repeating(std::chrono::hours{1}, [&] { ++calls; }, "repeat");
    const int fd = registry.last_fd;
    // Keep the real repeating interval far away but let the first expiration
    // become pending quickly without dispatching the registrar callback.
    itimerspec timer{};
    timer.it_value.tv_nsec = 1'000'000;
    timer.it_interval.tv_sec = 3600;
    REQUIRE(timerfd_settime(fd, 0, &timer, nullptr) == 0);
    REQUIRE(wait_timer_readable(fd, 500));
    itimerspec before{};
    REQUIRE(timerfd_gettime(fd, &before) == 0);
    REQUIRE(before.it_value.tv_sec > 0);

    const auto snapshots = scheduler.snapshot_next_runs({{"family", {"repeat"}}});
    REQUIRE(snapshots.size() == 1);
    CHECK(snapshots[0].state == ScheduledTaskState::Scheduled);
    REQUIRE(snapshots[0].remaining_ms.has_value());
    CHECK(*snapshots[0].remaining_ms == 0);
    CHECK(wait_timer_readable(fd, 0));
    CHECK(calls == 0);
    CHECK(scheduler.size() == 1);
    itimerspec after{};
    REQUIRE(timerfd_gettime(fd, &after) == 0);
    CHECK(after.it_interval.tv_sec == before.it_interval.tv_sec);
    CHECK(after.it_interval.tv_nsec == before.it_interval.tv_nsec);

    REQUIRE(registry.fire(fd));
    CHECK(calls == 1);
    CHECK(scheduler.size() == 1);
    const auto consumed = scheduler.snapshot_next_runs({{"family", {"repeat"}}});
    REQUIRE(consumed[0].remaining_ms.has_value());
    CHECK(*consumed[0].remaining_ms > 0);
    CHECK(*consumed[0].remaining_ms <= 3'600'000);
}

TEST_CASE("scheduler disarmed timers are not scheduled and do not hide an armed alias") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    scheduler.schedule_oneshot(std::chrono::milliseconds{0}, [] {}, "disarmed");
    scheduler.schedule_oneshot(std::chrono::hours{1}, [] {}, "armed");
    const auto snapshots = scheduler.snapshot_next_runs({
        {"disarmed-only", {"disarmed"}},
        {"combined", {"disarmed", "armed"}},
    });
    REQUIRE(snapshots.size() == 2);
    CHECK(snapshots[0].state == ScheduledTaskState::NotScheduled);
    CHECK_FALSE(snapshots[0].remaining_ms.has_value());
    CHECK(snapshots[1].state == ScheduledTaskState::Scheduled);
    REQUIRE(snapshots[1].remaining_ms.has_value());
    CHECK(*snapshots[1].remaining_ms > 0);
    CHECK(scheduler.size() == 2);
    CHECK(registry.callbacks.size() == 2);
}

TEST_CASE("scheduler failed alias inspection makes only its matching family unknown") {
    RecordingFdRegistry registry;
    Scheduler scheduler(registry.hooks());
    scheduler.schedule_oneshot(std::chrono::hours{1}, [] {}, "healthy");
    scheduler.schedule_oneshot(std::chrono::hours{2}, [] {}, "uninspectable");
    const int fd = registry.last_fd;
    // Substitute a live non-timer descriptor, retaining a duplicate that
    // restores the scheduler's exact timer before its normal cleanup runs.
    TimerDescriptorRestore restore(fd);
    REQUIRE(restore.valid());
    const int replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(replacement >= 0);
    const auto replaced = dup2(replacement, fd);
    close(replacement);
    REQUIRE(replaced == fd);

    const auto snapshots = scheduler.snapshot_next_runs({
        {"combined", {"healthy", "uninspectable"}},
        {"healthy-only", {"healthy"}},
        {"missing", {"missing"}},
    });
    REQUIRE(snapshots.size() == 3);
    CHECK(snapshots[0].state == ScheduledTaskState::Unknown);
    CHECK_FALSE(snapshots[0].remaining_ms.has_value());
    CHECK(snapshots[1].state == ScheduledTaskState::Scheduled);
    CHECK(snapshots[1].remaining_ms.has_value());
    CHECK(snapshots[2].state == ScheduledTaskState::NotScheduled);
    CHECK(scheduler.size() == 2);
    CHECK(registry.callbacks.size() == 2);
}

} // namespace
} // namespace keen_pbr3
