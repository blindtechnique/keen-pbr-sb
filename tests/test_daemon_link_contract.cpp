#include <doctest/doctest.h>

#include "daemon/daemon.hpp"

#include <chrono>
#include <future>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

struct TestFdEntry {
    int fd;
    int generation;
};

struct FaultingCopyFdEntry {
    int fd;
    int generation;
    const bool* fail_copy;

    FaultingCopyFdEntry(int fd_value,
                        int generation_value,
                        const bool* fail)
        : fd(fd_value)
        , generation(generation_value)
        , fail_copy(fail) {}

    FaultingCopyFdEntry(const FaultingCopyFdEntry& other)
        : fd(other.fd)
        , generation(other.generation)
        , fail_copy(other.fail_copy) {
        if (fail_copy != nullptr && *fail_copy) {
            throw std::bad_alloc{};
        }
    }

    FaultingCopyFdEntry(FaultingCopyFdEntry&&) noexcept = default;
    FaultingCopyFdEntry& operator=(
        const FaultingCopyFdEntry&) = default;
    FaultingCopyFdEntry& operator=(
        FaultingCopyFdEntry&&) noexcept = default;
};

struct TestControlTask {
    std::function<void()> callback;
    std::string label;
    daemon_detail::ControlTaskAdmissionHandle admission_token;
};

daemon_detail::ControlTaskAdmissionHandle make_control_task_token() {
    return std::make_shared<
        const daemon_detail::ControlTaskAdmissionToken>();
}

TEST_CASE("daemon production translation units link into the test binary") {
    using RunMethod = void (Daemon::*)();
    using RunningMethod = bool (Daemon::*)() const;
    using PostMethod = bool (Daemon::*)(std::function<void()>,
                                        const std::string&);

    const RunMethod run = &Daemon::run;
    const RunMethod stop = &Daemon::stop;
    const RunningMethod running = &Daemon::running;
    const PostMethod post = &Daemon::post_control_task;

    CHECK(run != nullptr);
    CHECK(stop != nullptr);
    CHECK(running != nullptr);
    CHECK(post != nullptr);
}

TEST_CASE("successful epoll add replaces stale bookkeeping after fd reuse") {
    // A failed removal left generation 1 behind. The OS later reused fd 41;
    // only a successful EPOLL_CTL_ADD authorizes replacing that stale entry.
    std::vector<TestFdEntry> entries{
        {41, 1},
        {52, 7},
    };
    bool epoll_add_succeeded = false;
    publish_fd_entry_after_successful_epoll_add(
        entries,
        TestFdEntry{41, 2},
        [&epoll_add_succeeded]() {
            epoll_add_succeeded = true;
        });

    CHECK(epoll_add_succeeded);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].fd == 52);
    CHECK(entries[0].generation == 7);
    CHECK(entries[1].fd == 41);
    CHECK(entries[1].generation == 2);
}

TEST_CASE("fd registry allocation failure happens before epoll add and retains stale ownership") {
    bool fail_copy = false;
    std::vector<FaultingCopyFdEntry> entries;
    entries.emplace_back(41, 1, &fail_copy);
    entries.emplace_back(52, 7, &fail_copy);
    fail_copy = true;
    bool epoll_add_called = false;

    CHECK_THROWS_AS(
        publish_fd_entry_after_successful_epoll_add(
            entries,
            FaultingCopyFdEntry{41, 2, &fail_copy},
            [&epoll_add_called]() {
                epoll_add_called = true;
            }),
        std::bad_alloc);

    CHECK_FALSE(epoll_add_called);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].fd == 41);
    CHECK(entries[0].generation == 1);
    CHECK(entries[1].fd == 52);
    CHECK(entries[1].generation == 7);
}

TEST_CASE("failed epoll add retains the exact stale fd bookkeeping") {
    std::vector<TestFdEntry> entries{
        {41, 1},
        {52, 7},
    };

    CHECK_THROWS_AS(
        publish_fd_entry_after_successful_epoll_add(
            entries,
            TestFdEntry{41, 2},
            []() {
                // Models EPOLL_CTL_ADD returning failure before publishing a
                // kernel registration; throwing after success is forbidden
                // by the helper's ownership contract.
                throw std::runtime_error("epoll add rejected");
            }),
        std::runtime_error);

    REQUIRE(entries.size() == 2);
    CHECK(entries[0].fd == 41);
    CHECK(entries[0].generation == 1);
    CHECK(entries[1].fd == 52);
    CHECK(entries[1].generation == 7);
}

TEST_CASE("wake failure cancels an exact queued fd task before caller release") {
    const auto token = make_control_task_token();
    bool caller_released_fd = false;
    bool registered_reused_fd = false;
    int calls = 0;
    std::vector<TestControlTask> queued{
        TestControlTask{
            [&]() {
                ++calls;
                registered_reused_fd = caller_released_fd;
            },
            "scheduler-add-fd",
            token,
        },
    };

    // Linearization outcome when wake failed before the event loop claimed
    // the vector entry: rollback is exact and the caller may now close fd.
    CHECK(daemon_detail::erase_exact_control_task_if_still_queued(
        queued, token, &TestControlTask::admission_token));
    caller_released_fd = true;
    for (auto& task : queued) {
        task.callback();
    }

    CHECK(queued.empty());
    CHECK(calls == 0);
    CHECK_FALSE(registered_reused_fd);
}

TEST_CASE("shutdown gate rejects a waiting task that loses the locked admission race") {
    // The producer's optimistic observation raced shutdown. The production
    // helper is invoked only after both sides acquire the same queue mutex;
    // model shutdown winning that lock and closing admission first.
    bool admission_open = true;
    CHECK(admission_open);

    auto completion = std::make_shared<std::promise<void>>();
    auto future = completion->get_future();
    int calls = 0;
    std::vector<TestControlTask> queued;

    admission_open = false;
    {
        TestControlTask candidate{
            [completion, &calls]() {
                ++calls;
                completion->set_value();
            },
            "scheduler-add-fd",
            make_control_task_token(),
        };
        CHECK_FALSE(daemon_detail::publish_control_task_if_admitted(
            queued, admission_open, std::move(candidate)));
    }

    // enqueue_control_task throws immediately on this false return. Stack
    // unwinding releases its last promise owner instead of calling fut.get();
    // a broken, ready future proves there is no stranded waiter.
    completion.reset();
    CHECK(queued.empty());
    CHECK(calls == 0);
    CHECK(future.wait_for(std::chrono::milliseconds{0}) ==
          std::future_status::ready);
    CHECK_THROWS_AS(future.get(), std::future_error);
}

TEST_CASE("wake failure preserves a task already claimed by the control loop") {
    const auto token = make_control_task_token();
    bool caller_released_fd = false;
    bool registered_reused_fd = false;
    int calls = 0;
    std::vector<TestControlTask> queued{
        TestControlTask{
            [&]() {
                ++calls;
                registered_reused_fd = caller_released_fd;
            },
            "scheduler-add-fd",
            token,
        },
    };
    std::vector<TestControlTask> claimed;
    claimed.swap(queued);

    CHECK_FALSE(
        daemon_detail::erase_exact_control_task_if_still_queued(
            queued, token, &TestControlTask::admission_token));
    // The caller observes authoritative admission and therefore retains fd
    // ownership until the claimed callback completes.
    for (auto& task : claimed) {
        task.callback();
    }

    CHECK(calls == 1);
    CHECK_FALSE(caller_released_fd);
    CHECK_FALSE(registered_reused_fd);
}

TEST_CASE("wake rollback never cancels a different task with the same label") {
    const auto first_token = make_control_task_token();
    const auto second_token = make_control_task_token();
    int first_calls = 0;
    int second_calls = 0;
    std::vector<TestControlTask> queued{
        TestControlTask{
            [&first_calls]() { ++first_calls; },
            "same-label",
            first_token,
        },
        TestControlTask{
            [&second_calls]() { ++second_calls; },
            "same-label",
            second_token,
        },
    };

    CHECK(daemon_detail::erase_exact_control_task_if_still_queued(
        queued, second_token, &TestControlTask::admission_token));
    REQUIRE(queued.size() == 1);
    CHECK(queued.front().admission_token.get() == first_token.get());
    queued.front().callback();
    CHECK(first_calls == 1);
    CHECK(second_calls == 0);
}

TEST_CASE("claimed waiting task preserves its body exception after wake failure") {
    const auto token = make_control_task_token();
    auto completion = std::make_shared<std::promise<void>>();
    auto future = completion->get_future();
    std::vector<TestControlTask> queued{
        TestControlTask{
            [completion]() {
                try {
                    throw std::runtime_error("claimed task body failed");
                } catch (...) {
                    completion->set_exception(std::current_exception());
                }
            },
            "same-label",
            token,
        },
    };
    std::vector<TestControlTask> claimed;
    claimed.swap(queued);

    CHECK_FALSE(
        daemon_detail::erase_exact_control_task_if_still_queued(
            queued, token, &TestControlTask::admission_token));
    REQUIRE(claimed.size() == 1);
    CHECK_NOTHROW(claimed.front().callback());
    CHECK_THROWS_WITH_AS(
        future.get(),
        "claimed task body failed",
        std::runtime_error);
}

} // namespace
} // namespace keen_pbr3
