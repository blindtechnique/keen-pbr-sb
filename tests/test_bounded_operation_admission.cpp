#include <doctest/doctest.h>

#include "../src/util/blocking_executor.hpp"
#include "../src/util/bounded_operation_admission.hpp"
#include "../src/log/logger.hpp"

#include <future>
#include <stdexcept>
#include <thread>

using namespace keen_pbr3;

namespace {

class ScopedThrowingQueueLogger {
public:
    ScopedThrowingQueueLogger()
        : previous_level_(Logger::instance().level()) {
        Logger::instance().set_level(LogLevel::debug);
        Logger::instance().set_sink([](const std::string& line) {
            if (line.find("event=executor_queue") !=
                std::string::npos) {
                throw std::runtime_error(
                    "synthetic post-enqueue logging failure");
            }
        });
    }

    ~ScopedThrowingQueueLogger() {
        Logger::instance().clear_sink();
        Logger::instance().set_level(previous_level_);
    }

private:
    LogLevel previous_level_;
};

} // namespace

TEST_CASE("bounded operation admission rejects a third request and releases once") {
    BoundedOperationAdmission admission(2);

    auto first = admission.try_acquire();
    auto second = admission.try_acquire();
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    CHECK(admission.active() == 2);
    CHECK_FALSE(admission.try_acquire().has_value());

    auto first_copy = *first;
    first->reset();
    CHECK(admission.active() == 2);
    first_copy.reset();
    CHECK(admission.active() == 1);

    auto replacement = admission.try_acquire();
    REQUIRE(replacement.has_value());
    CHECK(admission.active() == 2);
}

TEST_CASE("rejected executor enqueue releases its admission lease") {
    BoundedOperationAdmission admission(1);
    BlockingExecutor executor(0, 0);

    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());
    CHECK_FALSE(executor.try_post(
        "rejected-routing-test",
        [lease = std::move(*lease)]() mutable {
            (void)lease;
        }));
    CHECK(admission.active() == 0);
}

TEST_CASE("exception while preparing an enqueue releases its admission lease") {
    BoundedOperationAdmission admission(1);
    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());

    CHECK_THROWS_AS(
        ([lease = std::move(*lease)]() mutable {
            (void)lease;
            throw std::runtime_error("synthetic enqueue failure");
        })(),
        std::runtime_error);
    CHECK(admission.active() == 0);
}

TEST_CASE("post-enqueue exception cannot duplicate lease ownership") {
    ScopedThrowingQueueLogger logger;
    BoundedOperationAdmission admission(1);
    BlockingExecutor executor(1, 1);

    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());
    bool queued = false;
    CHECK_NOTHROW(queued = executor.try_post(
        "post-enqueue-routing-test",
        [lease = std::move(*lease)]() mutable {
            (void)lease;
        }));
    REQUIRE(queued);
    executor.submit("post-enqueue-barrier", [] {}).get();
    CHECK(admission.active() == 0);
}

TEST_CASE("throwing worker releases its admission lease") {
    BoundedOperationAdmission admission(1);
    BlockingExecutor executor(1, 1);

    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());
    REQUIRE(executor.try_post(
        "throwing-routing-test",
        [lease = std::move(*lease)]() mutable {
            (void)lease;
            throw std::runtime_error("expected worker failure");
        }));

    // A following barrier runs only after the throwing callback and its task
    // storage have been retired by the same worker.
    executor.submit("routing-test-barrier", [] {}).get();
    CHECK(admission.active() == 0);
}

TEST_CASE("admission shutdown rejects new work without stealing live leases") {
    BoundedOperationAdmission admission(1);
    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());

    admission.shutdown();
    CHECK_FALSE(admission.try_acquire().has_value());
    CHECK(admission.active() == 1);
    lease->reset();
    CHECK(admission.active() == 0);
}

TEST_CASE("executor shutdown drains a queued routing-test lease") {
    BoundedOperationAdmission admission(1);
    BlockingExecutor executor(1, 1);
    std::promise<void> first_started;
    std::promise<void> release_first;
    auto release = release_first.get_future().share();

    REQUIRE(executor.try_post(
        "routing-test-shutdown-blocker",
        [&first_started, release]() {
            first_started.set_value();
            release.wait();
        }));
    first_started.get_future().wait();

    auto lease = admission.try_acquire();
    REQUIRE(lease.has_value());
    REQUIRE(executor.try_post(
        "queued-routing-test",
        [lease = std::move(*lease)]() mutable {
            (void)lease;
        }));

    std::thread shutdown([&executor]() { executor.shutdown(); });
    release_first.set_value();
    shutdown.join();
    CHECK(admission.active() == 0);
}
