#include <doctest/doctest.h>

#include "daemon/targeted_probe_admission.hpp"

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {

TEST_CASE("one probe per tag at a time") {
    TargetedProbeAdmission admission;

    auto first = admission.acquire("awg_bound");
    REQUIRE(first.admitted());

    // A second click on the same row while the first is still running would
    // measure the same thing twice and publish two results for one request.
    auto second = admission.acquire("awg_bound");
    CHECK_FALSE(second.admitted());
    CHECK(admission.in_flight() == 1);
}

TEST_CASE("distinct tags are not collapsed into one another") {
    TargetedProbeAdmission admission;

    auto first = admission.acquire("awg_bound");
    auto second = admission.acquire("vless_outbound");

    // This is the whole reason this is not the round gate: coalescing is right
    // when every request measures the same thing, and wrong here, where two
    // clicks mean two different outbounds.
    CHECK(first.admitted());
    CHECK(second.admitted());
    CHECK(admission.in_flight() == 2);
}

TEST_CASE("a tag becomes probeable again once its lease ends") {
    TargetedProbeAdmission admission;

    {
        auto lease = admission.acquire("awg_bound");
        REQUIRE(lease.admitted());
    }

    CHECK(admission.in_flight() == 0);
    CHECK(admission.acquire("awg_bound").admitted());
}

TEST_CASE("a failed probe does not strand its tag") {
    TargetedProbeAdmission admission;

    // The executor refuses the task, or the probe throws. Release happens on
    // destruction rather than on a success path, so a tag left marked in
    // flight cannot become unprobeable until the daemon restarts.
    try {
        auto lease = admission.acquire("awg_bound");
        REQUIRE(lease.admitted());
        throw std::runtime_error("probe failed");
    } catch (const std::exception&) {
    }

    CHECK(admission.in_flight() == 0);
    CHECK(admission.acquire("awg_bound").admitted());
}

TEST_CASE("a moved lease releases exactly once") {
    TargetedProbeAdmission admission;

    {
        auto lease = admission.acquire("awg_bound");
        REQUIRE(lease.admitted());
        auto moved = std::move(lease);
        CHECK(moved.admitted());
        // The moved-from lease must not release the tag the new owner holds.
        CHECK_FALSE(lease.admitted());
        CHECK(admission.in_flight() == 1);
    }

    CHECK(admission.in_flight() == 0);
}

TEST_CASE("concurrency is bounded so a scripted caller cannot grow the set") {
    TargetedProbeAdmission admission;
    std::vector<TargetedProbeAdmission::Lease> leases;

    for (std::size_t i = 0; i < TargetedProbeAdmission::kMaxConcurrent; ++i) {
        auto lease = admission.acquire("tag-" + std::to_string(i));
        CHECK(lease.admitted());
        leases.push_back(std::move(lease));
    }

    // Refused rather than queued: a refused click is honest and retryable, a
    // queued one lands after the operator stopped looking.
    CHECK_FALSE(admission.acquire("one-too-many").admitted());
    CHECK(admission.in_flight() == TargetedProbeAdmission::kMaxConcurrent);
}

TEST_CASE("concurrent clicks on one tag admit exactly one") {
    TargetedProbeAdmission admission;
    std::atomic<int> admitted{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&admission, &admitted]() {
            auto lease = admission.acquire("awg_bound");
            if (lease.admitted()) {
                admitted.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        });
    }
    for (auto& thread : threads) thread.join();

    CHECK(admitted.load() == 1);
    CHECK(admission.in_flight() == 0);
}

} // namespace keen_pbr3
