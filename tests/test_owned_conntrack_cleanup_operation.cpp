#include <doctest/doctest.h>

#include "daemon/owned_conntrack_cleanup_operation.hpp"

#include <memory>
#include <utility>

using namespace keen_pbr3;

namespace {

OwnedConntrackCleanupRetry cleanup_retry() {
    return OwnedConntrackCleanupRetry{
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/7,
            /*owned_mask=*/0xff0000U,
            /*marks=*/{0x10000U, 0x20000U},
            /*priority_marks=*/{0x10000U},
            /*ipv6_enabled=*/true},
        {0x10000U, 0x20000U},
        /*no_progress_attempt=*/2};
}

} // namespace

TEST_CASE("owned conntrack cleanup operation publishes one exact result") {
    OwnedConntrackCleanupOperation operation{cleanup_retry()};
    ConntrackCleanupSummary cleanup;
    cleanup.remaining_marks = {0x20000U};

    CHECK(operation.finish(
        OwnedConntrackCleanupOperationStatus::completed,
        std::move(cleanup)));
    CHECK_FALSE(operation.finish(
        OwnedConntrackCleanupOperationStatus::busy));

    auto result = operation.take_result();
    REQUIRE(result.has_value());
    CHECK(result->status ==
          OwnedConntrackCleanupOperationStatus::completed);
    CHECK(result->cleanup.remaining_marks ==
          std::vector<std::uint32_t>{0x20000U});
    CHECK_FALSE(operation.take_result().has_value());
}

TEST_CASE("cancelled owned conntrack cleanup cannot publish late outcome") {
    OwnedConntrackCleanupOperation operation{cleanup_retry()};
    operation.cancel();

    CHECK(operation.cancelled());
    CHECK_FALSE(operation.finish(
        OwnedConntrackCleanupOperationStatus::completed));
    CHECK_FALSE(operation.take_result().has_value());
    CHECK(operation.retry().snapshot.runtime_generation == 7);
    CHECK(operation.retry().no_progress_attempt == 2);
}

TEST_CASE("cleanup operation retains admission until control completion") {
    RuntimeMutationAdmission admission;
    auto admitted = admission.try_acquire("conntrack-cleanup");
    REQUIRE(admitted.has_value());
    auto lease = std::make_shared<RuntimeMutationAdmission::Lease>(
        std::move(*admitted));

    OwnedConntrackCleanupOperation operation{cleanup_retry()};
    REQUIRE(operation.finish(
        OwnedConntrackCleanupOperationStatus::completed,
        {},
        lease));
    lease.reset();

    CHECK_FALSE(admission.try_acquire("foreground-apply").has_value());
    auto result = operation.take_result();
    REQUIRE(result.has_value());
    REQUIRE(result->mutation_lease);
    result->mutation_lease->release();
    CHECK(admission.try_acquire("foreground-apply").has_value());
}
