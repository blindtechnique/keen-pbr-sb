#include <doctest/doctest.h>

#include "../src/daemon/resolver_stream_attempt_owner.hpp"

#include <memory>
#include <stdexcept>
#include <string>

using namespace keen_pbr3;

namespace {

std::shared_ptr<ResolverGenerationSnapshot> generation(
    std::uint64_t generation_id) {
    auto value = std::make_shared<ResolverGenerationSnapshot>();
    value->generation = generation_id;
    return value;
}

struct LifetimeReleaseProbe {
    ResolverStreamAttemptOwner* owner{nullptr};
    std::string attempt_id;
    std::uint64_t stream_epoch{0};
    std::shared_ptr<const ResolverGenerationSnapshot> generation;
    bool* observed_exact_retirement_before_release{nullptr};

    ~LifetimeReleaseProbe() {
        *observed_exact_retirement_before_release =
            !owner->active_completion_is_exact(
                attempt_id, stream_epoch, generation) &&
            owner->ipc_gate_in_flight();
    }
};

} // namespace

TEST_CASE("resolver stream owner assigns epochs and publishes one exact attempt") {
    ResolverStreamAttemptOwner owner;
    const std::string attempt(32U, 'a');
    auto candidate = generation(41U);

    CHECK(owner.assign_next_stream_epoch(*candidate) == 1U);
    CHECK(candidate->stream_epoch == 1U);
    auto lifetime = owner.acquire_lifetime(
        attempt,
        candidate);
    owner.publish_active(
        lifetime, /*inactive_activation_authority=*/true);

    CHECK(owner.ipc_gate_in_flight());
    CHECK(owner.active_identity_is_exact(attempt, 1U));
    CHECK(owner.active_completion_is_exact(
        attempt, 1U, candidate));

    auto next = generation(42U);
    CHECK(owner.assign_next_stream_epoch(*next) == 2U);
    CHECK(next->stream_epoch == 2U);
}

TEST_CASE("resolver stream owner keeps correlated selection and inactive authority coherent") {
    ResolverStreamAttemptOwner owner;
    const std::string attempt(32U, 'b');
    const auto committed = generation(50U);
    auto candidate = generation(51U);
    owner.assign_next_stream_epoch(*candidate);
    auto lifetime = owner.acquire_lifetime(
        attempt,
        candidate);
    owner.publish_active(
        lifetime, /*inactive_activation_authority=*/true);

    const auto correlated = owner.select(attempt, committed);
    REQUIRE(correlated.selection);
    CHECK(correlated.selection.correlated_attempt);
    CHECK(correlated.selection.generation.get() == candidate.get());
    CHECK(correlated.inactive_activation_generation.get() ==
          candidate.get());

    const auto manual = owner.select({}, committed);
    CHECK_FALSE(manual.selection);
    CHECK(manual.selection.error ==
          RuntimeResolverStreamSelectionError::stream_busy);
    CHECK(manual.inactive_activation_generation.get() ==
          candidate.get());

    lifetime.reset();
    const auto retired = owner.select({}, committed);
    REQUIRE(retired.selection);
    CHECK_FALSE(retired.selection.correlated_attempt);
    CHECK(retired.selection.generation.get() == committed.get());
    CHECK_FALSE(retired.inactive_activation_generation);
}

TEST_CASE("resolver stream owner rejects stale retirement and accepts exact retirement") {
    ResolverStreamAttemptOwner owner;
    const std::string attempt(32U, 'c');
    auto candidate = generation(60U);
    owner.assign_next_stream_epoch(*candidate);
    auto lifetime = owner.acquire_lifetime(attempt, candidate);
    owner.publish_active(lifetime);

    const auto other = generation(60U);
    other->stream_epoch = candidate->stream_epoch;
    CHECK_FALSE(owner.retire_if_exact(
        std::string(32U, 'd'), candidate->stream_epoch, candidate));
    CHECK_FALSE(owner.retire_if_exact(
        attempt, candidate->stream_epoch + 1U, candidate));
    CHECK_FALSE(owner.retire_if_exact(
        attempt, candidate->stream_epoch, other));
    CHECK(owner.active_completion_is_exact(
        attempt, candidate->stream_epoch, candidate));

    CHECK(owner.retire_if_exact(
        attempt, candidate->stream_epoch, candidate));
    CHECK_FALSE(owner.active_identity_is_exact(
        attempt, candidate->stream_epoch));
    // Explicit exact retirement does not release the attempt lifetime's IPC
    // ownership early; coordinator retirement remains the gate boundary.
    CHECK(owner.ipc_gate_in_flight());
    lifetime.reset();
    CHECK_FALSE(owner.ipc_gate_in_flight());
}

TEST_CASE("resolver stream owner records only exact completion epochs") {
    ResolverStreamAttemptOwner owner;
    const std::string attempt(32U, 'e');
    auto candidate = generation(70U);
    owner.assign_next_stream_epoch(*candidate);
    auto lifetime = owner.acquire_lifetime(attempt, candidate);
    owner.publish_active(lifetime);

    CHECK(owner.completed_stream_epoch() == 0U);
    CHECK_FALSE(owner.record_completed_if_exact(
        std::string(32U, 'f'), candidate->stream_epoch, candidate));
    CHECK_FALSE(owner.record_completed_if_exact(
        attempt, candidate->stream_epoch + 1U, candidate));
    CHECK(owner.completed_stream_epoch() == 0U);
    CHECK(owner.record_completed_if_exact(
        attempt, candidate->stream_epoch, candidate));
    CHECK(owner.completed_stream_epoch() == candidate->stream_epoch);
}

TEST_CASE("resolver stream lifetime retires before authority and IPC gate release") {
    ResolverStreamAttemptOwner owner;
    const std::string attempt(32U, '1');
    auto candidate = generation(80U);
    owner.assign_next_stream_epoch(*candidate);
    bool observed_exact_retirement_before_release = false;
    auto retained = std::make_shared<LifetimeReleaseProbe>();
    retained->owner = &owner;
    retained->attempt_id = attempt;
    retained->stream_epoch = candidate->stream_epoch;
    retained->generation = candidate;
    retained->observed_exact_retirement_before_release =
        &observed_exact_retirement_before_release;

    auto lifetime = owner.acquire_lifetime(
        attempt, candidate, retained);
    owner.publish_active(lifetime);
    retained.reset();
    CHECK(owner.ipc_gate_in_flight());
    CHECK_THROWS_WITH_AS(
        ResolverIpcGate{owner},
        "system resolver operation is already in progress",
        std::runtime_error);

    lifetime.reset();
    CHECK(observed_exact_retirement_before_release);
    CHECK_FALSE(owner.ipc_gate_in_flight());
    CHECK_FALSE(owner.active_identity_is_exact(
        attempt, candidate->stream_epoch));
}
