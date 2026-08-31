#pragma once

#include "runtime_resolver_generation_snapshot.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace keen_pbr3 {

struct ResolverStreamAttemptOwnerState;
class ResolverStreamAttemptLifetime;

// One view of the resolver-stream authority captured under the owner's
// mutex. Keeping the inactive-activation pointer beside the selection avoids
// admitting a cold-boot stream against a pointer from another attempt.
struct ResolverStreamAttemptSelection {
    RuntimeResolverStreamSelection selection;
    std::shared_ptr<const ResolverGenerationSnapshot>
        inactive_activation_generation;
};

class ResolverStreamAttemptOwner;

// The existing single process-wide resolver IPC gate, now scoped to the
// resolver-stream owner instead of Daemon. It intentionally keeps the same
// fail-fast message used by the old Daemon-local guard.
class ResolverIpcGate {
public:
    explicit ResolverIpcGate(ResolverStreamAttemptOwner& owner);
    ~ResolverIpcGate() noexcept;

    ResolverIpcGate(const ResolverIpcGate&) = delete;
    ResolverIpcGate& operator=(const ResolverIpcGate&) = delete;
    ResolverIpcGate(ResolverIpcGate&&) = delete;
    ResolverIpcGate& operator=(ResolverIpcGate&&) = delete;

private:
    friend class ResolverStreamAttemptLifetime;

    explicit ResolverIpcGate(
        std::shared_ptr<ResolverStreamAttemptOwnerState> state);

    std::shared_ptr<ResolverStreamAttemptOwnerState> state_;
};

// Owns exactly the resolver-stream attempt tuple that previously lived on
// Daemon: active id/generation, inactive activation authority and the next /
// completed stream epochs. It adds no admission or retry policy.
class ResolverStreamAttemptOwner {
public:
    ResolverStreamAttemptOwner();
    ~ResolverStreamAttemptOwner();

    ResolverStreamAttemptOwner(const ResolverStreamAttemptOwner&) = delete;
    ResolverStreamAttemptOwner& operator=(
        const ResolverStreamAttemptOwner&) = delete;
    ResolverStreamAttemptOwner(ResolverStreamAttemptOwner&&) noexcept =
        default;
    ResolverStreamAttemptOwner& operator=(
        ResolverStreamAttemptOwner&&) noexcept = default;

    // Assigns the next exact epoch to a caller-owned private generation.
    // Generation construction/publication stays with the existing caller.
    std::uint64_t assign_next_stream_epoch(
        ResolverGenerationSnapshot& generation) noexcept;

    // Acquires the existing IPC gate and prepares one exact lifetime.
    // retained_authority is the existing optional mutation lease, type-erased
    // only so this resolver component does not own admission policy. The
    // caller publishes its generation/transaction pointers before exposing
    // the tuple with publish_active(), preserving the original ordering.
    std::shared_ptr<ResolverStreamAttemptLifetime> acquire_lifetime(
        std::string attempt_id,
        std::shared_ptr<const ResolverGenerationSnapshot> generation,
        std::shared_ptr<void> retained_authority = nullptr);

    void publish_active(
        const std::shared_ptr<ResolverStreamAttemptLifetime>& lifetime,
        bool inactive_activation_authority = false);

    ResolverStreamAttemptSelection select(
        std::string_view requested_attempt_id,
        const std::shared_ptr<const ResolverGenerationSnapshot>&
            committed_generation) const noexcept;

    bool active_identity_is_exact(
        std::string_view attempt_id,
        std::uint64_t stream_epoch) const noexcept;

    bool active_completion_is_exact(
        std::string_view attempt_id,
        std::uint64_t stream_epoch,
        const std::shared_ptr<const ResolverGenerationSnapshot>&
            generation) const noexcept;

    // Records completion only while the exact id/epoch/pointer tuple is still
    // active. Coordinator notification deliberately remains outside this
    // owner so no owner/coordinator lock ordering is introduced.
    bool record_completed_if_exact(
        std::string_view attempt_id,
        std::uint64_t stream_epoch,
        const std::shared_ptr<const ResolverGenerationSnapshot>&
            generation) noexcept;

    // Primarily used by ResolverStreamAttemptLifetime. It is public so an
    // outer exact-completion adapter can retire an already terminal tuple
    // without gaining access to the owner's state.
    bool retire_if_exact(
        std::string_view attempt_id,
        std::uint64_t stream_epoch,
        const std::shared_ptr<const ResolverGenerationSnapshot>&
            generation) noexcept;

    std::uint64_t completed_stream_epoch() const noexcept;
    bool ipc_gate_in_flight() const noexcept;

private:
    friend class ResolverIpcGate;
    friend class ResolverStreamAttemptLifetime;

    std::shared_ptr<ResolverStreamAttemptOwnerState> state_;
};

// The coordinator retains this object until it retires the claim. Destruction
// first retires the exact active tuple, then releases the retained authority,
// and releases the IPC gate last. No allocating clear callback is needed.
class ResolverStreamAttemptLifetime {
public:
    ~ResolverStreamAttemptLifetime() noexcept;

    ResolverStreamAttemptLifetime(
        const ResolverStreamAttemptLifetime&) = delete;
    ResolverStreamAttemptLifetime& operator=(
        const ResolverStreamAttemptLifetime&) = delete;
    ResolverStreamAttemptLifetime(ResolverStreamAttemptLifetime&&) = delete;
    ResolverStreamAttemptLifetime& operator=(
        ResolverStreamAttemptLifetime&&) = delete;

private:
    friend class ResolverStreamAttemptOwner;

    ResolverStreamAttemptLifetime(
        std::shared_ptr<ResolverStreamAttemptOwnerState> state,
        std::shared_ptr<void> retained_authority,
        std::shared_ptr<const ResolverGenerationSnapshot> generation,
        std::string attempt_id,
        std::uint64_t stream_epoch);

    // Declaration order is intentional: reverse member destruction releases
    // the retained authority before the gate, while state remains alive for
    // the gate's final atomic store.
    std::shared_ptr<ResolverStreamAttemptOwnerState> state_;
    ResolverIpcGate ipc_gate_;
    std::shared_ptr<void> retained_authority_;
    std::shared_ptr<const ResolverGenerationSnapshot> generation_;
    std::string attempt_id_;
    std::uint64_t stream_epoch_{0};
};

} // namespace keen_pbr3
