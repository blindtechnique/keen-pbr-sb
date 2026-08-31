#include "resolver_stream_attempt_owner.hpp"

#include <mutex>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

struct ResolverStreamAttemptOwnerState {
    std::atomic<bool> ipc_gate_in_flight{false};
    mutable std::mutex mutex;
    std::string active_attempt_id;
    std::shared_ptr<const ResolverGenerationSnapshot> active_generation;
    std::shared_ptr<const ResolverGenerationSnapshot>
        inactive_activation_generation;
    std::atomic<std::uint64_t> next_stream_epoch{0};
    std::atomic<std::uint64_t> completed_stream_epoch{0};
};

namespace {

bool active_completion_is_exact_locked(
    const ResolverStreamAttemptOwnerState& state,
    std::string_view attempt_id,
    std::uint64_t stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>& generation)
    noexcept {
    return runtime_resolver_stream_completion_is_exact(
        attempt_id,
        stream_epoch,
        generation,
        state.active_attempt_id,
        state.active_generation);
}

bool retire_if_exact_locked(
    ResolverStreamAttemptOwnerState& state,
    std::string_view attempt_id,
    std::uint64_t stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>& generation)
    noexcept {
    if (!active_completion_is_exact_locked(
            state, attempt_id, stream_epoch, generation)) {
        return false;
    }
    state.active_attempt_id.clear();
    state.active_generation.reset();
    state.inactive_activation_generation.reset();
    return true;
}

} // namespace

ResolverIpcGate::ResolverIpcGate(ResolverStreamAttemptOwner& owner)
    : ResolverIpcGate(owner.state_) {}

ResolverIpcGate::ResolverIpcGate(
    std::shared_ptr<ResolverStreamAttemptOwnerState> state)
    : state_(std::move(state)) {
    if (state_->ipc_gate_in_flight.exchange(
            true, std::memory_order_acq_rel)) {
        throw std::runtime_error(
            "system resolver operation is already in progress");
    }
}

ResolverIpcGate::~ResolverIpcGate() noexcept {
    state_->ipc_gate_in_flight.store(false, std::memory_order_release);
}

ResolverStreamAttemptOwner::ResolverStreamAttemptOwner()
    : state_(std::make_shared<ResolverStreamAttemptOwnerState>()) {}

ResolverStreamAttemptOwner::~ResolverStreamAttemptOwner() = default;

std::uint64_t ResolverStreamAttemptOwner::assign_next_stream_epoch(
    ResolverGenerationSnapshot& generation) noexcept {
    generation.stream_epoch =
        state_->next_stream_epoch.fetch_add(
            1U, std::memory_order_acq_rel) + 1U;
    return generation.stream_epoch;
}

std::shared_ptr<ResolverStreamAttemptLifetime>
ResolverStreamAttemptOwner::acquire_lifetime(
    std::string attempt_id,
    std::shared_ptr<const ResolverGenerationSnapshot> generation,
    std::shared_ptr<void> retained_authority) {
    const std::uint64_t stream_epoch =
        generation ? generation->stream_epoch : 0U;
    return std::shared_ptr<ResolverStreamAttemptLifetime>(
        new ResolverStreamAttemptLifetime(
            state_,
            std::move(retained_authority),
            std::move(generation),
            std::move(attempt_id),
            stream_epoch));
}

void ResolverStreamAttemptOwner::publish_active(
    const std::shared_ptr<ResolverStreamAttemptLifetime>& lifetime,
    bool inactive_activation_authority) {
    if (!lifetime || lifetime->state_.get() != state_.get()) {
        throw std::invalid_argument(
            "resolver stream lifetime belongs to another owner");
    }
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->active_attempt_id = lifetime->attempt_id_;
        state_->active_generation = lifetime->generation_;
        state_->inactive_activation_generation =
            inactive_activation_authority
            ? lifetime->generation_
            : nullptr;
    }
}

ResolverStreamAttemptSelection ResolverStreamAttemptOwner::select(
    std::string_view requested_attempt_id,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        committed_generation) const noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    ResolverStreamAttemptSelection result;
    result.selection = select_runtime_resolver_stream_generation(
        requested_attempt_id,
        state_->active_attempt_id,
        committed_generation,
        state_->active_generation);
    result.inactive_activation_generation =
        state_->inactive_activation_generation;
    return result;
}

bool ResolverStreamAttemptOwner::active_identity_is_exact(
    std::string_view attempt_id,
    std::uint64_t stream_epoch) const noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return !attempt_id.empty() &&
           attempt_id == state_->active_attempt_id &&
           stream_epoch != 0U && state_->active_generation &&
           state_->active_generation->stream_epoch == stream_epoch;
}

bool ResolverStreamAttemptOwner::active_completion_is_exact(
    std::string_view attempt_id,
    std::uint64_t stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>& generation)
    const noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return active_completion_is_exact_locked(
        *state_, attempt_id, stream_epoch, generation);
}

bool ResolverStreamAttemptOwner::record_completed_if_exact(
    std::string_view attempt_id,
    std::uint64_t stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>& generation)
    noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (!active_completion_is_exact_locked(
            *state_, attempt_id, stream_epoch, generation)) {
        return false;
    }
    state_->completed_stream_epoch.store(
        stream_epoch, std::memory_order_release);
    return true;
}

bool ResolverStreamAttemptOwner::retire_if_exact(
    std::string_view attempt_id,
    std::uint64_t stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>& generation)
    noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return retire_if_exact_locked(
        *state_, attempt_id, stream_epoch, generation);
}

std::uint64_t ResolverStreamAttemptOwner::completed_stream_epoch()
    const noexcept {
    return state_->completed_stream_epoch.load(std::memory_order_acquire);
}

bool ResolverStreamAttemptOwner::ipc_gate_in_flight() const noexcept {
    return state_->ipc_gate_in_flight.load(std::memory_order_acquire);
}

ResolverStreamAttemptLifetime::ResolverStreamAttemptLifetime(
    std::shared_ptr<ResolverStreamAttemptOwnerState> state,
    std::shared_ptr<void> retained_authority,
    std::shared_ptr<const ResolverGenerationSnapshot> generation,
    std::string attempt_id,
    std::uint64_t stream_epoch)
    : state_(std::move(state)),
      ipc_gate_(state_),
      retained_authority_(std::move(retained_authority)),
      generation_(std::move(generation)),
      attempt_id_(std::move(attempt_id)),
      stream_epoch_(stream_epoch) {}

ResolverStreamAttemptLifetime::~ResolverStreamAttemptLifetime() noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    retire_if_exact_locked(
        *state_, attempt_id_, stream_epoch_, generation_);
}

} // namespace keen_pbr3
