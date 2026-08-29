#pragma once

#include "runtime_recovery_policy.hpp"
#include "../runtime/runtime_mutation_admission.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <exception>
#include <memory>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

inline bool runtime_stop_cleanup_exact_lease_returned(
    const RuntimeMutationAdmission& admission,
    std::uint64_t expected_token,
    const std::unique_ptr<RuntimeMutationAdmission::Lease>& exact) noexcept {
    return exact && static_cast<bool>(*exact) &&
           exact->token() == expected_token && admission.owns(*exact);
}

enum class RuntimeStopCleanupIntent : std::uint8_t {
    runtime_stop,
    process_shutdown,
};

// Immutable authority for one monotonic STOP cleanup. Retrying this target may
// only delete the same keen-pbr-owned state; it must never resnapshot a newer
// runtime generation or widen conntrack selectors.
struct RuntimeStopCleanupTarget final {
    RuntimeStopCleanupIntent intent{
        RuntimeStopCleanupIntent::runtime_stop};
    std::uint64_t runtime_generation{0U};
    bool cleanup_conntrack{false};
    OwnedConntrackCleanupSnapshot conntrack_snapshot;
    bool deactivate_resolver{true};
    std::size_t maximum_attempts{3U};
};

enum class RuntimeStopCleanupFailureStage : std::uint8_t {
    none,
    conntrack,
    routing,
    firewall,
    resolver,
};

constexpr std::uint8_t runtime_stop_cleanup_failure_bit(
    RuntimeStopCleanupFailureStage stage) noexcept {
    return stage == RuntimeStopCleanupFailureStage::none
        ? 0U
        : static_cast<std::uint8_t>(
              1U << (static_cast<std::uint8_t>(stage) - 1U));
}

constexpr const char* runtime_stop_cleanup_failure_name(
    RuntimeStopCleanupFailureStage stage) noexcept {
    switch (stage) {
    case RuntimeStopCleanupFailureStage::conntrack:
        return "conntrack";
    case RuntimeStopCleanupFailureStage::routing:
        return "routing";
    case RuntimeStopCleanupFailureStage::firewall:
        return "firewall";
    case RuntimeStopCleanupFailureStage::resolver:
        return "resolver";
    case RuntimeStopCleanupFailureStage::none:
        break;
    }
    return "none";
}

struct RuntimeStopCleanupResult final {
    RuntimeStopCleanupTarget target;
    std::size_t attempts{0U};
    bool mutation_boundary_entered{false};
    bool conntrack_cleanup_verified{false};
    bool routing_cleanup_verified{false};
    // True only after the strict backend seam has proved that all targeted
    // keen-pbr-owned firewall state is absent. Merely completing a cleanup
    // call without throwing is not verification.
    bool firewall_absence_verified{false};
    bool resolver_deactivation_verified{false};
    // Worker bodies must never allocate after the first destructive command:
    // an allocation failure there would discard the only exact cleanup proof.
    // Fixed stage bits retain bounded diagnostics without strings/vectors.
    std::uint8_t failure_stages{0U};
    RuntimeStopCleanupFailureStage last_failure_stage{
        RuntimeStopCleanupFailureStage::none};

    void record_failure(RuntimeStopCleanupFailureStage stage) noexcept {
        failure_stages = static_cast<std::uint8_t>(
            failure_stages | runtime_stop_cleanup_failure_bit(stage));
        last_failure_stage = stage;
    }

    bool has_failures() const noexcept {
        return failure_stages != 0U;
    }

    bool kernel_cleanup_verified() const noexcept {
        return (!target.cleanup_conntrack ||
                conntrack_cleanup_verified) &&
               routing_cleanup_verified &&
               firewall_absence_verified;
    }

    bool fully_verified() const noexcept {
        return kernel_cleanup_verified() &&
               (!target.deactivate_resolver ||
                resolver_deactivation_verified);
    }
};

static_assert(
    std::is_nothrow_move_assignable_v<RuntimeStopCleanupResult>,
    "typed STOP proof must remain movable without allocation after mutation");

struct RuntimeStopCleanupServices final {
    std::function<bool(const OwnedConntrackCleanupSnapshot&)>
        cleanup_conntrack;
    std::function<bool()> clear_routing;
    // Must return true only after strict post-cleanup absence verification.
    std::function<bool()> cleanup_firewall;
    std::function<bool()> deactivate_resolver;
    std::function<void(std::chrono::milliseconds)> backoff;
};

inline bool runtime_shutdown_cleanup_owner_ready(
    bool admission_idle,
    bool owner_has_active_context,
    bool owner_has_pending_successor) noexcept {
    return admission_idle &&
           !owner_has_active_context &&
           !owner_has_pending_successor;
}

enum class RuntimeStopCleanupTerminalPublication : std::uint8_t {
    retain_running,
    retain_stopped,
    publish_stopped,
    // Any worker-side incomplete cleanup publishes an inactive broken runtime.
    publish_broken,
};

struct RuntimeStopCleanupTerminalFacts final {
    bool runtime_was_running{true};
    bool worker_started{false};
    bool mutation_boundary_entered{false};
    bool kernel_cleanup_verified{false};
    bool resolver_deactivation_required{true};
    bool resolver_deactivation_verified{false};
};

inline RuntimeStopCleanupTerminalPublication
runtime_stop_cleanup_terminal_publication(
    const RuntimeStopCleanupTerminalFacts& facts) noexcept {
    const auto cleanup_fully_verified =
        facts.kernel_cleanup_verified &&
        (!facts.resolver_deactivation_required ||
         facts.resolver_deactivation_verified);
    if (cleanup_fully_verified) {
        return RuntimeStopCleanupTerminalPublication::publish_stopped;
    }
    if (!facts.worker_started && !facts.mutation_boundary_entered) {
        return facts.runtime_was_running
            ? RuntimeStopCleanupTerminalPublication::retain_running
            : RuntimeStopCleanupTerminalPublication::retain_stopped;
    }
    return RuntimeStopCleanupTerminalPublication::publish_broken;
}

inline std::chrono::milliseconds runtime_stop_cleanup_backoff(
    std::size_t completed_attempts) noexcept {
    // The first body runs immediately. Only two bounded monotonic retries are
    // possible, and both stay short enough for Keenetic service shutdown.
    return completed_attempts <= 1U
        ? std::chrono::milliseconds{50}
        : std::chrono::milliseconds{150};
}

inline void execute_runtime_stop_cleanup_transaction_into(
    RuntimeStopCleanupResult& result,
    RuntimeStopCleanupTarget target,
    const RuntimeStopCleanupServices& services) {
    // This target assignment is intentionally before mutation. Production
    // preallocates `result`; the body below only updates fixed scalar proof.
    result = RuntimeStopCleanupResult{};
    result.target = std::move(target);
    result.conntrack_cleanup_verified =
        !result.target.cleanup_conntrack;
    result.resolver_deactivation_verified =
        !result.target.deactivate_resolver;

    const auto maximum_attempts =
        std::max<std::size_t>(
            1U,
            std::min<std::size_t>(
                result.target.maximum_attempts, 3U));
    for (std::size_t attempt = 0U;
         attempt < maximum_attempts && !result.fully_verified();
         ++attempt) {
        ++result.attempts;

        if (!result.conntrack_cleanup_verified) {
            result.mutation_boundary_entered = true;
            try {
                result.conntrack_cleanup_verified =
                    services.cleanup_conntrack &&
                    services.cleanup_conntrack(
                        result.target.conntrack_snapshot);
                if (!result.conntrack_cleanup_verified) {
                    result.record_failure(
                        RuntimeStopCleanupFailureStage::conntrack);
                }
            } catch (const std::exception&) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::conntrack);
            } catch (...) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::conntrack);
            }
        }

        if (!result.routing_cleanup_verified) {
            result.mutation_boundary_entered = true;
            try {
                result.routing_cleanup_verified =
                    services.clear_routing &&
                    services.clear_routing();
                if (!result.routing_cleanup_verified) {
                    result.record_failure(
                        RuntimeStopCleanupFailureStage::routing);
                }
            } catch (const std::exception&) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::routing);
            } catch (...) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::routing);
            }
        }

        if (!result.firewall_absence_verified) {
            result.mutation_boundary_entered = true;
            try {
                result.firewall_absence_verified =
                    services.cleanup_firewall &&
                    services.cleanup_firewall();
                if (!result.firewall_absence_verified) {
                    result.record_failure(
                        RuntimeStopCleanupFailureStage::firewall);
                }
            } catch (const std::exception&) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::firewall);
            } catch (...) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::firewall);
            }
        }

        if (result.kernel_cleanup_verified() &&
            !result.resolver_deactivation_verified) {
            try {
                result.resolver_deactivation_verified =
                    services.deactivate_resolver &&
                    services.deactivate_resolver();
                if (!result.resolver_deactivation_verified) {
                    result.record_failure(
                        RuntimeStopCleanupFailureStage::resolver);
                }
            } catch (const std::exception&) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::resolver);
            } catch (...) {
                result.record_failure(
                    RuntimeStopCleanupFailureStage::resolver);
            }
        }

        if (!result.fully_verified() &&
            attempt + 1U < maximum_attempts && services.backoff) {
            services.backoff(
                runtime_stop_cleanup_backoff(result.attempts));
        }
    }

}

inline RuntimeStopCleanupResult execute_runtime_stop_cleanup_transaction(
    RuntimeStopCleanupTarget target,
    const RuntimeStopCleanupServices& services) {
    RuntimeStopCleanupResult result;
    execute_runtime_stop_cleanup_transaction_into(
        result, std::move(target), services);
    return result;
}

} // namespace keen_pbr3
