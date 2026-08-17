#pragma once

#include "../config/config.hpp"
#include "internal_vpn_runtime_target.hpp"

#include <utility>
#include <vector>

namespace keen_pbr3 {

// Temporarily exposes a candidate native-VPN mapping to routing/firewall
// builders. Unless commit() is called after the kernel transaction succeeds,
// destruction restores the exact previous in-memory generation. This keeps
// the daemon's effective identity map aligned with the generation that is
// actually forwarding in the kernel.
template <typename Value>
class InternalVpnVectorGenerationTransaction {
public:
    InternalVpnVectorGenerationTransaction(
        std::vector<Value>& active,
        const std::vector<Value>& candidate)
        : active_(active),
          previous_(active) {
        active_ = candidate;
    }

    ~InternalVpnVectorGenerationTransaction() {
        if (!committed_) {
            active_ = std::move(previous_);
        }
    }

    InternalVpnVectorGenerationTransaction(
        const InternalVpnVectorGenerationTransaction&) = delete;
    InternalVpnVectorGenerationTransaction& operator=(
        const InternalVpnVectorGenerationTransaction&) = delete;
    InternalVpnVectorGenerationTransaction(
        InternalVpnVectorGenerationTransaction&&) = delete;
    InternalVpnVectorGenerationTransaction& operator=(
        InternalVpnVectorGenerationTransaction&&) = delete;

    void commit() noexcept {
        committed_ = true;
    }

private:
    std::vector<Value>& active_;
    std::vector<Value> previous_;
    bool committed_{false};
};

using InternalVpnRuntimeGenerationTransaction =
    InternalVpnVectorGenerationTransaction<InternalVpnServer>;
using InternalVpnRuntimeTargetGenerationTransaction =
    InternalVpnVectorGenerationTransaction<InternalVpnRuntimeTarget>;

template <typename ApplyKernelGeneration, typename PublishMemoryGeneration>
void commit_internal_vpn_runtime_generation(
    std::vector<InternalVpnServer>& active,
    const std::vector<InternalVpnServer>& candidate,
    ApplyKernelGeneration&& apply_kernel_generation,
    PublishMemoryGeneration&& publish_memory_generation) {
    InternalVpnRuntimeGenerationTransaction transaction(active, candidate);
    std::forward<ApplyKernelGeneration>(apply_kernel_generation)();
    // The kernel generation is now authoritative. Commit the matching active
    // map before any secondary publication (for example the LKG cache) that
    // could allocate or lock and fail independently.
    transaction.commit();
    std::forward<PublishMemoryGeneration>(publish_memory_generation)();
}

} // namespace keen_pbr3
