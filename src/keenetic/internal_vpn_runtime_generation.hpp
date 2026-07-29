#pragma once

#include "../config/config.hpp"

#include <utility>
#include <vector>

namespace keen_pbr3 {

// Temporarily exposes a candidate native-VPN mapping to routing/firewall
// builders. Unless commit() is called after the kernel transaction succeeds,
// destruction restores the exact previous in-memory generation. This keeps
// the daemon's effective identity map aligned with the generation that is
// actually forwarding in the kernel.
class InternalVpnRuntimeGenerationTransaction {
public:
    InternalVpnRuntimeGenerationTransaction(
        std::vector<InternalVpnServer>& active,
        const std::vector<InternalVpnServer>& candidate)
        : active_(active),
          previous_(active) {
        active_ = candidate;
    }

    ~InternalVpnRuntimeGenerationTransaction() {
        if (!committed_) {
            active_ = std::move(previous_);
        }
    }

    InternalVpnRuntimeGenerationTransaction(
        const InternalVpnRuntimeGenerationTransaction&) = delete;
    InternalVpnRuntimeGenerationTransaction& operator=(
        const InternalVpnRuntimeGenerationTransaction&) = delete;
    InternalVpnRuntimeGenerationTransaction(
        InternalVpnRuntimeGenerationTransaction&&) = delete;
    InternalVpnRuntimeGenerationTransaction& operator=(
        InternalVpnRuntimeGenerationTransaction&&) = delete;

    void commit() noexcept {
        committed_ = true;
    }

private:
    std::vector<InternalVpnServer>& active_;
    std::vector<InternalVpnServer> previous_;
    bool committed_{false};
};

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
