#pragma once

namespace keen_pbr3 {

// A transport may publish its TUN while a foreground Save already owns the
// runtime mutation lease but has not yet handed that lease to the firewall
// owner. Starting a background refresh in that narrow interval makes it wait
// for the Save's lease while the Save then waits for the background owner.
// Keep the firmware event in the existing debounce queue instead. The
// background worker itself is allowed through so later events can coalesce
// with its already admitted pass.
inline bool should_defer_netfilter_refresh_for_runtime_mutation(
    bool runtime_mutation_active,
    bool active_mutation_is_netfilter_worker) noexcept {
    return runtime_mutation_active &&
           !active_mutation_is_netfilter_worker;
}

} // namespace keen_pbr3
