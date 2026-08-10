#include "interface_uptime_anchor.hpp"

#include <algorithm>
#include <utility>

namespace keen_pbr3 {

InterfaceUptimeAnchorStore::InterfaceUptimeAnchorStore(
    Clock::duration tolerance)
    : tolerance_(tolerance) {}

void InterfaceUptimeAnchorStore::latch_locked(State& state,
                                              TimePoint candidate,
                                              InterfaceUptimeSource source) {
    if (state.anchor) {
        const auto& current = state.anchor->up_since;
        const auto delta = current > candidate
            ? current - candidate
            : candidate - current;
        if (delta <= tolerance_) {
            // The same transition, merely derived again. Keeping the stored
            // instant is the whole point: re-latching here would move the
            // rendered uptime by the derivation error on every single poll.
            // A firmware observation still upgrades the provenance of an
            // anchor that was first seen over netlink, because only the
            // firmware value outlives this process.
            if (source == InterfaceUptimeSource::firmware) {
                state.anchor->source = source;
            }
            return;
        }
    }
    state.anchor = InterfaceUptimeAnchor{candidate, source};
}

void InterfaceUptimeAnchorStore::observe_firmware_uptime(
    std::string_view interface_name,
    std::int64_t uptime_seconds,
    TimePoint observed_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& state = states_[std::string(interface_name)];

    if (state.observed_at && observed_at < *state.observed_at) {
        // Served from a cache that lags behind the newest edge we already
        // applied. Letting it through would resurrect the previous lifetime.
        return;
    }
    state.observed_at = observed_at;
    state.firmware_authoritative = true;

    if (uptime_seconds <= 0) {
        // The firmware reports zero for an interface it does not consider up,
        // which is a statement about the link, not a missing measurement.
        state.link_up = false;
        state.anchor.reset();
        return;
    }

    state.link_up = true;
    latch_locked(state,
                 observed_at - std::chrono::seconds(uptime_seconds),
                 InterfaceUptimeSource::firmware);
}

void InterfaceUptimeAnchorStore::observe_link_state(
    std::string_view interface_name,
    bool link_up,
    TimePoint observed_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& state = states_[std::string(interface_name)];

    if (state.observed_at && observed_at < *state.observed_at) {
        return;
    }
    state.observed_at = observed_at;

    if (!link_up) {
        state.link_up = false;
        state.anchor.reset();
        return;
    }

    const bool was_down = state.link_up.has_value() && !*state.link_up;
    state.link_up = true;
    if (state.firmware_authoritative) {
        // The firmware owns this interface's up-transition. A kernel-visible
        // "up" on a tunnel device says only that the device exists, so it must
        // not start an anchor here - that is how a dead tunnel would come to
        // claim it had just connected.
        return;
    }
    if (was_down) {
        latch_locked(state, observed_at, InterfaceUptimeSource::observed);
        return;
    }
    // Either the link was already known up - no transition, keep the anchor -
    // or this is the first time we have ever seen it, in which case we do not
    // know when it came up and must leave the anchor absent. See the header:
    // guessing "now" here would publish daemon uptime under an interface name.
}

std::optional<InterfaceUptimeAnchor> InterfaceUptimeAnchorStore::anchor(
    std::string_view interface_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = states_.find(std::string(interface_name));
    if (it == states_.end()) {
        return std::nullopt;
    }
    return it->second.anchor;
}

void InterfaceUptimeAnchorStore::forget(std::string_view interface_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    states_.erase(std::string(interface_name));
}

void InterfaceUptimeAnchorStore::retain_only(
    const std::vector<std::string>& interface_names) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = states_.begin(); it != states_.end();) {
        const bool keep = std::find(interface_names.begin(),
                                    interface_names.end(),
                                    it->first) != interface_names.end();
        it = keep ? std::next(it) : states_.erase(it);
    }
}

void InterfaceUptimeAnchorStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    states_.clear();
}

std::size_t InterfaceUptimeAnchorStore::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return states_.size();
}

} // namespace keen_pbr3
