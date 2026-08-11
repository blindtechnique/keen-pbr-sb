#include "interface_uptime_anchor.hpp"

#include <algorithm>
#include <iterator>
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
    state.anchor = Anchor{candidate, source};
}

void InterfaceUptimeAnchorStore::begin_round(
    const std::vector<std::string>& present,
    TimePoint now) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = states_.begin(); it != states_.end();) {
        const bool keep = std::find(present.begin(), present.end(), it->first)
            != present.end();
        it = keep ? std::next(it) : states_.erase(it);
    }

    for (const auto& name : present) {
        const auto inserted = states_.emplace(name, State{});
        if (inserted.second) {
            // A name we have not seen before, or one that vanished and came
            // back. Either way this is the start of a lifetime we can vouch
            // for, and nothing observed before it describes this interface.
            inserted.first->second.first_seen = now;
        }
    }
}

void InterfaceUptimeAnchorStore::observe_firmware_uptime(
    std::string_view interface_name,
    std::int64_t uptime_seconds,
    TimePoint observed_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto entry = states_.find(std::string(interface_name));
    if (entry == states_.end()) {
        // Not part of the current round. The firmware knows about interfaces
        // the kernel does not currently have, and inventing state for them
        // here would resurrect entries begin_round has just dropped.
        return;
    }
    auto& state = entry->second;

    if (observed_at < state.first_seen) {
        // Read before this interface entered the round set, so it describes a
        // previous lifetime. This is the deleted-and-recreated tunnel: the
        // catalog cache can still be serving a pre-deletion snapshot, and
        // applying it would hand the new interface the dead one's uptime.
        return;
    }
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
    const auto entry = states_.find(std::string(interface_name));
    if (entry == states_.end()) {
        // Outside the current round. begin_round is the only way an interface
        // enters this store, so that every entry carries a first_seen the
        // firmware guard can compare against.
        return;
    }
    auto& state = entry->second;

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

std::optional<InterfaceUptimeAnchorStore::Anchor>
InterfaceUptimeAnchorStore::anchor(std::string_view interface_name) const {
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

void InterfaceUptimeAnchorStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    states_.clear();
}

std::size_t InterfaceUptimeAnchorStore::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return states_.size();
}

} // namespace keen_pbr3
