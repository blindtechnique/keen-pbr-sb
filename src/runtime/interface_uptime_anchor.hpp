#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace keen_pbr3 {

// Which confirmed up-transition an anchor was derived from.
enum class InterfaceUptimeSource : std::uint8_t {
    // The KeeneticOS per-interface uptime counter. The firmware owns it, so it
    // survives a keen-pbr restart, a configuration apply and a UI reload.
    firmware,
    // A down->up edge this daemon observed itself. Immediate and precise, but
    // it only covers transitions that happened while this process was running.
    observed,
};

struct InterfaceUptimeAnchor {
    std::chrono::system_clock::time_point up_since{};
    InterfaceUptimeSource source{InterfaceUptimeSource::observed};
};

// Remembers when each interface last completed a confirmed up-transition.
//
// Both available inputs are relative - the firmware reports "up for N seconds"
// and netlink reports an edge - so the absolute instant has to be derived.
// Deriving it again on every poll would make the rendered uptime jitter by the
// poll interval and by the one-second granularity of the firmware counter, so
// the store latches an anchor once and then defends it: a freshly derived
// anchor replaces the stored one only when the two disagree by more than
// `tolerance`. That is what an actual flap looks like and what poll noise
// never is.
//
// An interface with no confirmed transition has no anchor at all, and callers
// must render that as unknown. Substituting process or router uptime would
// report a number that silently resets on every daemon restart, which is
// exactly the failure this store exists to prevent.
class InterfaceUptimeAnchorStore {
public:
    using Clock = std::chrono::system_clock;
    using TimePoint = Clock::time_point;

    static constexpr std::chrono::seconds kDefaultTolerance{5};

    explicit InterfaceUptimeAnchorStore(
        Clock::duration tolerance = kDefaultTolerance);

    // Applies the firmware "up for N seconds" counter as read at
    // `observed_at`. A non-positive counter is the firmware saying the
    // interface is not up, which drops any anchor it had.
    void observe_firmware_uptime(std::string_view interface_name,
                                 std::int64_t uptime_seconds,
                                 TimePoint observed_at);

    // Applies an observed link state. Only a transition into `up` starts a new
    // anchor. An interface that was already known to be up keeps the anchor it
    // has, so repeatedly observing an unchanged link never restarts its
    // uptime.
    //
    // The FIRST observation of an already-up interface deliberately creates no
    // anchor: this daemon cannot know when that link came up, and dating it to
    // "now" would silently report daemon uptime wearing an interface label.
    // Such an interface stays unknown until the firmware counter fills it in.
    void observe_link_state(std::string_view interface_name,
                            bool link_up,
                            TimePoint observed_at);

    std::optional<InterfaceUptimeAnchor> anchor(
        std::string_view interface_name) const;

    void forget(std::string_view interface_name);
    // Drops every entry outside `interface_names`. Callers that rebuild the
    // whole interface set pass it here so a tunnel that was deleted and later
    // recreated under the same name cannot inherit the previous lifetime's
    // anchor.
    void retain_only(const std::vector<std::string>& interface_names);
    void clear();
    std::size_t size() const;

private:
    struct State {
        std::optional<InterfaceUptimeAnchor> anchor;
        // Tri-state on purpose. "Never observed" must not collapse into
        // "observed down", or the first sighting of an already-up interface
        // would read as a fresh up-transition.
        std::optional<bool> link_up;
        // Newest observation instant applied to this entry. Inputs older than
        // it are dropped: the firmware counter is served from a cache that may
        // lag by up to its TTL, and a stale snapshot must never be allowed to
        // undo a newer netlink edge.
        std::optional<TimePoint> observed_at;
        // Set once the firmware has reported on this interface. A tunnel
        // device stays administratively and operationally "up" in the kernel
        // for as long as it exists, including while the tunnel itself is
        // dead, so a netlink edge must never be allowed to invent an
        // up-transition for an interface the firmware is already speaking
        // about. It may still retract one: a link the kernel reports down
        // cannot have an uptime whatever the firmware last said.
        bool firmware_authoritative{false};
    };

    void latch_locked(State& state,
                      TimePoint candidate,
                      InterfaceUptimeSource source);

    Clock::duration tolerance_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, State> states_;
};

} // namespace keen_pbr3
