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

// Remembers when each interface last completed a confirmed up-transition.
//
// Anchors live on the STEADY clock, never on the wall clock. A Keenetic has no
// battery-backed RTC: the daemon starts with the firmware's fallback time and
// NTP steps the clock minutes later. An anchor latched at the pre-sync instant
// and never re-derived would then report an uptime longer than the router has
// existed - and for an interface the firmware never reports, nothing would ever
// correct it. Callers convert to wall time only at publication, from a steady
// and wall pair read together, so a clock step moves the published instant
// without changing the elapsed time it represents.
//
// Both available inputs are relative - the firmware reports "up for N seconds"
// and netlink reports an edge - so the instant has to be derived. Deriving it
// again on every poll would make the rendered uptime jitter by the poll
// interval and by the one-second granularity of the firmware counter, so the
// store latches once and then defends: a freshly derived anchor replaces the
// stored one only when the two disagree by more than `tolerance`. That is what
// an actual flap looks like and what poll noise never is.
//
// An interface with no confirmed transition has no anchor at all, and callers
// must render that as unknown. Substituting process or router uptime would
// report a number that silently resets on every daemon restart, which is
// exactly the failure this store exists to prevent.
class InterfaceUptimeAnchorStore {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    static constexpr std::chrono::seconds kDefaultTolerance{5};

    struct Anchor {
        TimePoint up_since{};
        InterfaceUptimeSource source{InterfaceUptimeSource::observed};
    };

    explicit InterfaceUptimeAnchorStore(
        Clock::duration tolerance = kDefaultTolerance);

    // Opens an observation round: forgets every interface outside `present` and
    // records the first sighting of the ones that are new.
    //
    // One call under one lock on purpose. Two API workers can build an
    // inventory concurrently, and splitting this into separate drop and touch
    // steps let one worker's round erase an entry the other had just created.
    void begin_round(const std::vector<std::string>& present, TimePoint now);

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
    // "now" would publish daemon uptime wearing an interface label. Such an
    // interface stays unknown until the firmware counter fills it in.
    void observe_link_state(std::string_view interface_name,
                            bool link_up,
                            TimePoint observed_at);

    std::optional<Anchor> anchor(std::string_view interface_name) const;

    void forget(std::string_view interface_name);
    void clear();
    std::size_t size() const;

private:
    struct State {
        std::optional<Anchor> anchor;
        // Tri-state on purpose. "Never observed" must not collapse into
        // "observed down", or the first sighting of an already-up interface
        // would read as a fresh up-transition.
        std::optional<bool> link_up;
        // Newest observation instant applied to this entry. Inputs older than
        // it are dropped: the firmware counter is served from a cache that may
        // lag by up to its TTL, and a stale snapshot must never be allowed to
        // undo a newer netlink edge.
        std::optional<TimePoint> observed_at;
        // When this interface entered the current round set. A firmware
        // observation read BEFORE this instant describes a previous lifetime -
        // the case where a tunnel is deleted and recreated under the same name
        // while a pre-deletion catalog is still cached, which would otherwise
        // hand the new interface the dead one's uptime.
        TimePoint first_seen{};
        // True when this interface appeared in a round AFTER the first one,
        // which means the device did not exist a moment ago and we are seeing
        // it being created rather than seeing it for the first time.
        //
        // That distinction is what lets a sing-box TUN report an uptime at
        // all. Such devices are invisible to the Keenetic inventory, so the
        // firmware never describes them, and the "first sighting proves
        // nothing" rule would otherwise leave every one of them unknown
        // forever - including after the transport that owns it is restarted.
        bool appeared_after_first_round{false};
        // Whether this entry has ever been through observe_link_state with an
        // up link. Distinct from link_up, which the firmware also sets: only a
        // kernel observation proves the device was actually there.
        bool link_up_ever_observed{false};
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
    // The first round is special: everything in it is merely being seen for
    // the first time. Only from the second round on does a new name mean a
    // device that was genuinely created.
    bool any_round_completed_{false};
    std::unordered_map<std::string, State> states_;
};

} // namespace keen_pbr3
