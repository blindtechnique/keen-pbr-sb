#pragma once

#include <cstdint>
#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

namespace keen_pbr3 {

class InterfaceMonitorError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class InterfaceMonitor {
public:
    struct Event {
        std::string interface_name;
        bool administrative_state_changed{false};
        bool is_up{false};
        bool address_changed{false};
        // True when the kernel link namespace changed rather than only the
        // administrative state of an already known interface. In particular
        // this covers RTM_DELLINK, the first RTM_NEWLINK for a name, and a
        // rename observed under a previously unseen name.
        bool topology_changed{false};
        // Netlink reported an observation gap (for example ENOBUFS). The
        // daemon must revoke cached topology authority and request a fresh
        // NDMS observation instead of assuming a later outbound probe repairs
        // the internal-VPN mapping.
        bool observation_gap{false};
        // A main-table IPv4/IPv6 route changed. This is a revision fence for
        // off-loop reachability plans; it is not an interface/catalog event.
        bool route_changed{false};
        // A bounded ARP/NDP identity/presence hint, never an authoritative
        // hotspot count and never a routing/runtime observation.
        bool neighbor_changed{false};
        // Additional metadata hint on an existing main-table route event.
        bool default_route_changed{false};
    };
    using InterfaceStateCallback = std::function<void(const Event&)>;

    struct NeighborObservation {
        int address_family{0};
        std::uint32_t interface_index{0};
        // Exact network-order bytes: four for IPv4, sixteen for IPv6.
        std::string address;
        std::string link_address;
        std::uint16_t state{0};
        bool present{true};
    };

    // Pure bounded event classifier. Reachability refreshes retain the same
    // identity, so REACHABLE/STALE/DELAY/PROBE churn does not emit more hints.
    // Entries are evicted in insertion order; no inventory/count is exposed.
    class NeighborHintTracker {
    public:
        static constexpr std::size_t max_entries = 2048U;
        bool observe(const NeighborObservation& observation);
        void clear() noexcept;
        std::size_t size() const noexcept { return entries_.size(); }

    private:
        using Key = std::tuple<int, std::uint32_t, std::string>;
        struct State {
            std::string link_address;
            bool failed{false};
        };
        std::map<Key, State> entries_;
        std::deque<Key> insertion_order_;
    };

    explicit InterfaceMonitor(InterfaceStateCallback callback);
    ~InterfaceMonitor();

    InterfaceMonitor(const InterfaceMonitor&) = delete;
    InterfaceMonitor& operator=(const InterfaceMonitor&) = delete;
    InterfaceMonitor(InterfaceMonitor&&) = delete;
    InterfaceMonitor& operator=(InterfaceMonitor&&) = delete;

    int fd() const;
    void handle_events();
    void reconnect();

    // Pure transition classifier shared by the netlink adapter and tests.
    // link_present=false represents RTM_DELLINK. A missing previous state on
    // RTM_NEWLINK is a topology event, not an administrative-state event.
    static Event describe_link_transition(
        std::string interface_name,
        bool link_present,
        std::optional<bool> previous_is_up,
        bool is_up);
    static Event describe_indexed_link_transition(
        std::string interface_name,
        bool link_present,
        std::optional<std::string> previous_interface_name,
        std::optional<bool> previous_is_up,
        bool is_up);
    static std::optional<Event> describe_route_transition(
        std::uint32_t table,
        int address_family,
        bool default_route = false);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace keen_pbr3
