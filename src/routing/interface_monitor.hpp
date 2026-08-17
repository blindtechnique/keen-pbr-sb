#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

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
    };
    using InterfaceStateCallback = std::function<void(const Event&)>;

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

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace keen_pbr3
