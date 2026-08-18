#pragma once

#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Stops the operator's sing-box transports for the duration of an install and
// guarantees they are started again.
//
// The guarantee is why this is a class rather than two calls. Between the stop
// and the restart there is a fetch, a verification, an unpack and a file swap,
// and any of them can throw; without a destructor doing it, a failed install
// would leave an operator with no VPN and nothing saying why.
//
// The action is injected, so what this does to a router is testable without
// one - which matters here more than usual, because the interesting cases are
// the failures: a transport that will not stop, and one that will not start
// again.
class SingBoxTransportPause {
public:
    // Returns whether the manager accepted the action. `action` is "down" or
    // "up". Must not throw: it is called from a destructor.
    using Action =
        std::function<bool(const std::string& tag, const char* action)>;

    SingBoxTransportPause(Action action,
                          const std::vector<std::string>& running);
    ~SingBoxTransportPause();

    SingBoxTransportPause(const SingBoxTransportPause&) = delete;
    SingBoxTransportPause& operator=(const SingBoxTransportPause&) = delete;

    // False when something the operator agreed to stop is still running. The
    // install must not proceed then: the binary it would replace is in use,
    // which is the whole reason the blocker exists.
    bool all_stopped() const noexcept { return unstoppable_.empty(); }

    // Exactly the transports this stopped. A transport that was already down
    // is not here - it was not stopped, so it will not be started. The
    // operator stopped it, and an install is not a reason to overrule them.
    const std::vector<std::string>& stopped() const noexcept {
        return stopped_;
    }

    // Transports that were stopped and did not come back. Reported rather than
    // logged and forgotten: silence reads as "everything is fine" while the
    // operator's traffic has nowhere to go.
    const std::vector<std::string>& left_down() const noexcept {
        return left_down_;
    }

    const std::vector<std::string>& unstoppable() const noexcept {
        return unstoppable_;
    }

    // Idempotent, so the destructor after an explicit resume() does nothing.
    // Called explicitly when the caller wants to report what happened, because
    // a destructor cannot tell the operator anything.
    void resume() noexcept;

private:
    Action action_;
    std::vector<std::string> stopped_;
    std::vector<std::string> unstoppable_;
    std::vector<std::string> left_down_;
};

} // namespace keen_pbr3
