#include "sing_box_transport_pause.hpp"

namespace keen_pbr3 {

SingBoxTransportPause::SingBoxTransportPause(
    Action action, const std::vector<std::string>& running)
    : action_(std::move(action)) {
    for (const auto& tag : running) {
        // An empty tag cannot be addressed to the manager, so it cannot be
        // stopped and must not be reported as one this daemon could put back.
        // It is unstoppable rather than skipped: it is running on the binary.
        if (tag.empty() || !action_) {
            unstoppable_.push_back(tag);
            continue;
        }
        if (action_(tag, "down")) {
            stopped_.push_back(tag);
        } else {
            unstoppable_.push_back(tag);
        }
    }
}

SingBoxTransportPause::~SingBoxTransportPause() { resume(); }

void SingBoxTransportPause::resume() noexcept {
    if (!action_) {
        // Nothing was stopped, because nothing could be.
        stopped_.clear();
        return;
    }
    for (const auto& tag : stopped_) {
        if (!action_(tag, "up")) left_down_.push_back(tag);
    }
    stopped_.clear();
}

} // namespace keen_pbr3
