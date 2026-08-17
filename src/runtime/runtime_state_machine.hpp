#pragma once

#include <string>

namespace keen_pbr3 {

enum class RuntimeState {
    starting,
    running,
    restart_required,
    applying,
    stopped,
    broken,
    shutting_down,
};

const char* runtime_state_name(RuntimeState state);

class RuntimeStateMachine {
public:
    explicit RuntimeStateMachine(RuntimeState initial = RuntimeState::starting);

    RuntimeState state() const;
    const std::string& reason() const;
    bool transition(RuntimeState next, std::string reason, std::string& error);

private:
    RuntimeState state_;
    std::string reason_;
};

} // namespace keen_pbr3
