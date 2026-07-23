#include <doctest/doctest.h>

#include "runtime/runtime_state_machine.hpp"

using namespace keen_pbr3;

TEST_CASE("runtime state machine accepts recovery and rejects impossible transitions") {
    RuntimeStateMachine machine;
    std::string error;

    CHECK(machine.transition(RuntimeState::running, "startup complete", error));
    CHECK(machine.transition(RuntimeState::applying, "apply", error));
    CHECK(machine.transition(RuntimeState::broken, "apply failed", error));
    CHECK(machine.transition(RuntimeState::applying, "rollback", error));
    CHECK(machine.transition(RuntimeState::running, "rollback complete", error));
    CHECK(machine.transition(RuntimeState::stopped, "stopped", error));
    CHECK_FALSE(machine.transition(RuntimeState::running, "invalid shortcut", error));
    CHECK(error == "invalid runtime transition: stopped -> running");
}

TEST_CASE("broken runtime can be started explicitly") {
    RuntimeStateMachine machine(RuntimeState::broken);
    std::string error;
    CHECK(machine.transition(RuntimeState::starting, "retry requested", error));
    CHECK(machine.transition(RuntimeState::running, "retry complete", error));
}
