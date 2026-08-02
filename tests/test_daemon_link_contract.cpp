#include <doctest/doctest.h>

#include "daemon/daemon.hpp"

namespace keen_pbr3 {
namespace {

TEST_CASE("daemon production translation units link into the test binary") {
    using RunMethod = void (Daemon::*)();
    using RunningMethod = bool (Daemon::*)() const;
    using PostMethod = bool (Daemon::*)(std::function<void()>,
                                        const std::string&);

    const RunMethod run = &Daemon::run;
    const RunMethod stop = &Daemon::stop;
    const RunningMethod running = &Daemon::running;
    const PostMethod post = &Daemon::post_control_task;

    CHECK(run != nullptr);
    CHECK(stop != nullptr);
    CHECK(running != nullptr);
    CHECK(post != nullptr);
}

} // namespace
} // namespace keen_pbr3
