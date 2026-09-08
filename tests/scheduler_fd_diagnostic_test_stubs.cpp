// The focused scheduler gate uses real timerfd and its existing test registrar.
// No daemon is linked; accidentally taking the production registrar path fails.
#include "daemon/daemon.hpp"

#include <stdexcept>

namespace keen_pbr3 {

void Daemon::add_fd(int, std::uint32_t, std::function<void(std::uint32_t)>,
                    bool, const std::string&) {
    throw std::logic_error("focused scheduler test used the daemon fd registrar");
}

void Daemon::remove_fd(int, bool, const std::string&) {
    throw std::logic_error("focused scheduler test used the daemon fd registrar");
}

} // namespace keen_pbr3
