#include "scheduler.hpp"
#include <algorithm>
#include "daemon.hpp"

#include "../log/logger.hpp"

#include <cerrno>
#include <cstring>
#include <new>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

Scheduler::Scheduler(Daemon& daemon) : daemon_(&daemon) {}

#ifdef KEEN_PBR3_TESTING
Scheduler::Scheduler(SchedulerTestFdHooks hooks)
    : test_fd_hooks_(std::move(hooks)) {
    if (!test_fd_hooks_.add_fd || !test_fd_hooks_.remove_fd) {
        throw SchedulerError("scheduler test fd hooks are incomplete");
    }
}
#endif

Scheduler::~Scheduler() {
    // Best-effort cleanup: cancel all timers
    try {
        cancel_all();
    } catch (const std::exception& e) {
        try {
            Logger::instance().error(
                "Scheduler cleanup failed during destruction: {}",
                e.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().error(
                "Scheduler cleanup failed during destruction: unknown error");
        } catch (...) {
        }
    }
}

namespace {

timespec duration_to_timespec(std::chrono::milliseconds duration) {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    const auto remainder = duration - seconds;

    timespec spec{};
    spec.tv_sec = seconds.count();
    spec.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(remainder).count();
    return spec;
}

} // namespace

int Scheduler::create_timerfd(std::chrono::milliseconds initial,
                              std::chrono::milliseconds interval) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) {
        throw SchedulerError("timerfd_create failed: " + std::string(strerror(errno)));
    }

    struct itimerspec spec{};
    spec.it_value = duration_to_timespec(initial);
    // interval of {0,0} means one-shot (no repeat)
    spec.it_interval = duration_to_timespec(interval);

    if (timerfd_settime(fd, 0, &spec, nullptr) < 0) {
        close(fd);
        throw SchedulerError("timerfd_settime failed: " + std::string(strerror(errno)));
    }

    return fd;
}

int Scheduler::schedule_repeating(std::chrono::milliseconds interval,
                                  TaskCallback cb,
                                  std::string label) {
    return schedule_timer(interval,
                          interval,
                          std::move(cb),
                          /*repeating=*/true,
                          std::move(label));
}

int Scheduler::schedule_oneshot(std::chrono::milliseconds delay,
                                TaskCallback cb,
                                std::string label) {
    return schedule_timer(delay,
                          std::chrono::milliseconds{0},
                          std::move(cb),
                          /*repeating=*/false,
                          std::move(label));
}

int Scheduler::schedule_timer(std::chrono::milliseconds initial,
                              std::chrono::milliseconds interval,
                              TaskCallback cb,
                              bool repeating,
                              std::string label) {
    const int fd = create_timerfd(initial, interval);
    int id = 0;
    bool entry_published = false;
    bool registration_attempted = false;
    try {
        {
            KPBR_LOCK_GUARD(entries_mutex_);
            id = next_id_++;
#ifdef KEEN_PBR3_TESTING
            last_created_fd_ = fd;
            if (fail_next_entry_publication_) {
                fail_next_entry_publication_ = false;
                throw std::bad_alloc{};
            }
#endif
            entries_.push_back(
                {id, fd, std::move(cb), repeating, std::move(label)});
            entry_published = true;
        }

        // Publish the scheduler-side ownership record before making the
        // timer visible to epoll. A timerfd may already be readable when the
        // registrar returns (or even while a test registrar is running), so
        // on_timer() must be able to resolve it immediately.
        registration_attempted = true;
        register_timer_fd(fd);

#ifdef KEEN_PBR3_TESTING
        {
            KPBR_LOCK_GUARD(entries_mutex_);
            if (fail_next_post_registration_) {
                fail_next_post_registration_ = false;
                throw SchedulerError(
                    "injected post-registration scheduler failure");
            }
        }
#endif
    } catch (...) {
        // The callback may have synchronously consumed a ready one-shot while
        // the registrar was still running. In that case the entry is already
        // absent and its callback owns the unregister/close; touching the fd
        // again could affect an unrelated descriptor which reused its number.
        const bool still_owned =
            !entry_published || erase_timer_entry(fd);
        if (still_owned) {
            if (registration_attempted) {
                unregister_timer_fd(fd);
            }
            close(fd);
        }
        throw;
    }

    try {
        Logger::instance().trace("scheduler_register",
                                 "id={} timer_fd={} repeating={}",
                                 id,
                                 fd,
                                 repeating ? "true" : "false");
    } catch (...) {
    }
    return id;
}

void Scheduler::register_timer_fd(int fd) {
#ifdef KEEN_PBR3_TESTING
    if (test_fd_hooks_.add_fd) {
        test_fd_hooks_.add_fd(
            fd,
            [this, fd](std::uint32_t events) {
                on_timer(fd, events);
            });
        return;
    }
#endif
    if (daemon_ == nullptr) {
        throw SchedulerError("scheduler has no fd registrar");
    }
    daemon_->add_fd(
        fd,
        EPOLLIN,
        [this, fd](uint32_t events) { on_timer(fd, events); },
        true,
        "scheduler-add-fd");
}

void Scheduler::unregister_timer_fd(int fd) noexcept {
    try {
#ifdef KEEN_PBR3_TESTING
        if (test_fd_hooks_.remove_fd) {
            test_fd_hooks_.remove_fd(fd);
            return;
        }
#endif
        if (daemon_ != nullptr) {
            daemon_->remove_fd(
                fd, true, "scheduler-remove-fd");
        }
    } catch (...) {
    }
}

bool Scheduler::erase_timer_entry(int fd) noexcept {
    bool locked = false;
    try {
        // Avoid the tracing lock guard in this noexcept cleanup path: its
        // destructor also emits diagnostics, whereas ownership retirement
        // must not depend on diagnostic allocation or formatting.
        entries_mutex_.lock(
            "entries_mutex_", __FILE__, __LINE__, __func__);
        locked = true;
        const auto previous_size = entries_.size();
        entries_.erase(
            std::remove_if(
                entries_.begin(),
                entries_.end(),
                [fd](const TimerEntry& entry) {
                    return entry.timer_fd == fd;
                }),
            entries_.end());
        const bool erased = entries_.size() != previous_size;
        entries_mutex_.unlock();
        locked = false;
        return erased;
    } catch (...) {
        if (locked) {
            try {
                entries_mutex_.unlock();
            } catch (...) {
            }
        }
        return false;
    }
}

void Scheduler::on_timer(int timer_fd, uint32_t /*events*/) noexcept {
    // Read the timerfd to acknowledge the expiration
    uint64_t expirations = 0;
    ssize_t n = read(timer_fd, &expirations, sizeof(expirations));
    if (n != sizeof(expirations)) {
        return;
    }

    // Snapshot the callback outside of its invocation. Copying std::function
    // or its diagnostic label can allocate, so neither is allowed to unwind
    // through the daemon event loop.
    bool found = false;
    bool repeating = false;
    TaskCallback cb;
    std::string label;
    const char* preparation_failure = nullptr;
    bool locked = false;
    try {
        entries_mutex_.lock(
            "entries_mutex_", __FILE__, __LINE__, __func__);
        locked = true;
        for (const auto& entry : entries_) {
            if (entry.timer_fd != timer_fd) {
                continue;
            }
            found = true;
            repeating = entry.repeating;
            try {
                cb = entry.callback;
            } catch (...) {
                preparation_failure = "callback snapshot";
            }
            try {
                label = entry.label;
            } catch (...) {
                if (preparation_failure == nullptr) {
                    preparation_failure = "label snapshot";
                }
            }
            break;
        }
    } catch (...) {
        preparation_failure = "entry lookup";
    }
    if (locked) {
        try {
            entries_mutex_.unlock();
        } catch (...) {
            preparation_failure = "entry unlock";
            found = false;
        }
    }

    if (!found) {
        if (preparation_failure != nullptr) {
            try {
                Logger::instance().error(
                    "Scheduler timer dispatch failed during {} for fd {}",
                    preparation_failure,
                    timer_fd);
            } catch (...) {
            }
        }
        return;
    }
    if (!repeating) {
        // Consume a one-shot before calling user code. It stays consumed even
        // when callback preparation or invocation fails.
        remove_entry(timer_fd);
    }
    if (!cb) {
        if (preparation_failure != nullptr) {
            try {
                Logger::instance().error(
                    "Scheduler timer dispatch failed during {} for fd {}",
                    preparation_failure,
                    timer_fd);
            } catch (...) {
            }
        }
        return;
    }
    try {
        Logger::instance().trace(
            "scheduler_fire", "timer_fd={} label={}", timer_fd, label);
    } catch (...) {
    }
    try {
        cb();
    } catch (const std::exception& e) {
        try {
            Logger::instance().error(
                "Scheduler callback failed for fd {} ({}): {}",
                timer_fd,
                label,
                e.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().error(
                "Scheduler callback failed for fd {} ({}): unknown error",
                timer_fd,
                label);
        } catch (...) {
        }
    }
}

void Scheduler::cancel(int task_id) {
    int fd = -1;
    {
        KPBR_LOCK_GUARD(entries_mutex_);
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->id == task_id) {
                fd = it->timer_fd;
                entries_.erase(it);
                break;
            }
        }
    }
    if (fd >= 0) {
        try {
            Logger::instance().trace(
                "scheduler_cancel", "id={} timer_fd={}", task_id, fd);
        } catch (...) {
        }
        unregister_timer_fd(fd);
        close(fd);
    }
}

void Scheduler::cancel_all() {
    std::vector<int> timer_fds;
    {
        KPBR_LOCK_GUARD(entries_mutex_);
        timer_fds.reserve(entries_.size());
        for (const auto& entry : entries_) {
            timer_fds.push_back(entry.timer_fd);
        }
        entries_.clear();
    }

    for (int timer_fd : timer_fds) {
        try {
            Logger::instance().trace(
                "scheduler_cancel", "id={} timer_fd={}", -1, timer_fd);
        } catch (...) {
        }
        unregister_timer_fd(timer_fd);
        close(timer_fd);
    }
}

void Scheduler::remove_entry(int timer_fd) noexcept {
    // Only the actor which removed the ownership record may unregister and
    // close the fd. This prevents a racing cancel/dispatch path from touching
    // a newly reused descriptor number.
    if (!erase_timer_entry(timer_fd)) {
        return;
    }
    unregister_timer_fd(timer_fd);
    close(timer_fd);
}

#ifdef KEEN_PBR3_TESTING
void Scheduler::fail_next_entry_publication_for_testing() {
    KPBR_LOCK_GUARD(entries_mutex_);
    fail_next_entry_publication_ = true;
}

void Scheduler::fail_next_post_registration_for_testing() {
    KPBR_LOCK_GUARD(entries_mutex_);
    fail_next_post_registration_ = true;
}

int Scheduler::last_created_fd_for_testing() const {
    KPBR_LOCK_GUARD(entries_mutex_);
    return last_created_fd_;
}
#endif

size_t Scheduler::size() const {
    KPBR_LOCK_GUARD(entries_mutex_);
    return entries_.size();
}

} // namespace keen_pbr3
