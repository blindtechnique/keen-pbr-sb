#include <doctest/doctest.h>

#include "../src/update/sing_box_transport_pause.hpp"

#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Records every call, so the tests assert what a router would actually have
// been told rather than what the class reports about itself.
struct Manager {
    std::vector<std::string> calls;
    std::set<std::string> refuse_down;
    std::set<std::string> refuse_up;

    SingBoxTransportPause::Action action() {
        return [this](const std::string& tag, const char* what) {
            calls.push_back(std::string(what) + ":" + tag);
            if (std::string(what) == "down") {
                return refuse_down.count(tag) == 0U;
            }
            return refuse_up.count(tag) == 0U;
        };
    }
};

} // namespace

TEST_CASE("the pause stops what it was given and starts it again") {
    Manager manager;
    {
        SingBoxTransportPause pause(manager.action(), {"nl", "de"});
        CHECK(pause.all_stopped());
        CHECK(pause.stopped() == std::vector<std::string>{"nl", "de"});
        // Not started yet - the install happens here.
        CHECK(manager.calls ==
              std::vector<std::string>{"down:nl", "down:de"});
    }
    CHECK(manager.calls == std::vector<std::string>{"down:nl", "down:de",
                                                    "up:nl", "up:de"});
}

TEST_CASE("the transports come back even when the scope is left by a throw") {
    // This is the whole reason the restart lives in a destructor. Between the
    // stop and the restart there is a download, a verification, an unpack and
    // a file swap; any of them can throw, and an operator whose VPN stayed
    // down because of it would have no idea why.
    Manager manager;
    try {
        SingBoxTransportPause pause(manager.action(), {"nl"});
        throw std::runtime_error("install blew up");
    } catch (const std::runtime_error&) {
    }
    CHECK(manager.calls == std::vector<std::string>{"down:nl", "up:nl"});
}

TEST_CASE("a transport that would not stop is reported and none is invented") {
    // Something is still running on the binary the install would replace,
    // which is the exact situation the blocker exists to prevent. The caller
    // must be able to see it and refuse.
    Manager manager;
    manager.refuse_down.insert("de");
    SingBoxTransportPause pause(manager.action(), {"nl", "de"});

    CHECK_FALSE(pause.all_stopped());
    CHECK(pause.unstoppable() == std::vector<std::string>{"de"});
    // The one that did stop is still this pause's responsibility.
    CHECK(pause.stopped() == std::vector<std::string>{"nl"});
    pause.resume();
    CHECK(manager.calls ==
          std::vector<std::string>{"down:nl", "down:de", "up:nl"});
}

TEST_CASE("a transport that did not come back is named") {
    // Silence here would read as "everything is fine" while the operator's
    // traffic has nowhere to go.
    Manager manager;
    manager.refuse_up.insert("nl");
    SingBoxTransportPause pause(manager.action(), {"nl", "de"});
    pause.resume();

    CHECK(pause.left_down() == std::vector<std::string>{"nl"});
}

TEST_CASE("resume is idempotent so the destructor cannot start twice") {
    // The caller resumes explicitly to report what happened, and the
    // destructor still runs afterwards. Starting a transport twice would be
    // harmless; starting one the operator had stopped in between would not.
    Manager manager;
    {
        SingBoxTransportPause pause(manager.action(), {"nl"});
        pause.resume();
        CHECK(manager.calls ==
              std::vector<std::string>{"down:nl", "up:nl"});
    }
    CHECK(manager.calls == std::vector<std::string>{"down:nl", "up:nl"});
}

TEST_CASE("an untagged running transport is never claimed as stopped") {
    // The manager reported something running without a tag. It cannot be
    // addressed, so it cannot be stopped - and claiming it as stopped would
    // let an install proceed over a live transport.
    Manager manager;
    SingBoxTransportPause pause(manager.action(), {""});

    CHECK_FALSE(pause.all_stopped());
    CHECK(pause.stopped().empty());
    CHECK(manager.calls.empty());
}

TEST_CASE("nothing running means nothing is touched") {
    Manager manager;
    {
        SingBoxTransportPause pause(manager.action(), {});
        CHECK(pause.all_stopped());
    }
    CHECK(manager.calls.empty());
}

} // namespace keen_pbr3
