#include <doctest/doctest.h>

#include "runtime/conntrack_manager.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

TEST_CASE("ConntrackManager reconciles only policy changes") {
    ConntrackManager manager;
    const ConntrackPolicy enabled{true};

    CHECK(manager.reconcile(enabled));
    CHECK(manager.inspect() == enabled);
    CHECK_FALSE(manager.reconcile(enabled));
    CHECK(manager.reconcile(ConntrackPolicy{}));
    CHECK_FALSE(manager.inspect().bypass_established_or_dnat);
}

TEST_CASE("ConntrackManager deletes only the requested mark in both families") {
    std::vector<std::vector<std::string>> commands;
    ConntrackManager manager([&commands](const std::vector<std::string>& args) {
        commands.push_back(args);
        return ConntrackManager::CommandResult{0, {}};
    });

    CHECK(manager.delete_mark(0x120000, 0xFF0000) ==
          ConntrackCleanupResult::Succeeded);
    REQUIRE(commands.size() == 2);
    CHECK(commands[0] == std::vector<std::string>{
                             "conntrack", "-D", "-f", "ipv4", "--mark",
                             "1179648/16711680"});
    CHECK(commands[1] == std::vector<std::string>{
                             "conntrack", "-D", "-f", "ipv6", "--mark",
                             "1179648/16711680"});
}

TEST_CASE("ConntrackManager attempts both families when one cleanup fails") {
    std::vector<std::string> families;
    ConntrackManager manager([&families](const std::vector<std::string>& args) {
        families.push_back(args[3]);
        return ConntrackManager::CommandResult{
            args[3] == "ipv4" ? 1 : 0,
            args[3] == "ipv4" ? "Operation not permitted" : ""};
    });

    CHECK(manager.delete_mark(0x120000, 0xFF0000) ==
          ConntrackCleanupResult::Failed);
    CHECK(families == std::vector<std::string>{"ipv4", "ipv6"});
}

TEST_CASE("ConntrackManager treats an already-empty family as cleanup success") {
    ConntrackManager manager([](const std::vector<std::string>&) {
        return ConntrackManager::CommandResult{
            1,
            "conntrack v1.4.8 (conntrack-tools): "
            "0 flow entries have been deleted.\n"};
    });

    CHECK(manager.delete_mark(0x120000, 0xFF0000) ==
          ConntrackCleanupResult::Succeeded);
}

TEST_CASE("ConntrackManager does not hide other exit status one errors") {
    ConntrackManager manager([](const std::vector<std::string>&) {
        return ConntrackManager::CommandResult{1, "Operation not permitted\n"};
    });

    CHECK(manager.delete_mark(0x120000, 0xFF0000) ==
          ConntrackCleanupResult::Failed);
}

TEST_CASE("ConntrackManager reports a missing utility once without trying IPv6") {
    std::vector<std::string> families;
    ConntrackManager manager([&families](const std::vector<std::string>& args) {
        families.push_back(args[3]);
        return ConntrackManager::CommandResult{127, {}};
    });

    CHECK(manager.delete_mark(0x120000, 0xFF0000) ==
          ConntrackCleanupResult::CommandUnavailable);
    CHECK(families == std::vector<std::string>{"ipv4"});
}

TEST_CASE("ConntrackManager never deletes the unmarked conntrack population") {
    std::size_t calls = 0;
    ConntrackManager manager([&calls](const std::vector<std::string>&) {
        ++calls;
        return ConntrackManager::CommandResult{0, {}};
    });

    CHECK(manager.delete_mark(0, 0xFF0000) ==
          ConntrackCleanupResult::Failed);
    CHECK(manager.delete_mark(0x120000, 0) ==
          ConntrackCleanupResult::Failed);
    CHECK(calls == 0);
}

TEST_CASE("ConntrackManager cleans a deduplicated set and summarizes failures") {
    std::vector<std::string> marks;
    ConntrackManager manager([&marks](const std::vector<std::string>& args) {
        marks.push_back(args[5]);
        const bool fail = args[5].rfind("196608/", 0) == 0;
        return ConntrackManager::CommandResult{
            fail ? 1 : 0,
            fail ? "Operation not permitted" : ""};
    });

    const auto summary =
        manager.delete_marks({0x30000, 0x20000, 0x30000}, 0xFF0000);

    CHECK(summary.failed == 1);
    CHECK_FALSE(summary.command_unavailable);
    CHECK(marks == std::vector<std::string>{
                       "131072/16711680",
                       "131072/16711680",
                       "196608/16711680",
                       "196608/16711680"});
}

TEST_CASE("ConntrackManager stops a mark batch when the utility is unavailable") {
    std::vector<std::string> marks;
    ConntrackManager manager([&marks](const std::vector<std::string>& args) {
        marks.push_back(args[5]);
        return ConntrackManager::CommandResult{127, {}};
    });

    const auto summary =
        manager.delete_marks({0x20000, 0x30000}, 0xFF0000);

    CHECK(summary.failed == 0);
    CHECK(summary.command_unavailable);
    CHECK(marks == std::vector<std::string>{"131072/16711680"});
}

TEST_CASE("ConntrackManager preserves foreign bits while restoring and saving marks") {
    constexpr uint32_t owned = 0x00FF0000U;
    CHECK(ConntrackManager::restore_original_mark(
              0xA50000CCU, 0x00340011U, owned) == 0xA53400CCU);
    CHECK(ConntrackManager::save_selected_mark(
              0x5A0000AAU, 0x00BC00DDU, owned) == 0x5ABC00AAU);
}

TEST_CASE("ConntrackManager mark helpers are no-ops for an empty owned mask") {
    CHECK(ConntrackManager::restore_original_mark(
              0xA50000CCU, 0x00340011U, 0) == 0xA50000CCU);
    CHECK(ConntrackManager::save_selected_mark(
              0x5A0000AAU, 0x00BC00DDU, 0) == 0x5A0000AAU);
}

} // namespace keen_pbr3
