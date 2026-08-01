#include <doctest/doctest.h>

#include "runtime/conntrack_manager.hpp"

#include <chrono>
#include <string>
#include <thread>
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
    CHECK(summary.remaining_marks ==
          std::vector<std::uint32_t>{0x30000U});
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
    CHECK(summary.skipped == 2);
    CHECK(summary.remaining_marks ==
          std::vector<std::uint32_t>{0x20000U, 0x30000U});
    CHECK(marks == std::vector<std::string>{"131072/16711680"});
}

TEST_CASE("ConntrackManager skips IPv6 cleanup when IPv6 is disabled") {
    std::vector<std::string> families;
    ConntrackManager manager([&families](const std::vector<std::string>& args) {
        families.push_back(args[3]);
        return ConntrackManager::CommandResult{0, {}};
    });

    const auto summary = manager.delete_marks_ordered(
        {0x30000, 0x20000},
        0xFF0000,
        ConntrackCleanupOptions{
            /*ipv6_enabled=*/false,
            std::chrono::seconds{4}});

    CHECK(summary.failed == 0);
    CHECK(summary.skipped == 0);
    CHECK_FALSE(summary.budget_exhausted);
    CHECK(summary.remaining_marks.empty());
    CHECK(families == std::vector<std::string>{"ipv4", "ipv4"});
}

TEST_CASE("ConntrackManager bounds best-effort batch cleanup") {
    std::vector<std::string> marks;
    ConntrackManager manager([&marks](const std::vector<std::string>& args) {
        marks.push_back(args[5]);
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
        return ConntrackManager::CommandResult{0, {}};
    });

    const auto summary = manager.delete_marks_ordered(
        {0x10000, 0x20000, 0x30000},
        0xFF0000,
        ConntrackCleanupOptions{
            /*ipv6_enabled=*/true,
            std::chrono::milliseconds{1}});

    CHECK(summary.budget_exhausted);
    CHECK(summary.failed == 1);
    CHECK(summary.skipped == 2);
    CHECK(summary.remaining_marks ==
          std::vector<std::uint32_t>{0x20000U, 0x30000U, 0x10000U});
    CHECK(marks == std::vector<std::string>{"65536/16711680"});
}

TEST_CASE("ConntrackManager returns a retry-friendly bounded remainder") {
    std::vector<std::string> marks;
    ConntrackManager manager([&marks](const std::vector<std::string>& args) {
        marks.push_back(args[5]);
        const bool fail = args[5].rfind("131072/", 0) == 0;
        return ConntrackManager::CommandResult{
            fail ? 1 : 0,
            fail ? "Operation not permitted" : ""};
    });

    const auto first = manager.delete_marks_ordered(
        {0x20000U, 0x30000U, 0x40000U, 0x50000U},
        0xFF0000U,
        ConntrackCleanupOptions{
            /*ipv6_enabled=*/false,
            std::chrono::seconds{4},
            /*max_marks=*/2});

    CHECK(first.failed == 1);
    CHECK(first.skipped == 2);
    CHECK(first.remaining_marks ==
          std::vector<std::uint32_t>{
              0x40000U, 0x50000U, 0x20000U});
    CHECK(marks == std::vector<std::string>{
                       "131072/16711680",
                       "196608/16711680"});

    marks.clear();
    const auto second = manager.delete_marks_ordered(
        first.remaining_marks,
        0xFF0000U,
        ConntrackCleanupOptions{
            /*ipv6_enabled=*/false,
            std::chrono::seconds{4},
            /*max_marks=*/2});
    CHECK(second.failed == 0);
    CHECK(second.skipped == 1);
    CHECK(second.remaining_marks ==
          std::vector<std::uint32_t>{0x20000U});
    CHECK(marks == std::vector<std::string>{
                       "262144/16711680",
                       "327680/16711680"});
}

TEST_CASE("ConntrackManager deletes canonical deduplicated IPv4 source CIDRs") {
    std::vector<std::vector<std::string>> commands;
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });

    const auto summary = manager.delete_ipv4_source_cidrs({
        " 172.16.1.33/24 ",
        "172.16.1.0/24",
        "10.0.0.7",
    });

    CHECK(summary.failed == 0);
    CHECK(summary.skipped == 0);
    CHECK_FALSE(summary.command_unavailable);
    CHECK_FALSE(summary.budget_exhausted);
    CHECK(summary.remaining_source_cidrs.empty());
    CHECK(commands == std::vector<std::vector<std::string>>{
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "172.16.1.0/24"},
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "10.0.0.7/32"}});
}

TEST_CASE("ConntrackManager source cleanup rejects broad or non-IPv4 selectors") {
    std::vector<std::vector<std::string>> commands;
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });

    const auto summary = manager.delete_ipv4_source_cidrs({
        "0.0.0.0/0",
        "2001:db8::/64",
        "not-a-network",
        "192.0.2.4/32",
    });

    CHECK(summary.failed == 3);
    CHECK(summary.skipped == 0);
    CHECK(summary.remaining_source_cidrs ==
          std::vector<std::string>{
              "0.0.0.0/0", "2001:db8::/64", "not-a-network"});
    CHECK(commands == std::vector<std::vector<std::string>>{
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.0.2.4/32"}});
}

TEST_CASE("ConntrackManager source cleanup stops when conntrack is unavailable") {
    std::vector<std::string> selectors;
    ConntrackManager manager(
        [&selectors](const std::vector<std::string>& args) {
            selectors.push_back(args[5]);
            return ConntrackManager::CommandResult{127, {}};
        });

    const auto summary = manager.delete_ipv4_source_cidrs({
        "172.16.1.0/24",
        "10.0.0.0/8",
    });

    CHECK(summary.failed == 0);
    CHECK(summary.skipped == 2);
    CHECK(summary.command_unavailable);
    CHECK(summary.remaining_source_cidrs ==
          std::vector<std::string>{"172.16.1.0/24", "10.0.0.0/8"});
    CHECK(selectors == std::vector<std::string>{"172.16.1.0/24"});
}

TEST_CASE("ConntrackManager bounds source cleanup and returns retry order") {
    std::vector<std::string> selectors;
    ConntrackManager manager(
        [&selectors](const std::vector<std::string>& args) {
            selectors.push_back(args[5]);
            const bool fail = args[5] == "172.16.1.0/24";
            return ConntrackManager::CommandResult{
                fail ? 1 : 0,
                fail ? "Operation not permitted" : ""};
        });

    const auto summary = manager.delete_ipv4_source_cidrs(
        {"172.16.1.0/24", "10.0.0.0/8", "192.0.2.0/24"},
        ConntrackSourceCleanupOptions{
            std::chrono::seconds{4},
            /*max_source_cidrs=*/2});

    CHECK(summary.failed == 1);
    CHECK(summary.skipped == 1);
    CHECK_FALSE(summary.command_unavailable);
    CHECK_FALSE(summary.budget_exhausted);
    CHECK(summary.remaining_source_cidrs ==
          std::vector<std::string>{"192.0.2.0/24", "172.16.1.0/24"});
    CHECK(selectors ==
          std::vector<std::string>{"172.16.1.0/24", "10.0.0.0/8"});
}

TEST_CASE("ConntrackManager source cleanup honors an exhausted time budget") {
    std::size_t calls = 0;
    ConntrackManager manager(
        [&calls](const std::vector<std::string>&) {
            ++calls;
            return ConntrackManager::CommandResult{0, {}};
        });

    const auto summary = manager.delete_ipv4_source_cidrs(
        {"172.16.1.0/24", "10.0.0.0/8"},
        ConntrackSourceCleanupOptions{
            std::chrono::milliseconds{0},
            /*max_source_cidrs=*/2});

    CHECK(summary.failed == 0);
    CHECK(summary.skipped == 2);
    CHECK(summary.budget_exhausted);
    CHECK(summary.remaining_source_cidrs ==
          std::vector<std::string>{"172.16.1.0/24", "10.0.0.0/8"});
    CHECK(calls == 0);
}

TEST_CASE(
    "ConntrackManager reconnects only observed unmarked forwarded flow pairs") {
    std::vector<std::vector<std::string>> commands;
    const std::string snapshot =
        "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.44 dst=31.13.64.51 "
        "sport=50000 dport=443 src=31.13.64.51 dst=192.168.1.44 "
        "sport=443 dport=50000 mark=0 use=1\n"
        "ipv4 2 udp 17 20 src=192.168.1.44 dst=31.13.64.51 "
        "sport=50001 dport=443 src=31.13.64.51 dst=192.168.1.44 "
        "sport=443 dport=50001 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.1 dst=31.13.64.52 "
        "sport=50002 dport=443 src=31.13.64.52 dst=192.168.1.1 "
        "sport=443 dport=50002 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.45 dst=8.8.8.8 "
        "sport=50003 dport=443 src=8.8.8.8 dst=192.168.1.45 "
        "sport=443 dport=50003 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.46 dst=31.13.64.53 "
        "sport=50004 dport=443 src=31.13.64.53 dst=192.168.1.46 "
        "sport=443 dport=50004 mark=65536 use=1\n"
        "ipv4 2 tcp 6 100 ESTABLISHED src=198.51.100.20 dst=192.168.1.1 "
        "sport=50005 dport=443 src=192.168.1.1 dst=198.51.100.20 "
        "sport=443 dport=50005 mark=0 use=1\n"
        "ipv6 2 udp 17 20 src=fd00::44 dst=2001:db8:1::5 "
        "sport=50006 dport=443 src=2001:db8:1::5 dst=fd00::44 "
        "sport=443 dport=50006 mark=0 use=1\n"
        "ipv6 2 tcp 6 100 ESTABLISHED src=2001:db8:ffff::20 dst=::1 "
        "sport=50007 dport=443 src=::1 dst=2001:db8:ffff::20 "
        "sport=443 dport=50007 mark=0 use=1\n";
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto summary =
        manager.delete_unmarked_forwarded_destination_flows(
            {"31.13.64.99/18", "192.168.1.0/24", "2001:db8:1::/64",
             "::1/128"},
            {"127.0.0.1/8", "192.168.1.1/24", "::1/128"},
            0xFF0000U);

    CHECK(summary.matched == 2);
    CHECK(summary.attempted == 2);
    CHECK(summary.failed == 0);
    CHECK(summary.skipped == 0);
    CHECK(summary.remaining_flows.empty());
    CHECK(commands == std::vector<std::vector<std::string>>{
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.44", "-d", "31.13.64.51", "--mark",
                           "0/4294967295"},
                          {"conntrack", "-D", "-f", "ipv6", "-s",
                           "fd00::44", "-d", "2001:db8:1::5", "--mark",
                           "0/4294967295"}});
}

TEST_CASE(
    "ConntrackManager reconnects owned marks only for aggressive destinations") {
    std::vector<std::vector<std::string>> commands;
    std::size_t snapshot_calls = 0U;
    const std::string snapshot =
        "ipv4 2 tcp 6 100 src=192.168.1.40 dst=31.13.64.10 "
        "src=31.13.64.10 dst=192.168.1.40 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.41 dst=31.13.64.11 "
        "src=31.13.64.11 dst=192.168.1.41 mark=65536 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.42 dst=31.13.65.20 "
        "src=31.13.65.20 dst=192.168.1.42 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.43 dst=31.13.65.21 "
        "src=31.13.65.21 dst=192.168.1.43 mark=65536 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.44 dst=31.13.65.22 "
        "src=31.13.65.22 dst=192.168.1.44 mark=2768240640 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.45 dst=31.13.65.23 "
        "src=31.13.65.23 dst=192.168.1.45 mark=2768306380 use=1\n";
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot, &snapshot_calls](std::size_t) {
            ++snapshot_calls;
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto summary = manager.delete_forwarded_destination_flows(
        {"31.13.64.0/24", "31.13.65.0/24"},
        {"31.13.65.0/24"},
        {"192.168.1.1/24"},
        0x00FF0000U);

    CHECK(snapshot_calls == 1U);
    CHECK(summary.matched == 4U);
    CHECK(summary.attempted == 4U);
    CHECK(summary.failed == 0U);
    CHECK(summary.skipped == 0U);
    CHECK(commands == std::vector<std::vector<std::string>>{
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.40", "-d", "31.13.64.10", "--mark",
                           "0/4294967295"},
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.42", "-d", "31.13.65.20", "--mark",
                           "0/4294967295"},
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.43", "-d", "31.13.65.21", "--mark",
                           "65536/4294967295"},
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.45", "-d", "31.13.65.23", "--mark",
                          "2768306380/4294967295"}});
}

TEST_CASE(
    "ConntrackManager aggressive-only destinations include zero and owned marks") {
    std::vector<std::vector<std::string>> commands;
    const std::string snapshot =
        "ipv4 2 tcp 6 100 src=192.168.1.40 dst=31.13.66.10 "
        "src=31.13.66.10 dst=192.168.1.40 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.41 dst=31.13.66.11 "
        "src=31.13.66.11 dst=192.168.1.41 mark=65536 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.42 dst=31.13.66.12 "
        "src=31.13.66.12 dst=192.168.1.42 mark=2768240640 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.43 dst=31.13.66.13 "
        "src=31.13.66.13 dst=192.168.1.43 mark=2768306176 use=1\n";
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto summary = manager.delete_forwarded_destination_flows(
        {},
        {"31.13.66.0/24"},
        {"192.168.1.1/24"},
        0x00FF0000U);

    CHECK(summary.matched == 3U);
    CHECK(summary.attempted == 3U);
    CHECK(summary.failed == 0U);
    CHECK(summary.skipped == 0U);
    CHECK(commands == std::vector<std::vector<std::string>>{
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.40", "-d", "31.13.66.10", "--mark",
                           "0/4294967295"},
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.41", "-d", "31.13.66.11", "--mark",
                           "65536/4294967295"},
                          {"conntrack", "-D", "-f", "ipv4", "-s",
                           "192.168.1.43", "-d", "31.13.66.13", "--mark",
                           "2768306176/4294967295"}});
}

TEST_CASE(
    "ConntrackManager merges overlapping reconnect policies before the unique selector limit") {
    std::vector<std::vector<std::string>> commands;
    const std::string snapshot =
        "ipv4 2 udp 17 100 src=192.168.1.44 dst=31.13.64.10 "
        "src=31.13.64.10 dst=192.168.1.44 mark=65536 use=1\n";
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto summary = manager.delete_forwarded_destination_flows(
        {"31.13.64.0/24"},
        {"31.13.64.0/24"},
        {"192.168.1.1/24"},
        0x00FF0000U,
        ConntrackForwardedFlowCleanupOptions{
            true,
            std::chrono::seconds{2},
            256U,
            /*max_destination_input_cidrs=*/1U,
            2U * 1024U * 1024U,
            8192U});

    CHECK_FALSE(summary.destination_input_truncated);
    CHECK(summary.matched == 1U);
    CHECK(summary.attempted == 1U);
    REQUIRE(commands.size() == 1U);
    CHECK(commands.front().back() == "65536/4294967295");
}

TEST_CASE(
    "ConntrackManager requires explicit family original tuple and full zero mark") {
    std::vector<std::vector<std::string>> commands;
    const std::string snapshot =
        "ipv4 2 tcp 6 100 src=192.168.1.40 dst=31.13.64.40 "
        "src=31.13.64.40 dst=192.168.1.40 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.41 dst=31.13.64.41 "
        "src=31.13.64.41 dst=192.168.1.41 nmark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.42 dst=31.13.64.42 "
        "src=31.13.64.42 dst=192.168.1.42 mark=oops use=1\n"
        "ipv6 2 tcp 6 100 src=192.168.1.43 dst=31.13.64.43 "
        "src=31.13.64.43 dst=192.168.1.43 mark=0 use=1\n"
        "tcp 6 100 src=192.168.1.44 dst=31.13.64.44 "
        "src=31.13.64.44 dst=192.168.1.44 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 dst=31.13.64.46 src=192.168.1.46 "
        "src=31.13.64.46 dst=192.168.1.46 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.47/24 dst=31.13.64.47 "
        "src=31.13.64.47 dst=192.168.1.47 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.48 dst=31.13.64.48 "
        "src=31.13.64.48 dst=192.168.1.48 mark=1 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.45 dst=31.13.64.45 "
        "src=31.13.64.45 dst=192.168.1.45 mark=0x0 use=1\n";
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto summary =
        manager.delete_unmarked_forwarded_destination_flows(
            {"31.13.64.0/18"}, {"192.168.1.1/24"}, 0xFF0000U);

    CHECK(summary.matched == 1);
    CHECK(summary.attempted == 1);
    CHECK(commands.size() == 1);
    CHECK(commands.front()[5] == "192.168.1.45");
    CHECK(commands.front()[7] == "31.13.64.45");
}

TEST_CASE(
    "ConntrackManager forwarded cleanup fails closed without local authority") {
    std::size_t command_calls = 0;
    std::size_t snapshot_calls = 0;
    ConntrackManager manager(
        [&command_calls](const std::vector<std::string>&) {
            ++command_calls;
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot_calls](std::size_t) {
            ++snapshot_calls;
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{}};
        });

    const auto empty = manager.delete_unmarked_forwarded_destination_flows(
        {"31.13.64.0/18"}, {}, 0xFF0000U);
    const auto invalid = manager.delete_unmarked_forwarded_destination_flows(
        {"31.13.64.0/18"}, {"192.168.1.1/24", "not-an-address"},
        0xFF0000U);
    const auto zero_mask = manager.delete_unmarked_forwarded_destination_flows(
        {"31.13.64.0/18"}, {"192.168.1.1/24"}, 0U);

    CHECK(empty.local_address_scope_missing);
    CHECK(invalid.local_address_scope_missing);
    CHECK(zero_mask.invalid_owned_mask);
    CHECK(snapshot_calls == 0);
    CHECK(command_calls == 0);
}

TEST_CASE(
    "ConntrackManager forwarded cleanup reports unavailable and bounded snapshots") {
    const std::string snapshot =
        "ipv4 2 tcp 6 100 src=192.168.1.40 dst=31.13.64.40 "
        "src=31.13.64.40 dst=192.168.1.40 mark=0 use=1\n"
        "ipv4 2 tcp 6 100 src=192.168.1.41 dst=31.13.64.41 "
        "src=31.13.64.41 dst=192.168.1.41 mark=0 use=1\n";
    std::vector<std::vector<std::string>> commands;
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{127, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, true}};
        });

    const auto summary =
        manager.delete_unmarked_forwarded_destination_flows(
            {"31.13.64.0/18", "198.51.100.0/24"},
            {"192.168.1.1/24"},
            0xFF0000U,
            ConntrackForwardedFlowCleanupOptions{
                /*ipv6_enabled=*/true,
                std::chrono::seconds{2},
                /*max_flows=*/1,
                /*max_destination_input_cidrs=*/1,
                /*max_snapshot_bytes=*/4096,
                /*max_snapshot_lines=*/8192});

    CHECK(summary.destination_input_truncated);
    CHECK(summary.snapshot_truncated);
    CHECK(summary.command_unavailable);
    CHECK(summary.matched == 2);
    CHECK(summary.attempted == 1);
    CHECK(summary.skipped == 3);
    CHECK(summary.remaining_flows ==
          std::vector<ConntrackForwardedFlowPair>{
              {"192.168.1.40", "31.13.64.40", false}});
    CHECK(commands.size() == 1);
}

TEST_CASE(
    "ConntrackManager treats empty exact deletion as success and can disable IPv6") {
    std::vector<std::vector<std::string>> commands;
    const std::string snapshot =
        "ipv4 2 tcp 6 100 src=192.168.1.44 dst=31.13.64.51 "
        "src=31.13.64.51 dst=192.168.1.44 mark=0 use=1\n"
        "ipv6 2 udp 17 20 src=fd00::44 dst=2001:db8:1::5 "
        "src=2001:db8:1::5 dst=fd00::44 mark=0 use=1\n";
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{
                1,
                "conntrack v1.4.8 (conntrack-tools): "
                "0 flow entries have been deleted.\n"};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto summary =
        manager.delete_unmarked_forwarded_destination_flows(
            {"31.13.64.0/18", "2001:db8:1::/64"},
            {"192.168.1.1/24", "::1/128"},
            0xFF0000U,
            ConntrackForwardedFlowCleanupOptions{
                /*ipv6_enabled=*/false});

    CHECK(summary.matched == 1);
    CHECK(summary.attempted == 1);
    CHECK(summary.failed == 0);
    CHECK(summary.remaining_flows.empty());
    CHECK(commands.size() == 1);
    CHECK(commands.front()[3] == "ipv4");
}

TEST_CASE(
    "ConntrackManager forwarded cleanup fails closed when snapshot is unavailable") {
    std::size_t calls = 0;
    ConntrackManager manager(
        [&calls](const std::vector<std::string>&) {
            ++calls;
            return ConntrackManager::CommandResult{0, {}};
        },
        [](std::size_t) -> std::optional<ConntrackManager::Snapshot> {
            return std::nullopt;
        });

    const auto summary =
        manager.delete_unmarked_forwarded_destination_flows(
            {"0.0.0.0/0", "31.13.64.0/18", "bad-selector"},
            {"192.168.1.1/24"},
            0xFF0000U);

    CHECK(summary.snapshot_unavailable);
    CHECK(summary.failed == 2);
    CHECK(summary.attempted == 0);
    CHECK(calls == 0);
}

TEST_CASE(
    "ConntrackManager observes exact forwarded counters states and fastnat") {
    const std::string snapshot =
        "ipv4 2 tcp 6 431999 ESTABLISHED "
        "src=192.168.1.44 dst=31.13.66.10 sport=50000 dport=443 "
        "packets=12 bytes=900 "
        "src=31.13.66.10 dst=192.168.1.44 sport=443 dport=50000 "
        "packets=8 bytes=700 [ASSURED] [SEEN_REPLY] [FASTNAT] "
        "mark=0x10000 zone=0 use=2\n"
        "ipv6 10 udp 17 20 "
        "src=fd00::44 dst=2001:db8::5 sport=50001 dport=443 "
        "packets=4 bytes=320 [UNREPLIED] "
        "src=2001:db8::5 dst=fd00::44 sport=443 dport=50001 "
        "packets=0 bytes=0 mark=0 zone=0 use=1\n"
        // Missing accounting fields is not an exact observable record.
        "ipv4 2 tcp 6 100 ESTABLISHED "
        "src=192.168.1.45 dst=31.13.66.11 sport=50002 dport=443 "
        "src=31.13.66.11 dst=192.168.1.45 sport=443 dport=50002 "
        "mark=0 use=1\n";
    ConntrackManager manager(
        [](const std::vector<std::string>&) {
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto observation = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24", "2001:db8::/32"},
        {"192.168.1.1/24", "fe80::1/64"},
        0x00FF0000U);

    REQUIRE(observation.flows.size() == 2U);
    const auto& tcp = observation.flows[0];
    CHECK(tcp.family == ConntrackFlowFamily::Ipv4);
    CHECK(tcp.protocol == ConntrackFlowProtocol::Tcp);
    CHECK(tcp.source == "192.168.1.44");
    CHECK(tcp.destination == "31.13.66.10");
    CHECK(tcp.source_port == 50000U);
    CHECK(tcp.destination_port == 443U);
    CHECK(tcp.mark == 0x10000U);
    CHECK(tcp.original == ConntrackFlowCounters{12U, 900U});
    CHECK(tcp.reply == ConntrackFlowCounters{8U, 700U});
    REQUIRE(tcp.tcp_state.has_value());
    CHECK(*tcp.tcp_state == ConntrackTcpState::Established);
    CHECK(tcp.assured);
    CHECK(tcp.seen_reply);
    CHECK(tcp.fastnat);

    const auto& udp = observation.flows[1];
    CHECK(udp.family == ConntrackFlowFamily::Ipv6);
    CHECK(udp.protocol == ConntrackFlowProtocol::Udp);
    CHECK(udp.source == "fd00::44");
    CHECK(udp.destination == "2001:db8::5");
    CHECK(udp.source_port == 50001U);
    CHECK(udp.destination_port == 443U);
    CHECK(udp.mark == 0U);
    CHECK(udp.original == ConntrackFlowCounters{4U, 320U});
    CHECK(udp.reply == ConntrackFlowCounters{0U, 0U});
    CHECK_FALSE(udp.tcp_state.has_value());
    CHECK_FALSE(udp.assured);
    CHECK_FALSE(udp.seen_reply);
    CHECK_FALSE(udp.fastnat);
}

TEST_CASE(
    "ConntrackManager observer excludes local foreign and mixed marked flows") {
    const std::string snapshot =
        "ipv4 2 udp 17 20 src=192.168.1.40 dst=31.13.66.10 "
        "sport=50000 dport=443 packets=1 bytes=10 "
        "src=31.13.66.10 dst=192.168.1.40 sport=443 dport=50000 "
        "packets=1 bytes=20 mark=0 use=1\n"
        "ipv4 2 udp 17 20 src=192.168.1.41 dst=31.13.66.11 "
        "sport=50001 dport=443 packets=2 bytes=30 "
        "src=31.13.66.11 dst=192.168.1.41 sport=443 dport=50001 "
        "packets=2 bytes=40 mark=131072 use=1\n"
        "ipv4 2 udp 17 20 src=192.168.1.42 dst=31.13.66.12 "
        "sport=50002 dport=443 packets=3 bytes=50 "
        "src=31.13.66.12 dst=192.168.1.42 sport=443 dport=50002 "
        "packets=3 bytes=60 mark=2768240640 use=1\n"
        "ipv4 2 udp 17 20 src=192.168.1.43 dst=31.13.66.13 "
        "sport=50003 dport=443 packets=4 bytes=70 "
        "src=31.13.66.13 dst=192.168.1.43 sport=443 dport=50003 "
        "packets=4 bytes=80 mark=2768306176 use=1\n"
        "ipv4 2 udp 17 20 src=192.168.1.1 dst=31.13.66.14 "
        "sport=50004 dport=443 packets=5 bytes=90 "
        "src=31.13.66.14 dst=192.168.1.1 sport=443 dport=50004 "
        "packets=5 bytes=100 mark=0 use=1\n"
        "ipv4 2 udp 17 20 src=192.168.1.44 dst=31.13.66.15 "
        "sport=50005 dport=443 packets=6 bytes=110 "
        "src=31.13.66.15 dst=192.168.1.44 sport=443 dport=50005 "
        "packets=6 bytes=120 mark=0 use=1\n";
    ConntrackManager manager(
        [](const std::vector<std::string>&) {
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto observation = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24"},
        {"192.168.1.1/24", "31.13.66.15/32"},
        0x00FF0000U);

    REQUIRE(observation.flows.size() == 2U);
    CHECK(observation.flows[0].mark == 0U);
    CHECK(observation.flows[0].source == "192.168.1.40");
    CHECK(observation.flows[1].mark == 131072U);
    CHECK(observation.flows[1].source == "192.168.1.41");
}

TEST_CASE(
    "ConntrackManager observer guards arbitrary UDP media for selected sources") {
    std::size_t command_calls = 0U;
    std::size_t snapshot_calls = 0U;
    const std::string snapshot =
        "ipv4 2 tcp 6 431999 ESTABLISHED "
        "src=192.168.1.44 dst=31.13.66.10 sport=50000 dport=443 "
        "packets=12 bytes=900 "
        "src=31.13.66.10 dst=192.168.1.44 sport=443 dport=50000 "
        "packets=8 bytes=700 [ASSURED] [SEEN_REPLY] [FASTNAT] "
        "mark=458752 zone=0 use=2\n"
        // WhatsApp call media may use a peer address outside Meta CIDRs. It
        // must protect the selected source's signalling flow without itself
        // becoming a destination-selected deletion candidate.
        "ipv4 2 udp 17 120 "
        "src=192.168.1.44 dst=203.0.113.9 sport=51000 dport=3478 "
        "packets=45 bytes=7200 "
        "src=203.0.113.9 dst=192.168.1.44 sport=3478 dport=51000 "
        "packets=41 bytes=6800 [ASSURED] [SEEN_REPLY] "
        "mark=458752 zone=0 use=2\n";
    ConntrackManager manager(
        [&command_calls](const std::vector<std::string>&) {
            ++command_calls;
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot, &snapshot_calls](std::size_t) {
            ++snapshot_calls;
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto observation = manager.observe_forwarded_destination_flows(
        {"31.13.64.0/18"},
        {"192.168.1.1/24"},
        0x00FF0000U,
        ConntrackFlowObservationOptions{},
        {"192.168.1.44"});

    CHECK(snapshot_calls == 1U);
    CHECK(command_calls == 0U);
    CHECK(observation.invalid_media_guard_sources == 0U);
    REQUIRE(observation.flows.size() == 1U);
    CHECK(observation.flows[0].protocol == ConntrackFlowProtocol::Tcp);
    CHECK(observation.flows[0].source == "192.168.1.44");
    CHECK(observation.flows[0].destination == "31.13.66.10");
    REQUIRE(observation.source_wide_udp_flows.size() == 1U);
    const auto& media = observation.source_wide_udp_flows[0];
    CHECK(media.protocol == ConntrackFlowProtocol::Udp);
    CHECK(media.source == "192.168.1.44");
    CHECK(media.destination == "203.0.113.9");
    CHECK(media.source_port == 51000U);
    CHECK(media.destination_port == 3478U);
    CHECK(media.mark == 458752U);
    CHECK(media.original == ConntrackFlowCounters{45U, 7200U});
    CHECK(media.reply == ConntrackFlowCounters{41U, 6800U});
    CHECK(media.assured);
    CHECK(media.seen_reply);
}

TEST_CASE(
    "ConntrackManager observer rejects CIDR media guard sources before IO") {
    std::size_t command_calls = 0U;
    std::size_t snapshot_calls = 0U;
    ConntrackManager manager(
        [&command_calls](const std::vector<std::string>&) {
            ++command_calls;
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot_calls](std::size_t) {
            ++snapshot_calls;
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{}};
        });

    const auto observation = manager.observe_forwarded_destination_flows(
        {"31.13.64.0/18"},
        {"192.168.1.1/24"},
        0x00FF0000U,
        ConntrackFlowObservationOptions{},
        {"192.168.1.0/24"});

    CHECK(observation.invalid_media_guard_sources == 1U);
    CHECK(observation.flows.empty());
    CHECK(observation.source_wide_udp_flows.empty());
    CHECK(snapshot_calls == 0U);
    CHECK(command_calls == 0U);
}

TEST_CASE(
    "ConntrackManager observer rejects broad selectors and incomplete local scope") {
    std::size_t snapshot_calls = 0U;
    ConntrackManager manager(
        [](const std::vector<std::string>&) {
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot_calls](std::size_t) {
            ++snapshot_calls;
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{}};
        });

    const auto broad = manager.observe_forwarded_destination_flows(
        {"0.0.0.0/0", "::/0"}, {"192.168.1.1/24"}, 0x00FF0000U);
    CHECK(broad.invalid_destination_selectors == 2U);
    CHECK(broad.flows.empty());

    const auto empty_local = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24"}, {}, 0x00FF0000U);
    CHECK(empty_local.local_address_scope_missing);

    const auto invalid_local = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24"},
        {"192.168.1.1/24", "0.0.0.0/0"},
        0x00FF0000U);
    CHECK(invalid_local.local_address_scope_missing);
    CHECK(snapshot_calls == 0U);
}

TEST_CASE(
    "ConntrackManager observer bounds bytes lines flows and selector input") {
    const std::string first =
        "ipv4 2 udp 17 20 src=192.168.1.40 dst=31.13.66.10 "
        "sport=50000 dport=443 packets=1 bytes=10 "
        "src=31.13.66.10 dst=192.168.1.40 sport=443 dport=50000 "
        "packets=1 bytes=20 mark=0 use=1\n";
    const std::string second =
        "ipv4 2 udp 17 20 src=192.168.1.41 dst=31.13.66.11 "
        "sport=50001 dport=443 packets=2 bytes=30 "
        "src=31.13.66.11 dst=192.168.1.41 sport=443 dport=50001 "
        "packets=2 bytes=40 mark=0 use=1\n";
    const std::string snapshot = first + second;
    std::size_t requested_bytes = 0U;
    ConntrackManager manager(
        [](const std::vector<std::string>&) {
            return ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot, &requested_bytes](std::size_t max_bytes) {
            requested_bytes = max_bytes;
            return std::optional<ConntrackManager::Snapshot>{
                ConntrackManager::Snapshot{snapshot, false}};
        });

    const auto bytes = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24"}, {"192.168.1.1/24"}, 0x00FF0000U,
        ConntrackFlowObservationOptions{
            /*ipv6_enabled=*/true,
            /*max_flows=*/8U,
            /*max_destination_input_cidrs=*/8U,
            /*max_snapshot_bytes=*/first.size() + 8U,
            /*max_snapshot_lines=*/8U});
    CHECK(requested_bytes == first.size() + 8U);
    CHECK(bytes.snapshot_truncated);
    REQUIRE(bytes.flows.size() == 1U);
    CHECK(bytes.flows[0].source == "192.168.1.40");

    const auto lines = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24"}, {"192.168.1.1/24"}, 0x00FF0000U,
        ConntrackFlowObservationOptions{
            /*ipv6_enabled=*/true,
            /*max_flows=*/8U,
            /*max_destination_input_cidrs=*/8U,
            /*max_snapshot_bytes=*/snapshot.size(),
            /*max_snapshot_lines=*/1U});
    CHECK(lines.line_limit_reached);
    CHECK(lines.snapshot_truncated);
    CHECK(lines.flows.size() == 1U);

    const auto flows = manager.observe_forwarded_destination_flows(
        {"31.13.66.0/24", "198.51.100.0/24"},
        {"192.168.1.1/24"},
        0x00FF0000U,
        ConntrackFlowObservationOptions{
            /*ipv6_enabled=*/true,
            /*max_flows=*/1U,
            /*max_destination_input_cidrs=*/1U,
            /*max_snapshot_bytes=*/snapshot.size(),
            /*max_snapshot_lines=*/8U});
    CHECK(flows.destination_input_truncated);
    CHECK(flows.skipped_destination_selectors == 1U);
    CHECK(flows.flow_limit_reached);
    CHECK(flows.flows.size() == 1U);
}

TEST_CASE(
    "ConntrackManager exact deletion uses full tuple and rejects unsafe input") {
    std::vector<std::vector<std::string>> commands;
    ConntrackManager manager(
        [&commands](const std::vector<std::string>& args) {
            commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });
    ConntrackExactForwardedFlow flow;
    flow.family = ConntrackFlowFamily::Ipv4;
    flow.protocol = ConntrackFlowProtocol::Tcp;
    flow.source = "192.168.1.44";
    flow.destination = "31.13.66.10";
    flow.source_port = 50000U;
    flow.destination_port = 443U;
    flow.mark = 0x10000U;
    flow.tcp_state = ConntrackTcpState::Established;

    CHECK(manager.delete_exact_forwarded_flow(flow, 0x00FF0000U) ==
          ConntrackCleanupResult::Succeeded);
    REQUIRE(commands.size() == 1U);
    CHECK(commands[0] == std::vector<std::string>{
                             "conntrack", "-D", "-f", "ipv4", "-p", "tcp",
                             "-s", "192.168.1.44", "--sport", "50000",
                             "-d", "31.13.66.10", "--dport", "443",
                             "--mark", "65536/4294967295"});
    CHECK(std::find(commands[0].begin(), commands[0].end(), "-F") ==
          commands[0].end());

    flow.mark = 0xA5010000U;
    CHECK(manager.delete_exact_forwarded_flow(flow, 0x00FF0000U) ==
          ConntrackCleanupResult::Failed);
    flow.mark = 0x10000U;
    flow.source = "192.168.1.44/32";
    CHECK(manager.delete_exact_forwarded_flow(flow, 0x00FF0000U) ==
          ConntrackCleanupResult::Failed);
    CHECK(commands.size() == 1U);
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
