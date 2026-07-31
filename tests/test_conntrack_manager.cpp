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
