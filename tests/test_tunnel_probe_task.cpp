#include "../src/health/tunnel_probe_task.hpp"

#include <doctest/doctest.h>

#include <map>
#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr const char* kListFile = "/opt/etc/keen-pbr/found.lst";
constexpr const char* kLogFile = "/opt/var/log/nfqws2.log";

// The shape nfqws2 writes, positional with " : " between fields. Copied from
// the owner's router rather than invented, because the parser is positional
// and an invented line would prove nothing about the real one.
std::string retrans_line(const std::string& host) {
    return "28.08.2026 21:07:40 : " + host +
           " : profile 10 (noname) : client 192.168.1.117:38218 : proto tls : "
           "retrans threshold reached";
}

std::string log_for(const std::string& host) {
    return retrans_line(host) + "\n" + retrans_line(host) + "\n" +
           retrans_line(host) + "\n";
}

// "https://host/" back to "host", so a test can answer per host without
// repeating the URL the task builds.
std::string host_of(const std::string& url) {
    constexpr const char* kScheme = "https://";
    auto rest = url.compare(0, 8, kScheme) == 0 ? url.substr(8) : url;
    const auto slash = rest.find('/');
    return slash == std::string::npos ? rest : rest.substr(0, slash);
}

// A world the pass runs against: files it reads, the file it writes, and
// modelled answers for every host it probes.
struct World {
    std::vector<DifferentialProbeRequest> requests;
    std::vector<std::string> ensured;
    std::map<std::string, std::string> files;
    std::map<std::string, std::string> written;
    std::map<std::string, DifferentialVerdict> verdicts;
    std::map<std::string, bool> registry;
    std::vector<std::string> probed;
    int list_changed_calls{0};
    bool write_succeeds{true};
    TunnelProbeReviewState review_state;
    std::uint64_t now{1000000U};
    int review_writes{0};
    bool review_write_succeeds{true};
    std::function<void(const std::string&)> during_probe;

    TunnelProbeTask::Io io(bool reviews = false) {
        TunnelProbeTask::Io io;
        io.read_file = [this](const std::string& path) -> std::string {
            const auto it = files.find(path);
            return it == files.end() ? std::string{} : it->second;
        };
        io.read_limited_file = [this](const std::string& path, std::size_t limit)
            -> std::optional<std::string> {
            const auto it = files.find(path);
            if (it == files.end()) return std::string{};
            if (it->second.size() > limit) return std::nullopt;
            return it->second;
        };
        if (reviews) {
            io.clock_unix_ms = [this]() { return now; };
            io.load_review = [this](const std::string&, std::string&) {
                return review_state;
            };
            io.save_review = [this](const std::string&, const TunnelProbeReviewState& state,
                                    std::string&) {
                ++review_writes;
                if (!review_write_succeeds) return false;
                review_state = state;
                return true;
            };
        }
        io.write_file = [this](const std::string& path,
                               const std::string& contents) {
            if (!write_succeeds) return false;
            written[path] = contents;
            files[path] = contents;
            return true;
        };
        io.stat_log = [this](const std::string& path,
                             std::uint64_t& size,
                             std::string& fingerprint) {
            const auto it = files.find(path);
            if (it == files.end()) return false;
            size = it->second.size();
            fingerprint = it->second.substr(
                0, std::min<std::size_t>(kLogFingerprintBytes,
                                         it->second.size()));
            return true;
        };
        io.read_log_from = [this](const std::string& path,
                                  std::uint64_t offset,
                                  std::size_t budget) -> std::string {
            const auto it = files.find(path);
            if (it == files.end() || offset >= it->second.size()) return {};
            return it->second.substr(static_cast<std::size_t>(offset), budget);
        };
        io.ensure_file = [this](const std::string& path) {
            ensured.push_back(path);
            files.emplace(path, std::string{});
        };
        io.run_probe = [this](const DifferentialProbeRequest& request) {
            // The request carries the pinning the task chose; checking it here
            // is how the tests know the direct leg really is direct.
            requests.push_back(request);
            const auto host = host_of(request.url);
            probed.push_back(host);
            if (during_probe) during_probe(host);
            DifferentialProbeReport report;
            const auto it = verdicts.find(host);
            report.verdict = it == verdicts.end()
                                 ? DifferentialVerdict::inconclusive
                                 : it->second;
            return report;
        };
        io.registry_lookup =
            [this](const std::string& host) -> std::optional<bool> {
            const auto it = registry.find(host);
            if (it == registry.end()) return std::nullopt;
            return it->second;
        };
        io.on_list_changed = [this](const TunnelProbeSetup&) {
            ++list_changed_calls;
        };
        return io;
    }

    // nfqws2's configuration, as the parser expects to find it.
    void with_nfqws_config() {
        files[kNfqwsConfigPath] =
            "ISP_INTERFACE=\"eth3\"\n"
            "NFQWS_OPT=\"--hostlist-auto-debug=/opt/var/log/nfqws2.log\"\n";
    }
};

Config enabled_config() {
    Config config;
    Outbound tunnel;
    tunnel.tag = "tr_9786265a";
    tunnel.type = OutboundType::INTERFACE;
    tunnel.interface = std::string{"kpbr9786265a"};
    config.outbounds = std::vector<Outbound>{tunnel};

    ListConfig found;
    found.file = std::string{kListFile};
    config.lists = std::map<std::string, ListConfig>{{"found_blocked", found}};

    TunnelProbeConfig probe;
    probe.enabled = true;
    probe.outbound = std::string{"tr_9786265a"};
    probe.list = std::string{"found_blocked"};
    config.tunnel_probe = probe;
    return config;
}

}  // namespace

TEST_CASE("pass: switched off does nothing at all") {
    World world;
    TunnelProbeTask task(world.io());

    const auto outcome = task.run(Config{});

    CHECK_FALSE(outcome.ran);
    CHECK(outcome.refusal == TunnelProbeRefusal::disabled);
    CHECK(world.probed.empty());
    CHECK(world.written.empty());
}

TEST_CASE("pass: stops on nfqws2's configuration rather than guessing") {
    World world;  // no files at all
    TunnelProbeTask task(world.io());

    const auto outcome = task.run(enabled_config());

    CHECK_FALSE(outcome.ran);
    CHECK(outcome.source_error == NfqwsScanSourceError::config_unreadable);
    CHECK(world.probed.empty());
}

TEST_CASE("pass: an empty log is a reason to wait, not to act") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = "";
    TunnelProbeTask task(world.io());

    const auto outcome = task.run(enabled_config());

    CHECK_FALSE(outcome.ran);
    CHECK(outcome.log_empty);
    CHECK(world.probed.empty());
}

TEST_CASE("pass: a confirmed host is written and the caller is told") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("blocked.example");
    world.verdicts["blocked.example"] = DifferentialVerdict::blocked_here;
    world.registry["blocked.example"] = true;

    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());

    CHECK(outcome.ran);
    REQUIRE(outcome.appended.size() == 1);
    CHECK(outcome.appended[0] == "blocked.example");
    CHECK(world.written.at(kListFile) == "blocked.example\n");
    CHECK(world.list_changed_calls == 1);
}

TEST_CASE("pass: each leg is pinned to the device that makes it mean something") {
    // The direct leg has to leave through the provider's own device, taken
    // from nfqws2's configuration, and the tunnel leg through the configured
    // outbound's. Pinned to the same device, or to none, the two legs would
    // measure the same path and every verdict would be worthless.
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("blocked.example");
    world.verdicts["blocked.example"] = DifferentialVerdict::blocked_here;
    world.registry["blocked.example"] = true;

    TunnelProbeTask task(world.io());
    task.run(enabled_config());

    REQUIRE(world.requests.size() == 1);
    CHECK(world.requests[0].url == "https://blocked.example/");
    CHECK(world.requests[0].direct.interface == "eth3");
    CHECK(world.requests[0].tunnel.interface == "kpbr9786265a");
}

TEST_CASE("pass: a host the registry does not name is held back") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("ads.example");
    world.verdicts["ads.example"] = DifferentialVerdict::blocked_here;
    world.registry["ads.example"] = false;

    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());

    CHECK(outcome.ran);
    CHECK(outcome.appended.empty());
    CHECK(world.written.empty());
    CHECK(world.list_changed_calls == 0);
}

TEST_CASE("pass: a host already in the list file is not probed again") {
    // The file is coverage. Without this a restart would re-probe every host
    // the automation ever routed, and each of those is two requests to a host
    // that is no longer failing.
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("old.example");
    world.files[kListFile] = "old.example\n";
    world.verdicts["old.example"] = DifferentialVerdict::blocked_here;
    world.registry["old.example"] = true;

    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());

    CHECK(world.probed.empty());
    CHECK(outcome.appended.empty());
    CHECK(world.written.empty());
}

TEST_CASE("pass: a host on the never-list is not even probed") {
    // Refusing it only at the moment of writing would still cost two requests
    // a pass, forever, to re-answer a question a person already settled.
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("banned.example");
    world.files[std::string(kListFile) + ".excluded"] = "banned.example\n";
    world.verdicts["banned.example"] = DifferentialVerdict::blocked_here;
    world.registry["banned.example"] = true;

    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());

    CHECK(world.probed.empty());
    CHECK(outcome.appended.empty());
    CHECK(world.written.empty());
}

TEST_CASE("pass: a failed write is not reported as success") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("blocked.example");
    world.verdicts["blocked.example"] = DifferentialVerdict::blocked_here;
    world.registry["blocked.example"] = true;
    world.write_succeeds = false;

    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());

    CHECK(outcome.ran);
    CHECK(outcome.write_failed);
    CHECK(outcome.appended.empty());
    // Nothing may claim the host was routed, least of all the reload hook.
    CHECK(world.list_changed_calls == 0);
}

TEST_CASE("pass: a verdict other than blocked_here moves nothing") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("dead.example");
    world.verdicts["dead.example"] = DifferentialVerdict::down_everywhere;
    world.registry["dead.example"] = true;

    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());

    CHECK(outcome.ran);
    CHECK(outcome.probed == 1);
    CHECK(outcome.appended.empty());
    CHECK(world.written.empty());
}

TEST_CASE("pass: the queue advances instead of re-probing its own head") {
    // The defect this was written for, seen on the router: every pass fed the
    // whole log back in, so hosts that had just been answered were queued
    // again by the very lines that named them. Eight probed, "120 left for the
    // next pass", pass after pass, the same eight - and nothing behind them
    // ever reached.
    World world;
    world.with_nfqws_config();
    std::string log;
    for (int i = 0; i < 6; ++i) {
        const auto host = "host" + std::to_string(i) + ".example";
        log += log_for(host);
        world.verdicts[host] = DifferentialVerdict::down_everywhere;
    }
    world.files[kLogFile] = log;

    auto config = enabled_config();
    config.tunnel_probe->max_probes_per_pass = 2;

    TunnelProbeTask task(world.io());

    const auto first = task.run(config);
    REQUIRE(first.ran);
    CHECK(first.probed == 2);
    const auto after_first = world.probed;
    REQUIRE(after_first.size() == 2);

    const auto second = task.run(config);
    REQUIRE(second.ran);
    // Nothing was appended to the log between the two passes.
    CHECK(second.new_log_lines == 0);
    CHECK(second.probed == 2);
    REQUIRE(world.probed.size() == 4);

    // The decisive part: the second pass measured different hosts.
    for (const auto& host : after_first) {
        CHECK(world.probed[2] != host);
        CHECK(world.probed[3] != host);
    }
    CHECK(second.remaining < first.remaining);
}

TEST_CASE("pass: new lines are read, old ones are not read twice") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("first.example");
    world.verdicts["first.example"] = DifferentialVerdict::down_everywhere;
    world.verdicts["second.example"] = DifferentialVerdict::down_everywhere;

    TunnelProbeTask task(world.io());
    const auto first = task.run(enabled_config());
    CHECK(first.new_log_lines == 3);

    world.files[kLogFile] += log_for("second.example");
    const auto second = task.run(enabled_config());

    // Only the three lines that were added, not the six that are there.
    CHECK(second.new_log_lines == 3);
    CHECK_FALSE(second.log_restarted);
}

TEST_CASE("pass: a rotated log is re-read from the beginning") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("before.example");
    world.verdicts["before.example"] = DifferentialVerdict::down_everywhere;
    world.verdicts["after.example"] = DifferentialVerdict::down_everywhere;

    TunnelProbeTask task(world.io());
    task.run(enabled_config());

    // nfqws2 rotated its log: same path, different content, and shorter.
    world.files[kLogFile] = log_for("after.example");
    const auto second = task.run(enabled_config());

    CHECK(second.log_restarted);
    CHECK(second.new_log_lines == 3);
}

TEST_CASE("pass: the list file is created before anything can read it") {
    // A list whose file does not exist makes list streaming throw, and that
    // throw lands inside the firewall apply - so a missing file does not
    // disable one list, it stops routing being applied at all. The automation
    // owns the file, so it creates it.
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("any.example");
    world.verdicts["any.example"] = DifferentialVerdict::down_everywhere;

    TunnelProbeTask task(world.io());
    task.run(enabled_config());

    REQUIRE(world.ensured.size() == 1);
    CHECK(world.ensured[0] == kListFile);
}

TEST_CASE("pass: switched off creates nothing at all") {
    World world;
    TunnelProbeTask task(world.io());

    task.run(Config{});

    CHECK(world.ensured.empty());
}

TEST_CASE("review pass: an owned host is checked without new or available debug logs") {
    for (int log_case = 0; log_case < 3; ++log_case) {
        World world;
        world.with_nfqws_config();
        if (log_case == 0) world.files[kLogFile] = "";
        if (log_case == 2) world.files[kNfqwsConfigPath] = "ISP_INTERFACE=\"eth3\"\n";
        world.files[kListFile] = "old.example\n";
        world.verdicts["old.example"] = DifferentialVerdict::works_without_help;
        TunnelProbeTask task(world.io(true));

        const auto outcome = task.run(enabled_config());

        CHECK(outcome.ran);
        CHECK(outcome.reviewed == 1U);
        CHECK(outcome.probed == 1U);
        REQUIRE(world.requests.size() == 1U);
        CHECK(world.requests.front().direct.interface == "eth3");
        CHECK(world.requests.front().tunnel.interface == "kpbr9786265a");
        CHECK(world.written.empty());
        CHECK(world.list_changed_calls == 0);
        CHECK(world.files[kListFile] == "old.example\n");
        REQUIRE(world.review_state.entries.size() == 1U);
        CHECK(world.review_state.entries.front().record.direct_successes == 1U);
        CHECK_FALSE(world.review_state.entries.front().eligible);
        CHECK(TunnelProbeTask::describe(outcome).find("reviewed 1") != std::string::npos);
    }
}

TEST_CASE("review pass: disabled automation does not read, write or probe review history") {
    World world;
    world.files[kListFile] = "old.example\n";
    TunnelProbeTask task(world.io(true));
    task.run(Config{});
    CHECK(world.probed.empty());
    CHECK(world.ensured.empty());
    CHECK(world.review_writes == 0);
}

TEST_CASE("review pass: idle passes neither re-probe nor rewrite history before the due time") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.verdicts["old.example"] = DifferentialVerdict::works_without_help;
    TunnelProbeTask task(world.io(true));
    task.run(enabled_config());
    REQUIRE(world.review_state.entries.size() == 1U);
    const auto due = world.review_state.entries.front().next_due_unix_ms;
    const auto writes = world.review_writes;
    world.now = due - 1U;
    const auto idle = task.run(enabled_config());
    CHECK(idle.probed == 0U);
    CHECK(world.review_writes == writes);
    world.now = due;
    const auto next = task.run(enabled_config());
    CHECK(next.reviewed == 1U);
    CHECK(world.review_state.entries.front().record.direct_successes == 2U);
    CHECK(world.list_changed_calls == 0);
}

TEST_CASE("review pass: reviews share the candidate budget without consuming its queued tail") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.files[kLogFile] = log_for("a.example") + log_for("b.example") + log_for("c.example");
    auto config = enabled_config();
    config.tunnel_probe->max_probes_per_pass = 3;
    TunnelProbeTask task(world.io(true));

    const auto first = task.run(config);
    CHECK(first.probed == 3U);
    CHECK(first.reviewed == 1U);
    CHECK(first.remaining == 1U);
    const auto second = task.run(config);
    CHECK(second.probed == 1U);
    CHECK(second.reviewed == 0U);
    CHECK(second.remaining == 0U);
    REQUIRE(world.probed.size() == 4U);
    CHECK(world.probed[3] != world.probed[1]);
    CHECK(world.probed[3] != world.probed[2]);
}

TEST_CASE("review pass: a one-probe budget alternates due reviews and queued candidates") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old-a.example\nold-b.example\nold-c.example\n";
    world.files[kLogFile] = log_for("candidate-a.example") + log_for("candidate-b.example");
    auto config = enabled_config();
    config.tunnel_probe->max_probes_per_pass = 1;
    TunnelProbeTask task(world.io(true));
    for (int pass = 0; pass < 4; ++pass) {
        const auto outcome = task.run(config);
        CHECK(outcome.probed == 1U);
        CHECK(outcome.reviewed == (pass % 2 == 0 ? 1U : 0U));
    }
    REQUIRE(world.probed.size() == 4U);
    CHECK(world.probed[1].find("candidate-") == 0U);
    CHECK(world.probed[3].find("candidate-") == 0U);
    CHECK(world.probed[1] != world.probed[3]);
}

TEST_CASE("review pass: neither failed path observations nor suggestions alter routing") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.verdicts["old.example"] = DifferentialVerdict::works_without_help;
    TunnelProbeTask task(world.io(true));
    for (int pass = 0; pass < 3; ++pass) {
        task.run(enabled_config());
        REQUIRE(world.review_state.entries.size() == 1U);
        world.now = world.review_state.entries.front().next_due_unix_ms;
    }
    CHECK(world.review_state.entries.front().eligible);
    world.verdicts["old.example"] = DifferentialVerdict::down_everywhere;
    task.run(enabled_config());
    CHECK(world.review_state.entries.front().record.direct_successes == 3U);
    CHECK(world.review_state.entries.front().last_observation == DifferentialVerdict::down_everywhere);
    CHECK(world.written.empty());
    CHECK(world.list_changed_calls == 0);
}

TEST_CASE("review pass: a live target change during the network discards the old observation") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.verdicts["old.example"] = DifferentialVerdict::works_without_help;
    auto current = resolve_tunnel_probe_setup(enabled_config()).setup;
    auto io = world.io(true);
    io.current_setup = [&]() { return current; };
    world.during_probe = [&](const std::string&) { current->interface = "different-tunnel"; };
    TunnelProbeTask task(std::move(io));
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.target_changed);
    REQUIRE(world.review_state.entries.size() == 1U);
    CHECK(world.review_state.entries.front().record.direct_successes == 0U);
    CHECK(world.review_state.entries.front().last_checked_unix_ms == 0U);
    CHECK(world.written.empty());
}

TEST_CASE("review pass: a changed provider device cannot contribute to the old context") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.verdicts["old.example"] = DifferentialVerdict::works_without_help;
    world.during_probe = [&](const std::string&) {
        world.files[kNfqwsConfigPath] = "ISP_INTERFACE=\"eth4\"\n";
    };
    TunnelProbeTask task(world.io(true));
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.target_changed);
    REQUIRE(world.review_state.entries.size() == 1U);
    CHECK(world.review_state.entries.front().record.direct_successes == 0U);
}

TEST_CASE("review pass: disabled or changed target before a queued pass creates nothing") {
    World world;
    auto io = world.io(true);
    io.current_setup = []() -> std::optional<TunnelProbeSetup> { return std::nullopt; };
    TunnelProbeTask task(std::move(io));
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.target_changed);
    CHECK(world.ensured.empty());
    CHECK(world.probed.empty());
    CHECK(world.review_writes == 0);
}

TEST_CASE("review pass: removing the current host while probing does not reactivate it") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.verdicts["old.example"] = DifferentialVerdict::works_without_help;
    world.during_probe = [&](const std::string&) { world.files[kListFile] = "# removed in panel\n"; };
    TunnelProbeTask task(world.io(true));
    task.run(enabled_config());
    REQUIRE(world.review_state.entries.size() == 1U);
    CHECK_FALSE(world.review_state.entries.front().active);
    CHECK(world.review_state.entries.front().record.direct_successes == 0U);
    CHECK(world.files[kListFile] == "# removed in panel\n");
    CHECK(world.written.empty());
}

TEST_CASE("pass: appending a candidate retains intervening list edits and removed hosts") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("new.example");
    world.files[kListFile] = "removed.example\n";
    world.verdicts["new.example"] = DifferentialVerdict::blocked_here;
    world.registry["new.example"] = true;
    world.during_probe = [&](const std::string&) {
        world.files[kListFile] = "# changed in panel\nother.example\n";
    };
    TunnelProbeTask task(world.io());
    task.run(enabled_config());
    CHECK(world.files[kListFile] == "# changed in panel\nother.example\nnew.example\n");
    CHECK(world.list_changed_calls == 1);
}

TEST_CASE("pass: an exclusion added during a candidate probe prevents its append") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("new.example");
    world.verdicts["new.example"] = DifferentialVerdict::blocked_here;
    world.registry["new.example"] = true;
    world.during_probe = [&](const std::string&) {
        world.files[std::string(kListFile) + ".excluded"] = "new.example\n";
    };
    TunnelProbeTask task(world.io());
    task.run(enabled_config());
    CHECK(world.written.empty());
    CHECK(world.list_changed_calls == 0);
}

TEST_CASE("review pass: bounded file reads cannot turn a partial list into a replacement") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = std::string(TunnelProbeTask::kListReadBudget + 1U, 'x');
    TunnelProbeTask task(world.io(true));
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.write_failed);
    CHECK(world.probed.empty());
    CHECK(world.written.empty());
    CHECK(world.review_writes == 0);
}

TEST_CASE("pass: network calls never hold the panel's short list I/O mutex") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.files[kLogFile] = log_for("new.example");
    world.during_probe = [&](const std::string&) {
        bool available = false;
        std::thread panel([&]() {
            std::unique_lock<std::mutex> edit(tunnel_probe_list_io_mutex(), std::try_to_lock);
            available = edit.owns_lock();
        });
        panel.join();
        CHECK(available);
    };
    TunnelProbeTask task(world.io(true));
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.probed == 2U);
}

TEST_CASE("pass: removing an owned host permits fresh evidence without resetting the log cursor") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "returned.example\n";
    world.files[kLogFile] = log_for("returned.example") + log_for("already-answered.example");
    TunnelProbeTask task(world.io());
    const auto first = task.run(enabled_config());
    REQUIRE(world.probed.size() == 1U);
    CHECK(world.probed.front() == "already-answered.example");
    CHECK(first.new_log_lines == 6U);

    world.files[kListFile] = "";
    world.files[kLogFile] += log_for("returned.example");
    const auto second = task.run(enabled_config());
    CHECK(second.new_log_lines == 3U);
    CHECK_FALSE(second.log_restarted);
    REQUIRE(world.probed.size() == 2U);
    CHECK(world.probed.back() == "returned.example");
}

TEST_CASE("pass: excluding a queued host drops it while retaining other evidence and the cursor") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("a.example") + log_for("b.example") + log_for("c.example");
    auto config = enabled_config();
    config.tunnel_probe->max_probes_per_pass = 1;
    TunnelProbeTask task(world.io());
    const auto first = task.run(config);
    REQUIRE(world.probed.size() == 1U);
    CHECK(world.probed.front() == "a.example");
    CHECK(first.remaining == 2U);

    world.files[std::string(kListFile) + ".excluded"] = "b.example\n";
    const auto second = task.run(config);
    CHECK(second.new_log_lines == 0U);
    CHECK_FALSE(second.log_restarted);
    CHECK(second.remaining == 0U);
    REQUIRE(world.probed.size() == 2U);
    CHECK(world.probed.back() == "c.example");
}

TEST_CASE("pass: an exclusion added during another probe skips the next network request") {
    World world;
    world.with_nfqws_config();
    world.files[kLogFile] = log_for("a.example") + log_for("sub.b.example");
    world.during_probe = [&](const std::string&) {
        world.files[std::string(kListFile) + ".excluded"] = "b.example\n";
    };
    TunnelProbeTask task(world.io());
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.probed == 1U);
    CHECK(outcome.remaining == 0U);
    REQUIRE(world.probed.size() == 1U);
    CHECK(world.probed.front() == "a.example");
}

TEST_CASE("review pass: a just-excluded due host is not probed or counted as an observation") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "sub.old.example\n";
    auto io = world.io(true);
    const auto save = io.save_review;
    io.save_review = [&](const std::string& path, const TunnelProbeReviewState& state,
                         std::string& error) {
        const auto result = save(path, state, error);
        world.files[std::string(kListFile) + ".excluded"] = "old.example\n";
        return result;
    };
    TunnelProbeTask task(std::move(io));
    const auto outcome = task.run(enabled_config());
    CHECK(outcome.probed == 0U);
    CHECK(outcome.reviewed == 0U);
    CHECK(world.probed.empty());
    REQUIRE(world.review_state.entries.size() == 1U);
    CHECK_FALSE(world.review_state.entries.front().active);
    CHECK(world.review_state.entries.front().last_checked_unix_ms == 0U);
}

TEST_CASE("review pass: initial metadata write failure leaves the budget for candidates") {
    World world;
    world.with_nfqws_config();
    world.files[kListFile] = "old.example\n";
    world.files[kLogFile] = log_for("new.example");
    world.review_write_succeeds = false;
    auto config = enabled_config();
    config.tunnel_probe->max_probes_per_pass = 1;
    TunnelProbeTask task(world.io(true));
    const auto outcome = task.run(config);
    CHECK(outcome.review_write_failed);
    CHECK(outcome.reviewed == 0U);
    CHECK(outcome.probed == 1U);
    REQUIRE(world.probed.size() == 1U);
    CHECK(world.probed.front() == "new.example");
    CHECK(world.review_writes == 1);
}

TEST_CASE("describe: every early exit says which one it was") {
    TunnelProbeTask::PassOutcome disabled;
    disabled.refusal = TunnelProbeRefusal::disabled;
    CHECK(TunnelProbeTask::describe(disabled).find("switched off") !=
          std::string::npos);

    TunnelProbeTask::PassOutcome no_log;
    no_log.source_error = NfqwsScanSourceError::no_debug_log;
    CHECK(TunnelProbeTask::describe(no_log).find("auto-hostlist") !=
          std::string::npos);

    TunnelProbeTask::PassOutcome routed;
    routed.ran = true;
    routed.probed = 3;
    routed.appended = {"a.example"};
    const auto said = TunnelProbeTask::describe(routed);
    CHECK(said.find("probed 3") != std::string::npos);
    CHECK(said.find("a.example") != std::string::npos);
}

TEST_CASE("describe: hosts the registry held back are named, not counted") {
    // These are the ones worth a person deciding about: a tunnel fixes them
    // and the registry does not name them. "2 held back" tells that person
    // nothing at all.
    TunnelProbeTask::PassOutcome held;
    held.ran = true;
    held.unconfirmed = {"one.example", "two.example"};

    const auto said = TunnelProbeTask::describe(held);

    CHECK(said.find("one.example") != std::string::npos);
    CHECK(said.find("two.example") != std::string::npos);
}

TEST_CASE("describe: a long list of held-back hosts is cut, and says so") {
    // A pass can hold back more hosts than belong in one log line.
    TunnelProbeTask::PassOutcome held;
    held.ran = true;
    for (int i = 0; i < 12; ++i) {
        held.unconfirmed.push_back("host" + std::to_string(i) + ".example");
    }

    const auto said = TunnelProbeTask::describe(held);

    CHECK(said.find("host0.example") != std::string::npos);
    CHECK(said.find("host7.example") != std::string::npos);
    CHECK(said.find("host8.example") == std::string::npos);
    CHECK(said.find("and 4 more") != std::string::npos);
}

}  // namespace keen_pbr3
