#include "../src/health/tunnel_probe_task.hpp"

#include <doctest/doctest.h>

#include <map>
#include <string>
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

    TunnelProbeTask::Io io() {
        TunnelProbeTask::Io io;
        io.read_file = [this](const std::string& path) -> std::string {
            const auto it = files.find(path);
            return it == files.end() ? std::string{} : it->second;
        };
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

}  // namespace keen_pbr3
