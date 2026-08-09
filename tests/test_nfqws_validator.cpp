#include "../src/util/nfqws_validator.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

bool has_issue(const std::vector<ConfigValidationIssue>& issues,
               const std::string& path,
               const std::string& message = {}) {
    return std::any_of(
        issues.begin(), issues.end(), [&](const ConfigValidationIssue& issue) {
            return issue.path.find(path) != std::string::npos &&
                   (message.empty() ||
                    issue.message.find(message) != std::string::npos);
        });
}

NfqwsPathResolver allow_paths(std::set<std::string> paths) {
    return [paths = std::move(paths)](const std::string& path)
        -> std::optional<std::string> {
        return paths.count(path) != 0 ? std::optional<std::string>(path)
                                      : std::nullopt;
    };
}

std::size_t position_of(const std::vector<std::string>& args,
                        const std::string& value) {
    const auto found = std::find(args.begin(), args.end(), value);
    return found == args.end()
               ? std::string::npos
               : static_cast<std::size_t>(found - args.begin());
}

const char* const kValid =
    "ISP_INTERFACE=\"eth3\"\n"
    "NFQWS_BASE_ARGS=\"--lua-init=@/opt/lua/base.lua\"\n"
    "NFQWS_ARGS=\"--filter-tcp=80,443 --lua-desync=fake:strategy=1\"\n"
    "NFQWS_ARGS_QUIC=\"--filter-udp=443 --lua-desync=fake:strategy=1\"\n"
    "NFQUEUE_NUM=300\n"
    "USER=nobody\n";

} // namespace

TEST_CASE("nfqws validator: candidate accepts a structurally sound Keenetic profile") {
    const auto issues = validate_nfqws_candidate(
        kValid, allow_paths({"/opt/lua/base.lua"}));
    CHECK(issues.empty());
}

TEST_CASE("nfqws validator: candidate rejects empty filters and malformed ranges") {
    const auto issues = validate_nfqws_candidate(
        "NFQWS_ARGS=\"--filter-tcp= --lua-desync=fake\"\n"
        "NFQWS_ARGS_UDP=\"--filter-udp=443,,70000,9-2 --lua-desync=fake\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS/--filter-tcp", "must not be empty"));
    CHECK(has_issue(issues, "NFQWS_ARGS_UDP/--filter-udp", "empty item"));
    CHECK(has_issue(issues, "NFQWS_ARGS_UDP/--filter-udp", "out of range"));
    CHECK(has_issue(issues, "NFQWS_ARGS_UDP/--filter-udp", "inverted"));
}

TEST_CASE("nfqws validator: IPSET and mode selectors alone are not a traffic strategy") {
    const auto issues = validate_nfqws_candidate(
        "MODE_LIST=\"--hostlist=/opt/lists/user.list\"\n"
        "NFQWS_EXTRA_ARGS=\"$MODE_LIST\"\n"
        "NFQWS_ARGS_IPSET=\"--ipset=/opt/lists/ipset.list\"\n",
        allow_paths({"/opt/lists/user.list", "/opt/lists/ipset.list"}));
    CHECK(has_issue(issues, "NFQWS_ARGS", "selectors alone"));
}

TEST_CASE("nfqws validator: filters alone are not an nfqws action") {
    auto issues = validate_nfqws_candidate(
        "NFQWS_ARGS=\"--filter-tcp=443 --payload=tls_client_hello\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS", "no supported action"));

    issues = validate_nfqws_candidate(
        "NFQWS_ARGS=\"--filter-tcp=443 --dpi-desync=fake\"\n");
    CHECK(issues.empty());
}

TEST_CASE("nfqws validator: every custom profile needs its own action") {
    const auto issues = validate_nfqws_candidate(
        "NFQWS_ARGS_CUSTOM=\"--filter-tcp=80 --dpi-desync=fake "
        "--new --filter-tcp=443\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS_CUSTOM", "profile 2"));
}

TEST_CASE("nfqws validator: only the exact approved WebRTC passthrough may omit an action") {
    const std::string prefix =
        "NFQWS_ARGS_CUSTOM=\"--filter-tcp=80 --dpi-desync=fake ";
    auto issues = validate_nfqws_candidate(
        prefix + "--new=webrtc_passthrough --filter-udp=49152-65535 "
                 "--filter-l7=stun\"\n");
    CHECK(issues.empty());

    issues = validate_nfqws_candidate(
        prefix + "--new=other --filter-udp=49152-65535 "
                 "--filter-l7=stun\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS_CUSTOM", "profile 2"));

    issues = validate_nfqws_candidate(
        prefix + "--new=webrtc_passthrough --filter-udp=49153-65535 "
                 "--filter-l7=stun\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS_CUSTOM", "exactly"));

    issues = validate_nfqws_candidate(
        prefix + "--new=webrtc_passthrough --filter-udp=49152-65535 "
                 "--filter-l7=stun --payload=stun\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS_CUSTOM", "exactly"));
}

TEST_CASE("nfqws validator: CUSTOM preserves legal named profile boundaries") {
    const std::string content =
        "NFQWS_ARGS_CUSTOM=\"--filter-tcp=80 --lua-desync=fake "
        "--new=secure --filter-tcp=443 --lua-desync=multisplit\"\n";
    const auto issues = validate_nfqws_candidate(content);
    CHECK(issues.empty());

    const auto args = build_nfqws_dry_run_args(content);
    CHECK(std::count(args.begin(), args.end(), "--new=secure") == 1);
    // The init script closes the whole CUSTOM section before the next section.
    CHECK(std::count(args.begin(), args.end(), "--new") == 1);
}

TEST_CASE("nfqws validator: empty or consecutive CUSTOM boundaries are rejected") {
    const auto issues = validate_nfqws_candidate(
        "NFQWS_ARGS_CUSTOM=\"--new --new=two --filter-tcp=443 "
        "--lua-desync=fake --new\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS_CUSTOM", "non-empty"));
    CHECK(has_issue(issues, "NFQWS_ARGS_CUSTOM", "consecutive"));
}

TEST_CASE("nfqws validator: profile and mode variables cannot inject an init boundary") {
    const auto issues = validate_nfqws_candidate(
        "MODE_LIST=\"--hostlist=/opt/user.list --new=hidden\"\n"
        "NFQWS_EXTRA_ARGS=\"$MODE_LIST\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --new=other --lua-desync=fake\"\n");
    CHECK(has_issue(issues, "MODE_LIST", "--new"));
    CHECK(has_issue(issues, "NFQWS_EXTRA_ARGS", "--new"));
    CHECK(has_issue(issues, "NFQWS_ARGS", "--new"));
}

TEST_CASE("nfqws validator: shell expansion respects single and double quotes") {
    const std::string expanded =
        "MODE_LIST=\"--hostlist=/opt/lists/user.list\"\n"
        "NFQWS_EXTRA_ARGS=\"$MODE_LIST\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    auto args = build_nfqws_dry_run_args(expanded);
    CHECK(position_of(args, "--hostlist=/opt/lists/user.list") !=
          std::string::npos);

    const std::string literal =
        "MODE_LIST=\"--hostlist=/opt/lists/user.list\"\n"
        "NFQWS_EXTRA_ARGS='$MODE_LIST'\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    args = build_nfqws_dry_run_args(literal);
    CHECK(position_of(args, "$MODE_LIST") != std::string::npos);
    CHECK(position_of(args, "--hostlist=/opt/lists/user.list") ==
          std::string::npos);
    const auto issues = validate_nfqws_candidate(literal);
    CHECK(has_issue(issues, "NFQWS_EXTRA_ARGS", "single-quoted"));
}

TEST_CASE("nfqws validator: candidate rejects unknown assignments and inherited expansions") {
    const auto issues = validate_nfqws_candidate(
        "PATH=/tmp/attacker\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=$INHERITED\"\n");
    CHECK(has_issue(issues, "PATH", "unsupported"));
    CHECK(has_issue(issues, "NFQWS_ARGS", "undefined variable"));
}

TEST_CASE("nfqws validator: unquoted hash is literal inside an assignment word") {
    const auto content =
        std::string("POLICY_NAME=foo#bar # trailing comment\n") +
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    CHECK(validate_nfqws_candidate(content).empty());
    const auto args = build_nfqws_dry_run_args(content);
    CHECK(position_of(args, "--filter-tcp=443") != std::string::npos);
}

TEST_CASE("nfqws validator: all packaged Keenetic strategies pass structural validation") {
    namespace fs = std::filesystem;
    const auto root = fs::path(__FILE__).parent_path().parent_path() /
                      "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/"
                      "nfqws-strategies";
    std::size_t checked = 0;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file() ||
            entry.path().filename() != "nfqws2.conf") {
            continue;
        }
        std::ifstream input(entry.path(), std::ios::binary);
        REQUIRE(input.good());
        const std::string content{std::istreambuf_iterator<char>(input),
                                  std::istreambuf_iterator<char>()};
        INFO(entry.path().string());
        CHECK(validate_nfqws_candidate(content).empty());
        ++checked;
    }
    CHECK(checked == 16U);
}

TEST_CASE("nfqws validator: dry-run argv mirrors Keenetic CUSTOM UDP QUIC and TCP order") {
    const std::string content =
        "USER=daemon\nNFQUEUE_NUM=411\n"
        "NFQWS_BASE_ARGS=\"--lua-init=@/opt/base.lua\"\n"
        "NFQWS_ARGS_CUSTOM=\"--filter-tcp=22 --lua-desync=fake\"\n"
        "NFQWS_ARGS_UDP=\"--filter-udp=53 --lua-desync=fake\"\n"
        "NFQWS_ARGS_QUIC=\"--filter-udp=443 --lua-desync=fake\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n"
        "NFQWS_ARGS_IPSET=\"--ipset=/opt/ipset.list\"\n"
        "NFQWS_EXTRA_ARGS=\"--hostlist=/opt/user.list\"\n";
    const auto args = build_nfqws_dry_run_args(content);
    CHECK(args[0] == "--dry-run");
    CHECK(position_of(args, "--user=daemon") <
          position_of(args, "--qnum=411"));
    CHECK(position_of(args, "--filter-tcp=22") <
          position_of(args, "--filter-udp=53"));
    CHECK(position_of(args, "--filter-udp=53") <
          position_of(args, "--filter-udp=443"));
    CHECK(position_of(args, "--filter-udp=443") <
          position_of(args, "--filter-tcp=443"));
    CHECK(std::count(args.begin(), args.end(), "--new") == 5);
    CHECK(std::count(args.begin(), args.end(), "--ipset-ip=0.0.0.0") == 2);
}

TEST_CASE("nfqws validator: dry-run rewrites a missing live blob to its packaged source") {
    const std::string content =
        "NFQWS_BASE_ARGS=\"--blob=fake:@/opt/live/fake.bin\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    const NfqwsPathResolver resolver = [](const std::string& path)
        -> std::optional<std::string> {
        if (path == "/opt/live/fake.bin") return "/opt/package/fake.bin";
        return std::nullopt;
    };
    CHECK(validate_nfqws_candidate(content, resolver).empty());
    const auto args = build_nfqws_dry_run_args(content, 300, resolver);
    CHECK(position_of(args, "--blob=fake:@/opt/package/fake.bin") !=
          std::string::npos);
    CHECK(position_of(args, "--blob=fake:@/opt/live/fake.bin") ==
          std::string::npos);
}

TEST_CASE("nfqws validator: candidate parser rejects executable shell and unterminated quotes") {
    auto issues = validate_nfqws_candidate(
        "touch /tmp/owned\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n");
    CHECK(has_issue(issues, "touch", "unsupported"));

    issues = validate_nfqws_candidate(
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\n");
    CHECK(has_issue(issues, "NFQWS_ARGS", "unterminated"));
}

TEST_CASE("nfqws validator: candidate rejects init-time wildcard expansion") {
    const auto issues = validate_nfqws_candidate(
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake *\"\n");
    CHECK(has_issue(issues, "NFQWS_ARGS", "wildcard"));
}

TEST_CASE("nfqws validator: dry-run capability cache is bound to the binary identity") {
    NfqwsDryRunCapabilityCache cache;
    NfqwsBinaryIdentity identity{1, 10, 20, 30, 40, 50, 60};
    int probes = 0;
    const auto reader = [&](const std::string&)
        -> std::optional<NfqwsBinaryIdentity> { return identity; };
    const auto probe = [&](const std::string&) -> std::optional<std::string> {
        ++probes;
        return probes == 1 ? "usage: nfqws2 --dry-run" : "usage: nfqws2";
    };

    CHECK(cache.detect("/opt/nfqws2", reader, probe) ==
          NfqwsDryRunCapability::supported);
    CHECK(cache.detect("/opt/nfqws2", reader, probe) ==
          NfqwsDryRunCapability::supported);
    CHECK(probes == 1);

    identity.ctime_nanoseconds += 1;
    CHECK(cache.detect("/opt/nfqws2", reader, probe) ==
          NfqwsDryRunCapability::unsupported);
    CHECK(probes == 2);
}

TEST_CASE("nfqws validator: dry-run capability refuses a binary that changes during both probes") {
    NfqwsDryRunCapabilityCache cache;
    std::uint64_t inode = 1;
    const auto reader = [&](const std::string&)
        -> std::optional<NfqwsBinaryIdentity> {
        return NfqwsBinaryIdentity{1, inode++, 20, 30, 40, 50, 60};
    };
    const auto probe = [](const std::string&) -> std::optional<std::string> {
        return "--dry-run";
    };
    CHECK(cache.detect("/opt/nfqws2", reader, probe) ==
          NfqwsDryRunCapability::unavailable);
}

} // namespace keen_pbr3
