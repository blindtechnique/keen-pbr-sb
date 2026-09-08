#include "../src/util/nfqws_validator.hpp"

#ifdef WITH_API
#include "../src/api/config_validation_json.hpp"
#endif

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

TEST_CASE("nfqws config migration preserves owned Lua and operator settings byte for byte") {
    const std::string previous =
        "# Operator-selected strategy; do not replace with the package preset.\n"
        "CONFIG_VERSION=5\n"
        "ISP_INTERFACE='eth3 ppp0'\n"
        "TCP_PORTS=80,443,8443\nUDP_PORTS=443\nIPV6_ENABLED=0\n"
        "NFQUEUE_NUM=411\nUSER=daemon\nLOG_LEVEL=0\n"
        "POLICY_NAME='my-provider'\nPOLICY_EXCLUDE=1\n"
        "MODE_LIST='--hostlist=/opt/etc/nfqws2/lists/user.list'\n"
        "NFQWS_EXTRA_ARGS=\"$MODE_LIST\"\n"
        "NFQWS_BASE_ARGS='--lua-init=@/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua "
        "--writable=/var/run/keen-pbr-nfqws'\n"
        "NFQWS_ARGS=\"--filter-tcp=80,443,8443 \\\n"
        "--lua-desync=fake:strategy=1\"\n"
        "NFQWS_ARGS_QUIC='--filter-udp=443 --lua-desync=fake:strategy=2'\n";
    const std::string defaults =
        "CONFIG_VERSION=6\nISP_INTERFACE=eth0\n"
        "TCP_PORTS=443\nUDP_PORTS=443,500\nIPV6_ENABLED=1\n"
        "NFQUEUE_NUM=300\nUSER=nobody\nLOG_LEVEL=1\n"
        "POLICY_NAME=package\nPOLICY_EXCLUDE=0\nMODE_LIST=''\n"
        "NFQWS_EXTRA_ARGS=''\nNFQWS_BASE_ARGS=''\n"
        "NFQWS_ARGS='--filter-tcp=443 --dpi-desync=fake'\n"
        "NFQWS_ARGS_QUIC=''\n";
    const auto migrated = migrate_nfqws_config_preserving_settings(previous, defaults);
    REQUIRE(migrated.has_value());
    auto expected = previous;
    expected.replace(expected.find("CONFIG_VERSION=5"),
                     std::string("CONFIG_VERSION=5").size(), "CONFIG_VERSION=6");
    CHECK(*migrated == expected);
    const auto resolver = allow_paths({
        "/opt/etc/nfqws2/lists/user.list",
        "/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua",
    });
    CHECK(validate_nfqws_candidate(*migrated, resolver).empty());
    CHECK(build_nfqws_dry_run_args(*migrated, 300, resolver) ==
          build_nfqws_dry_run_args(previous, 300, resolver));
}

TEST_CASE("nfqws config migration adds resolved missing defaults without replacing existing empty values") {
    const std::string previous =
        "CONFIG_VERSION=1\nNFQUEUE_NUM=411\nMODE_ALL=''\n"
        "MODE_LIST='--hostlist=/opt/operator.list'\n";
    const std::string defaults =
        "CONFIG_VERSION='0002'\nNFQUEUE_NUM=300\nUSER=nobody\n"
        "MODE_ALL='--filter-tcp=80'\n"
        "MODE_LIST='--hostlist=/opt/package-default.list'\n"
        "NFQWS_EXTRA_ARGS=\"$MODE_LIST\"\n"
        "NFQWS_ARGS='--filter-tcp=443 --lua-desync=fake'\n";
    const auto migrated = migrate_nfqws_config_preserving_settings(previous, defaults);
    REQUIRE(migrated.has_value());
    CHECK(migrated->find("CONFIG_VERSION=2\n") != std::string::npos);
    CHECK(migrated->find("NFQUEUE_NUM=411\n") != std::string::npos);
    CHECK(migrated->find("MODE_ALL=''\n") != std::string::npos);
    CHECK(migrated->find("MODE_LIST='--hostlist=/opt/operator.list'\n") != std::string::npos);
    CHECK(migrated->find("USER='nobody'\n") != std::string::npos);
    CHECK(migrated->find("NFQWS_EXTRA_ARGS='--hostlist=/opt/package-default.list'\n") !=
          std::string::npos);
    const auto resolver = allow_paths({"/opt/package-default.list", "/opt/operator.list"});
    CHECK(validate_nfqws_candidate(*migrated, resolver).empty());
    const auto args = build_nfqws_dry_run_args(*migrated, 300, resolver);
    CHECK(position_of(args, "--qnum=411") != std::string::npos);
    CHECK(position_of(args, "--hostlist=/opt/package-default.list") != std::string::npos);
    CHECK(position_of(args, "--hostlist=/opt/operator.list") == std::string::npos);
}

TEST_CASE("nfqws config migration quotes literal dollars backticks and apostrophes without expansion") {
    const std::string previous = "CONFIG_VERSION=1\nNFQUEUE_NUM=300\n";
    const std::string backtick(1, '\x60');
    const std::string literal =
        "/opt/log/$MISSING-" + backtick + "never_run" + backtick +
        "-$(never_run)-'tail.log";
    const std::string defaults =
        "CONFIG_VERSION=2\nLOG_LEVEL=1\n"
        "LOG_DEBUG_PATH='/opt/log/$MISSING-" + backtick + "never_run" +
        backtick + "-$(never_run)-'\\''tail.log'\n"
        "POLICY_NAME='provider'\\''s-$CONFIG_VERSION-policy'\n";
    const auto migrated = migrate_nfqws_config_preserving_settings(previous, defaults);
    REQUIRE(migrated.has_value());
    const auto args = build_nfqws_dry_run_args(*migrated);
    CHECK(position_of(args, "--debug=" + literal) != std::string::npos);
    CHECK(migrated->find("POLICY_NAME='provider'\\''s-$CONFIG_VERSION-policy'\n") !=
          std::string::npos);
    // A second real parse must still see literals, not newly introduced shell code.
    const auto repeated = migrate_nfqws_config_preserving_settings(*migrated, defaults);
    REQUIRE(repeated.has_value());
    CHECK(*repeated == *migrated);
}

TEST_CASE("nfqws config migration normalizes real duplicate versions but preserves quoted lookalikes") {
    const std::string quoted_profile =
        "NFQWS_ARGS=\"--filter-tcp=443\n"
        "CONFIG_VERSION=777\n"
        "--lua-desync=fake\"\n";
    const std::string previous =
        "# CONFIG_VERSION=900 is a comment, not metadata.\n"
        "CONFIG_VERSION='001'\n" + quoted_profile +
        "CONFIG_VERSION=\"003\" # newest real assignment\n"
        "NFQUEUE_NUM=300\n";
    const std::string defaults = "CONFIG_VERSION=\"000006\"\nNFQUEUE_NUM=999\n";
    const auto migrated = migrate_nfqws_config_preserving_settings(previous, defaults);
    REQUIRE(migrated.has_value());
    CHECK(migrated->find(quoted_profile) != std::string::npos);
    CHECK(migrated->find("# CONFIG_VERSION=900 is a comment, not metadata.\n") !=
          std::string::npos);
    CHECK(migrated->find("# newest real assignment") != std::string::npos);
    CHECK(migrated->find("CONFIG_VERSION=6") != std::string::npos);
    CHECK(migrated->find("CONFIG_VERSION='001'") == std::string::npos);
    CHECK(migrated->find("CONFIG_VERSION=\"003\"") == std::string::npos);
    std::size_t count = 0;
    for (std::size_t at = 0;
         (at = migrated->find("CONFIG_VERSION=", at)) != std::string::npos;
         at += std::string("CONFIG_VERSION=").size()) {
        ++count;
    }
    CHECK(count == 3U); // One real assignment, one comment, one quoted argument.
    CHECK(build_nfqws_dry_run_args(*migrated) == build_nfqws_dry_run_args(previous));
}

TEST_CASE("nfqws config migration rejects missing malformed and overflowing versions in either input") {
    const std::vector<std::string> invalid{
        "NFQUEUE_NUM=300\n",
        "NFQWS_ARGS='CONFIG_VERSION=2'\n",
        "CONFIG_VERSION=\n",
        "CONFIG_VERSION=-1\n",
        "CONFIG_VERSION=+2\n",
        "CONFIG_VERSION=0x2\n",
        "CONFIG_VERSION=1.5\n",
        "CONFIG_VERSION=' 2 '\n",
        "CONFIG_VERSION=18446744073709551616\n",
        "CONFIG_VERSION=$UNDEFINED\n",
    };
    for (const auto& content : invalid) {
        CAPTURE(content);
        CHECK_FALSE(migrate_nfqws_config_preserving_settings(
            content, "CONFIG_VERSION=2\n").has_value());
        CHECK_FALSE(migrate_nfqws_config_preserving_settings(
            "CONFIG_VERSION=1\n", content).has_value());
    }
}

TEST_CASE("nfqws config migration refuses unsupported new variables commands and expansions") {
    const std::string backtick(1, '\x60');
    const std::vector<std::string> invalid_suffixes{
        "NEW_PACKAGE_OPTION=1\n",
        "PATH=/not-used\n",
        ". /not-used\n",
        "echo not-a-config\n",
        "USER=$(never_run)\n",
        "USER=" + backtick + "never_run" + backtick + "\n",
        "USER=\"$" "{USER:-nobody}\"\n",
        "LOG_DEBUG_PATH=\"$UNKNOWN\"\n",
        "USER=nobody;never_run\n",
        "USER= nobody\n",
        "POLICY_NAME=\"unterminated\n",
    };
    for (const auto& suffix : invalid_suffixes) {
        CAPTURE(suffix);
        CHECK_FALSE(migrate_nfqws_config_preserving_settings(
            "CONFIG_VERSION=1\n" + suffix, "CONFIG_VERSION=2\n").has_value());
        CHECK_FALSE(migrate_nfqws_config_preserving_settings(
            "CONFIG_VERSION=1\n", "CONFIG_VERSION=2\n" + suffix).has_value());
    }
}

TEST_CASE("nfqws config migration refuses changed version dependencies but preserves literal references") {
    for (const auto& dependent : {
             std::string("POLICY_NAME=\"$CONFIG_VERSION\"\n"),
             std::string("NFQUEUE_NUM=$CONFIG_VERSION\n"),
             std::string("MODE_LIST=\"v$CONFIG_VERSION\"\nPOLICY_NAME=\"$MODE_LIST\"\n"),
             std::string("POLICY_NAME=\"$CONFIG_VERSION\"\nCONFIG_VERSION=2\n"),
         }) {
        CAPTURE(dependent);
        CHECK_FALSE(migrate_nfqws_config_preserving_settings(
            "CONFIG_VERSION=1\n" + dependent, "CONFIG_VERSION=3\n").has_value());
    }
    const std::string previous =
        "CONFIG_VERSION=1\nPOLICY_NAME='literal-$CONFIG_VERSION'\n";
    const auto migrated = migrate_nfqws_config_preserving_settings(
        previous, "CONFIG_VERSION=3\n");
    REQUIRE(migrated.has_value());
    CHECK(migrated->find("POLICY_NAME='literal-$CONFIG_VERSION'\n") != std::string::npos);
}

TEST_CASE("nfqws config migration leaves its inputs unchanged and is idempotent after appending defaults") {
    const std::string previous = "CONFIG_VERSION=1\nUSER='daemon'";
    const std::string defaults = "CONFIG_VERSION=2\nUSER=nobody\nNFQUEUE_NUM=411\n";
    const auto previous_copy = previous;
    const auto defaults_copy = defaults;
    const auto migrated = migrate_nfqws_config_preserving_settings(previous, defaults);
    REQUIRE(migrated.has_value());
    CHECK(previous == previous_copy);
    CHECK(defaults == defaults_copy);
    CHECK(migrated->find("USER='daemon'\n") != std::string::npos);
    CHECK(migrated->find("NFQUEUE_NUM='411'\n") != std::string::npos);
    const auto repeated = migrate_nfqws_config_preserving_settings(*migrated, defaults);
    REQUIRE(repeated.has_value());
    CHECK(*repeated == *migrated);
    CHECK(migrate_nfqws_config_preserving_settings(previous, defaults) == migrated);
}

TEST_CASE("nfqws config identity ignores only genuine independent version metadata") {
    const std::string profile =
        "# CONFIG_VERSION=700 must remain visible in the identity.\n"
        "NFQWS_ARGS='--filter-tcp=443\nCONFIG_VERSION=800\n--lua-desync=fake'\n";
    const auto first = nfqws_config_without_version_metadata("CONFIG_VERSION=1\n" + profile);
    const auto second = nfqws_config_without_version_metadata("CONFIG_VERSION='002'\n" + profile);
    CHECK(first == second);
    CHECK(first.find(profile) != std::string::npos);
    CHECK(first.find("CONFIG_VERSION=1") == std::string::npos);
    CHECK(nfqws_config_without_version_metadata(first) == first);
    for (const auto& input : {
             std::string("CONFIG_VERSION=1\nNEW_OPTION=1\n"),
             std::string("CONFIG_VERSION=1\nPOLICY_NAME=\"$CONFIG_VERSION\"\n"),
             std::string("CONFIG_VERSION=1\nUSER=$(never_run)\n"),
         }) {
        CAPTURE(input);
        CHECK(nfqws_config_without_version_metadata(input) == input);
    }
}

TEST_CASE("nfqws PPE contract canonicalizes validated TCP and admits only QUIC UDP 443") {
    const auto contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=443,81,80\n"
        "UDP_PORTS=443,49152:65535\n"
        "NFQWS_ARGS=\"--filter-tcp=443,80-81 --lua-desync=fake\"\n"
        "NFQWS_ARGS_QUIC=\"--filter-udp=443 --filter-l7=quic "
        "--lua-desync=fake\"\n"
        "NFQWS_ARGS_UDP=\"--filter-udp=49152-65535 --filter-l7=stun "
        "--lua-desync=fake\"\n"
        "NFQUEUE_NUM=411\n");

    REQUIRE(contract.available);
    CHECK(contract.reason.empty());
    CHECK(contract.queue_number == 411);
    CHECK(contract.tcp_ranges ==
          std::vector<NfqwsPpePortRange>{{80, 81}, {443, 443}});
    REQUIRE(contract.tcp_chunks.size() == 1U);
    CHECK(contract.tcp_chunks.front() == contract.tcp_ranges);
    CHECK(contract.quic_udp_443);
}

TEST_CASE("nfqws PPE contract fails closed for empty malformed and mismatched candidates") {
    auto contract = extract_nfqws_ppe_port_contract("");
    CHECK_FALSE(contract.available);
    CHECK_FALSE(contract.reason.empty());

    contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=443\n"
        "NFQWS_ARGS=\"--filter-tcp=bad --lua-desync=fake\"\n"
        "NFQUEUE_NUM=300\n");
    CHECK_FALSE(contract.available);
    CHECK(contract.reason.find("validation failed") != std::string::npos);

    contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=80,443\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n"
        "NFQUEUE_NUM=300\n");
    CHECK_FALSE(contract.available);
    CHECK(contract.reason.find("exactly match") != std::string::npos);

    contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=443\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n");
    CHECK_FALSE(contract.available);
    CHECK(contract.reason.find("NFQUEUE_NUM is missing") != std::string::npos);
}

TEST_CASE("nfqws PPE contract never promotes general UDP or WebRTC to QUIC") {
    const auto contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=443\n"
        "UDP_PORTS=443,49152:65535\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n"
        "NFQWS_ARGS_UDP=\"--filter-udp=443,49152-65535 --filter-l7=stun "
        "--lua-desync=fake\"\n"
        "NFQWS_ARGS_CUSTOM=\"--filter-tcp=443 --lua-desync=fake "
        "--new=webrtc_passthrough --filter-udp=49152-65535 "
        "--filter-l7=stun\"\n"
        "NFQUEUE_NUM=300\n");
    REQUIRE(contract.available);
    CHECK_FALSE(contract.quic_udp_443);

    const auto widened_quic = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=443\n"
        "UDP_PORTS=443,49152:65535\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n"
        "NFQWS_ARGS_QUIC=\"--filter-udp=443,49152-65535 "
        "--filter-l7=quic --lua-desync=fake\"\n"
        "NFQUEUE_NUM=300\n");
    CHECK_FALSE(widened_quic.available);
    CHECK(widened_quic.reason.find("exact UDP/443") != std::string::npos);
}

TEST_CASE("nfqws PPE contract chunks multiport entries and bounds graph complexity") {
    std::string sixteen;
    for (int port = 1; port <= 31; port += 2) {
        if (!sixteen.empty()) sixteen += ',';
        sixteen += std::to_string(port);
    }
    auto contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=" + sixteen + "\nNFQWS_ARGS=\"--filter-tcp=" +
        sixteen + " --lua-desync=fake\"\nNFQUEUE_NUM=300\n");
    REQUIRE(contract.available);
    REQUIRE(contract.tcp_chunks.size() == 2U);
    CHECK(contract.tcp_chunks.front().size() ==
          kNfqwsPpeMultiportSlotsPerChunk);
    CHECK(contract.tcp_chunks.back().size() == 1U);

    std::string over_limit;
    const auto entries = kNfqwsPpeMultiportSlotsPerChunk *
                             kNfqwsPpeMaxTcpChunks +
                         1U;
    for (std::size_t index = 0; index < entries; ++index) {
        if (!over_limit.empty()) over_limit += ',';
        over_limit += std::to_string(index * 2U + 1U);
    }
    contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=" + over_limit + "\nNFQWS_ARGS=\"--filter-tcp=" +
        over_limit + " --lua-desync=fake\"\nNFQUEUE_NUM=300\n");
    CHECK_FALSE(contract.available);
    CHECK(contract.reason.find("chunk limit") != std::string::npos);

    contract = extract_nfqws_ppe_port_contract(
        "TCP_PORTS=1:2,4:5,7:8,10:11,13:14,16:17,19:20,22,24:25\n"
        "NFQWS_ARGS=\"--filter-tcp=1-2,4-5,7-8,10-11,13-14,16-17,19-20,22,24-25 "
        "--lua-desync=fake\"\nNFQUEUE_NUM=300\n");
    REQUIRE(contract.available);
    REQUIRE(contract.tcp_chunks.size() == 2U);
    CHECK(contract.tcp_chunks.front().size() == 8U); // 7 ranges + 1 port = 15 slots
    CHECK(contract.tcp_chunks.back().size() == 1U);
}

TEST_CASE("nfqws PPE contract is available for every managed generated profile") {
    namespace fs = std::filesystem;
    const auto root = fs::path(__FILE__).parent_path().parent_path() /
                      "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/"
                      "nfqws-strategies";
    for (const auto* profile : {"01 safe", "02 balanced", "03 max"}) {
        std::ifstream input(root / profile / "nfqws2.conf", std::ios::binary);
        REQUIRE(input.good());
        const std::string content{std::istreambuf_iterator<char>(input),
                                  std::istreambuf_iterator<char>()};
        const auto contract = extract_nfqws_ppe_port_contract(content);
        INFO(profile);
        INFO(contract.reason);
        REQUIRE(contract.available);
        CHECK(contract.queue_number == 300);
        CHECK(contract.tcp_ranges.size() == 9U);
        CHECK(contract.quic_udp_443);
    }
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

TEST_CASE("nfqws validator: logical Lua paths accept only a compressed Lua sibling") {
    const std::string content =
        "NFQWS_BASE_ARGS=\"--lua-init=@/opt/lua/base.lua\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    const auto compressed_lua = allow_paths({"/opt/lua/base.lua.gz"});

    CHECK(validate_nfqws_candidate(content, compressed_lua).empty());
    const auto args = build_nfqws_dry_run_args(content, 300, compressed_lua);
    CHECK(position_of(args, "--lua-init=@/opt/lua/base.lua") !=
          std::string::npos);
    CHECK(position_of(args, "--lua-init=@/opt/lua/base.lua.gz") ==
          std::string::npos);

    const std::string exact_only =
        "NFQWS_BASE_ARGS=\"--blob=fake:@/opt/blobs/fake.lua\"\n"
        "MODE_LIST=\"--hostlist=/opt/lists/user.lua\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    const auto misleading_gzip = allow_paths(
        {"/opt/blobs/fake.lua.gz", "/opt/lists/user.lua.gz"});
    const auto issues =
        validate_nfqws_candidate(exact_only, misleading_gzip);
    CHECK(has_issue(issues, "NFQWS_BASE_ARGS/--blob", "does not exist"));
    CHECK(has_issue(issues, "MODE_LIST/--hostlist", "does not exist"));
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

TEST_CASE("nfqws validator: writable is restricted before engine validation") {
    const auto candidate = [](const std::string& writable) {
        return "NFQWS_BASE_ARGS=\"" + writable + "\"\n"
               "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n";
    };

    const auto owned = candidate("--writable=/var/run/keen-pbr-nfqws");
    CHECK(validate_nfqws_candidate(owned).empty());
    const auto dry_run_args = build_nfqws_dry_run_args(owned);
    CHECK(position_of(dry_run_args,
                      "--writable=/var/run/keen-pbr-nfqws") ==
          std::string::npos);

    for (const auto& unsafe : {
             std::string("--writable=/tmp/attacker"),
             std::string("--writable"),
             std::string("--writable=/var/run/keen-pbr-nfqws/../victim"),
         }) {
        const auto issues = validate_nfqws_candidate(candidate(unsafe));
        INFO(unsafe);
        CHECK(has_issue(issues, "NFQWS_BASE_ARGS/--writable", "only"));
    }

    const auto duplicate = validate_nfqws_candidate(candidate(
        "--writable=/var/run/keen-pbr-nfqws "
        "--writable=/var/run/keen-pbr-nfqws"));
    CHECK(has_issue(duplicate, "NFQWS_BASE_ARGS/--writable", "only once"));

    const auto wrong_variable = validate_nfqws_candidate(
        "NFQWS_ARGS=\"--writable=/var/run/keen-pbr-nfqws "
        "--filter-tcp=443 --lua-desync=fake\"\n");
    CHECK(has_issue(wrong_variable, "NFQWS_ARGS/--writable", "only"));
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

TEST_CASE("nfqws validation codes cover every emitted cause with unchanged paths and messages") {
    struct Case {
        const char* suffix;
        const char* path;
        const char* message;
        const char* code;
    };
    const Case cases[] = {
        {"POLICY_NAME=\"$(id)\"\n", "POLICY_NAME", "command substitution is not allowed in an nfqws candidate", "nfqws.shell.command_substitution"},
        {"POLICY_NAME=\"${USER:-nobody}\"\n", "POLICY_NAME", "only simple ${NAME} expansion is allowed in an nfqws candidate", "nfqws.shell.expansion_syntax"},
        {"POLICY_NAME=\"$UNDEFINED\"\n", "POLICY_NAME", "undefined variable $UNDEFINED must not depend on the service environment", "nfqws.shell.undefined_variable"},
        {"1NAME=value\n", "nfqws2.conf", "only shell variable assignments and comments are allowed", "nfqws.shell.assignments_only"},
        {"PATH=/not-used\n", "PATH", "unsupported assignment in nfqws2.conf", "nfqws.shell.unsupported_assignment"},
        {"POLICY_NAME value\n", "POLICY_NAME", "only NAME=value assignments are allowed", "nfqws.shell.assignment_syntax"},
        {"POLICY_NAME= value\n", "POLICY_NAME", "whitespace after '=' would execute a shell command instead of assigning the value", "nfqws.shell.whitespace_after_equals"},
        {"POLICY_NAME=value extra\n", "POLICY_NAME", "unquoted whitespace would execute a shell command", "nfqws.shell.unquoted_whitespace"},
        {"POLICY_NAME=value;\n", "POLICY_NAME", "shell commands and control operators are not allowed in an nfqws candidate", "nfqws.shell.control_operator"},
        {"POLICY_NAME=\"unterminated", "POLICY_NAME", "unterminated quoted assignment", "nfqws.shell.unterminated_quote"},
        {"NFQWS_ARGS=\"--filter-tcp=-1 --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "empty port", "nfqws.port.empty"},
        {"NFQWS_ARGS=\"--filter-tcp=word --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "port 'word' is not a number", "nfqws.port.number"},
        {"NFQWS_ARGS=\"--filter-tcp=65536 --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "port 65536 is out of range 1-65535", "nfqws.port.range"},
        {"NFQWS_ARGS=\"--filter-tcp= --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "port filter must not be empty", "nfqws.port.filter_empty"},
        {"NFQWS_ARGS=\"--filter-tcp=1,,2 --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "port filter contains an empty item", "nfqws.port.empty_item"},
        {"NFQWS_ARGS=\"--filter-tcp=1-2-3 --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "port range '1-2-3' is malformed", "nfqws.port.range_malformed"},
        {"NFQWS_ARGS=\"--filter-tcp=2-1 --lua-desync=fake\"\n", "NFQWS_ARGS/--filter-tcp", "port range 2-1 is inverted (low > high)", "nfqws.port.range_inverted"},
        {"NFQWS_BASE_ARGS=\"--writable=/tmp/not-owned\"\n", "NFQWS_BASE_ARGS/--writable", "only the package-owned nfqws rotator writable directory is allowed", "nfqws.writable.owned_only"},
        {"NFQWS_EXTRA_ARGS='$USER'\n", "NFQWS_EXTRA_ARGS", "literal shell variable reference would reach nfqws2; single-quoted values are not expanded", "nfqws.shell.literal_variable"},
        {"NFQWS_EXTRA_ARGS='*'\n", "NFQWS_EXTRA_ARGS", "shell wildcard is not allowed because the init script would expand it differently from the dry run", "nfqws.shell.wildcard"},
        {"NFQWS_EXTRA_ARGS=\"--hostlist=\"\n", "NFQWS_EXTRA_ARGS/--hostlist", "empty file path", "nfqws.path.empty"},
        {"NFQWS_EXTRA_ARGS=\"--hostlist=/missing/list\"\n", "NFQWS_EXTRA_ARGS/--hostlist", "referenced file does not exist: /missing/list", "nfqws.path.missing"},
        {"NFQWS_ARGS=\"--filter-tcp=443 --new --lua-desync=fake\"\n", "NFQWS_ARGS", "--new is not allowed here; use NFQWS_ARGS_CUSTOM for additional profiles", "nfqws.profile.new_forbidden"},
        {"NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws --writable=/var/run/keen-pbr-nfqws\"\n", "NFQWS_BASE_ARGS/--writable", "the package-owned writable directory may be declared only once", "nfqws.writable.duplicate"},
        {"NFQWS_ARGS_CUSTOM=\"--new --filter-tcp=443 --lua-desync=fake\"\n", "NFQWS_ARGS_CUSTOM", "--new must separate two non-empty custom profiles", "nfqws.profile.empty_boundary"},
        {"NFQWS_ARGS_CUSTOM=\"--filter-tcp=80 --lua-desync=fake --new= --filter-tcp=443 --lua-desync=fake\"\n", "NFQWS_ARGS_CUSTOM", "a named --new boundary must have a name", "nfqws.profile.boundary_name_required"},
        {"NFQWS_ARGS_CUSTOM=\"--filter-tcp=80 --lua-desync=fake --new --new=two --filter-tcp=443 --lua-desync=fake\"\n", "NFQWS_ARGS_CUSTOM", "consecutive --new tokens create an empty custom profile", "nfqws.profile.consecutive_boundaries"},
        {"NFQWS_ARGS=\"--filter-tcp=443\"\n", "NFQWS_ARGS", "profile has no supported action (--lua-desync= or --dpi-desync=); filters and selectors alone do not process traffic", "nfqws.profile.action_required"},
        {"NFQWS_ARGS_CUSTOM=\"--filter-tcp=80 --lua-desync=fake --new=webrtc_passthrough --filter-udp=49153-65535 --filter-l7=stun\"\n", "NFQWS_ARGS_CUSTOM", "webrtc_passthrough must contain exactly --filter-udp=49152-65535 and --filter-l7=stun", "nfqws.profile.webrtc_passthrough"},
        {"NFQWS_ARGS_CUSTOM=\"--filter-tcp=443\"\n", "NFQWS_ARGS_CUSTOM", "custom profile 1 has no supported action (--lua-desync= or --dpi-desync=)", "nfqws.profile.custom_action_required"},
        {"NFQWS_ARGS=\"\"\nNFQWS_ARGS_QUIC=\"\"\n", "NFQWS_ARGS", "the candidate has no strategy profile; IPSET and mode selectors alone do not process traffic", "nfqws.profile.required"},
        {"NFQUEUE_NUM=65536\n", "NFQUEUE_NUM", "queue number must be an integer from 0 to 65535", "nfqws.queue.range"},
        {"USER='bad/name'\n", "USER", "nfqws user name contains unsafe characters", "nfqws.user.unsafe"},
    };
    std::set<std::string> covered_codes;
    for (const auto& item : cases) {
        CAPTURE(item.code);
        const auto issues = validate_nfqws_candidate(std::string(kValid) + item.suffix,
                                                     allow_paths({"/opt/lua/base.lua"}));
        REQUIRE(issues.size() == 1U);
        CHECK(issues[0].path == item.path);
        CHECK(issues[0].message == item.message);
        CHECK(issues[0].code == item.code);
        CHECK(issues[0].params.empty());
        CHECK(covered_codes.insert(issues[0].code).second);
    }
    CHECK(covered_codes.size() == 33U);
}

TEST_CASE("nfqws validation codes preserve issue order and PPE legacy failure diagnostics") {
    const std::string content =
        "PATH=/not-used\n"
        "NFQWS_BASE_ARGS='--writable=/tmp/not-owned'\n"
        "NFQWS_ARGS='--filter-tcp=,word,70000,2-1 --lua-desync=fake'\n"
        "NFQUEUE_NUM=65536\nUSER='bad/name'\n";
    const std::vector<ConfigValidationIssue> expected{
        {"PATH", "unsupported assignment in nfqws2.conf", "nfqws.shell.unsupported_assignment", {}},
        {"NFQWS_BASE_ARGS/--writable", "only the package-owned nfqws rotator writable directory is allowed", "nfqws.writable.owned_only", {}},
        {"NFQWS_ARGS/--filter-tcp", "port filter contains an empty item", "nfqws.port.empty_item", {}},
        {"NFQWS_ARGS/--filter-tcp", "port 'word' is not a number", "nfqws.port.number", {}},
        {"NFQWS_ARGS/--filter-tcp", "port 70000 is out of range 1-65535", "nfqws.port.range", {}},
        {"NFQWS_ARGS/--filter-tcp", "port range 2-1 is inverted (low > high)", "nfqws.port.range_inverted", {}},
        {"NFQUEUE_NUM", "queue number must be an integer from 0 to 65535", "nfqws.queue.range", {}},
        {"USER", "nfqws user name contains unsafe characters", "nfqws.user.unsafe", {}},
    };
    const auto issues = validate_nfqws_candidate(content);
    REQUIRE(issues.size() == expected.size());
    for (std::size_t index = 0; index < issues.size(); ++index) {
        CHECK(issues[index].path == expected[index].path);
        CHECK(issues[index].message == expected[index].message);
        CHECK(issues[index].code == expected[index].code);
        CHECK(issues[index].params.empty());
    }
    const auto ppe = extract_nfqws_ppe_port_contract(content);
    CHECK_FALSE(ppe.available);
    CHECK(ppe.reason == "candidate validation failed at PATH: unsupported assignment in nfqws2.conf");
    CHECK(ppe.queue_number == 300);
    const auto backticks = validate_nfqws_candidate(std::string(kValid) + "POLICY_NAME=\"`id`\"\n");
    REQUIRE(backticks.size() == 2U);
    for (const auto& issue : backticks) {
        CHECK(issue.path == "POLICY_NAME");
        CHECK(issue.message == "command substitution is not allowed in an nfqws candidate");
        CHECK(issue.code == "nfqws.shell.command_substitution");
    }
}

TEST_CASE("nfqws validation metadata leaves accepted expansions argv and PPE derivation unchanged") {
    const std::string content =
        "# accepted shell assignments only\n"
        "USER=daemon\nNFQUEUE_NUM=0\nLOG_LEVEL=1\n"
        "ISP_INTERFACE='eth0 eth1'\nIPV6_ENABLED=1\nTCP_PORTS=1:65535\n"
        "POLICY_NAME=foo#bar # a comment\n"
        "MODE_LIST=\"--hostlist=/opt/list\"\n"
        "NFQWS_EXTRA_ARGS=\"${MODE_LIST}\"\n"
        "NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws\"\n"
        "NFQWS_ARGS=\"--filter-tcp=1-65535 \\\n--lua-desync=fake\"\n";
    const auto resolver = allow_paths({"/opt/list"});
    CHECK(validate_nfqws_candidate(content, resolver).empty());
    const std::vector<std::string> expected{
        "--dry-run", "--debug=syslog", "--user=daemon", "--qnum=0",
        "--bind-fix4", "--bind-fix6", "--filter-tcp=1-65535", "--lua-desync=fake", "--hostlist=/opt/list"};
    CHECK(build_nfqws_dry_run_args(content, 300, resolver) == expected);
    const auto ppe = extract_nfqws_ppe_port_contract(content, resolver);
    REQUIRE(ppe.available);
    CHECK(ppe.queue_number == 0);
    CHECK(ppe.reason.empty());
    CHECK(ppe.tcp_ranges == std::vector<NfqwsPpePortRange>{{1, 65535}});
    CHECK_FALSE(ppe.quic_udp_443);
    for (const char* queue : {"0", "65535", ""}) {
        CHECK(validate_nfqws_candidate(std::string(kValid) + "NFQUEUE_NUM=" + queue + "\n").empty());
    }
}

#ifdef WITH_API
TEST_CASE("nfqws validation source codes survive the existing JSON and generated DTO wire path") {
    const auto issues = validate_nfqws_candidate(
        "NFQWS_ARGS='--filter-tcp=word --lua-desync=fake'\nNFQUEUE_NUM=65536\n");
    REQUIRE(issues.size() == 2U);
    const auto encoded = serialize_config_validation_issues(issues);
    const auto wire = nlohmann::json::parse(encoded.dump());
    REQUIRE(wire.size() == issues.size());
    for (std::size_t index = 0; index < issues.size(); ++index) {
        const auto dto = wire.at(index).get<api::ValidationErrorElement>();
        CHECK(dto.path == issues[index].path);
        CHECK(dto.message == issues[index].message);
        CHECK(dto.code == issues[index].code);
        CHECK_FALSE(dto.params.has_value());
        CHECK_FALSE(wire.at(index).contains("params"));
        const auto roundtrip = nlohmann::json(dto).get<api::ValidationErrorElement>();
        CHECK(roundtrip.path == dto.path);
        CHECK(roundtrip.message == dto.message);
        CHECK(roundtrip.code == dto.code);
    }
    CHECK(wire.at(0).at("message") == "port 'word' is not a number");
    CHECK(wire.at(0).at("code") == "nfqws.port.number");
    CHECK(wire.at(1).at("code") == "nfqws.queue.range");
}
#endif

} // namespace keen_pbr3
