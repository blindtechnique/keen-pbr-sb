#include <doctest/doctest.h>

#include "../src/nfqws/list_match.hpp"
#include "../src/util/nfqws_validator.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>

namespace keen_pbr3::nfqws {

TEST_CASE("nfqws hostlist parsing drops what nfqws itself ignores") {
    const auto entries = parse_hostlist(
        "#vpn\n"
        "techcorner.ignorelist.com\n"
        "\n"
        "   \n"
        "  sddvpn.mooo.com  \n"
        "windows.crlf.example\r\n"
        "# trailing comment\n");

    CHECK(
        entries ==
        std::vector<std::string>{
            "techcorner.ignorelist.com",
            "sddvpn.mooo.com",
            "windows.crlf.example",
        });
}

TEST_CASE("a commented entry covers nothing") {
    // Reporting a commented-out line as coverage would tell the operator that
    // nfqws is handling a domain it is not touching at all.
    const auto entries = parse_hostlist("#youtube.com\n");
    CHECK_FALSE(match_hostlist(entries, "youtube.com").has_value());
}

TEST_CASE("nfqws hostlist covers a domain and its subdomains") {
    const auto entries = parse_hostlist("youtube.com\ndiscord.gg\n");

    const auto exact = match_hostlist(entries, "youtube.com");
    REQUIRE(exact.has_value());
    CHECK(exact->entry == "youtube.com");
    CHECK(exact->exact);

    const auto sub = match_hostlist(entries, "www.youtube.com");
    REQUIRE(sub.has_value());
    CHECK(sub->entry == "youtube.com");
    CHECK_FALSE(sub->exact);

    const auto deep = match_hostlist(entries, "rr1---sn-x.googlevideo.youtube.com");
    REQUIRE(deep.has_value());
    CHECK(deep->entry == "youtube.com");
}

TEST_CASE("the boundary is a dot, not a substring") {
    const auto entries = parse_hostlist("youtube.com\n");
    // A plain suffix test would name youtube.com as the reason this domain is
    // handled, and it is not.
    CHECK_FALSE(match_hostlist(entries, "notyoutube.com").has_value());
    CHECK_FALSE(match_hostlist(entries, "youtube.com.evil.example").has_value());
    CHECK_FALSE(match_hostlist(entries, "outube.com").has_value());
}

TEST_CASE("the most specific covering entry is the one reported") {
    // Both cover the domain; the operator edits the specific one.
    const auto entries = parse_hostlist("com\nyoutube.com\nwww.youtube.com\n");

    const auto sub = match_hostlist(entries, "m.www.youtube.com");
    REQUIRE(sub.has_value());
    CHECK(sub->entry == "www.youtube.com");

    const auto exact = match_hostlist(entries, "youtube.com");
    REQUIRE(exact.has_value());
    CHECK(exact->entry == "youtube.com");
    CHECK(exact->exact);
}

TEST_CASE("matching ignores case and surrounding space on both sides") {
    const auto entries = parse_hostlist("  YouTube.COM  \n");
    const auto match = match_hostlist(entries, " WWW.YouTube.com ");
    REQUIRE(match.has_value());
    // The entry is reported as written, so the operator can find it in the file.
    CHECK(match->entry == "YouTube.COM");
}

TEST_CASE("list roles come from the flag, not from the file name") {
    // Taken from a live nfqws2.conf: the roles are what the flags say, and a
    // custom list named anything at all is classified the same way.
    const auto refs = parse_list_references(
        std::vector<std::string>{
            "--hostlist=/opt/etc/nfqws2/lists/user.list",
            "--hostlist-auto=/opt/etc/nfqws2/lists/auto.list",
            "--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list",
            "--ipset=/opt/etc/nfqws2/lists/ipset.list",
            "--ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list",
            "--hostlist=/opt/etc/nfqws2/lists/my-own.list"});

    REQUIRE(refs.size() == 6);
    const auto role_of = [&](const std::string& path) {
        for (const auto& ref : refs) {
            if (ref.path == path) return ref.role;
        }
        FAIL("no reference for ", path);
        return ListRole::hostlist;
    };
    CHECK(role_of("/opt/etc/nfqws2/lists/user.list") == ListRole::hostlist);
    CHECK(role_of("/opt/etc/nfqws2/lists/my-own.list") == ListRole::hostlist);
    CHECK(
        role_of("/opt/etc/nfqws2/lists/auto.list") == ListRole::hostlist_auto);
    CHECK(
        role_of("/opt/etc/nfqws2/lists/exclude.list") ==
        ListRole::hostlist_exclude);
    CHECK(role_of("/opt/etc/nfqws2/lists/ipset.list") == ListRole::ipset);
    CHECK(
        role_of("/opt/etc/nfqws2/lists/ipset_exclude.list") ==
        ListRole::ipset_exclude);

    CHECK(role_includes(ListRole::hostlist));
    CHECK(role_includes(ListRole::hostlist_auto));
    CHECK(role_includes(ListRole::ipset));
    CHECK_FALSE(role_includes(ListRole::hostlist_exclude));
    CHECK_FALSE(role_includes(ListRole::ipset_exclude));
    CHECK(role_is_hostlist(ListRole::hostlist_exclude));
    CHECK_FALSE(role_is_hostlist(ListRole::ipset));
}

TEST_CASE("the exclude flag is not read as the shorter one it starts with") {
    // "--hostlist-exclude=" begins with "--hostlist", and filing an exclude
    // list as coverage would invert the answer for every domain on it.
    const auto refs = parse_list_references(
        std::vector<std::string>{"--hostlist-exclude=/lists/exclude.list"});
    REQUIRE(refs.size() == 1);
    CHECK(refs[0].role == ListRole::hostlist_exclude);
    CHECK(refs[0].path == "/lists/exclude.list");
}

TEST_CASE("a repeated flag names its file once") {
    const auto refs = parse_list_references(
        std::vector<std::string>{
            "--hostlist-exclude=/lists/exclude.list",
            "--hostlist-exclude=/lists/exclude.list",
            "--hostlist-exclude=/lists/other.list"});
    CHECK(refs.size() == 2);
}

TEST_CASE("bounded hostlist parsing refuses entry and character amplification") {
    const auto ordinary = parse_hostlist_bounded(
        "# ignored\nexample.com\n  10.0.0.0/8  \n",
        4,
        64,
        4096);
    REQUIRE(ordinary.has_value());
    CHECK(
        ordinary->entries ==
        std::vector<std::string>{"example.com", "10.0.0.0/8"});
    CHECK(ordinary->normalized_characters == 21);
    CHECK(ordinary->conservative_bytes >
          ordinary->normalized_characters);

    CHECK_FALSE(parse_hostlist_bounded("a\nb\nc\n", 2, 64, 4096));
    CHECK_FALSE(parse_hostlist_bounded("abcd\n", 4, 3, 4096));
    CHECK_FALSE(parse_hostlist_bounded("ordinary.example\n", 4, 64, 1));
}

TEST_CASE("only the active nfqws mode contributes list references") {
    const auto args = build_nfqws_dry_run_args(
        "MODE_LIST=\"--hostlist=/lists/active.list\"\n"
        "MODE_AUTO=\"--hostlist-auto=/lists/inactive.list\"\n"
        "# NFQWS_EXTRA_ARGS=\"--hostlist=/lists/commented.list\"\n"
        "NFQWS_EXTRA_ARGS=\"$MODE_LIST\"\n");

    const auto refs = parse_list_references(args);
    REQUIRE(refs.size() == 1);
    CHECK(refs[0].path == "/lists/active.list");
    CHECK(refs[0].role == ListRole::hostlist);
}

TEST_CASE("address lists match by prefix, and families never cross") {
    const auto entries = parse_hostlist(
        "# comment\n"
        "10.0.0.0/8\n"
        "192.168.1.5\n"
        "2001:db8::/32\n");

    const auto inside = match_ipset(entries, "10.1.2.3");
    REQUIRE(inside.has_value());
    CHECK(inside->entry == "10.0.0.0/8");
    CHECK_FALSE(inside->exact);

    const auto host = match_ipset(entries, "192.168.1.5");
    REQUIRE(host.has_value());
    CHECK(host->entry == "192.168.1.5");
    CHECK(host->exact);

    const auto v6 = match_ipset(entries, "2001:db8::1");
    REQUIRE(v6.has_value());
    CHECK(v6->entry == "2001:db8::/32");

    CHECK_FALSE(match_ipset(entries, "11.0.0.1").has_value());
    CHECK_FALSE(match_ipset(entries, "192.168.1.6").has_value());
    // The v4 bytes of this address sit inside the v6 prefix's bytes; the
    // families still must not cross.
    CHECK_FALSE(match_ipset(entries, "32.1.13.184").has_value());
    CHECK_FALSE(match_ipset(entries, "not-an-address").has_value());
    CHECK_FALSE(match_ipset(entries, "").has_value());
}

TEST_CASE("the narrowest covering prefix is the one reported") {
    const auto entries = parse_hostlist("10.0.0.0/8\n10.1.0.0/16\n10.1.2.3\n");

    const auto exact = match_ipset(entries, "10.1.2.3");
    REQUIRE(exact.has_value());
    CHECK(exact->entry == "10.1.2.3");

    const auto narrower = match_ipset(entries, "10.1.9.9");
    REQUIRE(narrower.has_value());
    CHECK(narrower->entry == "10.1.0.0/16");
}

TEST_CASE("a malformed prefix is skipped rather than guessed at") {
    const auto entries = parse_hostlist("10.0.0.0/33\n10.0.0.0/\n10.0.0.0/8\n");
    const auto match = match_ipset(entries, "10.0.0.1");
    REQUIRE(match.has_value());
    CHECK(match->entry == "10.0.0.0/8");
}

TEST_CASE("an empty domain matches nothing") {
    const auto entries = parse_hostlist("youtube.com\n");
    CHECK_FALSE(match_hostlist(entries, "").has_value());
    CHECK_FALSE(match_hostlist(entries, "   ").has_value());
}

TEST_CASE("nfqws profiles retain order inline filters and local exclusions") {
    const auto profiles = parse_profile_references({
        "--filter-tcp=443", "--filter-l7=tls",
        "--ipset-ip=203.0.113.0/24", "--lua-desync=fake",
        "--new=domains", "--filter-udp=443", "--filter-l7=quic",
        "--hostlist-domains=example.test",
        "--hostlist-exclude-domains=excluded.example.test", "--lua-desync=fake",
        "--new=voice", "--filter-udp=50000-50099", "--filter-l7=discord"});
    REQUIRE(profiles.size() == 3);
    CHECK(profiles[0].index == 1);
    CHECK(profiles[1].name == "domains");
    CHECK(profiles[1].filters == std::vector<std::string>{
        "--filter-udp=443", "--filter-l7=quic"});
    CHECK_FALSE(profiles[2].has_actions);
    const auto first = evaluate_profile_lists(profiles[0],
        "excluded.example.test", {"203.0.113.1"}, {});
    const auto second = evaluate_profile_lists(profiles[1],
        "excluded.example.test", {"203.0.113.1"}, {});
    CHECK(first.result == "matched");
    CHECK(second.result == "excluded");
    REQUIRE(second.matches.size() == 2);
    CHECK(second.matches[0].reference.inline_values);
    CHECK(second.matches[1].reference.role == ListRole::hostlist_exclude);
}

TEST_CASE("nfqws IP and host predicates intersect within each profile") {
    const auto profile = parse_profile_references({
        "--filter-tcp=443", "--filter-l7=tls", "--lua-desync=fake",
        "--ipset-ip=203.0.113.0/24",
        "--ipset-exclude-ip=203.0.113.5",
        "--hostlist-domains=example.test",
        "--hostlist-exclude-domains=excluded.example.test"}).front();
    CHECK(evaluate_profile_lists(profile, "www.example.test",
        {"203.0.113.1"}, {}).result == "matched");
    CHECK(evaluate_profile_lists(profile, "other.test",
        {"203.0.113.1"}, {}).result == "unmatched");
    CHECK(evaluate_profile_lists(profile, "excluded.example.test",
        {"198.51.100.1"}, {}).result == "unmatched");
    CHECK(evaluate_profile_lists(profile, "www.example.test",
        {"203.0.113.5"}, {}).result == "excluded");
    CHECK(evaluate_profile_lists(profile, "www.example.test",
        {"203.0.113.1", "203.0.113.5"}, {}).result == "mixed");
    CHECK(evaluate_profile_lists(profile, "www.example.test",
        {}, {}).result == "ip_required");
    CHECK(evaluate_profile_lists(profile, "", {"203.0.113.1"}, {}).result ==
        "hostname_required");
}

TEST_CASE("nfqws domain exclusions require a visible hostname unlike UDP IP profiles") {
    const auto profiles = parse_profile_references({
        "--filter-udp=443", "--filter-l7=quic",
        "--hostlist-exclude-domains=example.test", "--lua-desync=fake",
        "--new=udp", "--filter-udp=50000-50099", "--filter-l7=discord,stun",
        "--lua-desync=fake"});
    CHECK(evaluate_profile_lists(profiles[0], "", {"203.0.113.1"}, {}).result ==
        "hostname_required");
    CHECK(evaluate_profile_lists(profiles[0], "other.test",
        {"203.0.113.1"}, {}).result == "unrestricted");
    CHECK(evaluate_profile_lists(profiles[1], "",
        {"203.0.113.1"}, {}).result == "unrestricted");
    CHECK_FALSE(evaluate_profile_lists(profiles[1], "",
        {"203.0.113.1"}, {}).hostname_required);
}

TEST_CASE("nfqws empty static lists auto learning and unreadable files differ") {
    const ListLoader empty = [](const std::string&) {
        return std::make_shared<const std::vector<std::string>>();
    };
    auto profile = parse_profile_references({
        "--hostlist=/lists/user", "--hostlist-exclude=/lists/exclude",
        "--lua-desync=fake"}).front();
    CHECK(evaluate_profile_lists(profile, "", {}, empty).result == "unrestricted");
    CHECK(evaluate_profile_lists(profile, "example.test", {}, {}).result == "unknown");
    profile = parse_profile_references({
        "--hostlist-auto=/lists/auto", "--lua-desync=fake"}).front();
    CHECK(evaluate_profile_lists(profile, "example.test", {}, empty).result == "auto_pending");
    CHECK(evaluate_profile_lists(profile, "", {}, empty).result == "hostname_required");
    profile = parse_profile_references({
        "--ipset=/lists/ip", "--ipset-ip=0.0.0.0", "--lua-desync=fake"}).front();
    CHECK(evaluate_profile_lists(profile, "", {"203.0.113.1"}, empty).result == "unmatched");
}

TEST_CASE("nfqws template or server semantics are not guessed at") {
    for (const auto* token : {"--import=base", "--template=base", "--server"}) {
        const auto profiles = parse_profile_references({
            token, "--hostlist-domains=example.test", "--lua-desync=fake",
            "--new", "--hostlist-exclude-domains=example.test", "--lua-desync=fake"});
        REQUIRE(profiles.size() == 2);
        for (const auto& profile : profiles) {
            CHECK(evaluate_profile_lists(profile, "example.test",
                {"203.0.113.1"}, {}).result == "unknown");
        }
    }
}

TEST_CASE("nfqws exact-only domain exclusions do not match subdomains") {
    const auto entries = parse_hostlist("^example.test\nparent.test\n");
    const auto exact = match_hostlist(entries, "EXAMPLE.TEST");
    REQUIRE(exact);
    CHECK(exact->entry == "^example.test");
    CHECK(exact->exact);
    CHECK_FALSE(match_hostlist(entries, "www.example.test"));
    CHECK(match_hostlist(entries, "www.parent.test"));
}

TEST_CASE("nfqws unsupported argument shapes cannot erase list conditions") {
    for (const auto* flag : {"--hostlist", "--ipset", "--hostlist-exclude=",
                             "--hostlist-domains=", "--lua-desync", "--skip"}) {
        const auto profile = parse_profile_references({
            flag, "example.test", "--filter-tcp=443"}).front();
        CHECK(evaluate_profile_lists(profile, "example.test",
            {"203.0.113.1"}, {}).result == "unknown");
    }
}

TEST_CASE("nfqws generated startup branches honor exclusions without losing MTProto or UDP") {
    const auto root = std::filesystem::path(__FILE__).parent_path().parent_path() /
        "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies";
    const ListLoader lists = [](const std::string& path) -> ListEntries {
        if (path.find("ipset_exclude.list") != std::string::npos)
            return std::make_shared<const std::vector<std::string>>(
                std::vector<std::string>{"203.0.113.7"});
        if (path.find("ipset.list") != std::string::npos)
            return std::make_shared<const std::vector<std::string>>(
                std::vector<std::string>{"203.0.113.0/24"});
        if (path.find("exclude.list") != std::string::npos)
            return std::make_shared<const std::vector<std::string>>(
                std::vector<std::string>{"youtube.com", "blocked.example.test"});
        if (path.find("user.list") != std::string::npos)
            return std::make_shared<const std::vector<std::string>>(
                std::vector<std::string>{"blocked.example.test", "allowed.example.test"});
        return std::make_shared<const std::vector<std::string>>();
    };
    for (const auto* name : {"01 safe", "02 balanced", "03 max"}) {
        INFO(name);
        std::ifstream input(root / name / "nfqws2.conf", std::ios::binary);
        REQUIRE(input.good());
        const std::string content{std::istreambuf_iterator<char>(input), {}};
        REQUIRE(validate_nfqws_candidate(content).empty());
        const auto profiles = parse_profile_references(build_nfqws_dry_run_args(content));
        std::size_t ip_branches = 0, mtproto_branches = 0, udp_branches = 0;
        for (const auto& profile : profiles) {
            INFO(profile.index);
            INFO(profile.name);
            REQUIRE(profile.supported);
            const auto has_filter = [&](const std::string& filter) {
                return std::find(profile.filters.begin(), profile.filters.end(), filter)
                    != profile.filters.end();
            };
            if (has_filter("--filter-l7=mtproto")) {
                ++mtproto_branches;
                CHECK(evaluate_profile_lists(profile, "", {"203.0.113.1"}, lists).result == "matched");
                CHECK(evaluate_profile_lists(profile, "", {"203.0.113.7"}, lists).result == "excluded");
                CHECK(evaluate_profile_lists(profile, "", {"198.51.100.1"}, lists).result == "unmatched");
            } else if (has_filter("--filter-l7=wireguard,stun,discord,mtproto")) {
                ++udp_branches;
                CHECK(evaluate_profile_lists(profile, "", {"198.51.100.1"}, lists).result == "unrestricted");
            } else {
                const bool ip_branch = std::any_of(profile.lists.begin(), profile.lists.end(),
                    [](const ListReference& ref) { return ref.role == ListRole::ipset; });
                if (ip_branch) {
                    ++ip_branches;
                    CHECK(evaluate_profile_lists(profile, "blocked.example.test",
                        {"203.0.113.1"}, lists).result == "excluded");
                    CHECK(evaluate_profile_lists(profile, "allowed.example.test",
                        {"203.0.113.1"}, lists).result == "matched");
                    CHECK(evaluate_profile_lists(profile, "",
                        {"203.0.113.1"}, lists).result == "hostname_required");
                }
                if (has_filter("--filter-l7=http,tls,mtproto") || has_filter("--filter-l7=quic"))
                    CHECK(evaluate_profile_lists(profile, "youtube.com",
                        {"203.0.113.1"}, lists).result == "excluded");
            }
        }
        CHECK(ip_branches == 2);
        CHECK(mtproto_branches == 1);
        CHECK(udp_branches == 1);
    }
}

} // namespace keen_pbr3::nfqws
