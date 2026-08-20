#include <doctest/doctest.h>

#include "../src/nfqws/list_match.hpp"
#include "../src/util/nfqws_validator.hpp"

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

} // namespace keen_pbr3::nfqws
