#include "../src/health/nfqws_scan_source.hpp"

#include <doctest/doctest.h>

#include <map>
#include <string>

namespace keen_pbr3 {

namespace {

// A reader backed by a table, so none of this touches a filesystem.
FileReader reader_over(std::map<std::string, std::string> files) {
    return [files = std::move(files)](const std::string& path) -> std::string {
        const auto it = files.find(path);
        return it == files.end() ? std::string{} : it->second;
    };
}

}  // namespace

TEST_CASE("nfqws flag: read where a flag can start") {
    const std::string config =
        "NFQWS_OPT=\"--hostlist=/opt/etc/nfqws2/lists/user.list\"\n";

    CHECK(nfqws_flag_value(config, "--hostlist") ==
          "/opt/etc/nfqws2/lists/user.list");
}

TEST_CASE("nfqws flag: a longer flag is not found inside a shorter one") {
    // The regression this parser was written for. Searching for
    // `--hostlist-auto-debug=` must not settle on the `--hostlist-auto=`
    // occurrence, and asking for `--hostlist` must not answer with the value
    // of `--hostlist-auto`.
    const std::string config =
        "NFQWS_OPT=\"--hostlist-auto=/tmp/auto.list "
        "--hostlist-auto-debug=/opt/var/log/nfqws2.log\"\n";

    CHECK(nfqws_flag_value(config, "--hostlist-auto-debug") ==
          "/opt/var/log/nfqws2.log");
    CHECK(nfqws_flag_value(config, "--hostlist-auto") == "/tmp/auto.list");
    // `--hostlist` appears only as a prefix of other flags here, never as one.
    CHECK(nfqws_flag_value(config, "--hostlist").empty());
}

TEST_CASE("nfqws flag: a shell assignment keeps its value in quotes") {
    // ISP_INTERFACE is written as a shell variable while nfqws2's own flags
    // are not. Reading to the first quote would return nothing for the first
    // shape; reading to the first space would return the whole line for the
    // second.
    const std::string config =
        "ISP_INTERFACE=\"eth3\"\n"
        "NFQWS_OPT=\"--hostlist=/tmp/a.list --dpi-desync=fake\"\n";

    CHECK(nfqws_flag_value(config, "ISP_INTERFACE") == "eth3");
    CHECK(nfqws_flag_value(config, "--hostlist") == "/tmp/a.list");
    CHECK(nfqws_flag_value(config, "--dpi-desync") == "fake");
}

TEST_CASE("nfqws flag: absent is empty, not a guess") {
    CHECK(nfqws_flag_value("", "--hostlist").empty());
    CHECK(nfqws_flag_value("NFQWS_OPT=\"--qnum=200\"\n", "--hostlist").empty());
}

TEST_CASE("nfqws flag: a value that ends the document is still a value") {
    CHECK(nfqws_flag_value("ISP_INTERFACE=eth3", "ISP_INTERFACE") == "eth3");
}

TEST_CASE("scan source: an unreadable configuration is named as such") {
    const auto result =
        read_nfqws_scan_source("/opt/etc/nfqws2/nfqws2.conf", reader_over({}));

    CHECK_FALSE(result.source.has_value());
    CHECK(result.error == NfqwsScanSourceError::config_unreadable);
}

TEST_CASE("scan source: without a debug log there is nothing to read") {
    const auto result = read_nfqws_scan_source(
        "/conf",
        reader_over({{"/conf", "ISP_INTERFACE=\"eth3\"\n"}}));

    CHECK_FALSE(result.source.has_value());
    CHECK(result.error == NfqwsScanSourceError::no_debug_log);
}

TEST_CASE("scan source: without the provider device the direct leg proves nothing") {
    const auto result = read_nfqws_scan_source(
        "/conf",
        reader_over({{"/conf", "NFQWS_OPT=\"--hostlist-auto-debug=/log\"\n"}}));

    CHECK_FALSE(result.source.has_value());
    CHECK(result.error == NfqwsScanSourceError::no_isp_interface);
}

TEST_CASE("scan source: the hostlists are read through the same reader") {
    const auto result = read_nfqws_scan_source(
        "/conf",
        reader_over({
            {"/conf",
             "ISP_INTERFACE=\"eth3\"\n"
             "NFQWS_OPT=\"--hostlist=/handled --hostlist-exclude=/excluded "
             "--hostlist-auto-debug=/log\"\n"},
            {"/handled", "example.com\nexample.org\n"},
            {"/excluded", "safe.example\n"},
        }));

    REQUIRE(result.source.has_value());
    CHECK(result.error == NfqwsScanSourceError::ok);
    CHECK(result.source->log_path == "/log");
    CHECK(result.source->isp_interface == "eth3");
    CHECK(result.source->handled.size() == 2);
    CHECK(result.source->excluded.size() == 1);
}

TEST_CASE("scan source: missing hostlists are empty, not fatal") {
    // nfqws2 may run with no hostlist at all. That is a configuration a scan
    // can still work with - it only means nothing is claimed as handled.
    const auto result = read_nfqws_scan_source(
        "/conf",
        reader_over({{"/conf",
                      "ISP_INTERFACE=\"eth3\"\n"
                      "NFQWS_OPT=\"--hostlist-auto-debug=/log\"\n"}}));

    REQUIRE(result.source.has_value());
    CHECK(result.source->handled.empty());
    CHECK(result.source->excluded.empty());
}

TEST_CASE("scan coverage: what nfqws2 handles is not coverage") {
    // The point of a scan is the hosts nfqws2 was asked to handle and kept
    // failing on. Counting them as covered would hide exactly the subject.
    NfqwsScanSource source;
    source.handled = {"blocked.example"};
    source.excluded = {"left.alone.example"};

    Config config;
    const auto coverage = build_scan_coverage(config, source);

    CHECK(coverage.nfqws_handled.size() == 1);
    CHECK(coverage.nfqws_excluded.size() == 1);
    CHECK(coverage.routing_lists.empty());
}

TEST_CASE("scan coverage: routing lists carry their domains and addresses") {
    Config config;
    ListConfig routed;
    routed.domains =
        std::vector<std::string>{"Example.COM", "*.example.org", "trailing.net."};
    routed.ip_cidrs = std::vector<std::string>{"10.0.0.0/8"};
    config.lists = std::map<std::string, ListConfig>{{"routed", routed}};

    const auto coverage = build_scan_coverage(config, NfqwsScanSource{});

    REQUIRE(coverage.routing_lists.size() == 1);
    CHECK(coverage.routing_lists[0].name == "routed");
    CHECK(coverage.routing_lists[0].addresses.size() == 1);
    REQUIRE(coverage.routing_lists[0].domains.size() == 3);
    // Case is kept as written. It looked like a normalisation worth asserting
    // and is not one: `ListParser::normalize_domain` validates the labels and
    // strips a `*.` prefix and a trailing dot, and lowercases nothing. That is
    // harmless because `match_hostlist` lowercases both sides when it
    // compares, so coverage is case-insensitive where it matters.
    CHECK(coverage.routing_lists[0].domains[0] == "Example.COM");
    // These two are real normalisations, and worth pinning down.
    CHECK(coverage.routing_lists[0].domains[1] == "example.org");
    CHECK(coverage.routing_lists[0].domains[2] == "trailing.net");
}

TEST_CASE("scan coverage: an unusable domain is dropped, not carried through") {
    // normalize_domain returns nothing for a label it cannot accept. Carrying
    // the raw string would put an entry in coverage that can never match, and
    // coverage that silently never matches is worse than none.
    Config config;
    ListConfig routed;
    routed.domains = std::vector<std::string>{"good.example", "-bad.example", ""};
    config.lists = std::map<std::string, ListConfig>{{"routed", routed}};

    const auto coverage = build_scan_coverage(config, NfqwsScanSource{});

    REQUIRE(coverage.routing_lists.size() == 1);
    REQUIRE(coverage.routing_lists[0].domains.size() == 1);
    CHECK(coverage.routing_lists[0].domains[0] == "good.example");
}

TEST_CASE("scan coverage: a cache-backed list is still a list") {
    // A list whose contents live in a downloaded cache file has neither
    // inline domains nor inline addresses. It is reported as present and
    // empty rather than silently dropped, so a caller can tell the two apart.
    Config config;
    ListConfig cached;
    cached.url = std::string{"https://example.invalid/list.srs"};
    config.lists = std::map<std::string, ListConfig>{{"cached", cached}};

    const auto coverage = build_scan_coverage(config, NfqwsScanSource{});

    REQUIRE(coverage.routing_lists.size() == 1);
    CHECK(coverage.routing_lists[0].name == "cached");
    CHECK(coverage.routing_lists[0].domains.empty());
    CHECK(coverage.routing_lists[0].addresses.empty());
}

}  // namespace keen_pbr3
