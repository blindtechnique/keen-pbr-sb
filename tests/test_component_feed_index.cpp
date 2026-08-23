#include <doctest/doctest.h>

#include "../src/update/component_feed_index.hpp"

#include <zlib.h>

#include <string>

namespace keen_pbr3 {

namespace {

// Verbatim from the router's /opt/var/opkg-lists/nfqws2-keenetic on
// 23.08.2026, so the parser meets the real stanza shape, not a tidy one.
constexpr const char* kLiveIndex =
    "Package: nfqws2-keenetic\n"
    "Version: 1.2.4\n"
    "Depends: iptables, busybox\n"
    "Conflicts: tpws-keenetic, nfqws-keenetic\n"
    "Section: net\n"
    "Architecture: all\n"
    "Filename: nfqws2-keenetic_1.2.4_all_entware.ipk\n"
    "Size: 2681893\n"
    "SHA256sum: "
    "b9c6e4e02f4b8b046bad0bfd6e7d3dcc1c3006691d49ca33cf67bd6e552be00c\n"
    "Description:  NFQWS2 service\n"
    " with a continuation line that belongs to the description\n"
    "\n";

std::string gzip(const std::string& plain) {
    z_stream stream{};
    REQUIRE(deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, 16 + MAX_WBITS,
                         8, Z_DEFAULT_STRATEGY) == Z_OK);
    std::string out(deflateBound(&stream, plain.size()) + 64, '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(plain.data()));
    stream.avail_in = static_cast<uInt>(plain.size());
    stream.next_out = reinterpret_cast<Bytef*>(&out[0]);
    stream.avail_out = static_cast<uInt>(out.size());
    REQUIRE(deflate(&stream, Z_FINISH) == Z_STREAM_END);
    out.resize(stream.total_out);
    deflateEnd(&stream);
    return out;
}

} // namespace

TEST_CASE("the live nfqws2 feed stanza identifies an exact ipk") {
    const auto entries = parse_opkg_packages_index(kLiveIndex);
    REQUIRE(entries.size() == 1);
    const auto& entry = entries.front();
    CHECK(entry.package == "nfqws2-keenetic");
    CHECK(entry.version == "1.2.4");
    CHECK(entry.filename == "nfqws2-keenetic_1.2.4_all_entware.ipk");
    CHECK(entry.size == 2681893U);
    CHECK(entry.sha256 ==
          "b9c6e4e02f4b8b046bad0bfd6e7d3dcc1c3006691d49ca33cf67bd6e552be00c");
    CHECK(entry.identifies_ipk());
}

TEST_CASE("a stanza that cannot identify an ipk is dropped, not guessed") {
    // No digest: nothing to verify against, so there is nothing exact here.
    const auto without_digest = parse_opkg_packages_index(
        "Package: a\nVersion: 1\nFilename: a_1.ipk\nSize: 10\n\n");
    CHECK(without_digest.empty());
    // A digest of the wrong shape is the same as none.
    const auto bad_digest = parse_opkg_packages_index(
        "Package: a\nVersion: 1\nFilename: a_1.ipk\nSize: 10\n"
        "SHA256sum: deadbeef\n\n");
    CHECK(bad_digest.empty());
    // A size that is not a number is no size.
    const auto bad_size = parse_opkg_packages_index(
        "Package: a\nVersion: 1\nFilename: a_1.ipk\nSize: big\n"
        "SHA256sum: " + std::string(64, 'a') + "\n\n");
    CHECK(bad_size.empty());
}

TEST_CASE("several stanzas parse independently and CRLF is tolerated") {
    const std::string two =
        "Package: a\r\nVersion: 1\r\nFilename: a_1.ipk\r\nSize: 10\r\n"
        "SHA256sum: " + std::string(64, 'a') + "\r\n\r\n"
        "Package: b\nVersion: 2\nFilename: b_2.ipk\nSize: 20\n"
        "SHA256sum: " + std::string(64, 'B') + "\n";
    const auto entries = parse_opkg_packages_index(two);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].package == "a");
    CHECK(entries[1].package == "b");
    // Digests compare case-insensitively with what a feed prints.
    CHECK(entries[1].sha256 == std::string(64, 'b'));
}

TEST_CASE("the feed index inflates from gzip within a budget") {
    const auto compressed = gzip(kLiveIndex);
    const auto text = gunzip_to_string(compressed, 64 * 1024);
    CHECK(text == kLiveIndex);

    // Over budget is refused, not truncated: a partial index could drop the
    // very stanza that proves a digest.
    CHECK_THROWS(gunzip_to_string(compressed, 16));
    // Garbage is refused.
    CHECK_THROWS(gunzip_to_string("not gzip at all", 64 * 1024));
}

TEST_CASE("retention is decided by version, with the store's copy winning") {
    const auto entries = parse_opkg_packages_index(kLiveIndex);
    const auto listed = find_feed_entry(entries, "nfqws2-keenetic", "1.2.4");
    REQUIRE(listed.has_value());
    CHECK_FALSE(find_feed_entry(entries, "nfqws2-keenetic", "1.2.3").has_value());

    // Nothing retained yet and the feed still lists the installed version:
    // this is the window, fetch now.
    CHECK(decide_ipk_retention("1.2.4", std::nullopt, listed) ==
          IpkRetentionAction::retain_now);

    // Already held: nothing to do, and a different digest in the feed does
    // not change that - the installed bytes are the retained ones.
    RetainedIpk held;
    held.version = "1.2.4";
    held.sha256 = std::string(64, '0');
    CHECK(decide_ipk_retention("1.2.4", held, listed) ==
          IpkRetentionAction::already_retained);

    // The feed moved on to a newer release and the store holds an older
    // version: the installed bytes are gone for good.
    RetainedIpk older;
    older.version = "1.2.3";
    CHECK(decide_ipk_retention("1.2.4", older, std::nullopt) ==
          IpkRetentionAction::unavailable);
    CHECK(decide_ipk_retention("1.2.4", std::nullopt, std::nullopt) ==
          IpkRetentionAction::unavailable);
}

} // namespace keen_pbr3
