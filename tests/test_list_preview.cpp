#include <doctest/doctest.h>

#include "../src/lists/list_preview.hpp"
#include "../src/lists/list_streamer.hpp"

#include <string>

namespace keen_pbr3 {

TEST_CASE("List preview counts physical lines and canonical unique families") {
    const auto result = preview_list_text(
        "# source\r\n \t\r\n192.0.2.129/24\r\n192.0.2.0/24\n"
        "192.0.2.1/32\n2001:0DB8::1/128\n2001:db8::1\n"
        "*.Example.COM.\nexample.com\ninvalid entry\n");
    CHECK(result.status == "ok");
    CHECK(result.complete);
    CHECK(result.lines == 10);
    CHECK(result.ignored_lines == 2);
    CHECK(result.valid_entries == 7);
    CHECK(result.unique_entries == 4);
    CHECK(result.duplicates == 3);
    CHECK(result.invalid_entries == 1);
    CHECK(result.ipv4 == 2);
    CHECK(result.ipv6 == 1);
    CHECK(result.domains == 1);
    REQUIRE(result.entries.size() == 4);
    CHECK(result.entries[0].line == 3);
    CHECK(result.entries[0].value == "192.0.2.0/24");
    CHECK(result.entries[0].type == "ipv4");
    CHECK(result.entries[1].value == "192.0.2.1");
    CHECK(result.entries[2].value == "2001:db8::1");
    CHECK(result.entries[2].type == "ipv6");
    CHECK(result.entries[3].line == 8);
    CHECK(result.entries[3].value == "example.com");
    CHECK(result.entries[3].type == "domain");
    REQUIRE(result.errors.size() == 1);
    CHECK(result.errors[0].line == 10);
    CHECK(result.errors[0].code == "invalid_entry");
}

TEST_CASE("List preview reuses shared IP validation diagnostics") {
    const auto result = preview_list_text(
        "01.2.3.4\n192.0.2.1/33\n2001:::1\n999.0.0.1\nbad..example\n");
    CHECK(result.valid_entries == 0);
    CHECK(result.invalid_entries == 5);
    REQUIRE(result.errors.size() == 5);
    CHECK(result.errors[0].code == "leading_zeros");
    CHECK(result.errors[1].code == "invalid_prefix");
    CHECK(result.errors[2].code == "invalid_address");
    CHECK(result.errors[3].code == "invalid_address");
    CHECK(result.errors[4].code == "invalid_entry");
}

TEST_CASE("List preview does not invent a trailing line or strip a runtime-visible BOM") {
    CHECK(preview_list_text("").lines == 0);
    CHECK(preview_list_text("\n").lines == 1);
    CHECK(preview_list_text("\r\n\r\n").lines == 2);
    CHECK(preview_list_text("example.org").lines == 1);
    CHECK(preview_list_text("example.org\n").lines == 1);
    const auto result = preview_list_text(std::string("\xef\xbb\xbf", 3) + "192.0.2.1\nexample.org");
    CHECK(result.status == "ok");
    CHECK(result.complete);
    CHECK(result.lines == 2);
    CHECK(result.valid_entries == 1);
    CHECK(result.invalid_entries == 1);
    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].value == "example.org");
}

TEST_CASE("List preview preserves the ordinary reader raw line byte limit") {
    const std::string host = "192.0.2.1";
    const auto accepted = preview_list_text(std::string(ListStreamer::kMaxLineBytes - host.size(), ' ') + host);
    CHECK(accepted.valid_entries == 1);
    const auto rejected = preview_list_text(
        "example.org\n" + std::string(ListStreamer::kMaxLineBytes, ' ') + host + "\nlater.example");
    CHECK(rejected.status == "ok");
    CHECK_FALSE(rejected.complete);
    CHECK(rejected.limit_reason == "line_too_long");
    CHECK(rejected.lines == 2);
    CHECK(rejected.valid_entries == 1);
    CHECK(rejected.invalid_entries == 1);
    CHECK(rejected.ignored_lines == 0);
    REQUIRE(rejected.errors.size() == 1);
    CHECK(rejected.errors[0].code == "line_too_long");
    CHECK(rejected.errors[0].value == host);
    const auto comment = preview_list_text("#" + std::string(ListStreamer::kMaxLineBytes, 'x') + "\nexample.org");
    CHECK_FALSE(comment.complete);
    CHECK(comment.lines == 1);
    CHECK(comment.ignored_lines == 0);
    CHECK(comment.valid_entries == 0);
    REQUIRE(comment.errors.size() == 1);
    CHECK(comment.errors[0].code == "line_too_long");
    CHECK(comment.errors[0].value.size() == 160);
}

TEST_CASE("List preview limits samples but retains bounded full counters") {
    std::string text;
    for (int index = 0; index < 51; ++index) text += "host" + std::to_string(index) + ".example\n";
    for (int index = 0; index < 51; ++index) text += "invalid entry " + std::to_string(index) + "\n";
    text += "HOST0.EXAMPLE.\n";
    const auto result = preview_list_text(text);
    CHECK(result.complete);
    CHECK(result.lines == 103);
    CHECK(result.valid_entries == 52);
    CHECK(result.unique_entries == 51);
    CHECK(result.duplicates == 1);
    CHECK(result.invalid_entries == 51);
    CHECK(result.entries.size() == kListPreviewSampleSize);
    CHECK(result.errors.size() == kListPreviewSampleSize);
    CHECK(result.entries_limited);
    CHECK(result.errors_limited);
    CHECK(result.entries.front().value == "host0.example");
    CHECK(result.entries.back().line == 50);
    CHECK(result.errors.back().line == 101);
}

TEST_CASE("List preview bounds invalid excerpts without splitting UTF8") {
    const std::string value = std::string(159, 'x') + "\xc3\xa9" + " invalid";
    const auto result = preview_list_text(value);
    REQUIRE(result.errors.size() == 1);
    CHECK(result.errors[0].value == std::string(159, 'x'));
    CHECK(result.errors[0].value.size() <= 160);
}

TEST_CASE("List preview reports partial counts at the physical line cap") {
    std::string text;
    for (std::size_t index = 0; index < kListPreviewMaxLines; ++index) text += "a.example\n";
    const auto exact = preview_list_text(text);
    CHECK(exact.complete);
    CHECK(exact.lines == static_cast<std::int64_t>(kListPreviewMaxLines));
    CHECK(exact.limit_reason.empty());
    text += "b.example\n";
    const auto partial = preview_list_text(text);
    CHECK(partial.status == "ok");
    CHECK_FALSE(partial.complete);
    CHECK(partial.limit_reason == "line_limit");
    CHECK(partial.lines == static_cast<std::int64_t>(kListPreviewMaxLines));
    CHECK(partial.valid_entries == static_cast<std::int64_t>(kListPreviewMaxLines));
    CHECK(partial.unique_entries == 1);
    CHECK(partial.duplicates == static_cast<std::int64_t>(kListPreviewMaxLines - 1));
}

TEST_CASE("List preview rejects oversized bodies before parsing") {
    const auto result = preview_list_text(std::string(kListPreviewMaxBytes + 1U, 'x'));
    CHECK(result.status == "too_large");
    CHECK_FALSE(result.complete);
    CHECK(result.lines == 0);
    CHECK(result.entries.empty());
}

TEST_CASE("List preview rejects binary SRS and malformed UTF8") {
    const std::string bodies[] = {std::string("SRS\x01\0binary", 11),
        std::string("example.org\0", 12), "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80"};
    for (const auto& body : bodies) {
        const auto result = preview_list_text(body);
        CHECK(result.status == "unsupported_format");
        CHECK_FALSE(result.complete);
        CHECK(result.lines == 0);
        CHECK(result.entries.empty());
    }
}

TEST_CASE("List preview does not interpret JSON YAML or inline comments") {
    for (const char* body : {"{\"rules\":[]}", "[\"example.org\"]", "---\npayload:\n", "payload:\n- example.org", "version: 1\nrules: []"}) {
        const auto result = preview_list_text(body);
        CHECK(result.status == "unsupported_format");
        CHECK_FALSE(result.complete);
        CHECK(result.lines == 0);
    }
    const auto inline_comment = preview_list_text("example.org # comment\n");
    CHECK(inline_comment.status == "ok");
    CHECK(inline_comment.valid_entries == 0);
    CHECK(inline_comment.invalid_entries == 1);
}

} // namespace keen_pbr3
