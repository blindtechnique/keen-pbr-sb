#include <doctest/doctest.h>

#include "../src/lists/list_source_decoder.hpp"
#include "../src/config/list_parser.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {
void expect_error(std::string_view body, std::string_view format,
                  const std::string& code, std::int64_t line = 1) {
    const auto result = decode_list_source(body, format);
    CHECK_FALSE(result.complete);
    CHECK(result.text.empty());
    REQUIRE_FALSE(result.errors.empty());
    CHECK(result.errors.front().code == code);
    CHECK(result.errors.front().line == line);
}

std::string sized_domain(std::size_t index, std::size_t size) {
    std::string value(size, 'a');
    const auto prefix = "entry" + std::to_string(index);
    value.replace(0, prefix.size(), prefix);
    for (std::size_t dot = 63; dot + 1U < value.size(); dot += 64U) value[dot] = '.';
    if (value.size() % 64U == 0U) value[value.size() - 2U] = '.';
    return value;
}
} // namespace

TEST_CASE("list source formats are finite and text remains the explicit legacy default") {
    CHECK(valid_list_source_format("text"));
    CHECK(valid_list_source_format("json-array"));
    CHECK(valid_list_source_format("yaml-payload"));
    for (const auto* format : {"", "json", "yaml", "auto", "sing-box-json", "TEXT"})
        CHECK_FALSE(valid_list_source_format(format));
    const auto result = decode_list_source("# comment\nExample.Org.\n192.0.2.99/24\n");
    REQUIRE(result.complete);
    CHECK(result.text == "example.org\n192.0.2.0/24\n");
    CHECK(result.input_entries == 2);
    CHECK(result.ignored_lines == 1);
    CHECK(result.lines == 3);
    expect_error("example.org", "auto", "unsupported_format");
}

TEST_CASE("JSON arrays normalize with ListParser and retain deterministic first source lines") {
    const auto result = decode_list_source(
        "[\n \"10.7.8.9/24\", \"10.7.8.0/24\",\n"
        " \"2001:0db8::123/64\", \"2001:db8::/64\",\n"
        " \"192.0.2.1/32\", \"192.0.2.1\",\n"
        " \"*.EXAMPLE.org\", \"example.org.\"\n]", "json-array");
    REQUIRE(result.complete);
    CHECK(result.errors.empty());
    CHECK(result.lines == 6);
    CHECK(result.input_entries == 8);
    CHECK(result.valid_entries == 8);
    CHECK(result.duplicates == 4);
    CHECK(result.ipv4 == 2);
    CHECK(result.ipv6 == 1);
    CHECK(result.domains == 1);
    REQUIRE(result.entries.size() == 4U);
    CHECK(result.entries[0].line == 2);
    CHECK(result.entries[1].line == 3);
    CHECK(result.entries[2].line == 4);
    CHECK(result.entries[3].line == 5);
    CHECK(result.text == "10.7.8.0/24\n2001:db8::/64\n192.0.2.1\nexample.org\n");
    for (const auto& entry : result.entries) {
        std::size_t dispatched = 0;
        FunctionalVisitor visitor([&](EntryType, std::string_view) { ++dispatched; });
        CHECK(ListParser::classify_entry(entry.value, visitor));
        CHECK(dispatched == 1U);
    }
}

TEST_CASE("JSON string decoding accepts escapes CRLF and an empty array without treating strings as comments") {
    const auto result = decode_list_source("[\r\n \"\\u0045XAMPLE.org.\",\r\n \"192.0.2.1\\/32\"\r\n]", "json-array");
    REQUIRE(result.complete);
    CHECK(result.text == "example.org\n192.0.2.1\n");
    REQUIRE(result.entries.size() == 2U);
    CHECK(result.entries[1].line == 3);
    CHECK(decode_list_source("[]", "json-array").complete);
    CHECK(decode_list_source("[]", "json-array").text.empty());
    expect_error("[\"# example.org\"]", "json-array", "invalid_entry");
    expect_error("[\"\"]", "json-array", "invalid_address");
}

TEST_CASE("JSON import rejects non-array roots nested containers and non-string elements") {
    for (const auto* body : {"{}", "null", "\"example.org\"", "42", "true"})
        expect_error(body, "json-array", "json_root_array");
    for (const auto* value : {"null", "true", "4", "1.5", "{}", "[]"})
        expect_error(std::string("[\n \"example.org\",\n ") + value + "\n]", "json-array", "json_entry_type", 3);
    expect_error(std::string(10000, '[') + std::string(10000, ']'), "json-array", "json_entry_type");
}

TEST_CASE("JSON syntax diagnostics use physical source lines and never expose partial normalized text") {
    expect_error("[\n \"example.org\",\n]", "json-array", "json_syntax", 3);
    expect_error("[\n \"example.org\"\n", "json-array", "json_syntax", 3);
    expect_error("[\"\\uD800\"]", "json-array", "json_syntax");
    expect_error("[\"example.org\"] trailing", "json-array", "json_syntax");
    const auto result = decode_list_source("[\n \"example.org\",\n \"bad\\nname\"\n]", "json-array");
    CHECK_FALSE(result.complete);
    CHECK(result.text.empty());
    REQUIRE(result.entries.size() == 1U);
    CHECK(result.entries.front().value == "example.org");
    REQUIRE(result.errors.size() == 1U);
    CHECK(result.errors.front().line == 3);
}

TEST_CASE("YAML payload accepts finite block scalars comments native domains and IPs") {
    auto body = std::string("# source\npayload: # values\n"
        "  - Example.Org. # native domain includes subdomains\n"
        "  - '*.example.org'\n"
        "  - \"192.0.2.129/24\" # IPv4\n"
        "  - 2001:db8::123/64\n");
    SUBCASE("indented block") {}
    SUBCASE("indentless block") {
        body = "payload:\n- example.org\n- '*.example.org'\n- 192.0.2.129/24\n- 2001:db8::123/64\n";
    }
    const auto result = decode_list_source(body, "yaml-payload");
    REQUIRE(result.complete);
    CHECK(result.text == "example.org\n192.0.2.0/24\n2001:db8::/64\n");
    CHECK(result.input_entries == 4);
    CHECK(result.valid_entries == 4);
    CHECK(result.duplicates == 1);
    CHECK(result.domains == 1);
    CHECK(result.ipv4 == 1);
    CHECK(result.ipv6 == 1);
    REQUIRE(result.entries.size() == 3U);
    CHECK(result.entries.front().line == (body.front() == '#' ? 3 : 2));
}

TEST_CASE("YAML quoting is single-line and preserves scalar contents for canonical validation") {
    const auto result = decode_list_source("payload:\r\n  - \"\\u0045XAMPLE.org\"\r\n  - 'true'\r\n", "yaml-payload");
    REQUIRE(result.complete);
    CHECK(result.text == "example.org\ntrue\n");
    expect_error("payload:\n  - 'exa''mple.org'\n", "yaml-payload", "invalid_entry", 2);
    expect_error("payload:\n  - \"example.org\"# adjacent comment\n", "yaml-payload", "yaml_syntax", 2);
    expect_error("payload:\n  - 'example.org' garbage\n", "yaml-payload", "yaml_syntax", 2);
    expect_error("payload:\n  - 'unclosed\n", "yaml-payload", "yaml_syntax", 2);
    expect_error("payload:\n  - \"\\x65xample.org\"\n", "yaml-payload", "yaml_syntax", 2);
    expect_error("payload:\n  - \"example.org\\nother.org\"\n", "yaml-payload", "invalid_entry", 2);
}

TEST_CASE("YAML import rejects unsupported syntax instead of flattening routing rules or objects") {
    for (const auto* body : {"", "# only comment\n", "rules:\n  - example.org\n", "  payload:\n  - example.org\n"})
        expect_error(body, "yaml-payload", "yaml_payload_required");
    expect_error("payload:\n", "yaml-payload", "yaml_syntax");
    expect_error("payload: []\n", "yaml-payload", "yaml_payload_required");
    for (const auto* value : {"&anchor example.org", "*anchor", "!!str example.org", "[example.org]",
                              "{domain: example.org}", "|", ">", "- example.org", "key: example.org",
                              "DOMAIN,example.org", "IP-CIDR,192.0.2.0/24", "true", "null", "1e3", "0xabc"})
        expect_error(std::string("payload:\n  - ") + value + "\n", "yaml-payload", "yaml_unsupported", 2);
    expect_error("---\npayload:\n - example.org\n", "yaml-payload", "yaml_unsupported");
    expect_error("payload:\n  - example.org\n--- # second document\npayload:\n - other.org\n",
                 "yaml-payload", "yaml_unsupported", 3);
    expect_error("payload:\n  - example.org\nother: value\n", "yaml-payload", "yaml_unsupported", 3);
    expect_error("payload:\n  - example.org\n   - other.org\n", "yaml-payload", "yaml_unsupported", 3);
    expect_error("payload:\n\t- example.org\n", "yaml-payload", "yaml_syntax", 2);
    expect_error("payload:\n  - '*.example.org'\n  - +.other.org\n", "yaml-payload", "invalid_entry", 3);
}

TEST_CASE("structured invalid-entry diagnostics reuse ListParser address reasons and source lines") {
    for (const auto* format : {"text", "json-array", "yaml-payload"}) {
        CAPTURE(format);
        const auto wrap = [&](const std::string& entry) {
            if (std::string(format) == "json-array") return "[\n\"" + entry + "\"]";
            if (std::string(format) == "yaml-payload") return "payload:\n- '" + entry + "'\n";
            return std::string("# source\n") + entry;
        };
        expect_error(wrap("010.0.0.1"), format, "leading_zeros", 2);
        expect_error(wrap("192.0.2.1/33"), format, "invalid_prefix", 2);
        expect_error(wrap("999.0.0.1"), format, "invalid_address", 2);
        expect_error(wrap("not a domain"), format, "invalid_entry", 2);
    }
}

TEST_CASE("source UTF8 validation is bounded and BOM follows explicit format semantics") {
    const auto bom = std::string("\xef\xbb\xbf");
    CHECK(decode_list_source(bom + "[\"example.org\"]", "json-array").complete);
    CHECK(decode_list_source(bom + "payload:\n- example.org\n", "yaml-payload").complete);
    expect_error(bom + "example.org\n", "text", "invalid_entry");
    expect_error(std::string("example.org\n") + char(0xff), "text", "invalid_encoding", 2);
    expect_error(std::string("payload:\n- example.org\n") + '\0', "yaml-payload", "invalid_encoding", 3);
    std::string unicode = "a";
    for (int index = 0; index < 100; ++index) unicode += "\xc3\xa9";
    const auto result = decode_list_source("[\"" + unicode + "\"]", "json-array");
    REQUIRE(result.errors.size() == 1U);
    CHECK(result.errors.front().value.size() == 159U);
}

TEST_CASE("source scalar and byte limits preserve useful prefixes but prohibit publication") {
    expect_error(std::string(kListSourceMaxBytes + 1U, 'x'), "json-array", "too_large");
    const auto padded = std::string(kListSourceMaxLineBytes - 11U, ' ') + "example.org";
    CHECK(decode_list_source("[\"" + padded + "\"]", "json-array").complete);
    expect_error("[\"" + padded + " \"]", "json-array", "line_too_long");
    CHECK(decode_list_source(padded, "text").complete);
    expect_error(padded + " ", "text", "line_too_long");
    expect_error(std::string("payload:\n- ") + padded + "\n", "yaml-payload", "line_too_long", 2);
    std::string minified = "[";
    for (int index = 0; index < 1000; ++index) {
        if (index != 0) minified += ',';
        minified += "\"example.org\"";
    }
    minified += ']';
    REQUIRE(minified.size() > kListSourceMaxLineBytes);
    const auto accepted = decode_list_source(minified, "json-array");
    CHECK(accepted.complete);
    CHECK(accepted.duplicates == 999);
}

TEST_CASE("source entry and diagnostic samples are independently bounded") {
    std::string body = "[";
    for (std::size_t index = 0; index < kListSourceMaxEntries + 1U; ++index) {
        if (index != 0U) body += ',';
        body += "\"example.org\"";
    }
    body += ']';
    const auto result = decode_list_source(body, "json-array");
    CHECK_FALSE(result.complete);
    CHECK(result.text.empty());
    CHECK(result.input_entries == static_cast<std::int64_t>(kListSourceMaxEntries));
    CHECK(result.entries.size() == 1U);
    CHECK(result.limit_reason == "entry_limit");
    REQUIRE(result.errors.size() == 1U);
    CHECK(result.errors.front().code == "entry_limit");
    std::string invalid;
    for (int index = 0; index < 60; ++index) invalid += "not a domain\n";
    const auto sampled = decode_list_source(invalid, "text");
    CHECK(sampled.invalid_entries == 60);
    CHECK(sampled.errors.size() == kListSourceMaxErrors);
    CHECK(sampled.errors_limited);
    CHECK(sampled.text.empty());
}

TEST_CASE("normalized source output has its own hard byte limit") {
    std::string body;
    std::size_t index = 0;
    while (kListSourceMaxBytes - body.size() > 253U) body += sized_domain(index++, 200U) + "\n";
    body += sized_domain(index, kListSourceMaxBytes - body.size());
    REQUIRE(body.size() == kListSourceMaxBytes);
    const auto result = decode_list_source(body, "text");
    CHECK_FALSE(result.complete);
    CHECK(result.text.empty());
    CHECK(result.limit_reason == "output_limit");
    REQUIRE(result.errors.size() == 1U);
    CHECK(result.errors.front().code == "output_limit");
}

} // namespace keen_pbr3
