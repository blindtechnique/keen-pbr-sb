#include <doctest/doctest.h>

#include "../src/config/list_parser.hpp"
#include "../src/log/logger.hpp"

#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class RecordingListVisitor : public ListEntryVisitor {
public:
    void on_entry(EntryType type, std::string_view entry) override {
        entries.emplace_back(type, std::string(entry));
    }

    std::vector<std::pair<EntryType, std::string>> entries;
};

} // namespace

TEST_CASE("ListParser canonicalizes hosts networks and full-prefix hosts") {
    const std::vector<std::pair<std::string, std::string>> cases{
        {" 192.168.7.199/24\t\r", "192.168.7.0/24"},
        {"10.33.45.67/13", "10.32.0.0/13"},
        {"192.0.2.1/32", "192.0.2.1"},
        {"192.0.2.1", "192.0.2.1"},
        {"2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
        {"2001:db8::1/128", "2001:db8::1"},
        {"2001:db8:abcd:ffff::1/49", "2001:db8:abcd:8000::/49"},
        {"2001:db8::abcd/64", "2001:db8::/64"},
        {"::FFFF:C000:0280/128", "::ffff:192.0.2.128"},
        {"::ffff:192.0.2.199/120", "::ffff:192.0.2.0/120"},
        {"192.168.1.1/0", "0.0.0.0/0"},
        {"2001:db8::1/0", "::/0"},
        {"10.0.0.9/08", "10.0.0.0/8"},
    };
    for (const auto& [input, expected] : cases) {
        CAPTURE(input);
        ListParser::IpCidrError error = ListParser::IpCidrError::invalid_address;
        const auto normalized = ListParser::normalize_ip_or_cidr(input, &error);
        REQUIRE(normalized.has_value());
        CHECK(*normalized == expected);
        CHECK(error == ListParser::IpCidrError::none);
        CHECK(ListParser::normalize_ip_or_cidr(*normalized) == normalized);
    }
}

TEST_CASE("ListParser does not reject private VPN or special address ranges") {
    for (const char* input : {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                              "100.64.0.0/10", "127.0.0.1", "169.254.0.0/16",
                              "224.0.0.0/4", "0.0.0.0/0", "::/0", "::1",
                              "fc00::/7", "fe80::/10", "ff00::/8"}) {
        CAPTURE(input);
        CHECK(ListParser::normalize_ip_or_cidr(input).has_value());
    }
}

TEST_CASE("ListParser distinguishes ambiguous IPv4 octets and malformed prefixes") {
    for (const char* input : {"01.2.3.4", "192.168.001.1/24", "::ffff:192.168.001.1"}) {
        ListParser::IpCidrError error;
        CHECK_FALSE(ListParser::normalize_ip_or_cidr(input, &error));
        CHECK(error == ListParser::IpCidrError::leading_zeros);
    }
    for (const char* input : {"192.0.2.1/33", "2001:db8::1/129", "192.0.2.1/",
                              "192.0.2.1/-1", "192.0.2.1/+1", "192.0.2.1/1tail",
                              "192.0.2.1/1/2", "192.0.2.1/4294967296"}) {
        CAPTURE(input);
        ListParser::IpCidrError error;
        CHECK_FALSE(ListParser::normalize_ip_or_cidr(input, &error));
        CHECK(error == ListParser::IpCidrError::invalid_prefix);
    }
    const std::vector<std::string> invalid{
        "", "example.org", "999.0.0.1", "1.2.3", "2001:::1", "fe80::1%eth0",
        "-0.1.2.3", std::string("2001:db8::1") + '\0' + "extra",
    };
    for (const auto& input : invalid) {
        ListParser::IpCidrError error;
        CHECK_FALSE(ListParser::normalize_ip_or_cidr(input, &error));
        CHECK(error == ListParser::IpCidrError::invalid_address);
    }
}

TEST_CASE("ListParser dispatches normalized hosts with host rather than CIDR type") {
    RecordingListVisitor visitor;
    REQUIRE(ListParser::classify_entry("192.0.2.1/32", visitor));
    REQUIRE(ListParser::classify_entry("2001:DB8::1/128", visitor));
    REQUIRE(ListParser::classify_entry("::ffff:192.0.2.128/128", visitor));
    REQUIRE(ListParser::classify_entry("192.0.2.1/0", visitor));
    CHECK(visitor.entries == std::vector<std::pair<EntryType, std::string>>{
        {EntryType::Ip, "192.0.2.1"}, {EntryType::Ip, "2001:db8::1"},
        {EntryType::Ip, "::ffff:192.0.2.128"}, {EntryType::Cidr, "0.0.0.0/0"},
    });
}

TEST_CASE("ListParser normalizes wildcard and root-dot domains") {
    RecordingListVisitor visitor;
    CHECK(ListParser::classify_entry("*.google.com", visitor));
    CHECK(ListParser::classify_entry("_dns._udp.example.com.", visitor));
    REQUIRE(visitor.entries.size() == 2);
    CHECK(visitor.entries[0].second == "google.com");
    CHECK(visitor.entries[1].second == "_dns._udp.example.com");
}

TEST_CASE("ListParser applies identical domain rules to streamed sources") {
    std::istringstream input(
        "*.google.com\n"
        "valid_example.test.\n"
        "bad/domain.test\n"
        "bad label.test\n"
        "-bad.example\n");
    RecordingListVisitor visitor;
    ListParser::stream_parse(input, visitor, "test-list");
    REQUIRE(visitor.entries.size() == 2);
    CHECK(visitor.entries[0].second == "google.com");
    CHECK(visitor.entries[1].second == "valid_example.test");
}

TEST_CASE("ListParser skips blank and comment entries") {
    std::istringstream input(
        "\n"
        "   \t\r\n"
        "  # comment\n"
        "example.com\n");
    RecordingListVisitor visitor;
    ListParser::stream_parse(input, visitor, "test-list");
    REQUIRE(visitor.entries.size() == 1);
    CHECK(visitor.entries[0].second == "example.com");
}

TEST_CASE("ListParser limits malformed-entry warnings per source") {
    auto& logger = Logger::instance();
    const LogLevel previous_level = logger.level();
    logger.set_level(LogLevel::warn);
    std::string log;
    logger.set_sink([&log](const std::string& line) {
        log += line;
        log.push_back('\n');
    });

    RecordingListVisitor visitor;
    ListParser::ParseContext context;
    for (std::size_t line = 1; line <= 7; ++line) {
        ListParser::parse_line("bad/domain" + std::to_string(line),
                               visitor,
                               "limited-test-list",
                               line,
                               &context);
    }

    logger.clear_sink();
    logger.set_level(previous_level);
    CHECK(log.find("Skipping invalid list entry 'bad/domain1' in limited-test-list") !=
          std::string::npos);
    CHECK(log.find("Skipping invalid list entry 'bad/domain5' in limited-test-list") !=
          std::string::npos);
    CHECK(log.find("Skipping invalid list entry 'bad/domain6'") ==
          std::string::npos);
    CHECK(log.find("Too many invalid list entries in limited-test-list") !=
          std::string::npos);
}

TEST_CASE("ListParser can suppress malformed-entry warnings for trusted cache") {
    auto& logger = Logger::instance();
    const LogLevel previous_level = logger.level();
    logger.set_level(LogLevel::warn);
    std::string log;
    logger.set_sink([&log](const std::string& line) { log += line; });

    RecordingListVisitor visitor;
    ListParser::ParseContext context{false};
    ListParser::parse_line(
        "bad/domain", visitor, "cached-list", 1, &context);

    logger.clear_sink();
    logger.set_level(previous_level);
    CHECK(log.empty());
}

TEST_CASE("ListParser rejects malformed DNS labels") {
    const std::vector<std::string> invalid = {
        "", "*", "*.*.example.com", "example..com", ".example.com",
        "example.com..", "bad-.example", "-bad.example",
        std::string(64, 'a') + ".example",
        "example.com\nserver=/evil/1.1.1.1",
    };
    for (const std::string& value : invalid) {
        CAPTURE(value);
        CHECK_FALSE(ListParser::normalize_domain(value).has_value());
    }
}

} // namespace keen_pbr3
