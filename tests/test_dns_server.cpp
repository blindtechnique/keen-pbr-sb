#include <doctest/doctest.h>

#include "../src/dns/dns_server.hpp"

using namespace keen_pbr3;

// ---------------------------------------------------------------------------
// IPv4 bare
// ---------------------------------------------------------------------------

TEST_CASE("parse: bare IPv4 -> port 53") {
    auto r = parse_dns_address_str("8.8.8.8");
    CHECK(r.ip   == "8.8.8.8");
    CHECK(r.port == 53);
}

TEST_CASE("parse: IPv4:port -> parsed port") {
    auto r = parse_dns_address_str("8.8.8.8:5353");
    CHECK(r.ip   == "8.8.8.8");
    CHECK(r.port == 5353);
}

TEST_CASE("parse: IPv4 port 1 -> valid") {
    auto r = parse_dns_address_str("1.2.3.4:1");
    CHECK(r.ip   == "1.2.3.4");
    CHECK(r.port == 1);
}

TEST_CASE("parse: IPv4 port 65535 -> valid") {
    auto r = parse_dns_address_str("1.2.3.4:65535");
    CHECK(r.ip   == "1.2.3.4");
    CHECK(r.port == 65535);
}

TEST_CASE("parse: IPv4 port 0 -> DnsError") {
    CHECK_THROWS_AS(parse_dns_address_str("1.2.3.4:0"), DnsError);
}

TEST_CASE("parse: IPv4 port 65536 -> DnsError") {
    CHECK_THROWS_AS(parse_dns_address_str("1.2.3.4:65536"), DnsError);
}

TEST_CASE("parse: IPv4 octets with leading zeroes are rejected") {
    CHECK_THROWS_AS(
        parse_dns_address_str("008.008.008.008"),
        DnsError);
    CHECK_NOTHROW(parse_dns_address_str("0.0.0.0"));
}

// ---------------------------------------------------------------------------
// IPv6 bare
// ---------------------------------------------------------------------------

TEST_CASE("parse: bare IPv6 -> port 53") {
    auto r = parse_dns_address_str("::1");
    CHECK(r.ip   == "::1");
    CHECK(r.port == 53);
}

TEST_CASE("parse: [IPv6]:port -> parsed port") {
    auto r = parse_dns_address_str("[::1]:5353");
    CHECK(r.ip   == "::1");
    CHECK(r.port == 5353);
}

TEST_CASE("parse: bracketed IPv6 without port -> port 53") {
    auto r = parse_dns_address_str("[::1]");
    CHECK(r.ip   == "::1");
    CHECK(r.port == 53);
}

TEST_CASE("parse: IPv6 is returned in binary-canonical spelling") {
    auto r = parse_dns_address_str(
        "[2001:0DB8:0000:0000:0000:0000:0000:0001]:53");
    CHECK(r.ip == "2001:db8::1");
    CHECK(r.port == 53);
}

// ---------------------------------------------------------------------------
// Invalid inputs
// ---------------------------------------------------------------------------

TEST_CASE("parse: empty string -> DnsError") {
    CHECK_THROWS_AS(parse_dns_address_str(""), DnsError);
}

TEST_CASE("parse: invalid IP -> DnsError") {
    CHECK_THROWS_AS(parse_dns_address_str("not-an-ip"), DnsError);
}

TEST_CASE("parse: valid IP + non-numeric port -> DnsError") {
    CHECK_THROWS_AS(parse_dns_address_str("8.8.8.8:abc"), DnsError);
}

TEST_CASE("parse: [IPv6] without closing bracket -> DnsError") {
    CHECK_THROWS_AS(parse_dns_address_str("[::1"), DnsError);
}

TEST_CASE("DNS structured errors retain every legacy diagnostic and branch") {
    struct Case {
        const char* address;
        const char* code;
        const char* message;
    };
    const Case cases[] = {
        {"", "config.value.required", "Invalid DNS server address: empty string"},
        {"8.8.8.8:abc", "config.dns.port_number",
         "Invalid DNS server address: '8.8.8.8:abc' (non-numeric port)"},
        {"8.8.8.8:", "config.dns.port_number",
         "Invalid DNS server address: '8.8.8.8:' (non-numeric port)"},
        {"8.8.8.8:-1", "config.dns.port_number",
         "Invalid DNS server address: '8.8.8.8:-1' (non-numeric port)"},
        // from_chars overflow has always used the non-numeric branch.
        {"8.8.8.8:4294967296", "config.dns.port_number",
         "Invalid DNS server address: '8.8.8.8:4294967296' (non-numeric port)"},
        {"8.8.8.8:53 ", "config.dns.port_number",
         "Invalid DNS server address: '8.8.8.8:53 ' (non-numeric port)"},
        {"8.8.8.8:0", "config.dns.port_range",
         "Invalid DNS server address: '8.8.8.8:0' (port out of range 1-65535)"},
        {"8.8.8.8:65536", "config.dns.port_range",
         "Invalid DNS server address: '8.8.8.8:65536' (port out of range 1-65535)"},
        {"[::1]:65536", "config.dns.port_range",
         "Invalid DNS server address: '[::1]:65536' (port out of range 1-65535)"},
        {"[::1", "config.dns.closing_bracket",
         "Invalid DNS server address: '[::1' (missing closing ']')"},
        {"[::1]x", "config.dns.port_separator",
         "Invalid DNS server address: '[::1]x' (expected ':' after ']')"},
        {"not-an-ip", "config.dns.address",
         "Invalid DNS server address: 'not-an-ip' (not a valid IPv4 or IPv6 address)"},
        {"008.008.008.008", "config.dns.address",
         "Invalid DNS server address: '008.008.008.008' (not a valid IPv4 or IPv6 address)"},
        {"[fe80::1%eth0]", "config.dns.address",
         "Invalid DNS server address: '[fe80::1%eth0]' (not a valid IPv4 or IPv6 address)"},
        {"[]", "config.dns.address",
         "Invalid DNS server address: '[]' (not a valid IPv4 or IPv6 address)"},
        // Port diagnostics still precede IP validation for mixed invalidity.
        {"invalid:abc", "config.dns.port_number",
         "Invalid DNS server address: 'invalid:abc' (non-numeric port)"},
    };
    for (const auto& item : cases) {
        CAPTURE(item.address);
        try {
            parse_dns_address_str(item.address);
            FAIL("expected DNS address validation to throw");
        } catch (const DnsError& error) {
            CHECK(error.code() == item.code);
            CHECK(std::string(error.what()) == item.message);
        }
    }
}

TEST_CASE("uncoded DNS errors retain inherited runtime_error constructors") {
    const DnsError literal("legacy literal");
    const DnsError string(std::string("legacy string"));
    CHECK(literal.code().empty());
    CHECK(std::string(literal.what()) == "legacy literal");
    CHECK(string.code().empty());
    CHECK(std::string(string.what()) == "legacy string");
    const DnsError coded("fixed diagnostic", "config.dns.address");
    const auto copied = coded;
    CHECK(copied.code() == "config.dns.address");
    CHECK(std::string(copied.what()) == "fixed diagnostic");
    static_assert(noexcept(coded.code()), "DNS code lookup must not throw");
}

TEST_CASE("structured DNS diagnostics do not change successful endpoint parsing") {
    struct Case {
        const char* address;
        const char* ip;
        uint16_t port;
    };
    const Case cases[] = {
        {"8.8.8.8", "8.8.8.8", 53},
        {"0.0.0.0:1", "0.0.0.0", 1},
        {"192.0.2.1:65535", "192.0.2.1", 65535},
        {"8.8.8.8:00053", "8.8.8.8", 53},
        {"[8.8.8.8]:5353", "8.8.8.8", 5353},
        {"::1", "::1", 53},
        {"[::1]", "::1", 53},
        {"[2001:0DB8:0000:0000:0000:0000:0000:0001]:5353", "2001:db8::1", 5353},
        {"2001:db8::1:5353", "2001:db8::1:5353", 53},
    };
    for (const auto& item : cases) {
        CAPTURE(item.address);
        const auto parsed = parse_dns_address_str(item.address);
        CHECK(parsed.ip == item.ip);
        CHECK(parsed.port == item.port);
        CHECK_NOTHROW(validate_dns_address(item.address));
        const auto server = parse_dns_server("fixture-dns", item.address, "fixture-route");
        CHECK(server.address == item.address);
        CHECK(server.resolved_ip == item.ip);
        CHECK(server.port == item.port);
        CHECK(server.tag == "fixture-dns");
        CHECK(server.detour == "fixture-route");
    }
}
