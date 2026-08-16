#include <doctest/doctest.h>

#include "../src/config/subscription_fetch_policy.hpp"

#include <string>

namespace keen_pbr3 {

namespace {
using Url = SubscriptionUrlVerdict;
using Dest = SubscriptionDestinationVerdict;
} // namespace

TEST_CASE("the router's own services are never a subscription source") {
    // The daemon runs as root with a loopback RCI on port 79 and its own API
    // on loopback. Fetching either on an operator's behalf turns the importer
    // into a confused deputy.
    for (const char* address : {"127.0.0.1", "127.1.2.3", "::1"}) {
        CHECK(subscription_destination_permitted(address) == Dest::loopback);
    }
    CHECK(classify_subscription_url("http://127.0.0.1:79/rci/show/system") ==
          Url::destination_not_permitted);
    CHECK(classify_subscription_url("http://[::1]:8080/api/config") ==
          Url::destination_not_permitted);
}

TEST_CASE("the LAN behind the router is not the public internet") {
    for (const char* address : {"10.0.0.1", "172.16.0.1", "172.31.255.254",
                                "192.168.1.1", "100.64.0.1"}) {
        CHECK(subscription_destination_permitted(address) ==
              Dest::private_network);
    }
    // ...and the boundaries are not off by one: these are public.
    for (const char* address : {"172.15.255.255", "172.32.0.1", "11.0.0.1",
                                "192.169.0.1", "100.63.255.255",
                                "100.128.0.1"}) {
        CHECK(subscription_destination_permitted(address) == Dest::allowed);
    }
}

TEST_CASE("link-local covers the metadata address family") {
    CHECK(subscription_destination_permitted("169.254.169.254") ==
          Dest::link_local);
    CHECK(subscription_destination_permitted("fe80::1") == Dest::link_local);
    CHECK(subscription_destination_permitted("fe80::1%br0") ==
          Dest::link_local);
    CHECK(subscription_destination_permitted("fd00::1") ==
          Dest::unique_local);
}

TEST_CASE("an IPv4 address wearing an IPv6 coat is judged as IPv4") {
    // Without this, every rule above is bypassed by one line of notation.
    CHECK(subscription_destination_permitted("::ffff:127.0.0.1") ==
          Dest::loopback);
    CHECK(subscription_destination_permitted("::ffff:192.168.1.1") ==
          Dest::private_network);
    CHECK(subscription_destination_permitted("::ffff:169.254.169.254") ==
          Dest::link_local);
    // A public one still passes, so the mapping is not a blanket refusal.
    CHECK(subscription_destination_permitted("::ffff:93.184.216.34") ==
          Dest::allowed);
}

TEST_CASE("6to4 and NAT64 embeddings are unwrapped, not trusted") {
    // 2002:7f00:0001:: embeds 127.0.0.1.
    CHECK(subscription_destination_permitted("2002:7f00:1::") ==
          Dest::loopback);
    // 64:ff9b:: NAT64 embedding of 10.0.0.1.
    CHECK(subscription_destination_permitted("64:ff9b::a00:1") ==
          Dest::private_network);
}

TEST_CASE("unspecified, multicast and reserved space are refused") {
    CHECK(subscription_destination_permitted("0.0.0.0") == Dest::unspecified);
    CHECK(subscription_destination_permitted("::") == Dest::unspecified);
    CHECK(subscription_destination_permitted("224.0.0.1") ==
          Dest::multicast_or_broadcast);
    CHECK(subscription_destination_permitted("255.255.255.255") ==
          Dest::multicast_or_broadcast);
    CHECK(subscription_destination_permitted("ff02::1") ==
          Dest::multicast_or_broadcast);
    for (const char* address : {"192.0.0.1", "198.18.0.1", "198.51.100.1",
                                "203.0.113.1", "240.0.0.1"}) {
        CHECK(subscription_destination_permitted(address) == Dest::reserved);
    }
}

TEST_CASE("an address we cannot parse is refused, not waved through") {
    // This function is the last gate before a connection. Anything it does not
    // understand is not something it can clear.
    for (const char* value : {"", "not-an-address", "999.1.1.1",
                              "127.0.0", "::gggg"}) {
        CHECK(subscription_destination_permitted(value) == Dest::unparsable);
    }
}

TEST_CASE("only http and https may be fetched") {
    CHECK(classify_subscription_url("https://example.com/sub") ==
          Url::allowed);
    CHECK(classify_subscription_url("HTTPS://example.com/sub") ==
          Url::allowed);
    for (const char* url : {"file:///etc/shadow", "ftp://example.com/x",
                            "gopher://example.com/x",
                            "data:text/plain;base64,AAAA",
                            "sing-box://example.com"}) {
        CHECK(classify_subscription_url(url) == Url::scheme_not_allowed);
    }
}

TEST_CASE("credentials in the URL are refused before anything else") {
    // A subscription secret must never enter a URL: a URL reaches the log, the
    // API and frontend storage, which is every place the roadmap forbids.
    CHECK(classify_subscription_url("https://user:pass@example.com/sub") ==
          Url::credentials_in_url);
    CHECK(classify_subscription_url("https://token@example.com/sub") ==
          Url::credentials_in_url);
    // Checked before the host is extracted, so it also fires when the host
    // itself would have been fine or refused for another reason.
    CHECK(classify_subscription_url("https://user:pass@127.0.0.1/sub") ==
          Url::credentials_in_url);
}

TEST_CASE("a hostname is deliberately left to the connect-time check") {
    // Resolving here would produce an answer the later connection is under no
    // obligation to reuse - and HttpClient follows five redirects silently, so
    // the address finally contacted may have nothing to do with this URL.
    CHECK(classify_subscription_url("https://example.com/sub") ==
          Url::allowed);
    CHECK(classify_subscription_url("https://localhost/sub") == Url::allowed);
    // ...which is exactly why stage 2 must run per connection: the name above
    // resolves to an address stage 2 refuses.
    CHECK(subscription_destination_permitted("127.0.0.1") == Dest::loopback);
}

TEST_CASE("malformed URLs are refused") {
    for (const char* url : {"", "example.com/sub", "://example.com",
                            "https://", "https://[fe80::1/sub",
                            // An allowed scheme without an authority is not a
                            // fetchable URL, however familiar it looks.
                            "http:/example.com", "https:example.com"}) {
        CHECK(classify_subscription_url(url) == Url::malformed);
    }
}

TEST_CASE("a port does not launder a refused destination") {
    CHECK(classify_subscription_url("http://127.0.0.1:8080/x") ==
          Url::destination_not_permitted);
    CHECK(classify_subscription_url("http://192.168.1.1:443/x") ==
          Url::destination_not_permitted);
    CHECK(classify_subscription_url("https://[::1]:9999/x") ==
          Url::destination_not_permitted);
}

TEST_CASE("the body bound is small enough to be configuration") {
    // A subscription is configuration, not payload, and this router shares
    // 1 GiB with the routing daemon.
    CHECK(kSubscriptionMaximumBytes == 1024U * 1024U);
}

TEST_CASE("every verdict has a name") {
    for (const auto verdict :
         {Url::allowed, Url::scheme_not_allowed, Url::credentials_in_url,
          Url::destination_not_permitted, Url::malformed}) {
        CHECK(std::string(subscription_url_verdict_name(verdict)).size() >
              0U);
    }
    for (const auto verdict :
         {Dest::allowed, Dest::loopback, Dest::private_network,
          Dest::link_local, Dest::unique_local,
          Dest::multicast_or_broadcast, Dest::unspecified, Dest::reserved,
          Dest::unparsable}) {
        CHECK(std::string(subscription_destination_verdict_name(verdict))
                  .size() > 0U);
    }
}

} // namespace keen_pbr3
