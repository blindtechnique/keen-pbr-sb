#include "../src/cmd/scan_tunnel_candidates.hpp"

#include <doctest/doctest.h>

#include <memory>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

Outbound interface_outbound(const std::string& tag, const std::string& iface) {
    Outbound outbound;
    outbound.tag = tag;
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = iface;
    return outbound;
}

}  // namespace

TEST_CASE("scan outbound: found by tag, with its interface") {
    const std::vector<Outbound> outbounds{
        interface_outbound("moooawg", "nwg1"),
        interface_outbound("tr_9786265a", "kpbr9786265a")};

    const auto found = find_scan_outbound(outbounds, "tr_9786265a");

    REQUIRE(found.has_value());
    CHECK(found->tag == "tr_9786265a");
    REQUIRE(found->interface.has_value());
    CHECK(*found->interface == "kpbr9786265a");
}

TEST_CASE("scan outbound: an unknown tag is absent, not a null to dereference") {
    const std::vector<Outbound> outbounds{interface_outbound("moooawg", "nwg1")};

    CHECK_FALSE(find_scan_outbound(outbounds, "nothing_like_it").has_value());
    CHECK_FALSE(find_scan_outbound({}, "moooawg").has_value());
}

TEST_CASE("scan outbound: the answer outlives the list it came from") {
    // The regression this file was written for. The first version returned a
    // pointer into `config.outbounds.value_or({})` - a temporary that dies with
    // the function - and the router took SIGSEGV once the freed block was
    // reused, at an address that was plainly ASCII from a log line.
    //
    // Holding the source in something destroyable makes the lifetime the
    // subject of the test rather than a matter of luck.
    std::optional<Outbound> found;
    {
        auto outbounds = std::make_unique<std::vector<Outbound>>();
        outbounds->push_back(interface_outbound("tr_9786265a", "kpbr9786265a"));
        found = find_scan_outbound(*outbounds, "tr_9786265a");
        REQUIRE(found.has_value());
    }

    // Source gone. A pointer would be dangling here; a value is still a value.
    REQUIRE(found.has_value());
    CHECK(found->tag == "tr_9786265a");
    REQUIRE(found->interface.has_value());
    CHECK(*found->interface == "kpbr9786265a");
}

TEST_CASE("scan outbound: a temporary vector is a safe source too") {
    // Exactly the call the command makes: the argument is the result of
    // optional::value_or, which is a temporary.
    const std::optional<std::vector<Outbound>> configured{
        std::vector<Outbound>{interface_outbound("moooawg", "nwg1")}};

    const auto found =
        find_scan_outbound(configured.value_or(std::vector<Outbound>{}), "moooawg");

    REQUIRE(found.has_value());
    REQUIRE(found->interface.has_value());
    CHECK(*found->interface == "nwg1");
}

}  // namespace keen_pbr3
