#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/connection_query.hpp"

namespace keen_pbr3 {
namespace {

api::ConnectionRecord record(std::string id,
                             std::string device,
                             std::string destination,
                             std::int64_t last_seen,
                             bool active) {
    api::ConnectionRecord value;
    value.id = std::move(id);
    value.protocol = "tcp";
    value.state = active ? "ESTABLISHED" : "CLOSED";
    value.source = "192.168.1.2";
    value.source_port = 1234;
    value.destination = std::move(destination);
    value.destination_port = 443;
    value.route = "vpn";
    value.mark = 1;
    value.active = active;
    value.device = std::move(device);
    value.destination_domains = {"example.org"};
    value.first_seen = last_seen - 10;
    value.last_seen = last_seen;
    return value;
}

} // namespace

TEST_CASE("connection query filters on router and sorts deterministically") {
    std::vector<api::ConnectionRecord> records{
        record("old", "phone", "1.1.1.1", 10, true),
        record("new", "laptop", "2.2.2.2", 20, true),
        record("closed", "laptop", "3.3.3.3", 30, false),
    };
    api::ConnectionQueryRequest request;
    request.device = "lap";

    const auto result =
        filter_and_sort_connections(std::move(records), request);

    REQUIRE(result.size() == 1);
    CHECK(result.front().id == "new");
}

TEST_CASE("connection query supports closed history and ascending sort") {
    std::vector<api::ConnectionRecord> records{
        record("b", "router", "2.2.2.2", 20, false),
        record("a", "router", "1.1.1.1", 10, true),
    };
    api::ConnectionQueryRequest request;
    request.active_only = false;
    request.sort = api::ConnectionSort::DESTINATION;
    request.order = api::SortOrder::ASC;

    const auto result =
        filter_and_sort_connections(std::move(records), request);

    REQUIRE(result.size() == 2);
    CHECK(result[0].id == "a");
    CHECK(result[1].id == "b");
}

TEST_CASE("connection query matches Cyrillic device names case-insensitively") {
    std::vector<api::ConnectionRecord> records{
        record("phone", "Телефон Максима", "2.2.2.2", 20, true),
    };
    api::ConnectionQueryRequest request;
    request.search = "ТЕЛЕФОН";

    const auto result =
        filter_and_sort_connections(std::move(records), request);

    REQUIRE(result.size() == 1);
    CHECK(result.front().id == "phone");
}

} // namespace keen_pbr3

#endif // WITH_API
