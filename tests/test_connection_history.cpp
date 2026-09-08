#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/connection_query.hpp"
#include "../src/api/handler_connections.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

std::string tcp_line(unsigned port, const std::string& state = "ESTABLISHED",
                     bool legacy = false) {
    return std::string(legacy ? "" : "ipv4 2 ") + "tcp 6 60 " + state +
        " src=192.168.1.2 dst=203.0.113.8 sport=" + std::to_string(port) +
        " dport=443 src=203.0.113.8 dst=192.168.1.2 sport=443 dport=" +
        std::to_string(port) + " [ASSURED] mark=262145 use=1\n";
}

std::string history_key(unsigned port) {
    return "tcp|192.168.1.2|" + std::to_string(port) + "|203.0.113.8|443";
}

void merge_history(connection_detail::History& history, const std::string& lines,
                   std::int64_t timestamp) {
    std::istringstream input(lines);
    connection_detail::update_history(history, input, {{0x40000, "vpn"}},
                                      0xffff0000U, timestamp);
}

class GeneratedConntrackBuffer : public std::streambuf {
public:
    explicit GeneratedConntrackBuffer(const connection_detail::History& history)
        : history_(history) {}
    size_t peak_current_entries{0};
    unsigned generated{0};

protected:
    int_type underflow() override {
        peak_current_entries = std::max(peak_current_entries, history_.size());
        if (generated == 12000) return traits_type::eof();
        line_ = tcp_line(10000 + generated++);
        setg(line_.data(), line_.data(), line_.data() + line_.size());
        return traits_type::to_int_type(*gptr());
    }

private:
    const connection_detail::History& history_;
    std::string line_;
};

class FailedConntrackBuffer : public std::streambuf {
public:
    FailedConntrackBuffer() : line_(tcp_line(2000)) {
        setg(line_.data(), line_.data(), line_.data() + line_.size());
    }

protected:
    int_type underflow() override {
        throw std::runtime_error("injected conntrack read failure");
    }

private:
    std::string line_;
};

std::vector<api::ConnectionRecord> query_history(
    const connection_detail::History& history, bool active_only) {
    std::vector<api::ConnectionRecord> records;
    for (const auto& [id, entry] : history) {
        api::ConnectionRecord record;
        record.id = id;
        record.active = entry.active;
        record.state = entry.state;
        record.first_seen = entry.first_seen;
        record.last_seen = entry.last_seen;
        records.push_back(std::move(record));
    }
    api::ConnectionQueryRequest query;
    query.active_only = active_only;
    return filter_and_sort_connections(std::move(records), query);
}

} // namespace

TEST_CASE("connection history classifies retained TCP shutdown states as inactive") {
    connection_detail::History history;
    const std::vector<std::string> terminal{
        "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "CLOSING"};
    std::string input = tcp_line(1000) + tcp_line(1001, "SYN_SENT");
    unsigned port = 2000;
    for (const auto& state : terminal) input += tcp_line(port++, state);
    merge_history(history, input, 100);

    CHECK(query_history(history, true).size() == 2);
    CHECK(query_history(history, false).size() == 2 + terminal.size());
    port = 2000;
    for (const auto& state : terminal) {
        const auto& entry = history.at(history_key(port++));
        CHECK_FALSE(entry.active);
        CHECK(entry.state == state);
        CHECK(entry.route == "vpn");
        CHECK(entry.source_port == port - 1);
    }
}

TEST_CASE("connection history keeps disappeared sessions and stable closed age") {
    connection_detail::History history;
    merge_history(history, tcp_line(1000) + tcp_line(1001), 100);
    merge_history(history, tcp_line(1000, "TIME_WAIT"), 115);
    CHECK_FALSE(history.at(history_key(1000)).active);
    CHECK(history.at(history_key(1000)).state == "TIME_WAIT");
    CHECK(history.at(history_key(1000)).last_seen == 100);
    CHECK(history.at(history_key(1001)).state == "CLOSED");
    CHECK(query_history(history, true).empty());
    CHECK(query_history(history, false).size() == 2);

    merge_history(history, tcp_line(1000, "TIME_WAIT"), 130);
    CHECK(history.at(history_key(1000)).last_seen == 100);
    CHECK(history.at(history_key(1000)).first_seen == 100);
    merge_history(history, tcp_line(1002), 150);
    CHECK(history.at(history_key(1000)).state == "CLOSED");
    CHECK(query_history(history, true).size() == 1);
    // All-mode retains the requested last-seen ordering, not closed-first.
    CHECK(query_history(history, false).front().id == history_key(1002));
}

TEST_CASE("connection history reserves recent closed entries under active load") {
    connection_detail::History history;
    std::string older, recent, live;
    for (unsigned port = 1000; port < 1200; ++port) older += tcp_line(port);
    for (unsigned port = 1200; port < 1600; ++port) recent += tcp_line(port);
    for (unsigned port = 2000; port < 3600; ++port) live += tcp_line(port);
    merge_history(history, older, 100);
    merge_history(history, recent, 200);
    merge_history(history, live, 300);

    REQUIRE(history.size() == 1500);
    CHECK(query_history(history, true).size() == 1200);
    CHECK(query_history(history, false).size() == 1500);
    size_t closed = 0;
    for (const auto& [id, entry] : history) {
        if (!entry.active) {
            ++closed;
            CHECK(entry.last_seen == 200);
        }
    }
    CHECK(closed == 300);
    merge_history(history, live, 310);
    CHECK(history.size() == 1500);
    CHECK(query_history(history, true).size() == 1200);
}

TEST_CASE("connection history shares unused closed quota with active entries") {
    connection_detail::History history;
    std::string live;
    for (unsigned port = 1000; port < 2600; ++port) live += tcp_line(port);
    merge_history(history, live, 100);
    CHECK(history.size() == 1500);
    CHECK(query_history(history, true).size() == 1500);
    merge_history(history, "", 110);
    CHECK(history.size() == 1500);
    CHECK(query_history(history, true).empty());
}

TEST_CASE("connection history streams a large kernel table with bounded working RAM") {
    connection_detail::History history;
    std::string old;
    for (unsigned port = 1000; port < 2500; ++port) old += tcp_line(port);
    merge_history(history, old, 100);
    GeneratedConntrackBuffer buffer(history);
    std::istream input(&buffer);
    connection_detail::update_history(history, input, {}, 0xffff0000U, 200);

    CHECK(buffer.generated == 12000);
    CHECK(buffer.peak_current_entries <= 1564);
    CHECK(history.size() == 1500);
    CHECK(query_history(history, true).size() == 1200);
    CHECK(query_history(history, false).size() == 1500);
}

TEST_CASE("connection history supports legacy conntrack and unchanged UDP semantics") {
    connection_detail::History history;
    merge_history(history, tcp_line(1000, "TIME_WAIT", true) +
        "ipv4 2 udp 17 30 src=192.168.1.2 dst=203.0.113.9 sport=2000 "
        "dport=443 src=203.0.113.9 dst=192.168.1.2 sport=443 dport=2000 mark=0\n",
        100);
    REQUIRE(history.size() == 2);
    CHECK_FALSE(history.at(history_key(1000)).active);
    CHECK(query_history(history, true).size() == 1);
    CHECK(query_history(history, false).size() == 2);
}

TEST_CASE("connection history does not turn a failed proc read into closed sessions") {
    connection_detail::History history;
    merge_history(history, tcp_line(1000), 100);
    std::istringstream unavailable;
    unavailable.setstate(std::ios::failbit);
    connection_detail::update_history(history, unavailable, {}, 0xffff0000U, 200);
    REQUIRE(history.size() == 1);
    CHECK(history.at(history_key(1000)).active);
    CHECK(history.at(history_key(1000)).state == "ESTABLISHED");
    CHECK(history.at(history_key(1000)).last_seen == 100);
}

TEST_CASE("routing connections match canonical exact original destinations and preserve raw tuples") {
    connection_detail::History history;
    connection_detail::SnapshotObservation observation;
    std::istringstream input(tcp_line(1000) +
        "ipv6 10 udp 17 30 src=2001:db8::2 dst=2001:DB8:0:0:0:0:0:8 sport=2000 "
        "dport=443 src=2001:DB8:0:0:0:0:0:8 dst=2001:db8::2 sport=443 dport=2000 mark=0\n");
    connection_detail::update_history(history, input, {{0x40000, "vpn"}},
                                      0xffff0000U, 100, &observation);
    const auto selected = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.8", "2001:db8::8", "2001:DB8::8"});
    CHECK(selected.snapshot_available);
    CHECK(selected.snapshot_at == 100);
    CHECK(selected.total == 2);
    REQUIRE(selected.rows.size() == 2);
    CHECK_FALSE(selected.truncated);
    const auto tcp = std::find_if(selected.rows.begin(), selected.rows.end(),
        [](const auto& row) { return row.protocol == "tcp"; });
    REQUIRE(tcp != selected.rows.end());
    CHECK(tcp->source == "192.168.1.2");
    CHECK(tcp->destination == "203.0.113.8");
    CHECK(tcp->source_port == 1000);
    CHECK(tcp->destination_port == 443);
    CHECK(tcp->state == "ESTABLISHED");
    CHECK(tcp->mark == 0x40001);
    CHECK(tcp->last_seen == 100);
    CHECK(connection_detail::select_routing_connections(history, observation,
        {"203.0.113.80", "203.0.113.8/32", "192.168.1.2", "2001:db8::2",
         "::ffff:203.0.113.8", "2001:db8::80", std::string("203.0.113.8\0ignored", 19)})
        .rows.empty());
}

TEST_CASE("routing connections distinguish current closing rows from retained history and readable emptiness") {
    connection_detail::History history;
    connection_detail::SnapshotObservation observation;
    merge_history(history, tcp_line(1000) + tcp_line(1001), 100);
    std::istringstream current(tcp_line(1000, "TIME_WAIT"));
    connection_detail::update_history(history, current, {}, 0xffff0000U, 115, &observation);
    const auto selected = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.8"});
    CHECK(selected.snapshot_available);
    CHECK(selected.total == 1);
    REQUIRE(selected.rows.size() == 1);
    CHECK(selected.rows.front().source_port == 1000);
    CHECK(selected.rows.front().state == "TIME_WAIT");
    CHECK_FALSE(selected.rows.front().active);
    CHECK(selected.rows.front().last_seen == 115);
    CHECK(history.at(history_key(1000)).last_seen == 100);
    CHECK(history.at(history_key(1001)).state == "CLOSED");
    CHECK_FALSE(history.at(history_key(1001)).observed_in_snapshot);

    std::istringstream empty;
    connection_detail::update_history(history, empty, {}, 0xffff0000U, 120, &observation);
    const auto no_current = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.8"});
    CHECK(no_current.snapshot_available);
    CHECK(no_current.snapshot_at == 120);
    CHECK(no_current.rows.empty());
    CHECK(no_current.total == 0);
    CHECK_FALSE(no_current.truncated);
    CHECK(history.size() == 2);
}

TEST_CASE("routing connections report failed reads unavailable instead of stale or partial evidence") {
    connection_detail::History history;
    connection_detail::SnapshotObservation observation{true, 100, false};
    merge_history(history, tcp_line(1000), 100);
    SUBCASE("unreadable proc file leaves history intact without claiming observation") {
        std::istringstream input;
        input.setstate(std::ios::failbit);
        connection_detail::update_history(history, input, {}, 0xffff0000U, 200, &observation);
        CHECK(history.at(history_key(1000)).active);
        CHECK(history.at(history_key(1000)).last_seen == 100);
    }
    SUBCASE("stream failure after one readable row does not publish a partial snapshot") {
        FailedConntrackBuffer buffer;
        std::istream input(&buffer);
        connection_detail::update_history(history, input, {}, 0xffff0000U, 200, &observation);
        CHECK(input.bad());
        CHECK(history.count(history_key(2000)) == 1);
    }
    const auto unavailable = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.8"});
    CHECK_FALSE(unavailable.snapshot_available);
    CHECK(unavailable.snapshot_at == 200);
    CHECK(unavailable.total == 0);
    CHECK(unavailable.rows.empty());
    CHECK_FALSE(unavailable.truncated);
}

TEST_CASE("routing connections cap returned tuples while keeping bounded snapshot match count") {
    connection_detail::History history;
    connection_detail::SnapshotObservation observation;
    std::string lines;
    for (unsigned port = 1000; port < 1100; ++port) lines += tcp_line(port);
    std::istringstream input(lines);
    connection_detail::update_history(history, input, {}, 0xffff0000U, 100, &observation);
    CHECK_FALSE(observation.truncated);
    const auto selected = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.8"});
    CHECK(selected.snapshot_available);
    CHECK(selected.rows.size() == 64);
    CHECK(selected.total == 100);
    CHECK(selected.truncated);
    const auto other = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.9"});
    CHECK(other.total == 0);
    CHECK(other.rows.empty());
    CHECK_FALSE(other.truncated);
}

TEST_CASE("routing connections disclose kernel rows omitted by the existing history cap") {
    connection_detail::History history;
    connection_detail::SnapshotObservation observation;
    std::string lines;
    for (unsigned port = 1000; port < 2600; ++port) lines += tcp_line(port);
    std::istringstream input(lines);
    connection_detail::update_history(history, input, {}, 0xffff0000U, 100, &observation);
    REQUIRE(observation.available);
    CHECK(observation.truncated);
    CHECK(history.size() == 1500);
    const auto selected = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.8"});
    CHECK(selected.total == 1500);
    CHECK(selected.rows.size() == 64);
    CHECK(selected.truncated);
    const auto not_observed = connection_detail::select_routing_connections(
        history, observation, {"203.0.113.9"});
    CHECK(not_observed.snapshot_available);
    CHECK(not_observed.total == 0);
    CHECK(not_observed.rows.empty());
    // No match in a partial sample cannot prove absence from the full table.
    CHECK(not_observed.truncated);
}

} // namespace keen_pbr3

#endif // WITH_API
