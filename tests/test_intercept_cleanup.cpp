#include <doctest/doctest.h>
#include "../src/intercept/intercept_cleanup.hpp"
#include "../src/daemon/runtime_background_point_mutation.hpp"
#include <map>

using namespace keen_pbr3;
namespace {
struct Writer final : nfnl::DynamicSetWriter {
    bool add(const nfnl::SetAdd*, nfnl::SetAddResult*, size_t, int) override { return true; }
    int last_errno() const override { return 0; }
};
struct CleanupFixture {
    std::shared_ptr<InterceptCleanupPolicy> policy = std::make_shared<InterceptCleanupPolicy>();
    std::shared_ptr<InterceptSnapshot> snapshot = std::make_shared<InterceptSnapshot>();
    std::shared_ptr<InterceptService> service = std::make_shared<InterceptService>(std::make_unique<Writer>());
    std::shared_ptr<InterceptCleanupGrant> grant = std::make_shared<InterceptCleanupGrant>();
    std::shared_ptr<InterceptCleanupTicket> ticket = std::make_shared<InterceptCleanupTicket>();
    ConntrackExactForwardedFlow flow;
    ConntrackFlowObservation observation;
    InterceptCleanupOperations ops;
    InterceptCleanupBatch batch;
    size_t deletes{}, queries{}, observations{};
    bool current{true}, proof{true};
    std::map<std::string, std::optional<bool>> membership;
    CleanupFixture() {
        policy->owned_mask = 0xff0000;
        policy->owned_marks = {0x10000, 0x20000};
        FirewallRuleCriteria criteria;
        criteria.dst_set_name = "kpbr4d_test";
        policy->rules.push_back({criteria, 0x10000});
        policy->learned_sets.insert("kpbr4d_test");
        membership["kpbr4d_test"] = true;
        snapshot->cleanup = policy;
        DomainIndex::Builder index;
        index.add_domain(index.add_list("test"), "example.org");
        snapshot->index = std::make_shared<DomainIndex>(std::move(index).build());
        service->start({}, snapshot);
        grant->snapshot = snapshot; grant->service = service;
        ticket->grant = grant; ticket->client = "192.168.1.2";
        ticket->destinations = {"203.0.113.5"};
        ticket->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        batch = {1, {ticket}};
        flow.source = ticket->client; flow.destination = ticket->destinations[0];
        flow.source_port = 23456; flow.destination_port = 443;
        flow.tcp_state = ConntrackTcpState::Established; flow.zone = 0;
        observation.flows = {flow};
        ops.current = [&] { return current; };
        ops.observe = [&](const auto& destinations, uint32_t mask, const auto& clients) {
            ++observations;
            CHECK(mask == policy->owned_mask);
            CHECK(destinations == ticket->destinations);
            CHECK(clients.count(ticket->client) == 1);
            return observation;
        };
        ops.membership = [&](const auto& set, const auto&) { ++queries; return membership[set]; };
        ops.evidence = [&](const auto&, const auto&, const auto&) { return proof; };
        ops.erase = [&](const auto& candidate, uint32_t mask, uint32_t desired) {
            CHECK(candidate.source == ticket->client); CHECK(candidate.destination == ticket->destinations[0]);
            CHECK(candidate.zone == std::optional<uint16_t>{0}); CHECK(mask == policy->owned_mask); CHECK(desired == 0x10000);
            ++deletes; return ConntrackCleanupResult::Succeeded;
        };
    }
    auto run() { return execute_intercept_cleanup(batch, ops); }
};
}
TEST_CASE("learning cleanup: exact client pair and family only") {
    CleanupFixture f;
    auto other = f.flow; other.source = "192.168.1.3"; f.observation.flows.push_back(other);
    other = f.flow; other.destination = "203.0.113.6"; f.observation.flows.push_back(other);
    other = f.flow; other.family = ConntrackFlowFamily::Ipv6; f.observation.flows.push_back(other);
    CHECK(f.run().attempted == 1); CHECK(f.deletes == 1);
}
TEST_CASE("learning cleanup: preserve correct, foreign and unknown marks") {
    CleanupFixture f;
    SUBCASE("already selected") { f.observation.flows[0].mark = 0x10000; }
    SUBCASE("foreign only") { f.observation.flows[0].mark = 1; }
    SUBCASE("mixed ownership") { f.observation.flows[0].mark = 0x20001; }
    SUBCASE("unconfigured owner") { f.observation.flows[0].mark = 0x30000; }
    CHECK(f.run().attempted == 0);
}
TEST_CASE("learning cleanup: another configured owned mark may be reclassified") {
    CleanupFixture f; f.observation.flows[0].mark = 0x20000;
    CHECK(f.run().attempted == 1);
}
TEST_CASE("learning cleanup: higher priority pass drop static and client VPN win") {
    CleanupFixture f;
    InterceptCleanupRule first;
    first.criteria.src_addr = {"192.168.1.2/32"};
    SUBCASE("pass or drop") { first.mark = 0; }
    SUBCASE("client VPN") { first.mark = 0x20000; }
    SUBCASE("static list") { first.criteria.dst_set_name = "kpbr4S_static"; first.mark = 0x20000; f.membership["kpbr4S_static"] = true; }
    f.policy->rules.insert(f.policy->rules.begin(), first);
    CHECK(f.run().attempted == 0);
}
TEST_CASE("learning cleanup: unknown preceding membership is not absence") {
    CleanupFixture f;
    auto first = f.policy->rules.front(); first.criteria.dst_set_name = "earlier"; first.mark = 0x20000;
    f.policy->rules.insert(f.policy->rules.begin(), first);
    CHECK(f.run().attempted == 0);
    f.membership["earlier"] = false;
    CHECK(f.run().attempted == 1);
}
TEST_CASE("learning cleanup: rule selectors and disabled native pool") {
    CleanupFixture f;
    auto& c = f.policy->rules[0].criteria;
    SUBCASE("source") { c.src_addr = {"192.168.2.0/24"}; }
    SUBCASE("negated source") { c.src_addr = {"192.168.1.0/24"}; c.negate_src_addr = true; }
    SUBCASE("destination") { c.dst_addr = {"198.51.100.0/24"}; }
    SUBCASE("source port") { c.src_port.ranges = {{2000, 3000}}; }
    SUBCASE("destination port") { c.dst_port.ranges = {{443, 443}}; c.negate_dst_port = true; }
    SUBCASE("protocol") { c.proto = L4Proto::Udp; }
    SUBCASE("family") { c.family = AF_INET6; }
    SUBCASE("DSCP unknown") { c.dscp = 16; }
    SUBCASE("no CT mark") { c.persist_conntrack_mark = false; }
    SUBCASE("excluded native client") { f.policy->excluded_clients = {"192.168.1.0/24"}; }
    SUBCASE("invalid prefix") { c.src_addr = {"192.168.1.2/99"}; }
    CHECK(f.run().attempted == 0);
}
TEST_CASE("learning cleanup: IPv6 stays in its own family") {
    CleanupFixture f;
    f.ticket->family = 6; f.ticket->client = "fd00::2"; f.ticket->destinations = {"2001:db8::5"};
    f.observation.flows[0].family = ConntrackFlowFamily::Ipv6;
    f.observation.flows[0].source = f.ticket->client; f.observation.flows[0].destination = f.ticket->destinations[0];
    f.policy->rules[0].criteria.src_addr = {"fd00::/64"};
    CHECK(f.run().attempted == 1);
}
TEST_CASE("learning cleanup: negated address selectors follow each backend's actual rows") {
    CleanupFixture f;
    auto first = f.policy->rules.front();
    first.mark = 0; first.criteria.dst_set_name.reset();
    first.criteria.src_addr = {"192.168.1.2", "192.168.1.3"}; first.criteria.negate_src_addr = true;
    SUBCASE("xtables expands two negated rows") {
        f.policy->split_negated_addresses = true;
        f.policy->rules.insert(f.policy->rules.begin(), first);
        CHECK(f.run().attempted == 0);
    }
    SUBCASE("nft negates a set") {
        f.policy->rules.insert(f.policy->rules.begin(), first);
        CHECK(f.run().attempted == 1);
    }
    SUBCASE("other address family produces no row even when negated") {
        first.criteria.src_addr = {"fd00::2"};
        f.policy->rules.insert(f.policy->rules.begin(), first);
        CHECK(f.run().attempted == 1);
    }
}
TEST_CASE("learning cleanup: stale STOP timeout and observation errors never delete") {
    CleanupFixture f;
    SUBCASE("STOP") { f.service->stop(); }
    SUBCASE("apply entered") { f.grant->active = false; }
    SUBCASE("snapshot superseded") { f.service->update_snapshot(std::make_shared<InterceptSnapshot>(*f.snapshot)); }
    SUBCASE("runtime generation changed") { f.current = false; }
    SUBCASE("deadline") { f.ticket->deadline = {}; }
    SUBCASE("write failed or expired") { f.proof = false; }
    SUBCASE("missing table") { f.observation.snapshot_unavailable = true; }
    SUBCASE("truncated snapshot") { f.observation.snapshot_truncated = true; }
    SUBCASE("flow cap") { f.observation.flow_limit_reached = true; }
    SUBCASE("unknown local scope") { f.observation.local_address_scope_missing = true; }
    SUBCASE("unknown zone") { f.observation.flows[0].zone.reset(); }
    SUBCASE("foreign zone") { f.observation.flows[0].zone = 1; }
    SUBCASE("DNS") { f.observation.flows[0].destination_port = 53; }
    CHECK(f.run().attempted == 0);
}
TEST_CASE("learning cleanup: STOP between observation and erase wins") {
    CleanupFixture f;
    f.ops.membership = [&](const auto&, const auto&) -> std::optional<bool> { f.grant->active = false; return true; };
    CHECK(f.run().attempted == 0);
}
TEST_CASE("learning cleanup: four deletes maximum and no retries") {
    CleanupFixture f;
    for (unsigned p = 1; p < 10; ++p) { auto flow = f.flow; flow.source_port += p; f.observation.flows.push_back(flow); }
    CHECK(f.run().attempted == 4); CHECK(f.deletes == 4); CHECK(f.observations == 1);
}
TEST_CASE("learning cleanup: mailbox coalesces duplicates and fences revoked generations") {
    CleanupFixture f;
    unsigned notifications = 0;
    InterceptCleanupChannel channel([&] { ++notifications; return true; });
    channel.publish(f.service, f.snapshot);
    std::array<uint8_t,16> client{192,168,1,2}, address{203,0,113,5};
    for (unsigned i = 0; i < 100; ++i) channel.request(f.snapshot, 4, client, address);
    CHECK(notifications == 1);
    const auto tickets = channel.take(); REQUIRE(tickets.size() == 1); CHECK(tickets[0]->current());
    channel.revoke(); CHECK_FALSE(tickets[0]->current()); channel.finish();
    channel.request(f.snapshot, 4, client, address); CHECK(channel.take().empty());
    CHECK(notifications == 1);
}
TEST_CASE("learning cleanup: a snapshot without cleanup revokes queued work but keeps learning") {
    CleanupFixture f;
    unsigned notifications = 0;
    InterceptCleanupChannel channel([&] { ++notifications; return true; });
    channel.publish(f.service, f.snapshot);
    std::array<uint8_t,16> client{192,168,1,2}, address{203,0,113,5};
    channel.request(f.snapshot, 4, client, address);
    const auto tickets = channel.take();
    REQUIRE(tickets.size() == 1);
    auto disabled = std::make_shared<InterceptSnapshot>(*f.snapshot);
    disabled->cleanup.reset();
    f.service->update_snapshot(disabled);
    channel.publish(f.service, disabled);
    CHECK_FALSE(tickets.front()->current());
    channel.finish();
    channel.request(disabled, 4, client, address);
    CHECK(channel.take().empty());
    CHECK(notifications == 1);
    CHECK(f.service->running());
    CHECK(f.service->snapshot_ready());
}
TEST_CASE("learning cleanup: typed background owner binds the exact batch") {
    CleanupFixture f;
    RuntimeBackgroundPointMutationTarget target;
    target.kind = RuntimeBackgroundPointMutationKind::intercept_cleanup;
    target.target_serial = 9; target.payload = f.batch;
    CHECK(target.valid()); CHECK(target.runtime_generation() == 1);
    RuntimeBackgroundPointMutationResult result;
    result.target = target; result.worker_started = true; result.completed = true;
    result.payload = InterceptCleanupResult{}; CHECK(result.control_publishable());
    result.mutation_boundary_entered = true; CHECK_FALSE(result.control_publishable());
    result.generation_revalidated = true; CHECK(result.control_publishable());
    std::get<InterceptCleanupResult>(result.payload).attempted = 5; CHECK_FALSE(result.control_publishable());
    std::get<InterceptCleanupBatch>(target.payload).runtime_generation = 2; CHECK(target != result.target);
}
