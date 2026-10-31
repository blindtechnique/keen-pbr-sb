#include <doctest/doctest.h>
#include "../src/intercept/intercept_runtime.hpp"
#include "../src/intercept/intercept_cleanup.hpp"
#include "../src/firewall/interception_rules.hpp"

using namespace keen_pbr3;

namespace {
class RuntimeWriter final : public nfnl::DynamicSetWriter {
public:
    bool add(const nfnl::SetAdd*, nfnl::SetAddResult*, std::size_t, int) override { return true; }
    int last_errno() const override { return 0; }
};
const std::vector<InterceptListBinding> bindings{{"test", "generation-1", {"kpbr4d_test", "kpbr6d_test", 60}}};
const InterceptDomainReader reader = [](const auto&, const auto& consume) { consume("example.org"); return true; };
const InterceptionRequest enabled{true, true, {"br0"}};
struct Fixture {
    InterceptService* service{};
    unsigned starts{};
    InterceptRuntime runtime{[this] {
        auto result = std::make_unique<InterceptService>(std::make_unique<RuntimeWriter>());
        service = result.get(); return result;
    }, [this](InterceptService& value, const InterceptServiceOptions& options) {
        ++starts;
        CHECK(options.queue_num == InterceptionHooks::queue);
        CHECK(options.nflog_group == InterceptionHooks::group);
        CHECK_FALSE(options.conntrack_cleanup);
        CHECK(options.fail_open);
        value.start({}, nullptr); // no netfilter privileges, real lifecycle/gates
    }};
    auto stage(bool reuse = false) {
        auto update = runtime.begin_update();
        update->prepare(bindings, {}, reader, reuse, enabled);
        return update;
    }
};
}

TEST_CASE("intercept runtime: disabled configuration opens no sockets") {
    Fixture f;
    auto update = f.runtime.begin_update();
    CHECK_FALSE(update->prepare({}, {}, {}, false).any());
    update->commit();
    CHECK(f.starts == 0);
}
TEST_CASE("intercept runtime: cleanup authority publishes only at COMMIT and is revoked at apply or STOP") {
    auto channel = std::make_shared<InterceptCleanupChannel>([] { return true; });
    InterceptService* service = nullptr;
    InterceptRuntime runtime([&] {
        auto result = std::make_unique<InterceptService>(std::make_unique<RuntimeWriter>());
        service = result.get(); return result;
    }, [](InterceptService& value, const InterceptServiceOptions& options) {
        CHECK(options.conntrack_cleanup); value.start({}, nullptr);
    }, channel);
    InterceptSnapshotPolicy policy;
    policy.cleanup = std::make_shared<InterceptCleanupPolicy>();
    const std::array<uint8_t, 16> client{192,168,1,2}, ip{203,0,113,5};
    auto first = runtime.begin_update(); first->prepare(bindings, policy, reader, false, enabled);
    CHECK_FALSE(service->current_snapshot());
    first->commit(); REQUIRE(service->current_snapshot());
    channel->request(service->current_snapshot(), 4, client, ip);
    auto tickets = channel->take(); REQUIRE(tickets.size() == 1); CHECK(tickets[0]->current()); channel->finish();
    auto next = runtime.begin_update(); CHECK_FALSE(tickets[0]->current());
    next->prepare(bindings, policy, reader, true, enabled); next->commit();
    channel->request(service->current_snapshot(), 4, client, ip);
    tickets = channel->take(); REQUIRE(tickets.size() == 1);
    runtime.stop(); CHECK_FALSE(tickets[0]->current()); channel->finish();
    next->commit(); CHECK_FALSE(tickets[0]->current()); CHECK_FALSE(service->running());
}
TEST_CASE("intercept runtime: listener precedes kernel commit, writes follow it") {
    Fixture f;
    auto update = f.stage();
    CHECK(f.starts == 1);
    CHECK(f.service->running());
    CHECK_FALSE(f.service->snapshot_ready());
    update->commit();
    REQUIRE(f.service->current_snapshot());
    CHECK(f.service->current_snapshot()->targets[0].set_v4 == "kpbr4d_test");
    auto next = f.stage(true);
    next->commit();
    CHECK(f.starts == 1); // ordinary refresh never rebinds a live listener
}
TEST_CASE("intercept runtime: aborted kernel publication retires learning authority") {
    Fixture f;
    f.stage()->commit();
    { auto update = f.stage(); }
    CHECK_FALSE(f.service->snapshot_ready());
    CHECK(f.service->running()); // still ACCEPTing DNS, not restarting services
    CHECK_THROWS_AS(f.stage(true), FirewallRulesOnlyError);
    f.stage()->commit();
    CHECK(f.service->snapshot_ready());
}
TEST_CASE("intercept runtime: STOP wins over late commit and permits explicit START") {
    Fixture f;
    auto stale = f.stage();
    f.runtime.stop();
    stale->commit();
    CHECK_FALSE(f.service->running());
    CHECK_FALSE(f.service->snapshot_ready());
    f.stage()->commit();
    REQUIRE(f.service->snapshot_ready());
    stale.reset(); // may not invalidate or use freed state of the new service
    CHECK(f.service->snapshot_ready());
    CHECK(f.starts == 2);
}
TEST_CASE("intercept runtime: removal detaches targets and disable stops listener") {
    Fixture f;
    f.stage()->commit();
    auto update = f.runtime.begin_update();
    CHECK_FALSE(update->prepare({}, {}, {}, true).any());
    update->commit();
    CHECK_FALSE(f.service->running());
    CHECK_FALSE(f.service->current_snapshot());
}
TEST_CASE("intercept runtime: changed source cannot reuse old index") {
    Fixture f;
    f.stage()->commit();
    auto changed = bindings;
    changed[0].content_signature = "generation-2";
    auto update = f.runtime.begin_update();
    CHECK_THROWS_AS(update->prepare(changed, {}, reader, true, enabled), FirewallRulesOnlyError);
}
TEST_CASE("intercept runtime: missing domain data is not a valid empty generation") {
    Fixture f;
    f.stage()->commit();
    auto update = f.runtime.begin_update();
    CHECK_THROWS_AS(update->prepare(bindings, {}, [](const auto&, const auto&) { return false; }, false, enabled), std::runtime_error);
}
TEST_CASE("intercept runtime: busy listener degrades only optional learning") {
    InterceptRuntime runtime([]() -> std::unique_ptr<InterceptService> { throw std::runtime_error("queue busy"); });
    auto update = runtime.begin_update();
    CHECK_FALSE(update->prepare(bindings, {}, reader, false, enabled).any());
    CHECK_NOTHROW(update->commit());
    CHECK(runtime.health().dns_state == "unavailable");
    CHECK(runtime.health().dns_detail == "queue busy");
}

TEST_CASE("interception health: disabled, no interfaces, no lists and STOP are distinct") {
    Fixture f;
    CHECK(f.runtime.health().dns_state == "unknown");
    auto off = f.runtime.begin_update();
    off->prepare({}, {}, {}, false);
    off->commit();
    CHECK(f.runtime.health().dns_state == "disabled");
    auto scopeless = f.runtime.begin_update();
    scopeless->prepare(bindings, {}, reader, false, {true, false, {}});
    scopeless->commit();
    CHECK(f.runtime.health().dns_state == "no_interfaces");
    CHECK(f.runtime.health().l7_state == "disabled");
    auto listless = f.runtime.begin_update();
    listless->prepare({}, {}, reader, false, enabled);
    listless->commit();
    CHECK(f.runtime.health().dns_state == "no_lists");
    CHECK(f.starts == 0);
    f.stage()->commit();
    auto pending = f.stage();
    CHECK(f.runtime.health().dns_state == "applying");
    f.runtime.stop();
    pending->commit();
    pending.reset();
    CHECK(f.runtime.health().dns_state == "stopped");
    CHECK(f.runtime.health().l7_state == "stopped");
    CHECK(f.starts == 1);
}

TEST_CASE("interception health: independent settings bind only requested listeners") {
    std::vector<InterceptServiceOptions> requests;
    InterceptRuntime runtime([] {
        return std::make_unique<InterceptService>(std::make_unique<RuntimeWriter>());
    }, [&](InterceptService& service, const InterceptServiceOptions& options) {
        requests.push_back(options);
        service.start({}, nullptr);
    });
    auto dns = runtime.begin_update();
    dns->prepare(bindings, {}, reader, false, {true, false, {"br0"}});
    dns->commit();
    REQUIRE(requests.size() == 1);
    CHECK(requests.back().queue_num == InterceptionHooks::queue);
    CHECK_FALSE(requests.back().nflog_group);
    CHECK(runtime.health().l7_state == "disabled");
    auto l7 = runtime.begin_update();
    l7->prepare(bindings, {}, reader, false, {false, true, {"br0"}});
    l7->commit();
    REQUIRE(requests.size() == 2);
    CHECK_FALSE(requests.back().queue_num);
    CHECK(requests.back().nflog_group == InterceptionHooks::group);
    CHECK(runtime.health().dns_state == "disabled");
    CHECK(runtime.health().interfaces == std::vector<std::string>{"br0"});
    for (int i = 0; i < 20; ++i) (void)runtime.health();
    CHECK(requests.size() == 2);
}

namespace {
InterceptionHooks capture_hooks(const FirewallGlobalPrefilter& scope,
    const std::vector<InternalVpnRuntimeTarget>& targets = {}, bool ipv6 = false) {
    InterceptionHooks hooks{true, true};
    hooks.client_scope = interception_client_scope(scope, targets, ipv6);
    hooks.interfaces = interception_interfaces(hooks.client_scope);
    return hooks;
}
FirewallGlobalPrefilter lan_scope() {
    FirewallGlobalPrefilter result;
    result.inbound_interfaces = {"br0"};
    return result;
}
InternalVpnRuntimeTarget pooled_target() {
    InternalVpnRuntimeTarget target;
    target.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    target.process_clients = true;
    target.interface = "br7"; // firmware binding is NOT ingress authority
    target.source_cidrs_v4 = {"192.0.2.15/24"};
    target.source_cidrs_v6 = {"2001:db8:12::15/64"};
    target.verified_ingress_interfaces = {"xfrms0"};
    return target;
}
}

TEST_CASE("interception scope: empty or unsafe interfaces never mean WAN capture") {
    FirewallGlobalPrefilter scope;
    CHECK(interception_client_scope(scope).include.empty());
    scope.inbound_interfaces = {"br0", "lo", "wan+", "br0", "bad name", "sstp0", "-bad"};
    scope.bypass_inbound_interfaces = {"sstp0"};
    CHECK(interception_interfaces(interception_client_scope(scope)) == std::vector<std::string>{"br0"});
}

TEST_CASE("interception scope: verified pools are family and ingress specific") {
    auto target = pooled_target();
    auto hooks = capture_hooks({}, {target}, true);
    REQUIRE(hooks.client_scope.include.size() == 2);
    CHECK(hooks.interfaces == std::vector<std::string>{"xfrms0"});
    const auto v4 = interception_iptables_script(hooks, false);
    const auto v6 = interception_iptables_script(hooks, true);
    CHECK(v4.find("-i xfrms0 -s 192.0.2.0/24") != std::string::npos);
    CHECK(v4.find("-o xfrms0 -d 192.0.2.0/24") != std::string::npos);
    CHECK(v4.find("2001:") == std::string::npos);
    CHECK(v4.find("br7") == std::string::npos);
    CHECK(v6.find("-i xfrms0 -s 2001:db8:12::/64") != std::string::npos);
    CHECK(v6.find("192.0.2.") == std::string::npos);
    hooks = capture_hooks({}, {target}, false);
    CHECK(hooks.client_scope.include.size() == 1);
    CHECK(interception_iptables_script(hooks, true).find("NFLOG") == std::string::npos);
    target.verified_ingress_interfaces.clear();
    target.verified_bridge_ingress_interfaces = {{"br7", "sstp0"}};
    CHECK(capture_hooks({}, {target}, true).client_scope.include.empty());
}

TEST_CASE("interception scope: disabled native clients bypass both directions but not the LAN") {
    auto scope = lan_scope();
    scope.bypass_bridge_source_selectors_v4 = {{"br0", "sstp0", "192.0.2.0/24"}};
    scope.bypass_source_selectors_v6 = {{"br0", "2001:db8:12::/64"}};
    // DNS-only REDIRECT bypass must not disable passive capture.
    scope.dns_redirect_bypass_source_selectors_v4 = {{"br0", "198.51.100.0/24"}};
    const auto hooks = capture_hooks(scope, {}, true);
    CHECK(hooks.interfaces == std::vector<std::string>{"br0"});
    const auto v4 = interception_iptables_script(hooks, false);
    CHECK(v4.find("-A KeenPbrL7Tap -i br0 -s 192.0.2.0/24 -j RETURN") < v4.find("-j NFLOG"));
    CHECK(v4.find("-A KeenPbrDnsTap -o br0 -d 192.0.2.0/24 -j RETURN") < v4.find("-j NFQUEUE"));
    CHECK(v4.find("198.51.100.") == std::string::npos);
    CHECK(v4.find("2001:") == std::string::npos);
    const auto v6 = interception_iptables_script(hooks, true);
    CHECK(v6.find("-o br0 -d 2001:db8:12::/64 -j RETURN") < v6.find("-j NFQUEUE"));

    auto target = pooled_target();
    target.process_clients = false;
    scope.inbound_interfaces = {"xfrms0", "br0"};
    const auto disabled = capture_hooks(scope, {target});
    CHECK(interception_iptables_script(disabled, false).find("-i xfrms0 -s 192.0.2.0/24 -j RETURN") != std::string::npos);
}

TEST_CASE("interception scope: invalid pools do not broaden include or weaken exclusions") {
    auto target = pooled_target();
    target.source_cidrs_v4 = {"0.0.0.0/0", "192.0.2.0/33", "bad -j ACCEPT", "::/0"};
    target.source_cidrs_v6 = {"::/0", "2001:db8::/129", "192.0.2.0/24"};
    CHECK(capture_hooks({}, {target}, true).client_scope.include.empty());
    auto scope = lan_scope();
    scope.bypass_source_selectors_v4 = {{"br0", "bad"}};
    const auto hooks = capture_hooks(scope, {}, true);
    REQUIRE(hooks.client_scope.include.size() == 1);
    CHECK(hooks.client_scope.include.front().family == 6);
    CHECK(interception_iptables_script(hooks, false).find("NFLOG") == std::string::npos);
}

TEST_CASE("interception scope: deduplicate explicit LAN and native interface without changing family") {
    InternalVpnRuntimeTarget target;
    target.interface = "br0";
    auto hooks = capture_hooks(lan_scope(), {target, target});
    CHECK(hooks.client_scope.include.size() == 1);
    target.process_clients = false;
    CHECK(capture_hooks(lan_scope(), {target}).client_scope.include.empty());
}

TEST_CASE("interception rules: xtables capture is scoped bounded and non-marking") {
    const auto hooks = capture_hooks(lan_scope());
    const auto rules = interception_iptables_script(hooks, false);
    CHECK(rules.find("--ctdir REPLY -j NFQUEUE --queue-num 43053 --queue-bypass") != std::string::npos);
    CHECK(rules.find("-o br0 -p udp --sport 53") != std::string::npos);
    CHECK(rules.find("-i br0 -p tcp -m multiport --dports 80,443") != std::string::npos);
    CHECK(rules.find("--limit 200/second") != std::string::npos);
    CHECK(rules.find("-A KeenPbrL7Tap -i br0 -j RETURN") > rules.find("-j NFLOG"));
    for (const auto* forbidden : {"DROP", "REJECT", "MARK", "CONNMARK", "-F PREROUTING", "-F POSTROUTING"})
        CHECK(rules.find(forbidden) == std::string::npos);
    const auto disabled = interception_iptables_script({}, false);
    CHECK(disabled.find("NFQUEUE") == std::string::npos);
    CHECK(disabled.find("NFLOG") == std::string::npos);
}

TEST_CASE("interception rules: nft mirrors family address and direction scope") {
    auto hooks = capture_hooks(lan_scope());
    const auto rules = interception_nft_commands(hooks, false);
    REQUIRE(rules.size() == 8);
    const auto text = rules.dump();
    for (const auto* expected : {"postrouting", "bypass", "original", "ipv4"})
        CHECK(text.find(expected) != std::string::npos);
    CHECK(text.find("drop") == std::string::npos);
    CHECK(interception_nft_commands({}, true).empty());
    CHECK(interception_nft_commands(capture_hooks({}), true).empty());
    auto scope = lan_scope();
    scope.bypass_bridge_source_selectors_v4 = {{"br0", "sstp0", "198.51.100.0/24"}};
    hooks = capture_hooks(scope, {pooled_target()}, true);
    const auto expanded = interception_nft_commands(hooks, true);
    const auto& first = expanded.at(2).at("add").at("rule");
    CHECK(first.at("chain") == "KeenPbrDnsTap");
    CHECK(first.at("expr").back().contains("return"));
    CHECK(first.dump().find("daddr") != std::string::npos);
    const auto both = expanded.dump();
    CHECK(both.find("2001:db8:12::") != std::string::npos);
    CHECK(both.find("saddr") != std::string::npos);
    CHECK(both.find("physdev") == std::string::npos);
    CHECK(both.find("br7") == std::string::npos);
    CHECK(interception_nft_commands(hooks, false).dump().find("ipv6") == std::string::npos);
}
