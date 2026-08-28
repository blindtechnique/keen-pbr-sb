#include <doctest/doctest.h>

#include "../src/firewall/firewall_runtime.hpp"
#include "../src/config/config.hpp"
#include "../src/dns/keenetic_dns.hpp"
#include "../src/lists/list_entry_visitor.hpp"
#include "../src/routing/firewall_state.hpp"
#include "../src/runtime/meta_udp_443_policy.hpp"

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

class RecordingFirewall final : public Firewall {
public:
    explicit RecordingFirewall(
        FirewallBackend backend = FirewallBackend::nftables)
        : backend_(backend) {}

    std::vector<std::string> events;
    std::vector<std::string> marked_destinations;
    std::vector<std::string> loaded_entries;
    std::function<void()> before_first_ipset;
    std::optional<FirewallApplyMode> refuse_apply_mode;
    bool refusal_is_external_repair{false};

    void create_ipset(const std::string&, int, uint32_t) override {
        if (before_first_ipset) {
            auto callback = std::move(before_first_ipset);
            callback();
        }
    }
    void create_udp_peer_set(
        const std::string&, int, uint32_t) override {
        events.push_back("affinity-set");
    }
    bool add_udp_peer(
        const std::string&,
        const std::string&,
        std::uint16_t,
        const std::string&) override {
        return true;
    }
    void create_mark_rule(
        uint32_t, const FirewallRuleCriteria& criteria) override {
        marked_destinations.insert(
            marked_destinations.end(),
            criteria.dst_addr.begin(),
            criteria.dst_addr.end());
        if (criteria.src_udp_peer_set_name.has_value()) {
            events.push_back(criteria.persist_conntrack_mark
                                 ? "affinity-mark-persistent"
                                 : "affinity-mark");
        } else if (!criteria.dst_port.empty()) {
            events.push_back(
                "mark:" + criteria.dst_port.to_config_string());
        } else {
            events.push_back("route-mark");
        }
    }
    void create_output_mark_rule(
        uint32_t, const FirewallRuleCriteria& criteria) override {
        events.push_back(
            "output-mark:" + criteria.dst_port.to_config_string());
    }
    void create_drop_rule(const FirewallRuleCriteria& criteria) override {
        events.push_back(
            "drop:" + criteria.dst_port.to_config_string());
    }
    void create_forward_udp_reject_rule(
        uint32_t expected_fwmark,
        const std::string& dst_set_name,
        std::uint16_t destination_port) override {
        events.push_back(
            "forward-reject:" + std::to_string(destination_port) + ":" +
            dst_set_name + ":" + std::to_string(expected_fwmark));
    }
    void create_dns_redirect_rules() override {
        events.push_back("dns-redirect");
    }
    void create_tunnel_snat_rules(
        const std::vector<std::string>&) override {}
    void create_source_egress_snat_rules(
        const std::vector<FirewallSourceEgressSnatSelector>&) override {}
    OwnedSnatState inspect_owned_snat_state() const override {
        return OwnedSnatState::healthy;
    }
    OwnedForwardUdpRejectState
    inspect_forward_udp_reject_state() const override {
        return OwnedForwardUdpRejectState::healthy;
    }
    void create_pass_rule(const FirewallRuleCriteria&) override {
        events.push_back("pass");
    }
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string&) override {
        return std::make_unique<FunctionalVisitor>(
            [this](EntryType type, std::string_view entry) {
                if (type != EntryType::Domain) {
                    loaded_entries.emplace_back(entry);
                }
            });
    }
    std::vector<FirewallApplyMode> applied_modes;
    void apply(FirewallApplyMode mode) override {
        events.push_back("apply");
        applied_modes.push_back(mode);
        if (refuse_apply_mode == mode) {
            refuse_apply_mode.reset();
            throw FirewallRulesOnlyError(
                "recorded backend refusal",
                refusal_is_external_repair);
        }
    }
    void cleanup() override {}
    FirewallBackend backend() const override {
        return backend_;
    }

private:
    FirewallBackend backend_;
};

class FirewallTempDirectory final {
public:
    FirewallTempDirectory() {
        char pattern[] = "/tmp/keen-pbr-firewall-runtime-XXXXXX";
        const char* value = ::mkdtemp(pattern);
        if (!value) throw std::runtime_error("mkdtemp failed");
        path_ = value;
    }

    ~FirewallTempDirectory() { std::filesystem::remove_all(path_); }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

Config staged_transaction_config();

static_assert(
    std::is_nothrow_swappable_v<std::vector<RuleState>>,
    "the published rule container must support allocation-free swap");
static_assert(
    noexcept(std::declval<FirewallState&>().swap_rules(
        std::declval<std::vector<RuleState>&>())),
    "rule publication must remain noexcept");

TEST_CASE(
    "FirewallState swaps the complete rule snapshot without moving storage") {
    const auto make_rule = [](std::size_t index,
                              std::string outbound,
                              std::uint32_t fwmark) {
        RuleState rule{};
        rule.rule_index = index;
        rule.outbound_tag = std::move(outbound);
        rule.action_type = RuleActionType::Mark;
        rule.fwmark = fwmark;
        return rule;
    };

    FirewallState state;
    state.set_rules({make_rule(1U, "old", 0x00010000U)});
    const auto* old_storage = state.get_rules().data();

    std::vector<RuleState> candidate{
        make_rule(2U, "new-primary", 0x00020000U),
        make_rule(3U, "new-fallback", 0x00030000U),
    };
    const auto* candidate_storage = candidate.data();

    state.swap_rules(candidate);

    REQUIRE(state.get_rules().size() == 2U);
    CHECK(state.get_rules().data() == candidate_storage);
    CHECK(state.get_rules()[0].outbound_tag == "new-primary");
    CHECK(state.get_rules()[1].outbound_tag == "new-fallback");

    REQUIRE(candidate.size() == 1U);
    CHECK(candidate.data() == old_storage);
    CHECK(candidate.front().outbound_tag == "old");
}

TEST_CASE("PPE remains fail-safe off during ordinary firewall staging") {
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall{FirewallBackend::iptables};

    (void)stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets);

    CHECK(firewall.ppe_deoffload_desired().mode ==
          PpeDeoffloadMode::off);
    CHECK_FALSE(firewall.ppe_deoffload_desired().nfqueue_active);
    CHECK(firewall.ppe_deoffload_desired().tcp_ports.empty());
    CHECK_FALSE(firewall.ppe_deoffload_desired().quic_enabled);
}

TEST_CASE("PPE runtime desired comparison ignores diagnostics, not live facts") {
    Config config;
    config.daemon = DaemonConfig{};
    config.daemon->ppe_deoffload_mode = api::PpeDeoffloadMode::AUTO;
    config.daemon->ppe_deoffload_quic_enabled = true;

    NfqwsPpeRuntimeContractObservation observation;
    observation.available = true;
    observation.diagnostic = "first wording";
    observation.contract.available = true;
    observation.contract.queue_number = 301;
    observation.contract.tcp_ranges = {
        {80U, 90U}, {443U, 443U}};
    observation.contract.quic_udp_443 = true;
    const auto desired = ppe_deoffload_desired_from_observation(
        config, observation);
    CHECK(desired.mode == PpeDeoffloadMode::automatic);
    CHECK(desired.nfqueue_number == 301);
    CHECK(desired.tcp_ports ==
          std::vector<std::string>{"80:90", "443"});
    CHECK(desired.quic_443_active);

    auto diagnostic_only = desired;
    diagnostic_only.runtime_contract_detail = "new wording";
    CHECK(ppe_deoffload_desired_semantically_equal(
        desired, diagnostic_only));

    auto queue_changed = diagnostic_only;
    queue_changed.nfqueue_number = 302;
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(
        desired, queue_changed));

    auto process_gone = diagnostic_only;
    process_gone.nfqueue_active = false;
    process_gone.strategy_ports_available = false;
    process_gone.nfqueue_number = -1;
    process_gone.tcp_ports.clear();
    process_gone.quic_443_active = false;
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(
        desired, process_gone));
}

TEST_CASE("late PPE observation cannot reuse a staged live NFQWS tuple") {
    NfqwsPpeRuntimeContractObservation staged_live;
    staged_live.available = true;
    staged_live.contract.available = true;
    staged_live.contract.queue_number = 300;
    staged_live.contract.tcp_ranges = {{443U, 443U}};
    staged_live.contract.quic_udp_443 = true;
    const auto staged = ppe_deoffload_desired_from_observation(
        PpeDeoffloadMode::automatic,
        /*quic_enabled=*/true,
        staged_live);

    NfqwsPpeRuntimeContractObservation late_dead;
    late_dead.diagnostic = "nfqws process is not running";
    const auto dead = ppe_deoffload_desired_from_observation(
        PpeDeoffloadMode::automatic,
        /*quic_enabled=*/true,
        late_dead);
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(staged, dead));
    CHECK_FALSE(dead.nfqueue_active);
    CHECK(build_ppe_deoffload_graph_spec(dead).empty());

    auto queue_changed = staged_live;
    queue_changed.contract.queue_number = 301;
    queue_changed.contract.tcp_ranges = {{80U, 80U}};
    queue_changed.contract.quic_udp_443 = false;
    const auto changed = ppe_deoffload_desired_from_observation(
        PpeDeoffloadMode::automatic,
        /*quic_enabled=*/true,
        queue_changed);
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(
        staged, changed));
    CHECK(changed.nfqueue_number == 301);
    const auto changed_graph = build_ppe_deoffload_graph_spec(changed);
    REQUIRE(changed_graph.tcp_chunks.size() == 1U);
    CHECK(changed_graph.tcp_chunks[0] == "80");
    CHECK_FALSE(changed_graph.quic);
}

TEST_CASE("PPE desired state is returned by value for concurrent health reads") {
    static_assert(!std::is_reference_v<decltype(
        std::declval<const RecordingFirewall&>()
            .ppe_deoffload_desired())>);

    RecordingFirewall firewall;
    PpeDeoffloadDesired desired;
    desired.mode = PpeDeoffloadMode::automatic;
    firewall.set_ppe_deoffload_desired(desired);
    auto copy = firewall.ppe_deoffload_desired();
    firewall.set_ppe_deoffload_desired({});
    CHECK(copy.mode == PpeDeoffloadMode::automatic);
    CHECK(firewall.ppe_deoffload_snapshot().mode == PpeDeoffloadMode::off);
}

class FirewallScopedPath final {
public:
    explicit FirewallScopedPath(const std::filesystem::path& prepend) {
        if (const char* current = std::getenv("PATH")) {
            previous_ = current;
        }

        std::string value = prepend.string();
        if (previous_.has_value() && !previous_->empty()) {
            value += ":" + *previous_;
        }
        if (::setenv("PATH", value.c_str(), 1) != 0) {
            throw std::runtime_error("setenv PATH failed");
        }
    }

    ~FirewallScopedPath() {
        if (previous_.has_value()) {
            (void)::setenv("PATH", previous_->c_str(), 1);
        } else {
            (void)::unsetenv("PATH");
        }
    }

private:
    std::optional<std::string> previous_;
};

void write_successful_nft_probe(const std::filesystem::path& directory) {
    const auto executable = directory / "nft";
    std::ofstream output(executable, std::ios::binary | std::ios::trunc);
    output << "#!/bin/sh\n"
              "while IFS= read -r line; do :; done\n"
              "exit 0\n";
    output.close();
    if (!output || ::chmod(executable.c_str(), 0700) != 0) {
        throw std::runtime_error("failed to create fake nft executable");
    }
}

class FirewallSequenceHttpTransport final : public HttpTransport {
public:
    void enqueue(std::string body) {
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = std::move(body);
        responses_.push_back(std::move(response));
    }

    HttpTransportResponse perform(const HttpTransportRequest&) override {
        if (responses_.empty()) {
            throw std::runtime_error("no queued HTTP response");
        }
        auto response = std::move(responses_.front());
        responses_.pop_front();
        return response;
    }

private:
    std::deque<HttpTransportResponse> responses_;
};

InternalVpnRuntimeTarget service_target(
    std::string stable_id,
    bool process_clients,
    std::vector<std::string> source_cidrs_v4,
    std::vector<std::string> source_cidrs_v6 = {}) {
    InternalVpnRuntimeTarget target;
    target.stable_id = std::move(stable_id);
    target.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    target.process_clients = process_clients;
    target.source_cidrs_v4 = std::move(source_cidrs_v4);
    target.source_cidrs_v6 = std::move(source_cidrs_v6);
    return target;
}

Config keenetic_detour_config() {
    return parse_config(R"json({
      "daemon": {"ipv6_enabled": false},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "dns": {
        "servers": [
          {"tag": "keenetic", "type": "keenetic", "detour": "vpn"}
        ],
        "fallback": ["keenetic"]
      }
    })json");
}

} // namespace

TEST_CASE("iptables capacity changes force one destructive replacement") {
    Config current;
    Config candidate;
    candidate.daemon = DaemonConfig{};
    candidate.daemon->ipset_maxelem = 131072;

    const auto policy = firewall_config_apply_policy(
        FirewallBackend::iptables, current, candidate);
    CHECK(policy.mode == FirewallApplyMode::Destructive);
    CHECK(policy.force_clear_dynamic_sets);
}

TEST_CASE("iptables capacity policy is symmetric for candidate and rollback") {
    Config old_config;
    old_config.daemon = DaemonConfig{};
    old_config.daemon->ipset_hashsize = 1024;
    old_config.daemon->ipset_maxelem = 65536;

    const auto check_round_trip = [&](const Config& candidate) {
        const auto apply = firewall_config_apply_policy(
            FirewallBackend::iptables, old_config, candidate);
        const auto rollback = firewall_config_apply_policy(
            FirewallBackend::iptables, candidate, old_config);
        CHECK(apply.mode == FirewallApplyMode::Destructive);
        CHECK(rollback.mode == apply.mode);
        CHECK(apply.force_clear_dynamic_sets);
        CHECK(rollback.force_clear_dynamic_sets);

        const auto nft_apply = firewall_config_apply_policy(
            FirewallBackend::nftables, old_config, candidate);
        const auto nft_rollback = firewall_config_apply_policy(
            FirewallBackend::nftables, candidate, old_config);
        CHECK(nft_apply.mode == FirewallApplyMode::PreserveSets);
        CHECK(nft_rollback.mode == nft_apply.mode);
        CHECK_FALSE(nft_apply.force_clear_dynamic_sets);
        CHECK_FALSE(nft_rollback.force_clear_dynamic_sets);
    };

    Config changed_hashsize = old_config;
    changed_hashsize.daemon->ipset_hashsize = 2048;
    check_round_trip(changed_hashsize);

    Config changed_maxelem = old_config;
    changed_maxelem.daemon->ipset_maxelem = 131072;
    check_round_trip(changed_maxelem);
}

TEST_CASE("ipset defaults and normalized hashsize preserve existing sets") {
    Config defaults;
    Config explicit_defaults;
    explicit_defaults.daemon = DaemonConfig{};
    explicit_defaults.daemon->ipset_hashsize = 1024;
    explicit_defaults.daemon->ipset_maxelem = 65536;
    const auto unchanged_defaults = firewall_config_apply_policy(
        FirewallBackend::iptables, defaults, explicit_defaults);
    CHECK(unchanged_defaults.mode == FirewallApplyMode::PreserveSets);
    CHECK_FALSE(unchanged_defaults.force_clear_dynamic_sets);

    Config rounded_low;
    rounded_low.daemon = DaemonConfig{};
    rounded_low.daemon->ipset_hashsize = 1536;
    Config rounded_high;
    rounded_high.daemon = DaemonConfig{};
    rounded_high.daemon->ipset_hashsize = 2048;
    const auto unchanged_rounded = firewall_config_apply_policy(
        FirewallBackend::iptables, rounded_low, rounded_high);
    CHECK(unchanged_rounded.mode == FirewallApplyMode::PreserveSets);
    CHECK_FALSE(unchanged_rounded.force_clear_dynamic_sets);

    const auto nftables = firewall_config_apply_policy(
        FirewallBackend::nftables, rounded_low, defaults);
    CHECK(nftables.mode == FirewallApplyMode::PreserveSets);
    CHECK_FALSE(nftables.force_clear_dynamic_sets);
}

TEST_CASE("Runtime firewall consumes one pinned remote-list generation") {
    constexpr const char* url = "https://example.test/remote.txt";
    const auto config = parse_config(R"json({
      "daemon": {"ipv6_enabled": false},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "remote": {"url": "https://example.test/remote.txt"}
      },
      "route": {
        "rules": [
          {"list": ["remote"], "outbound": "vpn"}
        ]
      }
    })json");
    FirewallTempDirectory temporary;
    auto transport = std::make_shared<FirewallSequenceHttpTransport>();
    CacheManager cache(temporary.path(), 1024, transport);
    cache.ensure_dir();
    transport->enqueue("192.0.2.1/32\n");
    REQUIRE(cache.download("remote", url).updated());
    const auto snapshot = cache.capture_generation({"remote"});

    RecordingFirewall firewall;
    firewall.before_first_ipset = [&]() {
        transport->enqueue("192.0.2.2/32\n");
        REQUIRE(cache.download("remote", url).updated());
        transport->enqueue("192.0.2.3/32\n");
        REQUIRE(cache.download("remote", url).updated());
    };
    AppliedListContentState applied;

    CHECK_NOTHROW(apply_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets,
        nullptr,
        nullptr,
        nullptr,
        &applied,
        /*udp_call_affinity_ipset_available=*/true,
        std::nullopt,
        snapshot));

    CHECK(firewall.loaded_entries ==
          std::vector<std::string>{"192.0.2.1/32"});
    REQUIRE(applied.static_destinations.count("remote") == 1U);
    CHECK(applied.static_destinations.at("remote") ==
          std::vector<std::string>{"192.0.2.1/32"});
}

TEST_CASE("Runtime firewall uses the prepared Keenetic DNS snapshot") {
    const auto config = keenetic_detour_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;
    KeeneticDnsSnapshot snapshot;
    snapshot.addresses = {"9.9.9.9:53", "149.112.112.112:5353"};

#ifdef KEEN_PBR3_TESTING
    reset_keenetic_dns_test_state();
    set_keenetic_dns_fetcher_for_tests([]() -> std::string {
        throw KeeneticDnsError("unexpected implicit Keenetic DNS fetch");
    });
#endif

    CHECK_NOTHROW(apply_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        /*udp_call_affinity_ipset_available=*/true,
        snapshot));

    CHECK(
        firewall.marked_destinations ==
        std::vector<std::string>{"9.9.9.9", "149.112.112.112"});
    CHECK(std::find(
              firewall.events.begin(),
              firewall.events.end(),
              "mark:53") != firewall.events.end());
    CHECK(std::find(
              firewall.events.begin(),
              firewall.events.end(),
              "mark:5353") != firewall.events.end());

#ifdef KEEN_PBR3_TESTING
    reset_keenetic_dns_test_state();
#endif
}

TEST_CASE(
    "Runtime firewall rejects Keenetic DNS without a prepared snapshot before mutation") {
    const auto config = keenetic_detour_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;

    CHECK_THROWS_WITH(
        apply_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::PreserveSets),
        "DNS server 'keenetic' requires a prepared Keenetic DNS snapshot");
    CHECK(firewall.events.empty());
    CHECK(firewall.marked_destinations.empty());
}

TEST_CASE(
    "WhatsApp call overlay remains behind user and generated DNS policy") {
    const auto config = parse_config(R"json({
      "daemon": {"ipv6_enabled": false},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "renamed_whatsapp": {
          "catalog_identity":
            "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe",
          "ip_cidrs": ["31.13.64.0/18"]
        }
      },
      "route": {
        "rules": [
          {"list": ["renamed_whatsapp"], "outbound": "vpn"}
        ]
      },
      "dns": {
        "servers": [
          {"tag": "vpn_dns", "address": "1.1.1.1:53", "detour": "vpn"}
        ],
        "client_dns_enforcement": {"enabled": true, "block_dot": true}
      }
    })json");
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;
    firewall.set_fwmark_mask(0x00FF0000U);

    const auto rules = apply_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets);

    REQUIRE(rules.size() == 1U);
    const auto affinity = std::find(
        firewall.events.begin(), firewall.events.end(), "affinity-mark");
    const auto dns_mark = std::find(
        firewall.events.begin(), firewall.events.end(), "mark:53");
    const auto dot_drop = std::find(
        firewall.events.begin(), firewall.events.end(), "drop:853");
    REQUIRE(affinity != firewall.events.end());
    REQUIRE(dns_mark != firewall.events.end());
    REQUIRE(dot_drop != firewall.events.end());
    CHECK(dns_mark < affinity);
    CHECK(dot_drop < affinity);
    CHECK(std::next(affinity) != firewall.events.end());
    CHECK(*std::next(affinity) == "apply");
}

TEST_CASE(
    "Missing optional tuple ipset disables only the iptables call overlay") {
    const auto config = parse_config(R"json({
      "daemon": {"ipv6_enabled": false},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "renamed_whatsapp": {
          "catalog_identity":
            "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe",
          "ip_cidrs": ["31.13.64.0/18"]
        }
      },
      "route": {
        "rules": [
          {"list": ["renamed_whatsapp"], "outbound": "vpn"}
        ]
      }
    })json");
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};

    SUBCASE("iptables keeps ordinary routing and skips affinity") {
        RecordingFirewall firewall{FirewallBackend::iptables};
        firewall.set_fwmark_mask(0x00FF0000U);
        const auto rules = apply_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::PreserveSets,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            /*udp_call_affinity_ipset_available=*/false);

        REQUIRE(rules.size() == 1U);
        CHECK(std::find(
                  firewall.events.begin(),
                  firewall.events.end(),
                  "route-mark") != firewall.events.end());
        CHECK(std::find(
                  firewall.events.begin(),
                  firewall.events.end(),
                  "affinity-set") == firewall.events.end());
        CHECK(firewall.events.back() == "apply");
    }

    SUBCASE("nftables does not depend on the ipset capability") {
        RecordingFirewall firewall{FirewallBackend::nftables};
        firewall.set_fwmark_mask(0x00FF0000U);
        apply_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::PreserveSets,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            /*udp_call_affinity_ipset_available=*/false);

        CHECK(std::find(
                  firewall.events.begin(),
                  firewall.events.end(),
                  "affinity-set") != firewall.events.end());
    }
}

TEST_CASE(
    "Native VPN direct egress covers SSTP OpenConnect L2TP and IKEv1 in both "
    "modes") {
    const auto disabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32", "172.16.1.34/31", ""});
    const auto enabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {"172.16.1.33/32", "172.16.1.36/30"});
    const auto openconnect_disabled = service_target(
        "ndms-service:oc-server",
        /*process_clients=*/false,
        {"172.30.4.17/32", "172.30.4.18/31"});
    const auto openconnect_enabled = service_target(
        "ndms-service:oc-server",
        /*process_clients=*/true,
        {"172.30.4.20/30", "172.16.1.33/32"});
    const auto l2tp_disabled = service_target(
        "ndms-crypto-map:l2tp:VPNL2TPServer",
        /*process_clients=*/false,
        {"172.16.2.33/32", "172.16.2.34/31"});
    const auto l2tp_enabled = service_target(
        "ndms-crypto-map:l2tp:SharedRemoteAccess",
        /*process_clients=*/true,
        {"172.16.2.36/30", "172.16.1.33/32"});
    const auto ikev1_disabled = service_target(
        "ndms-crypto-map:ikev1:VirtualIPServer",
        /*process_clients=*/false,
        {"172.20.0.1/32", "172.20.0.2/31"});
    const auto ikev1_enabled = service_target(
        "ndms-crypto-map:ikev1:SharedIPsecAccess",
        /*process_clients=*/true,
        {"172.20.0.4/30", "172.16.1.33/32"});

    const auto selectors =
        select_native_vpn_direct_egress_snat_selectors(
        {disabled,
         enabled,
         openconnect_disabled,
         openconnect_enabled,
         l2tp_disabled,
         l2tp_enabled,
         ikev1_disabled,
         ikev1_enabled},
        {"eth3", "eth3", "", "ppp0"});

    CHECK(
        selectors ==
        std::vector<FirewallSourceEgressSnatSelector>{
            {"eth3", "172.16.1.33/32"},
            {"eth3", "172.16.1.34/31"},
            {"eth3", "172.16.1.36/30"},
            {"eth3", "172.30.4.17/32"},
            {"eth3", "172.30.4.18/31"},
            {"eth3", "172.30.4.20/30"},
            {"eth3", "172.16.2.33/32"},
            {"eth3", "172.16.2.34/31"},
            {"eth3", "172.16.2.36/30"},
            {"eth3", "172.20.0.1/32"},
            {"eth3", "172.20.0.2/31"},
            {"eth3", "172.20.0.4/30"},
            {"ppp0", "172.16.1.33/32"},
            {"ppp0", "172.16.1.34/31"},
            {"ppp0", "172.16.1.36/30"},
            {"ppp0", "172.30.4.17/32"},
            {"ppp0", "172.30.4.18/31"},
            {"ppp0", "172.30.4.20/30"},
            {"ppp0", "172.16.2.33/32"},
            {"ppp0", "172.16.2.34/31"},
            {"ppp0", "172.16.2.36/30"},
            {"ppp0", "172.20.0.1/32"},
            {"ppp0", "172.20.0.2/31"},
            {"ppp0", "172.20.0.4/30"},
        });
}

TEST_CASE(
    "Meta UDP 443 messages-first policy requires packaged provenance and an active broad route") {
    constexpr const char* identity =
        "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe";
    const auto config = parse_config(std::string{R"json({
      "daemon": {
        "ipv6_enabled": false,
        "meta_udp443_policy": "messages_first"
      },
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "meta_domains": {"domains": ["whatsapp.com"]},
        "renamed_companion": {
          "catalog_identity": ")json"} + identity + R"json(",
          "ip_cidrs": ["31.13.64.0/18"]
        },
        "spoofed_whatsapp_ip": {"ip_cidrs": ["157.240.0.0/16"]}
      },
      "route": {
        "rules": [
          {
            "list": ["meta_domains", "renamed_companion", "spoofed_whatsapp_ip"],
            "outbound": "vpn"
          }
        ]
      }
    })json");
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;
    firewall.set_fwmark_mask(0x00FF0000U);

    apply_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets);

    const std::string expected =
        "forward-reject:443:kpbr4_renamed_companion:458752";
    CHECK(std::count(
              firewall.events.begin(), firewall.events.end(), expected) == 1);
    CHECK(std::none_of(
        firewall.events.begin(), firewall.events.end(),
        [](const std::string& event) {
            return event.find("spoofed_whatsapp_ip") != std::string::npos ||
                   event.find("meta_domains") != std::string::npos;
        }));

    RuleState pass;
    pass.rule_index = 0U;
    pass.action_type = RuleActionType::Pass;
    RuleState authoritative_mark;
    authoritative_mark.rule_index = 1U;
    authoritative_mark.list_names = {"renamed_companion"};
    authoritative_mark.set_names = {"kpbr4s_renamed_companion"};
    authoritative_mark.outbound_tag = "vpn";
    authoritative_mark.action_type = RuleActionType::Mark;
    authoritative_mark.fwmark = 0x00070000U;
    const auto ordered_selection = resolve_meta_udp_443_policy_selection(
        config,
        {pass, authoritative_mark},
        0x00FF0000U);
    REQUIRE(ordered_selection.active());
    CHECK_FALSE(ordered_selection.allow_unmarked_cleanup);
}

TEST_CASE(
    "Meta UDP 443 policy is off by default and ignores an installed unused companion") {
    const auto make_config = [](bool messages_first,
                                const std::string& active_list) {
        return parse_config(std::string{R"json({
      "daemon": {"ipv6_enabled": false)json"} +
            (messages_first
                 ? ", \"meta_udp443_policy\": \"messages_first\""
                 : "") + R"json(},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "companion": {
          "catalog_identity":
            "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe",
          "ip_cidrs": ["31.13.64.0/18"]
        },
        "ordinary": {"ip_cidrs": ["203.0.113.0/24"]}
      },
      "route": {"rules": [{"list": [")json" + active_list +
            R"json("], "outbound": "vpn"}]}
    })json");
    };
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};

    SUBCASE("omitted policy remains balanced") {
        const auto config = make_config(false, "companion");
        RecordingFirewall firewall;
        apply_runtime_firewall(
            config, {{"vpn", 0x00070000U}}, {}, cache, firewall,
            FirewallApplyMode::PreserveSets);
        CHECK(std::none_of(
            firewall.events.begin(), firewall.events.end(),
            [](const std::string& event) {
                return event.rfind("forward-reject:", 0U) == 0U;
            }));
    }

    SUBCASE("unused companion does not authorize an ordinary active list") {
        const auto config = make_config(true, "ordinary");
        RecordingFirewall firewall;
        apply_runtime_firewall(
            config, {{"vpn", 0x00070000U}}, {}, cache, firewall,
            FirewallApplyMode::PreserveSets);
        CHECK(std::none_of(
            firewall.events.begin(), firewall.events.end(),
            [](const std::string& event) {
                return event.rfind("forward-reject:", 0U) == 0U;
            }));
    }
}

TEST_CASE(
    "Meta UDP 443 messages-first rejects IPv6 without authoritative companion coverage") {
    FirewallTempDirectory tools;
    write_successful_nft_probe(tools.path());
    FirewallScopedPath path(tools.path());

    const auto config = parse_config(R"json({
      "daemon": {
        "ipv6_enabled": true,
        "meta_udp443_policy": "messages_first"
      },
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "companion": {
          "catalog_identity":
            "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe",
          "ip_cidrs": ["31.13.64.0/18"]
        }
      },
      "route": {
        "rules": [{"list": ["companion"], "outbound": "vpn"}]
      }
    })json");
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;
    firewall.set_fwmark_mask(0x00FF0000U);

    CHECK_THROWS_WITH(
        stage_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::PreserveSets),
        "daemon.meta_udp443_policy=messages_first cannot be enabled while "
        "IPv6 is active because the packaged Meta/WhatsApp companion has no "
        "authoritative IPv6 coverage; use balanced mode or disable IPv6");
    CHECK(firewall.applied_modes.empty());
    CHECK(std::none_of(
        firewall.events.begin(), firewall.events.end(),
        [](const std::string& event) {
            return event.rfind("forward-reject:", 0U) == 0U;
        }));
}

TEST_CASE(
    "Meta UDP 443 validates the family coverage actually streamed into pending sets") {
    FirewallTempDirectory tools;
    write_successful_nft_probe(tools.path());
    FirewallScopedPath path(tools.path());

    constexpr const char* url = "https://example.test/whatsapp-ip.txt";
    constexpr const char* identity =
        "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe";
    const auto config = parse_config(std::string{R"json({
      "daemon": {
        "ipv6_enabled": true,
        "meta_udp443_policy": "messages_first"
      },
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "companion": {
          "catalog_identity": ")json"} + identity + R"json(",
          "url": ")json" + url + R"json("
        }
      },
      "route": {
        "rules": [{"list": ["companion"], "outbound": "vpn"}]
      }
    })json");
    FirewallTempDirectory temporary;
    auto transport = std::make_shared<FirewallSequenceHttpTransport>();
    CacheManager cache(temporary.path(), 1024, transport);
    cache.ensure_dir();
    transport->enqueue("31.13.64.0/18\n2a03:2880::/32\n");
    REQUIRE(cache.download("companion", url).updated());

    RecordingFirewall firewall;
    firewall.set_fwmark_mask(0x00FF0000U);
    firewall.before_first_ipset = [&]() {
        // Simulate the atomic URL-cache replacement that can happen between
        // the planning pass and the actual set-loader pass.
        transport->enqueue("31.13.64.0/18\n");
        REQUIRE(cache.download("companion", url).updated());
    };

    CHECK_THROWS_WITH(
        stage_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::PreserveSets),
        "daemon.meta_udp443_policy=messages_first cannot be enabled while "
        "IPv6 is active because the packaged Meta/WhatsApp companion has no "
        "authoritative IPv6 coverage; use balanced mode or disable IPv6");
    CHECK(std::none_of(
        firewall.events.begin(), firewall.events.end(),
        [](const std::string& event) {
            return event.rfind("forward-reject:", 0U) == 0U;
        }));
    CHECK(firewall.applied_modes.empty());
}

TEST_CASE(
    "Meta UDP 443 policy fails closed when authoritative companions resolve to different marks") {
    const auto config = parse_config(R"json({
      "daemon": {
        "ipv6_enabled": false,
        "meta_udp443_policy": "messages_first"
      },
      "outbounds": [
        {"tag": "first", "type": "interface", "interface": "nwg0"},
        {"tag": "second", "type": "interface", "interface": "nwg1"}
      ],
      "lists": {
        "first_companion": {
          "catalog_identity":
            "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe",
          "ip_cidrs": ["31.13.64.0/18"]
        },
        "second_companion": {
          "catalog_identity":
            "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe",
          "ip_cidrs": ["157.240.0.0/16"]
        }
      },
      "route": {"rules": [
        {"list": ["first_companion"], "outbound": "first"},
        {"list": ["second_companion"], "outbound": "second"}
      ]}
    })json");
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;
    firewall.set_fwmark_mask(0x00FF0000U);

    CHECK_THROWS_WITH(
        stage_runtime_firewall(
            config,
            {{"first", 0x00070000U}, {"second", 0x00080000U}},
            {}, cache, firewall, FirewallApplyMode::PreserveSets),
        "daemon.meta_udp443_policy=messages_first requires the authoritative "
        "Meta/WhatsApp IP companion to resolve to one unambiguous active broad route");
    CHECK(firewall.applied_modes.empty());
}

TEST_CASE(
    "Meta UDP 443 activation cleanup selects only exact UDP 443 zero or expected owned marks") {
    const auto flow = [](ConntrackFlowProtocol protocol,
                         std::uint16_t destination_port,
                         std::uint32_t mark,
                         std::uint16_t source_port) {
        ConntrackExactForwardedFlow value;
        value.family = ConntrackFlowFamily::Ipv4;
        value.protocol = protocol;
        value.source = "192.168.1.44";
        value.destination = "31.13.66.10";
        value.source_port = source_port;
        value.destination_port = destination_port;
        value.mark = mark;
        if (protocol == ConntrackFlowProtocol::Tcp) {
            value.tcp_state = ConntrackTcpState::Established;
        }
        return value;
    };
    ConntrackFlowObservation observation;
    observation.media_seed_flows = {
        flow(ConntrackFlowProtocol::Udp, 443U, 0U, 50000U),
        // Expected owned mark plus foreign QoS bits remains exact and safe.
        flow(ConntrackFlowProtocol::Udp, 443U, 0xA0070000U, 50001U),
        // A foreign-only mark is an intentional skip_marked_packets bypass.
        flow(ConntrackFlowProtocol::Udp, 443U, 0xA0000000U, 50005U),
        // A previously committed messages-first route mark is eligible only
        // when the transition explicitly carries that exact authority.
        flow(ConntrackFlowProtocol::Udp, 443U, 0x00060000U, 50006U),
        flow(ConntrackFlowProtocol::Udp, 443U, 0x00080000U, 50002U),
        flow(ConntrackFlowProtocol::Udp, 3478U, 0x00070000U, 50003U),
        flow(ConntrackFlowProtocol::Tcp, 443U, 0x00070000U, 50004U),
    };

    const auto candidates = select_meta_udp_443_cleanup_candidates(
        observation, {0x00070000U}, 0x00FF0000U);
    REQUIRE(candidates.complete);
    REQUIRE(candidates.flows.size() == 2U);
    CHECK(candidates.flows[0].source_port == 50000U);
    CHECK(candidates.flows[1].source_port == 50001U);

    const auto route_mark_transition =
        select_meta_udp_443_cleanup_candidates(
            observation,
            {0x00060000U, 0x00070000U},
            0x00FF0000U);
    REQUIRE(route_mark_transition.complete);
    REQUIRE(route_mark_transition.flows.size() == 3U);
    CHECK(route_mark_transition.flows[2].source_port == 50006U);

    const auto marked_only = select_meta_udp_443_cleanup_candidates(
        observation,
        {0x00070000U},
        0x00FF0000U,
        /*allow_unmarked_cleanup=*/false);
    REQUIRE(marked_only.complete);
    REQUIRE(marked_only.flows.size() == 1U);
    CHECK(marked_only.flows.front().source_port == 50001U);

    observation.snapshot_truncated = true;
    const auto incomplete = select_meta_udp_443_cleanup_candidates(
        observation, {0x00070000U}, 0x00FF0000U);
    CHECK_FALSE(incomplete.complete);
    CHECK(incomplete.flows.empty());
}

TEST_CASE(
    "Native VPN direct egress IDs are strict and leave stable paths out") {
    const auto ikev2 = service_target(
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2",
        /*process_clients=*/true,
        {"172.20.8.0/23"});
    const auto wireguard = service_target(
        "ndms-interface:Wireguard0",
        /*process_clients=*/true,
        {"10.10.0.0/24"});
    const auto similarly_named = service_target(
        "ndms-service:sstp-server-backup",
        /*process_clients=*/false,
        {"172.30.0.0/24"});
    const auto similarly_named_openconnect = service_target(
        "ndms-service:oc-server-backup",
        /*process_clients=*/true,
        {"172.30.4.0/24"});
    const auto empty_l2tp_name = service_target(
        "ndms-crypto-map:l2tp:",
        /*process_clients=*/true,
        {"172.31.0.0/24"});
    const auto wrong_l2tp_namespace = service_target(
        "ndms-crypto-map:l2tp-backup:VPNL2TPServer",
        /*process_clients=*/true,
        {"172.31.1.0/24"});
    const auto empty_ikev1_name = service_target(
        "ndms-crypto-map:ikev1:",
        /*process_clients=*/true,
        {"172.31.3.0/24"});
    const auto wrong_ikev1_namespace = service_target(
        "ndms-crypto-map:ikev1-backup:VirtualIPServer",
        /*process_clients=*/true,
        {"172.31.4.0/24"});
    const auto generic_ike_namespace = service_target(
        "ndms-crypto-map:ike:VirtualIPServer",
        /*process_clients=*/true,
        {"172.31.5.0/24"});
    const auto case_variant_ikev1 = service_target(
        "ndms-crypto-map:IKEV1:VirtualIPServer",
        /*process_clients=*/true,
        {"172.31.7.0/24"});
    const auto ikev1_ipv6_only = service_target(
        "ndms-crypto-map:ikev1:IPv6Only",
        /*process_clients=*/true,
        {},
        {"2001:db8:20::/64"});
    const auto legacy_l2tp_interface = service_target(
        "ndms-interface:L2TP0",
        /*process_clients=*/true,
        {"172.31.2.0/24"});
    const auto legacy_ipsec_interface = service_target(
        "ndms-interface:Ipsec0",
        /*process_clients=*/true,
        {"172.31.6.0/24"});
    const auto sstp_ipv6_only = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {},
        {"2001:db8:16::/64"});

    CHECK(
        select_native_vpn_direct_egress_snat_selectors(
            {ikev2,
             wireguard,
             similarly_named,
             similarly_named_openconnect,
             empty_l2tp_name,
             wrong_l2tp_namespace,
             empty_ikev1_name,
             wrong_ikev1_namespace,
             generic_ike_namespace,
             case_variant_ikev1,
             ikev1_ipv6_only,
             legacy_l2tp_interface,
             legacy_ipsec_interface,
             sstp_ipv6_only},
            {"eth3"})
            .empty());
}

TEST_CASE("Native VPN direct egress selection requires a current WAN") {
    const auto sstp = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32"});

    CHECK(
        select_native_vpn_direct_egress_snat_selectors(
            {sstp}, {})
            .empty());
}

TEST_CASE(
    "Native VPN direct egress cleanup changes only affected source pools") {
    const std::vector<FirewallSourceEgressSnatSelector> sstp{
        {"eth3", "172.16.1.32/27"}};
    const std::vector<FirewallSourceEgressSnatSelector> with_l2tp{
        {"eth3", "172.16.1.32/27"},
        {"eth3", "172.16.2.32/27"}};

    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            sstp, with_l2tp) ==
        std::vector<std::string>{"172.16.2.32/27"});
    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            with_l2tp,
            {{"eth3", "172.16.2.32/27"},
             {"eth3", "172.16.1.32/27"}})
            .empty());
}

TEST_CASE(
    "Native VPN direct egress cleanup tracks pool and WAN changes exactly") {
    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            {{"eth3", "172.16.2.32/27"}},
            {{"eth3", "172.16.2.64/27"}}) ==
        std::vector<std::string>{
            "172.16.2.32/27", "172.16.2.64/27"});
    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            {{"eth3", "172.16.2.32/27"}},
            {{"ppp0", "172.16.2.32/27"}}) ==
        std::vector<std::string>{"172.16.2.32/27"});
}

// --- Seam between staging and commit -----------------------------------
//
// Staging fills backend buffers and may inspect or repair kernel state. Meta
// UDP/443 filter publication and exact conntrack deletion remain behind the
// specialized preflight/commit boundary. These cases keep that transaction
// seam explicit without pretending staging is process-local or non-blocking.

namespace {

Config staged_transaction_config() {
    return parse_config(R"json({
      "daemon": {"ipv6_enabled": false},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "lists": {
        "seam": {"ip_cidrs": ["198.51.100.0/24"]}
      },
      "route": {
        "rules": [
          {"list": ["seam"], "outbound": "vpn"}
        ]
      }
    })json");
}

}  // namespace

TEST_CASE("staging builds the whole transaction without committing it") {
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;

    const auto staged = stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets);

    // The transaction is fully described...
    CHECK(!firewall.events.empty());
    CHECK(!staged.rule_states.empty());
    // ...and nothing has been handed to the kernel yet.
    CHECK(std::find(firewall.events.begin(), firewall.events.end(), "apply") ==
          firewall.events.end());
    CHECK(firewall.applied_modes.empty());

    commit_runtime_firewall(firewall, staged);

    REQUIRE(!firewall.events.empty());
    CHECK(firewall.events.back() == "apply");
    CHECK(std::count(firewall.events.begin(), firewall.events.end(), "apply") ==
          1);
}

TEST_CASE("worker staging needs only a pinned list generation") {
    const auto config = staged_transaction_config();
    FirewallTempDirectory temp;
    std::shared_ptr<const ListCacheGenerationSnapshot> snapshot;
    {
        CacheManager cache{temp.path() / "cache", 1024};
        cache.ensure_dir();
        snapshot = cache.capture_generation({"seam"});
    }
    RecordingFirewall firewall;

    const auto staged = stage_runtime_firewall_from_snapshot(
        config,
        {{"vpn", 0x00070000U}},
        {},
        1024,
        snapshot,
        firewall,
        FirewallApplyMode::PreserveSets);

    CHECK(!staged.rule_states.empty());
    CHECK(firewall.loaded_entries ==
          std::vector<std::string>{"198.51.100.0/24"});
    CHECK(firewall.applied_modes.empty());
}

TEST_CASE("commit uses the mode the transaction was staged with") {
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;

    const auto staged = stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        firewall,
        FirewallApplyMode::PreserveSets);
    CHECK(staged.mode == FirewallApplyMode::PreserveSets);

    commit_runtime_firewall(firewall, staged);

    REQUIRE(firewall.applied_modes.size() == 1U);
    // Staging one mode and committing another would build one transaction and
    // publish a different one.
    CHECK(firewall.applied_modes.front() == FirewallApplyMode::PreserveSets);
}

TEST_CASE("runtime firewall commit has one owned RulesOnly fallback") {
    RecordingFirewall firewall;
    firewall.refuse_apply_mode = FirewallApplyMode::RulesOnly;
    firewall.refusal_is_external_repair = true;

    StagedRuntimeFirewall initial;
    initial.mode = FirewallApplyMode::RulesOnly;
    std::size_t fallback_calls = 0U;
    bool observed_external_repair = false;

    const auto committed =
        commit_runtime_firewall_with_rules_only_fallback(
            firewall,
            std::move(initial),
            [&](const FirewallRulesOnlyError& error) {
                ++fallback_calls;
                observed_external_repair = error.external_repair();
                StagedRuntimeFirewall fallback;
                fallback.mode = FirewallApplyMode::PreserveSets;
                return fallback;
            });

    CHECK(fallback_calls == 1U);
    CHECK(observed_external_repair);
    CHECK(committed.mode == FirewallApplyMode::PreserveSets);
    REQUIRE(firewall.applied_modes.size() == 2U);
    CHECK(firewall.applied_modes[0] == FirewallApplyMode::RulesOnly);
    CHECK(firewall.applied_modes[1] == FirewallApplyMode::PreserveSets);
}

TEST_CASE("runtime firewall commit never retries a non-RulesOnly transaction") {
    RecordingFirewall firewall;
    firewall.refuse_apply_mode = FirewallApplyMode::PreserveSets;

    StagedRuntimeFirewall staged;
    staged.mode = FirewallApplyMode::PreserveSets;
    std::size_t fallback_calls = 0U;

    CHECK_THROWS_AS(
        commit_runtime_firewall_with_rules_only_fallback(
            firewall,
            std::move(staged),
            [&](const FirewallRulesOnlyError&) {
                ++fallback_calls;
                return StagedRuntimeFirewall{};
            }),
        FirewallRulesOnlyError);
    CHECK(fallback_calls == 0U);
    REQUIRE(firewall.applied_modes.size() == 1U);
    CHECK(firewall.applied_modes.front() ==
          FirewallApplyMode::PreserveSets);
}

TEST_CASE("staging then committing equals the single-shot apply") {
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};

    RecordingFirewall split;
    const auto staged = stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        split,
        FirewallApplyMode::Destructive);
    commit_runtime_firewall(split, staged);

    RecordingFirewall single;
    AppliedListContentState single_content;
    const auto rules = apply_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        single,
        FirewallApplyMode::Destructive,
        nullptr,
        nullptr,
        nullptr,
        &single_content);

    CHECK(split.events == single.events);
    CHECK(split.applied_modes == single.applied_modes);
    CHECK(split.marked_destinations == single.marked_destinations);
    CHECK(staged.rule_states.size() == rules.size());
}

TEST_CASE("a transaction rejected during staging never reaches the backend") {
    const auto config = keenetic_detour_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;

    CHECK_THROWS_WITH(
        stage_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::PreserveSets),
        "DNS server 'keenetic' requires a prepared Keenetic DNS snapshot");
    CHECK(firewall.events.empty());
    CHECK(firewall.applied_modes.empty());
}

TEST_CASE("RulesOnly refuses to stage without a previous transaction") {
    // Nothing to reuse means nothing safe to skip: the error is the
    // contract the daemon's fallback relies on, not a crash.
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall firewall;

    CHECK_THROWS_AS(
        stage_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            firewall,
            FirewallApplyMode::RulesOnly),
        FirewallRulesOnlyError);
    CHECK(firewall.loaded_entries.empty());
    CHECK(firewall.applied_modes.empty());
}

TEST_CASE("RulesOnly reuses the previous transaction and streams nothing") {
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};

    // First, the ordinary transaction: it streams the inline list and tells
    // us what it learned.
    RecordingFirewall first;
    const auto full = stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        first,
        FirewallApplyMode::PreserveSets);
    REQUIRE(!first.loaded_entries.empty());
    REQUIRE(full.list_usage.count("seam") == 1);
    REQUIRE(full.list_content_state.static_destinations.count("seam") == 1);

    // Then the refresh that reuses it.
    RecordingFirewall refresh;
    PreviousRuntimeFirewall previous;
    previous.rule_states = &full.rule_states;
    previous.list_usage = &full.list_usage;
    previous.list_content_state = &full.list_content_state;
    const auto reused = stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        refresh,
        FirewallApplyMode::RulesOnly,
        nullptr, nullptr, nullptr,
        true,
        std::nullopt,
        nullptr,
        false,
        previous);

    // No entry reached a loader: the sets were not touched.
    CHECK(refresh.loaded_entries.empty());
    // But the rules still name the same sets, in the same shape.
    REQUIRE(reused.rule_states.size() == full.rule_states.size());
    CHECK(reused.rule_states.front().set_names ==
          full.rule_states.front().set_names);
    CHECK(reused.mode == FirewallApplyMode::RulesOnly);
    // And the content companions are carried over untouched: a refresh that
    // read nothing has nothing new to say about what the lists contain.
    CHECK(reused.list_content_state.static_destinations ==
          full.list_content_state.static_destinations);
    CHECK(reused.list_usage.count("seam") == 1);
}

TEST_CASE("RulesOnly refuses a previous transaction that does not match") {
    const auto config = staged_transaction_config();
    CacheManager cache{"/nonexistent/keen-pbr-test-cache"};
    RecordingFirewall first;
    auto full = stage_runtime_firewall(
        config,
        {{"vpn", 0x00070000U}},
        {},
        cache,
        first,
        FirewallApplyMode::PreserveSets);

    // The realized state names a different list for rule 0 - the kind of
    // drift a config change would leave behind. Reusing it would point the
    // rules at sets the kernel never loaded for this list.
    full.rule_states.front().list_names = {"somebody_else"};
    RecordingFirewall refresh;
    PreviousRuntimeFirewall previous;
    previous.rule_states = &full.rule_states;
    previous.list_usage = &full.list_usage;
    previous.list_content_state = &full.list_content_state;
    CHECK_THROWS_AS(
        stage_runtime_firewall(
            config,
            {{"vpn", 0x00070000U}},
            {},
            cache,
            refresh,
            FirewallApplyMode::RulesOnly,
            nullptr, nullptr, nullptr,
            true,
            std::nullopt,
            nullptr,
            false,
            previous),
        FirewallRulesOnlyError);
    CHECK(refresh.loaded_entries.empty());
}
