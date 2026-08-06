#include <doctest/doctest.h>

#include "../src/firewall/firewall_runtime.hpp"
#include "../src/config/config.hpp"
#include "../src/dns/keenetic_dns.hpp"
#include "../src/lists/list_entry_visitor.hpp"

#include <algorithm>
#include <deque>
#include <filesystem>
#include <functional>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>
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
    "Native VPN direct egress covers SSTP L2TP and IKEv1 in both modes") {
    const auto disabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32", "172.16.1.34/31", ""});
    const auto enabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {"172.16.1.33/32", "172.16.1.36/30"});
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
            {"eth3", "172.16.2.33/32"},
            {"eth3", "172.16.2.34/31"},
            {"eth3", "172.16.2.36/30"},
            {"eth3", "172.20.0.1/32"},
            {"eth3", "172.20.0.2/31"},
            {"eth3", "172.20.0.4/30"},
            {"ppp0", "172.16.1.33/32"},
            {"ppp0", "172.16.1.34/31"},
            {"ppp0", "172.16.1.36/30"},
            {"ppp0", "172.16.2.33/32"},
            {"ppp0", "172.16.2.34/31"},
            {"ppp0", "172.16.2.36/30"},
            {"ppp0", "172.20.0.1/32"},
            {"ppp0", "172.20.0.2/31"},
            {"ppp0", "172.20.0.4/30"},
        });
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
// Staging reads daemon state and touches nothing outside this process; the
// commit is the one step that spawns `ipset restore`, `iptables-restore` or
// `nft -f -`, each with a multi-second timeout and its own bounded retry.
// These cases pin that boundary so the commit can later be moved off the
// control loop without the staging silently following it.

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
