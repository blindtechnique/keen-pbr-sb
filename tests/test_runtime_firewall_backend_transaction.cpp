#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_backend_transaction.hpp"
#include "../src/lists/list_entry_visitor.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

class BackendTransactionTempDirectory final {
public:
    BackendTransactionTempDirectory() {
        char pattern[] = "/tmp/keen-pbr-backend-transaction-XXXXXX";
        const char* value = ::mkdtemp(pattern);
        if (!value) throw std::runtime_error("mkdtemp failed");
        path_ = value;
    }

    ~BackendTransactionTempDirectory() {
        std::filesystem::remove_all(path_);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

class BackendTransactionFirewall final : public Firewall {
public:
    std::vector<FirewallApplyMode> prepared_modes;
    std::vector<FirewallApplyMode> applied_modes;
    std::optional<FirewallApplyMode> transient_stage_mode;
    bool refuse_rules_only_commit{false};
    bool refuse_preserve_sets_commit{false};
    bool refusal_is_external_repair{false};

    void prepare_apply(FirewallApplyMode mode) override {
        prepared_modes.push_back(mode);
        if (transient_stage_mode == mode) {
            throw TransientFirewallError("recorded transient stage failure");
        }
    }

    void create_ipset(const std::string&, int, std::uint32_t) override {}
    void create_udp_peer_set(
        const std::string&, int, std::uint32_t) override {}
    bool add_udp_peer(
        const std::string&,
        const std::string&,
        std::uint16_t,
        const std::string&) override {
        return true;
    }
    void create_mark_rule(
        std::uint32_t, const FirewallRuleCriteria&) override {}
    void create_output_mark_rule(
        std::uint32_t, const FirewallRuleCriteria&) override {}
    void create_drop_rule(const FirewallRuleCriteria&) override {}
    void create_forward_udp_reject_rule(
        std::uint32_t, const std::string&, std::uint16_t) override {}
    void create_dns_redirect_rules() override {}
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
    void create_pass_rule(const FirewallRuleCriteria&) override {}
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string&) override {
        return std::make_unique<FunctionalVisitor>(
            [](EntryType, std::string_view) {});
    }

    void apply(FirewallApplyMode mode) override {
        applied_modes.push_back(mode);
        const bool refuse =
            (mode == FirewallApplyMode::RulesOnly &&
             refuse_rules_only_commit) ||
            (mode == FirewallApplyMode::PreserveSets &&
             refuse_preserve_sets_commit);
        if (refuse) {
            throw FirewallRulesOnlyError(
                "recorded commit refusal",
                refusal_is_external_repair);
        }
    }

    void cleanup() override {}
    FirewallBackend backend() const override {
        return FirewallBackend::nftables;
    }
};

Config direct_transaction_config() {
    return parse_config(R"json({
      "daemon": {"ipv6_enabled": false},
      "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "nwg0"}
      ],
      "route": {
        "rules": [
          {"dest_addr": "198.51.100.0/24", "outbound": "vpn"}
        ]
      }
    })json");
}

Config list_transaction_config() {
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

RuntimeFirewallBackendTransactionInput transaction_input(
    const std::filesystem::path& cache_path,
    Config config,
    FirewallApplyMode mode,
    std::vector<std::string> captured_lists = {}) {
    CacheManager cache{cache_path, 4096};
    cache.ensure_dir();

    RuntimeFirewallBackendTransactionInput input;
    input.operation_serial = 17U;
    input.config_generation = 23U;
    input.config = std::move(config);
    input.outbound_marks = {{"vpn", 0x00070000U}};
    input.list_max_file_size_bytes = cache.max_file_size();
    input.list_cache_snapshot =
        cache.capture_generation(captured_lists);
    input.requested_mode = mode;
    return input;
}

} // namespace

TEST_CASE("backend transaction returns one owned committed value") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        direct_transaction_config(),
        FirewallApplyMode::PreserveSets);
    BackendTransactionFirewall firewall;

    const auto result =
        execute_runtime_firewall_backend_transaction(input, firewall);

    CHECK(result.committed());
    CHECK(result.operation_serial == 17U);
    CHECK(result.config_generation == 23U);
    CHECK_FALSE(result.failure.has_value());
    CHECK_FALSE(result.rules_only_fallback.has_value());
    REQUIRE(result.committed_firewall.has_value());
    CHECK(result.committed_firewall->mode ==
          FirewallApplyMode::PreserveSets);
    CHECK(firewall.prepared_modes ==
          std::vector<FirewallApplyMode>{FirewallApplyMode::PreserveSets});
    CHECK(firewall.applied_modes ==
          std::vector<FirewallApplyMode>{FirewallApplyMode::PreserveSets});
}

TEST_CASE("backend transaction repairs one RulesOnly staging refusal") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        list_transaction_config(),
        FirewallApplyMode::RulesOnly,
        {"seam"});
    BackendTransactionFirewall firewall;

    const auto result =
        execute_runtime_firewall_backend_transaction(input, firewall);

    CHECK(result.committed());
    REQUIRE(result.rules_only_fallback.has_value());
    CHECK(result.rules_only_fallback->refused_phase ==
          RuntimeFirewallBackendTransactionPhase::initial_stage);
    REQUIRE(result.committed_firewall.has_value());
    CHECK(result.committed_firewall->mode ==
          FirewallApplyMode::PreserveSets);
    CHECK(firewall.prepared_modes ==
          std::vector<FirewallApplyMode>{
              FirewallApplyMode::RulesOnly,
              FirewallApplyMode::PreserveSets});
    CHECK(firewall.applied_modes ==
          std::vector<FirewallApplyMode>{FirewallApplyMode::PreserveSets});
}

TEST_CASE("backend transaction repairs one RulesOnly commit refusal") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        direct_transaction_config(),
        FirewallApplyMode::RulesOnly);
    BackendTransactionFirewall firewall;
    firewall.refuse_rules_only_commit = true;
    firewall.refusal_is_external_repair = true;

    const auto result =
        execute_runtime_firewall_backend_transaction(input, firewall);

    CHECK(result.committed());
    REQUIRE(result.rules_only_fallback.has_value());
    CHECK(result.rules_only_fallback->refused_phase ==
          RuntimeFirewallBackendTransactionPhase::initial_commit);
    CHECK(result.rules_only_fallback->external_repair);
    REQUIRE(result.committed_firewall.has_value());
    CHECK(result.committed_firewall->mode ==
          FirewallApplyMode::PreserveSets);
    CHECK(firewall.applied_modes ==
          std::vector<FirewallApplyMode>{
              FirewallApplyMode::RulesOnly,
              FirewallApplyMode::PreserveSets});
}

TEST_CASE("backend transaction never retries a failed fallback commit") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        direct_transaction_config(),
        FirewallApplyMode::RulesOnly);
    BackendTransactionFirewall firewall;
    firewall.refuse_rules_only_commit = true;
    firewall.refuse_preserve_sets_commit = true;

    const auto result =
        execute_runtime_firewall_backend_transaction(input, firewall);

    CHECK_FALSE(result.committed());
    REQUIRE(result.rules_only_fallback.has_value());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::fallback_commit);
    CHECK(result.failure->kind ==
          RuntimeFirewallBackendFailureKind::rules_only_refusal);
    CHECK(firewall.applied_modes ==
          std::vector<FirewallApplyMode>{
              FirewallApplyMode::RulesOnly,
              FirewallApplyMode::PreserveSets});
}

TEST_CASE("backend transaction reports the exact stage failure phase") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        direct_transaction_config(),
        FirewallApplyMode::PreserveSets);
    BackendTransactionFirewall firewall;
    firewall.transient_stage_mode = FirewallApplyMode::PreserveSets;

    const auto result =
        execute_runtime_firewall_backend_transaction(input, firewall);

    CHECK_FALSE(result.committed());
    CHECK_FALSE(result.committed_firewall.has_value());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_stage);
    CHECK(result.failure->kind ==
          RuntimeFirewallBackendFailureKind::transient_firewall);
    CHECK(firewall.applied_modes.empty());
}
