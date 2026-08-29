#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_backend_transaction.hpp"
#include "../src/lists/list_entry_visitor.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <set>
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
    explicit BackendTransactionFirewall(
        std::vector<std::string>* call_order = nullptr)
        : call_order_(call_order) {}

    std::vector<FirewallApplyMode> prepared_modes;
    std::vector<FirewallApplyMode> applied_modes;
    std::optional<FirewallApplyMode> transient_stage_mode;
    bool refuse_rules_only_stage{false};
    bool refuse_rules_only_commit{false};
    bool refuse_preserve_sets_commit{false};
    bool refusal_is_external_repair{false};

    void prepare_apply(FirewallApplyMode mode) override {
        record("stage", mode);
        prepared_modes.push_back(mode);
        if (mode == FirewallApplyMode::RulesOnly &&
            refuse_rules_only_stage) {
            throw FirewallRulesOnlyError(
                "recorded stage refusal",
                refusal_is_external_repair);
        }
        if (transient_stage_mode == mode) {
            throw TransientFirewallError("recorded transient stage failure");
        }
    }

    void create_ipset(const std::string&, int, std::uint32_t) override {}
    void create_udp_peer_set(
        const std::string&, int, std::uint32_t) override {}
    FirewallUdpPeerMutationResult add_udp_peer(
        const std::string&,
        const std::string&,
        std::uint16_t,
        const std::string&) override {
        return {true, true, false, false};
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
        record("commit", mode);
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

private:
    static const char* mode_name(FirewallApplyMode mode) noexcept {
        switch (mode) {
        case FirewallApplyMode::Destructive:
            return "destructive";
        case FirewallApplyMode::PreserveSets:
            return "preserve-sets";
        case FirewallApplyMode::RulesOnly:
            return "rules-only";
        }
        return "unknown";
    }

    void record(const char* action, FirewallApplyMode mode) {
        if (call_order_ != nullptr) {
            call_order_->push_back(
                std::string{action} + ":" + mode_name(mode));
        }
    }

    std::vector<std::string>* call_order_{nullptr};
};

class BackendTransactionMetaServices final
    : public MetaUdp443ActivationBackendServices {
public:
    explicit BackendTransactionMetaServices(
        std::vector<std::string>* call_order = nullptr)
        : call_order_(call_order) {}

    std::size_t fastnat_calls{0U};
    std::size_t fail_fastnat_on_call{0U};

    bool fastnat_is_disabled_or_unavailable() override {
        record("meta:fastnat");
        ++fastnat_calls;
        return fail_fastnat_on_call == 0U ||
               fastnat_calls != fail_fastnat_on_call;
    }

    ConntrackCleanupResult probe_exact_cleanup_capability(
        bool) override {
        record("meta:capability");
        return ConntrackCleanupResult::Succeeded;
    }

    std::vector<DumpedInterface> dump_interfaces() override {
        record("meta:interfaces");
        DumpedInterface interface;
        interface.name = "br0";
        interface.ipv4_addresses = {"192.168.1.1/24"};
        return {std::move(interface)};
    }

    ConntrackFlowObservation observe_forwarded_destination_flows(
        const std::vector<std::string>&,
        const std::vector<std::string>&,
        std::uint32_t,
        const ConntrackFlowObservationOptions&,
        const std::vector<std::string>&,
        const std::vector<std::string>&,
        const std::set<std::uint32_t>&) override {
        record("meta:observation");
        return {};
    }

private:
    void record(const char* event) {
        if (call_order_ != nullptr) {
            call_order_->push_back(event);
        }
    }

    std::vector<std::string>* call_order_{nullptr};
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

Config meta_transaction_config() {
    return parse_config(R"json({
      "daemon": {
        "ipv6_enabled": false,
        "meta_udp443_policy": "messages_first"
      },
      "fwmark": {"mask": "0x00FF0000"},
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
        "rules": [
          {"list": ["companion"], "outbound": "vpn"}
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
    input.runtime_generation = 23U;
    input.config = std::move(config);
    input.outbound_marks = {{"vpn", 0x00070000U}};
    input.list_max_file_size_bytes = cache.max_file_size();
    input.list_cache_snapshot =
        cache.capture_generation(captured_lists);
    input.requested_mode = mode;
    if (mode == FirewallApplyMode::RulesOnly) {
        input.requested_list_fingerprints = {{"seam", "same"}};
        input.previous_list_fingerprints = {{"seam", "same"}};
    }
    return input;
}

RuntimeFirewallBackendTransactionInput meta_transaction_input(
    const std::filesystem::path& cache_path,
    FirewallApplyMode mode) {
    auto input = transaction_input(
        cache_path,
        meta_transaction_config(),
        mode,
        {"companion"});
    input.requested_list_fingerprints = {{"companion", "same"}};
    input.previous_list_fingerprints = {{"companion", "same"}};

    RuleState previous_rule;
    previous_rule.rule_index = 0U;
    previous_rule.list_names = {"companion"};
    previous_rule.action_type = RuleActionType::Mark;
    previous_rule.fwmark = 0x00070000U;
    input.previous_rules = {std::move(previous_rule)};

    ListSetUsage previous_usage;
    previous_usage.has_static_entries = true;
    previous_usage.has_static_ipv4_entries = true;
    previous_usage.static_destinations = {"31.13.64.0/18"};
    input.previous_list_usage = {
        {"companion", std::move(previous_usage)}};
    input.previous_list_content_state.static_destinations["companion"] = {
        "31.13.64.0/18"};
    input.forwarded_scope_allows_unmarked_cleanup = true;
    return input;
}

} // namespace

TEST_CASE("backend transaction runs Meta preflight before initial commit") {
    BackendTransactionTempDirectory temp;
    auto input = meta_transaction_input(
        temp.path() / "cache",
        FirewallApplyMode::PreserveSets);
    std::vector<std::string> call_order;
    BackendTransactionFirewall firewall{&call_order};
    BackendTransactionMetaServices meta_services{&call_order};

    const auto result = execute_runtime_firewall_backend_transaction(
        input, firewall, meta_services);

    CHECK(result.committed());
    CHECK(result.commit_entered);
    CHECK(result.commit_returned);
    REQUIRE(result.meta_activation_plan.has_value());
    CHECK(result.meta_activation_plan->expected_fwmark == 0x00070000U);
    CHECK(call_order == std::vector<std::string>{
        "stage:preserve-sets",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit:preserve-sets",
    });
}

TEST_CASE("initial Meta preflight failure never enters commit") {
    BackendTransactionTempDirectory temp;
    auto input = meta_transaction_input(
        temp.path() / "cache",
        FirewallApplyMode::PreserveSets);
    std::vector<std::string> call_order;
    BackendTransactionFirewall firewall{&call_order};
    BackendTransactionMetaServices meta_services{&call_order};
    meta_services.fail_fastnat_on_call = 1U;

    const auto result = execute_runtime_firewall_backend_transaction(
        input, firewall, meta_services);

    CHECK_FALSE(result.committed());
    CHECK_FALSE(result.commit_entered);
    CHECK_FALSE(result.commit_returned);
    CHECK_FALSE(result.meta_activation_plan.has_value());
    CHECK_FALSE(result.rules_only_fallback.has_value());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_meta_preflight);
    CHECK(result.failure->kind ==
          RuntimeFirewallBackendFailureKind::meta_preflight);
    CHECK(call_order == std::vector<std::string>{
        "stage:preserve-sets",
        "meta:fastnat",
    });
    CHECK(firewall.applied_modes.empty());
}

TEST_CASE("RulesOnly commit fallback repeats Meta preflight before commit") {
    BackendTransactionTempDirectory temp;
    auto input = meta_transaction_input(
        temp.path() / "cache",
        FirewallApplyMode::RulesOnly);
    std::vector<std::string> call_order;
    BackendTransactionFirewall firewall{&call_order};
    BackendTransactionMetaServices meta_services{&call_order};
    firewall.refuse_rules_only_commit = true;

    const auto result = execute_runtime_firewall_backend_transaction(
        input, firewall, meta_services);

    CHECK(result.committed());
    CHECK(result.commit_entered);
    CHECK(result.commit_returned);
    REQUIRE(result.rules_only_fallback.has_value());
    REQUIRE(result.meta_activation_plan.has_value());
    CHECK(result.meta_activation_plan->expected_fwmark == 0x00070000U);
    CHECK(meta_services.fastnat_calls == 2U);
    CHECK(call_order == std::vector<std::string>{
        "stage:rules-only",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit:rules-only",
        "stage:preserve-sets",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit:preserve-sets",
    });
}

TEST_CASE("RulesOnly stage fallback runs Meta preflight before commit") {
    BackendTransactionTempDirectory temp;
    auto input = meta_transaction_input(
        temp.path() / "cache",
        FirewallApplyMode::RulesOnly);
    std::vector<std::string> call_order;
    BackendTransactionFirewall firewall{&call_order};
    BackendTransactionMetaServices meta_services{&call_order};
    firewall.refuse_rules_only_stage = true;

    const auto result = execute_runtime_firewall_backend_transaction(
        input, firewall, meta_services);

    CHECK(result.committed());
    CHECK(result.commit_entered);
    CHECK(result.commit_returned);
    REQUIRE(result.rules_only_fallback.has_value());
    CHECK(result.rules_only_fallback->refused_phase ==
          RuntimeFirewallBackendTransactionPhase::initial_stage);
    REQUIRE(result.meta_activation_plan.has_value());
    CHECK(meta_services.fastnat_calls == 1U);
    CHECK(call_order == std::vector<std::string>{
        "stage:rules-only",
        "stage:preserve-sets",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit:preserve-sets",
    });
}

TEST_CASE("fallback Meta failure does not enter fallback commit") {
    BackendTransactionTempDirectory temp;
    auto input = meta_transaction_input(
        temp.path() / "cache",
        FirewallApplyMode::RulesOnly);
    std::vector<std::string> call_order;
    BackendTransactionFirewall firewall{&call_order};
    BackendTransactionMetaServices meta_services{&call_order};
    firewall.refuse_rules_only_commit = true;
    meta_services.fail_fastnat_on_call = 2U;

    const auto result = execute_runtime_firewall_backend_transaction(
        input, firewall, meta_services);

    CHECK_FALSE(result.committed());
    CHECK(result.commit_entered);
    CHECK_FALSE(result.commit_returned);
    CHECK_FALSE(result.meta_activation_plan.has_value());
    REQUIRE(result.rules_only_fallback.has_value());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::fallback_meta_preflight);
    CHECK(result.failure->kind ==
          RuntimeFirewallBackendFailureKind::meta_preflight);
    CHECK(firewall.applied_modes ==
          std::vector<FirewallApplyMode>{FirewallApplyMode::RulesOnly});
    CHECK(call_order == std::vector<std::string>{
        "stage:rules-only",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit:rules-only",
        "stage:preserve-sets",
        "meta:fastnat",
    });
}

TEST_CASE("backend transaction returns one owned committed value") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        direct_transaction_config(),
        FirewallApplyMode::PreserveSets);
    BackendTransactionFirewall firewall;
    BackendTransactionMetaServices meta_services;

    const auto result =
        execute_runtime_firewall_backend_transaction(
            input, firewall, meta_services);

    CHECK(result.committed());
    CHECK(result.operation_serial == 17U);
    CHECK(result.runtime_generation == 23U);
    CHECK(result.commit_entered);
    CHECK(result.commit_returned);
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
    BackendTransactionMetaServices meta_services;

    const auto result =
        execute_runtime_firewall_backend_transaction(
            input, firewall, meta_services);

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

TEST_CASE("backend transaction streams a changed pinned list generation") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        list_transaction_config(),
        FirewallApplyMode::RulesOnly,
        {"seam"});
    input.requested_list_fingerprints = {{"seam", "new"}};
    input.previous_list_fingerprints = {{"seam", "old"}};
    BackendTransactionFirewall firewall;
    BackendTransactionMetaServices meta_services;

    const auto result =
        execute_runtime_firewall_backend_transaction(
            input, firewall, meta_services);

    CHECK(result.committed());
    CHECK_FALSE(result.rules_only_fallback.has_value());
    REQUIRE(result.committed_firewall.has_value());
    CHECK(result.committed_firewall->mode ==
          FirewallApplyMode::PreserveSets);
    CHECK(firewall.prepared_modes ==
          std::vector<FirewallApplyMode>{FirewallApplyMode::PreserveSets});
}

TEST_CASE("backend transaction repairs one RulesOnly commit refusal") {
    BackendTransactionTempDirectory temp;
    auto input = transaction_input(
        temp.path() / "cache",
        direct_transaction_config(),
        FirewallApplyMode::RulesOnly);
    BackendTransactionFirewall firewall;
    BackendTransactionMetaServices meta_services;
    firewall.refuse_rules_only_commit = true;
    firewall.refusal_is_external_repair = true;

    const auto result =
        execute_runtime_firewall_backend_transaction(
            input, firewall, meta_services);

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
    BackendTransactionMetaServices meta_services;
    firewall.refuse_rules_only_commit = true;
    firewall.refuse_preserve_sets_commit = true;

    const auto result =
        execute_runtime_firewall_backend_transaction(
            input, firewall, meta_services);

    CHECK_FALSE(result.committed());
    REQUIRE(result.rules_only_fallback.has_value());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::fallback_commit);
    CHECK(result.failure->kind ==
          RuntimeFirewallBackendFailureKind::rules_only_refusal);
    CHECK(result.commit_entered);
    CHECK_FALSE(result.commit_returned);
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
    BackendTransactionMetaServices meta_services;
    firewall.transient_stage_mode = FirewallApplyMode::PreserveSets;

    const auto result =
        execute_runtime_firewall_backend_transaction(
            input, firewall, meta_services);

    CHECK_FALSE(result.committed());
    CHECK_FALSE(result.committed_firewall.has_value());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_stage);
    CHECK(result.failure->kind ==
          RuntimeFirewallBackendFailureKind::transient_firewall);
    CHECK_FALSE(result.commit_entered);
    CHECK_FALSE(result.commit_returned);
    CHECK(firewall.applied_modes.empty());
}
