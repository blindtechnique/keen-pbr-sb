#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_worker_attempt.hpp"
#include "../src/lists/list_entry_visitor.hpp"

#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

class WorkerAttemptTempDirectory final {
public:
    WorkerAttemptTempDirectory() {
        char pattern[] = "/tmp/keen-pbr-worker-attempt-XXXXXX";
        const char* value = ::mkdtemp(pattern);
        if (value == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = value;
    }

    ~WorkerAttemptTempDirectory() {
        std::filesystem::remove_all(path_);
    }

    const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

class WorkerAttemptFirewall final : public Firewall {
public:
    explicit WorkerAttemptFirewall(std::vector<std::string>& order)
        : order_(order) {}

    mutable std::size_t owned_snat_inspections{0U};
    std::size_t throw_owned_snat_on_call{0U};
    std::vector<OwnedSnatState> owned_snat_states{
        OwnedSnatState::missing, OwnedSnatState::healthy};
    bool throw_forward_inspection{false};
    OwnedForwardUdpRejectState forward_state{
        OwnedForwardUdpRejectState::healthy};
    bool throw_after_publication{false};
    std::size_t apply_calls{0U};

    void prepare_apply(FirewallApplyMode) override {
        order_.push_back("stage");
    }

    void create_ipset(
        const std::string&, int, std::uint32_t) override {}
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
        order_.push_back(
            owned_snat_inspections == 0U
                ? "inspect:snat-before"
                : "inspect:snat-after");
        ++owned_snat_inspections;
        if (throw_owned_snat_on_call == owned_snat_inspections) {
            throw std::runtime_error("owned SNAT inspection failed");
        }
        const std::size_t index = owned_snat_inspections - 1U;
        if (index < owned_snat_states.size()) {
            return owned_snat_states[index];
        }
        return OwnedSnatState::unknown;
    }

    OwnedForwardUdpRejectState
    inspect_forward_udp_reject_state() const override {
        order_.push_back("inspect:meta-filter-after");
        if (throw_forward_inspection) {
            throw std::runtime_error("Meta filter inspection failed");
        }
        return forward_state;
    }

    void create_pass_rule(const FirewallRuleCriteria&) override {}
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string&) override {
        return std::make_unique<FunctionalVisitor>(
            [](EntryType, std::string_view) {});
    }

    void apply(FirewallApplyMode) override {
        order_.push_back("commit");
        ++apply_calls;
        enter_meta_udp443_publication_boundary();
        if (throw_after_publication) {
            throw FirewallError("commit result unavailable");
        }
    }

    void cleanup() override {}

    FirewallBackend backend() const override {
        return FirewallBackend::nftables;
    }

private:
    std::vector<std::string>& order_;
};

class WorkerAttemptMetaServices final
    : public MetaUdp443ActivationBackendServices {
public:
    explicit WorkerAttemptMetaServices(std::vector<std::string>& order)
        : order_(order) {}

    bool fastnat_disabled{true};
    std::size_t throw_fastnat_on_call{0U};
    std::size_t fastnat_calls{0U};

    bool fastnat_is_disabled_or_unavailable() override {
        order_.push_back("meta:fastnat");
        ++fastnat_calls;
        if (throw_fastnat_on_call == fastnat_calls) {
            throw std::runtime_error("FastNAT inspection failed");
        }
        return fastnat_disabled;
    }

    ConntrackCleanupResult probe_exact_cleanup_capability(
        bool) override {
        order_.push_back("meta:capability");
        return ConntrackCleanupResult::Succeeded;
    }

    std::vector<DumpedInterface> dump_interfaces() override {
        order_.push_back("meta:interfaces");
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
        order_.push_back("meta:observation");
        return {};
    }

private:
    std::vector<std::string>& order_;
};

class WorkerAttemptRouteHealthServices final
    : public RuntimeRouteHealthServices {
public:
    Ipv6SupportDecision resolve_ipv6(const Config&) override {
        ++ipv6_calls;
        return Ipv6SupportDecision{
            false,
            Ipv6SupportDecision::Reason::UnsupportedBySystem};
    }

    std::vector<DumpedRoute> dump_routes() override {
        ++route_calls;
        return {};
    }

    std::vector<DumpedInterface> dump_interfaces() override {
        ++interface_calls;
        return {DumpedInterface{"nwg0", true}};
    }

    int ipv6_calls{0};
    int route_calls{0};
    int interface_calls{0};
};

Config worker_attempt_config() {
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

RuntimeFirewallWorkerAttemptInput worker_attempt_input(
    const std::filesystem::path& cache_path) {
    CacheManager cache{cache_path, 4096};
    cache.ensure_dir();

    RuntimeFirewallWorkerAttemptInput input;
    input.inspect_owned_snat = true;
    OwnedConntrackCleanupSnapshot cleanup_snapshot;
    cleanup_snapshot.runtime_generation = 83U;
    cleanup_snapshot.owned_mask = 0x00FF0000U;
    cleanup_snapshot.marks = {0x00070000U};
    cleanup_snapshot.priority_marks = {0x00070000U};
    cleanup_snapshot.ipv6_enabled = false;
    input.pre_mutation_owned_conntrack_cleanup_snapshot =
        std::move(cleanup_snapshot);
    input.transaction.operation_serial = 71U;
    input.transaction.runtime_generation = 83U;
    input.transaction.config = worker_attempt_config();
    input.transaction.outbound_marks = {{"vpn", 0x00070000U}};
    input.transaction.list_max_file_size_bytes = cache.max_file_size();
    input.transaction.list_cache_snapshot =
        cache.capture_generation({"companion"});
    input.transaction.requested_mode = FirewallApplyMode::PreserveSets;
    input.transaction.forwarded_scope_allows_unmarked_cleanup = true;
    return input;
}

void enable_route_preparation(
    RuntimeFirewallWorkerAttemptInput& input) {
    input.route_health_request.operation_serial =
        input.transaction.operation_serial;
    input.route_health_request.runtime_generation =
        input.transaction.runtime_generation;
    input.route_health_request.route_epoch = 11U;
    input.route_health_request.config = input.transaction.config;
    input.route_health_request.outbound_marks =
        input.transaction.outbound_marks;
    input.route_mutation_checkpoint =
        std::make_shared<RuntimeRouteMutationCheckpoint>();
}

bool wait_until_plan_ready(
    const std::shared_ptr<RuntimeRouteMutationCheckpoint>& checkpoint) {
    using namespace std::chrono_literals;
    for (std::size_t attempt = 0U; attempt < 1000U; ++attempt) {
        if (checkpoint->state() ==
            RuntimeRouteMutationCheckpointState::plan_ready) {
            return true;
        }
        std::this_thread::sleep_for(1ms);
    }
    return false;
}

} // namespace

TEST_CASE("route preparation admits firewall backend only after applied acknowledgement") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    enable_route_preparation(input);
    WorkerAttemptRouteHealthServices route_services;
    int route_mutation_calls = 0;
    int backend_calls = 0;
    const std::string route_detail(512U, 'r');

    auto result_future = std::async(std::launch::async, [&]() {
        return
            execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
                input,
                route_services,
                [&](const RuntimeRouteHealthPlan& plan,
                    RouteReconcileMode mode) {
                    ++route_mutation_calls;
                    CHECK(mode == RouteReconcileMode::DeferredRepair);
                    CHECK(plan.operation_serial ==
                          input.transaction.operation_serial);
                    RuntimeRouteWorkerMutationResult result;
                    result.ack = RuntimeRouteMutationAck::applied;
                    result.failure_detail = route_detail;
                    return result;
                },
                [&]() {
                    ++backend_calls;
                    RuntimeFirewallWorkerAttemptResult result;
                    result.transaction_executed = true;
                    result.transaction.operation_serial =
                        input.transaction.operation_serial;
                    result.transaction.runtime_generation =
                        input.transaction.runtime_generation;
                    result.route_preparation.worker_mutation_failure_detail =
                        "sentinel must be replaced";
                    result.route_preparation.observation_failure.kind =
                        RuntimeRouteHealthFailureKind::unknown_exception;
                    result.route_preparation.observation_failure.detail =
                        "sentinel observation";
                    return result;
                });
    });

    REQUIRE(wait_until_plan_ready(input.route_mutation_checkpoint));
    CHECK(route_mutation_calls == 1);
    CHECK(backend_calls == 0);
    auto claim =
        input.route_mutation_checkpoint->try_claim_control();
    REQUIRE(claim.has_value());
    REQUIRE(claim->plan());
    CHECK(claim->plan()->route_epoch == 11U);
    REQUIRE(claim->acknowledge(RuntimeRouteMutationAck::applied));

    const auto result = result_future.get();
    REQUIRE(result);
    CHECK(backend_calls == 1);
    CHECK(result->transaction_executed);
    CHECK(result->route_preparation.required);
    CHECK(result->route_preparation.observation_succeeded);
    REQUIRE(result->route_preparation.worker_mutation_ack.has_value());
    CHECK(*result->route_preparation.worker_mutation_ack ==
          RuntimeRouteMutationAck::applied);
    CHECK(result->route_preparation.worker_mutation_failure_detail ==
          route_detail);
    CHECK_FALSE(result->route_preparation.observation_failure.failed());
    CHECK(result->route_preparation.observation_failure.detail.empty());
    CHECK(result->route_preparation.checkpoint_published);
    REQUIRE(result->route_preparation.mutation_ack.has_value());
    CHECK(*result->route_preparation.mutation_ack ==
          RuntimeRouteMutationAck::applied);
    CHECK(route_services.ipv6_calls == 1);
    CHECK(route_services.route_calls == 1);
    CHECK(route_services.interface_calls == 1);
}

TEST_CASE("config preapply skips compatibility route mutation") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    REQUIRE_FALSE(input.route_mutation_checkpoint);
    WorkerAttemptRouteHealthServices route_services;
    int route_mutation_calls = 0;
    int firewall_calls = 0;

    const auto result =
        execute_runtime_firewall_worker_attempt_with_route_preparation(
            input,
            route_services,
            [&](const RuntimeRouteHealthPlan&, RouteReconcileMode) {
                ++route_mutation_calls;
                RuntimeRouteWorkerMutationResult mutation;
                mutation.ack = RuntimeRouteMutationAck::applied;
                return mutation;
            },
            [&]() {
                ++firewall_calls;
                RuntimeFirewallWorkerAttemptResult completed;
                completed.operation_kind =
                    RuntimeFirewallWorkerOperationKind::config_preapply;
                return completed;
            });

    CHECK(route_mutation_calls == 0);
    CHECK(route_services.ipv6_calls == 0);
    CHECK(route_services.route_calls == 0);
    CHECK(route_services.interface_calls == 0);
    CHECK(firewall_calls == 1);
    CHECK_FALSE(result.route_preparation.required);
    CHECK_FALSE(result.route_preparation.worker_mutation_ack.has_value());
    CHECK_FALSE(result.route_preparation.mutation_ack.has_value());
}

TEST_CASE("route preparation rejects stale acknowledgement before firewall backend") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    enable_route_preparation(input);
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    input.route_reconcile_mode = RouteReconcileMode::Strict;
    WorkerAttemptRouteHealthServices route_services;
    int route_mutation_calls = 0;
    int backend_calls = 0;
    const std::string route_detail(384U, 's');

    auto result_future = std::async(std::launch::async, [&]() {
        return
            execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
                input,
                route_services,
                [&](const RuntimeRouteHealthPlan&,
                    RouteReconcileMode mode) {
                    ++route_mutation_calls;
                    CHECK(mode == RouteReconcileMode::Strict);
                    RuntimeRouteWorkerMutationResult result;
                    result.ack = RuntimeRouteMutationAck::applied;
                    result.failure_detail = route_detail;
                    return result;
                },
                [&]() {
                    ++backend_calls;
                    return RuntimeFirewallWorkerAttemptResult{};
                });
    });

    REQUIRE(wait_until_plan_ready(input.route_mutation_checkpoint));
    CHECK(route_mutation_calls == 1);
    auto claim =
        input.route_mutation_checkpoint->try_claim_control();
    REQUIRE(claim.has_value());
    REQUIRE(claim->acknowledge(RuntimeRouteMutationAck::stale));

    const auto result = result_future.get();
    REQUIRE(result);
    REQUIRE(result->route_preparation.worker_mutation_ack.has_value());
    CHECK(*result->route_preparation.worker_mutation_ack ==
          RuntimeRouteMutationAck::applied);
    CHECK(result->route_preparation.worker_mutation_failure_detail ==
          route_detail);
    CHECK(backend_calls == 0);
    CHECK_FALSE(result->transaction_executed);
    CHECK_FALSE(result->transaction.commit_entered);
    CHECK(result->previous_generation_certainly_retained());
    CHECK(result->operation_kind ==
          RuntimeFirewallWorkerOperationKind::config_preapply);
    CHECK(result->owned_conntrack_cleanup_mode ==
          RuntimeFirewallOwnedConntrackCleanupMode::
              exact_pre_mutation_snapshot);
    CHECK(result->exact_cleanup_authority_valid);
    CHECK(result->owned_snat_inspection_required);
    CHECK_FALSE(result->owned_snat_before.attempted);
    CHECK_FALSE(result->owned_snat_after.attempted);
    CHECK_FALSE(result->config_preapply_verified());
    REQUIRE(result->route_preparation.mutation_ack.has_value());
    CHECK(*result->route_preparation.mutation_ack ==
          RuntimeRouteMutationAck::stale);
}

TEST_CASE("route preparation shutdown before publish never enters firewall backend") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    enable_route_preparation(input);
    REQUIRE(input.route_mutation_checkpoint->cancel());
    WorkerAttemptRouteHealthServices route_services;
    int route_mutation_calls = 0;
    int backend_calls = 0;

    const auto result =
        execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
            input,
            route_services,
            [&](const RuntimeRouteHealthPlan&, RouteReconcileMode) {
                ++route_mutation_calls;
                RuntimeRouteWorkerMutationResult mutation;
                mutation.ack = RuntimeRouteMutationAck::applied;
                return mutation;
            },
            [&]() {
                ++backend_calls;
                return RuntimeFirewallWorkerAttemptResult{};
            });

    REQUIRE(result);
    CHECK(backend_calls == 0);
    CHECK_FALSE(result->transaction_executed);
    CHECK_FALSE(result->transaction.commit_entered);
    CHECK(result->previous_generation_certainly_retained());
    CHECK(route_mutation_calls == 0);
    CHECK(result->route_preparation.observation_succeeded);
    CHECK_FALSE(result->route_preparation.checkpoint_published);
    CHECK_FALSE(result->route_preparation.mutation_ack.has_value());
}

TEST_CASE("route worker mutation failure never publishes or enters firewall") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    enable_route_preparation(input);
    WorkerAttemptRouteHealthServices route_services;
    int backend_calls = 0;

    const auto result =
        execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
            input,
            route_services,
            [](const RuntimeRouteHealthPlan&, RouteReconcileMode) {
                RuntimeRouteWorkerMutationResult mutation;
                mutation.ack =
                    RuntimeRouteMutationAck::route_unavailable;
                mutation.failure_detail = "wg-test is down";
                return mutation;
            },
            [&]() {
                ++backend_calls;
                return RuntimeFirewallWorkerAttemptResult{};
            });

    REQUIRE(result);
    CHECK(backend_calls == 0);
    CHECK_FALSE(result->transaction_executed);
    CHECK_FALSE(result->transaction.commit_entered);
    CHECK(result->previous_generation_certainly_retained());
    CHECK(result->route_preparation.observation_succeeded);
    REQUIRE(result->route_preparation.worker_mutation_ack.has_value());
    CHECK(*result->route_preparation.worker_mutation_ack ==
          RuntimeRouteMutationAck::route_unavailable);
    CHECK(result->route_preparation.worker_mutation_failure_detail ==
          "wg-test is down");
    CHECK_FALSE(result->route_preparation.checkpoint_published);
    CHECK(input.route_mutation_checkpoint->state() ==
          RuntimeRouteMutationCheckpointState::empty);
}

TEST_CASE("worker attempt keeps observations and commit in exact order") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);

    CHECK(result.transaction_executed);
    CHECK(result.transaction.committed());
    CHECK(result.transaction.operation_serial == 71U);
    CHECK(result.transaction.runtime_generation == 83U);
    REQUIRE(result.owned_snat_before.state.has_value());
    CHECK(*result.owned_snat_before.state == OwnedSnatState::missing);
    REQUIRE(
        result.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(result.pre_mutation_owned_conntrack_cleanup_snapshot
              ->runtime_generation == 83U);
    CHECK(result.pre_mutation_owned_conntrack_cleanup_snapshot
              ->marks == std::set<std::uint32_t>{0x00070000U});
    REQUIRE(result.owned_snat_after.state.has_value());
    CHECK(*result.owned_snat_after.state == OwnedSnatState::healthy);
    CHECK(result.meta_publication_epoch_before == 0U);
    CHECK(result.meta_publication_epoch_after == 1U);
    REQUIRE(result.forward_udp_reject_after_commit.state.has_value());
    CHECK(*result.forward_udp_reject_after_commit.state ==
          OwnedForwardUdpRejectState::healthy);
    CHECK_FALSE(
        result.forward_udp_reject_after_commit.failure.failed());
    CHECK(result.fastnat.attempted);
    REQUIRE(result.fastnat.disabled_or_unavailable.has_value());
    CHECK(*result.fastnat.disabled_or_unavailable);
    CHECK(result.fastnat_after_commit.attempted);
    REQUIRE(
        result.fastnat_after_commit.disabled_or_unavailable.has_value());
    CHECK(*result.fastnat_after_commit.disabled_or_unavailable);
    CHECK_FALSE(result.previous_generation_certainly_retained());
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "stage",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit",
        "inspect:meta-filter-after",
        "meta:fastnat",
        "inspect:snat-after",
    });
}

TEST_CASE("START owned conntrack cleanup runs only after committed firewall") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::committed_candidate;
    std::vector<std::string> order;
    std::vector<std::vector<std::string>> cleanup_commands;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>& args) {
            order.push_back("cleanup:owned");
            cleanup_commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(result.transaction.committed());
    const auto& cleanup = result.post_commit_owned_conntrack_cleanup;
    CHECK(cleanup.attempted);
    REQUIRE(cleanup.snapshot.has_value());
    CHECK(cleanup.snapshot->runtime_generation == 83U);
    CHECK(cleanup.snapshot->owned_mask == 0x00FF0000U);
    CHECK(cleanup.snapshot->marks ==
          std::set<std::uint32_t>{0x00070000U});
    CHECK_FALSE(cleanup.failure.failed());
    CHECK(cleanup.summary.failed == 0U);
    CHECK(cleanup.summary.skipped == 0U);
    CHECK_FALSE(cleanup.summary.command_unavailable);
    CHECK_FALSE(cleanup.summary.budget_exhausted);
    CHECK(cleanup.summary.remaining_marks.empty());
    CHECK(cleanup_commands ==
          std::vector<std::vector<std::string>>{{
              "conntrack",
              "-D",
              "-f",
              "ipv4",
              "--mark",
              "458752/16711680",
          }});
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "stage",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit",
        "inspect:meta-filter-after",
        "meta:fastnat",
        "inspect:snat-after",
        "cleanup:owned",
    });
}

TEST_CASE(
    "missing pre-apply SNAT merges broad and mandatory cleanup authority") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    input.pre_mutation_owned_conntrack_cleanup_snapshot->marks = {
        0x00030000U, 0x00070000U};
    input.pre_mutation_owned_conntrack_cleanup_snapshot->priority_marks = {
        0x00030000U};
    input.mandatory_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    input.mandatory_owned_conntrack_cleanup_snapshot->marks = {
        0x00090000U};
    input.mandatory_owned_conntrack_cleanup_snapshot->priority_marks = {
        0x00090000U};
    input.transaction.previous_native_vpn_direct_egress_snat_selectors = {
        {"nwg0", "198.51.100.0/24"}};
    input.transaction.candidate_native_vpn_direct_egress_snat_selectors = {
        {"nwg1", "198.51.100.0/24"}};

    std::vector<std::string> order;
    std::vector<std::vector<std::string>> cleanup_commands;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>& args) {
            order.push_back("cleanup:owned");
            cleanup_commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    REQUIRE(result.transaction.committed());
    CHECK(result.exact_cleanup_authority_valid);
    CHECK(result.exact_cleanup_required);
    CHECK(result.config_preapply_verified());
    CHECK_FALSE(result.native_direct_egress_source_cleanup.attempted);
    CHECK(result.native_direct_egress_source_cleanup
              .affected_source_cidrs.empty());
    const auto& cleanup = result.post_commit_owned_conntrack_cleanup;
    REQUIRE(cleanup.attempted);
    REQUIRE(cleanup.snapshot.has_value());
    CHECK(cleanup.snapshot->runtime_generation == 83U);
    CHECK(cleanup.snapshot->owned_mask == 0x00FF0000U);
    CHECK(cleanup.snapshot->marks ==
          std::set<std::uint32_t>{
              0x00030000U, 0x00070000U, 0x00090000U});
    CHECK(cleanup.snapshot->priority_marks ==
          std::set<std::uint32_t>{0x00030000U, 0x00090000U});
    CHECK(cleanup_commands.size() == 3U);
    REQUIRE(cleanup_commands[0].size() == 6U);
    REQUIRE(cleanup_commands[1].size() == 6U);
    REQUIRE(cleanup_commands[2].size() == 6U);
    CHECK(cleanup_commands[0][5] == "196608/16711680");
    CHECK(cleanup_commands[1][5] == "589824/16711680");
    CHECK(cleanup_commands[2][5] == "458752/16711680");
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "stage",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit",
        "inspect:snat-after",
        "cleanup:owned",
        "cleanup:owned",
        "cleanup:owned",
    });
}

TEST_CASE(
    "healthy pre-apply cleans only mandatory retry authority") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    input.pre_mutation_owned_conntrack_cleanup_snapshot->marks = {
        0x00030000U, 0x00070000U};
    input.pre_mutation_owned_conntrack_cleanup_snapshot->priority_marks = {
        0x00070000U};
    input.mandatory_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    input.mandatory_owned_conntrack_cleanup_snapshot->marks = {
        0x00030000U};
    input.mandatory_owned_conntrack_cleanup_snapshot->priority_marks.clear();

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    std::vector<std::vector<std::string>> cleanup_commands;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>& args) {
            ++cleanup_calls;
            order.push_back("cleanup:owned");
            cleanup_commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    firewall.owned_snat_states = {
        OwnedSnatState::healthy, OwnedSnatState::healthy};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK_FALSE(result.transaction_executed);
    CHECK_FALSE(result.transaction.commit_entered);
    CHECK(firewall.apply_calls == 0U);
    REQUIRE(result.owned_snat_before.state.has_value());
    CHECK(*result.owned_snat_before.state == OwnedSnatState::healthy);
    REQUIRE(result.owned_snat_after.state.has_value());
    CHECK(*result.owned_snat_after.state == OwnedSnatState::healthy);
    CHECK(cleanup_calls == 1U);
    REQUIRE(result.selected_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(result.selected_owned_conntrack_cleanup_snapshot->marks ==
          std::set<std::uint32_t>{0x00030000U});
    CHECK(result.selected_owned_conntrack_cleanup_snapshot
              ->priority_marks.empty());
    REQUIRE(cleanup_commands.size() == 1U);
    REQUIRE(cleanup_commands[0].size() == 6U);
    CHECK(cleanup_commands[0][5] == "196608/16711680");
    CHECK(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK(result.config_preapply_verified());
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "inspect:snat-after",
        "cleanup:owned",
    });
}

TEST_CASE(
    "healthy pre-apply without mandatory cleanup does not touch conntrack") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    REQUIRE(input.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK_FALSE(input.pre_mutation_owned_conntrack_cleanup_snapshot
                    ->marks.empty());
    CHECK_FALSE(
        input.mandatory_owned_conntrack_cleanup_snapshot.has_value());

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    firewall.owned_snat_states = {
        OwnedSnatState::healthy, OwnedSnatState::healthy};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK_FALSE(result.transaction_executed);
    CHECK_FALSE(result.transaction.commit_entered);
    CHECK(firewall.apply_calls == 0U);
    CHECK(result.missing_snat_cleanup_authority_valid);
    CHECK(result.mandatory_cleanup_authority_valid);
    CHECK(result.exact_cleanup_authority_valid);
    CHECK_FALSE(result.exact_cleanup_required);
    CHECK_FALSE(
        result.selected_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(cleanup_calls == 0U);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK(result.config_preapply_verified());
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "inspect:snat-after",
    });
}

TEST_CASE(
    "pre-apply verdict rejects incomplete exact conntrack cleanup") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    input.mandatory_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;

    std::vector<std::string> order;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            order.push_back("cleanup:owned");
            return ConntrackManager::CommandResult{1, {}};
        });
    WorkerAttemptFirewall firewall{order};
    firewall.owned_snat_states = {
        OwnedSnatState::healthy, OwnedSnatState::healthy};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK(result.post_commit_owned_conntrack_cleanup.summary.failed == 1U);
    CHECK_FALSE(result.config_preapply_verified());
}

TEST_CASE(
    "pre-apply cleanup preserves progress across a throwing mark command") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    input.mandatory_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;
    input.mandatory_owned_conntrack_cleanup_snapshot->marks = {
        0x00030000U, 0x00070000U, 0x00090000U};
    input.mandatory_owned_conntrack_cleanup_snapshot->priority_marks = {
        0x00030000U, 0x00070000U, 0x00090000U};

    std::vector<std::string> order;
    std::vector<std::string> attempted_selectors;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>& args) {
            attempted_selectors.push_back(args.at(5));
            if (attempted_selectors.size() == 2U) {
                throw std::runtime_error("conntrack runner failed");
            }
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    firewall.owned_snat_states = {
        OwnedSnatState::healthy, OwnedSnatState::healthy};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    const auto& cleanup = result.post_commit_owned_conntrack_cleanup;
    REQUIRE(cleanup.attempted);
    CHECK_FALSE(cleanup.failure.failed());
    CHECK(cleanup.summary.failed == 1U);
    CHECK(cleanup.summary.skipped == 0U);
    CHECK(cleanup.summary.remaining_marks ==
          std::vector<std::uint32_t>{0x00070000U});
    CHECK(attempted_selectors == std::vector<std::string>{
        "196608/16711680",
        "458752/16711680",
        "589824/16711680",
    });
    CHECK_FALSE(result.config_preapply_verified());
}

TEST_CASE(
    "pre-apply unknown baseline never authorizes destructive cleanup") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    input.mandatory_owned_conntrack_cleanup_snapshot =
        input.pre_mutation_owned_conntrack_cleanup_snapshot;

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    firewall.owned_snat_states = {
        OwnedSnatState::unknown, OwnedSnatState::healthy};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK_FALSE(result.transaction_executed);
    CHECK(result.exact_cleanup_authority_valid);
    CHECK(result.exact_cleanup_required);
    CHECK(cleanup_calls == 0U);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK_FALSE(result.config_preapply_verified());
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "inspect:snat-after",
    });
}

TEST_CASE(
    "pre-apply malformed authority fails before COMMIT or conntrack") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    REQUIRE(input.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    bool expected_missing_snat_authority_valid = true;
    bool expected_mandatory_authority_valid = true;
    SUBCASE("generation mismatch") {
        input.pre_mutation_owned_conntrack_cleanup_snapshot
            ->runtime_generation = 82U;
        expected_missing_snat_authority_valid = false;
    }
    SUBCASE("mask mismatch") {
        input.pre_mutation_owned_conntrack_cleanup_snapshot->owned_mask =
            0x000F0000U;
        expected_missing_snat_authority_valid = false;
    }
    SUBCASE("IPv6 scope mismatch") {
        input.pre_mutation_owned_conntrack_cleanup_snapshot
            ->ipv6_enabled = true;
        expected_missing_snat_authority_valid = false;
    }
    SUBCASE("mandatory generation mismatch") {
        input.mandatory_owned_conntrack_cleanup_snapshot =
            input.pre_mutation_owned_conntrack_cleanup_snapshot;
        input.mandatory_owned_conntrack_cleanup_snapshot
            ->runtime_generation = 82U;
        expected_mandatory_authority_valid = false;
    }
    SUBCASE("mandatory mask mismatch") {
        input.mandatory_owned_conntrack_cleanup_snapshot =
            input.pre_mutation_owned_conntrack_cleanup_snapshot;
        input.mandatory_owned_conntrack_cleanup_snapshot->owned_mask =
            0x000F0000U;
        expected_mandatory_authority_valid = false;
    }
    SUBCASE("mandatory IPv6 scope mismatch") {
        input.mandatory_owned_conntrack_cleanup_snapshot =
            input.pre_mutation_owned_conntrack_cleanup_snapshot;
        input.mandatory_owned_conntrack_cleanup_snapshot
            ->ipv6_enabled = true;
        expected_mandatory_authority_valid = false;
    }

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK_FALSE(result.transaction_executed);
    CHECK_FALSE(result.transaction.commit_entered);
    CHECK(firewall.apply_calls == 0U);
    CHECK(result.missing_snat_cleanup_authority_valid ==
          expected_missing_snat_authority_valid);
    CHECK(result.mandatory_cleanup_authority_valid ==
          expected_mandatory_authority_valid);
    CHECK_FALSE(result.exact_cleanup_authority_valid);
    CHECK_FALSE(result.exact_cleanup_required);
    CHECK(cleanup_calls == 0U);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK_FALSE(result.config_preapply_verified());
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
    });
}

TEST_CASE(
    "pre-apply failed transaction never authorizes exact cleanup") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    SUBCASE("pre-commit failure") {
        meta_services.throw_fastnat_on_call = 1U;
    }
    SUBCASE("ambiguous commit") {
        firewall.throw_after_publication = true;
    }

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(result.transaction_executed);
    CHECK_FALSE(result.transaction.committed());
    CHECK(cleanup_calls == 0U);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK_FALSE(result.config_preapply_verified());
}

TEST_CASE("unsupported owned cleanup mode combinations fail closed") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");

    SUBCASE("pre-apply cannot use a committed candidate") {
        input.operation_kind =
            RuntimeFirewallWorkerOperationKind::config_preapply;
        input.owned_conntrack_cleanup_mode =
            RuntimeFirewallOwnedConntrackCleanupMode::
                committed_candidate;
    }
    SUBCASE("unknown cleanup mode cannot become committed candidate") {
        input.owned_conntrack_cleanup_mode =
            static_cast<RuntimeFirewallOwnedConntrackCleanupMode>(0xffU);
    }

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(cleanup_calls == 0U);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK_FALSE(result.config_preapply_verified());
}

TEST_CASE(
    "pre-apply authoritative empty mark set is a verified no-op") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    REQUIRE(input.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    input.pre_mutation_owned_conntrack_cleanup_snapshot->marks.clear();
    input.pre_mutation_owned_conntrack_cleanup_snapshot
        ->priority_marks.clear();

    std::vector<std::string> order;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    firewall.owned_snat_states = {
        OwnedSnatState::healthy, OwnedSnatState::healthy};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(result.exact_cleanup_authority_valid);
    CHECK_FALSE(result.exact_cleanup_required);
    CHECK(cleanup_calls == 0U);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK(result.config_preapply_verified());
}

TEST_CASE("durable worker adapter publishes the normal typed result") {
    static_assert(
        std::is_nothrow_move_constructible_v<
            RuntimeFirewallWorkerAttemptResult>);

    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt_durable(
        input, firewall, meta_services);

    REQUIRE(result);
    CHECK(result->transaction_executed);
    CHECK(result->transaction.committed());
    CHECK(result->transaction.commit_entered);
    CHECK(result->transaction.commit_returned);
    CHECK_FALSE(result->transaction.failure.has_value());
    CHECK(result->transaction.operation_serial == 71U);
    CHECK(result->transaction.runtime_generation == 83U);
    CHECK(result->meta_publication_epoch_after == 1U);
    CHECK_FALSE(result->previous_generation_certainly_retained());
    CHECK(firewall.apply_calls == 1U);
}

TEST_CASE(
    "durable worker adapter publishes exact populated result from separate slot") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");

    const auto result = execute_runtime_firewall_worker_attempt_durable(
        input,
        []() {
            RuntimeFirewallWorkerAttemptResult completed;
            completed.transaction_executed = true;
            completed.transaction.operation_serial = 71U;
            completed.transaction.runtime_generation = 83U;
            completed.transaction.failure = RuntimeFirewallBackendFailure{
                RuntimeFirewallBackendTransactionPhase::fallback_commit,
                RuntimeFirewallBackendFailureKind::transient_firewall,
                "exact completed backend failure",
                true};
            completed.owned_snat_before.attempted = true;
            completed.owned_snat_before.failure =
                RuntimeFirewallWorkerInspectionFailure{
                    RuntimeFirewallWorkerInspectionFailureKind::standard_exception,
                    "exact completed inspection failure"};
            completed.native_direct_egress_source_cleanup
                .affected_source_cidrs = {
                    "198.51.100.0/24", "203.0.113.7/32"};
            return completed;
        });

    REQUIRE(result);
    CHECK(result->transaction_executed);
    CHECK_FALSE(result->transaction.commit_entered);
    REQUIRE(result->transaction.failure.has_value());
    CHECK(result->transaction.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::fallback_commit);
    CHECK(result->transaction.failure->kind ==
          RuntimeFirewallBackendFailureKind::transient_firewall);
    CHECK(result->transaction.failure->message ==
          "exact completed backend failure");
    CHECK(result->transaction.failure->external_repair);
    CHECK(result->owned_snat_before.attempted);
    CHECK(result->owned_snat_before.failure.message ==
          "exact completed inspection failure");
    CHECK(result->native_direct_egress_source_cleanup
              .affected_source_cidrs ==
          std::vector<std::string>{
              "198.51.100.0/24", "203.0.113.7/32"});
}

TEST_CASE(
    "durable worker adapter retains ambiguous evidence after an escaped commit") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    firewall.throw_after_publication = true;
    bool runner_entered = false;

    const auto result = execute_runtime_firewall_worker_attempt_durable(
        input,
        [&]() -> RuntimeFirewallWorkerAttemptResult {
            runner_entered = true;
            firewall.apply(FirewallApplyMode::PreserveSets);
            return {};
        });

    REQUIRE(result);
    CHECK(runner_entered);
    CHECK(result->transaction_executed);
    CHECK_FALSE(result->transaction.committed());
    CHECK(result->transaction.commit_entered);
    CHECK_FALSE(result->transaction.commit_returned);
    REQUIRE(result->transaction.failure.has_value());
    CHECK(result->transaction.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_commit);
    CHECK(result->transaction.failure->kind ==
          RuntimeFirewallBackendFailureKind::unexpected_exception);
    CHECK(result->transaction.failure->message ==
          "worker attempt escaped before publishing its typed terminal result");
    CHECK(result->transaction.operation_serial == 71U);
    CHECK(result->transaction.runtime_generation == 83U);
    CHECK_FALSE(result->previous_generation_certainly_retained());
    REQUIRE(
        result->pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(result->pre_mutation_owned_conntrack_cleanup_snapshot
              ->runtime_generation == 83U);
    CHECK(result->pre_mutation_owned_conntrack_cleanup_snapshot
              ->marks == std::set<std::uint32_t>{0x00070000U});
    CHECK(firewall.apply_calls == 1U);
    CHECK(firewall.meta_udp443_publication_epoch() == 1U);
    CHECK(order == std::vector<std::string>{"commit"});
}

TEST_CASE(
    "worker retires exact changed native source flows after committed candidate") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    for (std::uint32_t host = 1U; host <= 33U; ++host) {
        input.transaction
            .candidate_native_vpn_direct_egress_snat_selectors
            .push_back(FirewallSourceEgressSnatSelector{
                "nwg0",
                "198.51.100." + std::to_string(host) + "/32"});
    }

    std::vector<std::string> order;
    std::vector<std::vector<std::string>> cleanup_commands;
    bool cleanup_started_after_snat_inspection = false;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>& args) {
            if (cleanup_commands.empty()) {
                cleanup_started_after_snat_inspection =
                    !order.empty() &&
                    order.back() == "inspect:snat-after";
            }
            cleanup_commands.push_back(args);
            return ConntrackManager::CommandResult{0, {}};
        });
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt_durable(
        input, firewall, meta_services, conntrack_manager);

    REQUIRE(result);
    CHECK(result->transaction.committed());
    const auto& cleanup =
        result->native_direct_egress_source_cleanup;
    CHECK(cleanup.attempted);
    CHECK(cleanup.affected_source_cidrs.size() == 33U);
    CHECK_FALSE(cleanup.failure.failed());
    CHECK(cleanup.summary.failed == 0U);
    CHECK(cleanup.summary.skipped == 1U);
    CHECK_FALSE(cleanup.summary.command_unavailable);
    CHECK_FALSE(cleanup.summary.budget_exhausted);
    CHECK(cleanup.summary.remaining_source_cidrs.size() == 1U);
    CHECK(cleanup_commands.size() == 32U);
    CHECK(cleanup_started_after_snat_inspection);
    for (const auto& command : cleanup_commands) {
        REQUIRE(command.size() == 6U);
        CHECK(command[0] == "conntrack");
        CHECK(command[1] == "-D");
        CHECK(command[2] == "-f");
        CHECK(command[3] == "ipv4");
        CHECK(command[4] == "-s");
    }
}

TEST_CASE("worker retains typed native source cleanup failure") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.transaction
        .previous_native_vpn_direct_egress_snat_selectors = {
            {"nwg0", "198.51.100.0/24"}};
    input.transaction
        .candidate_native_vpn_direct_egress_snat_selectors = {
            {"nwg1", "198.51.100.0/24"}};

    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) ->
            ConntrackManager::CommandResult {
            ++cleanup_calls;
            throw std::runtime_error("source conntrack cleanup failed");
        });
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(result.transaction.committed());
    const auto& cleanup =
        result.native_direct_egress_source_cleanup;
    CHECK(cleanup.attempted);
    CHECK(cleanup.affected_source_cidrs ==
          std::vector<std::string>{"198.51.100.0/24"});
    CHECK(cleanup.failure.failed());
    CHECK(cleanup.failure.kind ==
          RuntimeFirewallWorkerInspectionFailureKind::standard_exception);
    CHECK(cleanup.failure.message ==
          "source conntrack cleanup failed");
    CHECK(cleanup_calls == 1U);
    CHECK_FALSE(result.previous_generation_certainly_retained());
}

TEST_CASE("worker attempt records Meta preflight refusal without commit") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::committed_candidate;
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};
    meta_services.fastnat_disabled = false;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK(result.transaction_executed);
    CHECK_FALSE(result.transaction.committed());
    REQUIRE(result.transaction.failure.has_value());
    CHECK(result.transaction.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_meta_preflight);
    CHECK(result.transaction.failure->kind ==
          RuntimeFirewallBackendFailureKind::meta_preflight);
    CHECK_FALSE(result.transaction.commit_entered);
    CHECK(result.previous_generation_certainly_retained());
    CHECK(result.meta_publication_epoch_before == 0U);
    CHECK(result.meta_publication_epoch_after == 0U);
    CHECK(result.owned_snat_after.attempted);
    CHECK_FALSE(result.forward_udp_reject_after_commit.attempted);
    REQUIRE(result.fastnat.disabled_or_unavailable.has_value());
    CHECK_FALSE(*result.fastnat.disabled_or_unavailable);
    CHECK_FALSE(result.fastnat_after_commit.attempted);
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK_FALSE(
        result.post_commit_owned_conntrack_cleanup.snapshot.has_value());
    CHECK(cleanup_calls == 0U);
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "stage",
        "meta:fastnat",
        "inspect:snat-after",
    });
}

TEST_CASE("worker attempt preserves ambiguous commit evidence") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.owned_conntrack_cleanup_mode =
        RuntimeFirewallOwnedConntrackCleanupMode::committed_candidate;
    input.transaction
        .previous_native_vpn_direct_egress_snat_selectors = {
            {"nwg0", "198.51.100.0/24"}};
    input.transaction
        .candidate_native_vpn_direct_egress_snat_selectors = {
            {"nwg1", "198.51.100.0/24"}};
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};
    firewall.throw_after_publication = true;
    std::size_t cleanup_calls = 0U;
    ConntrackManager conntrack_manager(
        [&](const std::vector<std::string>&) {
            ++cleanup_calls;
            return ConntrackManager::CommandResult{0, {}};
        });

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services, conntrack_manager);

    CHECK_FALSE(result.transaction.committed());
    REQUIRE(result.transaction.failure.has_value());
    CHECK(result.transaction.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_commit);
    CHECK(result.transaction.failure->kind ==
          RuntimeFirewallBackendFailureKind::firewall);
    CHECK(result.transaction.commit_entered);
    CHECK_FALSE(result.transaction.commit_returned);
    CHECK_FALSE(result.previous_generation_certainly_retained());
    CHECK(result.meta_publication_epoch_before == 0U);
    CHECK(result.meta_publication_epoch_after == 1U);
    REQUIRE(
        result.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(result.pre_mutation_owned_conntrack_cleanup_snapshot
              ->runtime_generation ==
          result.transaction.runtime_generation);
    CHECK(result.owned_snat_after.attempted);
    CHECK(result.forward_udp_reject_after_commit.attempted);
    CHECK(result.fastnat_after_commit.attempted);
    REQUIRE(
        result.fastnat_after_commit.disabled_or_unavailable.has_value());
    CHECK(*result.fastnat_after_commit.disabled_or_unavailable);
    CHECK(firewall.apply_calls == 1U);
    CHECK_FALSE(
        result.native_direct_egress_source_cleanup.attempted);
    CHECK(result.native_direct_egress_source_cleanup
              .affected_source_cidrs.empty());
    CHECK_FALSE(result.post_commit_owned_conntrack_cleanup.attempted);
    CHECK_FALSE(
        result.post_commit_owned_conntrack_cleanup.snapshot.has_value());
    CHECK(cleanup_calls == 0U);
}

TEST_CASE("worker attempt returns post-commit inspection failures") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};
    firewall.throw_owned_snat_on_call = 2U;
    firewall.throw_forward_inspection = true;

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);

    CHECK(result.transaction.committed());
    CHECK(result.owned_snat_after.attempted);
    CHECK_FALSE(result.owned_snat_after.state.has_value());
    CHECK(result.owned_snat_after.failure.failed());
    CHECK(result.owned_snat_after.failure.kind ==
          RuntimeFirewallWorkerInspectionFailureKind::standard_exception);
    CHECK(result.owned_snat_after.failure.message ==
          "owned SNAT inspection failed");
    CHECK(result.forward_udp_reject_after_commit.attempted);
    CHECK_FALSE(
        result.forward_udp_reject_after_commit.state.has_value());
    CHECK(result.forward_udp_reject_after_commit.failure.failed());
    CHECK(result.forward_udp_reject_after_commit.failure.kind ==
          RuntimeFirewallWorkerInspectionFailureKind::standard_exception);
    CHECK(result.forward_udp_reject_after_commit.failure.message ==
          "Meta filter inspection failed");
    CHECK(result.meta_publication_epoch_after == 1U);
    CHECK(firewall.apply_calls == 1U);
}

TEST_CASE("worker attempt never mutates after required pre-inspection fails") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};
    firewall.throw_owned_snat_on_call = 1U;

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);

    CHECK_FALSE(result.transaction_executed);
    CHECK_FALSE(result.transaction.commit_entered);
    CHECK(result.previous_generation_certainly_retained());
    CHECK(result.owned_snat_before.failure.failed());
    CHECK(result.owned_snat_before.failure.message ==
          "owned SNAT inspection failed");
    CHECK_FALSE(result.owned_snat_after.attempted);
    CHECK_FALSE(result.fastnat.attempted);
    CHECK_FALSE(result.forward_udp_reject_after_commit.attempted);
    CHECK(result.meta_publication_epoch_before == 0U);
    CHECK(result.meta_publication_epoch_after == 0U);
    CHECK(firewall.apply_calls == 0U);
    CHECK(order ==
          std::vector<std::string>{"inspect:snat-before"});
}

TEST_CASE("worker attempt records the exact failed FastNAT observation") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};
    meta_services.throw_fastnat_on_call = 1U;

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);

    CHECK_FALSE(result.transaction.committed());
    REQUIRE(result.transaction.failure.has_value());
    CHECK(result.transaction.failure->phase ==
          RuntimeFirewallBackendTransactionPhase::initial_meta_preflight);
    CHECK(result.fastnat.attempted);
    CHECK_FALSE(result.fastnat.disabled_or_unavailable.has_value());
    CHECK(result.fastnat.failure.failed());
    CHECK(result.fastnat.failure.kind ==
          RuntimeFirewallWorkerInspectionFailureKind::standard_exception);
    CHECK(result.fastnat.failure.message ==
          "FastNAT inspection failed");
    CHECK(result.previous_generation_certainly_retained());
    CHECK(firewall.apply_calls == 0U);
}

TEST_CASE("worker attempt retains a failed post-commit FastNAT check") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};
    meta_services.throw_fastnat_on_call = 2U;

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);

    CHECK(result.transaction.committed());
    CHECK(result.fastnat.attempted);
    REQUIRE(result.fastnat.disabled_or_unavailable.has_value());
    CHECK(*result.fastnat.disabled_or_unavailable);
    CHECK_FALSE(result.fastnat.failure.failed());
    CHECK(result.fastnat_after_commit.attempted);
    CHECK_FALSE(
        result.fastnat_after_commit.disabled_or_unavailable.has_value());
    CHECK(result.fastnat_after_commit.failure.failed());
    CHECK(result.fastnat_after_commit.failure.kind ==
          RuntimeFirewallWorkerInspectionFailureKind::standard_exception);
    CHECK(result.fastnat_after_commit.failure.message ==
          "FastNAT inspection failed");
    CHECK(result.owned_snat_after.attempted);
    CHECK(firewall.apply_calls == 1U);
    CHECK(meta_services.fastnat_calls == 2U);
    CHECK(order == std::vector<std::string>{
        "inspect:snat-before",
        "stage",
        "meta:fastnat",
        "meta:capability",
        "meta:interfaces",
        "meta:observation",
        "commit",
        "inspect:meta-filter-after",
        "meta:fastnat",
        "inspect:snat-after",
    });
}

TEST_CASE("worker attempt does not invent a FastNAT observation") {
    WorkerAttemptTempDirectory temp;
    auto input = worker_attempt_input(temp.path() / "cache");
    input.transaction.config = parse_config(R"json({
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
    std::vector<std::string> order;
    WorkerAttemptFirewall firewall{order};
    WorkerAttemptMetaServices meta_services{order};

    const auto result = execute_runtime_firewall_worker_attempt(
        input, firewall, meta_services);

    CHECK(result.transaction.committed());
    CHECK_FALSE(result.fastnat.attempted);
    CHECK_FALSE(result.fastnat.disabled_or_unavailable.has_value());
    CHECK_FALSE(result.fastnat.failure.failed());
    CHECK_FALSE(result.fastnat_after_commit.attempted);
    CHECK(meta_services.fastnat_calls == 0U);
}
