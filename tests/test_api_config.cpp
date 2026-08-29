#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_config.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/backup/persistent_snapshot.hpp"
#include "../src/backup/restore_journal.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/daemon/config_store.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class ConfigApiTempDir {
public:
    ConfigApiTempDir() {
        char pattern[] = "/tmp/keen-pbr-api-config-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~ConfigApiTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

void write_text(const std::filesystem::path& path,
                const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << content;
    REQUIRE(output);
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

mode_t file_mode(const std::filesystem::path& path) {
    struct stat metadata {};
    REQUIRE(::stat(path.c_str(), &metadata) == 0);
    return metadata.st_mode & 0777;
}

std::filesystem::path config_save_journal_path(
    const ConfigApiTempDir& directory) {
    return directory.path /
           ".keen-pbr-recovery" /
           "config-save";
}

Config make_valid_config(const std::string& listen) {
    auto document = nlohmann::json::parse(R"({
        "daemon": {
            "cache_dir": "/tmp/keen-pbr-api-config-cache",
            "firewall_backend": "auto"
        },
        "api": {
            "enabled": true,
            "listen": "127.0.0.1:12121"
        },
        "outbounds": [
            {
                "type": "table",
                "tag": "wan",
                "table": 254
            }
        ],
        "dns": {
            "system_resolver": {
                "address": "127.0.0.1"
            },
            "servers": [
                {
                    "tag": "default_dns",
                    "address": "127.0.0.1"
                }
            ],
            "fallback": [
                "default_dns"
            ]
        },
        "route": {
            "rules": []
        }
    })");
    document["api"]["listen"] = listen;
    auto config = parse_config(document.dump());
    validate_config(config);
    return config;
}

Config make_recommended_list_config(
    const std::string& listen,
    const std::string& list_id) {
    Config config = make_valid_config(listen);

    ListConfig list;
    list.display_name = "Recommended test list";
    list.domains = std::vector<std::string>{"example.test"};
    config.lists =
        std::map<std::string, ListConfig>{{list_id, std::move(list)}};

    REQUIRE(config.dns.has_value());
    REQUIRE(config.dns->servers.has_value());
    REQUIRE_FALSE(config.dns->servers->empty());
    config.dns->servers->front().detour = "wan";

    DnsRule dns_rule;
    dns_rule.list = {list_id};
    dns_rule.server = config.dns->servers->front().tag;
    config.dns->rules = std::vector<DnsRule>{std::move(dns_rule)};

    REQUIRE(config.route.has_value());
    RouteRule route_rule;
    route_rule.list = std::vector<std::string>{list_id};
    route_rule.outbound = "wan";
    config.route->rules =
        std::vector<RouteRule>{std::move(route_rule)};

    validate_config(config);
    return config;
}

Config make_list_delete_config(
    const std::string& listen) {
    Config config = make_recommended_list_config(
        listen, "legacy");

    ListConfig replacement;
    replacement.display_name = "Replacement list";
    replacement.domains =
        std::vector<std::string>{"replacement.test"};
    REQUIRE(config.lists.has_value());
    config.lists->emplace(
        "replacement", std::move(replacement));
    validate_config(config);
    return config;
}

struct FakeMaintenanceState {
    std::vector<std::string> events;
    std::optional<MaintenanceLockErrorKind> acquire_error;
    std::optional<MaintenanceLockErrorKind> reserve_error;
    std::optional<MaintenanceLockErrorKind> verify_error;
    std::uint32_t base_generation{7};
    std::size_t reserve_calls{0};
    std::size_t verify_calls{0};
    std::size_t active_leases{0};
};

class FakeMaintenanceLease final : public MaintenanceLease {
public:
    explicit FakeMaintenanceLease(
        std::shared_ptr<FakeMaintenanceState> state)
        : state_(std::move(state)) {
        ++state_->active_leases;
        state_->events.push_back("lease-open");
    }

    ~FakeMaintenanceLease() override {
        state_->events.push_back("lease-release");
        --state_->active_leases;
    }

    std::uint32_t base_generation() const noexcept override {
        state_->events.push_back("base-generation");
        return state_->base_generation;
    }

    std::uint32_t reserve(
        std::uint32_t expected_generation) override {
        state_->events.push_back(
            "reserve:" + std::to_string(expected_generation));
        ++state_->reserve_calls;
        if (state_->reserve_error.has_value()) {
            throw MaintenanceLockError(
                *state_->reserve_error,
                "injected maintenance reserve failure",
                *state_->reserve_error ==
                        MaintenanceLockErrorKind::stale_generation
                    ? 73
                    : 1);
        }
        return expected_generation + 1U;
    }

    void verify_held() override {
        state_->events.push_back("verify-held");
        ++state_->verify_calls;
        if (state_->verify_error.has_value()) {
            throw MaintenanceLockError(
                *state_->verify_error,
                "injected maintenance verification failure",
                1);
        }
    }

private:
    std::shared_ptr<FakeMaintenanceState> state_;
};

void install_fake_maintenance(
    ApiContext& context,
    const std::shared_ptr<FakeMaintenanceState>& state) {
    context.maintenance_lease_factory_fn =
        [state](std::string operation)
            -> std::unique_ptr<MaintenanceLease> {
        state->events.push_back("acquire:" + operation);
        if (state->acquire_error.has_value()) {
            throw MaintenanceLockError(
                *state->acquire_error,
                "injected maintenance acquire failure",
                *state->acquire_error == MaintenanceLockErrorKind::busy
                    ? 75
                    : 1);
        }
        return std::make_unique<FakeMaintenanceLease>(state);
    };
}

void install_runtime_mutation_admission(
    ApiContext& context,
    RuntimeMutationAdmission& admission,
    std::vector<std::string>* events = nullptr,
    std::size_t* handoff_gate_calls = nullptr) {
    context.acquire_runtime_mutation_fn =
        [&admission](std::string label, bool, bool) {
            auto lease = admission.try_acquire(std::move(label));
            if (!lease.has_value()) {
                throw std::runtime_error(
                    "injected runtime mutation admission conflict");
            }
            return std::move(*lease);
        };
    context.validate_runtime_mutation_lease_fn =
        [&admission, events](
            const RuntimeMutationAdmission::Lease& lease) {
            if (events != nullptr) {
                events->push_back("runtime-lease-restored");
            }
            return admission.owns(lease);
        };
    context.try_acquire_runtime_mutation_handoff_gate_fn =
        [&admission, handoff_gate_calls](
            const RuntimeMutationAdmission::Lease& lease) noexcept {
            if (handoff_gate_calls != nullptr) {
                ++*handoff_gate_calls;
            }
            return admission.try_acquire_handoff_gate(lease);
        };
}

std::size_t event_index(
    const std::vector<std::string>& events,
    const std::string& expected) {
    const auto found =
        std::find(events.begin(), events.end(), expected);
    if (found == events.end()) {
        throw std::runtime_error(
            "Expected maintenance event was not recorded: " +
            expected);
    }
    return static_cast<std::size_t>(
        std::distance(events.begin(), found));
}

ApiContext make_config_context(
    const std::string& config_path,
    SseBroadcaster& broadcaster,
    const Config& staged,
    const std::string& staged_json,
    std::size_t& begin_calls,
    std::size_t& finish_calls,
    std::size_t& apply_calls,
    bool fail_first_finish_after_apply = false) {
    return ApiContext{
        config_path,
        broadcaster,
        [staged] { return staged; },
        [] { return true; },
        [](Config, std::string) {},
        [staged, staged_json]()
            -> std::optional<std::pair<Config, std::string>> {
            return std::make_pair(staged, staged_json);
        },
        [] {},
        [](const Config&) {},
        [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<std::string, api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        [&begin_calls] { ++begin_calls; },
        [&finish_calls, &apply_calls, fail_first_finish_after_apply] {
            ++finish_calls;
            if (fail_first_finish_after_apply &&
                apply_calls > 0U && finish_calls == 1U) {
                throw std::runtime_error(
                    "injected post-apply reporting fault");
            }
        },
        [&apply_calls](Config, std::string) {
            ++apply_calls;
            ConfigApplyResult result;
            result.applied = true;
            return result;
        },
        [] {},
        [] {},
        [] {},
        [](std::optional<std::string>) {
            return ListRefreshOperationResult{};
        },
    };
}

void connect_config_store(
    ApiContext& context,
    ConfigStore& store) {
    context.get_visible_config_fn =
        [&store]() { return store.visible_config(); };
    context.config_is_draft_fn =
        [&store]() { return store.config_is_draft(); };
    context.stage_config_fn =
        [&store](Config config, std::string serialized) {
            store.stage_config(
                std::move(config), std::move(serialized));
        };
    context.get_staged_config_snapshot_fn =
        [&store]() { return store.staged_snapshot(); };
    context.clear_staged_config_fn =
        [&store]() { store.clear_staged(); };
    context.get_visible_config_snapshot_fn =
        [&store]() { return store.visible_snapshot(); };
    context.get_staged_config_cas_snapshot_fn =
        [&store]() { return store.staged_cas_snapshot(); };
    context.stage_config_if_visible_revision_fn =
        [&store](
            const std::string& expected_visible_revision,
            Config config,
            std::string serialized) {
            return store.stage_config_if_visible_revision(
                expected_visible_revision,
                std::move(config),
                std::move(serialized));
        };
}

struct ExpectedConfigLifecycleProjection {
    LifecycleOperationResult result;
    LifecycleOperationStatus validation;
    LifecycleOperationStatus commit;
    bool finished;
    std::string error;
};

bool matches_config_lifecycle_projection(
    const LifecycleOperationSnapshot& actual,
    const ExpectedConfigLifecycleProjection& expected) {
    return actual.result == expected.result &&
           actual.finished_at.has_value() == expected.finished &&
           actual.error == expected.error &&
           actual.stages.size() == 2U &&
           actual.stages[0].status == expected.validation &&
           actual.stages[1].status == expected.commit;
}

void check_config_lifecycle_milestones(
    const std::vector<LifecycleOperationSnapshot>& actual,
    const std::vector<ExpectedConfigLifecycleProjection>& expected) {
    REQUIRE_FALSE(actual.empty());
    REQUIRE_FALSE(expected.empty());

    const std::string operation_id = actual.front().id;
    REQUIRE_FALSE(operation_id.empty());

    std::size_t next_expected = 0;
    for (const auto& snapshot : actual) {
        CHECK(snapshot.id == operation_id);
        CHECK(snapshot.type == LifecycleOperationType::ApplyConfig);
        REQUIRE(snapshot.stages.size() == 2U);
        CHECK(snapshot.stages[0].id == "validate_config");
        CHECK(snapshot.stages[1].id == "commit_and_apply");

        if (next_expected < expected.size() &&
            matches_config_lifecycle_projection(
                snapshot, expected[next_expected])) {
            ++next_expected;
        }
    }

    CHECK(next_expected == expected.size());
    CHECK(matches_config_lifecycle_projection(
        actual.back(), expected.back()));
}

void check_config_draft_unchanged(
    ConfigStore& store,
    const StagedConfigSnapshot& expected) {
    const auto actual = store.staged_cas_snapshot();
    REQUIRE(actual.has_value());
    CHECK(store.config_is_draft());
    CHECK(actual->serialized == expected.serialized);
    CHECK(actual->base_revision == expected.base_revision);
    CHECK(actual->active_revision == expected.active_revision);
    CHECK(nlohmann::json(actual->config) ==
          nlohmann::json(expected.config));
}

bool corrupt_active_config_save_rollback(
    const std::filesystem::path& journal_path) noexcept {
    try {
        RestoreJournal journal(journal_path);
        const auto active = journal.read_active();
        if (!active.has_value()) return false;

        std::ofstream output(
            journal_path /
                (active->transaction_id + ".rollback"),
            std::ios::binary | std::ios::trunc);
        if (!output) return false;
        output << "corrupt rollback payload";
        output.flush();
        const bool written = output.good();
        output.close();
        return written && !output.fail();
    } catch (...) {
        return false;
    }
}

} // namespace

TEST_CASE(
    "recommended list setup stages only the visible config revision") {
    constexpr int api_port = 18261;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config active =
        make_valid_config("127.0.0.1:12121");
    ConfigStore store(active);
    const Config candidate = make_recommended_list_config(
        "127.0.0.1:12121", "recommended");

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        active,
        nlohmann::json(active).dump(),
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string&, const std::string&) {});
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto initial_response = client.Get("/api/config");
    REQUIRE(initial_response != nullptr);
    REQUIRE(initial_response->status == 200);
    const nlohmann::json initial =
        nlohmann::json::parse(initial_response->body);
    const std::string base_revision =
        initial.at("revision").get<std::string>();
    REQUIRE(base_revision.size() == 64U);

    const auto stage_response = client.Post(
        "/api/setup/list/stage",
        nlohmann::json{
            {"config", candidate},
            {"list_id", "recommended"},
            {"base_revision", base_revision},
        }
            .dump(),
        "application/json");
    server.stop();

    REQUIRE(stage_response != nullptr);
    CHECK(stage_response->status == 200);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(apply_calls == 0U);
    CHECK_FALSE(store.active_config().lists.has_value());
    const auto staged = store.staged_cas_snapshot();
    REQUIRE(staged.has_value());
    CHECK(staged->base_revision == base_revision);
    REQUIRE(staged->config.lists.has_value());
    CHECK(staged->config.lists->count("recommended") == 1U);
}

TEST_CASE(
    "recommended list setup rejects a stale revision without clobbering active config") {
    constexpr int api_port = 18262;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:12121");
    ConfigStore store(original);
    const Config stale_candidate = make_recommended_list_config(
        "127.0.0.1:12121", "recommended");

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        original,
        nlohmann::json(original).dump(),
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string&, const std::string&) {});
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto initial_response = client.Get("/api/config");
    REQUIRE(initial_response != nullptr);
    REQUIRE(initial_response->status == 200);
    const std::string stale_revision =
        nlohmann::json::parse(initial_response->body)
            .at("revision")
            .get<std::string>();

    Config replacement =
        make_valid_config("127.0.0.1:12122");
    const nlohmann::json replacement_json = replacement;
    store.replace_active(
        replacement,
        allocate_outbound_marks(
            replacement.fwmark.value_or(FwmarkConfig{}),
            replacement.outbounds.value_or(
                std::vector<Outbound>{})));

    const auto stage_response = client.Post(
        "/api/setup/list/stage",
        nlohmann::json{
            {"config", stale_candidate},
            {"list_id", "recommended"},
            {"base_revision", stale_revision},
        }
            .dump(),
        "application/json");
    server.stop();

    REQUIRE(stage_response != nullptr);
    CHECK(stage_response->status == 409);
    const nlohmann::json error =
        nlohmann::json::parse(stage_response->body);
    CHECK(error.at("reason") == "base_revision_mismatch");
    CHECK(error.at("base_revision") == stale_revision);
    CHECK(error.at("current_base_revision") != stale_revision);
    CHECK(error.at("staged") == false);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(apply_calls == 0U);
    CHECK_FALSE(store.staged_cas_snapshot().has_value());
    CHECK(nlohmann::json(store.active_config()) == replacement_json);
}

TEST_CASE(
    "list delete endpoint atomically stages backend-planned rebinds") {
    constexpr int api_port = 18263;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config active =
        make_list_delete_config("127.0.0.1:12121");
    ConfigStore store(active);

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        active,
        nlohmann::json(active).dump(),
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string&, const std::string&) {});
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto initial_response = client.Get("/api/config");
    REQUIRE(initial_response != nullptr);
    REQUIRE(initial_response->status == 200);
    const std::string base_revision =
        nlohmann::json::parse(initial_response->body)
            .at("revision")
            .get<std::string>();

    const auto stage_response = client.Post(
        "/api/setup/lists/delete/stage",
        nlohmann::json{
            {"base_revision", base_revision},
            {"targets",
             nlohmann::json::array(
                 {{{"list_id", "legacy"},
                   {"replacement_list_id",
                    "replacement"}}})},
        }
            .dump(),
        "application/json");
    server.stop();

    REQUIRE(stage_response != nullptr);
    CHECK(stage_response->status == 200);
    const nlohmann::json response =
        nlohmann::json::parse(stage_response->body);
    CHECK(response.at("staged") == true);
    CHECK(
        response.at("summary")
            .at("rebound_references") == 2);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(apply_calls == 0U);
    CHECK(store.active_config().lists->count("legacy") == 1U);

    const auto staged = store.staged_cas_snapshot();
    REQUIRE(staged.has_value());
    REQUIRE(staged->config.lists.has_value());
    CHECK(staged->config.lists->count("legacy") == 0U);
    CHECK(
        staged->config.lists->count("replacement") == 1U);
    REQUIRE(staged->config.route.has_value());
    REQUIRE(staged->config.route->rules.has_value());
    CHECK(
        route_rule_lists(
            staged->config.route->rules->front()) ==
        std::vector<std::string>{"replacement"});
    REQUIRE(staged->config.dns.has_value());
    REQUIRE(staged->config.dns->rules.has_value());
    CHECK(
        staged->config.dns->rules->front().list ==
        std::vector<std::string>{"replacement"});
}

TEST_CASE(
    "list delete endpoint preserves a newer visible draft on CAS conflict") {
    constexpr int api_port = 18264;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config active =
        make_list_delete_config("127.0.0.1:12121");
    ConfigStore store(active);

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        active,
        nlohmann::json(active).dump(),
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);

    const std::string stale_revision =
        store.visible_snapshot().revision;
    Config newer = active;
    newer.api->listen = "127.0.0.1:12122";
    store.stage_config(
        newer, nlohmann::json(newer).dump());
    const std::string newer_revision =
        store.visible_snapshot().revision;
    REQUIRE(newer_revision != stale_revision);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string&, const std::string&) {});
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response = client.Post(
        "/api/setup/lists/delete/stage",
        nlohmann::json{
            {"base_revision", stale_revision},
            {"targets",
             nlohmann::json::array(
                 {{{"list_id", "legacy"}}})},
        }
            .dump(),
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 409);
    const nlohmann::json error =
        nlohmann::json::parse(response->body);
    CHECK(error.at("reason") == "base_revision_mismatch");
    CHECK(error.at("current_base_revision") == newer_revision);
    CHECK(error.at("draft_preserved") == true);
    CHECK(error.at("staged") == false);
    CHECK(begin_calls == 0U);
    CHECK(finish_calls == 0U);
    CHECK(apply_calls == 0U);
    CHECK(
        store.visible_snapshot().revision ==
        newer_revision);
    CHECK(store.visible_snapshot().is_draft);
}

TEST_CASE(
    "config save restores disk after post-rename atomic write failure") {
    constexpr int api_port = 18231;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";

    const Config original = make_valid_config("127.0.0.1:18231");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    REQUIRE(::chmod(config_path.c_str(), 0600) == 0);

    const Config staged = make_valid_config("127.0.0.1:18232");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    std::size_t write_calls = 0;
    const auto writer =
        [&write_calls](const std::string& path,
                       const std::string& body) {
            ++write_calls;
            if (write_calls == 1) {
                AtomicFileWriteOptions options;
                options.fault_injector =
                    [path](AtomicFileWriteStage stage) {
                        if (stage ==
                            AtomicFileWriteStage::directory_fsync) {
                            if (::chmod(path.c_str(), 0644) != 0) {
                                throw std::system_error(
                                    errno,
                                    std::generic_category(),
                                    "cannot alter injected replacement mode");
                            }
                            throw std::system_error(
                                EIO,
                                std::generic_category(),
                                "injected post-rename durability fault");
                        }
                    };
                write_file_atomically(path, body, options);
                return;
            }
            write_config_atomically(path, body);
        };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(server, context, writer);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");

    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(read_text(config_path) == original_json);
    CHECK(file_mode(config_path) == 0600);
    CHECK(write_calls == 1U);
    CHECK(apply_calls == 0U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
}

TEST_CASE(
    "config save keeps disk and runtime aligned after post-apply reporting failure") {
    constexpr int api_port = 18233;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";

    const Config original = make_valid_config("127.0.0.1:18233");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    const Config staged = make_valid_config("127.0.0.1:18234");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls,
        true);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    std::size_t write_calls = 0;
    const auto writer =
        [&write_calls](const std::string& path,
                       const std::string& body) {
            ++write_calls;
            write_config_atomically(path, body);
        };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(server, context, writer);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");

    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(read_text(config_path) == staged_json);
    CHECK(write_calls == 1U);
    CHECK(apply_calls == 1U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 2U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
    CHECK(event_index(
              maintenance->events, "reserve:7") <
          event_index(
              maintenance->events, "lease-release"));
}

TEST_CASE(
    "config save acquires maintenance before config operation and reserves before write") {
    constexpr int api_port = 18235;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18235");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    const Config staged = make_valid_config("127.0.0.1:18236");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.begin_save_operation_fn =
        [&] {
            maintenance->events.push_back("begin-config");
            ++begin_calls;
        };
    context.finish_config_operation_fn =
        [&] {
            maintenance->events.push_back("finish-config");
            ++finish_calls;
        };
    context.validate_candidate_config_fn =
        [&](const Config&) {
            maintenance->events.push_back("validate");
        };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            maintenance->events.push_back("apply");
            ++apply_calls;
            ConfigApplyResult result;
            result.applied = true;
            return result;
        };
    bool wal_active_before_write = false;
    bool rollback_payload_has_original = false;
    const auto writer =
        [&](const std::string& path, const std::string& body) {
            maintenance->events.push_back("write");
            RestoreJournal journal(
                config_save_journal_path(directory));
            const auto active = journal.read_active();
            wal_active_before_write = active.has_value();
            if (active.has_value()) {
                const auto payload =
                    nlohmann::json::parse(
                        journal.read_rollback_payload(*active));
                const auto parsed =
                    backup::parse_persistent_snapshot(payload);
                rollback_payload_has_original =
                    parsed.entries.size() == 1U &&
                    parsed.entries.front().target == "config" &&
                    parsed.entries.front().content == original_json;
            }
            write_config_atomically(path, body);
        };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(server, context, writer);
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(read_text(config_path) == staged_json);
    CHECK(wal_active_before_write);
    CHECK(rollback_payload_has_original);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
    CHECK(event_index(
              maintenance->events, "acquire:config-save") <
          event_index(maintenance->events, "begin-config"));
    CHECK(event_index(maintenance->events, "validate") <
          event_index(maintenance->events, "reserve:7"));
    CHECK(event_index(maintenance->events, "reserve:7") <
          event_index(maintenance->events, "write"));
    CHECK(event_index(maintenance->events, "finish-config") <
          event_index(maintenance->events, "lease-release"));
}

TEST_CASE(
    "successful config save publishes ordered apply lifecycle milestones") {
    constexpr int api_port = 18265;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18265");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    const Config staged = make_valid_config("127.0.0.1:18266");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t validation_calls = 0;
    std::size_t write_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.validate_candidate_config_fn =
        [&](const Config&) {
            ++validation_calls;
            maintenance->events.push_back("validate");
        };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++apply_calls;
            maintenance->events.push_back("apply");
            ConfigApplyResult result;
            result.applied = true;
            return result;
        };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    std::vector<LifecycleOperationSnapshot> lifecycle_updates;
    lifecycle_store.set_publish_callback([&] {
        const auto snapshot = lifecycle_store.snapshot();
        if (snapshot.has_value()) {
            lifecycle_updates.push_back(*snapshot);
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string& path, const std::string& body) {
            ++write_calls;
            maintenance->events.push_back("write");
            write_config_atomically(path, body);
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("saved") == true);
    CHECK(payload.at("applied") == true);
    CHECK(validation_calls == 1U);
    CHECK(write_calls == 1U);
    CHECK(apply_calls == 1U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
    CHECK(read_text(config_path) == staged_json);
    CHECK(event_index(maintenance->events, "validate") <
          event_index(maintenance->events, "write"));
    CHECK(event_index(maintenance->events, "write") <
          event_index(maintenance->events, "apply"));

    check_config_lifecycle_milestones(
        lifecycle_updates,
        {
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Running,
             LifecycleOperationStatus::Pending,
             false,
             {}},
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Running,
             false,
             {}},
            {LifecycleOperationResult::Succeeded,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Succeeded,
             true,
             {}},
        });
}

TEST_CASE(
    "invalid config never crosses the persistent or runtime boundary") {
    constexpr int api_port = 18266;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18266");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    const Config staged = make_valid_config("127.0.0.1:18267");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    ConfigStore store(original);
    store.stage_config(staged, staged_json);
    const auto draft_before = store.staged_cas_snapshot();
    REQUIRE(draft_before.has_value());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t validation_calls = 0;
    std::size_t write_calls = 0;
    std::size_t stop_calls = 0;
    std::size_t emergency_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.validate_candidate_config_fn =
        [&](const Config&) {
            ++validation_calls;
            throw ConfigValidationError(
                std::vector<ConfigValidationIssue>{{
                    "route.rules[0]",
                    "synthetic invalid candidate",
                }});
        };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++apply_calls;
            return ConfigApplyResult{};
        };
    context.stop_runtime_fn = [&] { ++stop_calls; };
    context.emergency_quiesce_runtime_fn =
        [&] { ++emergency_calls; };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    std::vector<LifecycleOperationSnapshot> lifecycle_updates;
    lifecycle_store.set_publish_callback([&] {
        const auto snapshot = lifecycle_store.snapshot();
        if (snapshot.has_value()) {
            lifecycle_updates.push_back(*snapshot);
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string&, const std::string&) {
            ++write_calls;
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 400);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("error") == "synthetic invalid candidate");
    CHECK(payload.at("saved") == false);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == false);
    REQUIRE(payload.at("validation_errors").size() == 1U);
    CHECK(payload.at("validation_errors")[0].at("path") ==
          "route.rules[0]");
    CHECK(payload.at("validation_errors")[0].at("message") ==
          "synthetic invalid candidate");
    CHECK(validation_calls == 1U);
    CHECK(write_calls == 0U);
    CHECK(apply_calls == 0U);
    CHECK(stop_calls == 0U);
    CHECK(emergency_calls == 0U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(maintenance->reserve_calls == 0U);
    CHECK(maintenance->active_leases == 0U);
    CHECK(read_text(config_path) == original_json);
    CHECK_FALSE(std::filesystem::exists(
        config_save_journal_path(directory)));

    const auto draft_after = store.staged_cas_snapshot();
    REQUIRE(draft_after.has_value());
    CHECK(store.config_is_draft());
    CHECK(draft_after->serialized == draft_before->serialized);
    CHECK(draft_after->base_revision == draft_before->base_revision);
    CHECK(draft_after->active_revision ==
          draft_before->active_revision);

    check_config_lifecycle_milestones(
        lifecycle_updates,
        {
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Running,
             LifecycleOperationStatus::Pending,
             false,
             {}},
            {LifecycleOperationResult::Failed,
             LifecycleOperationStatus::Failed,
             LifecycleOperationStatus::Skipped,
             true,
             "synthetic invalid candidate"},
        });
}

TEST_CASE(
    "config save WAL begin failure stays before reservation and fails closed") {
    constexpr int api_port = 18268;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto recovery_root = directory.path / "recovery";
    const auto operation_journal = recovery_root / "config-save";

    const Config original = make_valid_config("127.0.0.1:18268");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18269");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    ConfigStore store(original);
    store.stage_config(staged, staged_json);
    const auto draft_before = store.staged_cas_snapshot();
    REQUIRE(draft_before.has_value());

    RestoreJournal(operation_journal).mark_unknown();

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t validation_calls = 0;
    std::size_t write_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t stop_calls = 0;
    std::size_t emergency_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.validate_candidate_config_fn =
        [&](const Config&) { ++validation_calls; };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++apply_calls;
            return ConfigApplyResult{};
        };
    context.stop_runtime_fn = [&] { ++stop_calls; };
    context.emergency_quiesce_runtime_fn = [&] {
        ++emergency_calls;
        throw std::runtime_error(
            "synthetic emergency quiesce failure");
    };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    std::vector<LifecycleOperationSnapshot> lifecycle_updates;
    lifecycle_store.set_publish_callback([&] {
        const auto snapshot = lifecycle_store.snapshot();
        if (snapshot.has_value()) {
            lifecycle_updates.push_back(*snapshot);
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    ConfigSaveTestOptions options;
    options.recovery_state_root = recovery_root;
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string&, const std::string&) {
            ++write_calls;
        },
        std::move(options));
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("error") ==
          "Cannot start the durable configuration recovery journal: "
          "Restore journal is unsafe: UNKNOWN marker is present");
    CHECK(payload.at("saved") == false);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == false);
    CHECK(payload.at("recovery_required") == true);
    CHECK(payload.at("runtime_quiesced") == false);
    CHECK_FALSE(payload.contains("recovery_error"));
    CHECK(validation_calls == 1U);
    CHECK(write_calls == 0U);
    CHECK(apply_calls == 0U);
    CHECK(maintenance->reserve_calls == 0U);
    CHECK(emergency_calls == 1U);
    CHECK(stop_calls == 0U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
    CHECK(read_text(config_path) == original_json);
    check_config_draft_unchanged(store, *draft_before);
    CHECK(RestoreJournal(operation_journal).unknown_present());

    check_config_lifecycle_milestones(
        lifecycle_updates,
        {
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Running,
             false,
             {}},
            {LifecycleOperationResult::Failed,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Failed,
             true,
             "Cannot start configuration recovery journal"},
        });
}

TEST_CASE(
    "config save converts a direct runtime ApiError into recovery required") {
    constexpr int api_port = 18270;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18270");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18271");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    ConfigStore store(original);
    store.stage_config(staged, staged_json);
    const auto draft_before = store.staged_cas_snapshot();
    REQUIRE(draft_before.has_value());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t validation_calls = 0;
    std::size_t write_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t emergency_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.validate_candidate_config_fn =
        [&](const Config&) { ++validation_calls; };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) -> ConfigApplyResult {
            ++apply_calls;
            throw ApiError(
                "synthetic runtime conflict",
                409,
                nlohmann::json{{"error", "must not escape"}}.dump());
        };
    context.emergency_quiesce_runtime_fn =
        [&] { ++emergency_calls; };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    std::vector<LifecycleOperationSnapshot> lifecycle_updates;
    lifecycle_store.set_publish_callback([&] {
        const auto snapshot = lifecycle_store.snapshot();
        if (snapshot.has_value()) {
            lifecycle_updates.push_back(*snapshot);
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string& path, const std::string& body) {
            ++write_calls;
            write_config_atomically(path, body);
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("error") ==
          "Configuration runtime apply was interrupted; runtime state is "
          "unknown");
    CHECK(payload.at("saved") == false);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == false);
    CHECK(payload.at("recovery_required") == true);
    CHECK(payload.at("runtime_quiesced") == true);
    CHECK_FALSE(payload.contains("recovery_error"));
    CHECK(validation_calls == 1U);
    CHECK(write_calls == 1U);
    CHECK(apply_calls == 1U);
    CHECK(emergency_calls == 1U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
    CHECK(read_text(config_path) == staged_json);
    check_config_draft_unchanged(store, *draft_before);

    RestoreJournal journal(config_save_journal_path(directory));
    const auto active = journal.read_active();
    REQUIRE(active.has_value());
    CHECK(active->phase == RestoreJournalPhase::files_committed);

    check_config_lifecycle_milestones(
        lifecycle_updates,
        {
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Running,
             false,
             {}},
            {LifecycleOperationResult::Failed,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Failed,
             true,
             "Configuration runtime apply was interrupted"},
        });
}

TEST_CASE(
    "config save fails closed when exact persistent recovery cannot be proven") {
    struct RecoveryFailureCase {
        bool runtime_rolled_back;
        int api_port;
        const char* expected_error;
    };
    const std::vector<RecoveryFailureCase> cases{
        {
            false,
            18272,
            "Configuration write failed and exact recovery could not be "
            "proven",
        },
        {
            true,
            18273,
            "Runtime rolled back, but exact persistent recovery could not be "
            "proven",
        },
    };

    for (const auto& failure : cases) {
        CAPTURE(failure.runtime_rolled_back);
        ConfigApiTempDir directory;
        const auto config_path = directory.path / "config.json";
        const auto recovery_root =
            directory.path / ".keen-pbr-recovery";
        const auto operation_journal =
            recovery_root / "config-save";
        const Config original = make_valid_config(
            "127.0.0.1:" + std::to_string(failure.api_port));
        const std::string original_json =
            nlohmann::json(original).dump(1, '\t') + "\n";
        write_text(config_path, original_json);
        const Config staged = make_valid_config(
            "127.0.0.1:" +
            std::to_string(failure.api_port + 10));
        const std::string staged_json =
            nlohmann::json(staged).dump(1, '\t') + "\n";
        ConfigStore store(original);
        store.stage_config(staged, staged_json);
        const auto draft_before = store.staged_cas_snapshot();
        REQUIRE(draft_before.has_value());

        SseBroadcaster broadcaster;
        std::size_t begin_calls = 0;
        std::size_t finish_calls = 0;
        std::size_t validation_calls = 0;
        std::size_t write_calls = 0;
        std::size_t apply_calls = 0;
        std::size_t emergency_calls = 0;
        bool rollback_corrupted = false;
        auto context = make_config_context(
            config_path.string(),
            broadcaster,
            staged,
            staged_json,
            begin_calls,
            finish_calls,
            apply_calls);
        connect_config_store(context, store);
        const auto maintenance =
            std::make_shared<FakeMaintenanceState>();
        install_fake_maintenance(context, maintenance);
        context.validate_candidate_config_fn =
            [&](const Config&) { ++validation_calls; };
        context.enqueue_apply_validated_config_fn =
            [&](Config, std::string) {
                ++apply_calls;
                REQUIRE(failure.runtime_rolled_back);
                rollback_corrupted =
                    corrupt_active_config_save_rollback(
                        operation_journal);
                ConfigApplyResult result;
                result.error = "synthetic runtime apply failure";
                result.rolled_back = true;
                return result;
            };
        context.emergency_quiesce_runtime_fn =
            [&] { ++emergency_calls; };

        LifecycleOperationStore lifecycle_store;
        LifecycleOperationCoordinator lifecycle(lifecycle_store);
        std::vector<LifecycleOperationSnapshot> lifecycle_updates;
        lifecycle_store.set_publish_callback([&] {
            const auto snapshot = lifecycle_store.snapshot();
            if (snapshot.has_value()) {
                lifecycle_updates.push_back(*snapshot);
            }
        });
        context.lifecycle_operations = &lifecycle;

        ApiConfig api_config;
        api_config.listen =
            "127.0.0.1:" + std::to_string(failure.api_port);
        ApiServer server(api_config);
        register_config_handler_for_test(
            server,
            context,
            [&](const std::string& path, const std::string& body) {
                ++write_calls;
                write_config_atomically(path, body);
                if (!failure.runtime_rolled_back) {
                    rollback_corrupted =
                        corrupt_active_config_save_rollback(
                            operation_journal);
                    throw std::runtime_error(
                        "synthetic config write failure");
                }
            });
        server.start();
        httplib::Client client("127.0.0.1", failure.api_port);
        const auto response = client.Post(
            "/api/config/save", "", "application/json");
        server.stop();

        REQUIRE(response != nullptr);
        CHECK(response->status == 503);
        REQUIRE(rollback_corrupted);
        const auto payload =
            nlohmann::json::parse(response->body);
        CHECK(payload.at("error") == failure.expected_error);
        CHECK(payload.at("saved") == false);
        CHECK(payload.at("applied") == false);
        CHECK(payload.at("rolled_back") ==
              failure.runtime_rolled_back);
        CHECK(payload.at("recovery_required") == true);
        CHECK(payload.at("runtime_quiesced") == true);
        CHECK(payload.at("recovery_error") ==
              "Cannot verify config-save recovery journal: Restore journal "
              "is unsafe: Restore rollback payload size does not match "
              "active marker");
        CHECK(validation_calls == 1U);
        CHECK(write_calls == 1U);
        CHECK(apply_calls ==
              (failure.runtime_rolled_back ? 1U : 0U));
        CHECK(emergency_calls == 1U);
        CHECK(maintenance->reserve_calls == 1U);
        CHECK(begin_calls == 1U);
        CHECK(finish_calls == 1U);
        CHECK(maintenance->active_leases == 0U);
        CHECK(read_text(config_path) == staged_json);
        check_config_draft_unchanged(store, *draft_before);
        CHECK(std::filesystem::exists(
            operation_journal / "active.json"));
        CHECK(RestoreJournal(operation_journal).unknown_present());
        CHECK(RestoreJournal(recovery_root).unknown_present());

        check_config_lifecycle_milestones(
            lifecycle_updates,
            {
                {LifecycleOperationResult::Running,
                 LifecycleOperationStatus::Succeeded,
                 LifecycleOperationStatus::Running,
                 false,
                 {}},
                {LifecycleOperationResult::Failed,
                 LifecycleOperationStatus::Succeeded,
                 LifecycleOperationStatus::Failed,
                 true,
                 "Configuration file recovery failed"},
            });
    }
}

TEST_CASE(
    "config save maintenance contention and stale generation do not mutate draft") {
    struct FailureCase {
        MaintenanceLockErrorKind kind;
        bool acquire_failure;
        std::size_t expected_begin_calls;
        std::size_t expected_finish_calls;
    };
    const std::vector<FailureCase> cases{
        {MaintenanceLockErrorKind::busy, true, 0, 0},
        {MaintenanceLockErrorKind::stale_generation, false, 1, 1},
    };

    int port = 18237;
    for (const auto& failure : cases) {
        CAPTURE(failure.acquire_failure);
        ConfigApiTempDir directory;
        const auto config_path = directory.path / "config.json";
        const Config original =
            make_valid_config("127.0.0.1:" + std::to_string(port));
        const std::string original_json =
            nlohmann::json(original).dump(1, '\t') + "\n";
        write_text(config_path, original_json);
        const Config staged =
            make_valid_config(
                "127.0.0.1:" + std::to_string(port + 20));
        const std::string staged_json =
            nlohmann::json(staged).dump(1, '\t') + "\n";

        SseBroadcaster broadcaster;
        std::size_t begin_calls = 0;
        std::size_t finish_calls = 0;
        std::size_t apply_calls = 0;
        std::size_t clear_calls = 0;
        std::size_t write_calls = 0;
        auto context = make_config_context(
            config_path.string(),
            broadcaster,
            staged,
            staged_json,
            begin_calls,
            finish_calls,
            apply_calls);
        context.clear_staged_config_fn =
            [&] { ++clear_calls; };
        const auto maintenance =
            std::make_shared<FakeMaintenanceState>();
        if (failure.acquire_failure) {
            maintenance->acquire_error = failure.kind;
        } else {
            maintenance->reserve_error = failure.kind;
        }
        install_fake_maintenance(context, maintenance);

        ApiConfig api_config;
        api_config.listen =
            "127.0.0.1:" + std::to_string(port);
        ApiServer server(api_config);
        register_config_handler_for_test(
            server,
            context,
            [&](const std::string& path, const std::string& body) {
                ++write_calls;
                write_config_atomically(path, body);
            });
        server.start();
        httplib::Client client("127.0.0.1", port);
        const auto response =
            client.Post("/api/config/save", "", "application/json");
        server.stop();

        REQUIRE(response != nullptr);
        CHECK(response->status == 409);
        CHECK(read_text(config_path) == original_json);
        CHECK(write_calls == 0U);
        CHECK(apply_calls == 0U);
        CHECK(clear_calls == 0U);
        CHECK(begin_calls == failure.expected_begin_calls);
        CHECK(finish_calls == failure.expected_finish_calls);
        CHECK(maintenance->active_leases == 0U);
        CHECK(maintenance->reserve_calls ==
              (failure.acquire_failure ? 0U : 1U));
        ++port;
    }
}

TEST_CASE(
    "config save keeps maintenance lease through runtime rollback") {
    constexpr int api_port = 18239;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18239");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18240");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    ConfigStore store(original);
    store.stage_config(staged, staged_json);
    const auto draft_before = store.staged_cas_snapshot();
    REQUIRE(draft_before.has_value());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t emergency_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.finish_config_operation_fn =
        [&] {
            maintenance->events.push_back("finish-config");
            ++finish_calls;
        };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            maintenance->events.push_back("apply-failed");
            ++apply_calls;
            ConfigApplyResult result;
            result.error = "injected apply failure";
            result.rolled_back = true;
            return result;
        };
    context.emergency_quiesce_runtime_fn =
        [&] { ++emergency_calls; };
    std::size_t write_calls = 0;
    const auto writer =
        [&](const std::string& path, const std::string& body) {
            maintenance->events.push_back("write-new");
            ++write_calls;
            write_config_atomically(path, body);
        };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    std::vector<LifecycleOperationSnapshot> lifecycle_updates;
    lifecycle_store.set_publish_callback([&] {
        const auto snapshot = lifecycle_store.snapshot();
        if (snapshot.has_value()) {
            lifecycle_updates.push_back(*snapshot);
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(server, context, writer);
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("saved") == false);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == true);
    CHECK(payload.at("runtime_unchanged") == false);
    CHECK(payload.at("file_rolled_back") == true);
    CHECK(payload.at("recovery_required") == false);
    CHECK(read_text(config_path) == original_json);
    CHECK(write_calls == 1U);
    CHECK(apply_calls == 1U);
    CHECK(emergency_calls == 0U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(event_index(maintenance->events, "apply-failed") <
          event_index(maintenance->events, "finish-config"));
    CHECK(event_index(maintenance->events, "finish-config") <
          event_index(maintenance->events, "lease-release"));
    CHECK(maintenance->active_leases == 0U);
    CHECK_FALSE(std::filesystem::exists(
        config_save_journal_path(directory) / "active.json"));
    CHECK_FALSE(RestoreJournal(
                    config_save_journal_path(directory))
                    .unknown_present());
    check_config_draft_unchanged(store, *draft_before);

    check_config_lifecycle_milestones(
        lifecycle_updates,
        {
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Running,
             false,
             {}},
            {LifecycleOperationResult::Failed,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Failed,
             true,
             "Configuration commit or apply failed"},
        });
}

TEST_CASE(
    "config save marks UNKNOWN when exact rollback WAL removal fails") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18340");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const Config staged =
        make_valid_config("127.0.0.1:18341");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++apply_calls;
            ConfigApplyResult result;
            result.error = "injected runtime apply failure";
            result.rolled_back = true;
            return result;
        };
    std::size_t quiesce_calls = 0;
    context.emergency_quiesce_runtime_fn =
        [&] { ++quiesce_calls; };

    ConfigSaveTestOptions options;
    options.restore_journal_hooks.fault_injector =
        [](RestoreJournalFaultStage stage) {
            if (stage == RestoreJournalFaultStage::active_remove) {
                throw std::runtime_error(
                    "injected config-save active marker removal failure");
            }
        };

    try {
        (void)commit_prepared_config_for_test(
            context,
            "config-save-rollback-removal-failure",
            [&] {
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            },
            std::move(options));
        FAIL("an unproven rollback WAL removal must fail closed");
    } catch (const ApiError& error) {
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        const auto payload =
            nlohmann::json::parse(*error.body());
        CHECK(payload.at("saved") == false);
        CHECK(payload.at("applied") == false);
        CHECK(payload.at("rolled_back") == true);
        CHECK(payload.at("recovery_required") == true);
        CHECK(payload.at("runtime_quiesced") == true);
        CHECK(payload.at("recovery_error")
                  .get<std::string>()
                  .find(
                      "injected config-save active marker removal failure") !=
              std::string::npos);
    }

    const auto recovery_root =
        directory.path / ".keen-pbr-recovery";
    const auto operation_journal =
        config_save_journal_path(directory);
    CHECK(read_text(config_path) == original_json);
    CHECK(apply_calls == 1U);
    CHECK(quiesce_calls == 1U);
    CHECK(std::filesystem::exists(
        operation_journal / "active.json"));
    CHECK(RestoreJournal(operation_journal).unknown_present());
    CHECK(RestoreJournal(recovery_root).unknown_present());
    CHECK(maintenance->active_leases == 0U);
}

TEST_CASE(
    "config save restores the file without quiescing an unchanged runtime") {
    constexpr int api_port = 18259;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18259");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18260");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    ConfigStore store(original);
    store.stage_config(staged, staged_json);
    const auto draft_before = store.staged_cas_snapshot();
    REQUIRE(draft_before.has_value());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t stop_calls = 0;
    std::size_t write_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++apply_calls;
            ConfigApplyResult result;
            result.error = "remote list preparation failed";
            result.runtime_unchanged = true;
            return result;
        };
    context.emergency_quiesce_runtime_fn =
        [&] { ++stop_calls; };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    std::vector<LifecycleOperationSnapshot> lifecycle_updates;
    lifecycle_store.set_publish_callback([&] {
        const auto snapshot = lifecycle_store.snapshot();
        if (snapshot.has_value()) {
            lifecycle_updates.push_back(*snapshot);
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string& path, const std::string& body) {
            ++write_calls;
            write_config_atomically(path, body);
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    const auto payload =
        nlohmann::json::parse(response->body);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == false);
    CHECK(payload.at("runtime_unchanged") == true);
    CHECK(payload.at("file_rolled_back") == true);
    CHECK(payload.at("recovery_required") == false);
    CHECK(read_text(config_path) == original_json);
    CHECK(write_calls == 1U);
    CHECK(apply_calls == 1U);
    CHECK(stop_calls == 0U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(maintenance->active_leases == 0U);
    CHECK_FALSE(std::filesystem::exists(
        config_save_journal_path(directory) / "active.json"));
    CHECK_FALSE(RestoreJournal(
                    config_save_journal_path(directory))
                    .unknown_present());
    check_config_draft_unchanged(store, *draft_before);

    check_config_lifecycle_milestones(
        lifecycle_updates,
        {
            {LifecycleOperationResult::Running,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Running,
             false,
             {}},
            {LifecycleOperationResult::Failed,
             LifecycleOperationStatus::Succeeded,
             LifecycleOperationStatus::Failed,
             true,
             "Configuration commit or apply failed"},
        });
}

TEST_CASE(
    "config save releases maintenance after post-apply lifecycle fault") {
    constexpr int api_port = 18241;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18241");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18242");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.finish_config_operation_fn =
        [&] {
            maintenance->events.push_back("finish-config");
            ++finish_calls;
        };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            maintenance->events.push_back("apply");
            ++apply_calls;
            ConfigApplyResult result;
            result.applied = true;
            return result;
        };

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    bool injected = false;
    lifecycle_store.set_publish_callback([&] {
        if (apply_calls > 0U && !injected) {
            injected = true;
            maintenance->events.push_back("lifecycle-fault");
            throw std::runtime_error(
                "injected lifecycle publication failure");
        }
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string& path, const std::string& body) {
            maintenance->events.push_back("write");
            write_config_atomically(path, body);
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(injected);
    CHECK(read_text(config_path) == staged_json);
    CHECK(apply_calls == 1U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(event_index(maintenance->events, "lifecycle-fault") <
          event_index(maintenance->events, "finish-config"));
    CHECK(event_index(maintenance->events, "finish-config") <
          event_index(maintenance->events, "lease-release"));
    CHECK(maintenance->active_leases == 0U);
}

TEST_CASE(
    "config save releases config operation after lifecycle begin fault") {
    constexpr int api_port = 18243;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18243");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18244");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    LifecycleOperationStore lifecycle_store;
    LifecycleOperationCoordinator lifecycle(lifecycle_store);
    bool fail_once = true;
    lifecycle_store.set_publish_callback([&] {
        if (!fail_once) return;
        fail_once = false;
        throw std::runtime_error(
            "injected lifecycle begin publication failure");
    });
    context.lifecycle_operations = &lifecycle;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    std::size_t writer_calls = 0;
    register_config_handler_for_test(
        server,
        context,
        [&](const std::string&, const std::string&) {
            ++writer_calls;
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(read_text(config_path) == original_json);
    CHECK(apply_calls == 0U);
    CHECK(writer_calls == 0U);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(maintenance->reserve_calls == 0U);
    CHECK(maintenance->active_leases == 0U);

    LifecycleOperationSnapshot recovered;
    CHECK_FALSE(lifecycle.begin(
        LifecycleOperationType::ApplyConfig,
        {{"validate", "Validate"}},
        recovered));
    lifecycle.finish(recovered.id);
}

TEST_CASE(
    "config save fails closed when apply does not prove runtime rollback") {
    constexpr int api_port = 18245;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18245");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_json);
    const Config staged = make_valid_config("127.0.0.1:18246");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t stop_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++apply_calls;
            return ConfigApplyResult{
                false,
                false,
                std::nullopt,
                "",
            };
        };
    context.stop_runtime_fn = [] {
        throw std::runtime_error(
            "public stop callback would self-conflict");
    };
    context.emergency_quiesce_runtime_fn =
        [&] { ++stop_calls; };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string& path, const std::string& body) {
            write_config_atomically(path, body);
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    const auto payload =
        nlohmann::json::parse(response->body);
    CHECK(payload.at("recovery_required") == true);
    CHECK(payload.at("runtime_quiesced") == true);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == false);
    CHECK(read_text(config_path) == staged_json);
    CHECK(stop_calls == 1U);
    CHECK(apply_calls == 1U);

    RestoreJournal journal(config_save_journal_path(directory));
    const auto active = journal.read_active();
    REQUIRE(active.has_value());
    CHECK(std::regex_match(
        active->transaction_id,
        std::regex("^[0-9a-f]{32}$")));
    CHECK(active->phase == RestoreJournalPhase::files_committed);
}

TEST_CASE(
    "config save keeps WAL and quiesces when maintenance guardian is lost after apply") {
    constexpr int api_port = 18255;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18255");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const Config staged = make_valid_config("127.0.0.1:18256");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t quiesce_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    maintenance->verify_error =
        MaintenanceLockErrorKind::guardian_died;
    install_fake_maintenance(context, maintenance);
    context.emergency_quiesce_runtime_fn =
        [&] { ++quiesce_calls; };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string& path, const std::string& body) {
            write_config_atomically(path, body);
        });
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    const auto payload =
        nlohmann::json::parse(response->body);
    CHECK(payload.at("recovery_required") == true);
    CHECK(payload.at("runtime_quiesced") == true);
    CHECK(read_text(config_path) == staged_json);
    CHECK(apply_calls == 1U);
    CHECK(maintenance->verify_calls == 1U);
    CHECK(quiesce_calls == 1U);
    RestoreJournal journal(config_save_journal_path(directory));
    const auto active = journal.read_active();
    REQUIRE(active.has_value());
    CHECK(active->phase == RestoreJournalPhase::files_committed);
}

TEST_CASE(
    "config save restores exact state after every pre-apply boundary") {
    const std::vector<ConfigSaveFaultStage> stages{
        ConfigSaveFaultStage::wal_started,
        ConfigSaveFaultStage::generation_reserved,
        ConfigSaveFaultStage::config_written,
        ConfigSaveFaultStage::files_committed,
    };

    int api_port = 18247;
    for (const auto stage : stages) {
        CAPTURE(static_cast<int>(stage));
        ConfigApiTempDir directory;
        const auto config_path = directory.path / "config.json";
        const Config original =
            make_valid_config(
                "127.0.0.1:" + std::to_string(api_port));
        const std::string original_json =
            nlohmann::json(original).dump(1, '\t') + "\n";
        write_text(config_path, original_json);
        REQUIRE(::chmod(config_path.c_str(), 0600) == 0);
        const Config staged =
            make_valid_config(
                "127.0.0.1:" +
                std::to_string(api_port + 20));
        const std::string staged_json =
            nlohmann::json(staged).dump(1, '\t') + "\n";

        SseBroadcaster broadcaster;
        std::size_t begin_calls = 0;
        std::size_t finish_calls = 0;
        std::size_t apply_calls = 0;
        std::size_t stop_calls = 0;
        auto context = make_config_context(
            config_path.string(),
            broadcaster,
            staged,
            staged_json,
            begin_calls,
            finish_calls,
            apply_calls);
        const auto maintenance =
            std::make_shared<FakeMaintenanceState>();
        install_fake_maintenance(context, maintenance);
        context.stop_runtime_fn = [&] { ++stop_calls; };

        ApiConfig api_config;
        api_config.listen =
            "127.0.0.1:" + std::to_string(api_port);
        ApiServer server(api_config);
        ConfigSaveTestOptions options;
        options.fault_injector =
            [stage](ConfigSaveFaultStage current) {
                if (current == stage) {
                    throw std::runtime_error(
                        "injected config-save boundary failure");
                }
            };
        register_config_handler_for_test(
            server,
            context,
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            },
            std::move(options));
        server.start();
        httplib::Client client("127.0.0.1", api_port);
        const auto response =
            client.Post(
                "/api/config/save", "", "application/json");
        server.stop();

        REQUIRE(response != nullptr);
        CHECK(response->status == 500);
        CHECK(read_text(config_path) == original_json);
        CHECK(file_mode(config_path) == 0600);
        CHECK(apply_calls == 0U);
        CHECK(stop_calls == 0U);
        RestoreJournal journal(
            config_save_journal_path(directory));
        CHECK_FALSE(journal.read_active().has_value());
        ++api_port;
    }
}

TEST_CASE(
    "config save leaves active WAL and quiesces after runtime boundary faults") {
    const std::vector<ConfigSaveFaultStage> stages{
        ConfigSaveFaultStage::apply_returned,
        ConfigSaveFaultStage::core_applied,
    };

    int api_port = 18251;
    for (const auto stage : stages) {
        CAPTURE(static_cast<int>(stage));
        ConfigApiTempDir directory;
        const auto config_path = directory.path / "config.json";
        const Config original =
            make_valid_config(
                "127.0.0.1:" + std::to_string(api_port));
        write_text(
            config_path,
            nlohmann::json(original).dump(1, '\t') + "\n");
        const Config staged =
            make_valid_config(
                "127.0.0.1:" +
                std::to_string(api_port + 20));
        const std::string staged_json =
            nlohmann::json(staged).dump(1, '\t') + "\n";

        SseBroadcaster broadcaster;
        std::size_t begin_calls = 0;
        std::size_t finish_calls = 0;
        std::size_t apply_calls = 0;
        std::size_t stop_calls = 0;
        auto context = make_config_context(
            config_path.string(),
            broadcaster,
            staged,
            staged_json,
            begin_calls,
            finish_calls,
            apply_calls);
        const auto maintenance =
            std::make_shared<FakeMaintenanceState>();
        install_fake_maintenance(context, maintenance);
        context.stop_runtime_fn = [&] { ++stop_calls; };

        ApiConfig api_config;
        api_config.listen =
            "127.0.0.1:" + std::to_string(api_port);
        ApiServer server(api_config);
        ConfigSaveTestOptions options;
        options.fault_injector =
            [stage](ConfigSaveFaultStage current) {
                if (current == stage) {
                    throw std::runtime_error(
                        "injected post-apply boundary failure");
                }
            };
        register_config_handler_for_test(
            server,
            context,
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            },
            std::move(options));
        server.start();
        httplib::Client client("127.0.0.1", api_port);
        const auto response =
            client.Post(
                "/api/config/save", "", "application/json");
        server.stop();

        REQUIRE(response != nullptr);
        CHECK(response->status == 503);
        CHECK(
            nlohmann::json::parse(response->body)
                .at("recovery_required") == true);
        CHECK(read_text(config_path) == staged_json);
        CHECK(apply_calls == 1U);
        CHECK(stop_calls == 1U);
        RestoreJournal journal(
            config_save_journal_path(directory));
        const auto active = journal.read_active();
        REQUIRE(active.has_value());
        CHECK(
            active->phase ==
            (stage == ConfigSaveFaultStage::core_applied
                 ? RestoreJournalPhase::core_applied
                 : RestoreJournalPhase::files_committed));
        ++api_port;
    }
}

TEST_CASE(
    "config save never rolls back after durable WAL commit") {
    constexpr int api_port = 18253;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18253");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const Config staged = make_valid_config("127.0.0.1:18254");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t stop_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    context.stop_runtime_fn = [&] { ++stop_calls; };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    ConfigSaveTestOptions options;
    options.fault_injector =
        [](ConfigSaveFaultStage stage) {
            if (stage == ConfigSaveFaultStage::wal_committed) {
                throw std::runtime_error(
                    "injected late response bookkeeping failure");
            }
        };
    register_config_handler_for_test(
        server,
        context,
        [](const std::string& path,
           const std::string& body) {
            write_config_atomically(path, body);
        },
        std::move(options));
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(read_text(config_path) == staged_json);
    CHECK(apply_calls == 1U);
    CHECK(stop_calls == 0U);
    RestoreJournal journal(config_save_journal_path(directory));
    CHECK_FALSE(journal.read_active().has_value());
}

TEST_CASE(
    "production config save requires the complete exact-handoff seam") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18318");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const Config staged =
        make_valid_config("127.0.0.1:18319");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t legacy_apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        legacy_apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);
    RuntimeMutationAdmission admission;
    install_runtime_mutation_admission(context, admission);
    std::size_t exact_apply_calls = 0;
    SUBCASE("missing exact-handoff callback") {}
    SUBCASE("missing lease validator") {
        context.enqueue_apply_validated_config_with_lease_return_fn =
            [&](Config,
                std::string,
                RuntimeMutationAdmission::Lease&) {
                ++exact_apply_calls;
                return ConfigApplyResult{};
            };
        context.validate_runtime_mutation_lease_fn = {};
    }
    SUBCASE("missing handoff gate callback") {
        context.enqueue_apply_validated_config_with_lease_return_fn =
            [&](Config,
                std::string,
                RuntimeMutationAdmission::Lease&) {
                ++exact_apply_calls;
                return ConfigApplyResult{};
            };
        context.try_acquire_runtime_mutation_handoff_gate_fn = {};
    }

    std::size_t prepare_calls = 0;
    std::size_t write_calls = 0;
    try {
        (void)commit_prepared_config_for_test(
            context,
            "missing-owner-config-seam",
            [&] {
                ++prepare_calls;
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [&](const std::string& path,
                const std::string& body) {
                ++write_calls;
                write_config_atomically(path, body);
            });
        FAIL("production must not fall back to legacy config apply");
    } catch (const ApiError& error) {
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        const auto payload =
            nlohmann::json::parse(*error.body());
        CHECK(
            payload.at("error") ==
            "Runtime configuration owner is unavailable");
        CHECK(payload.at("saved") == false);
        CHECK(payload.at("applied") == false);
        CHECK(payload.at("rolled_back") == false);
        CHECK(payload.at("recovery_required") == false);
    }

    CHECK(prepare_calls == 0U);
    CHECK(write_calls == 0U);
    CHECK(exact_apply_calls == 0U);
    CHECK(legacy_apply_calls == 0U);
    CHECK(read_text(config_path) == original_json);
    CHECK_FALSE(
        RestoreJournal(config_save_journal_path(directory))
            .read_active()
            .has_value());
    auto subsequent = admission.try_acquire(
        "after-missing-owner-config-seam");
    REQUIRE(subsequent.has_value());
    subsequent->release();
}

TEST_CASE(
    "owner-backed config apply restores its exact lease before WAL commit") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18320");
    const Config staged =
        make_valid_config("127.0.0.1:18321");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t legacy_apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        legacy_apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    RuntimeMutationAdmission admission;
    install_runtime_mutation_admission(
        context, admission, &maintenance->events);
    std::size_t owner_apply_calls = 0;
    context.enqueue_apply_validated_config_with_lease_return_fn =
        [&](Config,
            std::string serialized,
            RuntimeMutationAdmission::Lease& request_lease) {
            ++owner_apply_calls;
            maintenance->events.push_back("owner-apply");
            CHECK(serialized == staged_json);
            CHECK(admission.owns(request_lease));

            auto owner_lease = std::move(request_lease);
            CHECK_FALSE(static_cast<bool>(request_lease));
            CHECK(admission.owns(owner_lease));
            request_lease = std::move(owner_lease);

            ConfigApplyResult result;
            result.applied = true;
            return result;
        };

    const auto response = nlohmann::json::parse(
        commit_prepared_config_for_test(
            context,
            "owner-backed-config-success",
            [&] {
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            }));

    CHECK(response.at("saved") == true);
    CHECK(response.at("applied") == true);
    CHECK(read_text(config_path) == staged_json);
    CHECK(owner_apply_calls == 1U);
    CHECK(legacy_apply_calls == 0U);
    CHECK(begin_calls == 0U);
    CHECK(finish_calls == 0U);
    CHECK(
        event_index(
            maintenance->events,
            "runtime-lease-restored") <
        event_index(maintenance->events, "verify-held"));
    CHECK_FALSE(admission.active().has_value());
    CHECK_FALSE(
        RestoreJournal(config_save_journal_path(directory))
            .read_active()
            .has_value());
}

TEST_CASE(
    "owner preapply clean failure returns lease before exact file rollback") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18322");
    const std::string original_json =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const Config staged =
        make_valid_config("127.0.0.1:18323");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(config_path, original_json);

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t legacy_apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        legacy_apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    RuntimeMutationAdmission admission;
    install_runtime_mutation_admission(context, admission);
    context.validate_runtime_mutation_lease_fn =
        [&](const RuntimeMutationAdmission::Lease& lease) {
            // Reclaim is required while the candidate is still durable. If
            // rollback ran first this assertion would observe original_json.
            CHECK(read_text(config_path) == staged_json);
            maintenance->events.push_back(
                "runtime-lease-restored");
            return admission.owns(lease);
        };
    std::size_t quiesce_calls = 0;
    context.emergency_quiesce_runtime_fn =
        [&] { ++quiesce_calls; };
    std::size_t owner_apply_calls = 0;
    context.enqueue_apply_validated_config_with_lease_return_fn =
        [&](Config,
            std::string,
            RuntimeMutationAdmission::Lease& request_lease) {
            ++owner_apply_calls;
            auto owner_lease = std::move(request_lease);
            request_lease = std::move(owner_lease);

            ConfigApplyResult result;
            result.error = "owner preapply failed cleanly";
            result.runtime_unchanged = true;
            return result;
        };

    try {
        (void)commit_prepared_config_for_test(
            context,
            "owner-backed-config-clean-failure",
            [&] {
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            });
        FAIL("clean owner preapply failure must reject the save");
    } catch (const ApiError& error) {
        CHECK(error.status() == 500);
        REQUIRE(error.body().has_value());
        const auto payload =
            nlohmann::json::parse(*error.body());
        CHECK(payload.at("recovery_required") == false);
        CHECK(payload.at("runtime_unchanged") == true);
        CHECK(payload.at("file_rolled_back") == true);
    }

    CHECK(read_text(config_path) == original_json);
    CHECK(owner_apply_calls == 1U);
    CHECK(legacy_apply_calls == 0U);
    CHECK(quiesce_calls == 0U);
    CHECK_FALSE(admission.active().has_value());
    CHECK_FALSE(
        RestoreJournal(config_save_journal_path(directory))
            .read_active()
            .has_value());
}

TEST_CASE(
    "owner exception is interpreted only after exact lease reclaim") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18330");
    const Config staged =
        make_valid_config("127.0.0.1:18331");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t legacy_apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        legacy_apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    RuntimeMutationAdmission admission;
    std::size_t handoff_gate_calls = 0;
    install_runtime_mutation_admission(
        context,
        admission,
        &maintenance->events,
        &handoff_gate_calls);
    std::size_t quiesce_calls = 0;
    context.emergency_quiesce_runtime_fn = [&] {
        FAIL("legacy emergency quiesce must not run");
    };
    context.emergency_quiesce_runtime_with_lease_return_fn =
        [&](RuntimeMutationAdmission::Lease& request_lease) {
            ++quiesce_calls;
            CHECK(admission.owns(request_lease));
            maintenance->events.push_back(
                "runtime-quiesce-lease-received");
            auto owner_lease = std::move(request_lease);
            CHECK_FALSE(static_cast<bool>(request_lease));
            request_lease = std::move(owner_lease);
            CHECK(admission.owns(request_lease));
            maintenance->events.push_back(
                "runtime-quiesce-lease-returned");
    };
    std::size_t owner_apply_calls = 0;
    context.enqueue_apply_validated_config_with_lease_return_fn =
        [&](Config,
            std::string,
            RuntimeMutationAdmission::Lease& request_lease)
            -> ConfigApplyResult {
            ++owner_apply_calls;
            CHECK(admission.owns(request_lease));

            auto owner_lease = std::move(request_lease);
            CHECK_FALSE(static_cast<bool>(request_lease));
            request_lease = std::move(owner_lease);
            CHECK(admission.owns(request_lease));

            throw std::runtime_error(
                "injected owner failure after exact lease return");
        };

    try {
        (void)commit_prepared_config_for_test(
            context,
            "owner-throws-after-exact-return",
            [&] {
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            });
        FAIL("owner exception after exact return must require recovery");
    } catch (const ApiError& error) {
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        const auto payload =
            nlohmann::json::parse(*error.body());
        CHECK(
            payload.at("error") ==
            "Configuration runtime apply was interrupted: "
            "injected owner failure after exact lease return");
        CHECK(payload.at("saved") == false);
        CHECK(payload.at("applied") == false);
        CHECK(payload.at("rolled_back") == false);
        CHECK(payload.at("recovery_required") == true);
        CHECK(payload.at("runtime_quiesced") == true);
    }

    CHECK(owner_apply_calls == 1U);
    CHECK(legacy_apply_calls == 0U);
    CHECK(handoff_gate_calls == 2U);
    CHECK(quiesce_calls == 1U);
    CHECK(
        event_index(
            maintenance->events,
            "runtime-lease-restored") <
        event_index(
            maintenance->events,
            "runtime-quiesce-lease-received"));
    CHECK(
        event_index(
            maintenance->events,
            "runtime-quiesce-lease-received") <
        event_index(
            maintenance->events,
            "runtime-quiesce-lease-returned"));
    CHECK(read_text(config_path) == staged_json);
    RestoreJournal journal(config_save_journal_path(directory));
    const auto active = journal.read_active();
    REQUIRE(active.has_value());
    CHECK(
        active->phase ==
        RestoreJournalPhase::files_committed);
    CHECK_FALSE(admission.active().has_value());
    auto subsequent = admission.try_acquire(
        "after-owner-throws-exact-return");
    REQUIRE(subsequent.has_value());
    subsequent->release();
}

TEST_CASE(
    "emergency quiesce fails closed when its exact lease is not returned") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18332");
    const Config staged =
        make_valid_config("127.0.0.1:18333");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t legacy_apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        legacy_apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    RuntimeMutationAdmission admission;
    std::size_t handoff_gate_calls = 0;
    install_runtime_mutation_admission(
        context,
        admission,
        nullptr,
        &handoff_gate_calls);
    std::optional<RuntimeMutationAdmission::Lease>
        retained_exact_lease;
    std::size_t legacy_quiesce_calls = 0;
    std::size_t exact_quiesce_calls = 0;
    context.emergency_quiesce_runtime_fn =
        [&] { ++legacy_quiesce_calls; };
    context.emergency_quiesce_runtime_with_lease_return_fn =
        [&](RuntimeMutationAdmission::Lease& request_lease) {
            ++exact_quiesce_calls;
            CHECK(admission.owns(request_lease));
            retained_exact_lease.emplace(
                std::move(request_lease));
            CHECK_FALSE(static_cast<bool>(request_lease));
        };
    context.enqueue_apply_validated_config_with_lease_return_fn =
        [&](Config,
            std::string,
            RuntimeMutationAdmission::Lease& request_lease)
            -> ConfigApplyResult {
            CHECK(admission.owns(request_lease));
            auto owner_lease = std::move(request_lease);
            request_lease = std::move(owner_lease);
            throw std::runtime_error(
                "injected apply failure before emergency quiesce");
        };

    try {
        (void)commit_prepared_config_for_test(
            context,
            "emergency-quiesce-invalid-return",
            [&] {
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            });
        FAIL("missing emergency lease return must require recovery");
    } catch (const ApiError& error) {
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        const auto payload =
            nlohmann::json::parse(*error.body());
        CHECK(payload.at("recovery_required") == true);
        CHECK(payload.at("runtime_quiesced") == false);
        CHECK(payload.at("applied") == false);
        CHECK(payload.at("rolled_back") == false);
    }

    CHECK(legacy_apply_calls == 0U);
    CHECK(legacy_quiesce_calls == 0U);
    CHECK(exact_quiesce_calls == 1U);
    CHECK(handoff_gate_calls == 2U);
    REQUIRE(retained_exact_lease.has_value());
    CHECK(static_cast<bool>(*retained_exact_lease));
    CHECK(admission.active().has_value());
    CHECK_FALSE(
        admission.try_acquire(
            "before-emergency-exact-release")
            .has_value());

    retained_exact_lease.reset();
    CHECK_FALSE(admission.active().has_value());
    auto subsequent = admission.try_acquire(
        "after-emergency-exact-release");
    REQUIRE(subsequent.has_value());
    subsequent->release();
}

TEST_CASE(
    "owner-backed config apply requires the exact lease on every return") {
    for (const bool return_foreign_lease : {false, true}) {
        CAPTURE(return_foreign_lease);
        ConfigApiTempDir directory;
        const auto config_path = directory.path / "config.json";
        const Config original = make_valid_config(
            return_foreign_lease
                ? "127.0.0.1:18324"
                : "127.0.0.1:18326");
        const Config staged = make_valid_config(
            return_foreign_lease
                ? "127.0.0.1:18325"
                : "127.0.0.1:18327");
        const std::string staged_json =
            nlohmann::json(staged).dump(1, '\t') + "\n";
        write_text(
            config_path,
            nlohmann::json(original).dump(1, '\t') + "\n");

        SseBroadcaster broadcaster;
        std::size_t begin_calls = 0;
        std::size_t finish_calls = 0;
        std::size_t legacy_apply_calls = 0;
        auto context = make_config_context(
            config_path.string(),
            broadcaster,
            staged,
            staged_json,
            begin_calls,
            finish_calls,
            legacy_apply_calls);
        const auto maintenance =
            std::make_shared<FakeMaintenanceState>();
        install_fake_maintenance(context, maintenance);

        RuntimeMutationAdmission admission;
        RuntimeMutationAdmission foreign_admission;
        std::size_t handoff_gate_calls = 0;
        install_runtime_mutation_admission(
            context,
            admission,
            nullptr,
            &handoff_gate_calls);
        std::optional<RuntimeMutationAdmission::Lease>
            retained_exact_lease;
        std::size_t quiesce_calls = 0;
        context.emergency_quiesce_runtime_fn =
            [&] { ++quiesce_calls; };
        context.enqueue_apply_validated_config_with_lease_return_fn =
            [&](Config,
                std::string,
                RuntimeMutationAdmission::Lease& request_lease) {
                CHECK(admission.owns(request_lease));
                if (return_foreign_lease) {
                    retained_exact_lease.emplace(
                        std::move(request_lease));
                    auto foreign = foreign_admission.try_acquire(
                        "foreign-config-operation");
                    REQUIRE(foreign.has_value());
                    request_lease = std::move(*foreign);
                } else {
                    request_lease.release();
                }
                CHECK_FALSE(
                    admission.try_acquire(
                        "during-invalid-config-handback")
                        .has_value());

                ConfigApplyResult result;
                result.error = "untrusted clean failure claim";
                result.runtime_unchanged = true;
                return result;
            };

        try {
            (void)commit_prepared_config_for_test(
                context,
                "owner-backed-config-invalid-return",
                [&] {
                    PreparedConfigCommit prepared;
                    prepared.config = staged;
                    prepared.serialized = staged_json;
                    return prepared;
                },
                [](const std::string& path,
                   const std::string& body) {
                    write_config_atomically(path, body);
                });
            FAIL("an empty or foreign lease must fail closed");
        } catch (const ApiError& error) {
            CHECK(error.status() == 503);
            REQUIRE(error.body().has_value());
            const auto payload =
                nlohmann::json::parse(*error.body());
            CHECK(payload.at("recovery_required") == true);
            CHECK(payload.at("applied") == false);
            CHECK(payload.at("rolled_back") == false);
            CHECK_FALSE(payload.contains("runtime_unchanged"));
        }

        CHECK(read_text(config_path) == staged_json);
        CHECK(legacy_apply_calls == 0U);
        CHECK(quiesce_calls == 1U);
        CHECK(handoff_gate_calls == 1U);
        RestoreJournal journal(
            config_save_journal_path(directory));
        const auto active = journal.read_active();
        REQUIRE(active.has_value());
        CHECK(
            active->phase ==
            RestoreJournalPhase::files_committed);
        CHECK(
            admission.active().has_value() ==
            return_foreign_lease);
        CHECK_FALSE(foreign_admission.active().has_value());
        if (return_foreign_lease) {
            CHECK_FALSE(
                admission.try_acquire(
                    "before-retained-exact-release")
                    .has_value());
        }
        retained_exact_lease.reset();
        CHECK_FALSE(admission.active().has_value());
        auto subsequent = admission.try_acquire(
            "after-invalid-config-handback");
        REQUIRE(subsequent.has_value());
        subsequent->release();
    }
}

TEST_CASE(
    "unverifiable exact handback releases its gate after request unwind") {
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original =
        make_valid_config("127.0.0.1:18328");
    const Config staged =
        make_valid_config("127.0.0.1:18329");
    const std::string staged_json =
        nlohmann::json(staged).dump(1, '\t') + "\n";
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t legacy_apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        staged,
        staged_json,
        begin_calls,
        finish_calls,
        legacy_apply_calls);
    const auto maintenance =
        std::make_shared<FakeMaintenanceState>();
    install_fake_maintenance(context, maintenance);

    RuntimeMutationAdmission admission;
    std::size_t handoff_gate_calls = 0;
    install_runtime_mutation_admission(
        context,
        admission,
        nullptr,
        &handoff_gate_calls);
    context.validate_runtime_mutation_lease_fn =
        [](const RuntimeMutationAdmission::Lease&) -> bool {
            throw std::runtime_error(
                "injected lease validator failure");
        };
    std::size_t quiesce_calls = 0;
    context.emergency_quiesce_runtime_fn =
        [&] { ++quiesce_calls; };
    context.enqueue_apply_validated_config_with_lease_return_fn =
        [&](Config,
            std::string,
            RuntimeMutationAdmission::Lease& request_lease) {
            CHECK(admission.owns(request_lease));
            auto owner_lease = std::move(request_lease);
            request_lease = std::move(owner_lease);
            ConfigApplyResult result;
            result.applied = true;
            return result;
        };

    try {
        (void)commit_prepared_config_for_test(
            context,
            "unverifiable-exact-config-handback",
            [&] {
                PreparedConfigCommit prepared;
                prepared.config = staged;
                prepared.serialized = staged_json;
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            });
        FAIL("validator failure must require recovery");
    } catch (const ApiError& error) {
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        CHECK(
            nlohmann::json::parse(*error.body())
                .at("recovery_required") == true);
    }

    CHECK(handoff_gate_calls == 1U);
    CHECK(quiesce_calls == 1U);
    CHECK_FALSE(admission.active().has_value());
    auto subsequent = admission.try_acquire(
        "after-validator-failure-unwind");
    REQUIRE(subsequent.has_value());
    subsequent->release();
    RestoreJournal journal(
        config_save_journal_path(directory));
    const auto active = journal.read_active();
    REQUIRE(active.has_value());
    CHECK(
        active->phase ==
        RestoreJournalPhase::files_committed);
}

TEST_CASE(
    "discarding a draft restores the persisted config without applying it") {
    // The point of the endpoint. Six other endpoints refuse to run while a
    // draft is staged and tell the operator to save or discard it; before this
    // route the only exits were saving a draft they had decided against - which
    // applies it to live routing - or restarting the daemon.
    constexpr int api_port = 18271;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config active = make_valid_config("127.0.0.1:12121");
    const std::string persisted = nlohmann::json(active).dump();
    write_text(config_path, persisted);

    ConfigStore store(active);
    const Config draft = make_recommended_list_config(
        "127.0.0.1:12121", "recommended");
    store.stage_config(draft, nlohmann::json(draft).dump());
    REQUIRE(store.config_is_draft());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    std::size_t writes = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        active,
        persisted,
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);

    ApiConfig api_config;
    api_config.listen = "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&writes](const std::string&, const std::string&) { ++writes; });
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/discard", "", "application/json");
    REQUIRE(response != nullptr);
    CHECK(response->status == 200);

    const auto after = client.Get("/api/config");
    server.stop();

    // The draft is gone, not merely hidden.
    CHECK_FALSE(store.config_is_draft());
    CHECK_FALSE(store.staged_cas_snapshot().has_value());
    // Nothing was persisted and nothing was applied: this is the exit that
    // does not put the abandoned draft into the routing runtime.
    CHECK(writes == 0U);
    CHECK(apply_calls == 0U);
    CHECK(read_text(config_path) == persisted);
    CHECK(nlohmann::json(store.active_config()) == nlohmann::json(active));
    // ...and the operator now sees the persisted config, so the six blocked
    // endpoints are reachable again.
    REQUIRE(after != nullptr);
    REQUIRE(after->status == 200);
    const auto state = nlohmann::json::parse(after->body);
    CHECK(state.at("is_draft").get<bool>() == false);
    // The draft's distinctive content is what has to be gone. Comparing whole
    // documents would compare default materialization instead.
    CHECK(state.at("config").at("lists").is_null());
}

TEST_CASE("discard reports having nothing to discard") {
    constexpr int api_port = 18272;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config active = make_valid_config("127.0.0.1:12121");
    ConfigStore store(active);
    REQUIRE_FALSE(store.config_is_draft());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        active,
        nlohmann::json(active).dump(),
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);

    ApiConfig api_config;
    api_config.listen = "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string&, const std::string&) {});
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/discard", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 400);
    CHECK(apply_calls == 0U);
    // The refusal must still release the runtime mutation claim. A discard
    // that failed while holding it would wedge every other config operation -
    // including the save this endpoint exists to offer an alternative to.
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == begin_calls);
}

TEST_CASE("discard holds the runtime mutation claim while it runs") {
    // Save takes the same claim across its CAS read and its apply. An
    // unguarded discard could land inside that window and clear a draft the
    // save had already committed to persisting.
    constexpr int api_port = 18273;
    ConfigApiTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config active = make_valid_config("127.0.0.1:12121");
    ConfigStore store(active);
    const Config draft = make_recommended_list_config(
        "127.0.0.1:12121", "recommended");
    store.stage_config(draft, nlohmann::json(draft).dump());

    SseBroadcaster broadcaster;
    std::size_t begin_calls = 0;
    std::size_t finish_calls = 0;
    std::size_t apply_calls = 0;
    bool draft_present_inside_claim = false;
    auto context = make_config_context(
        config_path.string(),
        broadcaster,
        active,
        nlohmann::json(active).dump(),
        begin_calls,
        finish_calls,
        apply_calls);
    connect_config_store(context, store);
    context.begin_save_operation_fn =
        [&begin_calls, &draft_present_inside_claim, &store] {
            ++begin_calls;
            // The claim is taken before the staged state is read.
            draft_present_inside_claim = store.config_is_draft();
        };

    ApiConfig api_config;
    api_config.listen = "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [](const std::string&, const std::string&) {});
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response =
        client.Post("/api/config/discard", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(begin_calls == 1U);
    CHECK(finish_calls == 1U);
    CHECK(draft_present_inside_claim);
    CHECK_FALSE(store.config_is_draft());
}

} // namespace keen_pbr3

#endif // WITH_API
