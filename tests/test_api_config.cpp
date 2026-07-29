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
            maintenance->events.push_back("apply-failed");
            ++apply_calls;
            ConfigApplyResult result;
            result.error = "injected apply failure";
            result.rolled_back = true;
            return result;
        };
    std::size_t write_calls = 0;
    const auto writer =
        [&](const std::string& path, const std::string& body) {
            maintenance->events.push_back("write-new");
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
    CHECK(read_text(config_path) == original_json);
    CHECK(write_calls == 1U);
    CHECK(maintenance->reserve_calls == 1U);
    CHECK(event_index(maintenance->events, "apply-failed") <
          event_index(maintenance->events, "finish-config"));
    CHECK(event_index(maintenance->events, "finish-config") <
          event_index(maintenance->events, "lease-release"));
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
            ConfigApplyResult result;
            result.error = "remote list preparation failed";
            result.runtime_unchanged = true;
            return result;
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
    CHECK(response->status == 500);
    const auto payload =
        nlohmann::json::parse(response->body);
    CHECK(payload.at("applied") == false);
    CHECK(payload.at("rolled_back") == false);
    CHECK(payload.at("runtime_unchanged") == true);
    CHECK(payload.at("file_rolled_back") == true);
    CHECK(payload.at("recovery_required") == false);
    CHECK(read_text(config_path) == original_json);
    CHECK(apply_calls == 1U);
    CHECK(stop_calls == 0U);
    CHECK(maintenance->active_leases == 0U);
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

} // namespace keen_pbr3

#endif // WITH_API
