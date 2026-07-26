#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_backup.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/crypto/sha256.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class BackupTempDir {
public:
    BackupTempDir() {
        char pattern[] = "/tmp/keen-pbr-backup-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~BackupTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

class EnvironmentVariableGuard {
public:
    EnvironmentVariableGuard(std::string name, const std::string& value)
        : name_(std::move(name)) {
        if (const char* previous = std::getenv(name_.c_str())) {
            previous_ = previous;
        }
        REQUIRE(::setenv(name_.c_str(), value.c_str(), 1) == 0);
    }

    ~EnvironmentVariableGuard() {
        if (previous_.has_value()) {
            (void)::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

struct BackupReadLeaseState {
    bool active{false};
    std::size_t reserve_calls{0};
    std::vector<std::string> operations;
};

class BackupReadLease final : public MaintenanceLease {
public:
    explicit BackupReadLease(
        std::shared_ptr<BackupReadLeaseState> state)
        : state_(std::move(state)) {
        state_->active = true;
    }

    ~BackupReadLease() override {
        state_->active = false;
    }

    std::uint32_t base_generation() const noexcept override {
        return 0;
    }

    std::uint32_t reserve(std::uint32_t) override {
        ++state_->reserve_calls;
        return 1;
    }

    void verify_held() override {}

private:
    std::shared_ptr<BackupReadLeaseState> state_;
};

std::shared_ptr<BackupReadLeaseState>
install_backup_read_lease(ApiContext& context) {
    auto state = std::make_shared<BackupReadLeaseState>();
    context.maintenance_lease_factory_fn =
        [state](std::string operation)
            -> std::unique_ptr<MaintenanceLease> {
        state->operations.push_back(std::move(operation));
        return std::make_unique<BackupReadLease>(state);
    };
    return state;
}

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

void reseal_rollback(nlohmann::json& rollback) {
    rollback.erase("integrity");
    rollback["integrity"] = {
        {"algorithm", "sha256"},
        {"digest", Sha256::hex(rollback.dump())},
    };
}

Config make_valid_config(const std::string& listen) {
    auto document = nlohmann::json::parse(R"({
        "daemon": {
            "cache_dir": "/tmp/keen-pbr-backup-cache",
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

Config make_group_round_trip_config(const std::string& prefix,
                                    const std::string& listen,
                                    int extra_table,
                                    const std::string& dns_address) {
    auto document = nlohmann::json(make_valid_config(listen));
    document["outbounds"].push_back({
        {"type", "table"},
        {"tag", prefix + "_aux"},
        {"table", extra_table},
    });
    document["dns"]["servers"] = nlohmann::json::array({
        {
            {"tag", prefix + "_dns"},
            {"address", dns_address},
        },
    });
    document["dns"]["fallback"] =
        nlohmann::json::array({prefix + "_dns"});
    document["lists"] = {
        {prefix + "_sites",
         {{"domains",
           nlohmann::json::array({prefix + ".example.test"})}}},
    };
    document["route"]["rules"] = nlohmann::json::array({
        {
            {"id", prefix + "_rule"},
            {"list", nlohmann::json::array({prefix + "_sites"})},
            {"outbound", "wan"},
        },
    });

    auto config = parse_config(document.dump());
    validate_config(config);
    return config;
}

ApiContext make_backup_context(
    const std::string& config_path,
    SseBroadcaster& broadcaster,
    const Config& visible,
    std::vector<Config>& applied) {
    return ApiContext{
        config_path,
        broadcaster,
        [visible] { return visible; },
        [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
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
        [] {},
        [] {},
        [&applied](Config config, std::string) {
            applied.push_back(std::move(config));
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

} // namespace

TEST_CASE("backup restore rolls every touched file back as one transaction") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";

    const Config original = make_valid_config("127.0.0.1:12121");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"old"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);
    REQUIRE(::chmod(transports_path.c_str(), 0600) == 0);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    const std::string config_path_string = config_path.string();
    auto context = make_backup_context(
        config_path_string, broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            // Fail before the core consumes references to the replacement
            // transport generation, then let rollback restore the old one.
            return restart_calls == 1 ? 17 : 0;
        };

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:13131"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array(
                 {{{"tag", "replacement"}}})}}}}},
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);

    CHECK(read_text(config_path) == original_config);
    CHECK(read_text(transports_path) == original_transports);
    struct stat restored_metadata {};
    REQUIRE(::stat(transports_path.c_str(), &restored_metadata) == 0);
    CHECK((restored_metadata.st_mode & 0777) == 0600);
    CHECK(applied.empty());
    CHECK(restart_calls == 2);
}

TEST_CASE("backup restore verifies transport generation before core apply") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"old"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);

    const nlohmann::json replacement_transports{
        {"transports",
         nlohmann::json::array({{{"tag", "replacement"}}})},
    };
    const std::string replacement_transport_bytes =
        replacement_transports.dump(1, '\t') + "\n";
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:13131"}}}}},
          {"transports", replacement_transports}}},
    };

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> events;
    context.restart_restore_service_fn =
        [&events](const std::string&) {
            events.push_back("transport-restart");
            return 0;
        };
    context.enqueue_apply_validated_config_fn =
        [&events, &applied](Config config, std::string) {
            events.push_back("core-apply");
            applied.push_back(std::move(config));
            ConfigApplyResult result;
            result.applied = true;
            return result;
        };
    BackupRestoreHooksForTest hooks;
    hooks.probe_transport_config_revision =
        [&events, &replacement_transport_bytes](
            const std::string& revision) {
            events.push_back("transport-revision");
            CHECK(revision ==
                  Sha256::hex(replacement_transport_bytes));
            return RestoreServiceReadinessForTest::ready;
        };

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, backup, hooks));
    CHECK(events ==
          std::vector<std::string>{
              "transport-restart",
              "transport-revision",
              "core-apply",
          });
    REQUIRE(applied.size() == 1U);
    CHECK(applied.front().api->listen == "127.0.0.1:13131");
}

TEST_CASE("backup rollback restores transport generation before old core") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"old"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);

    const nlohmann::json replacement_transports{
        {"transports",
         nlohmann::json::array({{{"tag", "replacement"}}})},
    };
    const std::string replacement_transport_bytes =
        replacement_transports.dump(1, '\t') + "\n";
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:13131"}}}}},
          {"transports", replacement_transports}}},
    };

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> events;
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&events, &restart_calls](const std::string&) {
            events.push_back(
                ++restart_calls == 1U
                    ? "transport-forward"
                    : "transport-rollback");
            return 0;
        };
    std::size_t apply_calls = 0;
    context.enqueue_apply_validated_config_fn =
        [&events, &applied, &apply_calls](
            Config config, std::string) {
            events.push_back(
                ++apply_calls == 1U
                    ? "core-forward"
                    : "core-rollback");
            applied.push_back(std::move(config));
            ConfigApplyResult result;
            if (apply_calls == 1U) {
                result.error = "injected core failure";
            } else {
                result.applied = true;
            }
            return result;
        };
    std::size_t revision_calls = 0;
    BackupRestoreHooksForTest hooks;
    hooks.probe_transport_config_revision =
        [&events,
         &revision_calls,
         &replacement_transport_bytes,
         &original_transports](const std::string& revision) {
            const bool forward = ++revision_calls == 1U;
            events.push_back(
                forward
                    ? "revision-forward"
                    : "revision-rollback");
            CHECK(
                revision ==
                Sha256::hex(
                    forward ? replacement_transport_bytes
                            : original_transports));
            return RestoreServiceReadinessForTest::ready;
        };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, hooks),
        ApiError);
    CHECK(events ==
          std::vector<std::string>{
              "transport-forward",
              "revision-forward",
              "core-forward",
              "transport-rollback",
              "revision-rollback",
              "core-rollback",
          });
    CHECK(read_text(config_path) == original_config);
    CHECK(read_text(transports_path) == original_transports);
}

TEST_CASE("backup export keeps selected groups separate") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);

    const auto general = create_backup_bundle_for_test(
        context,
        {{"general", true},
         {"transports", false},
         {"outbounds", false},
         {"dns", false},
         {"routing", false},
         {"nfqws", false}});
    REQUIRE(general.at("data").contains("general"));
    CHECK_FALSE(general.at("data").contains("outbounds"));
    CHECK_FALSE(general.at("data").contains("dns"));
    CHECK_FALSE(general.at("data").contains("lists"));
    CHECK_FALSE(general.at("data").contains("route"));

    const auto outbounds = create_backup_bundle_for_test(
        context,
        {{"general", false},
         {"transports", false},
         {"outbounds", true},
         {"dns", false},
         {"routing", false},
         {"nfqws", false}});
    CHECK(outbounds.at("data").size() == 1);
    CHECK(outbounds.at("data").contains("outbounds"));
    CHECK(outbounds.at("data").at("outbounds") ==
          nlohmann::json(original).at("outbounds"));
}

TEST_CASE("backup round-trip uses persisted configuration instead of draft") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    Config persisted = make_valid_config("127.0.0.1:18191");
    persisted.lists = std::map<std::string, ListConfig>{};
    const Config draft = make_valid_config("127.0.0.1:18192");
    write_text(
        config_path,
        nlohmann::json(persisted).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, draft, applied);

    const nlohmann::json groups{
        {"general", true},
        {"transports", false},
        {"outbounds", true},
        {"dns", true},
        {"routing", true},
        {"nfqws_config", false},
        {"nfqws_lists", false},
    };
    const auto backup =
        create_backup_bundle_for_test(context, groups);
    CHECK(backup.at("data")
              .at("general")
              .at("api")
              .at("listen") == "127.0.0.1:18191");

    const Config changed = make_valid_config("127.0.0.1:18193");
    write_text(
        config_path,
        nlohmann::json(changed).dump(1, '\t') + "\n");

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, backup));
    REQUIRE(applied.size() == 1);
    CHECK(nlohmann::json(applied.front()) ==
          nlohmann::json(persisted));

    const Config restored = parse_config(read_text(config_path));
    CHECK(nlohmann::json(restored) == nlohmann::json(persisted));
}

TEST_CASE("transport restore creates private file and directory") {
    BackupTempDir directory;
    const auto config_directory = directory.path / "private";
    const auto config_path = config_directory / "config.json";
    const auto transports_path = config_directory / "transports.json";
    const Config visible = make_valid_config("127.0.0.1:18194");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, visible, applied);
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };

    const nlohmann::json transports{
        {"transports",
         nlohmann::json::array(
             {{{"tag", "restored"}, {"type", "sing-box"}}})},
    };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data", {{"transports", transports}}},
    };

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, backup));
    REQUIRE(restarted.size() == 1);
    CHECK(restarted.front() ==
          "/opt/etc/init.d/S79transport-manager");
    CHECK(nlohmann::json::parse(read_text(transports_path)) ==
          transports);

    struct stat directory_metadata {};
    REQUIRE(::stat(config_directory.c_str(), &directory_metadata) == 0);
    CHECK((directory_metadata.st_mode & 0777) == 0700);

    struct stat file_metadata {};
    REQUIRE(::stat(transports_path.c_str(), &file_metadata) == 0);
    CHECK((file_metadata.st_mode & 0777) == 0600);
}

TEST_CASE("invalid restore keeps previous rollback backup intact") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto rollback_path = directory.path / "rollback.json";
    const Config persisted = make_valid_config("127.0.0.1:18195");
    write_text(
        config_path,
        nlohmann::json(persisted).dump(1, '\t') + "\n");
    write_text(rollback_path, "known-good-rollback\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, persisted, applied);
    const nlohmann::json invalid_backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data", {{"dns", nlohmann::json::array()}}},
    };

    CHECK_THROWS_AS(
        restore_backup_with_rollback_for_test(
            context, invalid_backup, rollback_path.string()),
        ApiError);
    CHECK(read_text(rollback_path) == "known-good-rollback\n");
    CHECK(applied.empty());
}

TEST_CASE("backup restore refuses to mix a staged draft into active state") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config persisted = make_valid_config("127.0.0.1:18198");
    const Config draft = make_valid_config("127.0.0.1:18199");
    const std::string persisted_json =
        nlohmann::json(persisted).dump(1, '\t') + "\n";
    write_text(config_path, persisted_json);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, draft, applied);
    context.config_is_draft_fn = [] { return true; };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"outbounds", nlohmann::json(persisted).at("outbounds")}}},
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);
    CHECK(read_text(config_path) == persisted_json);
    CHECK(applied.empty());
}

TEST_CASE("unsupported or corrupt backup has no persistent or runtime effects") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18201");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };

    const auto candidate_data = nlohmann::json{
        {"general",
         {{"api",
           {{"enabled", true}, {"listen", "127.0.0.1:18202"}}}}},
        {"transports",
         {{"transports",
           nlohmann::json::array({{{"tag", "replacement"}}})}}},
    };
    auto corrupt_data = candidate_data;
    corrupt_data["nfqws"] = {
        {"nfqws2/user.list",
         {{"encoding", "base64"}, {"data", "***="}}},
    };

    std::vector<nlohmann::json> invalid_backups{
        {
            {"format", "keen-pbr-sb-backup"},
            {"schema", 2},
            {"data", candidate_data},
        },
        {
            {"format", "keen-pbr-sb-backup"},
            {"schema", 1},
            {"data", corrupt_data},
        },
    };

    for (const auto& backup : invalid_backups) {
        CAPTURE(backup);
        CHECK_THROWS_AS(
            restore_backup_bundle_for_test(context, backup), ApiError);
        CHECK(read_text(config_path) == original_config);
        CHECK(read_text(transports_path) == original_transports);
        CHECK(applied.empty());
        CHECK(restarted.empty());
    }
}

TEST_CASE("failed runtime rollback is reported as incomplete") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18203");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t apply_calls = 0;
    context.enqueue_apply_validated_config_fn =
        [&applied, &apply_calls](Config config, std::string) {
            applied.push_back(std::move(config));
            ConfigApplyResult result;
            result.error =
                ++apply_calls == 1
                    ? "injected forward apply failure"
                    : "injected runtime rollback failure";
            return result;
        };

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18204"}}}}}}},
    };

    try {
        restore_backup_bundle_for_test(context, backup);
        FAIL("restore was expected to fail");
    } catch (const ApiError& error) {
        CHECK(error.status() == 500);
        const std::string message = error.what();
        CHECK(message.find("restore apply failed: injected forward apply failure") !=
              std::string::npos);
        CHECK(message.find("rollback was incomplete") !=
              std::string::npos);
        CHECK(message.find(
                  "runtime rollback failed: injected runtime rollback failure") !=
              std::string::npos);
    }

    CHECK(read_text(config_path) == original_config);
    CHECK(apply_calls == 2);
    REQUIRE(applied.size() == 2);
    CHECK(applied.front().api->listen == "127.0.0.1:18204");
    CHECK(applied.back().api->listen == "127.0.0.1:18203");
}

TEST_CASE("backup restore second target write failure restores bytes and metadata") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18210");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);

    struct stat original_metadata {};
    REQUIRE(::stat(config_path.c_str(), &original_metadata) == 0);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18211"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "replacement"}}})}}}}},
    };
    std::vector<std::string> attempted_paths;
    BackupRestoreHooksForTest hooks;
    hooks.before_forward_write =
        [&attempted_paths](std::size_t index, const std::string& path) {
            attempted_paths.push_back(path);
            if (index == 1) {
                throw ApiError("injected second target write failure", 507);
            }
        };

    CHECK_THROWS_WITH_AS(
        restore_backup_bundle_for_test(context, backup, hooks),
        "injected second target write failure",
        ApiError);

    REQUIRE(attempted_paths.size() == 2);
    CHECK(attempted_paths[0] == config_path.string());
    CHECK(attempted_paths[1] == transports_path.string());
    CHECK(read_text(config_path) == original_config);
    CHECK(read_text(transports_path) == original_transports);
    CHECK(applied.empty());
    CHECK(restarted.empty());

    struct stat restored_metadata {};
    REQUIRE(::stat(config_path.c_str(), &restored_metadata) == 0);
    CHECK((restored_metadata.st_mode & 07777) ==
          (original_metadata.st_mode & 07777));
    CHECK(restored_metadata.st_uid == original_metadata.st_uid);
    CHECK(restored_metadata.st_gid == original_metadata.st_gid);
}

TEST_CASE("backup rollback leaves an externally changed uncommitted target untouched") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18216");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);
    write_text(
        transports_path,
        R"({"transports":[{"tag":"original"}]})" "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18217"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array(
                 {{{"tag", "replacement"}}})}}}}},
    };

    BackupRestoreHooksForTest hooks;
    hooks.before_forward_write =
        [&transports_path](std::size_t index,
                           const std::string&) {
            if (index != 1U) return;
            write_text(
                transports_path,
                R"({"transports":[{"tag":"external"}]})" "\n");
            throw ApiError(
                "injected failure before second write", 500);
        };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, hooks),
        ApiError);
    CHECK(read_text(config_path) == original_config);
    CHECK(
        read_text(transports_path) ==
        R"({"transports":[{"tag":"external"}]})" "\n");
    CHECK(applied.empty());
}

TEST_CASE("backup restore persistent rollback ENOSPC leaves previous rescue point intact") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const auto rollback_path = directory.path / "rollback.json";
    const Config original = make_valid_config("127.0.0.1:18212");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);
    write_text(rollback_path, "previous-rescue-point\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t validated_candidates = 0;
    context.validate_candidate_config_fn =
        [&validated_candidates](const Config&) {
            ++validated_candidates;
        };
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18213"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "replacement"}}})}}}}},
    };
    std::vector<AtomicFileWriteStage> rollback_write_stages;
    BackupRestoreHooksForTest hooks;
    hooks.atomic_write_fault =
        [&rollback_path,
         &rollback_write_stages](
            const std::string& path,
            AtomicFileWriteStage stage) {
            if (path != rollback_path.string()) return;
            rollback_write_stages.push_back(stage);
            if (stage == AtomicFileWriteStage::write) {
                throw std::system_error(
                    ENOSPC,
                    std::generic_category(),
                    "injected rollback write");
            }
        };

    CHECK_THROWS_AS(
        restore_backup_with_rollback_for_test(
            context, backup, rollback_path.string(), hooks),
        ApiError);

    CHECK(validated_candidates == 1);
    REQUIRE(rollback_write_stages.size() == 1);
    CHECK(rollback_write_stages.front() ==
          AtomicFileWriteStage::write);
    CHECK(read_text(rollback_path) == "previous-rescue-point\n");
    CHECK(read_text(config_path) == original_config);
    CHECK(read_text(transports_path) == original_transports);
    CHECK(applied.empty());
    CHECK(restarted.empty());
}

TEST_CASE("empty backup restore preserves the previous rescue point") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto rollback_path = directory.path / "rollback.json";
    const Config original = make_valid_config("127.0.0.1:18225");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);
    write_text(rollback_path, "known-good-rescue\n");
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data", nlohmann::json::object()},
    };

    CHECK_THROWS_AS(
        restore_backup_with_rollback_for_test(
            context, backup, rollback_path.string()),
        ApiError);
    CHECK(read_text(rollback_path) == "known-good-rescue\n");
    CHECK(read_text(config_path) == original_config);
    CHECK(applied.empty());
}

TEST_CASE("backup successful restore creates an exact persistent rollback snapshot") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const auto rollback_path = directory.path / "rollback.json";
    const Config original = make_valid_config("127.0.0.1:18218");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);
    REQUIRE(::chmod(config_path.c_str(), 0640) == 0);
    struct stat original_metadata {};
    REQUIRE(::stat(config_path.c_str(), &original_metadata) == 0);
    REQUIRE_FALSE(std::filesystem::exists(transports_path));

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18219"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array(
                 {{{"tag", "temporary"}}})}}}}},
    };

    REQUIRE_NOTHROW(
        restore_backup_with_rollback_for_test(
            context, backup, rollback_path.string()));
    CHECK(rollback_backup_available_for_test(
        rollback_path.string()));
    CHECK(
        parse_config(read_text(config_path)).api->listen ==
        "127.0.0.1:18219");
    CHECK(std::filesystem::exists(transports_path));

    REQUIRE_NOTHROW(
        restore_persistent_rollback_for_test(
            context, rollback_path.string()));
    CHECK(read_text(config_path) == original_config);
    CHECK_FALSE(std::filesystem::exists(transports_path));
    struct stat restored_metadata {};
    REQUIRE(::stat(config_path.c_str(), &restored_metadata) == 0);
    CHECK((restored_metadata.st_mode & 0777) ==
          (original_metadata.st_mode & 0777));
    CHECK(restored_metadata.st_uid == original_metadata.st_uid);
    CHECK(restored_metadata.st_gid == original_metadata.st_gid);

    REQUIRE(applied.size() == 2);
    CHECK(applied[0].api->listen == "127.0.0.1:18219");
    CHECK(applied[1].api->listen == "127.0.0.1:18218");
    REQUIRE(restarted.size() == 2);
    CHECK(restarted[0] ==
          "/opt/etc/init.d/S79transport-manager");
    CHECK(restarted[1] ==
          "/opt/etc/init.d/S79transport-manager");
}

TEST_CASE("persistent tombstone removal is transactional across directory fsync failure") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const auto rollback_path = directory.path / "rollback.json";
    const Config original = make_valid_config("127.0.0.1:18226");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    context.restart_restore_service_fn =
        [](const std::string&) { return 0; };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "temporary"}}})}}}}},
    };
    REQUIRE_NOTHROW(
        restore_backup_with_rollback_for_test(
            context, backup, rollback_path.string()));
    const auto temporary_transports = read_text(transports_path);

    bool injected = false;
    BackupRestoreHooksForTest hooks;
    hooks.atomic_write_fault =
        [&transports_path, &injected](
            const std::string& path,
            AtomicFileWriteStage stage) {
            if (!injected &&
                path == transports_path.string() &&
                stage == AtomicFileWriteStage::directory_fsync) {
                injected = true;
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "injected tombstone directory fsync");
            }
        };
    CHECK_THROWS_AS(
        restore_persistent_rollback_for_test(
            context, rollback_path.string(), hooks),
        ApiError);
    CHECK(injected);
    CHECK(std::filesystem::exists(transports_path));
    CHECK(read_text(transports_path) == temporary_transports);

    REQUIRE_NOTHROW(
        restore_persistent_rollback_for_test(
            context, rollback_path.string()));
    CHECK_FALSE(std::filesystem::exists(transports_path));
}

TEST_CASE("backup rollback availability validates readability schema and integrity") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto rollback_path = directory.path / "rollback.json";
    const Config original = make_valid_config("127.0.0.1:18220");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18221"}}}}}}},
    };
    REQUIRE_NOTHROW(
        restore_backup_with_rollback_for_test(
            context, backup, rollback_path.string()));
    REQUIRE(rollback_backup_available_for_test(
        rollback_path.string()));

    const auto valid_rollback = read_text(rollback_path);
    auto rollback = nlohmann::json::parse(valid_rollback);
    rollback.at("entries").at(0).at("data") = "corrupt";
    write_text(
        rollback_path, rollback.dump(1, '\t') + "\n");
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));

    rollback = nlohmann::json::parse(valid_rollback);
    auto& config_entry = rollback.at("entries").at(0);
    config_entry["data"] = "bm90LWpzb24=";
    config_entry["size"] = 8;
    config_entry["sha256"] = Sha256::hex("not-json");
    reseal_rollback(rollback);
    write_text(
        rollback_path, rollback.dump(1, '\t') + "\n");
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));

    rollback = nlohmann::json::parse(valid_rollback);
    rollback.at("entries").at(0)["target"] = "nfqws2//bad.list";
    reseal_rollback(rollback);
    write_text(
        rollback_path, rollback.dump(1, '\t') + "\n");
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));

    rollback = nlohmann::json::parse(valid_rollback);
    rollback["schema"] = 99;
    reseal_rollback(rollback);
    write_text(
        rollback_path, rollback.dump(1, '\t') + "\n");
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));

    rollback = nlohmann::json::parse(valid_rollback);
    rollback["created_at"] = "not-a-timestamp";
    reseal_rollback(rollback);
    write_text(
        rollback_path, rollback.dump(1, '\t') + "\n");
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));

    rollback = nlohmann::json::parse(valid_rollback);
    rollback["scopes"] = nlohmann::json::array({"transports"});
    reseal_rollback(rollback);
    write_text(
        rollback_path, rollback.dump(1, '\t') + "\n");
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));

    const nlohmann::json legacy_rollback{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data", {{"transports", nlohmann::json::object()}}},
    };
    write_text(
        rollback_path, legacy_rollback.dump(1, '\t') + "\n");
    CHECK(rollback_backup_available_for_test(
        rollback_path.string()));

    std::filesystem::remove(rollback_path);
    std::filesystem::create_directory(rollback_path);
    CHECK_FALSE(rollback_backup_available_for_test(
        rollback_path.string()));
}

TEST_CASE("full rollback snapshot fails closed on symlinks in managed trees") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto rollback_path = directory.path / "rollback.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);
    const Config original = make_valid_config("127.0.0.1:18224");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    write_text(directory.path / "outside.list", "outside.example\n");
    std::filesystem::create_symlink(
        directory.path / "outside.list",
        nfqws_root / "linked.list");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };

    CHECK_THROWS_AS(
        create_full_rollback_backup_for_test(
            context, rollback_path.string(), roots),
        ApiError);
    CHECK_FALSE(std::filesystem::exists(rollback_path));
    CHECK(applied.empty());

    std::filesystem::remove_all(nfqws_root);
    const auto linked_root = directory.path / "linked-root";
    std::filesystem::create_directories(linked_root);
    write_text(linked_root / "managed.list", "linked.example\n");
    std::filesystem::create_directory_symlink(linked_root, nfqws_root);
    CHECK_THROWS_AS(
        create_full_rollback_backup_for_test(
            context, rollback_path.string(), roots),
        ApiError);
    CHECK_FALSE(std::filesystem::exists(rollback_path));
}

TEST_CASE("full rollback scope restores metadata and removes later managed files") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto rollback_path = directory.path / "rollback.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);
    const Config original = make_valid_config("127.0.0.1:18227");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const auto existing = nfqws_root / "existing.list";
    write_text(existing, "before.example\n");
    REQUIRE(::chmod(existing.c_str(), 0640) == 0);
    struct stat original_metadata {};
    REQUIRE(::stat(existing.c_str(), &original_metadata) == 0);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    context.restart_restore_service_fn =
        [](const std::string&) { return 0; };
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };
    REQUIRE_NOTHROW(
        create_full_rollback_backup_for_test(
            context, rollback_path.string(), roots));
    REQUIRE(rollback_backup_available_for_test(
        rollback_path.string()));

    write_text(existing, "after.example\n");
    REQUIRE(::chmod(existing.c_str(), 0600) == 0);
    const auto created = nfqws_root / "created.list";
    write_text(created, "created.example\n");
    REQUIRE_NOTHROW(
        restore_persistent_rollback_for_test(
            context, rollback_path.string(), roots));

    CHECK(read_text(existing) == "before.example\n");
    CHECK_FALSE(std::filesystem::exists(created));
    struct stat restored_metadata {};
    REQUIRE(::stat(existing.c_str(), &restored_metadata) == 0);
    CHECK((restored_metadata.st_mode & 0777) ==
          (original_metadata.st_mode & 0777));
    CHECK(restored_metadata.st_uid == original_metadata.st_uid);
    CHECK(restored_metadata.st_gid == original_metadata.st_gid);
}

TEST_CASE("backup restore interruption after runtime apply rolls disk and runtime back") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18214");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(config_path, original_config);
    write_text(transports_path, original_transports);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18215"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "replacement"}}})}}}}},
    };
    BackupRestoreHooksForTest hooks;
    hooks.after_forward_runtime_apply = [] {
        throw ApiError("injected interruption after runtime apply", 500);
    };

    CHECK_THROWS_WITH_AS(
        restore_backup_bundle_for_test(context, backup, hooks),
        "injected interruption after runtime apply",
        ApiError);

    CHECK(read_text(config_path) == original_config);
    CHECK(read_text(transports_path) == original_transports);
    REQUIRE(applied.size() == 2);
    CHECK(applied.front().api->listen == "127.0.0.1:18215");
    CHECK(applied.back().api->listen == "127.0.0.1:18214");
    REQUIRE(restarted.size() == 2U);
    CHECK(restarted[0] ==
          "/opt/etc/init.d/S79transport-manager");
    CHECK(restarted[1] ==
          "/opt/etc/init.d/S79transport-manager");
}

TEST_CASE("schema one legacy group selection remains restorable") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config legacy =
        make_group_round_trip_config(
            "legacy", "127.0.0.1:18205", 201, "1.1.1.1");
    write_text(
        config_path,
        nlohmann::json(legacy).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, legacy, applied);
    const nlohmann::json legacy_groups{
        {"general", true},
        {"transports", false},
        {"outbounds", true},
        {"dns", true},
        {"routing", true},
        {"nfqws", false},
    };
    const auto legacy_backup =
        create_backup_bundle_for_test(context, legacy_groups);

    const Config replacement =
        make_group_round_trip_config(
            "replacement", "127.0.0.1:18206", 202, "9.9.9.9");
    write_text(
        config_path,
        nlohmann::json(replacement).dump(1, '\t') + "\n");

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, legacy_backup));
    REQUIRE(applied.size() == 1);
    CHECK(nlohmann::json(applied.front()) == nlohmann::json(legacy));
    CHECK(nlohmann::json(parse_config(read_text(config_path))) ==
          nlohmann::json(legacy));
}

TEST_CASE("configuration backup groups round-trip independently") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config source =
        make_group_round_trip_config(
            "source", "127.0.0.1:18207", 203, "1.0.0.1");
    const Config target =
        make_group_round_trip_config(
            "target", "127.0.0.1:18208", 204, "9.9.9.9");
    const nlohmann::json source_json = source;
    const nlohmann::json target_json = target;
    write_text(config_path, source_json.dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, source, applied);

    struct GroupCase {
        const char* name;
        std::vector<const char*> sections;
    };
    const std::vector<GroupCase> cases{
        {"general", {}},
        {"outbounds", {"outbounds"}},
        {"dns", {"dns"}},
        {"routing", {"lists", "route"}},
    };

    for (const auto& group_case : cases) {
        nlohmann::json groups{
            {"general", false},
            {"transports", false},
            {"outbounds", false},
            {"dns", false},
            {"routing", false},
            {"nfqws_config", false},
            {"nfqws_lists", false},
        };
        groups[group_case.name] = true;
        write_text(config_path, source_json.dump(1, '\t') + "\n");
        const auto backup =
            create_backup_bundle_for_test(context, groups);
        write_text(config_path, target_json.dump(1, '\t') + "\n");
        applied.clear();

        REQUIRE_NOTHROW(
            restore_backup_bundle_for_test(context, backup));
        REQUIRE(applied.size() == 1);

        nlohmann::json expected = target_json;
        if (std::string(group_case.name) == "general") {
            for (const auto& item : source_json.items()) {
                if (item.key() != "outbounds" && item.key() != "dns" &&
                    item.key() != "lists" && item.key() != "route") {
                    expected[item.key()] = item.value();
                }
            }
        } else {
            for (const char* section : group_case.sections) {
                expected[section] = source_json.at(section);
            }
        }

        CAPTURE(group_case.name);
        CHECK(nlohmann::json(applied.front()) == expected);
        CHECK(nlohmann::json(parse_config(read_text(config_path))) ==
              expected);
    }
}

TEST_CASE("nfqws backup exports config and lists as independent groups") {
    BackupTempDir directory;
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(nfqws_root / "lua");
    std::filesystem::create_directories(strategies_root);

    write_text(nfqws_root / "nfqws2.conf", "config");
    write_text(nfqws_root / "user.list", "example.com");
    write_text(nfqws_root / "lua" / "strategy.lua", "return true");
    write_text(nfqws_root / "lua" / "packed.lua.gz", "compressed");
    write_text(nfqws_root / "ignored.txt", "unsupported");
    write_text(strategies_root / "custom.conf", "strategy");
    write_text(strategies_root / "ignored.list", "unsupported");

    const auto config = create_nfqws_backup_section_for_test(
        {{"nfqws_config", true}, {"nfqws_lists", false}},
        nfqws_root.string(),
        strategies_root.string());
    CHECK(config.contains("nfqws2/nfqws2.conf"));
    CHECK(config.contains("nfqws2/lua/strategy.lua"));
    CHECK(config.contains("nfqws2/lua/packed.lua.gz"));
    CHECK(config.contains("strategies/custom.conf"));
    CHECK_FALSE(config.contains("nfqws2/user.list"));
    CHECK_FALSE(config.contains("nfqws2/ignored.txt"));
    CHECK_FALSE(config.contains("strategies/ignored.list"));

    const auto lists = create_nfqws_backup_section_for_test(
        {{"nfqws_config", false}, {"nfqws_lists", true}},
        nfqws_root.string(),
        strategies_root.string());
    REQUIRE(lists.size() == 1);
    CHECK(lists.contains("nfqws2/user.list"));
}

TEST_CASE("nfqws split selection takes precedence over legacy flag") {
    BackupTempDir directory;
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);
    write_text(nfqws_root / "nfqws2.conf", "config");
    write_text(nfqws_root / "user.list", "example.com");

    const auto legacy = create_nfqws_backup_section_for_test(
        {{"nfqws", true}},
        nfqws_root.string(),
        strategies_root.string());
    CHECK(legacy.contains("nfqws2/nfqws2.conf"));
    CHECK(legacy.contains("nfqws2/user.list"));

    const auto both = create_nfqws_backup_section_for_test(
        {{"nfqws_config", true}, {"nfqws_lists", true}},
        nfqws_root.string(),
        strategies_root.string());
    CHECK(both == legacy);

    const auto split = create_nfqws_backup_section_for_test(
        {{"nfqws", true},
         {"nfqws_config", false},
         {"nfqws_lists", true}},
        nfqws_root.string(),
        strategies_root.string());
    CHECK_FALSE(split.contains("nfqws2/nfqws2.conf"));
    CHECK(split.contains("nfqws2/user.list"));
}

TEST_CASE("nfqws config and list groups round-trip independently") {
    BackupTempDir directory;
    const auto config_path = directory.path / "keen-pbr" / "config.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(config_path.parent_path());
    std::filesystem::create_directories(nfqws_root / "lua");
    std::filesystem::create_directories(strategies_root);

    const Config original = make_valid_config("127.0.0.1:18209");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    write_text(nfqws_root / "nfqws2.conf", "source-config\n");
    write_text(nfqws_root / "lua" / "strategy.lua", "source-lua\n");
    write_text(nfqws_root / "user.list", "source.example\n");
    write_text(strategies_root / "custom.conf", "source-strategy\n");

    const nlohmann::json config_groups{
        {"nfqws_config", true},
        {"nfqws_lists", false},
    };
    const nlohmann::json list_groups{
        {"nfqws_config", false},
        {"nfqws_lists", true},
    };
    const auto config_files = create_nfqws_backup_section_for_test(
        config_groups, nfqws_root.string(), strategies_root.string());
    const auto list_files = create_nfqws_backup_section_for_test(
        list_groups, nfqws_root.string(), strategies_root.string());

    const nlohmann::json config_backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups", config_groups},
        {"data", {{"nfqws", config_files}}},
    };
    const nlohmann::json list_backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups", list_groups},
        {"data", {{"nfqws", list_files}}},
    };

    write_text(nfqws_root / "nfqws2.conf", "target-config\n");
    write_text(nfqws_root / "lua" / "strategy.lua", "target-lua\n");
    write_text(nfqws_root / "user.list", "target.example\n");
    write_text(strategies_root / "custom.conf", "target-strategy\n");
    write_text(nfqws_root / "stale.conf", "stale-config\n");
    write_text(nfqws_root / "stale.list", "stale-list.example\n");
    write_text(strategies_root / "stale.conf", "stale-strategy\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::vector<std::string> restarted;
    context.restart_restore_service_fn =
        [&restarted](const std::string& service) {
            restarted.push_back(service);
            return 0;
        };
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, config_backup, roots));
    CHECK(read_text(nfqws_root / "nfqws2.conf") == "source-config\n");
    CHECK(read_text(nfqws_root / "lua" / "strategy.lua") == "source-lua\n");
    CHECK(read_text(strategies_root / "custom.conf") ==
          "source-strategy\n");
    CHECK(read_text(nfqws_root / "user.list") == "target.example\n");
    CHECK_FALSE(std::filesystem::exists(
        nfqws_root / "stale.conf"));
    CHECK_FALSE(std::filesystem::exists(
        strategies_root / "stale.conf"));
    CHECK(read_text(nfqws_root / "stale.list") ==
          "stale-list.example\n");

    write_text(nfqws_root / "nfqws2.conf", "after-config-restore\n");
    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, list_backup, roots));
    CHECK(read_text(nfqws_root / "user.list") == "source.example\n");
    CHECK_FALSE(std::filesystem::exists(
        nfqws_root / "stale.list"));
    CHECK(read_text(nfqws_root / "nfqws2.conf") ==
          "after-config-restore\n");
    CHECK(applied.empty());
    REQUIRE(restarted.size() == 2);
    CHECK(restarted[0] == "/opt/etc/init.d/S51nfqws2");
    CHECK(restarted[1] == "/opt/etc/init.d/S51nfqws2");
}

TEST_CASE("empty exact nfqws group removes only the selected class") {
    BackupTempDir directory;
    const auto config_path = directory.path / "keen-pbr" / "config.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(config_path.parent_path());
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);

    const Config original = make_valid_config("127.0.0.1:18231");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    write_text(nfqws_root / "nfqws2.conf", "config\n");
    write_text(strategies_root / "custom.conf", "strategy\n");
    write_text(nfqws_root / "user.list", "example.test\n");

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups",
         {{"nfqws_config", true}, {"nfqws_lists", false}}},
        {"data", {{"nfqws", nlohmann::json::object()}}},
    };
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return 0;
        };
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, backup, roots));
    CHECK_FALSE(std::filesystem::exists(
        nfqws_root / "nfqws2.conf"));
    CHECK_FALSE(std::filesystem::exists(
        strategies_root / "custom.conf"));
    CHECK(read_text(nfqws_root / "user.list") ==
          "example.test\n");
    CHECK(restart_calls == 1U);
}

TEST_CASE("exact nfqws tombstone is restored when service restart fails") {
    BackupTempDir directory;
    const auto config_path = directory.path / "keen-pbr" / "config.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(config_path.parent_path());
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);

    const Config original = make_valid_config("127.0.0.1:18232");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const auto stale_path = nfqws_root / "stale.conf";
    write_text(stale_path, "must-survive-rollback\n");

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups",
         {{"nfqws_config", true}, {"nfqws_lists", false}}},
        {"data", {{"nfqws", nlohmann::json::object()}}},
    };
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            return ++restart_calls == 1U ? 17 : 0;
        };
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, roots),
        ApiError);
    CHECK(read_text(stale_path) ==
          "must-survive-rollback\n");
    CHECK(restart_calls == 2U);
}

TEST_CASE("exact nfqws restore enforces the incremental entry budget") {
    BackupTempDir directory;
    const auto config_path = directory.path / "keen-pbr" / "config.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(config_path.parent_path());
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);

    const Config original = make_valid_config("127.0.0.1:18233");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    for (std::size_t index = 0; index < 513U; ++index) {
        write_text(
            nfqws_root /
                ("managed-" + std::to_string(index) + ".conf"),
            "config\n");
    }

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups",
         {{"nfqws_config", true}, {"nfqws_lists", false}}},
        {"data", {{"nfqws", nlohmann::json::object()}}},
    };
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return 0;
        };
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, roots),
        ApiError);
    CHECK(std::filesystem::exists(
        nfqws_root / "managed-0.conf"));
    CHECK(std::filesystem::exists(
        nfqws_root / "managed-512.conf"));
    CHECK(restart_calls == 0U);
}

TEST_CASE("exact nfqws restore enforces aggregate rollback bytes preflight") {
    BackupTempDir directory;
    const auto config_path = directory.path / "keen-pbr" / "config.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(config_path.parent_path());
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);

    const Config original = make_valid_config("127.0.0.1:18234");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const std::string two_mebibytes(
        2U * 1024U * 1024U, 'x');
    for (std::size_t index = 0; index < 9U; ++index) {
        write_text(
            nfqws_root /
                ("managed-" + std::to_string(index) + ".conf"),
            two_mebibytes);
    }

    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups",
         {{"nfqws_config", true}, {"nfqws_lists", false}}},
        {"data", {{"nfqws", nlohmann::json::object()}}},
    };
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return 0;
        };
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, roots),
        ApiError);
    CHECK(std::filesystem::file_size(
              nfqws_root / "managed-8.conf") ==
          two_mebibytes.size());
    CHECK(restart_calls == 0U);
}

TEST_CASE("nfqws restore rejects files outside declared split group") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"groups",
         {{"nfqws_config", true}, {"nfqws_lists", false}}},
        {"data",
         {{"nfqws",
           {{"nfqws2/user.list", "example.com"}}}}},
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);
    CHECK(applied.empty());
}

TEST_CASE("nfqws restore rejects unsupported file classes") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"nfqws",
           {{"strategies/not-a-strategy.list", "example.com"}}}}},
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);
    CHECK(applied.empty());
}

TEST_CASE("nfqws restore rejects intermediate and target symlinks") {
    BackupTempDir directory;
    const auto root = directory.path / "nfqws2";
    const auto outside = directory.path / "outside";
    std::filesystem::create_directories(root);
    std::filesystem::create_directories(outside);

    std::error_code error;
    std::filesystem::create_directory_symlink(
        outside, root / "linked-directory", error);
    REQUIRE_FALSE(error);
    CHECK_THROWS_AS(
        validate_confined_restore_target_for_test(
            root.string(),
            (root / "linked-directory" / "escaped.conf").string()),
        ApiError);

    write_text(outside / "outside.conf", "outside");
    std::filesystem::create_symlink(
        outside / "outside.conf", root / "linked-file.conf", error);
    REQUIRE_FALSE(error);
    CHECK_THROWS_AS(
        validate_confined_restore_target_for_test(
            root.string(), (root / "linked-file.conf").string()),
        ApiError);

    CHECK_NOTHROW(validate_confined_restore_target_for_test(
        root.string(), (root / "new" / "safe.conf").string()));
}

TEST_CASE("backup validation rejects path traversal before touching files") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:13131"}}}}},
          {"nfqws",
           {{"nfqws2/../outside.conf", "must-not-be-written"}}}}},
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);
    CHECK(read_text(config_path) == original_config);
    CHECK(applied.empty());
}

TEST_CASE("backup validation rejects NUL path before filesystem conversion") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto nfqws_root = directory.path / "nfqws2";
    const auto strategies_root = directory.path / "strategies";
    std::filesystem::create_directories(nfqws_root);
    std::filesystem::create_directories(strategies_root);
    const Config original = make_valid_config("127.0.0.1:12121");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);

    const std::string unsafe_target(
        "nfqws2/truncated.list\0outside.conf",
        sizeof("nfqws2/truncated.list\0outside.conf") - 1U);
    nlohmann::json files = nlohmann::json::object();
    files[unsafe_target] = "must-not-be-written";
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data", {{"nfqws", std::move(files)}}},
    };

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const BackupRestoreRootsForTest roots{
        nfqws_root.string(),
        strategies_root.string(),
    };
    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, roots),
        ApiError);
    CHECK_FALSE(
        std::filesystem::exists(
            nfqws_root / "truncated.list"));
    CHECK(read_text(config_path) == original_config);
    CHECK(applied.empty());
}

TEST_CASE("backup validation rejects unknown sections and reserved general keys") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    const std::string original_config =
        nlohmann::json(original).dump(1, '\t') + "\n";
    write_text(config_path, original_config);
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);

    const std::vector<nlohmann::json> invalid{
        {
            {"format", "keen-pbr-sb-backup"},
            {"schema", 1},
            {"data", {{"future_section", nlohmann::json::object()}}},
        },
        {
            {"format", "keen-pbr-sb-backup"},
            {"schema", 1},
            {"data",
             {{"general",
               {{"outbounds", nlohmann::json::array()}}}}},
        },
        {
            {"format", "keen-pbr-sb-backup"},
            {"schema", 1},
            {"data",
             {{"general", {{"dns", nlohmann::json::object()}}}}},
        },
    };
    for (const auto& backup : invalid) {
        CHECK_THROWS_AS(
            restore_backup_bundle_for_test(context, backup), ApiError);
        CHECK(read_text(config_path) == original_config);
        CHECK(applied.empty());
    }
}

TEST_CASE("backup rollback removes files created by a failed restore") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:12121");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return restart_calls == 1 ? 17 : 0;
        };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "temporary"}}})}}}}},
    };

    std::size_t probe_calls = 0;
    BackupRestoreHooksForTest hooks;
    hooks.probe_service_readiness =
        [&probe_calls](const std::string&) {
            ++probe_calls;
            return RestoreServiceReadinessForTest::ready;
        };
    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup, hooks),
        ApiError);
    CHECK_FALSE(std::filesystem::exists(transports_path));
    CHECK(applied.empty());
    CHECK(restart_calls == 2);
    CHECK(probe_calls == 1U);
}

TEST_CASE("backup restore rolls back on a fatal readiness probe") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18222");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(transports_path, original_transports);
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return 0;
        };
    std::size_t probe_calls = 0;
    BackupRestoreHooksForTest hooks;
    hooks.probe_service_readiness =
        [&probe_calls](const std::string&) {
            ++probe_calls;
            return probe_calls == 1U
                       ? RestoreServiceReadinessForTest::failed
                       : RestoreServiceReadinessForTest::ready;
        };
    hooks.wait_before_service_probe = [] {};
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"transports",
           {{"transports",
             nlohmann::json::array(
                  {{{"tag", "replacement"}}})}}}}},
    };

    try {
        restore_backup_bundle_for_test(
            context, backup, hooks);
        FAIL("restore was expected to fail readiness");
    } catch (const ApiError& error) {
        CHECK(
            std::string(error.what()).find(
                "stopped immediately after restart") !=
            std::string::npos);
    }
    CHECK(read_text(transports_path) == original_transports);
    CHECK(restart_calls == 2U);
    CHECK(probe_calls == 2U);
    CHECK(applied.empty());
}

TEST_CASE("backup restore readiness timeout is bounded and rolls back") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18223");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(transports_path, original_transports);
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return 0;
        };
    std::size_t probe_calls = 0;
    std::size_t wait_calls = 0;
    BackupRestoreHooksForTest hooks;
    hooks.probe_service_readiness =
        [&probe_calls](const std::string&) {
            ++probe_calls;
            return probe_calls <= 20U
                       ? RestoreServiceReadinessForTest::starting
                       : RestoreServiceReadinessForTest::ready;
        };
    hooks.wait_before_service_probe =
        [&wait_calls] { ++wait_calls; };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"general",
           {{"api",
             {{"enabled", true},
              {"listen", "127.0.0.1:18228"}}}}},
          {"transports",
           {{"transports",
             nlohmann::json::array(
                  {{{"tag", "replacement"}}})}}}}},
    };

    try {
        restore_backup_bundle_for_test(
            context, backup, hooks);
        FAIL("restore was expected to time out");
    } catch (const ApiError& error) {
        CHECK(
            std::string(error.what()).find(
                "did not become ready before timeout") !=
            std::string::npos);
    }
    CHECK(read_text(transports_path) == original_transports);
    CHECK(restart_calls == 2U);
    CHECK(probe_calls == 21U);
    CHECK(wait_calls == 19U);
    CHECK(applied.empty());
}

TEST_CASE("backup restore accepts delayed service readiness") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18229");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    context.restart_restore_service_fn =
        [](const std::string&) { return 0; };
    std::size_t probe_calls = 0;
    std::size_t wait_calls = 0;
    BackupRestoreHooksForTest hooks;
    hooks.probe_service_readiness =
        [&probe_calls](const std::string&) {
            ++probe_calls;
            return probe_calls < 3U
                       ? RestoreServiceReadinessForTest::starting
                       : RestoreServiceReadinessForTest::ready;
        };
    hooks.wait_before_service_probe =
        [&wait_calls] { ++wait_calls; };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "replacement"}}})}}}}},
    };

    REQUIRE_NOTHROW(
        restore_backup_bundle_for_test(context, backup, hooks));
    CHECK(std::filesystem::exists(transports_path));
    CHECK(probe_calls == 3U);
    CHECK(wait_calls == 2U);
}

TEST_CASE("backup restore reports failed rollback readiness as incomplete") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto transports_path = directory.path / "transports.json";
    const Config original = make_valid_config("127.0.0.1:18230");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");
    const std::string original_transports =
        R"({"transports":[{"tag":"original"}]})" "\n";
    write_text(transports_path, original_transports);
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    std::size_t restart_calls = 0;
    context.restart_restore_service_fn =
        [&restart_calls](const std::string&) {
            ++restart_calls;
            return 0;
        };
    std::size_t probe_calls = 0;
    BackupRestoreHooksForTest hooks;
    hooks.probe_service_readiness =
        [&probe_calls](const std::string&) {
            ++probe_calls;
            return RestoreServiceReadinessForTest::failed;
        };
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "replacement"}}})}}}}},
    };

    try {
        restore_backup_bundle_for_test(context, backup, hooks);
        FAIL("restore was expected to fail readiness twice");
    } catch (const ApiError& error) {
        const std::string message = error.what();
        CHECK(message.find("rollback was incomplete") !=
              std::string::npos);
        CHECK(message.find(
                  "transport manager rollback restart failed") !=
              std::string::npos);
    }
    CHECK(read_text(transports_path) == original_transports);
    CHECK(restart_calls == 2U);
    CHECK(probe_calls == 2U);
}

TEST_CASE("backup HTTP responses are never cacheable") {
    BackupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const Config original = make_valid_config("127.0.0.1:18196");
    write_text(
        config_path,
        nlohmann::json(original).dump(1, '\t') + "\n");

    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        config_path.string(), broadcaster, original, applied);
    const auto maintenance =
        install_backup_read_lease(context);

    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18196");
    ApiServer server(api_config);
    register_backup_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", 18196);
    const nlohmann::json request{
        {"groups",
         {{"general", true},
          {"transports", false},
          {"outbounds", false},
          {"dns", false},
          {"routing", false},
          {"nfqws_config", false},
          {"nfqws_lists", false}}},
    };
    const auto export_response =
        client.Post("/api/backup", request.dump(), "application/json");
    const auto restore_error =
        client.Post("/api/backup/restore", "{", "application/json");
    const auto rollback_status = client.Get("/api/backup/rollback");
    server.stop();

    REQUIRE(export_response != nullptr);
    CHECK(export_response->status == 200);
    CHECK(export_response->get_header_value("Cache-Control") == "no-store");
    CHECK(maintenance->operations ==
          std::vector<std::string>{"backup-read"});
    CHECK(maintenance->reserve_calls == 0U);
    CHECK_FALSE(maintenance->active);

    REQUIRE(restore_error != nullptr);
    CHECK(restore_error->status == 400);
    CHECK(restore_error->get_header_value("Cache-Control") == "no-store");

    REQUIRE(rollback_status != nullptr);
    CHECK(rollback_status->status == 200);
    CHECK(rollback_status->get_header_value("Cache-Control") == "no-store");
}

TEST_CASE(
    "backup export maps maintenance refusal before snapshot read") {
    struct FailureCase {
        MaintenanceLockErrorKind kind;
        int expected_status;
    };
    const std::vector<FailureCase> cases{
        {MaintenanceLockErrorKind::busy, 409},
        {MaintenanceLockErrorKind::unsafe_state, 503},
    };

    int port = 18198;
    for (const auto& failure : cases) {
        CAPTURE(failure.expected_status);
        BackupTempDir directory;
        const Config original = make_valid_config(
            "127.0.0.1:" + std::to_string(port));
        SseBroadcaster broadcaster;
        std::vector<Config> applied;
        auto context = make_backup_context(
            (directory.path / "missing-config.json").string(),
            broadcaster,
            original,
            applied);

        std::vector<std::string> operations;
        context.maintenance_lease_factory_fn =
            [&operations, kind = failure.kind](
                std::string operation)
                -> std::unique_ptr<MaintenanceLease> {
            operations.push_back(std::move(operation));
            throw MaintenanceLockError(
                kind, "injected backup maintenance refusal");
        };

        std::size_t snapshot_reads = 0;
        ApiConfig api_config;
        api_config.listen =
            "127.0.0.1:" + std::to_string(port);
        ApiServer server(api_config);
        register_backup_handler_for_test(
            server,
            context,
            [&snapshot_reads](
                const ApiContext&,
                const nlohmann::json&) {
                ++snapshot_reads;
                return nlohmann::json::object();
            });
        server.start();

        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/backup",
            R"({"groups":{"general":true}})",
            "application/json");
        server.stop();

        REQUIRE(response != nullptr);
        CHECK(response->status == failure.expected_status);
        CHECK(snapshot_reads == 0U);
        CHECK(operations ==
              std::vector<std::string>{"backup-read"});
        ++port;
    }
}

TEST_CASE(
    "backup export holds read lease without reserving generation") {
    constexpr int api_port = 18200;
    BackupTempDir directory;
    const Config original =
        make_valid_config("127.0.0.1:18200");
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        (directory.path / "unused-config.json").string(),
        broadcaster,
        original,
        applied);
    const auto maintenance =
        install_backup_read_lease(context);

    std::size_t snapshot_reads = 0;
    bool read_started_with_lease = false;
    ApiConfig api_config;
    api_config.listen = "127.0.0.1:18200";
    ApiServer server(api_config);
    register_backup_handler_for_test(
        server,
        context,
        [&](const ApiContext&, const nlohmann::json&) {
            ++snapshot_reads;
            read_started_with_lease = maintenance->active;
            return nlohmann::json{
                {"format", "test-backup"},
            };
        });
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response = client.Post(
        "/api/backup",
        R"({"groups":{}})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(snapshot_reads == 1U);
    CHECK(read_started_with_lease);
    CHECK(maintenance->operations ==
          std::vector<std::string>{"backup-read"});
    CHECK(maintenance->reserve_calls == 0U);
    CHECK_FALSE(maintenance->active);
}

TEST_CASE("backup HTTP endpoints inherit configured session authentication") {
    BackupTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const Config original = make_valid_config("127.0.0.1:18197");
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    auto context = make_backup_context(
        (directory.path / "config.json").string(),
        broadcaster,
        original,
        applied);

    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18197");
    ApiServer server(api_config);
    register_backup_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", 18197);
    const auto response =
        client.Post("/api/backup", R"({"groups":{}})", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 401);
    CHECK(response->get_header_value("Cache-Control") == "no-store");
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "authentication required");
}

} // namespace keen_pbr3

#endif
