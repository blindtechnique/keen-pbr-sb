#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_backup.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <sys/stat.h>
#include <unistd.h>
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

    // The test container deliberately has no transport-manager init script.
    // Restart therefore fails after the new files and runtime were applied.
    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);

    CHECK(read_text(config_path) == original_config);
    CHECK(read_text(transports_path) == original_transports);
    struct stat restored_metadata {};
    REQUIRE(::stat(transports_path.c_str(), &restored_metadata) == 0);
    CHECK((restored_metadata.st_mode & 0777) == 0600);
    REQUIRE(applied.size() == 2);
    CHECK(applied.front().api->listen == "127.0.0.1:13131");
    CHECK(applied.back().api->listen == "127.0.0.1:12121");
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
    const nlohmann::json backup{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"data",
         {{"transports",
           {{"transports",
             nlohmann::json::array({{{"tag", "temporary"}}})}}}}},
    };

    CHECK_THROWS_AS(
        restore_backup_bundle_for_test(context, backup), ApiError);
    CHECK_FALSE(std::filesystem::exists(transports_path));
    CHECK(applied.empty());
}

} // namespace keen_pbr3

#endif
