#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_backup.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/config/config_migration.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {
namespace fs = std::filesystem;
using json = nlohmann::json;

class ConfigBackupMigrationTempDir {
public:
    ConfigBackupMigrationTempDir() {
        char pattern[] = "/tmp/keen-pbr-config-backup-migration-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~ConfigBackupMigrationTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    fs::path path;
};

std::string read_config_bytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_config_bytes(const fs::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << bytes;
    REQUIRE(output);
}

json unknown_values() {
    return { {"note", "synthetic extension"}, {"null_value", nullptr},
             {"empty_object", json::object()}, {"empty_array", json::array()},
             {"nested", {{"empty", json::object()}, {"null", nullptr}}} };
}

json baseline_document(const fs::path& directory) {
    auto document = json::parse(R"({
        "schema_version":2,
        "daemon":{"firewall_backend":"auto"},
        "api":{"enabled":true,"listen":"127.0.0.1:12121"},
        "outbounds":[{"type":"table","tag":"wan","table":254}],
        "dns":{"system_resolver":{"address":"127.0.0.1"},
               "servers":[{"tag":"default_dns","address":"127.0.0.1"}],
               "fallback":["default_dns"]},
        "lists":{"alpha":{"domains":["example.invalid"]}},
        "route":{"rules":[{"list":["alpha"],"outbound":"wan"}]}
    })");
    document["schema_version"] = kCurrentConfigSchemaVersion;
    document["daemon"]["cache_dir"] = (directory / "cache").string();
    return document;
}

json extended_document(const fs::path& directory) {
    auto document = baseline_document(directory);
    const auto extension = unknown_values();
    document["unknown_root"] = extension;
    document["daemon"]["unknown_daemon"] = extension;
    document["dns"]["unknown_dns"] = extension;
    document["dns"]["servers"][0]["unknown_server"] = extension;
    document["outbounds"][0]["unknown_outbound"] = extension;
    document["lists"]["alpha"]["unknown_list"] = extension;
    document["route"]["rules"][0]["unknown_rule"] = extension;
    return document;
}

struct AppliedConfigBackup {
    Config config;
    std::string serialized;
};

ApiContext make_migration_context(const std::string& path, SseBroadcaster& broadcaster,
                                 const Config& visible,
                                 std::vector<AppliedConfigBackup>& applied) {
    return ApiContext{
        path, broadcaster, [visible] { return visible; }, [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> { return std::nullopt; },
        [] {}, [](const Config&) {}, [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
        [](const std::string&) { return TestRoutingResult{}; }, [] {}, [] {},
        [&applied](Config config, std::string serialized) {
            applied.push_back({std::move(config), std::move(serialized)});
            ConfigApplyResult result;
            result.applied = true;
            return result;
        },
        [] {}, [] {}, [] {},
        [](const api::ListRefreshRequest&) { return ListRefreshOperationResult{}; },
    };
}

json archive_with_data(json data) {
    return {{"format", "keen-pbr-sb-backup"}, {"schema", 1}, {"data", std::move(data)}};
}

struct ConfigBackupMigrationFixture {
    ConfigBackupMigrationTempDir directory;
    const fs::path config_path{directory.path / "config.json"};
    const json original = extended_document(directory.path);
    const Config visible{parse_and_validate_config(original.dump())};
    SseBroadcaster broadcaster;
    std::vector<AppliedConfigBackup> applied;
    std::vector<std::string> restarted;
    ApiContext context{make_migration_context(config_path.string(), broadcaster, visible, applied)};

    ConfigBackupMigrationFixture() {
        write_config_bytes(config_path, original.dump(2) + "\n");
        context.restart_restore_service_fn = [this](const std::string& script) {
            restarted.push_back(script);
            return 0;
        };
    }

    json persisted() const { return json::parse(read_config_bytes(config_path)); }
    json archive() const {
        return create_backup_bundle_for_test(context,
            {{"general", true}, {"outbounds", true}, {"dns", true}, {"routing", true}});
    }
};

void check_unknown_sections(const json& document, const json& expected) {
    CHECK(document.at("unknown_root") == expected.at("unknown_root"));
    for (const char* section : {"daemon", "dns", "outbounds", "lists", "route"}) {
        CHECK(document.at(section) == expected.at(section));
    }
}
} // namespace

TEST_CASE("config backup migration exports exact unknown root nested and item fields") {
    ConfigBackupMigrationFixture fixture;
    const auto archive = fixture.archive();
    CHECK(archive.at("config_schema_version") == kCurrentConfigSchemaVersion);
    const auto data = archive.at("data");
    CHECK(data.at("general").at("unknown_root") == fixture.original.at("unknown_root"));
    CHECK(data.at("general").at("daemon") == fixture.original.at("daemon"));
    for (const char* section : {"dns", "outbounds", "lists", "route"}) {
        CHECK(data.at(section) == fixture.original.at(section));
    }
    CHECK(fixture.applied.empty());
    CHECK(fixture.restarted.empty());
}

TEST_CASE("config backup migration partial general restore retains unselected unknown settings") {
    ConfigBackupMigrationFixture fixture;
    const auto replacement_api = json{{"enabled", true}, {"listen", "127.0.0.1:13131"}};
    restore_backup_bundle_for_test(fixture.context,
        archive_with_data({{"general", {{"api", replacement_api}}}}));
    const auto restored = fixture.persisted();
    check_unknown_sections(restored, fixture.original);
    CHECK(restored.at("api") == replacement_api);
    REQUIRE(fixture.applied.size() == 1U);
    CHECK(json::parse(fixture.applied.front().serialized) == restored);
    const auto exported = fixture.archive().at("data");
    CHECK(exported.at("general").at("unknown_root") == unknown_values());
    CHECK(exported.at("dns") == fixture.original.at("dns"));
    CHECK(fixture.restarted.empty());
}

TEST_CASE("config backup migration full archive round trip preserves unknown null and empty shapes") {
    ConfigBackupMigrationFixture fixture;
    const auto archive = fixture.archive();
    write_config_bytes(fixture.config_path, baseline_document(fixture.directory.path).dump() + "\n");
    restore_backup_bundle_for_test(fixture.context, archive);
    check_unknown_sections(fixture.persisted(), fixture.original);
    CHECK(fixture.archive().at("data") == archive.at("data"));
    REQUIRE(fixture.applied.size() == 1U);
    CHECK(fixture.restarted.empty());
}

TEST_CASE("config backup migration selected sections replace removed map keys arrays and known options") {
    ConfigBackupMigrationFixture fixture;
    auto baseline = baseline_document(fixture.directory.path);
    auto replacement_dns = baseline.at("dns");
    replacement_dns.erase("fallback");
    const auto replacement_daemon = json{{"cache_dir", (fixture.directory.path / "new-cache").string()}};
    const auto replacement_lists = json::object();
    const auto replacement_route = json{{"rules", json::array()}};
    restore_backup_bundle_for_test(fixture.context,
        archive_with_data({
            {"general", {{"daemon", replacement_daemon}}},
            {"outbounds", baseline.at("outbounds")}, {"dns", replacement_dns},
            {"lists", replacement_lists}, {"route", replacement_route},
        }));
    const auto restored = fixture.persisted();
    CHECK(restored.at("daemon") == replacement_daemon);
    CHECK(restored.at("dns") == replacement_dns);
    CHECK(restored.at("outbounds") == baseline.at("outbounds"));
    CHECK(restored.at("lists") == replacement_lists);
    CHECK(restored.at("route") == replacement_route);
    CHECK(restored.at("unknown_root") == fixture.original.at("unknown_root"));
    CHECK_FALSE(restored.at("daemon").contains("firewall_backend"));
    CHECK_FALSE(restored.at("dns").contains("fallback"));
    CHECK(fixture.restarted.empty());
}

TEST_CASE("config backup migration versionless partial archive migrates independently of modern destination") {
    ConfigBackupMigrationFixture fixture;
    auto legacy_dns = baseline_document(fixture.directory.path).at("dns");
    legacy_dns["fallback"] = "default_dns";
    auto archive = archive_with_data({
        {"general", {{"fwmark", {{"start", 65536}, {"mask", 4294901760ULL}}}}},
        {"dns", legacy_dns},
    });
    SUBCASE("old archives have no source version metadata") {}
    SUBCASE("explicit source version one follows the same migration") {
        archive["config_schema_version"] = 1;
    }
    restore_backup_bundle_for_test(fixture.context, archive);
    const auto restored = fixture.persisted();
    CHECK(restored.at("schema_version") == kCurrentConfigSchemaVersion);
    CHECK(restored.at("dns").at("fallback") == json::array({"default_dns"}));
    REQUIRE(restored.at("fwmark").at("start").is_string());
    REQUIRE(restored.at("fwmark").at("mask").is_string());
    CHECK(std::stoull(restored.at("fwmark").at("start").get<std::string>(), nullptr, 16) == 65536ULL);
    CHECK(std::stoull(restored.at("fwmark").at("mask").get<std::string>(), nullptr, 16) == 4294901760ULL);
    CHECK(restored.at("unknown_root") == fixture.original.at("unknown_root"));
    REQUIRE(fixture.applied.size() == 1U);
    CHECK(fixture.applied.front().config.schema_version == kCurrentConfigSchemaVersion);
    CHECK(fixture.restarted.empty());
}

TEST_CASE("config backup migration rejects future source schema before persistent or runtime changes") {
    ConfigBackupMigrationFixture fixture;
    const auto before = read_config_bytes(fixture.config_path);
    auto archive = archive_with_data({
        {"general", {{"schema_version", kCurrentConfigSchemaVersion + 1},
                     {"api", {{"enabled", true}, {"listen", "127.0.0.1:13132"}}}}},
    });
    SUBCASE("version in the general section") {}
    SUBCASE("future metadata on a DNS-only archive") {
        archive = archive_with_data({
            {"dns", baseline_document(fixture.directory.path).at("dns")},
        });
        archive["config_schema_version"] = kCurrentConfigSchemaVersion + 1;
    }
    SUBCASE("current general marker does not hide future archive metadata") {
        archive["data"]["general"]["schema_version"] = kCurrentConfigSchemaVersion;
        archive["config_schema_version"] = kCurrentConfigSchemaVersion + 1;
    }
    CHECK_THROWS_AS(restore_backup_bundle_for_test(fixture.context, archive), ApiError);
    CHECK(read_config_bytes(fixture.config_path) == before);
    CHECK(fixture.applied.empty());
    CHECK(fixture.restarted.empty());
}

TEST_CASE("config backup migration keeps omitted top level export defaults without rewriting present sections") {
    ConfigBackupMigrationFixture fixture;
    auto sparse = baseline_document(fixture.directory.path);
    sparse.erase("schema_version");
    write_config_bytes(fixture.config_path, sparse.dump() + "\n");
    const auto data = fixture.archive().at("data");
    CHECK(data.at("general").at("schema_version") == kCurrentConfigSchemaVersion);
    REQUIRE(data.at("general").contains("tunnel_probe"));
    CHECK(data.at("general").at("tunnel_probe").is_null());
    REQUIRE(data.at("general").contains("fwmark"));
    CHECK(data.at("general").at("fwmark").is_null());
    CHECK(data.at("dns") == sparse.at("dns"));
    CHECK(data.at("outbounds") == sparse.at("outbounds"));
    const auto dns_only = create_backup_bundle_for_test(fixture.context, {{"dns", true}});
    CHECK(dns_only.at("config_schema_version") == kCurrentConfigSchemaVersion);
    CHECK_FALSE(dns_only.at("data").contains("general"));
    CHECK(fixture.persisted() == sparse);
}

TEST_CASE("config backup migration failed runtime apply restores original bytes with unknown settings") {
    ConfigBackupMigrationFixture fixture;
    const auto before = read_config_bytes(fixture.config_path);
    fixture.context.enqueue_apply_validated_config_fn = [&fixture](Config config, std::string serialized) {
        fixture.applied.push_back({std::move(config), std::move(serialized)});
        ConfigApplyResult result;
        if (fixture.applied.size() == 1U) result.error = "synthetic apply failure";
        else result.applied = true;
        return result;
    };
    CHECK_THROWS_AS(restore_backup_bundle_for_test(fixture.context,
        archive_with_data({{"general", {{"api", {{"enabled", true},
            {"listen", "127.0.0.1:13133"}}}}}})), ApiError);
    CHECK(read_config_bytes(fixture.config_path) == before);
    REQUIRE(fixture.applied.size() == 2U);
    CHECK(fixture.applied.back().serialized == before);
    check_unknown_sections(fixture.persisted(), fixture.original);
    CHECK(fixture.restarted.empty());
}

} // namespace keen_pbr3
#endif
