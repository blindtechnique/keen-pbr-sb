#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_backup.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/config/subscription_import_plan.hpp"
#include "../src/config/subscription_store.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {
namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr const char* kSourceUrl =
    "https://provider.example/subscription?token=synthetic-backup-secret";
constexpr const char* kLink =
    "vless://00000000-0000-0000-0000-000000000001@vpn.example:443?security=tls#Saved";
constexpr const char* kOtherLink =
    "vless://00000000-0000-0000-0000-000000000002@other.example:443?security=tls#Other";

class SubscriptionBackupTempDir {
public:
    SubscriptionBackupTempDir() {
        char pattern[] = "/tmp/keen-pbr-backup-subscriptions-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~SubscriptionBackupTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    fs::path path;
};

void write_text(const fs::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << content;
    REQUIRE(output);
}

std::string read_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

Config valid_config() {
    auto config = parse_config(R"({
        "daemon":{"cache_dir":"/tmp/keen-pbr-backup-subscriptions-cache","firewall_backend":"auto"},
        "api":{"enabled":true,"listen":"127.0.0.1:12121"},
        "outbounds":[{"type":"table","tag":"wan","table":254}],
        "dns":{"system_resolver":{"address":"127.0.0.1"},
               "servers":[{"tag":"default_dns","address":"127.0.0.1"}],
               "fallback":["default_dns"]},
        "route":{"rules":[]}
    })");
    validate_config(config);
    return config;
}

ApiContext make_context(const std::string& path, SseBroadcaster& broadcaster,
                        const Config& visible, std::vector<Config>& applied) {
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
        [&applied](Config config, std::string) {
            applied.push_back(std::move(config));
            ConfigApplyResult result;
            result.applied = true;
            return result;
        },
        [] {}, [] {}, [] {},
        [](const api::ListRefreshRequest&) { return ListRefreshOperationResult{}; },
    };
}

json transport_config(const std::string& link = kLink) {
    return {{"transports", json::array({
        {{"type", "sing-box"}, {"tag", "vpn-bound"}, {"link", link}},
    })}};
}

json bundle_with_data(json data) {
    return {{"format", "keen-pbr-sb-backup"}, {"schema", 1}, {"data", std::move(data)}};
}

struct SubscriptionBackupFixture {
    SubscriptionBackupTempDir directory;
    const fs::path config_path{directory.path / "config.json"};
    const fs::path transports_path{directory.path / "transports.json"};
    const fs::path sources_path{directory.path / "subscriptions.json"};
    const fs::path rollback_path{directory.path / "rollback.json"};
    const Config original{valid_config()};
    SseBroadcaster broadcaster;
    std::vector<Config> applied;
    std::vector<std::string> restarted;
    ApiContext context{make_context(config_path.string(), broadcaster, original, applied)};

    SubscriptionBackupFixture() {
        write_text(config_path, json(original).dump() + "\n");
        write_text(transports_path, transport_config().dump() + "\n");
        context.restart_restore_service_fn = [this](const std::string& script) {
            restarted.push_back(script);
            return 0;
        };
    }

    json seed_sources() {
        SubscriptionStore store(sources_path.string());
        const auto fingerprint = subscription_link_fingerprint(kLink);
        const auto source = store.save(kSourceUrl, "Saved source", {{"checked_at", 120}},
            {"vpn-bound"}, json::array({{{"tag", "vpn-bound"},
                {"key", "exact:" + fingerprint}, {"fingerprint", fingerprint},
                {"stable", false}}}));
        store.set_refresh_interval(source.at("id").get<std::string>(), 43200);
        return sources();
    }

    json sources() const { return json::parse(read_text(sources_path)); }
    json archive() const {
        return create_backup_bundle_for_test(context, {{"transports", true}});
    }
};
} // namespace

TEST_CASE("subscription backup exports private sources only with the transports group") {
    SubscriptionBackupFixture fixture;
    const auto saved = fixture.seed_sources();
    const auto selected = fixture.archive();
    CHECK(selected.at("data").at("subscriptions") == saved);
    CHECK(selected.at("data").at("subscriptions")[0].at("url") == kSourceUrl);
    CHECK(selected.at("data").at("subscriptions")[0].contains("_bindings"));
    CHECK_FALSE(create_backup_bundle_for_test(fixture.context,
        {{"general", true}, {"transports", false}}).at("data").contains("subscriptions"));
    SubscriptionStore store(fixture.sources_path.string());
    const auto public_sources = store.list();
    REQUIRE(public_sources.size() == 1U);
    CHECK_FALSE(public_sources[0].contains("url"));
    CHECK_FALSE(public_sources[0].contains("_bindings"));
    CHECK(public_sources.dump().find("synthetic-backup-secret") == std::string::npos);
}

TEST_CASE("subscription backup round trip restores sources bindings interval and private mode") {
    SubscriptionBackupFixture fixture;
    const auto saved = fixture.seed_sources();
    const auto archive = fixture.archive();
    fs::remove(fixture.sources_path);
    write_text(fixture.transports_path, transport_config(kOtherLink).dump() + "\n");
    restore_backup_bundle_for_test(fixture.context, archive);
    CHECK(fixture.sources() == saved);
    CHECK(fixture.sources()[0].at("refresh_interval_seconds") == 43200);
    CHECK(json::parse(read_text(fixture.transports_path)) == transport_config());
    struct stat metadata {};
    REQUIRE(::stat(fixture.sources_path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    REQUIRE(fixture.restarted.size() == 1U);
    CHECK(fixture.restarted.front() == "/opt/etc/init.d/S79transport-manager");
    CHECK(fixture.applied.empty());
}

TEST_CASE("legacy transport archive keeps subscription sources but prunes reused tag identity") {
    SubscriptionBackupFixture fixture;
    const auto saved = fixture.seed_sources();
    const auto legacy = bundle_with_data({{"transports", transport_config(kOtherLink)}});
    restore_backup_bundle_for_test(fixture.context, legacy);
    auto expected = saved;
    expected[0]["transport_tags"] = json::array();
    expected[0]["_bindings"] = json::array();
    CHECK(fixture.sources() == expected);
    CHECK(fixture.sources()[0].at("url") == kSourceUrl);
    CHECK(fixture.sources()[0].at("refresh_interval_seconds") == 43200);
}

TEST_CASE("explicit empty subscription archive clears sources without restarting transports") {
    SubscriptionBackupFixture fixture;
    fixture.seed_sources();
    const auto transports = read_text(fixture.transports_path);
    restore_backup_bundle_for_test(fixture.context,
        bundle_with_data({{"subscriptions", json::array()}}));
    CHECK(fixture.sources().empty());
    CHECK(read_text(fixture.transports_path) == transports);
    CHECK(fixture.restarted.empty());
    CHECK(fixture.applied.empty());
}

TEST_CASE("metadata only subscription restore and persistent rollback have no service effects") {
    SubscriptionBackupFixture fixture;
    auto changed = fixture.seed_sources();
    const auto original_bytes = read_text(fixture.sources_path);
    changed[0]["name"] = "Renamed source";
    restore_backup_with_rollback_for_test(fixture.context,
        bundle_with_data({{"subscriptions", changed}}), fixture.rollback_path.string());
    CHECK(fixture.sources()[0].at("name") == "Renamed source");
    const auto rollback = json::parse(read_text(fixture.rollback_path));
    REQUIRE(rollback.at("entries").size() == 1U);
    CHECK(rollback.at("entries")[0].at("target") == "subscriptions");
    restore_persistent_rollback_for_test(fixture.context, fixture.rollback_path.string());
    CHECK(read_text(fixture.sources_path) == original_bytes);
    CHECK(fixture.restarted.empty());
    CHECK(fixture.applied.empty());
}

TEST_CASE("subscription write failure compensates both sources and transport configuration") {
    SubscriptionBackupFixture fixture;
    fixture.seed_sources();
    auto archive = fixture.archive();
    archive["data"]["subscriptions"][0]["name"] = "New source name";
    write_text(fixture.transports_path, transport_config(kOtherLink).dump() + "\n");
    const auto original_sources = read_text(fixture.sources_path);
    const auto original_transports = read_text(fixture.transports_path);
    bool injected = false;
    BackupRestoreHooksForTest hooks;
    hooks.atomic_write_fault = [&](const std::string& path, AtomicFileWriteStage stage) {
        if (!injected && path == fixture.sources_path.string() &&
            stage == AtomicFileWriteStage::directory_fsync) {
            injected = true;
            throw std::runtime_error("injected subscriptions write failure");
        }
    };
    CHECK_THROWS_AS(restore_backup_with_rollback_for_test(fixture.context, archive,
        fixture.rollback_path.string(), hooks), ApiError);
    CHECK(injected);
    CHECK(read_text(fixture.sources_path) == original_sources);
    CHECK(read_text(fixture.transports_path) == original_transports);
    CHECK(fixture.restarted.empty());
    CHECK(fixture.applied.empty());
}

TEST_CASE("malformed subscription archive rejects before writes and preserves the rollback point") {
    SubscriptionBackupFixture fixture;
    fixture.seed_sources();
    auto archive = fixture.archive();
    const auto original_sources = read_text(fixture.sources_path);
    const auto original_transports = read_text(fixture.transports_path);
    write_text(fixture.rollback_path, "existing rollback point\n");
    SUBCASE("section is not an array") { archive["data"]["subscriptions"] = json::object(); }
    SUBCASE("source URL is malformed") { archive["data"]["subscriptions"][0]["url"] = "invalid"; }
    SUBCASE("binding is malformed") { archive["data"]["subscriptions"][0]["_bindings"][0]["fingerprint"] = "bad"; }
    std::size_t writes = 0;
    BackupRestoreHooksForTest hooks;
    hooks.atomic_write_fault = [&](const std::string&, AtomicFileWriteStage) { ++writes; };
    CHECK_THROWS_WITH_AS(restore_backup_with_rollback_for_test(fixture.context, archive,
        fixture.rollback_path.string(), hooks), "invalid subscription backup", ApiError);
    CHECK(writes == 0U);
    CHECK(read_text(fixture.rollback_path) == "existing rollback point\n");
    CHECK(read_text(fixture.sources_path) == original_sources);
    CHECK(read_text(fixture.transports_path) == original_transports);
    CHECK(fixture.restarted.empty());
}

} // namespace keen_pbr3
#endif
