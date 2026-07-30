#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_catalog.hpp"
#include "../src/api/handler_catalog_setup.hpp"
#include "../src/api/handler_config.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/daemon/config_store.hpp"

#include <algorithm>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class CatalogSetupTempDir {
public:
    CatalogSetupTempDir() {
        char pattern[] = "/tmp/keen-pbr-catalog-setup-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~CatalogSetupTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

void write_text(
    const std::filesystem::path& path,
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

Config catalog_base_config() {
    auto config = parse_config(R"({
        "daemon": {
            "cache_dir": "/tmp/keen-pbr-catalog-setup-cache",
            "firewall_backend": "auto"
        },
        "outbounds": [
            {
                "type": "table",
                "tag": "wan",
                "table": 254
            },
            {
                "type": "interface",
                "tag": "proxy",
                "interface": "tun0"
            }
        ],
        "dns": {
            "system_resolver": {
                "address": "127.0.0.1"
            },
            "servers": [
                {
                    "tag": "proxy_dns",
                    "address": "9.9.9.9",
                    "detour": "proxy"
                },
                {
                    "tag": "direct_dns",
                    "address": "1.1.1.1"
                }
            ],
            "fallback": ["direct_dns"],
            "rules": []
        },
        "route": {
            "rules": []
        }
    })");
    validate_config(config);
    return config;
}

nlohmann::json catalog_snapshot(
    std::string url =
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs") {
    return {
        {"source", "test"},
        {"catalog_id", "test:catalog"},
        {"presets",
         nlohmann::json::array(
             {{{"id", "category-ai"},
               {"name", "Нейросети"},
               {"engines",
                {
                    {"dns",
                     {{"domains",
                       {"chatgpt.com", "oaistatic.com"}},
                      {"subnets", {"203.0.113.0/24"}}}},
                    {"singbox",
                     {{"action", "tunnel"},
                      {"ruleSets",
                       nlohmann::json::array(
                           {{{"tag", "geosite-ai"},
                             {"url", std::move(url)}}})}}},
                }}}})},
    };
}

nlohmann::json catalog_intent(
    std::optional<std::string> source_detour = "proxy") {
    nlohmann::json intent = {
        {"selections",
         nlohmann::json::array(
             {{{"preset_id", "category-ai"},
               {"display_name", "AI-сервисы"}}})},
        {"mode", "outbound"},
        {"outbound_tag", "proxy"},
        {"dns_mode", "automatic"},
        {"route_display_name", "AI через прокси"},
        {"dns_display_name", "DNS для AI"},
    };
    if (source_detour.has_value()) {
        intent["source_detour_tag"] = *source_detour;
    }
    return intent;
}

nlohmann::json apply_request(
    const nlohmann::json& intent,
    const nlohmann::json& preview,
    bool accept_warnings) {
    return {
        {"intent", intent},
        {"base_revision", preview.at("base_revision")},
        {"candidate_revision", preview.at("candidate_revision")},
        {"preview_token", preview.at("preview_token")},
        {"accept_warnings", accept_warnings},
    };
}

class CatalogMaintenanceLease final : public MaintenanceLease {
public:
    std::uint32_t base_generation() const noexcept override {
        return 1U;
    }

    std::uint32_t reserve(
        std::uint32_t expected_generation) override {
        return expected_generation + 1U;
    }

    void verify_held() override {}
};

class ConfigOperationGate {
public:
    void begin() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_) {
            throw ApiError(
                "Another configuration operation is in progress",
                409,
                nlohmann::json{
                    {"error",
                     "Another configuration operation is in progress"},
                    {"reason", "config_operation_in_progress"},
                }
                    .dump());
        }
        active_ = true;
    }

    void finish() {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = false;
    }

private:
    std::mutex mutex_;
    bool active_{false};
};

ApiContext make_catalog_context(
    const std::string& config_path,
    SseBroadcaster& broadcaster,
    ConfigStore& store,
    ConfigOperationGate& operation_gate,
    std::size_t& apply_calls) {
    ApiContext context{
        config_path,
        broadcaster,
        [&store] { return store.visible_config(); },
        [&store] { return store.config_is_draft(); },
        [&store](Config config, std::string serialized) {
            store.stage_config(
                std::move(config), std::move(serialized));
        },
        [&store]() { return store.staged_snapshot(); },
        [&store] { store.clear_staged(); },
        [](const Config& config) { validate_config(config); },
        [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<
                std::string,
                api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        [&operation_gate] { operation_gate.begin(); },
        [&operation_gate] { operation_gate.finish(); },
        [&store, &apply_calls](
            Config config,
            std::string serialized) {
            ++apply_calls;
            auto marks = allocate_outbound_marks(
                config.fwmark.value_or(FwmarkConfig{}),
                config.outbounds.value_or(
                    std::vector<Outbound>{}));
            store.replace_active(
                std::move(config), std::move(marks));
            store.clear_staged_if_matches(serialized);
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
    context.get_visible_config_snapshot_fn =
        [&store] { return store.visible_snapshot(); };
    context.get_staged_config_cas_snapshot_fn =
        [&store] { return store.staged_cas_snapshot(); };
    context.maintenance_lease_factory_fn =
        [](std::string) -> std::unique_ptr<MaintenanceLease> {
        return std::make_unique<CatalogMaintenanceLease>();
    };
    context.emergency_quiesce_runtime_fn = [] {};
    return context;
}

void register_catalog_test_handler(
    ApiServer& server,
    ApiContext& context,
    CatalogSnapshotProvider provider,
    const CatalogSetupTempDir& directory,
    ConfigSaveTestOptions options = {}) {
    if (options.recovery_state_root.empty()) {
        options.recovery_state_root =
            directory.path / ".keen-pbr-recovery";
    }
    register_catalog_setup_handler_for_test(
        server,
        context,
        std::move(provider),
        [](const std::string& path, const std::string& body) {
            write_config_atomically(path, body);
        },
        std::move(options));
}

} // namespace

TEST_CASE(
    "catalog handler enriches upstream-shaped snapshots with local routing companions") {
    const nlohmann::json upstream = nlohmann::json::array({
        {
            {"id", "meta"},
            {"name", "Meta"},
            {"engines",
             {{"singbox",
               {{"ruleSets",
                 {{{"url",
                    "https://raw.githubusercontent.com/SagerNet/"
                    "sing-geosite/rule-set/geosite-meta.srs"}}}}}}}},
        },
        {
            {"id", "whatsapp"},
            {"name", "WhatsApp"},
            {"engines",
             {{"dns",
               {{"domains", {"whatsapp.com"}},
                {"subnets", {"31.13.64.0/18"}}}}}},
        },
        {
            {"id", "telegram"},
            {"name", "Telegram"},
            {"engines",
             {{"dns",
               {{"domains", {"t.me", "telegram.org"}},
                {"subnets", {"91.108.4.0/22"}}}},
              {"singbox",
               {{"ruleSets",
                 {{{"url",
                    "https://repo.hoaxisr.ru/rulesets/srs/"
                    "telegram.srs"}}}}}}}},
        },
        {
            {"id", "unrelated"},
            {"name", "Unrelated"},
            {"engines",
             {{"dns", {{"domains", {"example.test"}}}}}},
        },
    });
    const nlohmann::json bundled = nlohmann::json::array({
        {
            {"id", "meta"},
            {"name", "Meta"},
            {"routingCompanions",
             {{{"id", "meta_whatsapp_ip"},
               {"name", "Meta / WhatsApp IP"},
               {"sourcePresetId", "whatsapp"},
               {"include", "ip_cidrs"},
               {"suppressDirectSelection", true}}}},
            {"engines",
             {{"singbox",
               {{"ruleSets",
                 {{{"url",
                    "https://raw.githubusercontent.com/SagerNet/"
                    "sing-geosite/rule-set/geosite-meta.srs"}}}}}}}},
        },
        {
            {"id", "whatsapp"},
            {"name", "WhatsApp"},
            {"engines",
             {{"dns",
               {{"domains", {"whatsapp.com", "whatsapp.net"}},
                {"subnets",
                 {"31.13.24.0/21", "57.141.24.0/24"}}}}}},
        },
        {
            {"id", "telegram"},
            {"name", "Telegram"},
            {"routingCompanions",
             {{{"id", "telegram_ip"},
               {"name", "Telegram IP"},
               {"url",
                "https://raw.githubusercontent.com/runetfreedom/"
                "russia-v2ray-rules-dat/release/sing-box/"
                "rule-set-geoip/geoip-telegram.srs"}}}},
            {"engines",
             {{"dns", {{"domains", {"t.me", "telegram.org"}}}},
              {"singbox",
               {{"ruleSets",
                 {{{"url",
                    "https://repo.hoaxisr.ru/rulesets/srs/"
                    "telegram.srs"}}}}}}}},
        },
    });

    const auto enriched =
        enrich_catalog_with_routing_companions(
            upstream, bundled);
    const auto preset =
        [&](const std::string& id) -> const nlohmann::json& {
            const auto found = std::find_if(
                enriched.begin(),
                enriched.end(),
                [&](const nlohmann::json& candidate) {
                    return candidate.value(
                               "id", std::string{}) == id;
                });
            REQUIRE(found != enriched.end());
            return *found;
        };

    CHECK(preset("meta").at("routingCompanions").size() == 1U);
    CHECK(
        preset("whatsapp")
            .at("engines")
            .at("dns")
            .at("subnets") ==
        nlohmann::json::array(
            {"31.13.24.0/21", "57.141.24.0/24"}));
    CHECK_FALSE(
        preset("telegram")
            .at("engines")
            .at("dns")
            .contains("subnets"));
    CHECK(
        preset("telegram")
            .at("routingCompanions")
            .at(0)
            .at("id") == "telegram_ip");
    CHECK(
        preset("unrelated")
            .at("engines")
            .at("dns")
            .at("domains")
            .at(0) == "example.test");

    const auto bundled_fallback =
        enrich_catalog_with_routing_companions(
            bundled, bundled);
    CHECK(bundled_fallback == bundled);
}

TEST_CASE(
    "catalog setup preview and apply commit one authoritative candidate") {
    constexpr int api_port = 18471;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(original));

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    std::size_t provider_calls = 0;
    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [&provider_calls] {
            ++provider_calls;
            return catalog_snapshot();
        },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);
    CHECK(preview.at("base_revision").get<std::string>().size() == 64U);
    CHECK(
        preview.at("candidate_revision")
                .get<std::string>()
                .size() == 64U);
    CHECK(preview.at("requires_warning_acceptance") == false);
    CHECK(
        preview.at("summary")
                .at("lists")
                .at(0)
                .at("has_inline_cidrs") == true);

    const auto apply_response = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    server.stop();

    REQUIRE(apply_response != nullptr);
    REQUIRE(apply_response->status == 200);
    const auto response =
        nlohmann::json::parse(apply_response->body);
    CHECK(response.at("saved") == true);
    CHECK(response.at("applied") == true);
    CHECK(apply_calls == 1U);
    CHECK(provider_calls == 2U);
    CHECK_FALSE(store.visible_snapshot().is_draft);

    const auto persisted = parse_and_validate_config(
        read_text(config_path));
    REQUIRE(persisted.lists.has_value());
    const auto& list = persisted.lists->at("category_ai");
    CHECK(list.display_name == "AI-сервисы");
    REQUIRE(list.catalog_identity.has_value());
    CHECK(list.catalog_identity->size() == 64U);
    CHECK(
        list.url ==
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs");
    CHECK(
        list.ip_cidrs ==
        std::vector<std::string>{"203.0.113.0/24"});
    REQUIRE(persisted.route->rules.has_value());
    CHECK(
        persisted.route->rules->front().display_name ==
        "AI через прокси");
    REQUIRE(persisted.dns->rules.has_value());
    CHECK(
        persisted.dns->rules->front().display_name ==
        "DNS для AI");
}

TEST_CASE(
    "catalog setup reuses a legacy list and applies missing route and DNS policies") {
    constexpr int api_port = 18479;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    auto initial = catalog_base_config();
    ListConfig legacy;
    legacy.display_name = "Existing AI";
    legacy.url =
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs";
    initial.lists = std::map<std::string, ListConfig>{
        {"existing_ai", std::move(legacy)}};
    validate_config(initial);
    write_text(
        config_path,
        serialize_config_for_persistence(initial));

    ConfigStore store(initial);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);
    const auto& summary = preview.at("summary");
    CHECK(
        summary.at("lists").at(0).at("already_installed") ==
        true);
    CHECK(
        summary.at("lists").at(0).at("technical_id") ==
        "existing_ai");
    REQUIRE(summary.contains("route_rule"));
    REQUIRE(summary.contains("dns_rule"));

    const auto apply_response = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    server.stop();

    REQUIRE(apply_response != nullptr);
    CHECK(apply_response->status == 200);
    CHECK(apply_calls == 1U);
    REQUIRE(store.active_config().lists.has_value());
    CHECK(store.active_config().lists->size() == 1U);
    REQUIRE(store.active_config().route->rules.has_value());
    REQUIRE(store.active_config().route->rules->size() == 1U);
    REQUIRE(
        store.active_config().route->rules->front().list.has_value());
    CHECK(
        *store.active_config().route->rules->front().list ==
        std::vector<std::string>{"existing_ai"});
    REQUIRE(store.active_config().dns->rules.has_value());
    REQUIRE(store.active_config().dns->rules->size() == 1U);
    CHECK(
        store.active_config().dns->rules->front().list ==
        std::vector<std::string>{"existing_ai"});
}

TEST_CASE(
    "catalog setup reports an installed preset and refuses a duplicate no-op apply") {
    constexpr int api_port = 18480;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto initial = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(initial));

    ConfigStore store(initial);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto first_preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(first_preview_response != nullptr);
    REQUIRE(first_preview_response->status == 200);
    const auto first_preview =
        nlohmann::json::parse(first_preview_response->body);
    const auto first_apply = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, first_preview, false).dump(),
        "application/json");
    REQUIRE(first_apply != nullptr);
    REQUIRE(first_apply->status == 200);

    const auto duplicate_preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(duplicate_preview_response != nullptr);
    REQUIRE(duplicate_preview_response->status == 200);
    const auto duplicate_preview =
        nlohmann::json::parse(duplicate_preview_response->body);
    const auto& summary = duplicate_preview.at("summary");
    REQUIRE(summary.at("lists").size() == 1U);
    CHECK(
        summary.at("lists").at(0).at("already_installed") ==
        true);
    CHECK_FALSE(summary.contains("route_rule"));
    CHECK_FALSE(summary.contains("dns_rule"));

    const auto duplicate_apply = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, duplicate_preview, false).dump(),
        "application/json");
    server.stop();

    REQUIRE(duplicate_apply != nullptr);
    CHECK(duplicate_apply->status == 409);
    CHECK(
        nlohmann::json::parse(duplicate_apply->body).at("reason") ==
        "already_installed");
    CHECK(apply_calls == 1U);
    REQUIRE(store.active_config().lists.has_value());
    CHECK(store.active_config().lists->size() == 1U);
    REQUIRE(store.active_config().route->rules.has_value());
    CHECK(store.active_config().route->rules->size() == 1U);
    REQUIRE(store.active_config().dns->rules.has_value());
    CHECK(store.active_config().dns->rules->size() == 1U);
}

TEST_CASE(
    "parallel catalog applies serialize and create one preset only") {
    constexpr int api_port = 18481;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto initial = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(initial));

    ConfigStore store(initial);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    std::mutex apply_mutex;
    std::condition_variable apply_condition;
    bool first_apply_entered = false;
    bool release_first_apply = false;
    context.enqueue_apply_validated_config_fn =
        [&](Config config, std::string serialized) {
            {
                std::unique_lock<std::mutex> lock(apply_mutex);
                ++apply_calls;
                first_apply_entered = true;
                apply_condition.notify_all();
                apply_condition.wait(
                    lock, [&] { return release_first_apply; });
            }
            auto marks = allocate_outbound_marks(
                config.fwmark.value_or(FwmarkConfig{}),
                config.outbounds.value_or(
                    std::vector<Outbound>{}));
            store.replace_active(
                std::move(config), std::move(marks));
            store.clear_staged_if_matches(serialized);
            ConfigApplyResult result;
            result.applied = true;
            return result;
        };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);
    const auto request =
        apply_request(intent, preview, false).dump();

    int first_status = -1;
    std::thread first([&] {
        httplib::Client first_client("127.0.0.1", api_port);
        const auto response = first_client.Post(
            "/api/setup/catalog/apply",
            request,
            "application/json");
        if (response != nullptr) first_status = response->status;
    });
    {
        std::unique_lock<std::mutex> lock(apply_mutex);
        apply_condition.wait(
            lock, [&] { return first_apply_entered; });
    }

    httplib::Client second_client("127.0.0.1", api_port);
    const auto second = second_client.Post(
        "/api/setup/catalog/apply",
        request,
        "application/json");
    REQUIRE(second != nullptr);
    CHECK(second->status == 409);
    CHECK(
        nlohmann::json::parse(second->body).at("reason") ==
        "config_operation_in_progress");

    {
        std::lock_guard<std::mutex> lock(apply_mutex);
        release_first_apply = true;
    }
    apply_condition.notify_all();
    first.join();
    server.stop();

    CHECK(first_status == 200);
    CHECK(apply_calls == 1U);
    REQUIRE(store.active_config().lists.has_value());
    CHECK(store.active_config().lists->size() == 1U);
    REQUIRE(store.active_config().route->rules.has_value());
    CHECK(store.active_config().route->rules->size() == 1U);
    REQUIRE(store.active_config().dns->rules.has_value());
    CHECK(store.active_config().dns->rules->size() == 1U);
}

TEST_CASE(
    "catalog setup rejects an existing draft without committing it") {
    constexpr int api_port = 18472;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    const auto original_serialized =
        serialize_config_for_persistence(original);
    write_text(config_path, original_serialized);

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);

    auto draft = original;
    draft.daemon->cache_dir = "/tmp/unrelated-user-draft";
    store.stage_config(
        draft, serialize_config_for_persistence(draft));
    const auto apply_response = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    REQUIRE(apply_response != nullptr);
    CHECK(apply_response->status == 409);
    CHECK(
        nlohmann::json::parse(apply_response->body).at("reason") ==
        "draft_present");

    const auto preview_with_draft_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    server.stop();

    REQUIRE(preview_with_draft_response != nullptr);
    CHECK(preview_with_draft_response->status == 409);
    CHECK(
        nlohmann::json::parse(
            preview_with_draft_response->body)
                .at("reason") ==
        "draft_present");
    CHECK(apply_calls == 0U);
    CHECK(read_text(config_path) == original_serialized);
    CHECK(store.visible_snapshot().is_draft);
    CHECK(
        store.visible_config().daemon->cache_dir ==
        "/tmp/unrelated-user-draft");
}

TEST_CASE(
    "catalog warnings require acceptance and can be retried without a hidden draft") {
    constexpr int api_port = 18473;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(original));

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent =
        catalog_intent(std::string{"missing-outbound"});
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);
    CHECK(preview.at("requires_warning_acceptance") == true);

    const auto refused = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    REQUIRE(refused != nullptr);
    CHECK(refused->status == 409);
    CHECK_FALSE(store.visible_snapshot().is_draft);
    CHECK(apply_calls == 0U);

    const auto accepted = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, true).dump(),
        "application/json");
    server.stop();

    REQUIRE(accepted != nullptr);
    CHECK(accepted->status == 200);
    CHECK(apply_calls == 1U);
    CHECK_FALSE(store.visible_snapshot().is_draft);
}

TEST_CASE(
    "catalog commit failure restores disk and leaves no invisible draft") {
    constexpr int api_port = 18474;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    const auto original_serialized =
        serialize_config_for_persistence(original);
    write_text(config_path, original_serialized);

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ConfigSaveTestOptions options;
    options.fault_injector =
        [](ConfigSaveFaultStage stage) {
            if (stage == ConfigSaveFaultStage::config_written) {
                throw std::runtime_error(
                    "injected catalog commit failure");
            }
        };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory,
        std::move(options));
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);
    const auto response = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(read_text(config_path) == original_serialized);
    CHECK(apply_calls == 0U);
    CHECK_FALSE(store.visible_snapshot().is_draft);
    CHECK(
        nlohmann::json(store.active_config()) ==
        nlohmann::json(original));
}

TEST_CASE(
    "ordinary staging cannot race a catalog commit and works after it") {
    constexpr int api_port = 18475;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(original));

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    std::mutex provider_mutex;
    std::condition_variable provider_condition;
    std::size_t provider_calls = 0;
    bool apply_is_planning = false;
    bool allow_apply_to_continue = false;
    const auto provider = [&]() {
        std::unique_lock<std::mutex> lock(provider_mutex);
        ++provider_calls;
        if (provider_calls == 2U) {
            apply_is_planning = true;
            provider_condition.notify_all();
            provider_condition.wait(
                lock,
                [&] { return allow_apply_to_continue; });
        }
        return catalog_snapshot();
    };

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
    register_catalog_test_handler(
        server, context, provider, directory);
    server.start();

    httplib::Client preview_client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = preview_client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);

    int apply_status = -1;
    std::string apply_body;
    std::thread apply_thread([&] {
        httplib::Client client("127.0.0.1", api_port);
        const auto response = client.Post(
            "/api/setup/catalog/apply",
            apply_request(intent, preview, false).dump(),
            "application/json");
        if (response != nullptr) {
            apply_status = response->status;
            apply_body = response->body;
        }
    });
    {
        std::unique_lock<std::mutex> lock(provider_mutex);
        provider_condition.wait(
            lock, [&] { return apply_is_planning; });
    }

    auto competing = original;
    competing.daemon->cache_dir = "/tmp/competing-draft";
    httplib::Client competing_client("127.0.0.1", api_port);
    const auto blocked = competing_client.Post(
        "/api/config",
        nlohmann::json(competing).dump(),
        "application/json");
    REQUIRE(blocked != nullptr);
    CHECK(blocked->status == 409);
    CHECK_FALSE(store.visible_snapshot().is_draft);

    {
        std::lock_guard<std::mutex> lock(provider_mutex);
        allow_apply_to_continue = true;
    }
    provider_condition.notify_all();
    apply_thread.join();
    CHECK(apply_status == 200);
    CHECK_FALSE(apply_body.empty());
    CHECK(apply_calls == 1U);
    CHECK_FALSE(store.visible_snapshot().is_draft);

    auto later = store.active_config();
    later.daemon->cache_dir = "/tmp/later-draft";
    const auto staged_later = competing_client.Post(
        "/api/config",
        nlohmann::json(later).dump(),
        "application/json");
    server.stop();

    REQUIRE(staged_later != nullptr);
    CHECK(staged_later->status == 200);
    CHECK(store.visible_snapshot().is_draft);
    CHECK(
        store.visible_config().daemon->cache_dir ==
        "/tmp/later-draft");
}

TEST_CASE(
    "catalog apply rejects a preview after active config reload") {
    constexpr int api_port = 18476;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(original));

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [] { return catalog_snapshot(); },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);

    auto reloaded = original;
    reloaded.daemon->cache_dir =
        "/tmp/config-reloaded-after-preview";
    const auto reloaded_serialized =
        serialize_config_for_persistence(reloaded);
    write_text(config_path, reloaded_serialized);
    store.replace_active(
        reloaded,
        allocate_outbound_marks(
            reloaded.fwmark.value_or(FwmarkConfig{}),
            reloaded.outbounds.value_or(
                std::vector<Outbound>{})));

    const auto apply_response = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    server.stop();

    REQUIRE(apply_response != nullptr);
    CHECK(apply_response->status == 409);
    const auto error =
        nlohmann::json::parse(apply_response->body);
    CHECK(error.at("reason") == "base_revision_mismatch");
    CHECK(
        error.at("current_base_revision") !=
        preview.at("base_revision"));
    CHECK(apply_calls == 0U);
    CHECK(read_text(config_path) == reloaded_serialized);
    CHECK_FALSE(store.visible_snapshot().is_draft);
    CHECK(
        store.active_config().daemon->cache_dir ==
        "/tmp/config-reloaded-after-preview");
}

TEST_CASE(
    "catalog apply rejects a preview after authoritative preset changes") {
    constexpr int api_port = 18477;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    const auto original_serialized =
        serialize_config_for_persistence(original);
    write_text(config_path, original_serialized);

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    std::size_t catalog_reads = 0;
    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_catalog_test_handler(
        server,
        context,
        [&catalog_reads] {
            ++catalog_reads;
            return catalog_snapshot(
                catalog_reads == 1U
                    ? "https://repo.hoaxisr.ru/rulesets/srs/ai.srs"
                    : "https://repo.hoaxisr.ru/rulesets/srs/ai-v2.srs");
        },
        directory);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto intent = catalog_intent();
    const auto preview_response = client.Post(
        "/api/setup/catalog/preview",
        nlohmann::json{{"intent", intent}}.dump(),
        "application/json");
    REQUIRE(preview_response != nullptr);
    REQUIRE(preview_response->status == 200);
    const auto preview =
        nlohmann::json::parse(preview_response->body);

    const auto apply_response = client.Post(
        "/api/setup/catalog/apply",
        apply_request(intent, preview, false).dump(),
        "application/json");
    server.stop();

    REQUIRE(apply_response != nullptr);
    CHECK(apply_response->status == 409);
    const auto error =
        nlohmann::json::parse(apply_response->body);
    CHECK(error.at("reason") == "candidate_revision_mismatch");
    CHECK(
        error.at("current_candidate_revision") !=
        preview.at("candidate_revision"));
    CHECK(catalog_reads == 2U);
    CHECK(apply_calls == 0U);
    CHECK(read_text(config_path) == original_serialized);
    CHECK_FALSE(store.visible_snapshot().is_draft);
}

TEST_CASE(
    "ordinary config save preserves a reloaded active config when draft is stale") {
    constexpr int api_port = 18478;
    CatalogSetupTempDir directory;
    const auto config_path = directory.path / "config.json";
    const auto original = catalog_base_config();
    write_text(
        config_path,
        serialize_config_for_persistence(original));

    ConfigStore store(original);
    SseBroadcaster broadcaster;
    ConfigOperationGate operation_gate;
    std::size_t apply_calls = 0;
    std::size_t writer_calls = 0;
    auto context = make_catalog_context(
        config_path.string(),
        broadcaster,
        store,
        operation_gate,
        apply_calls);

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_config_handler_for_test(
        server,
        context,
        [&writer_calls](
            const std::string& path,
            const std::string& body) {
            ++writer_calls;
            write_config_atomically(path, body);
        });
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    auto draft = original;
    draft.daemon->cache_dir = "/tmp/stale-draft";
    const auto stage_response = client.Post(
        "/api/config",
        nlohmann::json(draft).dump(),
        "application/json");
    REQUIRE(stage_response != nullptr);
    REQUIRE(stage_response->status == 200);
    REQUIRE(store.visible_snapshot().is_draft);
    const auto visible_response = client.Get("/api/config");
    REQUIRE(visible_response != nullptr);
    REQUIRE(visible_response->status == 200);
    const auto visible =
        nlohmann::json::parse(visible_response->body);
    CHECK(visible.at("is_draft") == true);
    CHECK(
        visible.at("config")
            .at("daemon")
            .at("cache_dir") ==
        "/tmp/stale-draft");

    auto reloaded = original;
    reloaded.daemon->cache_dir = "/tmp/reloaded-active";
    const auto reloaded_serialized =
        serialize_config_for_persistence(reloaded);
    write_text(config_path, reloaded_serialized);
    store.replace_active(
        reloaded,
        allocate_outbound_marks(
            reloaded.fwmark.value_or(FwmarkConfig{}),
            reloaded.outbounds.value_or(
                std::vector<Outbound>{})));

    const auto save_response = client.Post(
        "/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(save_response != nullptr);
    CHECK(save_response->status == 409);
    const auto error =
        nlohmann::json::parse(save_response->body);
    CHECK(
        error.at("reason") ==
        "draft_base_revision_mismatch");
    CHECK(error.at("draft_preserved") == true);
    CHECK(error.at("base_revision") != error.at("active_revision"));
    CHECK(writer_calls == 0U);
    CHECK(apply_calls == 0U);
    CHECK(read_text(config_path) == reloaded_serialized);
    CHECK(
        store.active_config().daemon->cache_dir ==
        "/tmp/reloaded-active");
    CHECK(store.visible_snapshot().is_draft);
    CHECK(
        store.visible_config().daemon->cache_dir ==
        "/tmp/stale-draft");
}

} // namespace keen_pbr3

#endif // WITH_API
