#include <doctest/doctest.h>

#include "../src/setup/catalog_setup_planner.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace keen_pbr3;
using namespace keen_pbr3::setup;

namespace {

Config base_config() {
    Config config;

    Outbound proxy;
    proxy.tag = "proxy";
    proxy.type = OutboundType::INTERFACE;
    proxy.interface = "tun0";
    Outbound backup;
    backup.tag = "backup";
    backup.type = OutboundType::TABLE;
    backup.table = 123;
    Outbound direct;
    direct.tag = "wan";
    direct.type = OutboundType::TABLE;
    direct.table = 254;
    config.outbounds = std::vector<Outbound>{proxy, backup, direct};

    DnsServer proxy_dns;
    proxy_dns.tag = "proxy_dns";
    proxy_dns.address = "1.1.1.1";
    proxy_dns.detour = "proxy";
    DnsServer direct_dns;
    direct_dns.tag = "direct_dns";
    direct_dns.address = "9.9.9.9";
    config.dns = DnsConfig{};
    config.dns->servers =
        std::vector<DnsServer>{proxy_dns, direct_dns};
    config.dns->fallback = std::vector<std::string>{"direct_dns"};
    api::SystemResolver resolver;
    resolver.address = "127.0.0.1";
    config.dns->system_resolver = resolver;
    config.dns->rules = std::vector<DnsRule>{};
    config.route = RouteConfig{};
    config.route->rules = std::vector<RouteRule>{};
    validate_config(config);
    return config;
}

nlohmann::json routing_preset(
    std::string id = "category-ai",
    std::string name = "Нейросети",
    std::string url =
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs") {
    return {
        {"id", std::move(id)},
        {"name", std::move(name)},
        {"engines",
         {
             {"dns",
              {{"domains",
                {"chatgpt.com", "oaistatic.com", "oaiusercontent.com"}}}},
             {"singbox",
              {
                  {"action", "tunnel"},
                  {"ruleSets",
                   {{{"tag", "geosite-ai"},
                     {"url", std::move(url)}}}},
              }},
         }},
    };
}

nlohmann::json blocking_preset() {
    return {
        {"id", "ads"},
        {"name", "Реклама"},
        {"engines",
         {{"singbox",
           {
               {"action", "reject"},
               {"ruleSets",
                {{{"url",
                   "https://repo.hoaxisr.ru/rulesets/srs/ads.srs"}}}},
           }}}},
    };
}

const std::vector<std::string>& whatsapp_domains() {
    static const std::vector<std::string> domains{
        "whatsapp.com",
        "whatsapp.net",
    };
    return domains;
}

const std::vector<std::string>& whatsapp_ipv4_cidrs() {
    static const std::vector<std::string> cidrs{
        "31.13.24.0/21",
        "31.13.64.0/18",
        "45.64.40.0/22",
        "57.141.0.0/21",
        "57.141.8.0/24",
        "57.141.10.0/24",
        "57.141.12.0/23",
        "57.141.14.0/24",
        "57.141.16.0/22",
        "57.141.20.0/24",
        "57.141.22.0/24",
        "57.141.24.0/24",
        "57.144.0.0/14",
        "66.220.144.0/20",
        "69.63.176.0/20",
        "69.171.224.0/19",
        "74.119.76.0/22",
        "102.132.96.0/20",
        "103.4.96.0/22",
        "129.134.0.0/16",
        "147.75.208.0/20",
        "157.240.0.0/16",
        "163.70.128.0/17",
        "163.77.128.0/17",
        "173.252.64.0/18",
        "179.60.192.0/22",
        "185.60.216.0/22",
        "185.89.216.0/22",
        "189.247.71.0/24",
        "204.15.20.0/22",
    };
    return cidrs;
}

nlohmann::json whatsapp_preset() {
    return {
        {"id", "whatsapp"},
        {"name", "WhatsApp"},
        {"routingCompanions",
         {{{"id", "whatsapp_ip"},
           {"name", "WhatsApp IP"},
           {"sourcePresetId", "whatsapp-ip-source"},
           {"include", "ip_cidrs"},
           {"catalogIdentityId",
            "meta#routing-companion:meta_whatsapp_ip"},
           {"suppressDirectSelection", true}}}},
        {"engines",
         {
             {"dns",
              {
                  {"domains", whatsapp_domains()},
              }},
             {"singbox",
              {
                  {"action", "tunnel"},
                  {"ruleSets",
                   {{{"tag", "geosite-whatsapp"},
                     {"url",
                      "https://repo.hoaxisr.ru/rulesets/srs/whatsapp.srs"}}}},
              }},
         }},
    };
}

nlohmann::json whatsapp_ip_source_preset() {
    return {
        {"id", "whatsapp-ip-source"},
        {"name", "WhatsApp IP source"},
        {"hidden", true},
        {"engines",
         {{"dns", {{"subnets", whatsapp_ipv4_cidrs()}}}}},
    };
}

nlohmann::json meta_preset() {
    return {
        {"id", "meta"},
        {"name", "Meta (все сервисы)"},
        {"covers", {"whatsapp"}},
        {"routingCompanions",
         {{{"id", "meta_whatsapp_ip"},
           {"name", "Meta / WhatsApp IP"},
           {"sourcePresetId", "whatsapp-ip-source"},
           {"include", "ip_cidrs"},
           {"suppressDirectSelection", true}}}},
        {"engines",
         {{"singbox",
           {
               {"action", "tunnel"},
               {"ruleSets",
                {{{"tag", "geosite-meta"},
                  {"url",
                   "https://raw.githubusercontent.com/SagerNet/sing-geosite/"
                   "rule-set/geosite-meta.srs"}}}},
           }}}},
    };
}

nlohmann::json telegram_preset() {
    return {
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
         {
             {"dns", {{"domains", {"t.me", "telegram.org"}}}},
             {"singbox",
              {
                  {"action", "tunnel"},
                  {"ruleSets",
                   {{{"tag", "geosite-telegram"},
                     {"url",
                      "https://repo.hoaxisr.ru/rulesets/srs/"
                      "telegram.srs"}}}},
              }},
         }},
    };
}

const std::vector<std::string>& kinopub_core_domains() {
    static const std::vector<std::string> domains{
        "ahc.ovh",
        "alador.space",
        "api.ios-kp.store",
        "api.service-kp.com",
        "api.srvkp.com",
        "cdn-service.space",
        "firebaseremoteconfigrealtime.googleapis.com",
        "gfw.ovh",
        "gravatar.com",
        "i0.wp.com",
        "kino.pub",
        "kino.watch",
        "kinopub.online",
        "kp-apps.xyz",
        "kpapp.link",
        "kpdl.cc",
        "kpdl.link",
        "m.boraboraboom.ru",
        "media.service-kp.com",
        "mos-gorsud.co",
        "mos-gorsud.site",
        "prod-lt-playstoregatewayadapter-pa.googleapis.com",
        "proxykp.xyz",
        "pushbr.com",
        "smarttv.zeasn.tv",
        "support-kp.com",
        "themoviedb.org",
        "tmdb.org",
        "tsx.ovh",
    };
    return domains;
}

nlohmann::json kinopub_full_preset() {
    return {
        {"id", "kinopub"},
        {"name", "Kino.pub"},
        {"covers", {"kinopub-core"}},
        {"engines",
         {
             {"dns", {{"domains", {"kino.pub", "kino.watch"}}}},
             {"singbox",
              {
                  {"action", "tunnel"},
                  {"ruleSets",
                   {{{"tag", "geosite-kinopub"},
                     {"url",
                      "https://raw.githubusercontent.com/SagerNet/"
                      "sing-geosite/rule-set/geosite-kinopub.srs"}}}},
              }},
         }},
    };
}

nlohmann::json kinopub_core_preset() {
    return {
        {"id", "kinopub-core"},
        {"name", "Kino.pub (без CDN)"},
        {"engines",
         {{"dns",
           {{"domains", kinopub_core_domains()}}}}},
    };
}

CatalogSetupIntent outbound_intent() {
    CatalogSetupIntent intent;
    intent.selections = {{"category-ai", std::nullopt}};
    intent.mode = CatalogSetupMode::outbound;
    intent.outbound_tag = "proxy";
    intent.dns_mode = CatalogDnsMode::automatic;
    intent.source_detour_tag = "proxy";
    return intent;
}

CatalogSetupIntent meta_outbound_intent() {
    auto intent = outbound_intent();
    intent.selections = {{"meta", std::nullopt}};
    return intent;
}

const CatalogSetupWarning* warning(
    const CatalogSetupPlan& plan,
    CatalogSetupWarningCode code) {
    for (const auto& candidate : plan.warnings) {
        if (candidate.code == code) return &candidate;
    }
    return nullptr;
}

} // namespace

TEST_CASE("catalog planner preserves URL and inline domains") {
    const auto plan = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        base_config());

    REQUIRE(plan.candidate.lists.has_value());
    const auto& list = plan.candidate.lists->at("category_ai");
    CHECK(
        list.url ==
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs");
    CHECK(
        list.domains ==
        std::vector<std::string>{
            "chatgpt.com", "oaistatic.com", "oaiusercontent.com"});
    CHECK(list.detour == "proxy");
    CHECK(list.display_name == "Нейросети");

    REQUIRE(plan.summary.lists.size() == 1U);
    CHECK(plan.summary.lists[0].technical_id == "category_ai");
    CHECK(plan.summary.lists[0].display_name == "Нейросети");
    CHECK(plan.summary.lists[0].url_backed);
    CHECK(plan.summary.lists[0].has_inline_domains);
    CHECK_FALSE(plan.summary.lists[0].has_inline_cidrs);
    CHECK(plan.summary.lists[0].source_detour == "proxy");
    REQUIRE(plan.summary.route_rule.has_value());
    CHECK(plan.summary.route_rule->display_name == "Нейросети");
    REQUIRE(plan.summary.dns_rule.has_value());
    CHECK(plan.summary.dns_rule->server == "proxy_dns");
    REQUIRE(plan.summary.dns_server.has_value());
    CHECK(plan.summary.dns_server->technical_id == "proxy_dns");
    CHECK(plan.summary.dns_server->address == "1.1.1.1");
    CHECK(plan.summary.dns_server->detour == "proxy");
    CHECK_FALSE(plan.summary.dns_server->created);
    CHECK(plan.warnings.empty());
    CHECK(plan.candidate_revision.size() == 64U);
    CHECK_NOTHROW(validate_config(plan.candidate));
    CHECK_NOTHROW(validate_recommended_list_setup(
        plan.candidate, "category_ai"));
}

TEST_CASE("KinoPub full variant remains URL backed") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:kinopub-variants"},
        {"presets",
         nlohmann::json::array(
             {kinopub_full_preset(), kinopub_core_preset()})},
    };

    auto full_intent = outbound_intent();
    full_intent.selections = {{"kinopub", std::nullopt}};
    const auto full = plan_catalog_setup(
        full_intent, catalog, base_config());
    REQUIRE(full.candidate.lists.has_value());
    REQUIRE(full.candidate.lists->size() == 1U);
    REQUIRE(full.candidate.lists->count("kinopub") == 1U);
    const auto& full_list = full.candidate.lists->at("kinopub");
    CHECK(
        full_list.url ==
        "https://raw.githubusercontent.com/SagerNet/"
        "sing-geosite/rule-set/geosite-kinopub.srs");
    CHECK(full_list.domains.has_value());
    REQUIRE(full.summary.lists.size() == 1U);
    CHECK(full.summary.lists.front().url_backed);
}

TEST_CASE("KinoPub no-CDN variant keeps lightweight dependencies inline") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:kinopub-variants"},
        {"presets",
         nlohmann::json::array(
             {kinopub_full_preset(), kinopub_core_preset()})},
    };

    auto core_intent = outbound_intent();
    core_intent.selections = {{"kinopub-core", std::nullopt}};
    const auto core = plan_catalog_setup(
        core_intent, catalog, base_config());
    REQUIRE(core.candidate.lists.has_value());
    REQUIRE(core.candidate.lists->size() == 1U);
    const auto& core_list = core.candidate.lists->at("kinopub_core");
    CHECK_FALSE(core_list.url.has_value());
    CHECK(
        core_list.domains ==
        std::optional<std::vector<std::string>>{
            kinopub_core_domains()});
    REQUIRE(core.summary.lists.size() == 1U);
    CHECK(core.summary.lists[0].technical_id == "kinopub_core");
    CHECK_FALSE(core.summary.lists[0].url_backed);
}

TEST_CASE(
    "Meta uses a URL primary and an IP-only routing companion") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:meta-companion"},
        {"presets",
         nlohmann::json::array(
             {meta_preset(),
              whatsapp_preset(),
              whatsapp_ip_source_preset()})},
    };
    const auto plan = plan_catalog_setup(
        meta_outbound_intent(),
        catalog,
        base_config());

    REQUIRE(plan.candidate.lists.has_value());
    REQUIRE(plan.candidate.lists->size() == 2U);
    const auto& primary = plan.candidate.lists->at("meta");
    const auto& companion =
        plan.candidate.lists->at("meta_whatsapp_ip");
    CHECK(
        primary.url ==
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/"
        "rule-set/geosite-meta.srs");
    CHECK_FALSE(primary.domains.has_value());
    CHECK_FALSE(primary.ip_cidrs.has_value());
    CHECK(primary.detour == "proxy");
    CHECK_FALSE(companion.url.has_value());
    CHECK_FALSE(companion.domains.has_value());
    REQUIRE(companion.ip_cidrs.has_value());
    CHECK(companion.ip_cidrs->size() == 30U);
    CHECK(*companion.ip_cidrs == whatsapp_ipv4_cidrs());
    CHECK_FALSE(companion.detour.has_value());
    REQUIRE(primary.catalog_identity.has_value());
    REQUIRE(companion.catalog_identity.has_value());
    CHECK(primary.catalog_identity != companion.catalog_identity);

    REQUIRE(plan.summary.lists.size() == 2U);
    CHECK(plan.summary.lists[0].preset_id == "meta");
    CHECK(plan.summary.lists[0].technical_id == "meta");
    CHECK(plan.summary.lists[0].url_backed);
    CHECK_FALSE(plan.summary.lists[0].has_inline_domains);
    CHECK_FALSE(plan.summary.lists[0].has_inline_cidrs);
    CHECK(plan.summary.lists[1].preset_id == "meta_whatsapp_ip");
    CHECK(plan.summary.lists[1].technical_id == "meta_whatsapp_ip");
    CHECK_FALSE(plan.summary.lists[1].url_backed);
    CHECK_FALSE(plan.summary.lists[1].has_inline_domains);
    CHECK(plan.summary.lists[1].has_inline_cidrs);

    REQUIRE(plan.summary.route_rules.size() == 2U);
    for (const auto& summary : plan.summary.route_rules) {
        const auto& rule =
            plan.candidate.route->rules->at(summary.insertion_index);
        CHECK(rule.outbound == "proxy");
        REQUIRE(rule.list.has_value());
        CHECK(rule.list->size() == 1U);
    }
    REQUIRE(plan.summary.dns_rules.size() == 1U);
    const auto& dns_rule =
        plan.candidate.dns->rules->at(
            plan.summary.dns_rules.front().insertion_index);
    CHECK(dns_rule.list == std::vector<std::string>{"meta"});
    CHECK(dns_rule.server == "proxy_dns");
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE(
    "Telegram uses separate domain and URL-backed IP lists") {
    auto intent = outbound_intent();
    intent.selections = {{"telegram", std::nullopt}};
    const nlohmann::json catalog = {
        {"catalog_id", "test:telegram-companion"},
        {"presets", nlohmann::json::array({telegram_preset()})},
    };
    const auto plan = plan_catalog_setup(
        intent, catalog, base_config());

    REQUIRE(plan.candidate.lists.has_value());
    const auto& primary = plan.candidate.lists->at("telegram");
    const auto& companion = plan.candidate.lists->at("telegram_ip");
    CHECK(
        primary.url ==
        "https://repo.hoaxisr.ru/rulesets/srs/telegram.srs");
    CHECK(
        primary.domains ==
        std::optional<std::vector<std::string>>{
            {"t.me", "telegram.org"}});
    CHECK_FALSE(primary.ip_cidrs.has_value());
    CHECK(
        companion.url ==
        "https://raw.githubusercontent.com/runetfreedom/"
        "russia-v2ray-rules-dat/release/sing-box/"
        "rule-set-geoip/geoip-telegram.srs");
    CHECK_FALSE(companion.domains.has_value());
    CHECK_FALSE(companion.ip_cidrs.has_value());
    CHECK(primary.detour == "proxy");
    CHECK(companion.detour == "proxy");

    REQUIRE(plan.summary.route_rules.size() == 2U);
    REQUIRE(plan.summary.dns_rules.size() == 1U);
    const auto& dns_rule =
        plan.candidate.dns->rules->at(
            plan.summary.dns_rules.front().insertion_index);
    CHECK(dns_rule.list == std::vector<std::string>{"telegram"});
}

TEST_CASE(
    "existing Meta primary receives its missing routing companion") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:meta-companion-upgrade"},
        {"presets",
         nlohmann::json::array(
             {meta_preset(),
              whatsapp_preset(),
              whatsapp_ip_source_preset()})},
    };
    const auto initial = plan_catalog_setup(
        meta_outbound_intent(), catalog, base_config());
    auto old_install = initial.candidate;
    REQUIRE(old_install.lists.has_value());
    old_install.lists->erase("meta_whatsapp_ip");
    REQUIRE(old_install.route.has_value());
    REQUIRE(old_install.route->rules.has_value());
    auto& route_rules = *old_install.route->rules;
    route_rules.erase(
        std::remove_if(
            route_rules.begin(),
            route_rules.end(),
            [](const RouteRule& rule) {
                return rule.list ==
                    std::optional<std::vector<std::string>>{
                        {"meta_whatsapp_ip"}};
            }),
        route_rules.end());
    validate_config(old_install);

    const auto upgraded = plan_catalog_setup(
        meta_outbound_intent(), catalog, old_install);
    REQUIRE(upgraded.summary.lists.size() == 2U);
    CHECK(upgraded.summary.lists[0].already_installed);
    CHECK_FALSE(upgraded.summary.lists[1].already_installed);
    CHECK(upgraded.summary.lists[0].technical_id == "meta");
    CHECK(
        upgraded.summary.lists[1].technical_id ==
        "meta_whatsapp_ip");
    REQUIRE(upgraded.summary.route_rules.size() == 1U);
    CHECK(upgraded.summary.dns_rules.empty());
    CHECK(
        upgraded.candidate.lists->at("meta").url ==
        old_install.lists->at("meta").url);
    REQUIRE(
        upgraded.candidate.lists
            ->at("meta_whatsapp_ip")
            .ip_cidrs.has_value());

    const auto repeated = plan_catalog_setup(
        meta_outbound_intent(), catalog, upgraded.candidate);
    REQUIRE(repeated.summary.lists.size() == 2U);
    CHECK(repeated.summary.lists[0].already_installed);
    CHECK(repeated.summary.lists[1].already_installed);
    CHECK(repeated.summary.route_rules.empty());
    CHECK(repeated.summary.dns_rules.empty());
    CHECK(
        nlohmann::json(repeated.candidate) ==
        nlohmann::json(upgraded.candidate));
}

TEST_CASE(
    "managed Telegram primary drops stale inline CIDRs during companion migration") {
    auto intent = outbound_intent();
    intent.selections = {{"telegram", std::nullopt}};
    const nlohmann::json catalog = {
        {"catalog_id", "test:telegram-companion-migration"},
        {"presets", nlohmann::json::array({telegram_preset()})},
    };
    const auto installed =
        plan_catalog_setup(intent, catalog, base_config());
    auto legacy = installed.candidate;
    REQUIRE(legacy.lists.has_value());
    legacy.lists->at("telegram").ip_cidrs =
        std::vector<std::string>{
            "91.108.4.0/22",
            "149.154.160.0/20",
        };
    validate_config(legacy);

    const auto reconciled =
        plan_catalog_setup(intent, catalog, legacy);
    REQUIRE(reconciled.summary.lists.size() == 2U);
    CHECK(reconciled.summary.lists[0].already_installed);
    CHECK(reconciled.summary.lists[1].already_installed);
    CHECK_FALSE(
        reconciled.candidate.lists
            ->at("telegram")
            .ip_cidrs.has_value());
    CHECK(
        reconciled.candidate.lists
            ->at("telegram")
            .domains ==
        std::optional<std::vector<std::string>>{
            {"t.me", "telegram.org"}});
    CHECK(reconciled.summary.route_rules.empty());
    CHECK(reconciled.summary.dns_rules.empty());

    const auto repeated =
        plan_catalog_setup(intent, catalog, reconciled.candidate);
    CHECK(
        nlohmann::json(repeated.candidate) ==
        nlohmann::json(reconciled.candidate));
    CHECK(repeated.summary.route_rules.empty());
    CHECK(repeated.summary.dns_rules.empty());
}

TEST_CASE(
    "selecting Meta with covered WhatsApp does not duplicate IP routing") {
    auto intent = meta_outbound_intent();
    intent.selections.push_back({"whatsapp", std::nullopt});
    const nlohmann::json catalog = {
        {"catalog_id", "test:meta-covered-selection"},
        {"presets",
         nlohmann::json::array(
             {meta_preset(),
              whatsapp_preset(),
              whatsapp_ip_source_preset()})},
    };

    const auto plan =
        plan_catalog_setup(intent, catalog, base_config());
    REQUIRE(plan.candidate.lists.has_value());
    REQUIRE(plan.candidate.lists->size() == 2U);
    CHECK(plan.candidate.lists->count("meta") == 1U);
    CHECK(
        plan.candidate.lists->count("meta_whatsapp_ip") ==
        1U);
    CHECK(plan.candidate.lists->count("whatsapp") == 0U);
    REQUIRE(plan.summary.route_rules.size() == 2U);
    REQUIRE(plan.summary.dns_rules.size() == 1U);
    CHECK(
        plan.candidate.dns->rules
            ->at(plan.summary.dns_rules.front().insertion_index)
            .list ==
        std::vector<std::string>{"meta"});
}

TEST_CASE(
    "WhatsApp installs the shared IP companion and Meta reuses it") {
    auto whatsapp_intent = outbound_intent();
    whatsapp_intent.selections = {{"whatsapp", std::nullopt}};
    const nlohmann::json catalog = {
        {"catalog_id", "test:shared-whatsapp-ip"},
        {"presets",
         nlohmann::json::array(
             {meta_preset(),
              whatsapp_preset(),
              whatsapp_ip_source_preset()})},
    };

    const auto whatsapp = plan_catalog_setup(
        whatsapp_intent, catalog, base_config());
    REQUIRE(whatsapp.candidate.lists.has_value());
    REQUIRE(whatsapp.candidate.lists->size() == 2U);
    CHECK(whatsapp.candidate.lists->count("whatsapp") == 1U);
    CHECK(whatsapp.candidate.lists->count("whatsapp_ip") == 1U);
    CHECK_FALSE(
        whatsapp.candidate.lists->at("whatsapp").ip_cidrs.has_value());
    CHECK(
        whatsapp.candidate.lists->at("whatsapp_ip").ip_cidrs ==
        std::optional<std::vector<std::string>>{
            whatsapp_ipv4_cidrs()});
    CHECK(
        whatsapp.candidate.lists->at("whatsapp_ip").catalog_identity ==
        catalog_preset_identity(
            catalog,
            "meta#routing-companion:meta_whatsapp_ip"));

    const auto meta = plan_catalog_setup(
        meta_outbound_intent(), catalog, whatsapp.candidate);
    REQUIRE(meta.candidate.lists.has_value());
    CHECK(meta.candidate.lists->size() == 3U);
    CHECK(meta.candidate.lists->count("meta") == 1U);
    CHECK(meta.candidate.lists->count("whatsapp_ip") == 1U);
    CHECK(meta.candidate.lists->count("meta_whatsapp_ip") == 0U);
    REQUIRE(meta.summary.lists.size() == 2U);
    CHECK_FALSE(meta.summary.lists[0].already_installed);
    CHECK(meta.summary.lists[1].already_installed);
    CHECK(meta.summary.lists[1].technical_id == "whatsapp_ip");
    REQUIRE(meta.summary.route_rules.size() == 1U);
    CHECK(
        meta.candidate.route->rules
            ->at(meta.summary.route_rules.front().insertion_index)
            .list ==
        std::vector<std::string>{"meta"});
}

TEST_CASE(
    "existing combined WhatsApp list migrates to the shared IP companion") {
    auto intent = outbound_intent();
    intent.selections = {{"whatsapp", std::nullopt}};
    const nlohmann::json catalog = {
        {"catalog_id", "test:whatsapp-split-migration"},
        {"presets",
         nlohmann::json::array(
             {whatsapp_preset(), whatsapp_ip_source_preset()})},
    };
    auto active = base_config();
    ListConfig combined;
    combined.display_name = "WhatsApp";
    combined.catalog_identity =
        catalog_preset_identity(catalog, "whatsapp");
    combined.url =
        "https://repo.hoaxisr.ru/rulesets/srs/whatsapp.srs";
    combined.domains = whatsapp_domains();
    combined.ip_cidrs = whatsapp_ipv4_cidrs();
    active.lists =
        std::map<std::string, ListConfig>{{"whatsapp", combined}};
    validate_config(active);

    const auto migrated =
        plan_catalog_setup(intent, catalog, active);
    REQUIRE(migrated.candidate.lists.has_value());
    CHECK(migrated.candidate.lists->size() == 2U);
    CHECK_FALSE(
        migrated.candidate.lists->at("whatsapp").ip_cidrs.has_value());
    CHECK(
        migrated.candidate.lists->at("whatsapp_ip").ip_cidrs ==
        std::optional<std::vector<std::string>>{
            whatsapp_ipv4_cidrs()});
    REQUIRE(migrated.summary.lists.size() == 2U);
    CHECK(migrated.summary.lists[0].already_installed);
    CHECK_FALSE(migrated.summary.lists[1].already_installed);
}

TEST_CASE(
    "catalog covers suppress selected descendants transitively") {
    auto aggregate = routing_preset("all", "All services");
    aggregate["covers"] = {"middle"};
    auto middle = routing_preset("middle", "Middle");
    middle["covers"] = {"leaf"};
    auto leaf = routing_preset("leaf", "Leaf");
    auto intent = outbound_intent();
    intent.selections = {
        {"leaf", std::nullopt},
        {"all", std::nullopt},
        {"middle", std::nullopt},
    };

    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({aggregate, middle, leaf}),
        base_config());
    REQUIRE(plan.summary.lists.size() == 1U);
    CHECK(plan.summary.lists.front().preset_id == "all");
    CHECK(plan.candidate.lists->size() == 1U);
}

TEST_CASE("catalog covers metadata is a validated DAG") {
    SUBCASE("unknown child") {
        auto parent = routing_preset("parent", "Parent");
        parent["covers"] = {"missing"};
        auto intent = outbound_intent();
        intent.selections = {{"parent", std::nullopt}};
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(
                intent,
                nlohmann::json::array({parent}),
                base_config()),
            "Catalogue preset 'parent' covers unknown preset 'missing'",
            CatalogSetupPlanError);
    }

    SUBCASE("self cover") {
        auto parent = routing_preset("parent", "Parent");
        parent["covers"] = {"parent"};
        auto intent = outbound_intent();
        intent.selections = {{"parent", std::nullopt}};
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(
                intent,
                nlohmann::json::array({parent}),
                base_config()),
            "Catalogue preset 'parent' must not cover itself",
            CatalogSetupPlanError);
    }

    SUBCASE("cycle") {
        auto first = routing_preset("first", "First");
        first["covers"] = {"second"};
        auto second = routing_preset("second", "Second");
        second["covers"] = {"first"};
        auto intent = outbound_intent();
        intent.selections = {{"first", std::nullopt}};
        CHECK_THROWS_AS(
            plan_catalog_setup(
                intent,
                nlohmann::json::array({first, second}),
                base_config()),
            CatalogSetupPlanError);
    }

    SUBCASE("duplicate edge") {
        auto parent = routing_preset("parent", "Parent");
        parent["covers"] = {"child", "child"};
        auto child = routing_preset("child", "Child");
        auto intent = outbound_intent();
        intent.selections = {{"parent", std::nullopt}};
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(
                intent,
                nlohmann::json::array({parent, child}),
                base_config()),
            "Catalogue preset 'parent' covers 'child' more than once",
            CatalogSetupPlanError);
    }
}

TEST_CASE(
    "broad traffic catalog warning requires the existing acceptance flow") {
    auto cloudflare = routing_preset("cloudflare", "Cloudflare");
    cloudflare["warnings"] = nlohmann::json::array(
        {{{"code", "broad_traffic_scope"},
          {"requiresAcceptance", true}}});
    auto intent = outbound_intent();
    intent.selections = {{"cloudflare", std::nullopt}};

    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({cloudflare}),
        base_config());
    REQUIRE(plan.warnings.size() == 1U);
    CHECK(
        plan.warnings.front().code ==
        CatalogSetupWarningCode::broad_traffic_scope);
    CHECK(plan.warnings.front().path == "catalog.presets.cloudflare");
}

TEST_CASE("routing companion metadata rejects unsafe or missing sources") {
    SUBCASE("unknown inline source") {
        auto meta = meta_preset();
        meta["routingCompanions"][0]["sourcePresetId"] = "missing";
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(
                meta_outbound_intent(),
                nlohmann::json::array(
                    {std::move(meta), whatsapp_preset()}),
                base_config()),
            "Catalogue routing companion references unknown preset 'missing'",
            CatalogSetupPlanError);
    }

    SUBCASE("URL and inline source are mutually exclusive") {
        auto meta = meta_preset();
        meta["routingCompanions"][0]["url"] =
            "https://repo.hoaxisr.ru/rulesets/srs/meta-ip.srs";
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(
                meta_outbound_intent(),
                nlohmann::json::array(
                    {std::move(meta),
                     whatsapp_preset(),
                     whatsapp_ip_source_preset()}),
                base_config()),
            "Catalogue routing companion must define exactly one of url or "
            "sourcePresetId",
            CatalogSetupPlanError);
    }
}

TEST_CASE(
    "recommended list setup rejects route-only and mismatched DNS candidates") {
    const auto planned = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        base_config());

    auto route_only = planned.candidate;
    REQUIRE(route_only.dns.has_value());
    route_only.dns->rules = std::vector<DnsRule>{};
    CHECK_THROWS_WITH(
        validate_recommended_list_setup(
            route_only, "category_ai"),
        "Beginner setup requires one dedicated DNS rule for the list");

    auto mismatched = planned.candidate;
    REQUIRE(mismatched.dns->rules.has_value());
    mismatched.dns->rules->front().server = "direct_dns";
    CHECK_THROWS_WITH(
        validate_recommended_list_setup(
            mismatched, "category_ai"),
        "Beginner setup DNS server must use the same outbound as the route; "
        "create or select a compatible DNS server");
}

TEST_CASE(
    "recommended list setup rejects a route with an extra selector") {
    const auto planned = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        base_config());

    auto candidate = planned.candidate;
    REQUIRE(candidate.route.has_value());
    REQUIRE(candidate.route->rules.has_value());
    candidate.route->rules->front().proto = "tcp";

    CHECK_THROWS_WITH(
        validate_recommended_list_setup(
            candidate, "category_ai"),
        "Beginner setup requires one dedicated route rule for the list");
}

TEST_CASE("catalog planner prefers SRS when authoritative preset also has raw subscription") {
    const nlohmann::json upstream_fixture = {
        {"id", "unavailable-in-russia"},
        {"name", "Недоступно из РФ (hoaxisr/rulesets)"},
        {"engines",
         {
             {"dns",
              {{"subscriptionUrl",
                "https://repo.hoaxisr.ru/rulesets/raw/"
                "unavailable-in-russia.txt"}}},
             {"singbox",
              {
                  {"ruleSets",
                   {{{"tag", "geosite-unavailable-in-russia"},
                     {"url",
                      "https://repo.hoaxisr.ru/rulesets/srs/"
                      "unavailable-in-russia.srs"}}}},
                  {"action", "tunnel"},
              }},
         }},
    };
    auto intent = outbound_intent();
    intent.selections = {{"unavailable-in-russia", std::nullopt}};

    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({upstream_fixture}),
        base_config());

    REQUIRE(plan.summary.lists.size() == 1U);
    const auto& list = plan.candidate.lists->at(
        plan.summary.lists.front().technical_id);
    CHECK(
        list.url ==
        "https://repo.hoaxisr.ru/rulesets/srs/"
        "unavailable-in-russia.srs");
    CHECK(list.detour == "proxy");
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE("catalog planner accepts trusted URL hosts case-insensitively") {
    const std::vector<std::string> trusted_urls = {
        "HTTPS://REPO.HOAXISR.RU./rulesets/srs/ai.srs",
        "https://RAW.GITHUBUSERCONTENT.COM./owner/repository/main/ai.srs",
    };

    for (const auto& url : trusted_urls) {
        CAPTURE(url);
        const auto plan = plan_catalog_setup(
            outbound_intent(),
            nlohmann::json::array(
                {routing_preset("category-ai", "Нейросети", url)}),
            base_config());
        REQUIRE(plan.candidate.lists.has_value());
        CHECK(plan.candidate.lists->at("category_ai").url == url);
    }
}

TEST_CASE("catalog planner rejects untrusted catalogue URLs") {
    const auto rejected = [](const std::string& url,
                             const std::string& expected) {
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(
                outbound_intent(),
                nlohmann::json::array(
                    {routing_preset(
                        "category-ai", "Нейросети", url)}),
                base_config()),
            expected.c_str(),
            CatalogSetupPlanError);
    };

    SUBCASE("plain HTTP") {
        rejected(
            "http://repo.hoaxisr.ru/rulesets/srs/ai.srs",
            "Catalogue URL must use HTTPS");
    }
    SUBCASE("loopback") {
        rejected(
            "https://127.0.0.1/private",
            "Catalogue URL host is not trusted");
    }
    SUBCASE("private address") {
        rejected(
            "https://192.168.1.1/private",
            "Catalogue URL host is not trusted");
    }
    SUBCASE("userinfo") {
        rejected(
            "https://root@repo.hoaxisr.ru/rulesets/srs/ai.srs",
            "Catalogue URL must not include userinfo");
    }
    SUBCASE("trusted-host suffix") {
        rejected(
            "https://repo.hoaxisr.ru.attacker.example/ai.srs",
            "Catalogue URL host is not trusted");
    }
}

TEST_CASE("catalog planner accepts authoritative subnet-only Cloudflare preset") {
    const std::vector<std::string> cloudflare_subnets = {
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    };
    const nlohmann::json cloudflare_fixture = {
        {"id", "cloudflare-ips"},
        {"name", "Cloudflare IPs"},
        {"engines", {{"dns", {{"subnets", cloudflare_subnets}}}}},
    };
    auto intent = outbound_intent();
    intent.selections = {{"cloudflare-ips", std::nullopt}};
    intent.source_detour_tag.reset();

    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({cloudflare_fixture}),
        base_config());

    REQUIRE(plan.summary.lists.size() == 1U);
    const auto& summary = plan.summary.lists.front();
    CHECK(summary.technical_id == "cloudflare_ips");
    CHECK_FALSE(summary.url_backed);
    CHECK_FALSE(summary.has_inline_domains);
    CHECK(summary.has_inline_cidrs);
    CHECK_FALSE(plan.summary.dns_server.has_value());
    CHECK_FALSE(plan.summary.dns_rule.has_value());
    CHECK(
        plan.candidate.lists->at("cloudflare_ips").ip_cidrs ==
        cloudflare_subnets);
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE("pure IP catalogue selection ignores explicit DNS input") {
    const nlohmann::json ip_only = {
        {"id", "service-ips"},
        {"name", "Service IPs"},
        {"engines",
         {{"dns", {{"subnets", {"203.0.113.0/24"}}}}}},
    };
    auto intent = outbound_intent();
    intent.selections = {{"service-ips", std::nullopt}};
    intent.dns_mode = CatalogDnsMode::explicit_server;
    intent.dns_server_tag = "missing_dns";
    intent.source_detour_tag.reset();

    const auto plan = plan_catalog_setup(
        intent, nlohmann::json::array({ip_only}), base_config());

    CHECK_FALSE(plan.summary.dns_server.has_value());
    CHECK_FALSE(plan.summary.dns_rule.has_value());
    REQUIRE(plan.summary.route_rule.has_value());
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE("catalog planner preserves Ubisoft domains and subnets together") {
    const std::vector<std::string> domains = {
        "ubi.com",
        "ubisoft.com",
        "ubisoftconnect.com",
        "uplay.com",
        "ubisoft-uplay-savegames.s3.amazonaws.com",
        "ubisoft-orbit-savegames.s3.amazonaws.com",
        "ubistatic1-a.akamaihd.net",
        "ubisoft.siteintercept.qualtrics.com",
    };
    const std::vector<std::string> subnets = {
        "52.202.184.0/24",
        "203.132.26.0/24",
        "92.122.79.0/24",
        "52.223.17.0/24",
        "52.21.118.0/24",
        "3.218.57.0/24",
        "2.19.213.0/24",
    };
    const nlohmann::json ubisoft_fixture = {
        {"id", "ubisoft"},
        {"name", "Ubisoft"},
        {"engines",
         {{"dns", {{"domains", domains}, {"subnets", subnets}}}}},
    };
    auto intent = outbound_intent();
    intent.selections = {{"ubisoft", std::nullopt}};
    intent.source_detour_tag.reset();

    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({ubisoft_fixture}),
        base_config());

    const auto& list = plan.candidate.lists->at("ubisoft");
    CHECK(list.domains == domains);
    CHECK(list.ip_cidrs == subnets);
    CHECK(plan.summary.lists.front().has_inline_domains);
    CHECK(plan.summary.lists.front().has_inline_cidrs);
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE("catalog planner allocates technical IDs after more than 100 collisions") {
    auto config = base_config();
    std::map<std::string, ListConfig> lists;
    ListConfig existing;
    existing.domains = std::vector<std::string>{"existing.example"};
    lists.emplace("category_ai", existing);
    for (std::size_t suffix = 2U; suffix <= 120U; ++suffix) {
        lists.emplace("category_ai_" + std::to_string(suffix), existing);
    }
    config.lists = std::move(lists);

    std::vector<RouteRule> route_rules;
    std::vector<DnsRule> dns_rules;
    for (std::size_t suffix = 0U; suffix <= 120U; ++suffix) {
        const auto id =
            suffix == 0U ? "catalog_category_ai"
                         : "catalog_category_" + std::to_string(suffix + 1U);
        RouteRule route;
        route.id = id;
        route.list = std::vector<std::string>{"category_ai"};
        route.outbound = "proxy";
        route_rules.push_back(route);

        DnsRule dns;
        dns.id = id;
        dns.list = {"category_ai"};
        dns.server = "proxy_dns";
        dns_rules.push_back(dns);
    }
    config.route->rules = std::move(route_rules);
    config.dns->rules = std::move(dns_rules);
    validate_config(config);

    const auto plan = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        config);
    CHECK(plan.summary.lists[0].technical_id == "category_ai_121");
    CHECK(plan.candidate.lists->at("category_ai").domains == existing.domains);
    CHECK(
        plan.candidate.lists->at("category_ai_121").display_name ==
        "Нейросети");
    REQUIRE(plan.summary.route_rule.has_value());
    REQUIRE(plan.summary.dns_rule.has_value());
    CHECK(
        plan.summary.route_rule->technical_id != "catalog_category_ai");
    CHECK(
        plan.summary.dns_rule->technical_id != "catalog_category_ai");
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE("catalog planner rejects mixed tunnel and reject semantics") {
    auto intent = outbound_intent();
    intent.selections = {
        {"category-ai", std::nullopt},
        {"ads", std::nullopt},
    };
    CHECK_THROWS_WITH_AS(
        plan_catalog_setup(
            intent,
            nlohmann::json::array(
                {routing_preset(), blocking_preset()}),
            base_config()),
        "Reject and tunnel catalogue presets must be planned separately",
        CatalogSetupPlanError);
}

TEST_CASE("catalog planner reuses blackhole and prepends blocking rule") {
    auto config = base_config();
    Outbound blackhole;
    blackhole.tag = "drop";
    blackhole.type = OutboundType::BLACKHOLE;
    config.outbounds->push_back(blackhole);

    RouteRule normal;
    normal.id = "normal";
    normal.list = std::vector<std::string>{"existing"};
    normal.outbound = "proxy";
    ListConfig existing;
    existing.domains = std::vector<std::string>{"existing.example"};
    config.lists = std::map<std::string, ListConfig>{{"existing", existing}};
    config.route->rules = std::vector<RouteRule>{normal};
    validate_config(config);

    CatalogSetupIntent intent;
    intent.selections = {{"ads", std::nullopt}};
    intent.mode = CatalogSetupMode::block;
    intent.dns_mode = CatalogDnsMode::automatic;
    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({blocking_preset()}),
        config);

    REQUIRE(plan.summary.blackhole.has_value());
    CHECK(plan.summary.blackhole->tag == "drop");
    CHECK_FALSE(plan.summary.blackhole->created);
    REQUIRE(plan.summary.route_rule.has_value());
    CHECK(plan.summary.route_rule->blocking);
    CHECK(plan.summary.route_rule->insertion_index == 0U);
    CHECK(plan.candidate.route->rules->front().outbound == "drop");
    CHECK(plan.candidate.route->rules->at(1).id == "normal");
    CHECK_FALSE(plan.summary.dns_rule.has_value());
    CHECK(warning(plan, CatalogSetupWarningCode::dns_ignored_for_block));
}

TEST_CASE("catalog planner creates a collision-safe blackhole") {
    auto config = base_config();
    Outbound occupied;
    occupied.tag = "block";
    occupied.type = OutboundType::INTERFACE;
    occupied.interface = "tun9";
    config.outbounds->push_back(occupied);
    validate_config(config);

    CatalogSetupIntent intent;
    intent.selections = {{"ads", std::nullopt}};
    intent.mode = CatalogSetupMode::block;
    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({blocking_preset()}),
        config);

    REQUIRE(plan.summary.blackhole.has_value());
    CHECK(plan.summary.blackhole->created);
    CHECK(plan.summary.blackhole->tag == "block_2");
    CHECK(plan.candidate.outbounds->back().tag == "block_2");
    CHECK(plan.candidate.outbounds->back().type == OutboundType::BLACKHOLE);
    CHECK(plan.candidate.route->rules->front().outbound == "block_2");
}

TEST_CASE("normal catalog route is inserted before the first active blackhole") {
    auto config = base_config();
    ListConfig existing;
    existing.domains = std::vector<std::string>{"existing.example"};
    config.lists = std::map<std::string, ListConfig>{{"existing", existing}};

    Outbound blackhole;
    blackhole.tag = "drop";
    blackhole.type = OutboundType::BLACKHOLE;
    config.outbounds->push_back(blackhole);

    RouteRule disabled_block;
    disabled_block.id = "disabled";
    disabled_block.enabled = false;
    disabled_block.list = std::vector<std::string>{"existing"};
    disabled_block.outbound = "drop";
    RouteRule active_block = disabled_block;
    active_block.id = "active";
    active_block.enabled = true;
    RouteRule later = disabled_block;
    later.id = "later";
    later.outbound = "proxy";
    config.route->rules =
        std::vector<RouteRule>{disabled_block, active_block, later};
    validate_config(config);

    const auto plan = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        config);
    REQUIRE(plan.summary.route_rule.has_value());
    CHECK(plan.summary.route_rule->insertion_index == 1U);
    CHECK(
        plan.candidate.route->rules->at(0).id ==
        std::optional<std::string>{"disabled"});
    CHECK(
        plan.candidate.route->rules->at(1).id ==
        std::optional<std::string>{"catalog_category_ai"});
    CHECK(
        plan.candidate.route->rules->at(2).id ==
        std::optional<std::string>{"active"});
}

TEST_CASE("source detour applies only to URL-backed lists") {
    auto domain_only = routing_preset("inline", "Встроенный список");
    domain_only["engines"]["singbox"].erase("ruleSets");
    nlohmann::json catalog = nlohmann::json::array(
        {routing_preset(), domain_only});
    auto intent = outbound_intent();
    intent.selections = {
        {"category-ai", "Каталог AI"},
        {"inline", "Встроенные домены"},
    };
    intent.route_display_name = "Маршрут AI";
    intent.dns_display_name = "DNS для AI";

    const auto plan = plan_catalog_setup(intent, catalog, base_config());
    CHECK(plan.candidate.lists->at("category_ai").detour == "proxy");
    CHECK_FALSE(plan.candidate.lists->at("inline").detour.has_value());
    CHECK(
        plan.summary.lists[0].source_detour ==
        std::optional<std::string>{"proxy"});
    CHECK_FALSE(plan.summary.lists[1].source_detour.has_value());
    CHECK(plan.summary.lists[0].display_name == "Каталог AI");
    CHECK(plan.summary.lists[1].display_name == "Встроенные домены");
    REQUIRE(plan.summary.route_rule.has_value());
    REQUIRE(plan.summary.route_rules.size() == 2U);
    CHECK(plan.summary.route_rules[0].display_name == "Каталог AI");
    CHECK(plan.summary.route_rules[1].display_name == "Встроенные домены");
    REQUIRE(plan.summary.dns_rule.has_value());
    REQUIRE(plan.summary.dns_rules.size() == 2U);
    CHECK(plan.summary.dns_rules[0].display_name == "Каталог AI");
    CHECK(plan.summary.dns_rules[1].display_name == "Встроенные домены");
    for (const auto& rule : *plan.candidate.route->rules) {
        REQUIRE(rule.list.has_value());
        CHECK(rule.list->size() == 1U);
    }
    for (const auto& rule : *plan.candidate.dns->rules) {
        CHECK(rule.list.size() == 1U);
    }
}

TEST_CASE("unusable source detour is omitted with an exact warning") {
    auto intent = outbound_intent();
    intent.source_detour_tag = "missing";
    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json::array({routing_preset()}),
        base_config());

    CHECK_FALSE(plan.candidate.lists->at("category_ai").detour.has_value());
    const auto* found =
        warning(plan, CatalogSetupWarningCode::source_detour_not_found);
    REQUIRE(found != nullptr);
    CHECK(found->path == "intent.source_detour_tag");
    CHECK(
        found->message ==
        "Source detour 'missing' was not used because the outbound does not exist");
}

TEST_CASE("explicit DNS server mismatch is rejected") {
    auto intent = outbound_intent();
    intent.dns_mode = CatalogDnsMode::explicit_server;
    intent.dns_server_tag = "direct_dns";
    try {
        static_cast<void>(plan_catalog_setup(
            intent,
            nlohmann::json::array({routing_preset()}),
            base_config()));
        FAIL("mismatched explicit DNS unexpectedly produced a plan");
    } catch (const CatalogSetupPlanError& error) {
        CHECK(
            error.code() ==
            CatalogSetupErrorCode::dns_detour_mismatch);
        CHECK(error.path() == "intent.dns_server_tag");
        CHECK(
            std::string(error.what()) ==
            "DNS server 'direct_dns' has no detour while the route uses "
            "outbound 'proxy'");
    }
}

TEST_CASE("automatic DNS creates a separate detoured resolver when needed") {
    auto config = base_config();
    config.outbounds->front().display_name = "Amsterdam";
    config.dns->servers->front().detour = "backup";
    validate_config(config);
    const auto catalog = nlohmann::json::array({routing_preset()});
    const auto plan =
        plan_catalog_setup(outbound_intent(), catalog, config);

    REQUIRE(plan.summary.dns_server.has_value());
    CHECK(plan.summary.dns_server->technical_id == "cloudflare_proxy");
    CHECK(
        plan.summary.dns_server->display_name ==
        "Cloudflare · Amsterdam");
    CHECK(plan.summary.dns_server->address == "1.0.0.1");
    CHECK(plan.summary.dns_server->detour == "proxy");
    CHECK(plan.summary.dns_server->created);
    REQUIRE(plan.candidate.dns.has_value());
    REQUIRE(plan.candidate.dns->servers.has_value());
    CHECK(plan.candidate.dns->servers->size() == 3U);
    const auto created = std::find_if(
        plan.candidate.dns->servers->begin(),
        plan.candidate.dns->servers->end(),
        [](const DnsServer& server) {
            return server.tag == "cloudflare_proxy";
        });
    REQUIRE(created != plan.candidate.dns->servers->end());
    CHECK(created->address == "1.0.0.1");
    CHECK(created->detour == "proxy");
    CHECK(created->type == api::DnsServerType::STATIC);
    REQUIRE(plan.summary.dns_rule.has_value());
    CHECK(plan.summary.dns_rule->server == "cloudflare_proxy");
    CHECK_NOTHROW(validate_recommended_list_setup(
        plan.candidate, "category_ai"));

    const auto repeated = plan_catalog_setup(
        outbound_intent(), catalog, plan.candidate);
    REQUIRE(repeated.summary.dns_server.has_value());
    CHECK(
        repeated.summary.dns_server->technical_id ==
        "cloudflare_proxy");
    CHECK_FALSE(repeated.summary.dns_server->created);
    CHECK_FALSE(repeated.summary.route_rule.has_value());
    CHECK_FALSE(repeated.summary.dns_rule.has_value());
    CHECK(
        nlohmann::json(repeated.candidate) ==
        nlohmann::json(plan.candidate));
}

TEST_CASE("automatic DNS creates a complete DNS config on first setup") {
    auto config = base_config();
    config.dns->servers.reset();
    config.dns->fallback.reset();
    config.dns->rules.reset();
    validate_config(config);

    const auto plan = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        config);

    REQUIRE(plan.candidate.dns.has_value());
    REQUIRE(plan.candidate.dns->system_resolver.has_value());
    CHECK(plan.candidate.dns->system_resolver->address == "127.0.0.1");
    REQUIRE(plan.candidate.dns->servers.has_value());
    CHECK(plan.candidate.dns->servers->size() == 1U);
    REQUIRE(plan.summary.dns_server.has_value());
    CHECK(plan.summary.dns_server->created);
    CHECK_NOTHROW(validate_config(plan.candidate));
}

TEST_CASE("automatic DNS reuses the lowest exact-detour tag") {
    auto config = base_config();
    DnsServer preferred;
    preferred.tag = "a_proxy_dns";
    preferred.display_name = "Preferred DNS";
    preferred.address = "8.8.8.8";
    preferred.detour = "proxy";
    config.dns->servers->push_back(preferred);
    validate_config(config);

    const auto plan = plan_catalog_setup(
        outbound_intent(),
        nlohmann::json::array({routing_preset()}),
        config);

    REQUIRE(plan.summary.dns_server.has_value());
    CHECK(plan.summary.dns_server->technical_id == "a_proxy_dns");
    CHECK(plan.summary.dns_server->display_name == "Preferred DNS");
    CHECK_FALSE(plan.summary.dns_server->created);
    REQUIRE(plan.summary.dns_rule.has_value());
    CHECK(plan.summary.dns_rule->server == "a_proxy_dns");
}

TEST_CASE(
    "automatic DNS prefers an exact-detour server covering the selected list") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:dns-coverage-preference"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    auto list_only_intent = outbound_intent();
    list_only_intent.mode = CatalogSetupMode::none;
    list_only_intent.outbound_tag.reset();
    list_only_intent.dns_mode = CatalogDnsMode::none;
    list_only_intent.source_detour_tag.reset();
    auto config =
        plan_catalog_setup(list_only_intent, catalog, base_config())
            .candidate;

    DnsServer a_dns;
    a_dns.tag = "a_dns";
    a_dns.address = "8.8.4.4";
    a_dns.detour = "proxy";
    DnsServer z_dns;
    z_dns.tag = "z_dns";
    z_dns.address = "8.8.8.8";
    z_dns.detour = "proxy";
    config.dns->servers = std::vector<DnsServer>{a_dns, z_dns};
    config.dns->fallback = std::vector<std::string>{"z_dns"};

    RouteRule route_rule;
    route_rule.enabled = true;
    route_rule.list = std::vector<std::string>{"category_ai"};
    route_rule.outbound = "proxy";
    config.route->rules = std::vector<RouteRule>{route_rule};

    DnsRule dns_rule;
    dns_rule.enabled = true;
    dns_rule.list = std::vector<std::string>{"category_ai"};
    dns_rule.server = "z_dns";
    config.dns->rules = std::vector<DnsRule>{dns_rule};
    validate_config(config);

    const auto plan =
        plan_catalog_setup(outbound_intent(), catalog, config);
    REQUIRE(plan.summary.dns_server.has_value());
    CHECK(plan.summary.dns_server->technical_id == "z_dns");
    CHECK_FALSE(plan.summary.dns_server->created);
    CHECK_FALSE(plan.summary.route_rule.has_value());
    CHECK_FALSE(plan.summary.dns_rule.has_value());
    CHECK(nlohmann::json(plan.candidate) == nlohmann::json(config));
}

TEST_CASE(
    "automatic DNS accepts split same-detour coverage without duplicate rules") {
    const auto second_preset =
        routing_preset(
            "category-search",
            "Поиск",
            "https://repo.hoaxisr.ru/rulesets/srs/search.srs");
    const nlohmann::json catalog = {
        {"catalog_id", "test:dns-split-coverage"},
        {"presets",
         nlohmann::json::array({routing_preset(), second_preset})},
    };
    auto intent = outbound_intent();
    intent.selections = {
        {"category-ai", std::nullopt},
        {"category-search", std::nullopt},
    };

    auto config =
        plan_catalog_setup(intent, catalog, base_config()).candidate;
    DnsServer alternate;
    alternate.tag = "alternate_dns";
    alternate.address = "8.8.8.8";
    alternate.detour = "proxy";
    config.dns->servers->push_back(alternate);
    REQUIRE(config.dns->rules.has_value());
    REQUIRE(config.dns->rules->size() == 2U);
    config.dns->rules->at(0).server = "proxy_dns";
    config.dns->rules->at(1).server = "alternate_dns";
    validate_config(config);

    const auto plan = plan_catalog_setup(intent, catalog, config);
    REQUIRE(plan.summary.dns_server.has_value());
    CHECK_FALSE(plan.summary.dns_server->created);
    CHECK(plan.summary.dns_rules.empty());
    CHECK_FALSE(plan.summary.dns_rule.has_value());
    CHECK(nlohmann::json(plan.candidate) == nlohmann::json(config));
}

TEST_CASE(
    "explicit DNS does not reuse coverage from another same-detour server") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:dns-explicit-server"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    auto config =
        plan_catalog_setup(
            outbound_intent(), catalog, base_config())
            .candidate;

    DnsServer alternate;
    alternate.tag = "alternate_dns";
    alternate.address = "8.8.8.8";
    alternate.detour = "proxy";
    config.dns->servers->push_back(alternate);
    REQUIRE(config.dns->rules.has_value());
    REQUIRE(config.dns->rules->size() == 1U);
    config.dns->rules->front().server = "alternate_dns";
    validate_config(config);

    auto explicit_intent = outbound_intent();
    explicit_intent.dns_mode = CatalogDnsMode::explicit_server;
    explicit_intent.dns_server_tag = "proxy_dns";
    const auto plan =
        plan_catalog_setup(explicit_intent, catalog, config);
    REQUIRE(plan.summary.dns_server.has_value());
    CHECK(plan.summary.dns_server->technical_id == "proxy_dns");
    REQUIRE(plan.summary.dns_rules.size() == 1U);
    CHECK(plan.summary.dns_rules.front().server == "proxy_dns");
    REQUIRE(plan.candidate.dns->rules.has_value());
    CHECK(plan.candidate.dns->rules->size() == 2U);
    CHECK(plan.candidate.dns->rules->back().server == "proxy_dns");
}

TEST_CASE("automatic DNS fails when every built-in endpoint is occupied") {
    auto config = base_config();
    config.dns->servers->front().detour = "backup";
    DnsServer google;
    google.tag = "google";
    google.address = "8.8.8.8:53";
    DnsServer cloudflare_secondary;
    cloudflare_secondary.tag = "cloudflare_secondary";
    cloudflare_secondary.address = "1.0.0.1";
    DnsServer google_secondary;
    google_secondary.tag = "google_secondary";
    google_secondary.address = "8.8.4.4";
    DnsServer quad9_secondary;
    quad9_secondary.tag = "quad9_secondary";
    quad9_secondary.address = "149.112.112.112";
    DnsServer opendns;
    opendns.tag = "opendns";
    opendns.address = "208.67.222.222";
    DnsServer opendns_secondary;
    opendns_secondary.tag = "opendns_secondary";
    opendns_secondary.address = "208.67.220.220";
    DnsServer yandex;
    yandex.tag = "yandex";
    yandex.address = "77.88.8.8";
    DnsServer yandex_secondary;
    yandex_secondary.tag = "yandex_secondary";
    yandex_secondary.address = "77.88.8.1";
    config.dns->servers->push_back(cloudflare_secondary);
    config.dns->servers->push_back(google);
    config.dns->servers->push_back(google_secondary);
    config.dns->servers->push_back(quad9_secondary);
    config.dns->servers->push_back(opendns);
    config.dns->servers->push_back(opendns_secondary);
    config.dns->servers->push_back(yandex);
    config.dns->servers->push_back(yandex_secondary);
    validate_config(config);

    CHECK_THROWS_WITH_AS(
        plan_catalog_setup(
            outbound_intent(),
            nlohmann::json::array({routing_preset()}),
            config),
        "No unused built-in DNS endpoint is available for outbound 'proxy'",
        CatalogSetupPlanError);
}

TEST_CASE("none mode adds only lists and supports API catalog response snapshot") {
    CatalogSetupIntent intent;
    intent.selections = {{"category-ai", std::nullopt}};
    intent.mode = CatalogSetupMode::none;
    const auto plan = plan_catalog_setup(
        intent,
        nlohmann::json{{"source", "cache"},
                       {"presets",
                        nlohmann::json::array({routing_preset()})}},
        base_config());

    REQUIRE(plan.candidate.lists.has_value());
    CHECK(plan.candidate.lists->count("category_ai") == 1U);
    CHECK_FALSE(plan.summary.route_rule.has_value());
    CHECK_FALSE(plan.summary.dns_rule.has_value());
}

TEST_CASE("candidate revision is deterministic and changes with the candidate") {
    const auto catalog = nlohmann::json::array({routing_preset()});
    const auto first =
        plan_catalog_setup(outbound_intent(), catalog, base_config());
    const auto second =
        plan_catalog_setup(outbound_intent(), catalog, base_config());
    CHECK(first.candidate_revision == second.candidate_revision);
    CHECK(nlohmann::json(first.candidate) == nlohmann::json(second.candidate));

    auto changed_intent = outbound_intent();
    changed_intent.route_display_name = "AI через прокси";
    const auto changed =
        plan_catalog_setup(changed_intent, catalog, base_config());
    CHECK(changed.candidate_revision != first.candidate_revision);
}

TEST_CASE("reject catalog preset requires block mode") {
    CatalogSetupIntent intent;
    intent.selections = {{"ads", std::nullopt}};
    const auto catalog = nlohmann::json::array({blocking_preset()});

    SUBCASE("list-only mode cannot neutralize the authoritative action") {
        intent.mode = CatalogSetupMode::none;
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(intent, catalog, base_config()),
            "A reject catalogue preset must use block mode",
            CatalogSetupPlanError);
    }

    SUBCASE("reject cannot be routed through an outbound") {
        intent.mode = CatalogSetupMode::outbound;
        intent.outbound_tag = "proxy";
        CHECK_THROWS_WITH_AS(
            plan_catalog_setup(intent, catalog, base_config()),
            "A reject catalogue preset must use block mode",
            CatalogSetupPlanError);
    }
}

TEST_CASE(
    "catalog planner persists provenance and makes a repeated preset a no-op") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:authoritative-catalog"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    const auto first =
        plan_catalog_setup(outbound_intent(), catalog, base_config());

    REQUIRE(first.summary.lists.size() == 1U);
    CHECK_FALSE(first.summary.lists.front().already_installed);
    const auto technical_id =
        first.summary.lists.front().technical_id;
    const auto& installed =
        first.candidate.lists->at(technical_id);
    REQUIRE(installed.catalog_identity.has_value());
    CHECK(installed.catalog_identity->size() == 64U);

    const auto repeated = plan_catalog_setup(
        outbound_intent(), catalog, first.candidate);
    REQUIRE(repeated.summary.lists.size() == 1U);
    CHECK(repeated.summary.lists.front().already_installed);
    CHECK(
        repeated.summary.lists.front().technical_id ==
        technical_id);
    CHECK_FALSE(repeated.summary.route_rule.has_value());
    CHECK_FALSE(repeated.summary.dns_rule.has_value());
    CHECK_FALSE(repeated.summary.blackhole.has_value());
    CHECK(
        nlohmann::json(repeated.candidate) ==
        nlohmann::json(first.candidate));
    CHECK(
        repeated.candidate_revision ==
        first.candidate_revision);
}

TEST_CASE(
    "catalog planner reuses a legacy list and adds its missing policies") {
    auto config = base_config();
    ListConfig legacy;
    legacy.display_name = "Переименовано пользователем";
    legacy.url =
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs";
    legacy.domains =
        std::vector<std::string>{"old-inline.example"};
    config.lists =
        std::map<std::string, ListConfig>{{"my_custom_ai", legacy}};
    validate_config(config);

    const nlohmann::json catalog = {
        {"catalog_id", "test:authoritative-catalog"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    const auto plan =
        plan_catalog_setup(outbound_intent(), catalog, config);

    REQUIRE(plan.summary.lists.size() == 1U);
    CHECK(plan.summary.lists.front().already_installed);
    CHECK(
        plan.summary.lists.front().technical_id ==
        "my_custom_ai");
    CHECK(
        plan.summary.lists.front().display_name ==
        "Переименовано пользователем");
    CHECK(plan.candidate.lists->size() == 1U);
    REQUIRE(plan.summary.route_rule.has_value());
    REQUIRE(plan.summary.dns_rule.has_value());
    const auto& route_rule =
        plan.candidate.route->rules->at(
            plan.summary.route_rule->insertion_index);
    REQUIRE(route_rule.list.has_value());
    CHECK(
        *route_rule.list ==
        std::vector<std::string>{"my_custom_ai"});
    const auto& dns_rule =
        plan.candidate.dns->rules->at(
            plan.summary.dns_rule->insertion_index);
    CHECK(
        dns_rule.list ==
        std::vector<std::string>{"my_custom_ai"});
}

TEST_CASE(
    "catalog planner adds requested policies to a provenance list-only install") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:list-only-catalog"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    auto list_only_intent = outbound_intent();
    list_only_intent.mode = CatalogSetupMode::none;
    list_only_intent.outbound_tag.reset();
    list_only_intent.dns_mode = CatalogDnsMode::none;
    const auto list_only =
        plan_catalog_setup(list_only_intent, catalog, base_config());
    CHECK_FALSE(list_only.summary.route_rule.has_value());
    CHECK_FALSE(list_only.summary.dns_rule.has_value());

    const auto with_policies = plan_catalog_setup(
        outbound_intent(), catalog, list_only.candidate);
    REQUIRE(with_policies.summary.lists.size() == 1U);
    CHECK(with_policies.summary.lists.front().already_installed);
    CHECK(
        with_policies.summary.lists.front().technical_id ==
        list_only.summary.lists.front().technical_id);
    REQUIRE(with_policies.summary.route_rule.has_value());
    REQUIRE(with_policies.summary.dns_rule.has_value());
    CHECK(with_policies.candidate.lists->size() == 1U);

    const auto covered = plan_catalog_setup(
        outbound_intent(), catalog, with_policies.candidate);
    CHECK(covered.summary.lists.front().already_installed);
    CHECK_FALSE(covered.summary.route_rule.has_value());
    CHECK_FALSE(covered.summary.dns_rule.has_value());
    CHECK(
        nlohmann::json(covered.candidate) ==
        nlohmann::json(with_policies.candidate));
}

TEST_CASE(
    "catalog planner creates only a missing DNS policy for an installed list") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:partial-policy-catalog"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    const auto installed =
        plan_catalog_setup(outbound_intent(), catalog, base_config());
    auto route_only = installed.candidate;
    route_only.dns->rules = std::vector<DnsRule>{};
    validate_config(route_only);

    const auto repaired =
        plan_catalog_setup(outbound_intent(), catalog, route_only);
    CHECK(repaired.summary.lists.front().already_installed);
    CHECK_FALSE(repaired.summary.route_rule.has_value());
    REQUIRE(repaired.summary.dns_rule.has_value());
    REQUIRE(repaired.candidate.route->rules.has_value());
    CHECK(repaired.candidate.route->rules->size() == 1U);
    REQUIRE(repaired.candidate.dns->rules.has_value());
    CHECK(repaired.candidate.dns->rules->size() == 1U);
}

TEST_CASE(
    "multi-list rules do not count as dedicated catalogue coverage") {
    const nlohmann::json catalog = {
        {"catalog_id", "test:exact-policy-catalog"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    auto list_only_intent = outbound_intent();
    list_only_intent.mode = CatalogSetupMode::none;
    list_only_intent.outbound_tag.reset();
    list_only_intent.dns_mode = CatalogDnsMode::none;
    const auto list_only =
        plan_catalog_setup(list_only_intent, catalog, base_config());

    auto config = list_only.candidate;
    ListConfig other;
    other.domains = std::vector<std::string>{"other.example"};
    config.lists->emplace("other", std::move(other));

    RouteRule shared_route;
    shared_route.enabled = true;
    shared_route.list =
        std::vector<std::string>{"category_ai", "other"};
    shared_route.outbound = "proxy";
    config.route->rules = std::vector<RouteRule>{shared_route};

    DnsRule shared_dns;
    shared_dns.enabled = true;
    shared_dns.list =
        std::vector<std::string>{"category_ai", "other"};
    shared_dns.server = "proxy_dns";
    config.dns->rules = std::vector<DnsRule>{shared_dns};
    validate_config(config);

    const auto repaired =
        plan_catalog_setup(outbound_intent(), catalog, config);
    REQUIRE(repaired.summary.route_rule.has_value());
    REQUIRE(repaired.summary.dns_rule.has_value());
    const auto& dedicated_route =
        repaired.candidate.route->rules->at(
            repaired.summary.route_rule->insertion_index);
    const auto& dedicated_dns =
        repaired.candidate.dns->rules->at(
            repaired.summary.dns_rule->insertion_index);
    CHECK(
        dedicated_route.list ==
        std::optional<std::vector<std::string>>{{"category_ai"}});
    CHECK(
        dedicated_dns.list ==
        std::vector<std::string>{"category_ai"});
}

TEST_CASE(
    "same preset id from a different authoritative source is not conflated") {
    const nlohmann::json first_catalog = {
        {"catalog_id", "test:catalog-a"},
        {"presets", nlohmann::json::array({routing_preset()})},
    };
    auto different_preset = routing_preset(
        "category-ai",
        "Нейросети B",
        "https://repo.hoaxisr.ru/rulesets/srs/ai-b.srs");
    const nlohmann::json second_catalog = {
        {"catalog_id", "test:catalog-b"},
        {"presets", nlohmann::json::array({different_preset})},
    };

    const auto first = plan_catalog_setup(
        outbound_intent(), first_catalog, base_config());
    const auto second = plan_catalog_setup(
        outbound_intent(), second_catalog, first.candidate);

    REQUIRE(second.summary.lists.size() == 1U);
    CHECK_FALSE(second.summary.lists.front().already_installed);
    CHECK(second.candidate.lists->size() == 2U);
    CHECK(
        second.candidate.lists
            ->at(second.summary.lists.front().technical_id)
            .catalog_identity !=
        first.candidate.lists
            ->at(first.summary.lists.front().technical_id)
            .catalog_identity);
}

TEST_CASE(
    "mixed catalogue selection only wires rules for presets still to install") {
    const auto first_preset = routing_preset();
    const auto second_preset = routing_preset(
        "category-video",
        "Видео",
        "https://repo.hoaxisr.ru/rulesets/srs/video.srs");
    const nlohmann::json first_catalog = {
        {"catalog_id", "test:mixed-catalog"},
        {"presets", nlohmann::json::array({first_preset})},
    };
    const nlohmann::json mixed_catalog = {
        {"catalog_id", "test:mixed-catalog"},
        {"presets",
         nlohmann::json::array({first_preset, second_preset})},
    };

    const auto installed = plan_catalog_setup(
        outbound_intent(), first_catalog, base_config());
    auto mixed_intent = outbound_intent();
    mixed_intent.selections.push_back(
        {"category-video", std::nullopt});
    const auto mixed = plan_catalog_setup(
        mixed_intent, mixed_catalog, installed.candidate);

    REQUIRE(mixed.summary.lists.size() == 2U);
    CHECK(mixed.summary.lists.at(0).already_installed);
    CHECK_FALSE(mixed.summary.lists.at(1).already_installed);
    REQUIRE(mixed.summary.route_rule.has_value());
    REQUIRE(mixed.summary.dns_rule.has_value());
    REQUIRE(mixed.summary.route_rules.size() == 1U);
    REQUIRE(mixed.summary.dns_rules.size() == 1U);
    const auto& route_rule =
        mixed.candidate.route->rules->at(
            mixed.summary.route_rule->insertion_index);
    REQUIRE(route_rule.list.has_value());
    CHECK(
        *route_rule.list ==
        std::vector<std::string>{"category_video"});
    const auto& dns_rule =
        mixed.candidate.dns->rules->at(
            mixed.summary.dns_rule->insertion_index);
    CHECK(
        dns_rule.list ==
        std::vector<std::string>{"category_video"});
}

TEST_CASE(
    "mixed catalogue selection wires an uncovered legacy list with the new list") {
    auto config = base_config();
    ListConfig legacy;
    legacy.display_name = "Existing AI";
    legacy.url =
        "https://repo.hoaxisr.ru/rulesets/srs/ai.srs";
    config.lists =
        std::map<std::string, ListConfig>{{"existing_ai", legacy}};
    validate_config(config);

    const auto first_preset = routing_preset();
    const auto second_preset = routing_preset(
        "category-video",
        "Видео",
        "https://repo.hoaxisr.ru/rulesets/srs/video.srs");
    const nlohmann::json catalog = {
        {"catalog_id", "test:mixed-uncovered-catalog"},
        {"presets",
         nlohmann::json::array({first_preset, second_preset})},
    };
    auto intent = outbound_intent();
    intent.selections.push_back({"category-video", std::nullopt});

    const auto plan = plan_catalog_setup(intent, catalog, config);

    REQUIRE(plan.summary.lists.size() == 2U);
    CHECK(plan.summary.lists.at(0).already_installed);
    CHECK(
        plan.summary.lists.at(0).technical_id ==
        "existing_ai");
    CHECK_FALSE(plan.summary.lists.at(1).already_installed);
    REQUIRE(plan.summary.route_rule.has_value());
    REQUIRE(plan.summary.route_rules.size() == 2U);
    for (const auto& summary : plan.summary.route_rules) {
        const auto& route_rule =
            plan.candidate.route->rules->at(
                summary.insertion_index);
        REQUIRE(route_rule.list.has_value());
        CHECK(route_rule.list->size() == 1U);
    }
    REQUIRE(plan.summary.dns_rule.has_value());
    REQUIRE(plan.summary.dns_rules.size() == 2U);
    for (const auto& summary : plan.summary.dns_rules) {
        const auto& dns_rule =
            plan.candidate.dns->rules->at(
                summary.insertion_index);
        CHECK(dns_rule.list.size() == 1U);
    }
}
