#include <doctest/doctest.h>

#include "../src/setup/catalog_setup_planner.hpp"

#include <nlohmann/json.hpp>

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

CatalogSetupIntent outbound_intent() {
    CatalogSetupIntent intent;
    intent.selections = {{"category-ai", std::nullopt}};
    intent.mode = CatalogSetupMode::outbound;
    intent.outbound_tag = "proxy";
    intent.dns_mode = CatalogDnsMode::automatic;
    intent.source_detour_tag = "proxy";
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
    CHECK(plan.warnings.empty());
    CHECK(plan.candidate_revision.size() == 64U);
    CHECK_NOTHROW(validate_config(plan.candidate));
    CHECK_NOTHROW(validate_recommended_list_setup(
        plan.candidate, "category_ai"));
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
    CHECK(
        plan.candidate.lists->at("cloudflare_ips").ip_cidrs ==
        cloudflare_subnets);
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

TEST_CASE("automatic DNS fails closed when no server follows route") {
    auto config = base_config();
    config.dns->servers->front().detour = "backup";
    validate_config(config);
    try {
        static_cast<void>(plan_catalog_setup(
            outbound_intent(),
            nlohmann::json::array({routing_preset()}),
            config));
        FAIL("automatic DNS unexpectedly produced a partial plan");
    } catch (const CatalogSetupPlanError& error) {
        CHECK(
            error.code() ==
            CatalogSetupErrorCode::dns_automatic_unavailable);
        CHECK(error.path() == "intent.dns_mode");
        CHECK(
            std::string(error.what()) ==
            "No DNS server is detoured through outbound 'proxy'; "
            "create or select a compatible DNS server first");
    }
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
