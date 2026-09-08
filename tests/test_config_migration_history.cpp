#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/config_migration.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

using Json = nlohmann::json;

Json history_fixture(const char* name) {
    const auto path = std::filesystem::path(__FILE__).parent_path() /
                      "fixtures" / "config-migrations" / name;
    std::ifstream input(path);
    if (!input) throw std::runtime_error("Cannot read migration fixture: " + path.string());
    return Json::parse(input);
}

} // namespace

TEST_CASE("historical config migration: released shapes retain routing DNS and mark settings") {
    for (const char* filename : {"pre-hex-fwmark.json", "pre-dns-probe-rename.json",
                                 "sb3-unversioned-modern.json"}) {
        CAPTURE(filename);
        for (const bool explicit_v1 : {false, true}) {
            CAPTURE(explicit_v1);
            auto original = history_fixture(filename);
            if (explicit_v1) original["schema_version"] = 1;
            const auto untouched = original;
            const auto migrated = migrate_config_json(original);
            CHECK(original == untouched);
            CHECK(migrated.at("schema_version") == kCurrentConfigSchemaVersion);
            CHECK(migrate_config_json(migrated) == migrated);
            CHECK(migrated.at("fwmark").at("start") == "0x00010000");
            CHECK(migrated.at("fwmark").at("mask") == "0x00FF0000");
            CHECK(migrated.at("dns").at("fallback") == Json::array({"quad9"}));
            const auto config = parse_and_validate_config(original.dump());
            REQUIRE(config.fwmark.has_value());
            CHECK(fwmark_start_value(*config.fwmark) == 65536);
            CHECK(fwmark_mask_value(*config.fwmark) == 16711680);
            REQUIRE(config.dns.has_value());
            CHECK(config.dns->fallback == std::vector<std::string>{"quad9"});
            REQUIRE(config.dns->dns_test_server.has_value());
            CHECK(config.dns->dns_test_server->listen == "127.0.0.88:12153");
            CHECK(config.dns->dns_test_server->answer_ipv4 == "192.0.2.1");
            REQUIRE(config.route.has_value());
            REQUIRE(config.route->rules.has_value());
            REQUIRE(config.route->rules->size() == 1);
            CHECK(config.route->rules->front().outbound == "vpn");
            REQUIRE(config.outbounds.has_value());
            REQUIRE(config.outbounds->size() == 2);
            CHECK(config.outbounds->front().strict_enforcement == true);
            CHECK(config.outbounds->front().interface == "tun0");
            const Json encoded = config;
            CHECK(Json(parse_and_validate_config(encoded.dump())) == encoded);
        }
    }
}

TEST_CASE("historical config migration: unknown raw fields survive at every migrated level") {
    auto original = history_fixture("pre-dns-probe-rename.json");
    original["unknown"] = {{"order", {3, 1, 2}}, {"nullable", nullptr}};
    original["fwmark"]["unknown"] = Json::array({true, "kept"});
    original["dns"]["unknown"] = {{"nested", "kept"}};
    original["dns"]["test_server"]["unknown"] = 42;
    auto expected = original;
    expected["schema_version"] = kCurrentConfigSchemaVersion;
    expected["fwmark"]["start"] = "0x00010000";
    expected["fwmark"]["mask"] = "0x00FF0000";
    expected["dns"]["fallback"] = Json::array({"quad9"});
    expected["dns"]["dns_test_server"] = original["dns"]["test_server"];
    CHECK(migrate_config_json(original) == expected);
    CHECK(migrate_config_json(expected) == expected);
}

TEST_CASE("historical config migration: existing canonical DNS probe wins without extra errors") {
    auto original = history_fixture("pre-dns-probe-rename.json");
    original["dns"]["dns_test_server"] = {
        {"listen", "127.0.0.89:12153"}, {"answer_ipv4", "192.0.2.2"}};
    const auto migrated = migrate_config_json(original);
    CHECK(migrated["dns"]["test_server"] == original["dns"]["test_server"]);
    CHECK(migrated["dns"]["dns_test_server"] == original["dns"]["dns_test_server"]);
    const auto config = parse_and_validate_config(original.dump());
    REQUIRE(config.dns->dns_test_server.has_value());
    CHECK(config.dns->dns_test_server->listen == "127.0.0.89:12153");
    CHECK(config.dns->dns_test_server->answer_ipv4 == "192.0.2.2");
}

TEST_CASE("historical config migration: null canonical probe accepts the historical listener") {
    auto original = history_fixture("pre-dns-probe-rename.json");
    original["dns"]["dns_test_server"] = nullptr;
    const auto migrated = migrate_config_json(original);
    CHECK(migrated["dns"]["dns_test_server"] == original["dns"]["test_server"]);
    const auto config = parse_and_validate_config(original.dump());
    REQUIRE(config.dns->dns_test_server.has_value());
    CHECK(config.dns->dns_test_server->listen == "127.0.0.88:12153");
}

TEST_CASE("historical config migration: current schema does not silently reinterpret legacy types") {
    for (const char* filename : {"pre-hex-fwmark.json", "pre-dns-probe-rename.json"}) {
        auto document = history_fixture(filename);
        document["schema_version"] = kCurrentConfigSchemaVersion;
        CHECK(migrate_config_json(document) == document);
        CHECK_THROWS_AS(parse_config(document.dump()), ConfigValidationError);
    }
    auto current = history_fixture("sb3-unversioned-modern.json");
    current["schema_version"] = kCurrentConfigSchemaVersion;
    current["dns"]["fallback"] = "quad9";
    CHECK(migrate_config_json(current) == current);
    CHECK_THROWS_AS(parse_config(current.dump()), ConfigValidationError);
}

TEST_CASE("historical config migration: uint32 integers are encoded without losing high bits") {
    const std::array<std::pair<std::uint64_t, const char*>, 4> cases{{
        {0, "0x00000000"}, {65536, "0x00010000"},
        {0x80000000ULL, "0x80000000"}, {0xFFFFFFFFULL, "0xFFFFFFFF"},
    }};
    for (const char* field : {"start", "mask"}) {
        for (const auto& item : cases) {
            CAPTURE(field);
            CAPTURE(item.first);
            const Json document = {{"fwmark", {{field, item.first}}}};
            CHECK(migrate_config_json(document)["fwmark"][field] == item.second);
        }
    }
}

TEST_CASE("historical config migration: invalid numeric fwmarks still fail normal validation") {
    const std::vector<Json> invalid = {
        Json(false), Json(true), Json(-1), Json(65536.0),
        Json(0x100000000ULL), Json(std::numeric_limits<std::uint64_t>::max()),
        Json::array({65536}), Json::object(),
    };
    for (const char* field : {"start", "mask"}) {
        for (const auto& value : invalid) {
            CAPTURE(field);
            CAPTURE(value.dump());
            auto document = history_fixture("sb3-unversioned-modern.json");
            document["fwmark"][field] = value;
            CHECK(migrate_config_json(document)["fwmark"][field] == value);
            CHECK_THROWS_AS(parse_config(document.dump()), ConfigValidationError);
        }
    }
}

TEST_CASE("historical config migration: modern unversioned settings change only the version marker") {
    const auto original = history_fixture("sb3-unversioned-modern.json");
    auto expected = original;
    expected["schema_version"] = kCurrentConfigSchemaVersion;
    CHECK(migrate_config_json(original) == expected);
}
