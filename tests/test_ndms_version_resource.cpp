#include <doctest/doctest.h>

#include "../src/keenetic/ndms_version_projection.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

std::string measured_version() {
    return R"({
        "model":"KN-1811",
        "vendor":"Keenetic",
        "hw_id":"KN-1811",
        "region":"RU",
        "arch":"mipsel",
        "title":"4.3.2",
        "release":"4.3.2.1",
        "sandbox":"stable",
        "ndm":{"cdate":"2026-08-31"}
    })";
}

TEST_CASE("version facts and firmware projection share one raw fetch") {
    int calls = 0;
    NdmsVersionResource resource([&] {
        ++calls;
        return measured_version();
    });
    NdmsRouterVersionFactsCache facts(resource);
    NdmsFirmwareVersionCache firmware(resource);

    const auto facts_snapshot = facts.get();
    const auto firmware_snapshot = firmware.get();

    REQUIRE(facts_snapshot.facts.has_value());
    REQUIRE(firmware_snapshot.version.has_value());
    CHECK(calls == 1);
    CHECK(facts_snapshot.facts->model == "KN-1811");
    CHECK(facts_snapshot.facts->vendor == "Keenetic");
    CHECK(facts_snapshot.facts->firmware_date == "2026-08-31");
    CHECK(*firmware_snapshot.version == "4.3.2");
    CHECK(facts_snapshot.status == NdmsCatalogCacheStatus::fresh);
    CHECK(firmware_snapshot.status == NdmsCatalogCacheStatus::fresh);
    CHECK(facts_snapshot.source_content_generation == 1U);
    CHECK(firmware_snapshot.source_content_generation ==
          facts_snapshot.source_content_generation);
    CHECK(firmware_snapshot.source_observation_generation ==
          facts_snapshot.source_observation_generation);
    CHECK(firmware_snapshot.observation_epoch ==
          facts_snapshot.observation_epoch);
}

TEST_CASE("semantic version no-op advances observation stamps only") {
    int calls = 0;
    NdmsVersionResource resource([&] {
        ++calls;
        if (calls == 1) return measured_version();
        return std::string{R"({
            "ndm" : { "cdate" : "2026-08-31" },
            "sandbox" : "stable", "release" : "4.3.2.1",
            "title" : "4.3.2", "arch" : "mipsel",
            "region" : "RU", "hw_id" : "KN-1811",
            "vendor" : "Keenetic", "model" : "KN-1811"
        })"};
    });
    NdmsRouterVersionFactsCache facts(resource);
    NdmsFirmwareVersionCache firmware(resource);

    const auto initial_facts = facts.get();
    const auto initial_firmware = firmware.get();
    REQUIRE(initial_facts.facts.has_value());
    REQUIRE(initial_firmware.version.has_value());

    resource.invalidate();
    const auto verified_facts = facts.force_refresh();
    const auto verified_firmware = firmware.get();

    REQUIRE(verified_facts.facts.has_value());
    REQUIRE(verified_firmware.version.has_value());
    CHECK(calls == 2);
    CHECK(verified_facts.source_content_generation ==
          initial_facts.source_content_generation);
    CHECK(verified_firmware.source_content_generation ==
          initial_firmware.source_content_generation);
    CHECK(verified_facts.source_observation_generation ==
          initial_facts.source_observation_generation + 1U);
    CHECK(verified_firmware.source_observation_generation ==
          initial_firmware.source_observation_generation + 1U);
    CHECK(verified_facts.observation_epoch == 1U);
    CHECK(verified_firmware.observation_epoch == 1U);
    CHECK_FALSE(verified_facts.changed);
    CHECK_FALSE(verified_firmware.changed);
    CHECK(verified_facts.status == NdmsCatalogCacheStatus::fresh);
    CHECK(verified_firmware.status == NdmsCatalogCacheStatus::fresh);
}

TEST_CASE("malformed version refresh preserves both typed LKG snapshots") {
    int calls = 0;
    NdmsVersionResource resource([&] {
        ++calls;
        return calls == 1 ? measured_version()
                          : std::string{"{not-json"};
    });
    NdmsRouterVersionFactsCache facts(resource);
    NdmsFirmwareVersionCache firmware(resource);

    const auto initial_facts = facts.get();
    const auto initial_firmware = firmware.get();
    REQUIRE(initial_facts.facts.has_value());
    REQUIRE(initial_firmware.version.has_value());

    resource.invalidate();
    const auto stale_facts = facts.force_refresh();
    const auto stale_firmware = firmware.get();

    REQUIRE(stale_facts.facts.has_value());
    REQUIRE(stale_firmware.version.has_value());
    CHECK(calls == 2);
    CHECK(stale_facts.facts->model == "KN-1811");
    CHECK(*stale_firmware.version == "4.3.2");
    CHECK(stale_facts.status == NdmsCatalogCacheStatus::stale);
    CHECK(stale_firmware.status == NdmsCatalogCacheStatus::stale);
    CHECK(stale_facts.source_content_generation ==
          initial_facts.source_content_generation);
    CHECK(stale_firmware.source_content_generation ==
          initial_firmware.source_content_generation);
    CHECK(stale_facts.source_observation_generation ==
          initial_facts.source_observation_generation);
    CHECK(stale_firmware.source_observation_generation ==
          initial_firmware.source_observation_generation);
}

TEST_CASE("version projections accept independent authoritative shapes") {
    int calls = 0;
    const std::vector<std::string> payloads{
        R"({"model":"KN-1811","vendor":"Keenetic","arch":"mipsel"})",
        R"("4.4.0")",
    };
    NdmsVersionResource resource([&] {
        return payloads.at(static_cast<std::size_t>(calls++));
    });
    NdmsRouterVersionFactsCache facts(resource);
    NdmsFirmwareVersionCache firmware(resource);

    const auto current_facts = facts.get();
    const auto absent_firmware = firmware.get();
    REQUIRE(current_facts.facts.has_value());
    CHECK(calls == 1);
    CHECK(current_facts.facts->model == "KN-1811");
    CHECK(current_facts.status == NdmsCatalogCacheStatus::fresh);
    CHECK_FALSE(absent_firmware.version.has_value());
    CHECK(absent_firmware.status == NdmsCatalogCacheStatus::fresh);
    CHECK(absent_firmware.source_content_generation ==
          current_facts.source_content_generation);

    resource.invalidate();
    const auto stale_facts = facts.force_refresh();
    const auto scalar_firmware = firmware.get();
    REQUIRE(stale_facts.facts.has_value());
    REQUIRE(scalar_firmware.version.has_value());
    CHECK(calls == 2);
    CHECK(stale_facts.facts->model == "KN-1811");
    CHECK(stale_facts.status == NdmsCatalogCacheStatus::stale);
    CHECK(stale_facts.source_content_generation ==
          current_facts.source_content_generation);
    CHECK(*scalar_firmware.version == "4.4.0");
    CHECK(scalar_firmware.status == NdmsCatalogCacheStatus::fresh);
    CHECK(scalar_firmware.source_content_generation ==
          absent_firmware.source_content_generation + 1U);
}

TEST_CASE("firmware projection preserves legacy plain version payloads") {
    const std::vector<std::string> payloads{"4.3", "Версия 4.3"};
    for (const auto& payload : payloads) {
        CAPTURE(payload);
        int calls = 0;
        NdmsVersionResource resource([&] {
            ++calls;
            return payload;
        });
        NdmsFirmwareVersionCache firmware(resource);

        const auto snapshot = firmware.get();

        REQUIRE(snapshot.version.has_value());
        CHECK(calls == 1);
        CHECK(*snapshot.version == payload);
        CHECK(snapshot.status == NdmsCatalogCacheStatus::fresh);
        CHECK(snapshot.source_content_generation == 1U);
        CHECK(snapshot.source_observation_generation == 1U);
    }
}

} // namespace
} // namespace keen_pbr3
