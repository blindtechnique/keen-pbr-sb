#include <doctest/doctest.h>
#include "../src/config/subscription_backup.hpp"
#include "../src/config/subscription_refresh.hpp"
#include "../src/crypto/sha256.hpp"

#include <limits>
#include <stdexcept>

using namespace keen_pbr3;
namespace {
using json = nlohmann::json;
const std::string backup_url = "https://provider.example/sub/private-backup-token";
const std::string first_link = "vless://private-old@one.example:443#Primary";
const std::string second_link = "trojan://private-next@two.example:443#Secondary";

json source_record() {
    const auto plan = plan_subscription_import(first_link + "\n" + second_link, {}, {});
    auto record = subscription_refresh_metadata(first_link + "\n" + second_link, plan, 100);
    record["id"] = "sub-" + Sha256::hex(backup_url).substr(0, 24);
    record["url"] = backup_url;
    record["name"] = "My plan";
    record["name_is_custom"] = true;
    record["provider_name"] = "Provider plan";
    record["source_host"] = "provider.example";
    record["refresh_interval_seconds"] = 3600;
    record["transport_tags"] = {"primary", "secondary"};
    record["_bindings"] = subscription_import_bindings(plan, {{1, "primary"}, {2, "secondary"}});
    record["_known_candidates"] = {subscription_candidate_key(plan, 0)};
    record["_pending_candidates"] = {subscription_candidate_key(plan, 1)};
    record["pending_new_servers_count"] = 1;
    record["pending_servers_revision"] = 3;
    record["upload_bytes"] = 0;
    record["download_bytes"] = 20;
    record["total_bytes"] = 100;
    record["expires_at"] = 2000000000;
    record["usage_cycle"] = 2;
    return record;
}

json transports() {
    return {{"transports", json::array({
        {{"tag", "primary"}, {"type", "sing-box"}, {"link", first_link}},
        {{"tag", "secondary"}, {"type", "sing-box"}, {"link", second_link}}
    })}};
}

void rejects_without_secrets(const json& records) {
    try {
        (void)validated_subscription_backup(records);
        FAIL("malformed private source was accepted");
    } catch (const std::invalid_argument& error) {
        CHECK(std::string(error.what()) == "invalid subscription backup");
        CHECK(std::string(error.what()).find("private-backup-token") == std::string::npos);
    }
}
}

TEST_CASE("subscription backup preserves private sources schedules names and metadata exactly") {
    const auto original = json::array({source_record()});
    const auto archived = validated_subscription_backup(original);
    CHECK(archived == original);
    CHECK(archived[0].at("url") == backup_url);
    CHECK(archived[0].at("_bindings").size() == 2);
    CHECK(reconcile_subscription_backup(archived, transports()) == original);
    CHECK_FALSE(public_subscription(archived[0]).contains("url"));
    CHECK_FALSE(public_subscription(archived[0]).contains("_bindings"));
    CHECK_FALSE(public_subscription(archived[0]).contains("_inventory"));
    auto disabled = original;
    disabled[0]["refresh_interval_seconds"] = 0;
    CHECK(validated_subscription_backup(disabled) == disabled);
}

TEST_CASE("subscription restore unlinks deleted VPNs without deleting their source") {
    const auto original = json::array({source_record()});
    auto target = transports();
    target["transports"].erase(1);
    const auto restored = reconcile_subscription_backup(original, target);
    REQUIRE(restored.size() == 1);
    CHECK(restored[0].at("transport_tags") == json::array({"primary"}));
    CHECK(restored[0].at("_bindings") == json::array({original[0]["_bindings"][0]}));
    auto expected = original;
    expected[0]["transport_tags"] = restored[0]["transport_tags"];
    expected[0]["_bindings"] = restored[0]["_bindings"];
    CHECK(restored == expected);
    CHECK(original[0].at("transport_tags").size() == 2); // Pure input remains unchanged.

    const auto none = reconcile_subscription_backup(original, nullptr);
    CHECK(none[0].at("transport_tags").empty());
    CHECK(none[0].at("_bindings").empty());
    CHECK(none[0].at("url") == backup_url);
    CHECK(none[0].at("refresh_interval_seconds") == 3600);
}

TEST_CASE("subscription restore never reattaches a reused tag with another fingerprint") {
    const auto original = json::array({source_record()});
    auto target = transports();
    target["transports"][0]["link"] = second_link;
    // The archived source knows this second connection too. Its existence does
    // not permit moving the first binding by tag or by another inventory row.
    target["transports"][0]["link_fingerprint"] = subscription_link_fingerprint(first_link);
    const auto restored = reconcile_subscription_backup(original, target);
    CHECK(restored[0].at("transport_tags") == json::array({"secondary"}));
    REQUIRE(restored[0].at("_bindings").size() == 1);
    CHECK(restored[0].at("_bindings")[0].at("tag") == "secondary");

    target = transports();
    target["transports"][0]["link"] = "";
    target["transports"][0]["link_fingerprint"] = subscription_link_fingerprint(first_link);
    CHECK(reconcile_subscription_backup(original, target)[0].at("transport_tags") == json::array({"secondary"}));
    target = transports();
    target["transports"][0]["type"] = "native";
    CHECK(reconcile_subscription_backup(original, target)[0].at("transport_tags") == json::array({"secondary"}));
}

TEST_CASE("subscription restore accepts changed provider remarks but not changed connection data") {
    const auto original = json::array({source_record()});
    auto target = transports();
    target["transports"][0]["link"] = " \tvless://private-old@one.example:443#Renamed\n";
    CHECK(reconcile_subscription_backup(original, target) == original);
}

TEST_CASE("subscription legacy bindings require exact unique saved inventory evidence") {
    auto legacy = json::array({source_record()});
    legacy[0].erase("_bindings");
    auto restored = reconcile_subscription_backup(legacy, transports());
    CHECK(restored[0].at("transport_tags") == legacy[0].at("transport_tags"));
    CHECK(restored[0].at("_bindings") == source_record().at("_bindings"));
    legacy[0].erase("_inventory");
    restored = reconcile_subscription_backup(legacy, transports());
    CHECK(restored.size() == 1);
    CHECK(restored[0].at("transport_tags").empty());
    CHECK_FALSE(restored[0].contains("_bindings"));

    legacy = json::array({source_record()});
    legacy[0].erase("_bindings");
    legacy[0]["_inventory"][1]["fingerprint"] = subscription_link_fingerprint(first_link);
    restored = reconcile_subscription_backup(legacy, transports());
    CHECK(restored[0].at("transport_tags").empty());
}

TEST_CASE("subscription archive absence can preserve current sources while explicit empty clears") {
    const auto current = json::array({source_record()});
    const auto old_archive = json{{"data", json::object()}};
    const auto selected = old_archive.at("data").contains("subscriptions")
        ? old_archive.at("data").at("subscriptions") : current;
    const auto retained = reconcile_subscription_backup(selected, nullptr);
    CHECK(retained.size() == 1);
    CHECK(retained[0].at("transport_tags").empty());
    CHECK(reconcile_subscription_backup(json::array(), transports()).empty());
}

TEST_CASE("subscription backup rejects unsupported wrappers and duplicate source identity") {
    rejects_without_secrets(nullptr);
    rejects_without_secrets(json{{"version", 1}, {"subscriptions", json::array()}});
    auto records = json::array({source_record(), source_record()});
    rejects_without_secrets(records);
    records[1]["id"] = "another-id";
    rejects_without_secrets(records); // Duplicate URL with another ID.
    records[1]["url"] = "https://provider.example/other";
    records[1]["id"] = records[0]["id"];
    rejects_without_secrets(records); // Duplicate ID with another URL.
}

TEST_CASE("subscription backup validates optional fields and all private collections") {
    const auto valid = json::array({source_record()});
    for (const char* field : {"name", "provider_name", "source_host", "name_is_custom",
             "transport_tags", "_bindings", "_inventory", "_known_candidates",
             "_pending_candidates", "checked_at", "pending_servers_revision"}) {
        auto malformed = valid;
        malformed[0][field] = nullptr;
        rejects_without_secrets(malformed);
    }
    for (const auto interval : {-1, 1, 3599, 604801}) {
        auto malformed = valid;
        malformed[0]["refresh_interval_seconds"] = interval;
        rejects_without_secrets(malformed);
    }
    for (const auto interval : {0, 3600, 21600, 604800}) {
        auto accepted = valid;
        accepted[0]["refresh_interval_seconds"] = interval;
        CHECK(validated_subscription_backup(accepted) == accepted);
    }
    auto malformed = valid;
    malformed[0]["checked_at"] = std::numeric_limits<std::uint64_t>::max();
    rejects_without_secrets(malformed);
    malformed = valid;
    malformed[0]["error"] = backup_url;
    rejects_without_secrets(malformed);
    malformed = valid;
    malformed[0]["url"] = "file:///private-backup-token";
    rejects_without_secrets(malformed);
    malformed = valid;
    malformed[0]["_bindings"][0]["tag"] = "not_linked";
    rejects_without_secrets(malformed);
    malformed = valid;
    malformed[0]["_bindings"].push_back(malformed[0]["_bindings"][0]);
    rejects_without_secrets(malformed);
    malformed = valid;
    malformed[0]["_inventory"][0]["fingerprint"] = "private-backup-token";
    rejects_without_secrets(malformed);
}

TEST_CASE("subscription backup is bounded by the existing store source and inventory limits") {
    auto records = json::array();
    for (unsigned index = 0; index < 64; ++index) {
        auto record = source_record();
        record["id"] = "source-" + std::to_string(index);
        record["url"] = backup_url + std::to_string(index);
        records.push_back(record);
    }
    CHECK(validated_subscription_backup(records).size() == 64);
    auto extra = source_record();
    extra["id"] = "source-64";
    extra["url"] = backup_url + "64";
    records.push_back(extra);
    rejects_without_secrets(records);
    auto oversized = json::array({source_record()});
    oversized[0]["name"] = std::string(4U * 1024U * 1024U, 'x');
    rejects_without_secrets(oversized);
    for (const char* field : {"transport_tags", "_bindings", "_inventory",
                              "_known_candidates", "_pending_candidates"}) {
        auto malformed = json::array({source_record()});
        const auto example = malformed[0][field][0];
        malformed[0][field] = json::array();
        for (unsigned index = 0; index < 513; ++index)
            malformed[0][field].push_back(example);
        rejects_without_secrets(malformed);
    }
}

TEST_CASE("subscription restore rejects malformed transport evidence instead of guessing") {
    const auto records = json::array({source_record()});
    for (const auto& malformed : {json::object(),
            json{{"transports", "private-backup-token"}},
            json{{"transports", json::array({transports()["transports"][0], transports()["transports"][0]})}}})
        CHECK_THROWS_WITH_AS(reconcile_subscription_backup(records, malformed),
                            "invalid subscription backup", std::invalid_argument);
}

TEST_CASE("subscription restore accepts the legacy transport array format") {
    const auto records = json::array({source_record()});
    CHECK(reconcile_subscription_backup(records, transports().at("transports")) == records);
    const auto restored = reconcile_subscription_backup(records, json::array());
    CHECK(restored.size() == 1);
    CHECK(restored[0].at("transport_tags").empty());
}

TEST_CASE("subscription backup retains opaque metadata extensions inside the private size bound") {
    auto records = json::array({source_record()});
    records[0]["future_provider_metadata"] = {{"opaque", json::array({1, true, "private-backup-token"})}};
    records[0]["_inventory"][0]["future_inventory_metadata"] = "preserved";
    records[0]["_bindings"][0]["future_binding_metadata"] = {{"revision", 2}};
    CHECK(validated_subscription_backup(records) == records);
    CHECK(reconcile_subscription_backup(records, transports()) == records);
}
