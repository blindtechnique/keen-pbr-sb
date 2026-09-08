#include <doctest/doctest.h>
#include "../src/config/subscription_refresh.hpp"
#include "../src/update/maintenance_lock.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <functional>
#include <unistd.h>

using namespace keen_pbr3;
namespace {
using json = nlohmann::json;
const std::string source_url = "https://provider.example/sub/private-source-token";
const std::string old_link = "vless://old-credential@one.example:443#Primary";
const std::string changed_link = "vless://new-credential@two.example:8443#Primary";
const std::string new_link = "trojan://private-password@new.example:443#New%20server";

struct RefreshDirectory {
    std::filesystem::path path;
    std::shared_ptr<SubscriptionStore> store;
    RefreshDirectory() {
        char name[] = "/tmp/kpbr-subscription-refresh-XXXXXX";
        const auto created = ::mkdtemp(name);
        REQUIRE(created != nullptr);
        path = created;
        store = std::make_shared<SubscriptionStore>((path / "subscriptions.json").string());
    }
    ~RefreshDirectory() { std::filesystem::remove_all(path); }
};

json save_source(const std::shared_ptr<SubscriptionStore>& store, const std::string& body,
                 std::int64_t now, const std::map<std::size_t, std::string>& links = {}) {
    const auto plan = plan_subscription_import(body, {}, {});
    std::vector<std::string> tags;
    for (const auto& [_, tag] : links) tags.push_back(tag);
    return store->save(source_url, "My provider", subscription_refresh_metadata(body, plan, now),
                       tags, subscription_import_bindings(plan, links));
}

std::string file_contents(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
}

TEST_CASE("subscription background refresh chooses one due source and respects persisted interval") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto first = directory.store->save(source_url, "One", {{"checked_at", 100}}, {});
    const auto second = directory.store->save("https://other.example/sub", "Two", {{"checked_at", 80}}, {});
    CHECK(first.at("refresh_interval_seconds") == 21600);
    CHECK(first.at("next_check_at") == 21700);
    unsigned fetches = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        ++fetches; return SubscriptionFetchResult(old_link);
    }, {}, {}, [&] { return now; });
    CHECK_FALSE(service.refresh_due_once().has_value());
    now = 21701;
    REQUIRE(service.refresh_due_once().has_value());
    CHECK(directory.store->find(second.at("id")).at("checked_at") == now);
    CHECK(directory.store->find(first.at("id")).at("checked_at") == 100);
    CHECK(service.refresh_due_once()->at("id") == first.at("id"));
    CHECK_FALSE(service.refresh_due_once().has_value());
    CHECK(fetches == 2);

    const auto disabled = directory.store->set_refresh_interval(first.at("id"), 0);
    CHECK_FALSE(disabled.contains("next_check_at"));
    SubscriptionStore reopened((directory.path / "subscriptions.json").string());
    CHECK(reopened.find(first.at("id")).at("refresh_interval_seconds") == 0);
    directory.store->set_refresh_interval(second.at("id"), 604800);
    now += 21600;
    CHECK_FALSE(service.refresh_due_once().has_value());
    service.refresh(first.at("id"));
    CHECK(fetches == 3); // Explicit refresh still works when automation is off.
    CHECK_THROWS_AS(directory.store->set_refresh_interval(first.at("id"), 3599), std::invalid_argument);
    CHECK_THROWS_AS(directory.store->set_refresh_interval(first.at("id"), 604801), std::invalid_argument);
}

TEST_CASE("subscription new servers stay proposed until explicit import and revision is stable") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = save_source(directory.store, old_link, now, {{1, "my_alias"}});
    const auto id = source.at("id").get<std::string>();
    std::string body = old_link + "\n" + new_link;
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) { return SubscriptionFetchResult(body); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; }, {}, [&] { return ++now; });
    const auto first = service.refresh(id);
    CHECK(first.at("pending_new_servers_count") == 1);
    const auto revision = first.at("pending_servers_revision");
    CHECK(service.refresh(id).at("pending_servers_revision") == revision);
    CHECK(applies == 0);
    const auto plan = plan_subscription_import(body, {}, {});
    const auto private_source = directory.store->find(id);
    CHECK_FALSE(subscription_candidate_pending(private_source, plan, 0));
    CHECK(subscription_candidate_pending(private_source, plan, 1));
    const auto imported = save_source(directory.store, body, ++now, {{2, "chosen_new_alias"}});
    CHECK(imported.at("pending_new_servers_count") == 0);
    CHECK(imported.at("pending_servers_revision") != revision);
    CHECK(service.refresh(id).at("pending_new_servers_count") == 0);
    CHECK(applies == 0);
    CHECK(imported.at("transport_tags").size() == 2);
}

TEST_CASE("subscription refresh applies changed existing parameters once and never leaks links") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = save_source(directory.store, old_link, now, {{1, "user_custom_alias"}});
    const auto id = source.at("id").get<std::string>();
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        return SubscriptionFetchResult(changed_link + "\n" + new_link);
    }, [&](const std::vector<SubscriptionTransportUpdate>& batch) {
        ++applies;
        REQUIRE(batch.size() == 1);
        CHECK(batch[0].tag == "user_custom_alias");
        CHECK(batch[0].link == changed_link);
        CHECK(batch[0].previous_fingerprint == subscription_link_fingerprint(old_link));
        CHECK(batch[0].next_fingerprint == subscription_link_fingerprint(changed_link));
        return SubscriptionUpdateResult{{batch[0].tag}, {}};
    }, {}, [&] { return ++now; });
    const auto result = service.refresh(id);
    CHECK(applies == 1);
    CHECK(result.at("pending_new_servers_count") == 1);
    CHECK_FALSE(result.contains("last_sync_error"));
    service.refresh(id);
    CHECK(applies == 1);
    const auto public_body = directory.store->list().dump();
    CHECK(public_body.find("private-source-token") == std::string::npos);
    CHECK(public_body.find("new-credential") == std::string::npos);
    CHECK(public_body.find(subscription_link_fingerprint(changed_link)) == std::string::npos);
    CHECK(public_body.find("_bindings") == std::string::npos);
    const auto stored = file_contents(directory.path / "subscriptions.json");
    CHECK(stored.find(changed_link) == std::string::npos);
    CHECK(stored.find("new-credential") == std::string::npos);
    CHECK(stored.find("private-password") == std::string::npos);
    CHECK(directory.store->find(id).at("_bindings")[0].at("tag") == "user_custom_alias");
}

TEST_CASE("subscription refresh detaches confirmed absent VPNs without recreating or proposing them") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link + "\n" + new_link, 100,
                                    {{1, "deleted_vpn"}, {2, "kept_vpn"}});
    const auto id = source.at("id").get<std::string>();
    unsigned applies = 0;
    unsigned reads = 0;
    auto now = std::int64_t{100};
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) { return SubscriptionFetchResult(changed_link + "\n" + new_link); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; },
        [&] {
            ++reads;
            return std::vector<SubscriptionTransportState>{{"kept_vpn", subscription_link_fingerprint(new_link)}};
        }, [&] { return ++now; });
    const auto result = service.refresh(id);
    CHECK(result.at("transport_tags") == json::array({"kept_vpn"}));
    CHECK(result.at("pending_new_servers_count") == 0);
    CHECK_FALSE(result.contains("last_sync_error"));
    const auto record = directory.store->find(id);
    REQUIRE(record.at("_bindings").size() == 1);
    CHECK(record.at("_bindings")[0].at("tag") == "kept_vpn");
    CHECK(record.at("url") == source_url);
    CHECK(record.at("name") == "My provider");
    CHECK(reads == 1);
    CHECK(service.refresh(id).at("pending_new_servers_count") == 0);
    CHECK(applies == 0);
}

TEST_CASE("subscription refresh accepts confirmed empty manager inventory and clears legacy links") {
    RefreshDirectory directory;
    const auto source = directory.store->save(source_url, "Legacy", {{"checked_at", 100}}, {"deleted_vpn"});
    const auto id = source.at("id").get<std::string>();
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) { return SubscriptionFetchResult(old_link); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; },
        [] { return std::vector<SubscriptionTransportState>{}; }, [] { return 101; });
    const auto result = service.refresh(id);
    CHECK(result.at("transport_tags").empty());
    CHECK(directory.store->find(id).at("_bindings").empty());
    CHECK(result.at("pending_new_servers_count") == 0);
    CHECK_FALSE(result.contains("last_sync_error"));
    CHECK(applies == 0);
}

TEST_CASE("subscription refresh never infers deletion from missing fingerprint or unavailable manager") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    const auto original = directory.store->find(id);
    bool unavailable = false;
    std::string fingerprint;
    SUBCASE("existing nonimportable transport") {}
    SUBCASE("manually edited transport") { fingerprint = "user-modified-fingerprint"; }
    SUBCASE("manager unavailable") { unavailable = true; }
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) { return SubscriptionFetchResult(old_link); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; },
        [&]() -> std::vector<SubscriptionTransportState> {
            if (unavailable) throw std::runtime_error("unavailable");
            return {{"vpn1", fingerprint}};
        }, [] { return 101; });
    const auto result = service.refresh(id);
    CHECK(result.at("transport_tags") == original.at("transport_tags"));
    CHECK(directory.store->find(id).at("_bindings") == original.at("_bindings"));
    CHECK(applies == 0);
    if (unavailable) CHECK(result.at("last_sync_error") == "transport_unavailable");
    else CHECK_FALSE(result.contains("last_sync_error"));
}

TEST_CASE("subscription detached during HTTP is not relinked by the completed refresh") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) {
            CHECK(directory.store->detach_transport("vpn1"));
            return SubscriptionFetchResult(changed_link);
        }, [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; }, {}, [] { return 101; });
    const auto result = service.refresh(id);
    CHECK(result.at("transport_tags").empty());
    CHECK(directory.store->find(id).at("_bindings").empty());
    CHECK(result.at("pending_new_servers_count") == 0);
    CHECK_FALSE(result.contains("last_sync_error"));
    CHECK(applies == 0);
}

TEST_CASE("subscription disappearance and ambiguous names never overwrite an existing VPN") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = save_source(directory.store, old_link, now, {{1, "old_alias"}});
    const auto id = source.at("id").get<std::string>();
    std::string body = new_link;
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) { return SubscriptionFetchResult(body); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; }, {}, [&] { return ++now; });
    CHECK(service.refresh(id).at("pending_new_servers_count") == 1);
    CHECK(directory.store->find(id).at("_bindings").size() == 1);
    CHECK(directory.store->find(id).at("transport_tags")[0] == "old_alias");
    body = changed_link + "\nvless://other@another.example:443#Primary";
    CHECK(service.refresh(id).at("pending_new_servers_count") == 2);
    CHECK(applies == 0);
}

TEST_CASE("subscription remark-only rename keeps its existing VPN out of pending proposals") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = save_source(directory.store, old_link, now, {{1, "my_alias"}});
    const auto id = source.at("id").get<std::string>();
    std::string body = "vless://old-credential@one.example:443#Renamed";
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) { return SubscriptionFetchResult(body); },
        [&](const auto& batch) {
            ++applies;
            REQUIRE(batch.size() == 1);
            CHECK(batch[0].tag == "my_alias");
            return SubscriptionUpdateResult{{batch[0].tag}, {}};
        }, {}, [&] { return ++now; });
    CHECK(service.refresh(id).at("pending_new_servers_count") == 0);
    CHECK(applies == 0);
    const auto plan = plan_subscription_import(body, {}, {});
    auto stored = directory.store->find(id);
    CHECK(stored.at("_bindings")[0].at("key") == subscription_candidate_key(plan, 0));
    CHECK_FALSE(subscription_candidate_pending(stored, plan, 0));
    CHECK(service.refresh(id).at("pending_new_servers_count") == 0);
    CHECK(applies == 0);
    body = "vless://new-credential@two.example:8443#Renamed";
    CHECK(service.refresh(id).at("pending_new_servers_count") == 0);
    CHECK(applies == 1);
    CHECK(directory.store->find(id).at("transport_tags")[0] == "my_alias");
}

TEST_CASE("legacy source bootstraps bindings only from actual imported fingerprints") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = directory.store->save(source_url, "Legacy", {{"checked_at", now}}, {"legacy_alias"});
    const auto id = source.at("id").get<std::string>();
    std::string body = old_link + "\n" + new_link;
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) { return SubscriptionFetchResult(body); },
        [&](const auto& batch) { ++applies; return SubscriptionUpdateResult{{batch.at(0).tag}, {}}; },
        [&] { return std::vector<SubscriptionTransportState>{{"legacy_alias", subscription_link_fingerprint(old_link)}}; },
        [&] { return ++now; });
    const auto initial = service.refresh(id);
    CHECK(initial.at("pending_new_servers_count") == 0);
    CHECK_FALSE(initial.contains("last_sync_error"));
    CHECK(directory.store->find(id).at("_bindings").size() == 1);
    body = changed_link + "\n" + new_link;
    service.refresh(id);
    CHECK(applies == 1);
}

TEST_CASE("subscription failed refresh preserves provider limits and failed apply retries existing binding") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = save_source(directory.store, old_link, now, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    directory.store->refresh(id, {{"checked_at", now}, {"updated_at", now}, {"total_bytes", 1000}});
    bool fail_fetch = true;
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        if (fail_fetch) throw std::runtime_error("private-password in provider response");
        return SubscriptionFetchResult(changed_link);
    }, [&](const auto&) { ++applies; return SubscriptionUpdateResult{{}, "secret raw callback message"}; },
        {}, [&] { return ++now; });
    const auto failed = service.refresh(id);
    CHECK(failed.at("total_bytes") == 1000);
    CHECK(failed.at("updated_at") == 100);
    CHECK(failed.at("error") == "fetch_failed");
    CHECK(failed.dump().find("private-password") == std::string::npos);
    fail_fetch = false;
    CHECK(service.refresh(id).at("last_sync_error") == "apply_failed");
    CHECK(directory.store->find(id).at("_bindings")[0].at("fingerprint") == subscription_link_fingerprint(old_link));
    CHECK(service.refresh(id).at("last_sync_error") == "apply_failed");
    CHECK(applies == 2);
}

TEST_CASE("subscription refresh allows metadata edits during fetch and never resurrects a removed source") {
    RefreshDirectory directory;
    auto now = std::int64_t{100};
    const auto source = save_source(directory.store, old_link, now, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    bool remove = false;
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        if (remove) directory.store->erase(id);
        else {
            directory.store->rename(id, "Edited while downloading");
            directory.store->set_refresh_interval(id, 3600);
        }
        return SubscriptionFetchResult(changed_link);
    }, [&](const auto& batch) { ++applies; return SubscriptionUpdateResult{{batch[0].tag}, {}}; },
        {}, [&] { return ++now; });
    const auto result = service.refresh(id);
    CHECK(result.at("name") == "Edited while downloading");
    CHECK(result.at("refresh_interval_seconds") == 3600);
    CHECK(applies == 1);
    remove = true;
    CHECK_THROWS_AS(service.refresh(id), std::out_of_range);
    CHECK(directory.store->list().empty());
    CHECK(applies == 1);
}

TEST_CASE("subscription usage cycle advances once when provider counters reset") {
    RefreshDirectory directory;
    const auto first = directory.store->save(source_url, "Plan",
        {{"checked_at", 100}, {"upload_bytes", 200}, {"download_bytes", 700}}, {});
    const auto id = first.at("id").get<std::string>();
    CHECK(first.at("usage_cycle") == 0);
    auto reset = json{{"checked_at", 200}, {"upload_bytes", 0}, {"download_bytes", 100}};
    CHECK(directory.store->refresh(id, reset).at("usage_cycle") == 1);
    reset["checked_at"] = 300;
    CHECK(directory.store->refresh(id, reset).at("usage_cycle") == 1);
    CHECK(directory.store->refresh(id, {{"checked_at", 400}, {"error", "fetch_failed"}}).at("usage_cycle") == 1);
    CHECK(directory.store->refresh(id, {{"checked_at", 50}, {"upload_bytes", 0}, {"download_bytes", 0}}).at("usage_cycle") == 1);
    CHECK(directory.store->find(id).at("checked_at") == 400);
}

namespace {
struct RefreshAccessLease final : MaintenanceLease {
    bool& held;
    unsigned& reserves;
    std::function<void()> on_release;
    RefreshAccessLease(bool& is_held, unsigned& reserve_count, std::function<void()> released = {})
        : held(is_held), reserves(reserve_count), on_release(std::move(released)) {
        CHECK_FALSE(held);
        held = true;
    }
    ~RefreshAccessLease() override {
        if (on_release) on_release();
        held = false;
    }
    std::uint32_t base_generation() const noexcept override { return 5; }
    std::uint32_t reserve(std::uint32_t expected) override {
        CHECK(held);
        CHECK(expected == 5);
        ++reserves;
        return 6;
    }
    void verify_held() override { CHECK(held); }
};
}

TEST_CASE("subscription late HTTP result cannot overwrite another completed refresh") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    bool outer_automatic = false;
    bool inner_automatic = false;
    bool same_second = false;
    bool late_failure = false;
    SUBCASE("manual response arrives after automatic refresh") { inner_automatic = true; }
    SUBCASE("automatic response arrives after manual refresh") { outer_automatic = true; }
    SUBCASE("both refreshes start within the same clock second") { same_second = true; }
    SUBCASE("late failed response cannot replace successful provider metadata") { late_failure = true; }

    auto now = std::int64_t{21701};
    bool held = false;
    unsigned reserves = 0;
    unsigned applies = 0;
    unsigned reads = 0;
    unsigned acquisitions = 0;
    auto running_fingerprint = subscription_link_fingerprint(old_link);
    const auto latest_fingerprint = subscription_link_fingerprint(changed_link);
    auto access = [&]() -> std::unique_ptr<MaintenanceLease> {
        ++acquisitions;
        return std::make_unique<RefreshAccessLease>(held, reserves);
    };
    auto apply = [&](const std::vector<SubscriptionTransportUpdate>& updates) {
        CHECK(held);
        REQUIRE(updates.size() == 1);
        CHECK(updates[0].link == changed_link);
        CHECK(updates[0].previous_fingerprint == running_fingerprint);
        running_fingerprint = updates[0].next_fingerprint;
        ++applies;
        return SubscriptionUpdateResult{{updates[0].tag}, {}};
    };
    auto read = [&] {
        CHECK(held);
        ++reads;
        return std::vector<SubscriptionTransportState>{{"vpn1", running_fingerprint}};
    };
    SubscriptionRefreshService latest(directory.store, [&](const auto&) {
        CHECK_FALSE(held);
        SubscriptionFetchResult fetched(changed_link + "\n" + new_link);
        fetched.headers["subscription-userinfo"] = "upload=20; download=300; total=1000";
        return fetched;
    }, apply, read, [&] { return now; }, access);

    json latest_result;
    std::string latest_file;
    SubscriptionRefreshService delayed(directory.store, [&](const auto&) -> SubscriptionFetchResult {
        CHECK_FALSE(held);
        if (!same_second) ++now;
        if (inner_automatic) {
            const auto result = latest.refresh_due_once();
            REQUIRE(result.has_value());
            latest_result = *result;
        } else latest_result = latest.refresh(id);
        latest_file = file_contents(directory.path / "subscriptions.json");
        CHECK(running_fingerprint == latest_fingerprint);
        // A completed newer request is followed by delivery of A's old body.
        // No threads, sleeps or wall-clock ordering are needed for this race.
        if (!same_second) ++now;
        if (late_failure) throw std::runtime_error("delayed fetch failure");
        return SubscriptionFetchResult(old_link);
    }, apply, read, [&] { return now; }, access);

    json result;
    if (outer_automatic) {
        const auto automatic = delayed.refresh_due_once();
        REQUIRE(automatic.has_value());
        result = *automatic;
    } else result = delayed.refresh(id);
    CHECK(result == latest_result);
    CHECK(result.at("checked_at") == (same_second ? 21701 : 21702));
    CHECK(result.at("pending_new_servers_count") == 1);
    CHECK(result.at("total_bytes") == 1000);
    CHECK_FALSE(result.contains("error"));
    CHECK(running_fingerprint == latest_fingerprint);
    CHECK(file_contents(directory.path / "subscriptions.json") == latest_file);
    CHECK(applies == 1);
    CHECK(reads == 1);
    CHECK(reserves == 1);
    CHECK(acquisitions == 2);
    CHECK_FALSE(held);
}

TEST_CASE("subscription late HTTP result cannot overwrite same URL backup state") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    auto restored = directory.store->find(id);
    SUBCASE("restore replaces the existing VPN binding without changing URL or checked time") {
        const auto plan = plan_subscription_import(changed_link, {}, {});
        restored["_bindings"] = subscription_import_bindings(plan, {{1, "vpn1"}});
    }
    SUBCASE("restore retains URL and binding but replaces older provider metadata") {
        restored["checked_at"] = 80;
        restored["total_bytes"] = 7000;
    }
    restored["name"] = "Restored source";
    bool held = false;
    unsigned reserves = 0;
    unsigned applies = 0;
    unsigned reads = 0;
    const auto restored_file = json::array({restored}).dump();
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        CHECK_FALSE(held);
        return SubscriptionFetchResult("vless://delayed@old.example:443#Primary");
    }, [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; },
    [&] { ++reads; return std::vector<SubscriptionTransportState>{}; }, [] { return 101; },
    [&]() -> std::unique_ptr<MaintenanceLease> {
        // Real backup restore replaces the raw file while owning maintenance
        // and the existing store mutex; no persisted revision is introduced.
        {
            auto backup_lock = directory.store->lock_for_backup();
            std::ofstream output(directory.path / "subscriptions.json");
            REQUIRE(output.good());
            output << restored_file;
            output.close();
            REQUIRE(output.good());
        }
        return std::make_unique<RefreshAccessLease>(held, reserves);
    });
    CHECK(service.refresh(id) == public_subscription(restored));
    CHECK(directory.store->find(id) == restored);
    CHECK(file_contents(directory.path / "subscriptions.json") == restored_file);
    CHECK(applies == 0);
    CHECK(reads == 0);
    CHECK(reserves == 0);
    CHECK_FALSE(held);
}

TEST_CASE("subscription refresh timestamps the attempt before receiving HTTP") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100);
    auto now = std::int64_t{101};
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        now = 200;
        return SubscriptionFetchResult(old_link);
    }, {}, {}, [&] { return now; });
    const auto result = service.refresh(source.at("id").get<std::string>());
    CHECK(result.at("checked_at") == 101);
    CHECK(result.at("updated_at") == 101);
}

TEST_CASE("subscription refresh holds existing maintenance from fresh read through apply and commit") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    bool held = false;
    unsigned reserves = 0;
    unsigned applies = 0;
    bool committed_before_release = false;
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        CHECK_FALSE(held); // HTTP is outside the lease and metadata mutex.
        auto lock = directory.store->lock_for_backup();
        CHECK(lock.owns_lock());
        return SubscriptionFetchResult(changed_link);
    }, [&](const auto& updates) {
        CHECK(held);
        CHECK(reserves == 1);
        ++applies;
        return SubscriptionUpdateResult{{updates.at(0).tag}, {}};
    }, {}, [] { return 101; }, [&]() -> std::unique_ptr<MaintenanceLease> {
        return std::make_unique<RefreshAccessLease>(held, reserves, [&] {
            const auto record = directory.store->find(id);
            committed_before_release = record.at("checked_at") == 101 &&
                record.at("_bindings")[0].at("fingerprint") == subscription_link_fingerprint(changed_link);
        });
    });
    CHECK(service.refresh(id).at("checked_at") == 101);
    CHECK_FALSE(held);
    CHECK(applies == 1);
    CHECK(reserves == 1);
    CHECK(committed_before_release);
}

TEST_CASE("subscription refresh rereads restored bindings only after acquiring maintenance") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    bool held = false;
    unsigned reserves = 0;
    unsigned applies = 0;
    unsigned acquisitions = 0;
    SubscriptionRefreshService service(directory.store, [&](const auto&) {
        CHECK_FALSE(held);
        return SubscriptionFetchResult(changed_link);
    }, [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; }, {}, [] { return 101; },
    [&]() -> std::unique_ptr<MaintenanceLease> {
        ++acquisitions;
        // A restore wins maintenance while HTTP is in flight and removes only
        // the VPN composition. The just-fetched response must see that result.
        directory.store->refresh(id, {{"transport_tags", json::array()}, {"_bindings", json::array()}});
        directory.store->rename(id, "Restored source");
        directory.store->set_refresh_interval(id, 0);
        return std::make_unique<RefreshAccessLease>(held, reserves);
    });
    const auto refreshed = service.refresh(id);
    CHECK(acquisitions == 1);
    CHECK(applies == 0);
    CHECK(reserves == 0);
    CHECK(refreshed.at("name") == "Restored source");
    CHECK(refreshed.at("refresh_interval_seconds") == 0);
    CHECK(refreshed.at("transport_tags").empty());
    CHECK(directory.store->find(id).at("_bindings").empty());
}

TEST_CASE("subscription failed fetch commits under maintenance without reserving config generation") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100);
    const auto id = source.at("id").get<std::string>();
    bool held = false;
    unsigned reserves = 0;
    bool committed_before_release = false;
    SubscriptionRefreshService service(directory.store, [&](const auto&) -> SubscriptionFetchResult {
        CHECK_FALSE(held);
        throw std::runtime_error("private-source-token");
    }, {}, {}, [] { return 101; }, [&]() -> std::unique_ptr<MaintenanceLease> {
        return std::make_unique<RefreshAccessLease>(held, reserves, [&] {
            committed_before_release = directory.store->find(id).value("error", "") == "fetch_failed";
        });
    });
    CHECK(service.refresh(id).at("error") == "fetch_failed");
    CHECK(reserves == 0);
    CHECK(committed_before_release);
    CHECK_FALSE(held);
}

TEST_CASE("subscription refresh cannot use an old response for a restored different source URL") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    bool held = false;
    unsigned reserves = 0;
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) { return SubscriptionFetchResult(changed_link); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; }, {}, [] { return 101; },
        [&]() -> std::unique_ptr<MaintenanceLease> {
            directory.store->refresh(id, {{"url", "https://provider.example/sub/restored-source"}});
            return std::make_unique<RefreshAccessLease>(held, reserves);
        });
    CHECK(service.refresh(id).at("checked_at") == 100);
    CHECK(applies == 0);
    CHECK(reserves == 0);
    CHECK(directory.store->find(id).at("_bindings")[0].at("fingerprint") == subscription_link_fingerprint(old_link));
}

TEST_CASE("subscription refresh does not write if required maintenance access is unavailable") {
    RefreshDirectory directory;
    const auto source = save_source(directory.store, old_link, 100, {{1, "vpn1"}});
    const auto id = source.at("id").get<std::string>();
    const auto before = file_contents(directory.path / "subscriptions.json");
    unsigned applies = 0;
    SubscriptionRefreshService service(directory.store,
        [&](const auto&) { return SubscriptionFetchResult(changed_link); },
        [&](const auto&) { ++applies; return SubscriptionUpdateResult{}; }, {}, [] { return 101; },
        []() -> std::unique_ptr<MaintenanceLease> { return {}; });
    CHECK_THROWS_WITH_AS(service.refresh(id), "subscription refresh access unavailable", std::runtime_error);
    CHECK(applies == 0);
    CHECK(file_contents(directory.path / "subscriptions.json") == before);
}
