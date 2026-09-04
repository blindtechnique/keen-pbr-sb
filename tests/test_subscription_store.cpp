#include <doctest/doctest.h>
#include "../src/config/subscription_store.hpp"
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace keen_pbr3;
namespace {
struct SubscriptionDirectory {
    std::filesystem::path path;
    SubscriptionDirectory() {
        char name[] = "/tmp/kpbr-subscriptions-XXXXXX";
        const auto created = ::mkdtemp(name);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~SubscriptionDirectory() { std::filesystem::remove_all(path); }
};
}

TEST_CASE("subscription provider counters preserve unknown and zero") {
    CHECK(parse_subscription_userinfo("").empty());
    const auto limits = parse_subscription_userinfo(" upload=0; download=120; total=1000; expire=2000000000; junk=x");
    CHECK(limits.at("upload_bytes") == 0);
    CHECK(limits.at("download_bytes") == 120);
    CHECK(limits.at("total_bytes") == 1000);
    CHECK(limits.at("expires_at") == 2000000000);
    const auto unspecified = parse_subscription_userinfo("upload=0; download=0; total=0; expire=0");
    CHECK(unspecified.size() == 2);
    CHECK_FALSE(unspecified.contains("total_bytes"));
    CHECK_FALSE(unspecified.contains("expires_at"));
}

TEST_CASE("subscription provider title accepts plain and base64 names") {
    CHECK(parse_subscription_title(" Тариф VPN ") == "Тариф VPN");
    CHECK(parse_subscription_title("base64:UGxhbg==") == "Plan");
    CHECK(parse_subscription_title("").empty());
    CHECK(parse_subscription_title("base64:!invalid!").empty());
    CHECK(parse_subscription_title("one\ntwo").empty());
}

TEST_CASE("provider name fills subscription names without overwriting a rename") {
    SubscriptionDirectory directory;
    SubscriptionStore store((directory.path / "subscriptions.json").string());
    const std::string url = "https://provider.example/sub";
    const auto initial = store.save(url, "", {{"provider_name", "Provider plan"}}, {"vpn1"});
    const auto id = initial.at("id").get<std::string>();
    CHECK(initial.at("name") == "Provider plan");
    CHECK_FALSE(initial.contains("name_is_custom"));
    CHECK(store.refresh(id, {{"provider_name", "Updated plan"}}).at("name") == "Updated plan");
    CHECK(store.rename(id, "My name").at("name") == "My name");
    CHECK(store.refresh(id, {{"provider_name", "Another plan"}}).at("name") == "My name");
    CHECK(store.save(url, "", {{"provider_name", "Reimported plan"}}, {"vpn2"}).at("name") == "My name");
}

TEST_CASE("subscription header rejects malformed overflowing and ambiguous fields") {
    CHECK(parse_subscription_userinfo("upload=-1; download=1e9; total=999999999999999999999; expire=9007199254740991").empty());
    CHECK(parse_subscription_userinfo("total=100; total=200; total=300").empty());
    CHECK(parse_subscription_userinfo("download=12oops").empty());
}

TEST_CASE("subscription sources persist without exposing their URLs or duplicating tags") {
    SubscriptionDirectory directory;
    const auto path = (directory.path / "subscriptions.json").string();
    SubscriptionStore store(path);
    CHECK(store.list().empty());
    const std::string url = "https://provider.example/sub/private-token?secret=private";
    const auto first = store.save(url, "My plan", {{"checked_at", 100}, {"updated_at", 100}, {"total_bytes", 1000}}, {"vpn1"});
    CHECK_FALSE(first.contains("url"));
    CHECK(first.at("source_host") == "provider.example");
    const auto second = store.save(url, "", {{"checked_at", 101}, {"updated_at", 101}}, {"vpn1", "vpn2"});
    CHECK(second.at("id") == first.at("id"));
    CHECK(second.at("name") == "My plan");
    CHECK(second.at("transport_tags").size() == 2);
    CHECK_FALSE(second.contains("total_bytes"));
    SubscriptionStore reopened(path);
    REQUIRE(reopened.list().size() == 1);
    CHECK(reopened.list().dump().find("private-token") == std::string::npos);
    CHECK(reopened.find(first.at("id")).at("url") == url);
    struct stat status{};
    REQUIRE(::stat(path.c_str(), &status) == 0);
    CHECK((status.st_mode & 0777) == 0600);
    CHECK(reopened.rename(first.at("id"), "New name").at("name") == "New name");
}

TEST_CASE("subscription refresh failure keeps last success and deletion cannot touch VPN files") {
    SubscriptionDirectory directory;
    const auto path = (directory.path / "subscriptions.json").string();
    const auto transports = directory.path / "transports.json";
    { std::ofstream output(transports); output << "unchanged VPN config"; }
    SubscriptionStore store(path);
    const auto created = store.save("https://provider.example/sub", "Plan", {{"checked_at", 100}, {"updated_at", 100}, {"total_bytes", 1000}}, {"vpn1"});
    const auto id = created.at("id").get<std::string>();
    const auto failed = store.refresh(id, {{"checked_at", 200}, {"error", "fetch_failed"}});
    CHECK(failed.at("total_bytes") == 1000);
    CHECK(failed.at("updated_at") == 100);
    CHECK(failed.at("checked_at") == 200);
    store.erase(id);
    CHECK(store.list().empty());
    CHECK_THROWS_AS(store.refresh(id, {{"checked_at", 300}}), std::out_of_range);
    std::ifstream input(transports);
    std::string content; std::getline(input, content);
    CHECK(content == "unchanged VPN config");
}

TEST_CASE("subscription corrupt storage is not overwritten with an empty list") {
    SubscriptionDirectory directory;
    const auto path = (directory.path / "subscriptions.json").string();
    { std::ofstream output(path); output << "broken"; }
    SubscriptionStore store(path);
    CHECK_THROWS(store.save("https://provider.example/sub", "Plan", {{"checked_at", 1}}, {}));
    std::ifstream input(path);
    std::string content; input >> content;
    CHECK(content == "broken");
}
