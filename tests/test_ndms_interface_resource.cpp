#include <doctest/doctest.h>

#include "../src/keenetic/ndms_interface_resource.hpp"
#include "../src/keenetic/ndms_catalog_cache.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <optional>
#include <string>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

class PromiseRelease final {
public:
    explicit PromiseRelease(std::promise<void>& promise)
        : promise_(promise) {}

    ~PromiseRelease() { release(); }

    void release() {
        if (released_) return;
        promise_.set_value();
        released_ = true;
    }

private:
    std::promise<void>& promise_;
    bool released_{false};
};

std::string interface_payload(
    const std::string& address = "192.168.1.1",
    const std::string& description = "Office VPN") {
    return std::string{
               R"({"Bridge0":{"id":"Bridge0","address":")"} +
        address +
        R"(","connected":"yes","global":false,"admin-only":false,"security-level":"private"},"Wireguard5":{"id":"Wireguard5","type":"Wireguard","description":")" +
        description + R"("}})";
}

TEST_CASE("interface resource cold readers share one fetch and snapshot") {
    std::atomic<int> calls{0};
    std::promise<void> fetch_started;
    auto fetch_started_future = fetch_started.get_future();
    std::promise<void> release_fetch;
    const auto release_signal = release_fetch.get_future().share();

    NdmsInterfaceResource resource([&] {
        if (calls.fetch_add(1, std::memory_order_acq_rel) == 0) {
            fetch_started.set_value();
            release_signal.wait();
        }
        return interface_payload();
    });

    // Keep the release guard later than the futures so a failed REQUIRE
    // releases the stand-in fetch before std::future destructors can wait.
    std::optional<std::future<NdmsInterfaceSnapshot>> first;
    std::optional<std::future<NdmsInterfaceSnapshot>> second;
    PromiseRelease release_guard(release_fetch);

    first.emplace(std::async(std::launch::async, [&] {
        return resource.get();
    }));
    REQUIRE(fetch_started_future.wait_for(2s) ==
            std::future_status::ready);
    second.emplace(std::async(std::launch::async, [&] {
        return resource.get();
    }));
    CHECK(calls.load(std::memory_order_acquire) == 1);

    release_guard.release();
    const auto left = first->get();
    const auto right = second->get();
    REQUIRE_UNARY(static_cast<bool>(left.document));
    REQUIRE_UNARY(static_cast<bool>(right.document));
    CHECK_UNARY(left.document == right.document);
    CHECK(left.content_generation == 1U);
    CHECK(right.content_generation == 1U);
    CHECK(left.observation_generation == 1U);
    CHECK(right.observation_generation == 1U);
    CHECK(left.status == NdmsCatalogCacheStatus::fresh);
    CHECK(right.status == NdmsCatalogCacheStatus::fresh);
    CHECK(calls.load(std::memory_order_acquire) == 1);
}

TEST_CASE("interface resource semantic no-op advances observation only") {
    int calls = 0;
    NdmsInterfaceResource resource([&] {
        ++calls;
        if (calls == 1) return interface_payload();
        return std::string{
            "{\n  \"Wireguard5\" : { \"description\" : \"Office VPN\", "
            "\"type\" : \"Wireguard\", \"id\" : \"Wireguard5\" },\n"
            "  \"Bridge0\" : { \"security-level\" : \"private\", "
            "\"admin-only\" : false, \"global\" : false, "
            "\"connected\" : \"yes\", \"address\" : \"192.168.1.1\", "
            "\"id\" : \"Bridge0\" }\n}"};
    });

    const auto initial = resource.get();
    REQUIRE_UNARY(static_cast<bool>(initial.document));
    resource.invalidate();
    const auto verified = resource.force_refresh();

    CHECK(calls == 2);
    CHECK(verified.refreshed);
    CHECK_FALSE(verified.changed);
    CHECK_UNARY(verified.document == initial.document);
    CHECK(verified.content_generation == initial.content_generation);
    CHECK(verified.observation_generation ==
          initial.observation_generation + 1U);
    CHECK(verified.observation_epoch == 1U);
    CHECK(verified.invalidation_epoch == 1U);
    CHECK(verified.status == NdmsCatalogCacheStatus::fresh);
}

TEST_CASE("interface resource malformed refresh preserves and recovers LKG") {
    int calls = 0;
    NdmsInterfaceResource resource([&] {
        ++calls;
        if (calls == 1) return interface_payload();
        if (calls == 2) return std::string{"{not-json"};
        return interface_payload("192.168.1.2", "Branch VPN");
    });

    const auto initial = resource.get();
    REQUIRE_UNARY(static_cast<bool>(initial.document));

    resource.invalidate();
    const auto malformed = resource.force_refresh();
    CHECK(calls == 2);
    CHECK_UNARY(malformed.document == initial.document);
    CHECK(malformed.status == NdmsCatalogCacheStatus::stale);
    CHECK_FALSE(malformed.refreshed);
    CHECK_FALSE(malformed.changed);
    CHECK(malformed.content_generation == initial.content_generation);
    CHECK(malformed.observation_generation ==
          initial.observation_generation);

    resource.invalidate();
    const auto recovered = resource.force_refresh();
    REQUIRE_UNARY(static_cast<bool>(recovered.document));
    CHECK(calls == 3);
    CHECK_UNARY(recovered.document != initial.document);
    CHECK(recovered.status == NdmsCatalogCacheStatus::fresh);
    CHECK(recovered.refreshed);
    CHECK(recovered.changed);
    CHECK(recovered.content_generation ==
          initial.content_generation + 1U);
    CHECK(recovered.observation_generation ==
          initial.observation_generation + 1U);
    CHECK(recovered.observation_epoch == 2U);
    CHECK(recovered.invalidation_epoch == 2U);
    CHECK(recovered.document->body().find("192.168.1.2") !=
          std::string_view::npos);
}

TEST_CASE("interface resource rejects superseded in-flight observation") {
    std::atomic<int> calls{0};
    std::promise<void> old_fetch_started;
    auto old_fetch_started_future = old_fetch_started.get_future();
    std::promise<void> release_old_fetch;
    const auto release_signal = release_old_fetch.get_future().share();

    NdmsInterfaceResource resource([&] {
        const auto call =
            calls.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (call == 1) {
            old_fetch_started.set_value();
            release_signal.wait();
            return interface_payload("192.168.1.1", "Pre-event VPN");
        }
        return interface_payload("192.168.1.2", "Post-event VPN");
    });

    std::optional<std::future<NdmsInterfaceSnapshot>> old_fetch;
    std::optional<std::future<NdmsInterfaceSnapshot>> replacement;
    PromiseRelease release_guard(release_old_fetch);

    old_fetch.emplace(std::async(std::launch::async, [&] {
        return resource.get();
    }));
    REQUIRE(old_fetch_started_future.wait_for(2s) ==
            std::future_status::ready);
    resource.invalidate();
    replacement.emplace(std::async(std::launch::async, [&] {
        return resource.force_refresh();
    }));
    release_guard.release();

    const auto superseded = old_fetch->get();
    const auto current = replacement->get();
    CHECK_UNARY_FALSE(static_cast<bool>(superseded.document));
    CHECK(superseded.status == NdmsCatalogCacheStatus::unavailable);
    CHECK_FALSE(superseded.refreshed);
    CHECK(superseded.content_generation == 0U);
    CHECK(superseded.observation_generation == 0U);
    REQUIRE_UNARY(static_cast<bool>(current.document));
    CHECK(current.status == NdmsCatalogCacheStatus::fresh);
    CHECK(current.refreshed);
    CHECK(current.changed);
    CHECK(current.content_generation == 1U);
    CHECK(current.observation_generation == 1U);
    CHECK(current.observation_epoch == 1U);
    CHECK(current.invalidation_epoch == 1U);
    CHECK(current.document->body().find("Post-event VPN") !=
          std::string_view::npos);
    CHECK(calls.load(std::memory_order_acquire) == 2);
}

TEST_CASE("interface catalog projects the exact shared raw observation") {
    int calls = 0;
    NdmsInterfaceResource resource([&] {
        ++calls;
        return interface_payload(
            calls == 1 ? "192.168.1.1" : "192.168.1.2",
            calls == 1 ? "Office VPN" : "Branch VPN");
    });
    NdmsCatalogCache catalog(resource);

    const auto raw = resource.get();
    const auto typed = catalog.get();
    REQUIRE_UNARY(static_cast<bool>(raw.document));
    REQUIRE(typed.catalog.firmware_available);
    REQUIRE(typed.catalog.tunnels.size() == 1U);
    CHECK(calls == 1);
    CHECK(typed.catalog.tunnels.front().label == "Office VPN");
    CHECK(typed.status == NdmsCatalogCacheStatus::fresh);
    CHECK_FALSE(typed.refreshed);
    CHECK(typed.observed_at == raw.observed_at);
    CHECK(typed.observation_generation == raw.observation_generation);
    CHECK(typed.observation_epoch == raw.observation_epoch);

    catalog.invalidate();
    const auto updated = catalog.force_refresh();
    REQUIRE(updated.catalog.tunnels.size() == 1U);
    CHECK(calls == 2);
    CHECK(updated.catalog.tunnels.front().label == "Branch VPN");
    CHECK(updated.status == NdmsCatalogCacheStatus::fresh);
    CHECK(updated.refreshed);
    CHECK(updated.observation_generation ==
          raw.observation_generation + 1U);
    CHECK(updated.observation_epoch == 1U);
    CHECK(updated.invalidation_epoch == 1U);
}

} // namespace
} // namespace keen_pbr3
