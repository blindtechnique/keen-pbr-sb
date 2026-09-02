#include <doctest/doctest.h>

#include "../src/keenetic/ndms_running_config_resource.hpp"
#include "../src/keenetic/ndms_vpn_server_service_cache.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

class PromiseRelease {
public:
    explicit PromiseRelease(std::promise<void>& promise)
        : promise_(promise) {}
    ~PromiseRelease() { release(); }

    void release() {
        if (!released_) {
            promise_.set_value();
            released_ = true;
        }
    }

private:
    std::promise<void>& promise_;
    bool released_{false};
};

std::string running_config(unsigned int port = 80U) {
    return std::string{
               R"({"status":"ok","message":["service http","ip http port )"} +
        std::to_string(port) + R"(","interface Wireguard5"]})";
}

TEST_CASE("running-config cold readers share one fetch and one snapshot") {
    std::atomic<int> calls{0};
    std::promise<void> fetch_started;
    auto fetch_started_future = fetch_started.get_future();
    std::promise<void> release_fetch;
    const auto release_signal = release_fetch.get_future().share();
    NdmsRunningConfigResource resource([&] {
        if (calls.fetch_add(1, std::memory_order_acq_rel) == 0) {
            fetch_started.set_value();
            release_signal.wait();
        }
        return running_config();
    });

    std::optional<std::future<NdmsRunningConfigSnapshot>> first;
    std::optional<std::future<NdmsRunningConfigSnapshot>> second;
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
    REQUIRE(left.document);
    REQUIRE(right.document);
    CHECK(left.document == right.document);
    CHECK(left.content_generation == 1U);
    CHECK(right.content_generation == 1U);
    CHECK(left.status == NdmsCatalogCacheStatus::fresh);
    CHECK(right.status == NdmsCatalogCacheStatus::fresh);
    CHECK(calls.load(std::memory_order_acquire) == 1);
}

TEST_CASE("running-config peek is cache-only during a stalled refresh") {
    std::atomic<int> calls{0};
    std::promise<void> refresh_started;
    auto refresh_started_future = refresh_started.get_future();
    std::promise<void> release_refresh;
    const auto release_signal = release_refresh.get_future().share();
    NdmsRunningConfigResource resource(
        [&] {
            const auto call =
                calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (call == 2) {
                refresh_started.set_value();
                release_signal.wait();
            }
            return running_config(call == 1 ? 80U : 8080U);
        });

    const auto initial = resource.get();
    REQUIRE(initial.document);
    resource.invalidate();
    std::optional<std::future<NdmsRunningConfigSnapshot>> refresh;
    std::optional<std::future<NdmsRunningConfigSnapshot>> peek;
    std::optional<std::future<NdmsRunningConfigSnapshot>> reader;
    PromiseRelease release_guard(release_refresh);
    refresh.emplace(std::async(std::launch::async, [&] {
        return resource.force_refresh();
    }));
    REQUIRE(refresh_started_future.wait_for(2s) ==
            std::future_status::ready);

    peek.emplace(std::async(std::launch::async, [&] {
        return resource.peek();
    }));
    reader.emplace(std::async(std::launch::async, [&] {
        return resource.get();
    }));
    REQUIRE(peek->wait_for(2s) == std::future_status::ready);
    REQUIRE(reader->wait_for(2s) == std::future_status::ready);
    const auto peeked = peek->get();
    const auto ordinary_reader = reader->get();
    CHECK(peeked.document == initial.document);
    CHECK(ordinary_reader.document == initial.document);
    CHECK(peeked.status == NdmsCatalogCacheStatus::stale);
    CHECK(ordinary_reader.status == NdmsCatalogCacheStatus::stale);
    CHECK(calls.load(std::memory_order_acquire) == 2);

    release_guard.release();
    const auto updated = refresh->get();
    CHECK(updated.changed);
    CHECK(updated.content_generation == 2U);
}

TEST_CASE("semantic no-op advances authority without publication") {
    int calls = 0;
    NdmsRunningConfigResource resource(
        [&] {
            ++calls;
            if (calls == 1) return running_config(80U);
            return std::string{
                "{\n  \"message\" : [ \"service http\", "
                "\"ip http port 80\", \"interface Wireguard5\" ],"
                "\n  \"status\" : \"ok\"\n}"};
        },
        30s,
        0s);

    const auto initial = resource.get();
    REQUIRE(initial.document);
    resource.invalidate();
    const auto verified = resource.force_refresh();

    CHECK(verified.refreshed);
    CHECK_FALSE(verified.changed);
    CHECK(verified.document == initial.document);
    CHECK(verified.content_generation == initial.content_generation);
    CHECK(verified.observation_epoch == 1U);
    CHECK(verified.invalidation_epoch == 1U);
    CHECK(verified.status == NdmsCatalogCacheStatus::fresh);
    CHECK(verified.observation_generation ==
          initial.observation_generation + 1U);

    const auto same_epoch = resource.force_refresh();
    CHECK_FALSE(same_epoch.changed);
    CHECK(same_epoch.content_generation ==
          initial.content_generation);
    CHECK(same_epoch.observation_generation ==
          verified.observation_generation + 1U);
    CHECK(same_epoch.observation_epoch ==
          verified.observation_epoch);
}

TEST_CASE("changed running-config publishes exactly one new generation") {
    int calls = 0;
    NdmsRunningConfigResource resource([&] {
        ++calls;
        return running_config(calls == 1 ? 80U : 8080U);
    });

    const auto initial = resource.get();
    REQUIRE(initial.document);
    resource.invalidate();
    const auto updated = resource.force_refresh();
    REQUIRE(updated.document);
    CHECK(updated.refreshed);
    CHECK(updated.changed);
    CHECK(updated.document != initial.document);
    CHECK(updated.content_generation ==
          initial.content_generation + 1U);

    const auto cached = resource.get();
    CHECK(cached.document == updated.document);
    CHECK(cached.content_generation == updated.content_generation);
    CHECK_FALSE(cached.refreshed);
    CHECK_FALSE(cached.changed);
    CHECK(calls == 2);
}

TEST_CASE("VPN inventory projects the exact shared raw generation") {
    int calls = 0;
    NdmsRunningConfigResource resource([&] {
        ++calls;
        return running_config(calls == 1 ? 80U : 8080U);
    });
    NdmsVpnServerServiceCache inventory(resource);

    const auto raw = resource.get();
    const auto typed = inventory.get();
    REQUIRE(raw.document);
    CHECK(calls == 1);
    CHECK(typed.catalog.firmware_available);
    CHECK(typed.status == NdmsCatalogCacheStatus::fresh);
    CHECK(typed.source_content_generation ==
          raw.content_generation);
    CHECK(typed.source_observation_generation ==
          raw.observation_generation);

    resource.invalidate();
    const auto updated = inventory.force_refresh();
    CHECK(calls == 2);
    CHECK(updated.catalog.firmware_available);
    CHECK(updated.status == NdmsCatalogCacheStatus::fresh);
    CHECK(updated.refreshed);
    CHECK(updated.changed);
    CHECK(updated.source_content_generation ==
          raw.content_generation + 1U);
    CHECK(updated.source_observation_generation !=
          typed.source_observation_generation);
}

TEST_CASE("failures and superseded observations preserve exact LKG") {
    std::atomic<int> calls{0};
    std::promise<void> old_fetch_started;
    auto old_fetch_started_future = old_fetch_started.get_future();
    std::promise<void> release_old_fetch;
    const auto release_signal = release_old_fetch.get_future().share();
    NdmsRunningConfigResource resource(
        [&] {
            const auto call =
                calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (call == 1) {
                old_fetch_started.set_value();
                release_signal.wait();
                return running_config(80U);
            }
            return running_config(8080U);
        },
        30s,
        0s);

    std::optional<std::future<NdmsRunningConfigSnapshot>> old_fetch;
    std::optional<std::future<NdmsRunningConfigSnapshot>> replacement;
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
    CHECK_FALSE(superseded.document);
    REQUIRE(current.document);
    CHECK(current.content_generation == 1U);
    CHECK(current.observation_epoch == 1U);
    CHECK(calls.load(std::memory_order_acquire) == 2);

    NdmsRunningConfigResource failing(
        []() -> std::string {
            throw std::runtime_error("transport");
        },
        30s,
        0s);
    const auto cold_failure = failing.get();
    CHECK_FALSE(cold_failure.document);
    CHECK(cold_failure.status ==
          NdmsCatalogCacheStatus::unavailable);
    CHECK(cold_failure.failure ==
          NdmsRunningConfigFailure::transport_failed);

    int warm_calls = 0;
    NdmsRunningConfigResource warm(
        [&] {
            ++warm_calls;
            if (warm_calls == 1) return running_config();
            if (warm_calls == 2) return std::string{"not-json"};
            if (warm_calls == 3) {
                return std::string(2U * 1024U * 1024U + 1U, 'x');
            }
            if (warm_calls == 4) {
                return std::string{
                    R"({"status":"error","message":["service http"]})"};
            }
            return running_config(8080U);
        },
        30s,
        0s);
    const auto lkg = warm.get();
    REQUIRE(lkg.document);
    warm.invalidate();
    const auto malformed = warm.force_refresh();
    CHECK(malformed.document == lkg.document);
    CHECK(malformed.content_generation == lkg.content_generation);
    CHECK(malformed.status == NdmsCatalogCacheStatus::stale);
    CHECK(malformed.failure ==
          NdmsRunningConfigFailure::malformed_response);

    warm.invalidate();
    const auto oversized = warm.force_refresh();
    CHECK(oversized.document == lkg.document);
    CHECK(oversized.content_generation == lkg.content_generation);
    CHECK(oversized.failure ==
          NdmsRunningConfigFailure::response_too_large);

    warm.invalidate();
    const auto error_envelope = warm.force_refresh();
    CHECK(error_envelope.document == lkg.document);
    CHECK(error_envelope.content_generation ==
          lkg.content_generation);
    CHECK(error_envelope.failure ==
          NdmsRunningConfigFailure::malformed_response);

    warm.invalidate();
    const auto recovered = warm.force_refresh();
    REQUIRE(recovered.document);
    CHECK(recovered.document != lkg.document);
    CHECK(recovered.status == NdmsCatalogCacheStatus::fresh);
    CHECK(recovered.failure == NdmsRunningConfigFailure::none);
    CHECK(recovered.content_generation ==
          lkg.content_generation + 1U);
}

TEST_CASE("invalid typed generation keeps the VPN inventory LKG") {
    int calls = 0;
    NdmsRunningConfigResource resource(
        [&] {
            ++calls;
            if (calls == 1) return running_config();
            return std::string{"{\"message\":[\""} +
                std::string(4097U, 'x') + "\"]}";
        },
        30s,
        0s);
    NdmsVpnServerServiceCache inventory(resource);

    const auto initial = inventory.get();
    REQUIRE(initial.catalog.firmware_available);
    REQUIRE(initial.source_content_generation != 0U);
    resource.invalidate();
    const auto invalid = inventory.force_refresh();
    CHECK(calls == 2);
    CHECK(invalid.catalog.firmware_available);
    CHECK(invalid.status == NdmsCatalogCacheStatus::stale);
    CHECK(invalid.source_content_generation ==
          initial.source_content_generation);

    const auto cached_failure = inventory.peek();
    CHECK(cached_failure.status == NdmsCatalogCacheStatus::stale);
    CHECK(cached_failure.source_content_generation ==
          initial.source_content_generation);
    CHECK(calls == 2);
}

} // namespace
} // namespace keen_pbr3
