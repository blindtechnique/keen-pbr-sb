#include <doctest/doctest.h>

#include "../src/keenetic/ndms_http_config_projection.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

std::string http_config(
    std::string port = "777",
    std::string threshold = "5",
    bool include_policy = true) {
    std::string payload =
        std::string{R"({"port":")"} + port +
        R"(","security-level":{"public":true,"ssl":true})";
    if (include_policy) {
        payload +=
            std::string{R"(,"lockout-policy":{"threshold":")"} +
            threshold +
            R"(","duration":"15","observation-window":"3"})";
    }
    payload += R"(,"ssl":{"enable":true,"port":"5443"}})";
    return payload;
}

TEST_CASE("HTTP config projections share one raw observation") {
    int calls = 0;
    NdmsHttpConfigResource resource([&] {
        ++calls;
        return http_config();
    });
    NdmsHttpServiceConfigCache service(resource);
    NdmsLockoutPolicyCache policy(resource);

    const auto service_snapshot = service.get();
    const auto policy_snapshot = policy.get();

    REQUIRE(service_snapshot.config.has_value());
    REQUIRE(policy_snapshot.policy.has_value());
    CHECK(calls == 1);
    CHECK(service_snapshot.config->enabled);
    CHECK(service_snapshot.config->port == 777U);
    CHECK(policy_snapshot.policy->threshold == 5U);
    CHECK(policy_snapshot.policy->duration == 15min);
    CHECK(policy_snapshot.policy->observation_window == 3min);
    CHECK(service_snapshot.status == NdmsCatalogCacheStatus::fresh);
    CHECK(policy_snapshot.status == NdmsCatalogCacheStatus::fresh);
    CHECK(service_snapshot.source_content_generation == 1U);
    CHECK(policy_snapshot.source_content_generation ==
          service_snapshot.source_content_generation);
    CHECK(policy_snapshot.source_observation_generation ==
          service_snapshot.source_observation_generation);
}

TEST_CASE("HTTP config semantic no-op advances only observation stamps") {
    int calls = 0;
    NdmsHttpConfigResource resource([&] {
        ++calls;
        if (calls == 1) return http_config();
        return std::string{R"({
            "ssl" : { "port" : "5443", "enable" : true },
            "lockout-policy" : {
                "observation-window" : "3", "duration" : "15",
                "threshold" : "5"
            },
            "security-level" : { "ssl" : true, "public" : true },
            "port" : "777"
        })"};
    });
    NdmsHttpServiceConfigCache service(resource);
    NdmsLockoutPolicyCache policy(resource);

    const auto initial_service = service.get();
    const auto initial_policy = policy.get();
    REQUIRE(initial_service.config.has_value());
    REQUIRE(initial_policy.policy.has_value());

    resource.invalidate();
    const auto verified_service = service.force_refresh();
    const auto verified_policy = policy.get();

    REQUIRE(verified_service.config.has_value());
    REQUIRE(verified_policy.policy.has_value());
    CHECK(calls == 2);
    CHECK_FALSE(verified_service.changed);
    CHECK_FALSE(verified_policy.changed);
    CHECK(verified_service.config->port == 777U);
    CHECK(verified_policy.policy->threshold == 5U);
    CHECK(verified_service.source_content_generation ==
          initial_service.source_content_generation);
    CHECK(verified_policy.source_content_generation ==
          initial_policy.source_content_generation);
    CHECK(verified_service.source_observation_generation ==
          initial_service.source_observation_generation + 1U);
    CHECK(verified_policy.source_observation_generation ==
          initial_policy.source_observation_generation + 1U);
    CHECK(verified_service.observation_epoch == 1U);
    CHECK(verified_policy.observation_epoch == 1U);
    CHECK(verified_service.status == NdmsCatalogCacheStatus::fresh);
    CHECK(verified_policy.status == NdmsCatalogCacheStatus::fresh);
}

TEST_CASE("malformed HTTP config preserves both typed LKG projections") {
    int calls = 0;
    NdmsHttpConfigResource resource([&] {
        ++calls;
        return calls == 1 ? http_config() : std::string{"{not-json"};
    });
    NdmsHttpServiceConfigCache service(resource);
    NdmsLockoutPolicyCache policy(resource);

    const auto initial_service = service.get();
    const auto initial_policy = policy.get();
    REQUIRE(initial_service.config.has_value());
    REQUIRE(initial_policy.policy.has_value());

    resource.invalidate();
    const auto stale_service = service.force_refresh();
    const auto stale_policy = policy.get();

    REQUIRE(stale_service.config.has_value());
    REQUIRE(stale_policy.policy.has_value());
    CHECK(calls == 2);
    CHECK(stale_service.config->port == 777U);
    CHECK(stale_policy.policy->threshold == 5U);
    CHECK(stale_service.status == NdmsCatalogCacheStatus::stale);
    CHECK(stale_policy.status == NdmsCatalogCacheStatus::stale);
    CHECK(stale_service.source_content_generation ==
          initial_service.source_content_generation);
    CHECK(stale_policy.source_content_generation ==
          initial_policy.source_content_generation);
    CHECK(stale_service.source_observation_generation ==
          initial_service.source_observation_generation);
    CHECK(stale_policy.source_observation_generation ==
          initial_policy.source_observation_generation);
}

TEST_CASE("HTTP service and policy reject bad typed fields independently") {
    int calls = 0;
    const std::vector<std::string> payloads{
        http_config(),
        http_config("invalid", "7"),
        http_config("888", "5", false),
    };
    NdmsHttpConfigResource resource([&] {
        const auto index = static_cast<std::size_t>(calls++);
        return payloads.at(index);
    });
    NdmsHttpServiceConfigCache service(resource);
    NdmsLockoutPolicyCache policy(resource);

    const auto initial_service = service.get();
    const auto initial_policy = policy.get();
    REQUIRE(initial_service.config.has_value());
    REQUIRE(initial_policy.policy.has_value());

    resource.invalidate();
    const auto invalid_service = service.force_refresh();
    const auto updated_policy = policy.get();
    REQUIRE(invalid_service.config.has_value());
    REQUIRE(updated_policy.policy.has_value());
    CHECK(calls == 2);
    CHECK(invalid_service.config->port == 777U);
    CHECK(invalid_service.status == NdmsCatalogCacheStatus::stale);
    CHECK(invalid_service.source_content_generation ==
          initial_service.source_content_generation);
    CHECK(updated_policy.policy->threshold == 7U);
    CHECK(updated_policy.status == NdmsCatalogCacheStatus::fresh);
    CHECK(updated_policy.source_content_generation ==
          initial_policy.source_content_generation + 1U);

    resource.invalidate();
    const auto updated_service = service.force_refresh();
    const auto absent_policy = policy.get();
    REQUIRE(updated_service.config.has_value());
    CHECK(calls == 3);
    CHECK(updated_service.config->port == 888U);
    CHECK(updated_service.status == NdmsCatalogCacheStatus::fresh);
    CHECK(updated_service.source_content_generation ==
          initial_service.source_content_generation + 2U);
    CHECK_FALSE(absent_policy.policy.has_value());
    CHECK(absent_policy.status == NdmsCatalogCacheStatus::fresh);
    CHECK(absent_policy.source_content_generation ==
          initial_policy.source_content_generation + 2U);
    CHECK(absent_policy.source_content_generation ==
          updated_service.source_content_generation);
}

} // namespace
} // namespace keen_pbr3
