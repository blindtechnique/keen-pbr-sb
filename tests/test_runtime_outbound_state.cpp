#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/health/runtime_outbound_state.hpp"

using namespace keen_pbr3;

TEST_CASE("failed urltest result does not publish default zero latency") {
    URLTestResult result;
    result.success = false;
    result.latency_ms = 0;
    result.error = "probe timed out";

    CHECK_FALSE(
        runtime_outbound_detail::latency_from_urltest_result(result).has_value());
    CHECK(result.error == "probe timed out");
}

TEST_CASE("successful urltest result publishes measured latency") {
    URLTestResult result;
    result.success = true;
    result.latency_ms = 247;

    CHECK(
        runtime_outbound_detail::latency_from_urltest_result(result) ==
        std::optional<int64_t>{247});
}

#endif // WITH_API
