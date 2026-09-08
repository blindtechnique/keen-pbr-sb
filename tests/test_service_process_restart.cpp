#ifdef WITH_API
#include <doctest/doctest.h>
#include "../src/api/handler_reload.hpp"

using namespace keen_pbr3;

TEST_CASE("process restart schedules one fixed detached S80 action") {
    std::vector<std::string> recorded;
    unsigned calls = 0;
    const auto body = request_service_process_restart([&](const auto& args) {
        ++calls;
        recorded = args;
        return 0;
    });
    CHECK(calls == 1);
    const std::vector<std::string> expected{"/opt/etc/init.d/S80keen-pbr", "restart-stack-background"};
    CHECK(recorded == expected);
    const auto response = nlohmann::json::parse(body);
    CHECK(response.at("status") == "ok");
    CHECK(response.at("message") == "Service process restart scheduled");
}

TEST_CASE("process restart does not report success if its launcher fails") {
    unsigned calls = 0;
    CHECK_THROWS_AS(request_service_process_restart([&](const auto&) {
        ++calls;
        return 1;
    }), ApiError);
    CHECK(calls == 1);
    CHECK_THROWS_AS(request_service_process_restart({}), ApiError);
}
#endif
