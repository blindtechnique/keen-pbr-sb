#ifdef WITH_API

#include "../src/api/handler_health_service.hpp"

#include <keen-pbr/version.hpp>

#include <doctest/doctest.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <string>

namespace keen_pbr3 {
namespace {

bool valid_compiled_commit(const std::string& value) {
    if (value == "unknown") {
        return true;
    }
    std::string base = value;
    constexpr const char* dirty_suffix = "-dirty";
    if (base.size() > 6 &&
        base.compare(base.size() - 6, 6, dirty_suffix) == 0) {
        base.resize(base.size() - 6);
    }
    return base.size() >= 12 && base.size() <= 64 &&
           std::all_of(base.begin(), base.end(), [](unsigned char character) {
               return std::isdigit(character) != 0 ||
                      (character >= 'a' && character <= 'f');
           });
}

}  // namespace

TEST_CASE("compiled build identity is canonical and internally consistent") {
    const std::string commit = KEEN_PBR3_VERSION_COMMIT;
    CHECK(valid_compiled_commit(commit));

    const std::string expected =
        std::string(KEEN_PBR3_VERSION_STRING) + " (build " +
        KEEN_PBR3_VERSION_RELEASE_STRING + ", commit " + commit + ")";
    CHECK(std::string(KEEN_PBR3_VERSION_IDENTITY_STRING) == expected);
}

TEST_CASE("health response publishes the compiled build identity") {
    ServiceHealthState state;
    const auto response = build_health_response(state);

    REQUIRE(response.commit.has_value());
    CHECK(*response.commit == KEEN_PBR3_VERSION_COMMIT);

    const nlohmann::json serialized = response;
    REQUIRE(serialized.contains("commit"));
    CHECK(serialized.at("commit") == KEEN_PBR3_VERSION_COMMIT);
}

}  // namespace keen_pbr3

#endif  // WITH_API
