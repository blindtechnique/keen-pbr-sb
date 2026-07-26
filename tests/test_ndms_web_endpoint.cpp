#include "../src/keenetic/ndms_web_endpoint.hpp"

#include <doctest/doctest.h>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

nlohmann::json private_interface(const std::string& id,
                                 const std::string& address) {
    return {
        {"id", id},
        {"address", address},
        {"connected", "yes"},
        {"global", false},
        {"admin-only", false},
        {"security-level", "private"},
    };
}

} // namespace

TEST_CASE("NDMS web addresses prefer Bridge0 and reject unsafe interfaces") {
    auto interfaces = nlohmann::json::object();
    interfaces["Bridge2"] =
        private_interface("Bridge2", "192.168.30.1");
    interfaces["Bridge0"] =
        private_interface("Bridge0", "10.42.0.1");
    interfaces["Public"] =
        private_interface("Public", "192.0.2.1");
    interfaces["Public"]["security-level"] = "public";
    interfaces["Disconnected"] =
        private_interface("Disconnected", "192.168.40.1");
    interfaces["Disconnected"]["connected"] = "no";
    interfaces["Global"] =
        private_interface("Global", "192.168.50.1");
    interfaces["Global"]["global"] = true;
    interfaces["AdminOnly"] =
        private_interface("AdminOnly", "192.168.60.1");
    interfaces["AdminOnly"]["admin-only"] = true;
    interfaces["NonCanonical"] =
        private_interface("NonCanonical", "192.168.070.1");

    const auto addresses = parse_ndms_web_addresses(interfaces);
    REQUIRE(addresses.size() == 2U);
    CHECK(addresses[0].interface_id == "Bridge0");
    CHECK(addresses[0].address == "10.42.0.1");
    CHECK(addresses[0].preferred);
    CHECK(addresses[1].interface_id == "Bridge2");
}

TEST_CASE("NDMS structured HTTP config accepts decimal string and integer") {
    const auto from_string =
        parse_ndms_http_service_config({{"port", "17777"}});
    CHECK(from_string.enabled);
    CHECK(from_string.port == 17777);

    const auto from_integer =
        parse_ndms_http_service_config({{"port", 8080}});
    CHECK(from_integer.enabled);
    CHECK(from_integer.port == 8080);

    for (const auto& invalid :
         std::vector<nlohmann::json>{
             nlohmann::json::object(),
             nlohmann::json{{"port", true}},
             nlohmann::json{{"port", 0}},
             nlohmann::json{{"port", 65536}},
             nlohmann::json{{"port", 80.5}},
             nlohmann::json{{"port", "80junk"}},
         }) {
        CAPTURE(invalid);
        CHECK_THROWS_AS(
            parse_ndms_http_service_config(invalid),
            std::invalid_argument);
    }
}

TEST_CASE("NDMS running-config is a strict legacy HTTP port fallback") {
    const auto explicit_port =
        parse_ndms_running_config_http_service({
            {"message",
             {"ip http port 9123",
              "ip http ssl port 9443",
              "service http"}},
        });
    CHECK(explicit_port.enabled);
    CHECK(explicit_port.port == 9123);

    const auto default_port =
        parse_ndms_running_config_http_service({
            {"message", {"service http"}},
        });
    CHECK(default_port.enabled);
    CHECK(default_port.port == 80);

    const auto disabled =
        parse_ndms_running_config_http_service({
            {"message", {"ip http port 8080"}},
        });
    CHECK_FALSE(disabled.enabled);
    CHECK(disabled.port == 8080);

    CHECK_THROWS_AS(
        parse_ndms_running_config_http_service({
            {"message",
             {"ip http port 8080",
              "ip http port 8081",
              "service http"}},
        }),
        std::invalid_argument);
}

TEST_CASE("NDMS endpoint selection probes Bridge0 before other private LANs") {
    const std::vector<NdmsWebAddress> addresses{
        {"Bridge0", "10.0.0.1", true},
        {"Bridge2", "192.168.2.1", false},
    };
    const NdmsHttpServiceConfig service{true, 777};
    std::vector<std::string> probed;
    const auto selected = select_ndms_web_endpoint(
        addresses,
        service,
        [&probed](const NdmsWebEndpoint& endpoint) {
            probed.push_back(endpoint.canonical);
            return endpoint.host == "192.168.2.1";
        });

    REQUIRE(selected);
    CHECK(selected->canonical == "192.168.2.1:777");
    CHECK(probed ==
          std::vector<std::string>{
              "10.0.0.1:777",
              "192.168.2.1:777"});
}
