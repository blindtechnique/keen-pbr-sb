#include <doctest/doctest.h>

#include "keenetic/ndms_rci_observation.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

NdmsTunnelInterface expected_interface(
    const NdmsTunnelKind kind = NdmsTunnelKind::wireguard,
    const std::string& id = "Wireguard1",
    const std::string& firmware_name = "Wireguard1") {
    NdmsTunnelInterface interface;
    interface.id = id;
    interface.firmware_interface_name = firmware_name;
    interface.kind = kind;
    interface.role = NdmsInterfaceRole::client;
    return interface;
}

NdmsRciReadResponse json_response(const nlohmann::json& body) {
    return {
        200,
        "application/json; charset=utf-8",
        body.dump(),
    };
}

std::string observation_error_message(
    const NdmsRciReadResponse& response,
    const NdmsTunnelInterface& expected = expected_interface()) {
    try {
        static_cast<void>(
            parse_ndms_rci_tunnel_observation(response, expected));
    } catch (const NdmsRciObservationError& error) {
        return error.what();
    }
    return {};
}

} // namespace

TEST_CASE("NDMS RCI observation parses safe WG fields through a fake gateway") {
    int fetches = 0;
    NdmsRciObservationGateway gateway(
        [&fetches](const NdmsTunnelInterface& expected) {
            ++fetches;
            CHECK(expected.id == "Wireguard1");

            nlohmann::json body;
            body["status"] =
                nlohmann::json::array({{{"status", "ok"}}});
            body["data"]["interface"]["Wireguard1"] = {
                {"type", "Wireguard"},
                {"interface-name", "Wireguard1"},
                {"description", "Primary WG"},
                {"enabled", true},
                {"mtu", 1420},
                {"listen-port", 51820},
                {"addresses",
                 nlohmann::json::array(
                     {"10.0.0.2/32", "fd00::2/128"})},
                {"peers",
                 nlohmann::json::array(
                     {{{"public-key", "not-returned"}}})},
                {"private-key", "must-not-be-returned"},
            };
            return json_response(body);
        });

    const auto observation = gateway.acquire(expected_interface());

    CHECK(fetches == 1);
    CHECK(observation.interface_id == "Wireguard1");
    CHECK(observation.kind == NdmsTunnelKind::wireguard);
    CHECK(observation.firmware_type == "Wireguard");
    CHECK(observation.description ==
          std::optional<std::string>{"Primary WG"});
    CHECK(observation.enabled == std::optional<bool>{true});
    CHECK(observation.mtu == std::optional<std::uint32_t>{1420U});
    CHECK(observation.listen_port ==
          std::optional<std::uint16_t>{51820U});
    CHECK(observation.addresses ==
          std::vector<std::string>{"10.0.0.2/32", "fd00::2/128"});
    CHECK(observation.peer_count == 1U);
    CHECK(observation.observation_revision.rfind("ndms-rci-v1-", 0) == 0);
    CHECK(observation.observation_revision.size() == 76U);
    CHECK(observation.observation_revision.find("must-not-be-returned") ==
          std::string::npos);
}

TEST_CASE("NDMS RCI observation validates AWG independently from WG") {
    const auto response = json_response({
        {"Wireguard1",
         {{"type", "Wireguard"},
          {"protocol", "AmneziaWireguard"},
          {"interface-name", "Wireguard1"}}},
    });

    const auto awg = parse_ndms_rci_tunnel_observation(
        response,
        expected_interface(NdmsTunnelKind::amnezia_wireguard));
    CHECK(awg.kind == NdmsTunnelKind::amnezia_wireguard);

    CHECK_THROWS_AS(
        parse_ndms_rci_tunnel_observation(
            response,
            expected_interface(NdmsTunnelKind::wireguard)),
        NdmsRciObservationError);
}

TEST_CASE("NDMS RCI observation fails closed on HTTP and JSON errors") {
    SUBCASE("non-success HTTP status") {
        const auto message = observation_error_message(
            {403, "application/json", R"({"error":"secret"})"});
        CHECK(message == "NDMS RCI request did not return HTTP 200");
        CHECK(message.find("secret") == std::string::npos);
    }

    SUBCASE("non-JSON content type") {
        CHECK_THROWS_AS(
            parse_ndms_rci_tunnel_observation(
                {200, "text/html", "{}"},
                expected_interface()),
            NdmsRciObservationError);
    }

    SUBCASE("malformed JSON does not leak parser context") {
        const std::string secret = "private-key-do-not-log";
        const auto message = observation_error_message(
            {200,
             "application/json",
             "{\"private-key\":\"" + secret});
        CHECK(message == "NDMS RCI response contains invalid JSON");
        CHECK(message.find(secret) == std::string::npos);
    }
}

TEST_CASE("NDMS RCI observation rejects nested status and error envelopes") {
    const std::string secret = "credential-material";

    SUBCASE("nested error object") {
        nlohmann::json body;
        body["data"]["result"]["error"]["message"] = secret;
        body["data"]["result"]["interface"]["Wireguard1"] = {
            {"type", "Wireguard"},
        };

        const auto message =
            observation_error_message(json_response(body));
        CHECK(message == "NDMS RCI reported an error");
        CHECK(message.find(secret) == std::string::npos);
    }

    SUBCASE("failed status array") {
        nlohmann::json body;
        body["status"] = nlohmann::json::array(
            {{{"status", "failed"}, {"message", secret}}});
        body["Wireguard1"] = {{"type", "Wireguard"}};
        CHECK_THROWS_AS(
            parse_ndms_rci_tunnel_observation(
                json_response(body),
                expected_interface()),
            NdmsRciObservationError);
    }

    SUBCASE("unknown status token") {
        nlohmann::json body;
        body["status"] =
            nlohmann::json::array({{{"status", "maybe"}}});
        body["Wireguard1"] = {{"type", "Wireguard"}};
        CHECK_THROWS_AS(
            parse_ndms_rci_tunnel_observation(
                json_response(body),
                expected_interface()),
            NdmsRciObservationError);
    }
}

TEST_CASE("NDMS RCI observation rejects invalid critical fields") {
    SUBCASE("identity mismatch") {
        CHECK_THROWS_AS(
            parse_ndms_rci_tunnel_observation(
                json_response({
                    {"Wireguard1",
                     {{"type", "Wireguard"},
                      {"interface-name", "Wireguard2"}}},
                }),
                expected_interface()),
            NdmsRciObservationError);
    }

    SUBCASE("invalid MTU type") {
        CHECK_THROWS_AS(
            parse_ndms_rci_tunnel_observation(
                json_response({
                    {"Wireguard1",
                     {{"type", "Wireguard"},
                      {"mtu", "1420"}}},
                }),
                expected_interface()),
            NdmsRciObservationError);
    }

    SUBCASE("unsupported type") {
        CHECK_THROWS_AS(
            parse_ndms_rci_tunnel_observation(
                json_response({
                    {"Wireguard1", {{"type", "OpenVPN"}}},
                }),
                expected_interface()),
            NdmsRciObservationError);
    }
}

TEST_CASE("NDMS RCI observation digest never depends on secrets") {
    const auto first = json_response({
        {"Wireguard1",
         {{"type", "Wireguard"},
          {"description", "Stable"},
          {"private-key", "first-secret"},
          {"peers",
           nlohmann::json::array(
               {{{"public-key", "peer-one"},
                 {"preshared-key", "first-peer-secret"}}})}}},
    });
    const auto second = json_response({
        {"Wireguard1",
         {{"type", "Wireguard"},
          {"description", "Stable"},
          {"private-key", "second-secret"},
          {"peers",
           nlohmann::json::array(
               {{{"public-key", "different-peer-identity"},
                 {"preshared-key", "second-peer-secret"}}})}}},
    });

    const auto first_observation =
        parse_ndms_rci_tunnel_observation(
            first,
            expected_interface());
    const auto second_observation =
        parse_ndms_rci_tunnel_observation(
            second,
            expected_interface());

    CHECK(first_observation.observation_revision ==
          second_observation.observation_revision);
    CHECK(first_observation.peer_count ==
          second_observation.peer_count);
}

TEST_CASE("NDMS RCI identity separates catalog id and firmware name") {
    const auto expected = expected_interface(
        NdmsTunnelKind::wireguard,
        "tunnel-primary",
        "Wireguard7");

    nlohmann::json body;
    body["data"]["interface"]["tunnel-primary"] = {
        {"id", "tunnel-primary"},
        {"interface-name", "Wireguard7"},
        {"type", "Wireguard"},
    };
    const auto response = json_response(body);

    const auto observation =
        parse_ndms_rci_tunnel_observation(response, expected);
    CHECK(observation.interface_id == "tunnel-primary");

    body["data"]["interface"]["tunnel-primary"]["interface-name"] =
        "Wireguard8";
    CHECK_THROWS_AS(
        parse_ndms_rci_tunnel_observation(
            json_response(body),
            expected),
        NdmsRciObservationError);
}
