#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_direct_observation.hpp"
#include "../src/keenetic/ndms_native_import_identity.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kMarker{
    "kpbr-ni-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

class QueueTransport final : public HttpTransport {
public:
    std::vector<HttpTransportResponse> responses;
    std::vector<HttpTransportRequest> requests;

    HttpTransportResponse perform(
        const HttpTransportRequest& request) override {
        requests.push_back(request);
        if (requests.size() > responses.size()) {
            throw HttpTransportError("unexpected direct observation read");
        }
        return responses[requests.size() - 1U];
    }
};

HttpTransportResponse response(const std::string& body) {
    HttpTransportResponse value;
    value.status_code = 200;
    value.body = body;
    return value;
}

nlohmann::json tunnel(const std::string& name,
                      const std::string& description) {
    return {
        {"type", "Wireguard"},
        {"interface-name", name},
        {"description", description},
        {"link", "down"},
    };
}

nlohmann::json config_document(const std::string& description) {
    return {
        {"description", description},
        {"wireguard",
         {{"listen-port", {{"port", 48123}}},
          {"peer",
           nlohmann::json::array(
               {{{"key", "public-peer-key"},
                 {"preshared-key", "raw-secret-from-firmware"}}})}}},
        {"up", true},
    };
}

nlohmann::json config_document_with_marker(
    const std::string& description,
    const std::string_view marker) {
    auto document = config_document(description);
    document["wireguard"]["peer"][0]["key"] =
        "E6E1kIJLnMIXinj5Ebs2qHCHWRUNoJyrEJ0tTJ7tbDs=";
    document["wireguard"]["peer"][0]["comment"] = marker;
    return document;
}

nlohmann::json runtime_document(const std::string& name) {
    return {
        {"id", name},
        {"interface-name", name},
        {"type", "Wireguard"},
        {"description", "observed target"},
        {"link", "down"},
        {"state", "up"},
        {"wireguard", {{"public-key", "public-interface-key"}}},
    };
}

void enqueue_target(QueueTransport& transport,
                    const std::string& name,
                    const nlohmann::json& asc = nlohmann::json::object()) {
    transport.responses.push_back(
        response(config_document("observed " + name).dump()));
    transport.responses.push_back(response(runtime_document(name).dump()));
    transport.responses.push_back(response(asc.dump()));
}

void check_fixed_request(const HttpTransportRequest& request,
                         const std::size_t maximum_bytes) {
    CHECK(request.timeout_ms == 4000L);
    CHECK(request.max_response_size == maximum_bytes);
    CHECK(request.max_redirects == 0L);
    REQUIRE(static_cast<bool>(request.destination_filter));
    CHECK(request.destination_filter("127.0.0.1"));
    CHECK_FALSE(request.destination_filter("127.0.0.2"));
    CHECK_FALSE(request.destination_filter("::1"));
    CHECK_FALSE(request.destination_filter("192.168.1.1"));
    CHECK(request.fwmark == 0U);
    CHECK(request.bind_interface.empty());
}

NdmsNativeDirectObservationGateway gateway_for(
    const std::shared_ptr<QueueTransport>& transport) {
    return NdmsNativeDirectObservationGateway(
        transport,
        [] {
            return NdmsNativeDirectObservationGateway::Clock::time_point{
                std::chrono::seconds{42}};
        });
}

} // namespace

TEST_CASE("direct NDMS catalog observation is fixed bounded and non-durable") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Bridge0",
         {{"type", "Bridge"},
          {"interface-name", "br0"},
          {"description", "Home"}}},
    }.dump()));

    const auto observed = gateway_for(transport).observe_catalog();
    REQUIRE(observed.snapshot.has_value());
    CHECK(observed.failure == NdmsNativeDirectObservationFailure::none);
    CHECK(observed.scope ==
          NdmsNativeDirectCatalogScope::runtime_state);
    CHECK(observed.snapshot->status == NdmsCatalogCacheStatus::fresh);
    CHECK(observed.snapshot->refreshed);
    REQUIRE(observed.snapshot->observed_at.has_value());
    CHECK(*observed.snapshot->observed_at ==
          NdmsNativeDirectObservationGateway::Clock::time_point{
              std::chrono::seconds{42}});
    CHECK(observed.snapshot->catalog.firmware_available);
    CHECK(observed.snapshot->catalog.wireguard_slot_evidence_complete);
    // These cache identities are intentionally absent.  A caller must bind
    // the canonical measured revision to the durable observation ledger.
    CHECK(observed.snapshot->observation_generation == 0U);
    CHECK(observed.snapshot->observation_epoch == 0U);
    CHECK(observed.snapshot->invalidation_epoch == 0U);

    REQUIRE(transport->requests.size() == 1U);
    CHECK(transport->requests.front().url ==
          kNdmsNativeDirectRuntimeCatalogEndpoint);
    check_fixed_request(
        transport->requests.front(),
        kNdmsNativeDirectCatalogMaximumBytes);
}

TEST_CASE("running-config scope is fixed and makes no persistence claim") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5",
         {{"description", "persistent target"},
          {"wireguard",
           {{"peer",
             nlohmann::json::array(
                 {{{"preshared-key", "firmware-secret"}}})}}}}},
    }.dump()));

    const auto observed = gateway_for(transport).observe_catalog(
        NdmsNativeDirectCatalogScope::running_config);
    REQUIRE(observed.snapshot.has_value());
    CHECK(observed.scope ==
          NdmsNativeDirectCatalogScope::running_config);
    CHECK(observed.snapshot->status == NdmsCatalogCacheStatus::fresh);
    CHECK(observed.snapshot->refreshed);
    CHECK(observed.snapshot->observation_generation == 0U);
    CHECK(observed.snapshot->catalog.wireguard_slots[5].state ==
          NdmsWireguardCatalogSlotState::occupied);
    REQUIRE(transport->requests.size() == 1U);
    CHECK(transport->requests.front().url ==
          kNdmsNativeDirectRunningConfigCatalogEndpoint);
    check_fixed_request(
        transport->requests.front(),
        kNdmsNativeDirectCatalogMaximumBytes);
}

TEST_CASE("direct catalog parsing rejects malformed and error documents") {
    struct Refusal {
        std::string body;
        NdmsNativeDirectObservationFailure expected;
    };
    const std::vector<Refusal> refusals{
        {"", NdmsNativeDirectObservationFailure::empty_response},
        {"not-json", NdmsNativeDirectObservationFailure::malformed_json},
        {"[]", NdmsNativeDirectObservationFailure::response_not_object},
        {"{}", NdmsNativeDirectObservationFailure::empty_response},
        {R"({"error":{"message":"no"}})",
         NdmsNativeDirectObservationFailure::rci_error_response},
        {R"({"status":"failed"})",
         NdmsNativeDirectObservationFailure::rci_error_response},
        {R"({"status":[{"status":"error","code":"1"}]})",
         NdmsNativeDirectObservationFailure::rci_error_response},
        {R"({"Wireguard5":{"type":"Wireguard"},"Wireguard5":{"type":"Wireguard"}})",
         NdmsNativeDirectObservationFailure::duplicate_json_key},
        {R"({"Wireguard5":"malformed"})",
         NdmsNativeDirectObservationFailure::catalog_malformed},
    };

    for (const auto& refusal : refusals) {
        CAPTURE(refusal.body);
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(refusal.body));
        const auto observed = gateway_for(transport).observe_catalog();
        CHECK_FALSE(observed.snapshot.has_value());
        CHECK(observed.failure == refusal.expected);
        CHECK(transport->requests.size() == 1U);
    }

    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(std::string(
        kNdmsNativeDirectCatalogMaximumBytes + 1U, 'x')));
    const auto oversized = gateway_for(transport).observe_catalog();
    CHECK_FALSE(oversized.snapshot.has_value());
    CHECK(oversized.failure ==
          NdmsNativeDirectObservationFailure::response_too_large);
}

TEST_CASE("one marker yields one exact redacted target measurement") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
    }.dump()));
    enqueue_target(*transport, "Wireguard5");

    const auto measured = gateway_for(transport).observe_recovery(
        kMarker, std::optional<std::string>{"Wireguard5"});
    REQUIRE(measured.complete());
    REQUIRE(measured.snapshot.has_value());
    REQUIRE(measured.target_evidence.size() == 1U);
    CHECK(measured.target_evidence.front().interface_name == "Wireguard5");
    CHECK(measured.target_evidence.front().link_down);
    CHECK(measured.target_evidence.front().full_revision.rfind(
              "ndms-rci-full-v1-", 0U) == 0U);
    REQUIRE(measured.target_protocols.size() == 1U);
    CHECK(measured.target_protocols.front().interface_name == "Wireguard5");
    CHECK(measured.target_protocols.front().asc_class ==
          NdmsNativeAscClass::plain_wireguard);
    CHECK(measured.catalog_revision ==
          ndms_native_import_recovery_catalog_revision(
              measured.snapshot->catalog, measured.target_evidence));
    CHECK(measured.catalog_revision.rfind(
              kNdmsNativeObservationCatalogRevisionPrefix, 0U) == 0U);

    REQUIRE(transport->requests.size() == 4U);
    CHECK(transport->requests[0].url ==
          kNdmsNativeDirectRuntimeCatalogEndpoint);
    CHECK(transport->requests[1].url ==
          "http://127.0.0.1:79/rci/show/rc/interface/Wireguard5");
    CHECK(transport->requests[2].url ==
          "http://127.0.0.1:79/rci/show/interface/Wireguard5");
    CHECK(transport->requests[3].url ==
          "http://127.0.0.1:79/rci/show/rc/interface/"
          "Wireguard5/wireguard/asc");
    check_fixed_request(
        transport->requests[0],
        kNdmsNativeDirectCatalogMaximumBytes);
    for (std::size_t index = 1U; index < transport->requests.size(); ++index) {
        check_fixed_request(
            transport->requests[index],
            kNdmsNativeDirectTargetMaximumBytes);
    }
}

TEST_CASE("a clean interface label retains exact ownership in one peer comment") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5", tunnel("Wireguard5", "Мой VPN")},
    }.dump()));
    transport->responses.push_back(response(
        config_document_with_marker("Мой VPN", kMarker).dump()));
    transport->responses.push_back(
        response(runtime_document("Wireguard5").dump()));
    transport->responses.push_back(
        response(nlohmann::json::object().dump()));

    const auto measured = gateway_for(transport).observe_recovery(
        kMarker, std::optional<std::string>{"Wireguard5"});
    REQUIRE(measured.complete());
    REQUIRE(measured.target_evidence.size() == 1U);
    CHECK(measured.target_evidence.front().ownership_marker_present);
    CHECK(measured.target_evidence.front().primary_peer_public_key ==
          "E6E1kIJLnMIXinj5Ebs2qHCHWRUNoJyrEJ0tTJ7tbDs=");
    REQUIRE(measured.snapshot.has_value());
    REQUIRE(measured.snapshot->catalog.tunnels.size() == 1U);
    CHECK(measured.snapshot->catalog.tunnels.front().label == "Мой VPN");
}

TEST_CASE("recovery completeness binds requested and observed catalog scope") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
    }.dump()));
    enqueue_target(*transport, "Wireguard5");

    auto measured = gateway_for(transport).observe_recovery(
        NdmsNativeDirectCatalogScope::running_config,
        kMarker,
        std::optional<std::string>{"Wireguard5"});
    REQUIRE(measured.complete());
    CHECK(measured.requested_catalog_scope ==
          NdmsNativeDirectCatalogScope::running_config);
    CHECK(measured.catalog_scope ==
          NdmsNativeDirectCatalogScope::running_config);
    REQUIRE_FALSE(transport->requests.empty());
    CHECK(transport->requests.front().url ==
          kNdmsNativeDirectRunningConfigCatalogEndpoint);

    // An injected/adapted gateway cannot combine a runtime request with a
    // complete running-config payload (or the inverse) and retain complete.
    measured.requested_catalog_scope =
        NdmsNativeDirectCatalogScope::runtime_state;
    CHECK_FALSE(measured.complete());
    measured.requested_catalog_scope =
        NdmsNativeDirectCatalogScope::running_config;
    measured.catalog_scope = NdmsNativeDirectCatalogScope::runtime_state;
    CHECK_FALSE(measured.complete());
}

TEST_CASE("running-config recovery accepts canonical untyped Keenetic slot") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5",
         {{"description", std::string{kMarker}},
          {"wireguard",
           {{"peer",
             nlohmann::json::array(
                 {{{"preshared-key", "firmware-secret"}}})}}}}},
    }.dump()));
    enqueue_target(*transport, "Wireguard5");

    const auto measured = gateway_for(transport).observe_recovery(
        NdmsNativeDirectCatalogScope::running_config,
        kMarker,
        std::optional<std::string>{"Wireguard5"});
    REQUIRE(measured.complete());
    REQUIRE(measured.snapshot.has_value());
    REQUIRE(measured.snapshot->catalog.tunnels.size() == 1U);
    const auto& synthesized = measured.snapshot->catalog.tunnels.front();
    CHECK(synthesized.firmware_interface_name == "Wireguard5");
    CHECK(synthesized.label == kMarker);
    CHECK(synthesized.kind == NdmsTunnelKind::wireguard);
    REQUIRE(measured.target_evidence.size() == 1U);
    REQUIRE(measured.target_protocols.size() == 1U);
    CHECK(measured.target_protocols.front().asc_class ==
          NdmsNativeAscClass::plain_wireguard);
    CHECK(transport->requests.size() == 4U);
    CHECK(transport->requests.front().url ==
          kNdmsNativeDirectRunningConfigCatalogEndpoint);
}

TEST_CASE("ASC is measured directly rather than inferred from a name") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
    }.dump()));
    enqueue_target(
        *transport, "Wireguard5",
        nlohmann::json{{"jc", "5"}, {"jmin", "8"}, {"jmax", "120"}});

    const auto measured =
        gateway_for(transport).observe_recovery(kMarker);
    REQUIRE(measured.complete());
    REQUIRE(measured.target_protocols.size() == 1U);
    CHECK(measured.target_protocols.front().asc_class ==
          NdmsNativeAscClass::amnezia_wg);
}

TEST_CASE("unsafe or ambiguous catalogs stop before target reads") {
    SUBCASE("two records claiming one slot are unsafe") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"First", tunnel("Wireguard5", std::string{kMarker})},
            {"Second", tunnel("Wireguard5", "duplicate")},
        }.dump()));
        const auto measured =
            gateway_for(transport).observe_recovery(kMarker);
        CHECK_FALSE(measured.complete());
        REQUIRE(measured.snapshot.has_value());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::catalog_unsafe);
        CHECK(transport->requests.size() == 1U);
    }

    SUBCASE("two marker sightings are ambiguous") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
            {"Wireguard6", tunnel("Wireguard6", std::string{kMarker})},
        }.dump()));
        const auto measured =
            gateway_for(transport).observe_recovery(kMarker);
        CHECK_FALSE(measured.complete());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::ambiguous_marker);
        CHECK(transport->requests.size() == 1U);
    }

    SUBCASE("an occupied runtime slot without a typed tunnel is unsafe") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5",
             {{"interface-name", "Wireguard5"},
              {"description", std::string{kMarker}}}},
        }.dump()));
        const auto measured =
            gateway_for(transport).observe_recovery(kMarker);
        CHECK_FALSE(measured.complete());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::catalog_unsafe);
        CHECK(transport->requests.size() == 1U);
    }
}

TEST_CASE("marker and distinct occupied target have a fixed seven-read cap") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
        {"Wireguard7", tunnel("Wireguard7", "expected target")},
    }.dump()));
    enqueue_target(*transport, "Wireguard5");
    enqueue_target(*transport, "Wireguard7");

    const auto measured = gateway_for(transport).observe_recovery(
        kMarker, std::optional<std::string>{"Wireguard7"});
    REQUIRE(measured.complete());
    CHECK(measured.target_evidence.size() == 2U);
    CHECK(transport->requests.size() == 7U);
    CHECK(transport->requests[1].url.find("Wireguard5") !=
          std::string::npos);
    CHECK(transport->requests[4].url.find("Wireguard7") !=
          std::string::npos);
}

TEST_CASE("untrusted marker and target never become an RCI path") {
    SUBCASE("invalid marker") {
        auto transport = std::make_shared<QueueTransport>();
        const auto measured = gateway_for(transport).observe_recovery(
            "kpbr-ni-v1-not-hex");
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::invalid_marker);
        CHECK(transport->requests.empty());
    }

    SUBCASE("path-like target") {
        auto transport = std::make_shared<QueueTransport>();
        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard5/../../system"});
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::invalid_target);
        CHECK(transport->requests.empty());
    }

    SUBCASE("protected target") {
        auto transport = std::make_shared<QueueTransport>();
        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard0"});
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::invalid_target);
        CHECK(transport->requests.empty());
    }
}

TEST_CASE("a target error envelope cannot produce a durable revision") {
    auto transport = std::make_shared<QueueTransport>();
    transport->responses.push_back(response(nlohmann::json{
        {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
    }.dump()));
    transport->responses.push_back(
        response(R"({"status":[{"status":"error","code":"1"}]})"));

    const auto measured =
        gateway_for(transport).observe_recovery(kMarker);
    CHECK_FALSE(measured.complete());
    CHECK(measured.catalog_revision.empty());
    CHECK(measured.failure ==
          NdmsNativeDirectObservationFailure::rci_error_response);
    CHECK(measured.failed_document ==
          NdmsNativeDirectDocumentKind::target_config);
    CHECK(measured.failed_interface == "Wireguard5");
    CHECK(transport->requests.size() == 2U);
}

TEST_CASE("catalog absence and target unreadability never collapse") {
    SUBCASE("absence is proved by the complete full catalog") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Bridge0",
             {{"type", "Bridge"}, {"interface-name", "br0"}}},
        }.dump()));

        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard5"});
        REQUIRE(measured.complete());
        CHECK(measured.target_evidence.empty());
        CHECK(measured.target_protocols.empty());
        CHECK(transport->requests.size() == 1U);
    }

    SUBCASE("an empty config response is unreadable, not absent") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5", tunnel("Wireguard5", "occupied")},
        }.dump()));
        transport->responses.push_back(response(""));

        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard5"});
        CHECK_FALSE(measured.complete());
        CHECK(measured.catalog_revision.empty());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::empty_response);
        CHECK(measured.failed_document ==
              NdmsNativeDirectDocumentKind::target_config);
        CHECK(measured.failed_interface == "Wireguard5");
        CHECK(transport->requests.size() == 2U);
    }

    SUBCASE("a runtime RCI error is unreadable, not absent") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5", tunnel("Wireguard5", "occupied")},
        }.dump()));
        transport->responses.push_back(
            response(config_document("occupied").dump()));
        transport->responses.push_back(
            response(R"({"status":[{"status":"error"}]})"));

        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard5"});
        CHECK_FALSE(measured.complete());
        CHECK(measured.catalog_revision.empty());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::rci_error_response);
        CHECK(measured.failed_document ==
              NdmsNativeDirectDocumentKind::target_runtime);
        CHECK(transport->requests.size() == 3U);
    }

    SUBCASE("an ASC error is unreadable, not a protocol") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5", tunnel("Wireguard5", "occupied")},
        }.dump()));
        transport->responses.push_back(
            response(config_document("occupied").dump()));
        transport->responses.push_back(
            response(runtime_document("Wireguard5").dump()));
        transport->responses.push_back(
            response(R"({"status":[{"status":"failed"}]})"));

        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard5"});
        CHECK_FALSE(measured.complete());
        CHECK(measured.catalog_revision.empty());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::rci_error_response);
        CHECK(measured.failed_document ==
              NdmsNativeDirectDocumentKind::target_asc);
        CHECK(transport->requests.size() == 4U);
    }

    SUBCASE("an HTTP failure is unreadable, not absent") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5", tunnel("Wireguard5", "occupied")},
        }.dump()));
        auto unavailable = response("unavailable");
        unavailable.status_code = 503;
        transport->responses.push_back(std::move(unavailable));

        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard5"});
        CHECK_FALSE(measured.complete());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::transport_failed);
        CHECK(measured.failed_document ==
              NdmsNativeDirectDocumentKind::target_config);
        CHECK(transport->requests.size() == 2U);
    }

    SUBCASE("a later target failure discards earlier partial evidence") {
        auto transport = std::make_shared<QueueTransport>();
        transport->responses.push_back(response(nlohmann::json{
            {"Wireguard5", tunnel("Wireguard5", std::string{kMarker})},
            {"Wireguard7", tunnel("Wireguard7", "expected target")},
        }.dump()));
        enqueue_target(*transport, "Wireguard5");
        transport->responses.push_back(response(""));

        const auto measured = gateway_for(transport).observe_recovery(
            kMarker, std::optional<std::string>{"Wireguard7"});
        CHECK_FALSE(measured.complete());
        CHECK(measured.target_evidence.empty());
        CHECK(measured.target_protocols.empty());
        CHECK(measured.catalog_revision.empty());
        CHECK(measured.failure ==
              NdmsNativeDirectObservationFailure::empty_response);
        CHECK(measured.failed_interface == "Wireguard7");
        CHECK(transport->requests.size() == 5U);
    }
}

} // namespace keen_pbr3
