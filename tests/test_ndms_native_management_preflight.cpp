#include <doctest/doctest.h>

#include "keenetic/ndms_native_management_preflight.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

bool has_blocker(
    const NdmsNativeManagementPreflight& preflight,
    const NdmsNativePreflightBlocker blocker) {
    return std::find(
               preflight.blockers.begin(),
               preflight.blockers.end(),
               blocker) != preflight.blockers.end();
}

NdmsTunnelInterface native_interface(
    const NdmsTunnelKind kind = NdmsTunnelKind::wireguard,
    const NdmsInterfaceRole role = NdmsInterfaceRole::client,
    const std::string& firmware_name = "Wireguard7",
    const std::optional<std::string>& kernel_name = "nwg7") {
    NdmsTunnelInterface interface;
    interface.id = "tunnel-primary";
    interface.firmware_interface_name = firmware_name;
    interface.kernel_name = kernel_name;
    interface.label = "Primary tunnel";
    interface.firmware_type =
        kind == NdmsTunnelKind::amnezia_wireguard
            ? "AmneziaWireguard"
            : "Wireguard";
    interface.kind = kind;
    interface.role = role;
    interface.inventory_revision = std::string(64U, 'a');
    return interface;
}

NdmsRciTunnelObservation observation_for(
    const NdmsTunnelInterface& interface) {
    NdmsRciTunnelObservation observation;
    observation.interface_id = interface.id;
    observation.kind = interface.kind;
    observation.firmware_type = interface.firmware_type;
    observation.observation_revision =
        "ndms-rci-v1-" + std::string(64U, 'b');
    return observation;
}

NdmsRciRestorableSnapshot snapshot_for(
    const NdmsTunnelInterface& interface,
    const std::string& private_key) {
    return {
        interface.id,
        interface.firmware_interface_name,
        interface.kind,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        {},
        NdmsRciSecret(private_key),
        std::nullopt,
        {},
        "ndms-rci-full-v1-" + std::string(64U, 'c'),
    };
}

NdmsNativeMutationFacilities all_facilities() {
    NdmsNativeMutationFacilities facilities;
    facilities.wireguard_conf_parser = true;
    facilities.import_preview_builder = true;
    facilities.protected_secret_transport = true;
    facilities.private_key_backup_source = true;
    facilities.ownership_verification = true;
    facilities.typed_mutation_commands = true;
    facilities.optimistic_compare_and_swap = true;
    facilities.automatic_rollback = true;
    return facilities;
}

} // namespace

TEST_CASE("measured native RCI read plans are fixed-origin and always probe ASC") {
    const auto wireguard =
        measured_ndms_native_read_plan(native_interface());
    REQUIRE(wireguard.has_value());
    REQUIRE(wireguard->size() == 3U);
    CHECK((*wireguard)[0].document ==
          NdmsNativeRciReadDocument::running_configuration);
    CHECK((*wireguard)[0].relative_path ==
          "/rci/show/rc/interface/Wireguard7");
    CHECK((*wireguard)[0].sensitive_response);
    CHECK((*wireguard)[1].document ==
          NdmsNativeRciReadDocument::runtime_state);
    CHECK((*wireguard)[1].relative_path ==
          "/rci/show/interface/Wireguard7");
    CHECK((*wireguard)[1].sensitive_response);
    CHECK((*wireguard)[2].document ==
          NdmsNativeRciReadDocument::amnezia_asc);
    CHECK((*wireguard)[2].relative_path ==
          "/rci/show/rc/interface/Wireguard7/wireguard/asc");
    CHECK((*wireguard)[2].sensitive_response);

    const auto amnezia = measured_ndms_native_read_plan(
        native_interface(NdmsTunnelKind::amnezia_wireguard));
    REQUIRE(amnezia.has_value());
    REQUIRE(amnezia->size() == 3U);
    CHECK((*amnezia)[2].document ==
          NdmsNativeRciReadDocument::amnezia_asc);
    CHECK((*amnezia)[2].relative_path ==
          "/rci/show/rc/interface/Wireguard7/wireguard/asc");
    CHECK((*amnezia)[2].sensitive_response);
}

TEST_CASE("unmeasured or unsafe RCI identities never produce request paths") {
    for (const auto& name : {
             "Wireguard",
             "Wireguard00",
             "Wireguard127",
             "wireguard7",
             "Wireguard7/../../system",
             "nwg7",
         }) {
        CAPTURE(name);
        CHECK_FALSE(
            measured_ndms_native_read_plan(
                native_interface(
                    NdmsTunnelKind::wireguard,
                    NdmsInterfaceRole::client,
                    name))
                .has_value());
    }

    CHECK_FALSE(
        measured_ndms_native_read_plan(
            native_interface(NdmsTunnelKind::openvpn))
            .has_value());
}

TEST_CASE("production preflight exposes precise gaps and keeps every mutation disabled") {
    NdmsNativeManagementPreflightInput input;
    input.catalog_fresh = true;
    const auto preflight = preflight_ndms_native_management(
        native_interface(),
        input);

    CHECK(preflight.mutation_mode ==
          NdmsNativeMutationMode::disabled);
    CHECK(preflight.candidate);
    CHECK(preflight.catalog_fresh);
    CHECK(preflight.inventory_identity_stable);
    CHECK(preflight.measured_read_plan_available);
    CHECK(preflight.inventory_revision.rfind("ndms-v1-", 0U) == 0U);
    CHECK_FALSE(preflight.observation_verified);
    CHECK_FALSE(preflight.restorable_snapshot_verified);
    CHECK_FALSE(preflight.observation_revision.has_value());
    CHECK_FALSE(preflight.restorable_snapshot_revision.has_value());
    CHECK_FALSE(preflight.capabilities.can_create);
    CHECK_FALSE(preflight.capabilities.can_edit);
    CHECK_FALSE(preflight.capabilities.can_delete);
    CHECK_FALSE(preflight.capabilities.can_apply_import);
    CHECK_FALSE(
        preflight.import_capabilities.can_parse_wireguard_conf);
    CHECK_FALSE(preflight.import_capabilities.can_build_preview);
    CHECK_FALSE(preflight.import_capabilities.can_apply);
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::rci_observation_unavailable));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::restorable_snapshot_unavailable));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::
            protected_secret_transport_unavailable));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::private_key_backup_unavailable));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::typed_mutation_commands_unavailable));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::mutation_release_disabled));
}

TEST_CASE("matching typed evidence is retained only as safe digests") {
    const std::string secret =
        "private-key-material-that-must-never-enter-preflight";
    const auto interface = native_interface(
        NdmsTunnelKind::amnezia_wireguard);
    const auto observation = observation_for(interface);
    const auto snapshot = snapshot_for(interface, secret);

    NdmsNativeManagementPreflightInput input;
    input.catalog_fresh = true;
    input.observation = &observation;
    input.restorable_snapshot = &snapshot;
    input.facilities = all_facilities();
    const auto preflight =
        preflight_ndms_native_management(interface, input);

    CHECK(preflight.observation_verified);
    CHECK(preflight.restorable_snapshot_verified);
    CHECK(preflight.observation_revision ==
          std::optional<std::string>{observation.observation_revision});
    CHECK(preflight.restorable_snapshot_revision ==
          std::optional<std::string>{snapshot.full_revision});
    CHECK(preflight.inventory_revision.find(secret) == std::string::npos);
    REQUIRE(preflight.observation_revision.has_value());
    REQUIRE(preflight.restorable_snapshot_revision.has_value());
    CHECK(preflight.observation_revision->find(secret) ==
          std::string::npos);
    CHECK(preflight.restorable_snapshot_revision->find(secret) ==
          std::string::npos);
    CHECK(preflight.blockers ==
          std::vector<NdmsNativePreflightBlocker>{
              NdmsNativePreflightBlocker::mutation_release_disabled});

    // Preflight evidence can never arm a mutation in this slice.
    CHECK(preflight.mutation_mode == NdmsNativeMutationMode::disabled);
    CHECK_FALSE(preflight.capabilities.can_create);
    CHECK_FALSE(preflight.capabilities.can_edit);
    CHECK_FALSE(preflight.capabilities.can_delete);
    CHECK_FALSE(preflight.capabilities.can_apply_import);
    CHECK(preflight.import_capabilities.can_parse_wireguard_conf);
    CHECK(preflight.import_capabilities.can_build_preview);
    CHECK_FALSE(preflight.import_capabilities.can_apply);
}

TEST_CASE("mismatched or attacker-shaped evidence fails closed without echoing it") {
    const std::string secret = "do-not-echo-this-value";
    const auto interface = native_interface();
    auto observation = observation_for(interface);
    observation.interface_id = "Wireguard8";
    observation.observation_revision = secret;
    auto snapshot = snapshot_for(interface, secret);
    snapshot.firmware_interface_name = "Wireguard8";
    snapshot.full_revision = secret;

    NdmsNativeManagementPreflightInput input;
    input.catalog_fresh = true;
    input.observation = &observation;
    input.restorable_snapshot = &snapshot;
    input.facilities = all_facilities();
    const auto preflight =
        preflight_ndms_native_management(interface, input);

    CHECK_FALSE(preflight.observation_verified);
    CHECK_FALSE(preflight.restorable_snapshot_verified);
    CHECK_FALSE(preflight.observation_revision.has_value());
    CHECK_FALSE(preflight.restorable_snapshot_revision.has_value());
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::rci_observation_mismatch));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::restorable_snapshot_mismatch));
    for (const auto blocker : preflight.blockers) {
        CHECK(std::string{ndms_native_preflight_blocker_name(blocker)}
                  .find(secret) == std::string::npos);
    }
}

TEST_CASE("stale catalogs, non-client roles and unresolved kernel identities remain blocked") {
    const auto interface = native_interface(
        NdmsTunnelKind::wireguard,
        NdmsInterfaceRole::server,
        "Wireguard7",
        std::nullopt);
    const auto preflight =
        preflight_ndms_native_management(interface);

    CHECK_FALSE(preflight.candidate);
    CHECK_FALSE(preflight.catalog_fresh);
    CHECK_FALSE(preflight.inventory_identity_stable);
    CHECK(preflight.measured_read_plan_available);
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::catalog_not_fresh));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::unsupported_role));
    CHECK(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::kernel_identity_unresolved));
    CHECK_FALSE(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::rci_observation_unavailable));
    CHECK_FALSE(has_blocker(
        preflight,
        NdmsNativePreflightBlocker::restorable_snapshot_unavailable));
}

TEST_CASE("native preflight names are stable machine-readable tokens") {
    CHECK(std::string{ndms_native_rci_read_document_name(
              NdmsNativeRciReadDocument::amnezia_asc)} ==
          "amnezia_asc");
    CHECK(std::string{ndms_native_preflight_blocker_name(
              NdmsNativePreflightBlocker::
                  protected_secret_transport_unavailable)} ==
          "protected_secret_transport_unavailable");
    CHECK(std::string{ndms_native_preflight_blocker_name(
              NdmsNativePreflightBlocker::private_key_backup_unavailable)} ==
          "private_key_backup_unavailable");
    CHECK(std::string{ndms_native_preflight_blocker_name(
              NdmsNativePreflightBlocker::mutation_release_disabled)} ==
          "mutation_release_disabled");
}
