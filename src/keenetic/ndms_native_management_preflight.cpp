#include "ndms_native_management_preflight.hpp"

#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string_view>

namespace keen_pbr3 {

namespace {

bool has_prefix(const std::string& value,
                const std::string_view prefix) {
    return value.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool native_kind(const NdmsTunnelKind kind) noexcept {
    return kind == NdmsTunnelKind::wireguard ||
           kind == NdmsTunnelKind::amnezia_wireguard;
}

bool lowercase_hex(const std::string& value,
                   const std::size_t offset) {
    return value.size() == offset + 64U &&
           std::all_of(
               value.begin() + static_cast<std::ptrdiff_t>(offset),
               value.end(),
               [](const unsigned char character) {
                   return std::isdigit(character) != 0 ||
                          (character >= 'a' && character <= 'f');
               });
}

bool safe_revision(const std::string& value,
                   const std::string_view prefix) {
    return has_prefix(value, prefix) &&
           lowercase_hex(value, prefix.size());
}

bool matching_observation(
    const NdmsRciTunnelObservation& observation,
    const NdmsTunnelInterface& interface) {
    return observation.interface_id == interface.id &&
           observation.kind == interface.kind &&
           !observation.firmware_type.empty() &&
           safe_revision(
               observation.observation_revision,
               "ndms-rci-v1-");
}

bool matching_snapshot(
    const NdmsRciRestorableSnapshot& snapshot,
    const NdmsTunnelInterface& interface) {
    return snapshot.interface_id == interface.id &&
           snapshot.firmware_interface_name ==
               interface.firmware_interface_name &&
           snapshot.kind == interface.kind &&
           safe_revision(
               snapshot.full_revision,
               "ndms-rci-full-v1-");
}

void add_environment_blockers(
    const NdmsNativeMutationFacilities& facilities,
    std::vector<NdmsNativePreflightBlocker>& blockers) {
    if (!facilities.protected_secret_transport) {
        blockers.push_back(
            NdmsNativePreflightBlocker::
                protected_secret_transport_unavailable);
    }
    if (!facilities.private_key_backup_source) {
        blockers.push_back(
            NdmsNativePreflightBlocker::private_key_backup_unavailable);
    }
    if (!facilities.ownership_verification) {
        blockers.push_back(
            NdmsNativePreflightBlocker::ownership_unverified);
    }
    if (!facilities.typed_mutation_commands) {
        blockers.push_back(
            NdmsNativePreflightBlocker::
                typed_mutation_commands_unavailable);
    }
    if (!facilities.optimistic_compare_and_swap) {
        blockers.push_back(
            NdmsNativePreflightBlocker::
                optimistic_revision_unavailable);
    }
    if (!facilities.automatic_rollback) {
        blockers.push_back(
            NdmsNativePreflightBlocker::automatic_rollback_unavailable);
    }

    // This first slice is intentionally incapable of enabling mutations.
    blockers.push_back(
        NdmsNativePreflightBlocker::mutation_release_disabled);
}

} // namespace

std::optional<std::vector<NdmsNativeRciReadRequest>>
measured_ndms_native_read_plan(
    const NdmsTunnelInterface& interface) {
    if (!native_kind(interface.kind) ||
        !parse_ndms_wireguard_identity(
             interface.firmware_interface_name).has_value()) {
        return std::nullopt;
    }

    const auto& name = interface.firmware_interface_name;
    std::vector<NdmsNativeRciReadRequest> plan{
        {
            NdmsNativeRciReadDocument::running_configuration,
            "/rci/show/rc/interface/" + name,
            true,
        },
        {
            NdmsNativeRciReadDocument::runtime_state,
            "/rci/show/interface/" + name,
            true,
        },
        {
            // KeeneticOS reports both WG and AWG runtime type as
            // `Wireguard`. The measured ASC document is therefore required
            // for every allowlisted WireguardN identity: an empty object is
            // WG, while the measured 16-field object identifies AWG.
            NdmsNativeRciReadDocument::amnezia_asc,
            "/rci/show/rc/interface/" + name + "/wireguard/asc",
            true,
        },
    };
    return plan;
}

NdmsNativeManagementPreflight preflight_ndms_native_management(
    const NdmsTunnelInterface& interface,
    const NdmsNativeManagementPreflightInput& input) {
    NdmsNativeManagementPreflight result;
    result.catalog_fresh = input.catalog_fresh;
    result.import_capabilities.can_parse_wireguard_conf =
        input.facilities.wireguard_conf_parser;
    result.import_capabilities.can_build_preview =
        input.facilities.import_preview_builder &&
        input.facilities.wireguard_conf_parser;
    // `can_apply` and `capabilities.can_apply_import` intentionally retain
    // their false defaults regardless of parsing/preview facilities.

    const auto readiness =
        assess_ndms_interface_management(interface);
    result.candidate = readiness.candidate;
    result.inventory_identity_stable = readiness.identity_stable;
    if (safe_revision(readiness.observed_revision, "ndms-v1-")) {
        result.inventory_revision = readiness.observed_revision;
    }

    if (!input.catalog_fresh) {
        result.blockers.push_back(
            NdmsNativePreflightBlocker::catalog_not_fresh);
    }
    if (!native_kind(interface.kind)) {
        result.blockers.push_back(
            NdmsNativePreflightBlocker::unsupported_kind);
    }
    if (interface.role == NdmsInterfaceRole::unknown) {
        result.blockers.push_back(
            NdmsNativePreflightBlocker::role_unknown);
    } else if (interface.role != NdmsInterfaceRole::client) {
        result.blockers.push_back(
            NdmsNativePreflightBlocker::unsupported_role);
    }
    if (!readiness.identity_stable) {
        result.blockers.push_back(
            NdmsNativePreflightBlocker::kernel_identity_unresolved);
    }

    const auto read_plan = measured_ndms_native_read_plan(interface);
    if (read_plan) {
        result.measured_read_plan_available = true;
        result.read_plan = *read_plan;
    } else if (native_kind(interface.kind)) {
        result.blockers.push_back(
            NdmsNativePreflightBlocker::
                measured_rci_read_plan_unavailable);
    }

    if (result.candidate) {
        if (input.observation == nullptr) {
            result.blockers.push_back(
                NdmsNativePreflightBlocker::rci_observation_unavailable);
        } else if (matching_observation(
                       *input.observation, interface)) {
            result.observation_verified = true;
            result.observation_revision =
                input.observation->observation_revision;
        } else {
            result.blockers.push_back(
                NdmsNativePreflightBlocker::rci_observation_mismatch);
        }

        if (input.restorable_snapshot == nullptr) {
            result.blockers.push_back(
                NdmsNativePreflightBlocker::
                    restorable_snapshot_unavailable);
        } else if (matching_snapshot(
                       *input.restorable_snapshot, interface)) {
            result.restorable_snapshot_verified = true;
            result.restorable_snapshot_revision =
                input.restorable_snapshot->full_revision;
        } else {
            result.blockers.push_back(
                NdmsNativePreflightBlocker::
                    restorable_snapshot_mismatch);
        }
    }

    add_environment_blockers(input.facilities, result.blockers);
    return result;
}

const char* ndms_native_rci_read_document_name(
    const NdmsNativeRciReadDocument document) noexcept {
    switch (document) {
    case NdmsNativeRciReadDocument::running_configuration:
        return "running_configuration";
    case NdmsNativeRciReadDocument::runtime_state:
        return "runtime_state";
    case NdmsNativeRciReadDocument::amnezia_asc:
        return "amnezia_asc";
    }
    return "unknown";
}

const char* ndms_native_preflight_blocker_name(
    const NdmsNativePreflightBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativePreflightBlocker::catalog_not_fresh:
        return "catalog_not_fresh";
    case NdmsNativePreflightBlocker::unsupported_kind:
        return "unsupported_kind";
    case NdmsNativePreflightBlocker::role_unknown:
        return "role_unknown";
    case NdmsNativePreflightBlocker::unsupported_role:
        return "unsupported_role";
    case NdmsNativePreflightBlocker::kernel_identity_unresolved:
        return "kernel_identity_unresolved";
    case NdmsNativePreflightBlocker::measured_rci_read_plan_unavailable:
        return "measured_rci_read_plan_unavailable";
    case NdmsNativePreflightBlocker::rci_observation_unavailable:
        return "rci_observation_unavailable";
    case NdmsNativePreflightBlocker::rci_observation_mismatch:
        return "rci_observation_mismatch";
    case NdmsNativePreflightBlocker::restorable_snapshot_unavailable:
        return "restorable_snapshot_unavailable";
    case NdmsNativePreflightBlocker::restorable_snapshot_mismatch:
        return "restorable_snapshot_mismatch";
    case NdmsNativePreflightBlocker::
        protected_secret_transport_unavailable:
        return "protected_secret_transport_unavailable";
    case NdmsNativePreflightBlocker::private_key_backup_unavailable:
        return "private_key_backup_unavailable";
    case NdmsNativePreflightBlocker::ownership_unverified:
        return "ownership_unverified";
    case NdmsNativePreflightBlocker::typed_mutation_commands_unavailable:
        return "typed_mutation_commands_unavailable";
    case NdmsNativePreflightBlocker::optimistic_revision_unavailable:
        return "optimistic_revision_unavailable";
    case NdmsNativePreflightBlocker::automatic_rollback_unavailable:
        return "automatic_rollback_unavailable";
    case NdmsNativePreflightBlocker::mutation_release_disabled:
        return "mutation_release_disabled";
    }
    return "unknown";
}

} // namespace keen_pbr3
