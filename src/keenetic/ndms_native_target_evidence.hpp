#pragma once

#include "ndms_native_import_recovery_probe.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace keen_pbr3 {

// Turns the two measured direct-JSON reads of one WireGuard interface into
// the per-target evidence the recovery probe consumes. The last hand-built
// input in the chain: everything else is now derived from firmware documents.
//
// Measured on NC-1812, 2026-08-16, against the live Wireguard0:
//
//   show/rc/interface/WireguardN  -> description, ip.*, wireguard.peer[],
//                                    wireguard.listen-port.port, up
//   show/interface/WireguardN     -> id, type, description, link, connected,
//                                    state, mtu, wireguard.public-key, ...
//   show/rc/interface/WireguardN/wireguard/asc -> "{}" for plain WireGuard
//
// No endpoint returns a private key - re-confirmed by this measurement, which
// is why the secret snapshot exists at all.
struct NdmsNativeTargetReadFailure {
    enum class Reason {
        config_not_object,
        status_not_object,
        identity_mismatch,
        type_not_wireguard,
        link_state_unknown,
        secret_material_present,
    };
    Reason reason{Reason::config_not_object};
};

struct NdmsNativeTargetEvidenceResult {
    std::optional<NdmsNativeImportRecoveryTargetEvidence> evidence;
    std::optional<NdmsNativeTargetReadFailure> failure;
    // Non-empty ASC distinguishes AmneziaWG from plain WireGuard - the
    // measured discriminator. Reported, never inferred from a name.
    bool amnezia{false};
};

// Pure and fail-closed. Both documents must agree on the identity, the type
// must be the measured Wireguard, and link state must be one of the exact
// strings the firmware emits - a link whose state we cannot read is not a
// link we may call down, and "down" is what authorizes an exact-owned delete.
//
// If any secret-looking material appears in either document, the read is
// refused outright rather than sanitized: a firmware that started returning
// private keys is a changed world, and the safe response is to stop, not to
// quietly strip it and carry on.
NdmsNativeTargetEvidenceResult build_ndms_native_target_evidence(
    const std::string& interface_name,
    const nlohmann::json& config_document,
    const nlohmann::json& status_document,
    const nlohmann::json& asc_document);

const char* ndms_native_target_read_failure_name(
    NdmsNativeTargetReadFailure::Reason reason) noexcept;

} // namespace keen_pbr3
