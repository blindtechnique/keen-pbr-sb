#include "ndms_native_target_evidence.hpp"

#include "ndms_native_secret_redaction.hpp"
#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <cctype>

namespace keen_pbr3 {

namespace {

using Reason = NdmsNativeTargetReadFailure::Reason;

NdmsNativeTargetEvidenceResult refuse(const Reason reason) {
    NdmsNativeTargetEvidenceResult result;
    result.failure = NdmsNativeTargetReadFailure{reason};
    return result;
}

// Measured on NC-1812 across all five occupied slots: every one of them
// carries wireguard.peer[].preshared-key, and Wireguard0 alone also carries
// security-level.private - a boolean access-level flag set to private on that
// interface and to public on the others. A boolean cannot hold key material,
// so counting it would refuse an interface over its access level while an
// identical neighbour passed.
//
// The one thing a secret-naming key may hold is a redaction marker, which is
// a digest of the secret rather than the secret. Anything else - a plain
// string, an object, an array, a marker with one character changed - refuses,
// so a caller who forgets to redact, or redacts into the wrong shape, is
// stopped rather than trusted.
bool mentions_secret(const nlohmann::json& document) {
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            if (ndms_key_could_name_a_secret(key) && !value.is_boolean() &&
                !value.is_number() && !value.is_null() &&
                !(value.is_string() && is_ndms_secret_redaction_marker(
                                           value.get<std::string>()))) {
                return true;
            }
            if (mentions_secret(value)) return true;
        }
        return false;
    }
    if (document.is_array()) {
        for (const auto& element : document) {
            if (mentions_secret(element)) return true;
        }
    }
    return false;
}

// The ASC document answers three different things, and only two of them are
// protocols. Measured: "{}" for plain WireGuard; jc/jmin/jmax present for
// AmneziaWG; and for an interface that does not exist, a non-empty object
// holding an RCI error envelope - status: [{status: "error", ...}]. An
// emptiness test reads that third answer as AmneziaWG, so classify instead,
// and refuse anything that is none of the three.
std::optional<NdmsNativeAscClass> classify_asc(
    const nlohmann::json& asc_document) {
    if (!asc_document.is_object()) return std::nullopt;
    // The error envelope, exactly as the firmware writes it.
    if (asc_document.contains("status") &&
        asc_document["status"].is_array()) {
        return std::nullopt;
    }
    if (asc_document.empty()) return NdmsNativeAscClass::plain_wireguard;
    if (asc_document.contains("jc") && asc_document.contains("jmin") &&
        asc_document.contains("jmax")) {
        return NdmsNativeAscClass::amnezia_wg;
    }
    return std::nullopt;
}

void update_field(Sha256& hasher, const std::string& value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    unsigned char length[8];
    for (unsigned i = 0U; i < 8U; ++i) {
        length[i] = static_cast<unsigned char>(size >> (56U - i * 8U));
    }
    hasher.update(reinterpret_cast<const char*>(length), sizeof(length));
    hasher.update(value.data(), value.size());
}

} // namespace

NdmsNativeTargetEvidenceResult build_ndms_native_target_evidence(
    const std::string& interface_name,
    const nlohmann::json& config_document,
    const nlohmann::json& status_document,
    const nlohmann::json& asc_document) {
    if (!config_document.is_object()) {
        return refuse(Reason::config_not_object);
    }
    if (!status_document.is_object()) {
        return refuse(Reason::status_not_object);
    }
    const auto identity = parse_ndms_wireguard_identity(interface_name);
    if (!identity || identity->canonical_name() != interface_name) {
        return refuse(Reason::identity_mismatch);
    }
    // Both documents must agree they describe this exact interface. A read
    // that silently answered about another one would attach this evidence to
    // the wrong target - and the target is what gets deleted.
    const auto id = status_document.value("id", std::string{});
    const auto name =
        status_document.value("interface-name", std::string{});
    if ((!id.empty() && id != interface_name) ||
        (!name.empty() && name != interface_name) ||
        (id.empty() && name.empty())) {
        return refuse(Reason::identity_mismatch);
    }
    if (status_document.value("type", std::string{}) != "Wireguard") {
        return refuse(Reason::type_not_wireguard);
    }
    if (mentions_secret(config_document) ||
        mentions_secret(status_document)) {
        return refuse(Reason::secret_material_present);
    }

    // Measured strings, exactly. A link state we cannot read is not one we
    // may call down, and "down" is what authorizes an exact-owned delete.
    const auto link = status_document.value("link", std::string{});
    if (link != "up" && link != "down") {
        return refuse(Reason::link_state_unknown);
    }

    // Secret-independent revision over the config document plus the public
    // status fields that decide identity. Serialized canonically by
    // nlohmann's ordered dump, so two reads of an unchanged interface hash
    // the same and any drift moves it.
    Sha256 hasher;
    update_field(hasher, "keen-pbr.ndms-native-target-revision.v1");
    update_field(hasher, interface_name);
    update_field(hasher, config_document.dump());
    update_field(hasher,
                 status_document.value("description", std::string{}));
    update_field(hasher, status_document.value("state", std::string{}));
    if (status_document.contains("wireguard") &&
        status_document["wireguard"].is_object()) {
        update_field(hasher,
                     status_document["wireguard"].value(
                         "public-key", std::string{}));
    }

    const auto asc_class = classify_asc(asc_document);
    if (!asc_class) return refuse(Reason::asc_not_classifiable);

    NdmsNativeTargetEvidenceResult result;
    NdmsNativeImportRecoveryTargetEvidence evidence;
    evidence.interface_name = interface_name;
    evidence.link_down = link == "down";
    evidence.full_revision = "ndms-rci-full-v1-" + hasher.hex_digest();
    result.evidence = std::move(evidence);
    result.asc_class = asc_class;
    return result;
}

const char* ndms_native_target_read_failure_name(
    const NdmsNativeTargetReadFailure::Reason reason) noexcept {
    switch (reason) {
    case Reason::config_not_object:
        return "config_not_object";
    case Reason::status_not_object:
        return "status_not_object";
    case Reason::identity_mismatch:
        return "identity_mismatch";
    case Reason::type_not_wireguard:
        return "type_not_wireguard";
    case Reason::link_state_unknown:
        return "link_state_unknown";
    case Reason::secret_material_present:
        return "secret_material_present";
    case Reason::asc_not_classifiable:
        return "asc_not_classifiable";
    }
    return "config_not_object";
}

const char* ndms_native_asc_class_name(
    const NdmsNativeAscClass value) noexcept {
    switch (value) {
    case NdmsNativeAscClass::plain_wireguard:
        return "plain_wireguard";
    case NdmsNativeAscClass::amnezia_wg:
        return "amnezia_wg";
    }
    return "plain_wireguard";
}

} // namespace keen_pbr3
