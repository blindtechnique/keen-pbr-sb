#include "ndms_native_target_evidence.hpp"

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

// Any key that could carry secret material. Measured absent today; if the
// firmware ever starts returning one, that is a changed world and this must
// stop rather than sanitize.
bool mentions_secret(const nlohmann::json& document) {
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            std::string lowered = key;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                           [](const unsigned char ch) {
                               return static_cast<char>(std::tolower(ch));
                           });
            if (lowered.find("private") != std::string::npos ||
                lowered.find("preshared") != std::string::npos ||
                lowered.find("secret") != std::string::npos) {
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

    NdmsNativeTargetEvidenceResult result;
    NdmsNativeImportRecoveryTargetEvidence evidence;
    evidence.interface_name = interface_name;
    evidence.link_down = link == "down";
    evidence.full_revision = "ndms-rci-full-v1-" + hasher.hex_digest();
    result.evidence = std::move(evidence);
    // Measured discriminator: plain WireGuard answers "{}" here; a non-empty
    // ASC object is AmneziaWG. Never inferred from a name.
    result.amnezia = asc_document.is_object() && !asc_document.empty();
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
    }
    return "config_not_object";
}

} // namespace keen_pbr3
