#include "ndms_native_secret_redaction.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>

namespace keen_pbr3 {

const char kNdmsSecretRedactionPrefix[] = "kpbr-redacted-v1-";

namespace {

constexpr std::size_t kDigestHexLength = 64U;

void update_field(Sha256& hasher, const std::string& value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    unsigned char length[8];
    for (unsigned i = 0U; i < 8U; ++i) {
        length[i] = static_cast<unsigned char>(size >> (56U - i * 8U));
    }
    hasher.update(reinterpret_cast<const char*>(length), sizeof(length));
    hasher.update(value.data(), value.size());
}

// Length-prefixed so no concatenation of one triple can be read as another.
std::string marker_for(const std::string& interface_name,
                       const std::string& path, const std::string& value) {
    Sha256 hasher;
    update_field(hasher, "keen-pbr.ndms-secret-redaction.v1");
    update_field(hasher, interface_name);
    update_field(hasher, path);
    update_field(hasher, value);
    return kNdmsSecretRedactionPrefix + hasher.hex_digest();
}

// A value that cannot hold material: replacing it would only make the
// document differ from the firmware's for no gain.
bool cannot_carry_material(const nlohmann::json& value) {
    return value.is_boolean() || value.is_number() || value.is_null();
}

nlohmann::json redact(const nlohmann::json& document,
                      const std::string& interface_name,
                      const std::string& path, bool under_secret_key) {
    if (document.is_object()) {
        auto copy = nlohmann::json::object();
        for (const auto& [key, value] : document.items()) {
            copy[key] =
                redact(value, interface_name, path + "/" + key,
                       under_secret_key || ndms_key_could_name_a_secret(key));
        }
        return copy;
    }
    if (document.is_array()) {
        auto copy = nlohmann::json::array();
        for (std::size_t i = 0U; i < document.size(); ++i) {
            copy.push_back(redact(document[i], interface_name,
                                  path + "/" + std::to_string(i),
                                  under_secret_key));
        }
        return copy;
    }
    if (!under_secret_key || cannot_carry_material(document)) return document;
    // Already a marker: leave it. A caller that redacts defensively, or a
    // document that has been through here before, must not produce a second,
    // different revision for an unchanged interface. Nothing the firmware
    // emits can collide with the shape - a WireGuard key is 44 base64
    // characters, a marker is 81 of prefix and hex.
    if (document.is_string() &&
        is_ndms_secret_redaction_marker(document.get<std::string>())) {
        return document;
    }
    // Digest the serialized value, not just its string content: a secret
    // hidden as a number inside a secret-named object still moves the marker.
    return marker_for(interface_name, path,
                      document.is_string() ? document.get<std::string>()
                                           : document.dump());
}

} // namespace

bool ndms_key_could_name_a_secret(const std::string& key) {
    std::string lowered = key;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](const unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return lowered.find("private") != std::string::npos ||
           lowered.find("preshared") != std::string::npos ||
           lowered.find("secret") != std::string::npos;
}

bool is_ndms_secret_redaction_marker(const std::string& value) {
    const std::string prefix = kNdmsSecretRedactionPrefix;
    if (value.size() != prefix.size() + kDigestHexLength) return false;
    if (value.compare(0U, prefix.size(), prefix) != 0) return false;
    return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(
                                           prefix.size()),
                       value.end(), [](const unsigned char ch) {
                           return (ch >= '0' && ch <= '9') ||
                                  (ch >= 'a' && ch <= 'f');
                       });
}

nlohmann::json redact_ndms_secret_material(
    const nlohmann::json& document, const std::string& interface_name) {
    return redact(document, interface_name, "", false);
}

} // namespace keen_pbr3
