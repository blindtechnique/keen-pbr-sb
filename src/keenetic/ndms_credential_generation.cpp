#include "ndms_credential_generation.hpp"

#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

// The shape measured on 5.1.1: an object keyed by user name, each value an
// object carrying `password` (an object of hash kinds) and `tag`.
//
// Every member must be an object, which is what rejects an error envelope
// keyed by `status` with an array value. At least one member must carry
// password material, which is what rejects a document that could not witness
// the change this authority exists to witness.
bool looks_like_user_document(const nlohmann::json& document) {
    if (!document.is_object() || document.empty()) return false;

    bool any_password_material = false;
    for (const auto& entry : document.items()) {
        if (!entry.value().is_object()) return false;
        const auto password = entry.value().find("password");
        if (password != entry.value().end() && password->is_object() &&
            !password->empty()) {
            any_password_material = true;
        }
    }
    return any_password_material;
}

} // namespace

const char* ndms_credential_generation_verdict_name(
    const NdmsCredentialGenerationVerdict verdict) noexcept {
    switch (verdict) {
    case NdmsCredentialGenerationVerdict::known:
        return "known";
    case NdmsCredentialGenerationVerdict::unreadable:
        return "unreadable";
    }
    return "unreadable";
}

const char* ndms_credential_change_name(
    const NdmsCredentialChange change) noexcept {
    switch (change) {
    case NdmsCredentialChange::unchanged:
        return "unchanged";
    case NdmsCredentialChange::changed:
        return "changed";
    case NdmsCredentialChange::unknown:
        return "unknown";
    }
    return "unknown";
}

NdmsCredentialGeneration ndms_credential_generation(
    const std::string& document) {
    NdmsCredentialGeneration generation;
    if (document.empty()) return generation;

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(document);
    } catch (const nlohmann::json::exception&) {
        return generation;
    }
    if (!looks_like_user_document(parsed)) return generation;

    // Digested from the exact bytes rather than from a re-serialization: the
    // question is whether the firmware's answer changed, and normalizing it
    // first would discard changes the firmware chose to make.
    generation.verdict = NdmsCredentialGenerationVerdict::known;
    generation.digest = Sha256::hex(document);
    return generation;
}

NdmsCredentialChange ndms_credential_change(
    const NdmsCredentialGeneration& previous,
    const NdmsCredentialGeneration& current) noexcept {
    if (previous.verdict != NdmsCredentialGenerationVerdict::known ||
        current.verdict != NdmsCredentialGenerationVerdict::known) {
        return NdmsCredentialChange::unknown;
    }
    return previous.digest == current.digest
               ? NdmsCredentialChange::unchanged
               : NdmsCredentialChange::changed;
}

} // namespace keen_pbr3
