#include "ndms_native_interface_delete.hpp"

#include "ndms_native_create_policy.hpp"

namespace keen_pbr3 {

namespace {

// The firmware answers a slot that does not exist with a zero-byte body, and
// an unreadable read arrives as nullopt. Only a real object counts as present:
// anything else is either absence or an answer we refuse to interpret, and
// both are handled by the caller rather than guessed at here.
bool document_describes_an_interface(
    const std::optional<nlohmann::json>& document) {
    return document.has_value() && document->is_object() &&
           !document->empty();
}

std::string description_of(const nlohmann::json& document) {
    const auto it = document.find("description");
    if (it == document.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

} // namespace

std::string ndms_native_interface_delete_command(
    const std::string& interface_name) {
    // The whole of what the router is told. Keenetic's CLI removes an
    // interface with `no interface <name>`; nothing else is issued, and in
    // particular no `system configuration save`, so a mistake is erased by a
    // reboot rather than persisted.
    return "no interface " + interface_name;
}

NdmsNativeImportRecoveryDeleteOutcome delete_exact_owned_ndms_interface(
    const std::string& interface_name,
    const std::string& marker,
    const NdmsNativeInterfaceDeleteDependencies& dependencies) {
    if (!dependencies.read_document || !dependencies.run_command) {
        return NdmsNativeImportRecoveryDeleteOutcome::failed;
    }
    if (marker.empty()) {
        // Without a marker there is no evidence of ownership to check, and
        // this operation exists precisely to refuse in that case.
        return NdmsNativeImportRecoveryDeleteOutcome::refused;
    }
    // The dispatcher already checked eligibility. Checking again here is the
    // last line before an unrecoverable action, and this function is also
    // reachable from future callers that have not.
    if (!ndms_native_created_target_is_eligible(interface_name)) {
        return NdmsNativeImportRecoveryDeleteOutcome::refused;
    }

    const std::string config_path =
        "show/rc/interface/" + interface_name;
    const std::string runtime_path = "show/interface/" + interface_name;

    const auto before = dependencies.read_document(config_path);
    if (!before.has_value()) {
        // The read failed. Deleting on an unknown world is exactly what a
        // fail-closed rollback must not do.
        return NdmsNativeImportRecoveryDeleteOutcome::failed;
    }
    if (!document_describes_an_interface(before)) {
        // Already gone. The postcondition this step exists to establish
        // already holds, and refusing here would strand a rollback with
        // nothing left to do. Absence is still proven below rather than
        // assumed from this one read.
        const auto runtime = dependencies.read_document(runtime_path);
        if (!runtime.has_value()) {
            return NdmsNativeImportRecoveryDeleteOutcome::failed;
        }
        return document_describes_an_interface(runtime)
                   ? NdmsNativeImportRecoveryDeleteOutcome::failed
                   : NdmsNativeImportRecoveryDeleteOutcome::
                         deleted_confirmed;
    }

    // Ownership re-checked against a fresh read, not inherited from the
    // observation that authorized the plan. Between that observation and this
    // instant the interface may have stopped being ours - renamed, replaced,
    // re-described - and one that is no longer ours must never be removed.
    // Containment, matching how the marker is detected everywhere else: the
    // importer may compose the marker with other text.
    if (description_of(*before).find(marker) == std::string::npos) {
        return NdmsNativeImportRecoveryDeleteOutcome::refused;
    }

    if (!dependencies.run_command(
            ndms_native_interface_delete_command(interface_name))) {
        return NdmsNativeImportRecoveryDeleteOutcome::failed;
    }

    // deleted_confirmed is what advances the WAL into a phase that asserts
    // absence, so it is never returned on the strength of an exit code. Both
    // documents must agree the interface is gone.
    const auto after_config = dependencies.read_document(config_path);
    const auto after_runtime = dependencies.read_document(runtime_path);
    if (!after_config.has_value() || !after_runtime.has_value()) {
        return NdmsNativeImportRecoveryDeleteOutcome::failed;
    }
    if (document_describes_an_interface(after_config) ||
        document_describes_an_interface(after_runtime)) {
        return NdmsNativeImportRecoveryDeleteOutcome::failed;
    }
    return NdmsNativeImportRecoveryDeleteOutcome::deleted_confirmed;
}


} // namespace keen_pbr3
