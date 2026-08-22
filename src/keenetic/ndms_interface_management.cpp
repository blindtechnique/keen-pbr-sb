#include "ndms_interface_management.hpp"

#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>

namespace keen_pbr3 {

namespace {

bool is_management_candidate_kind(const NdmsTunnelKind kind) noexcept {
    return kind == NdmsTunnelKind::wireguard ||
           kind == NdmsTunnelKind::amnezia_wireguard;
}

bool has_non_whitespace(const std::string& value) {
    return std::any_of(
        value.begin(),
        value.end(),
        [](const unsigned char character) {
            return std::isspace(character) == 0;
        });
}

std::string make_observed_revision(
    const NdmsTunnelInterface& interface) {
    if (interface.inventory_revision.empty()) return {};

    // Hash the safe inventory digest again together with its stable identity
    // and kind. This remains an observation token, not a concurrency guard.
    const auto material = nlohmann::json{
        {"schema", "ndms-observed-revision-v1"},
        {"id", interface.id},
        {"firmware_interface_name", interface.firmware_interface_name},
        {"kind", ndms_tunnel_kind_name(interface.kind)},
        {"inventory_revision", interface.inventory_revision},
    };
    return "ndms-v1-" + Sha256::hex(material.dump());
}

} // namespace

NdmsInterfaceManagementReadiness assess_ndms_interface_management(
    const NdmsTunnelInterface& interface) {
    NdmsInterfaceManagementReadiness readiness;
    const bool supported_kind =
        is_management_candidate_kind(interface.kind);
    readiness.candidate =
        supported_kind &&
        interface.role == NdmsInterfaceRole::client;
    readiness.identity_stable =
        has_non_whitespace(interface.id) &&
        has_non_whitespace(interface.firmware_interface_name) &&
        interface.kernel_name.has_value() &&
        has_non_whitespace(*interface.kernel_name);
    readiness.observed_revision = make_observed_revision(interface);

    if (!supported_kind) {
        readiness.blockers.push_back(
            NdmsInterfaceManagementBlocker::unsupported_kind);
    }
    if (interface.role == NdmsInterfaceRole::unknown) {
        readiness.blockers.push_back(
            NdmsInterfaceManagementBlocker::role_unknown);
    } else if (interface.role != NdmsInterfaceRole::client) {
        readiness.blockers.push_back(
            NdmsInterfaceManagementBlocker::unsupported_role);
    }
    if (!readiness.identity_stable) {
        readiness.blockers.push_back(
            NdmsInterfaceManagementBlocker::kernel_identity_unresolved);
    }

    // These guards are intentionally explicit and unconditional. An observed
    // inventory revision is not a full configuration snapshot and cannot
    // replace an optimistic re-read immediately before a future mutation.
    readiness.blockers.push_back(
        NdmsInterfaceManagementBlocker::typed_rci_unavailable);
    readiness.blockers.push_back(
        NdmsInterfaceManagementBlocker::automatic_backup_unavailable);
    readiness.blockers.push_back(
        NdmsInterfaceManagementBlocker::ownership_unknown);
    readiness.blockers.push_back(
        NdmsInterfaceManagementBlocker::optimistic_revision_unavailable);

    return readiness;
}

const char* ndms_interface_management_blocker_name(
    const NdmsInterfaceManagementBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsInterfaceManagementBlocker::unsupported_kind:
        return "unsupported_kind";
    case NdmsInterfaceManagementBlocker::role_unknown:
        return "role_unknown";
    case NdmsInterfaceManagementBlocker::unsupported_role:
        return "unsupported_role";
    case NdmsInterfaceManagementBlocker::kernel_identity_unresolved:
        return "kernel_identity_unresolved";
    case NdmsInterfaceManagementBlocker::typed_rci_unavailable:
        return "typed_rci_unavailable";
    case NdmsInterfaceManagementBlocker::automatic_backup_unavailable:
        return "automatic_backup_unavailable";
    case NdmsInterfaceManagementBlocker::ownership_unknown:
        return "ownership_unknown";
    case NdmsInterfaceManagementBlocker::optimistic_revision_unavailable:
        return "optimistic_revision_unavailable";
    }
    return "unknown";
}

namespace {

class LifecycleWriterGuard final
    : public NdmsNativeExactMutationPreDispatchGuard {
public:
    explicit LifecycleWriterGuard(NdmsNativeWriterLease& writer) noexcept
        : writer_(writer) {}

    bool authorize_dispatch() noexcept override {
        try {
            writer_.verify_held();
            return true;
        } catch (...) {
            return false;
        }
    }

private:
    NdmsNativeWriterLease& writer_;
};

bool acknowledged(
    const NdmsNativeExactMutationTransportResult& result) noexcept {
    return result.pre_dispatch_guard_passed &&
           result.response_manifest.acknowledged_needs_observation();
}

} // namespace

NdmsNativeInterfaceLifecycleCoordinator::
NdmsNativeInterfaceLifecycleCoordinator(
    NdmsNativeExactMutationBackend& backend) noexcept
    : backend_(&backend) {}

NdmsNativeExactMutationTransportResult
NdmsNativeInterfaceLifecycleCoordinator::dispatch_once(
    NdmsNativeExactMutationRequest request,
    NdmsNativeExactMutationPreDispatchGuard& guard) {
    auto authority = NdmsNativeExactMutationDispatchAuthority{
        NdmsNativeExactMutationDispatchAuthority::ConstructionKey{}};
    if (!authority.consume()) {
        throw NdmsNativeExactMutationTransportError(
            "native lifecycle authority is invalid");
    }
    auto capability = NdmsNativeExactMutationDispatchCapability{
        NdmsNativeExactMutationDispatchCapability::ConstructionKey{}};
    return post_ndms_native_exact_mutation_once(
        std::move(capability),
        std::move(request),
        guard,
        *backend_);
}

NdmsNativeInterfaceLifecycleResult
NdmsNativeInterfaceLifecycleCoordinator::apply_once(
    NdmsNativeWriterLease& writer,
    std::string interface_name,
    const NdmsNativeInterfaceLifecycleAction action) noexcept {
    NdmsNativeInterfaceLifecycleResult result;
    if (backend_ == nullptr) return result;
    try {
        writer.verify_held();
        LifecycleWriterGuard guard{writer};
        const auto dispatch = [this, &guard, &result](
                                  NdmsNativeExactMutationRequest request) {
            auto current = dispatch_once(std::move(request), guard);
            result.request_may_have_been_dispatched =
                result.request_may_have_been_dispatched ||
                current.request_may_have_been_dispatched;
            return current;
        };

        if (action == NdmsNativeInterfaceLifecycleAction::down) {
            const auto down = dispatch(
                NdmsNativeExactMutationRequest::
                    disable_existing_interface(interface_name));
            if (!acknowledged(down)) {
                result.status = result.request_may_have_been_dispatched
                                    ? NdmsNativeInterfaceLifecycleStatus::
                                          outcome_unknown
                                    : NdmsNativeInterfaceLifecycleStatus::
                                          not_started;
                return result;
            }
        } else if (action == NdmsNativeInterfaceLifecycleAction::up) {
            const auto up = dispatch(
                NdmsNativeExactMutationRequest::
                    enable_existing_interface(interface_name));
            if (!acknowledged(up)) {
                result.status = result.request_may_have_been_dispatched
                                    ? NdmsNativeInterfaceLifecycleStatus::
                                          outcome_unknown
                                    : NdmsNativeInterfaceLifecycleStatus::
                                          not_started;
                return result;
            }
        } else {
            const auto down = dispatch(
                NdmsNativeExactMutationRequest::
                    disable_existing_interface(interface_name));
            if (!down.pre_dispatch_guard_passed &&
                !down.request_may_have_been_dispatched) {
                return result;
            }
            // Even if the down acknowledgement was lost, always issue the
            // exact up command so a restart cannot strand a working VPN down.
            const auto up = dispatch(
                NdmsNativeExactMutationRequest::
                    enable_existing_interface(interface_name));
            if (!acknowledged(up)) {
                result.status = result.request_may_have_been_dispatched
                                    ? NdmsNativeInterfaceLifecycleStatus::
                                          outcome_unknown
                                    : NdmsNativeInterfaceLifecycleStatus::
                                          not_started;
                return result;
            }
        }

        const auto save = dispatch(
            NdmsNativeExactMutationRequest::save_configuration());
        result.status = acknowledged(save)
                            ? NdmsNativeInterfaceLifecycleStatus::completed
                            : result.request_may_have_been_dispatched
                                  ? NdmsNativeInterfaceLifecycleStatus::
                                        outcome_unknown
                                  : NdmsNativeInterfaceLifecycleStatus::
                                        not_started;
        return result;
    } catch (...) {
        result.status = result.request_may_have_been_dispatched
                            ? NdmsNativeInterfaceLifecycleStatus::
                                  outcome_unknown
                            : NdmsNativeInterfaceLifecycleStatus::not_started;
        return result;
    }
}

} // namespace keen_pbr3
