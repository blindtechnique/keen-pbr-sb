#pragma once

#include "ndms_catalog_cache.hpp"
#include "ndms_native_target_evidence.hpp"

#include "../http/http_transport.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

// The direct mutation observer has no caller-controlled origin or path.  The
// destination policy is still applied at socket-open time: judging the URL is
// not enough to defend a privileged control-plane read from proxying or a
// future hostname change.
inline constexpr std::string_view kNdmsNativeDirectRuntimeCatalogEndpoint{
    "http://127.0.0.1:79/rci/show/interface"};
inline constexpr std::string_view
    kNdmsNativeDirectRunningConfigCatalogEndpoint{
    "http://127.0.0.1:79/rci/show/rc/interface"};
inline constexpr auto kNdmsNativeDirectObservationTimeout =
    std::chrono::seconds{4};
inline constexpr std::size_t kNdmsNativeDirectCatalogMaximumBytes =
    2U * 1024U * 1024U;
inline constexpr std::size_t kNdmsNativeDirectTargetMaximumBytes =
    512U * 1024U;
inline constexpr std::size_t kNdmsNativeDirectMaximumMarkerSightings = 1U;
inline constexpr std::size_t kNdmsNativeDirectMaximumEvidenceTargets = 2U;

inline bool ndms_native_direct_loopback_destination_permitted(
    const std::string_view address) noexcept {
    return address == "127.0.0.1";
}

enum class NdmsNativeDirectObservationFailure {
    none,
    invalid_marker,
    invalid_target,
    transport_failed,
    response_too_large,
    empty_response,
    malformed_json,
    duplicate_json_key,
    response_not_object,
    rci_error_response,
    catalog_malformed,
    catalog_unavailable,
    catalog_unsafe,
    ambiguous_marker,
    marker_target_not_managed_wireguard,
    target_evidence_refused,
};

enum class NdmsNativeDirectDocumentKind {
    none,
    catalog,
    target_config,
    target_runtime,
    target_asc,
};

enum class NdmsNativeDirectCatalogScope {
    // Live interface/status view from show/interface.
    runtime_state,
    // Current NDMS running configuration from show/rc/interface.  This is
    // not proof that `system configuration save` reached startup storage.
    running_config,
};

struct NdmsNativeDirectCatalogObservation final {
    std::optional<NdmsCatalogSnapshot> snapshot;
    NdmsNativeDirectObservationFailure failure{
        NdmsNativeDirectObservationFailure::none};
    NdmsNativeDirectCatalogScope scope{
        NdmsNativeDirectCatalogScope::runtime_state};
};

struct NdmsNativeDirectTargetProtocol final {
    std::string interface_name;
    NdmsNativeAscClass asc_class{NdmsNativeAscClass::plain_wireguard};
};

// One coherent recovery measurement.  catalog_revision is present only when
// the full Wireguard0..126 catalog is safe and every required exact target
// read succeeded.  A caller may then record a durable observation stamp for
// this revision and attach that stamp to this same snapshot/evidence payload.
// The gateway itself owns no durable authority and mints no stamp.
struct NdmsNativeDirectRecoveryObservation final {
    std::optional<NdmsCatalogSnapshot> snapshot;
    std::vector<NdmsNativeImportRecoveryTargetEvidence> target_evidence;
    std::vector<NdmsNativeDirectTargetProtocol> target_protocols;
    std::string catalog_revision;
    NdmsNativeDirectObservationFailure failure{
        NdmsNativeDirectObservationFailure::none};
    NdmsNativeDirectDocumentKind failed_document{
        NdmsNativeDirectDocumentKind::none};
    std::string failed_interface;
    std::optional<NdmsNativeTargetReadFailure::Reason>
        target_evidence_failure;
    NdmsNativeDirectCatalogScope catalog_scope{
        NdmsNativeDirectCatalogScope::runtime_state};
    // Kept separately so injected/adapted gateways cannot attach a complete
    // running-config payload to a runtime-state request (or vice versa).
    NdmsNativeDirectCatalogScope requested_catalog_scope{
        NdmsNativeDirectCatalogScope::runtime_state};

    bool complete() const noexcept;
};

// Read-only, bounded production gateway for mutation/recovery observations.
// It exposes no mutation backend, writer token, save operation or production
// issuer.  Tests inject a transport; production uses the ordinary HttpClient
// transport with an exact actual-peer filter, zero redirects and fixed caps.
class NdmsNativeDirectObservationGateway final {
public:
    using Clock = std::chrono::steady_clock;
    using NowFn = std::function<Clock::time_point()>;

    NdmsNativeDirectObservationGateway();
    explicit NdmsNativeDirectObservationGateway(
        std::shared_ptr<HttpTransport> transport,
        NowFn now_fn = {});

    NdmsNativeDirectCatalogObservation observe_catalog(
        NdmsNativeDirectCatalogScope scope =
            NdmsNativeDirectCatalogScope::runtime_state) const noexcept;

    // Reads the catalog exactly once.  Per-target reads are issued only for a
    // unique marker sighting and/or an occupied exact expected target.  With
    // one permitted marker sighting this is bounded to two unique targets,
    // each with the exact config/runtime/ASC triple.
    NdmsNativeDirectRecoveryObservation observe_recovery(
        std::string_view marker,
        const std::optional<std::string>& expected_target =
            std::nullopt) const noexcept;

    // Delete admission needs two separately measured catalog scopes. Target
    // config/runtime/ASC evidence remains the same bounded exact triple; only
    // the complete catalog endpoint selected here differs.
    NdmsNativeDirectRecoveryObservation observe_recovery(
        NdmsNativeDirectCatalogScope scope,
        std::string_view marker,
        const std::optional<std::string>& expected_target =
            std::nullopt) const noexcept;

private:
    std::shared_ptr<HttpTransport> transport_;
    NowFn now_fn_;
};

const char* ndms_native_direct_observation_failure_name(
    NdmsNativeDirectObservationFailure failure) noexcept;

} // namespace keen_pbr3
