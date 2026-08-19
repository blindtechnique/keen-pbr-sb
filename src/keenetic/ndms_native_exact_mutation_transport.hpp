#pragma once

#include "ndms_native_import_transport.hpp"

#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {

struct NdmsNativePanelDeleteExecutionPlan;
struct NdmsNativePanelDeleteExecutionResult;
class NdmsNativePanelDeleteExecutorDependencies;
#ifdef KEEN_PBR3_TESTING
class NdmsNativeExactMutationDispatchAuthorityTestIssuer;
#endif

inline constexpr std::size_t
    kNdmsNativeExactMutationMaximumResponseBytes = 64U * 1024U;
inline constexpr auto kNdmsNativeExactMutationRequiredDispatchWindow =
    std::chrono::seconds{17};

enum class NdmsNativeExactMutationKind {
    delete_managed_interface,
    save_configuration,
};

enum class NdmsNativeExactMutationResponseOutcome {
    guard_rejected,
    transport_failed,
    body_too_large,
    http_status_not_200,
    content_type_not_json,
    body_empty,
    shape_not_acknowledged,
    acknowledged_needs_observation,
};

class NdmsNativeExactMutationTransportError final
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Closed, move-only command vocabulary for the two RCI writes used by panel
// deletion. Callers cannot supply a URL, a JSON tree or an arbitrary command.
// A delete target must be a canonical managed candidate (Wireguard5..98).
class NdmsNativeExactMutationRequest final {
public:
    static NdmsNativeExactMutationRequest delete_managed_interface(
        std::string target);
    static NdmsNativeExactMutationRequest save_configuration();

    NdmsNativeExactMutationRequest(
        const NdmsNativeExactMutationRequest&) = delete;
    NdmsNativeExactMutationRequest& operator=(
        const NdmsNativeExactMutationRequest&) = delete;
    NdmsNativeExactMutationRequest(
        NdmsNativeExactMutationRequest&& other) noexcept;
    NdmsNativeExactMutationRequest& operator=(
        NdmsNativeExactMutationRequest&& other) noexcept;
    ~NdmsNativeExactMutationRequest();

    NdmsNativeExactMutationKind kind() const noexcept;
    std::string_view target() const noexcept;
    std::size_t content_length() const noexcept;

    // Writes the exact stock RCI body once. The sink is bounded and wiping;
    // false means either a replay/moved-from request or a sink failure.
    bool write_body_once(NdmsNativeSecretBuffer& sink) noexcept;

private:
    NdmsNativeExactMutationRequest(
        NdmsNativeExactMutationKind kind,
        std::string target) noexcept;
    void invalidate() noexcept;

    NdmsNativeExactMutationKind kind_{
        NdmsNativeExactMutationKind::save_configuration};
    std::string target_;
    bool available_{false};
};

struct NdmsNativeExactMutationRawResponse final {
    NdmsNativeExactMutationRawResponse();

    bool request_may_have_been_dispatched{false};
    bool transport_ok{false};
    int status_code{0};
    bool content_type_seen{false};
    bool content_type_is_json{false};
    bool content_type_ambiguous{false};
    bool callback_failed{false};
    NdmsNativeSecretBuffer body;
};

class NdmsNativeExactMutationPreDispatchGuard {
public:
    virtual ~NdmsNativeExactMutationPreDispatchGuard() = default;
    virtual bool authorize_dispatch() noexcept = 0;
};

struct NdmsNativeExactMutationBackendTrace final {
    bool pre_dispatch_guard_evaluated{false};
    bool pre_dispatch_guard_passed{false};
    bool perform_started{false};
};

class NdmsNativeExactMutationDispatchCapability;
struct NdmsNativeExactMutationTransportResult;

// Opaque, move-only production authority required by the one exact panel
// delete transaction entry point. This slice intentionally has no production
// issuer: wiring it requires the still-unproven global NDMS writer lease.
class NdmsNativeExactMutationDispatchAuthority final {
public:
    NdmsNativeExactMutationDispatchAuthority(
        NdmsNativeExactMutationDispatchAuthority&& other) noexcept;
    NdmsNativeExactMutationDispatchAuthority& operator=(
        NdmsNativeExactMutationDispatchAuthority&& other) noexcept;
    NdmsNativeExactMutationDispatchAuthority(
        const NdmsNativeExactMutationDispatchAuthority&) = delete;
    NdmsNativeExactMutationDispatchAuthority& operator=(
        const NdmsNativeExactMutationDispatchAuthority&) = delete;
    ~NdmsNativeExactMutationDispatchAuthority() = default;

private:
    struct ConstructionKey final {};
    explicit NdmsNativeExactMutationDispatchAuthority(
        ConstructionKey) noexcept : valid_(true) {}
    bool consume() noexcept;

    bool valid_{false};

    friend NdmsNativePanelDeleteExecutionResult
    execute_ndms_native_panel_delete_transaction(
        const NdmsNativePanelDeleteExecutionPlan&,
        NdmsNativeExactMutationDispatchAuthority&&,
        const NdmsNativePanelDeleteExecutorDependencies&);
#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeExactMutationDispatchAuthorityTestIssuer;
#endif
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeExactMutationDispatchAuthorityTestIssuer final {
public:
    static NdmsNativeExactMutationDispatchAuthority issue() noexcept;
    static bool consume_for_test(
        NdmsNativeExactMutationDispatchAuthority& authority) noexcept;
};
#endif

// The backend has no endpoint argument. Its only production implementation
// posts once to the compile-time loopback RCI URL; no generic HttpTransport
// or caller-selected redirect/proxy path is involved.
class NdmsNativeExactMutationBackend {
public:
    virtual ~NdmsNativeExactMutationBackend() = default;

private:
    virtual NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&& capability,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeExactMutationPreDispatchGuard& guard,
        NdmsNativeExactMutationBackendTrace& trace) = 0;

    friend NdmsNativeExactMutationTransportResult
    post_ndms_native_exact_mutation_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeExactMutationRequest,
        NdmsNativeExactMutationPreDispatchGuard&,
        NdmsNativeExactMutationBackend&);
};

class NdmsNativeLibcurlExactMutationBackend final
    : public NdmsNativeExactMutationBackend {
private:
    NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&& capability,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeExactMutationPreDispatchGuard& guard,
        NdmsNativeExactMutationBackendTrace& trace) override;
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeExactMutationDispatchCapabilityTestIssuer;
#endif

// One-shot callsite barrier. Production construction is deliberately limited
// to one exact free-function signature that also consumes the opaque writer
// authority above. There is no extensible named-class friend that another
// translation unit could define to mint this capability.
class NdmsNativeExactMutationDispatchCapability final {
public:
    NdmsNativeExactMutationDispatchCapability(
        NdmsNativeExactMutationDispatchCapability&& other) noexcept;
    NdmsNativeExactMutationDispatchCapability& operator=(
        NdmsNativeExactMutationDispatchCapability&& other) noexcept;
    NdmsNativeExactMutationDispatchCapability(
        const NdmsNativeExactMutationDispatchCapability&) = delete;
    NdmsNativeExactMutationDispatchCapability& operator=(
        const NdmsNativeExactMutationDispatchCapability&) = delete;
    ~NdmsNativeExactMutationDispatchCapability() = default;

private:
    struct ConstructionKey final {};
    explicit NdmsNativeExactMutationDispatchCapability(
        ConstructionKey) noexcept;
    bool consume() noexcept;

    bool valid_{false};

    friend NdmsNativePanelDeleteExecutionResult
    execute_ndms_native_panel_delete_transaction(
        const NdmsNativePanelDeleteExecutionPlan&,
        NdmsNativeExactMutationDispatchAuthority&&,
        const NdmsNativePanelDeleteExecutorDependencies&);
#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeExactMutationDispatchCapabilityTestIssuer;
#endif
    friend NdmsNativeExactMutationTransportResult
    post_ndms_native_exact_mutation_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeExactMutationRequest,
        NdmsNativeExactMutationPreDispatchGuard&,
        NdmsNativeExactMutationBackend&);
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeExactMutationDispatchCapabilityTestIssuer final {
public:
    static NdmsNativeExactMutationDispatchCapability issue() noexcept;
};
#endif

struct NdmsNativeExactMutationResponseManifest final {
    NdmsNativeExactMutationResponseOutcome outcome{
        NdmsNativeExactMutationResponseOutcome::transport_failed};
    bool transport_ok{false};
    int http_status{0};
    bool content_type_is_json{false};
    std::size_t body_bytes{0U};

    bool acknowledged_needs_observation() const noexcept {
        return outcome ==
               NdmsNativeExactMutationResponseOutcome::
                   acknowledged_needs_observation;
    }
};

struct NdmsNativeExactMutationTransportResult final {
    NdmsNativeExactMutationKind kind{
        NdmsNativeExactMutationKind::save_configuration};
    bool backend_call_confirmed{false};
    bool pre_dispatch_guard_evaluated{false};
    bool pre_dispatch_guard_passed{false};
    bool perform_started{false};
    bool request_may_have_been_dispatched{false};
    NdmsNativeExactMutationResponseManifest response_manifest;
};

// Performs one and only one fixed-loopback POST. A syntactically acknowledged
// response is never proof that a delete/save happened: the caller must use a
// fresh independent observation before advancing durable state.
NdmsNativeExactMutationTransportResult
post_ndms_native_exact_mutation_once(
    NdmsNativeExactMutationDispatchCapability&& capability,
    NdmsNativeExactMutationRequest request,
    NdmsNativeExactMutationPreDispatchGuard& pre_dispatch_guard,
    NdmsNativeExactMutationBackend& backend);

} // namespace keen_pbr3
