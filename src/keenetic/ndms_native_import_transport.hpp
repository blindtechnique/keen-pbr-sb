#pragma once

#include "ndms_native_allocator_fence.hpp"
#include "ndms_native_import_request.hpp"
#include "ndms_native_import_response.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {

struct NdmsNativeImportExecutionPlan;
struct NdmsNativeImportExecutionResult;
class NdmsNativeImportExecutorDependencies;
class NdmsNativeImportBaselineEvidence;

// Fifteen seconds of bounded curl execution plus a two-second setup margin.
// Allocator receipts must retain at least this much monotonic lifetime at the
// final guard immediately before curl_easy_perform().
inline constexpr auto kNdmsNativeImportRequiredDispatchWindow =
    std::chrono::seconds{17};

class NdmsNativeImportTransportError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Move-only bounded storage for request or response bytes that may contain a
// WireGuard private key. Its allocation is overwritten before release. It is
// also the only production sink accepted by the request serializer.
class NdmsNativeSecretBuffer final : public NdmsNativeSecretBodySink {
public:
    explicit NdmsNativeSecretBuffer(std::size_t maximum_bytes);
    ~NdmsNativeSecretBuffer();

    NdmsNativeSecretBuffer(const NdmsNativeSecretBuffer&) = delete;
    NdmsNativeSecretBuffer& operator=(const NdmsNativeSecretBuffer&) = delete;

    NdmsNativeSecretBuffer(NdmsNativeSecretBuffer&& other);
    NdmsNativeSecretBuffer& operator=(
        NdmsNativeSecretBuffer&& other);

    bool write_secret_body_chunk(std::string_view chunk) override;

    std::string_view view() const noexcept;
    std::size_t size() const noexcept;
    std::size_t maximum_bytes() const noexcept;
    bool empty() const noexcept;
    void clear() noexcept;

private:
    void wipe() noexcept;

    std::string bytes_;
    std::size_t maximum_bytes_{0U};
};

// Raw response exists only between the fixed loopback transport and the
// structural inspector. It is never returned by the public import operation.
struct NdmsNativeImportRawTransportResponse {
    NdmsNativeImportRawTransportResponse();

    bool request_may_have_been_dispatched{false};
    bool transport_ok{false};
    int status_code{0};
    // Raw header bytes are never retained. The callback records only a
    // bounded, fail-closed classification of the final response block.
    bool content_type_seen{false};
    bool content_type_is_json{false};
    bool content_type_ambiguous{false};
    bool callback_failed{false};
    NdmsNativeSecretBuffer body;
};

// Revalidates the allocator receipt and generation after the secret request
// and curl setup have completed, immediately before curl_easy_perform().
class NdmsNativeImportPreDispatchGuard {
public:
    virtual ~NdmsNativeImportPreDispatchGuard() = default;
    virtual bool authorize_dispatch() noexcept = 0;
};

struct NdmsNativeImportBackendTrace final {
    bool pre_dispatch_guard_evaluated{false};
    bool pre_dispatch_guard_passed{false};
    bool perform_started{false};
};

class NdmsNativeImportDispatchCapability;
struct NdmsNativeImportTransportResult;

// The backend has no URL argument by design. Its dispatch method is private,
// accepts the wiping request by rvalue reference (no throwing parameter move)
// and is callable only by the capability-consuming helper below.
class NdmsNativeLoopbackRciPostBackend {
public:
    virtual ~NdmsNativeLoopbackRciPostBackend() = default;

private:
    virtual NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&& dispatch_capability,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeImportPreDispatchGuard& pre_dispatch_guard,
        NdmsNativeImportBackendTrace& trace) = 0;

    friend NdmsNativeImportTransportResult post_ndms_native_import_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeWireguardImportRequest,
        const std::string&,
        NdmsNativeImportPreDispatchGuard&,
        NdmsNativeLoopbackRciPostBackend&);
};

class NdmsNativeLibcurlLoopbackRciPostBackend final
    : public NdmsNativeLoopbackRciPostBackend {
private:
    NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&& dispatch_capability,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeImportPreDispatchGuard& pre_dispatch_guard,
        NdmsNativeImportBackendTrace& trace) override;
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeImportDispatchCapabilityTestIssuer;
#endif

// One-shot accidental-callsite barrier. It is not an authorization
// replacement: the executor must still validate the opaque allocator receipt,
// durable WAL and generation. Production construction is available only
// inside the exact coordinator function friended below.
class NdmsNativeImportDispatchCapability final {
public:
    NdmsNativeImportDispatchCapability(
        NdmsNativeImportDispatchCapability&& other) noexcept;
    NdmsNativeImportDispatchCapability& operator=(
        NdmsNativeImportDispatchCapability&& other) noexcept;
    NdmsNativeImportDispatchCapability(
        const NdmsNativeImportDispatchCapability&) = delete;
    NdmsNativeImportDispatchCapability& operator=(
        const NdmsNativeImportDispatchCapability&) = delete;
    ~NdmsNativeImportDispatchCapability() = default;

private:
    struct ConstructionKey final {};
    explicit NdmsNativeImportDispatchCapability(
        ConstructionKey) noexcept;
    bool consume() noexcept;

    bool valid_{false};

    friend NdmsNativeImportExecutionResult
    execute_ndms_native_import_transaction(
        NdmsNativeWireguardImportRequest,
        const NdmsNativeImportExecutionPlan&,
        const NdmsNativeImportBaselineEvidence&,
        std::optional<NdmsNativeAllocatorFenceReceipt>,
        const NdmsNativeImportExecutorDependencies&);
#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeImportDispatchCapabilityTestIssuer;
#endif
    friend NdmsNativeImportTransportResult post_ndms_native_import_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeWireguardImportRequest,
        const std::string&,
        NdmsNativeImportPreDispatchGuard&,
        NdmsNativeLoopbackRciPostBackend&);
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeImportDispatchCapabilityTestIssuer final {
public:
    static NdmsNativeImportDispatchCapability issue() noexcept;
};

// Deterministic test seam for the only throwing region that remains before
// the private backend boundary. It is absent from production builds.
class NdmsNativeImportTransportTestControl final {
public:
    static void fail_before_backend_once() noexcept;

private:
    static bool consume_fail_before_backend() noexcept;

    friend NdmsNativeImportTransportResult post_ndms_native_import_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeWireguardImportRequest,
        const std::string&,
        NdmsNativeImportPreDispatchGuard&,
        NdmsNativeLoopbackRciPostBackend&);
};
#endif

struct NdmsNativeImportTransportResult {
    bool backend_call_confirmed{false};
    bool pre_dispatch_guard_evaluated{false};
    bool pre_dispatch_guard_passed{false};
    bool perform_started{false};
    bool request_may_have_been_dispatched{false};
    NdmsNativeImportResponseManifestV2 response_manifest;
};

// Serializes and consumes request exactly once, performs exactly one fixed
// loopback POST through backend, inspects the response in wiping storage, and
// returns only redacted structural evidence. No retry is performed here.
NdmsNativeImportTransportResult post_ndms_native_import_once(
    NdmsNativeImportDispatchCapability&& capability,
    NdmsNativeWireguardImportRequest request,
    const std::string& expected_created_interface,
    NdmsNativeImportPreDispatchGuard& pre_dispatch_guard,
    NdmsNativeLoopbackRciPostBackend& backend);

} // namespace keen_pbr3
