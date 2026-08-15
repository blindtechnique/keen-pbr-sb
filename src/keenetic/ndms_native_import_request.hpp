#pragma once

#include "ndms_native_tunnel_import.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// The stock importer accepts a plain WireGuard .conf. URI envelopes and
// AmneziaWG extensions deliberately remain outside this request boundary.
constexpr std::size_t kNdmsNativeWireguardImportRequestMaximumBytes =
    kNdmsNativeTunnelImportMaximumBytes;

enum class NdmsNativeWireguardImportRequestErrorCode {
    unsupported_source,
    amnezia_wireguard_blocked,
    entropy_unavailable,
    already_consumed,
};

const char* ndms_native_wireguard_import_request_error_code_name(
    NdmsNativeWireguardImportRequestErrorCode code) noexcept;

class NdmsNativeWireguardImportRequestError : public std::runtime_error {
public:
    explicit NdmsNativeWireguardImportRequestError(
        NdmsNativeWireguardImportRequestErrorCode code);

    NdmsNativeWireguardImportRequestErrorCode code() const noexcept;

private:
    NdmsNativeWireguardImportRequestErrorCode code_;
};

// A transport must consume each view synchronously and must never retain,
// log, persist or generically serialize it. Chunks may contain a private key
// or preshared key even though the surrounding JSON punctuation is public.
class NdmsNativeSecretBodySink {
public:
    virtual ~NdmsNativeSecretBodySink() = default;

    virtual bool write_secret_body_chunk(std::string_view chunk) = 0;
};

// Move-only, single-use request for the measured stock RCI create primitive.
// There is intentionally no string conversion, JSON conversion, target/name
// setter or raw-body accessor. The only caller-controlled input is parsed by
// make_ndms_native_wireguard_import_request().
class NdmsNativeWireguardImportRequest {
public:
    ~NdmsNativeWireguardImportRequest();

    NdmsNativeWireguardImportRequest(
        const NdmsNativeWireguardImportRequest&) = delete;
    NdmsNativeWireguardImportRequest& operator=(
        const NdmsNativeWireguardImportRequest&) = delete;

    NdmsNativeWireguardImportRequest(
        NdmsNativeWireguardImportRequest&& other) noexcept;
    NdmsNativeWireguardImportRequest& operator=(
        NdmsNativeWireguardImportRequest&& other) noexcept;

    std::string_view operation() const noexcept;
    std::string_view transaction_id() const noexcept;
    std::string_view marker() const noexcept;
    std::string_view filename() const noexcept;
    std::string_view candidate_revision() const noexcept;
    std::size_t content_length() const noexcept;
    bool has_pending_secret_body() const noexcept;

    // Streams exactly one stock WebUI batch body. The canonical .conf and
    // base64 scratch are wiped on success, sink rejection or exception. The
    // request cannot be replayed after this method is entered.
    bool write_stock_rci_body_once(NdmsNativeSecretBodySink& sink);

private:
    friend NdmsNativeWireguardImportRequest
    make_ndms_native_wireguard_import_request(std::string&& raw_conf);

    NdmsNativeWireguardImportRequest(
        std::string canonical_conf,
        std::string transaction_id,
        std::string marker,
        std::string filename,
        std::string candidate_revision);

    void wipe_secret() noexcept;

    std::string canonical_conf_;
    std::string transaction_id_;
    std::string marker_;
    std::string filename_;
    std::string candidate_revision_;
    std::size_t content_length_{0U};
    bool consumed_{true};
};

// Validates and canonicalizes one bounded plain WireGuard .conf. It strips
// all caller comments/labels, injects a cryptographically random ownership
// marker, and derives the only filename used by the RCI body from that marker.
// The rvalue-only boundary wipes the caller's adopted allocation before
// returning or throwing; callers cannot accidentally retain an lvalue copy.
NdmsNativeWireguardImportRequest
make_ndms_native_wireguard_import_request(std::string&& raw_conf);

} // namespace keen_pbr3
