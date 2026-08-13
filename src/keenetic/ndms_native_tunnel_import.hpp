#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

constexpr std::size_t kNdmsNativeTunnelImportMaximumBytes =
    256U * 1024U;

enum class NdmsNativeTunnelImportErrorCode {
    input_too_large,
    invalid_encoding,
    unsupported_uri,
    invalid_base64,
    invalid_compression,
    invalid_json,
    unsupported_json_schema,
    malformed_line,
    unknown_section,
    duplicate_section,
    duplicate_field,
    unknown_field,
    dangerous_directive,
    missing_required_field,
    invalid_field,
    limit_exceeded,
};

const char* ndms_native_tunnel_import_error_code_name(
    NdmsNativeTunnelImportErrorCode code) noexcept;

class NdmsNativeTunnelImportError : public std::runtime_error {
public:
    explicit NdmsNativeTunnelImportError(
        NdmsNativeTunnelImportErrorCode code);

    NdmsNativeTunnelImportErrorCode code() const noexcept;

private:
    NdmsNativeTunnelImportErrorCode code_;
};

// Import credentials are deliberately move-only. Callers must opt in at the
// eventual typed-RCI boundary; previews and errors have no credential accessor.
class NdmsNativeTunnelImportSecret {
public:
    explicit NdmsNativeTunnelImportSecret(std::string value);
    ~NdmsNativeTunnelImportSecret();

    NdmsNativeTunnelImportSecret(
        const NdmsNativeTunnelImportSecret&) = delete;
    NdmsNativeTunnelImportSecret& operator=(
        const NdmsNativeTunnelImportSecret&) = delete;

    NdmsNativeTunnelImportSecret(
        NdmsNativeTunnelImportSecret&& other) noexcept;
    NdmsNativeTunnelImportSecret& operator=(
        NdmsNativeTunnelImportSecret&& other) noexcept;

    const std::string& reveal_for_typed_rci() const noexcept;
    std::string sha256() const;

private:
    void wipe() noexcept;

    std::string value_;
};

enum class NdmsNativeTunnelImportKind {
    wireguard,
    amnezia_wireguard,
};

const char* ndms_native_tunnel_import_kind_name(
    NdmsNativeTunnelImportKind kind) noexcept;

enum class NdmsNativeTunnelImportSource {
    wireguard_conf,
    amnezia_vpn_uri,
};

struct NdmsNativeTunnelImportAwgParameters {
    std::uint32_t jc{0};
    std::uint32_t jmin{0};
    std::uint32_t jmax{0};
    std::uint32_t s1{0};
    std::uint32_t s2{0};
    std::optional<std::uint32_t> s3;
    std::optional<std::uint32_t> s4;
    std::string h1;
    std::string h2;
    std::string h3;
    std::string h4;
    std::optional<std::string> i1;
    std::optional<std::string> i2;
    std::optional<std::string> i3;
    std::optional<std::string> i4;
    std::optional<std::string> i5;
};

struct NdmsNativeTunnelImportPeer {
    std::string public_key;
    std::optional<NdmsNativeTunnelImportSecret> preshared_key;
    std::string endpoint;
    std::string endpoint_host;
    std::uint16_t endpoint_port{0};
    std::vector<std::string> allowed_ips;
    std::optional<std::uint16_t> persistent_keepalive;
};

struct NdmsNativeTunnelImport {
    NdmsNativeTunnelImportSource source{
        NdmsNativeTunnelImportSource::wireguard_conf};
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::vector<std::string> addresses;
    std::vector<std::string> dns_servers;
    std::optional<std::uint16_t> listen_port;
    std::optional<std::uint32_t> mtu;
    NdmsNativeTunnelImportSecret private_key;
    std::optional<NdmsNativeTunnelImportAwgParameters> awg;
    std::vector<NdmsNativeTunnelImportPeer> peers;
};

// Safe for JSON serialization and logs. It intentionally omits every key and
// all raw source lines. `revision` is a one-way digest of canonical data.
struct NdmsNativeTunnelImportPreview {
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::size_t address_count{0};
    std::size_t dns_count{0};
    std::size_t peer_count{0};
    std::size_t allowed_ip_count{0};
    std::optional<std::string> endpoint_host;
    std::optional<std::uint16_t> endpoint_port;
    std::optional<std::uint16_t> persistent_keepalive;
    std::vector<std::string> amnezia_parameter_names;
    bool has_private_key{false};
    std::size_t preshared_key_count{0};
    std::string revision;
};

// Accepts a bounded wg-quick/AmneziaWG .conf body. URI schemes, including
// `vpn://` and non-standard `wireguard://`, fail closed until their decoding
// path can guarantee secure wipe of every secret-bearing allocation. This
// function performs no I/O and no mutation.
NdmsNativeTunnelImport parse_ndms_native_tunnel_import(
    std::string input);

NdmsNativeTunnelImportPreview
build_ndms_native_tunnel_import_preview(
    const NdmsNativeTunnelImport& input);

} // namespace keen_pbr3
