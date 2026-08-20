#pragma once

#include "ndms_native_tunnel_import.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {

class NdmsNativeSecretSnapshotStore;
class NdmsNativePreparedImport;

class NdmsNativePanelDeleteSnapshotError final
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Encrypted-store payload for rollback after a panel-owned WG/AWG delete.
// It contains one exact canonical .conf, including the private key, every
// preshared key, all required AWG base fields and every present optional ASC
// field with its presence preserved. Raw bytes have no public accessor; the
// object is move-only and wiping.
class NdmsNativePanelDeleteSnapshot final {
public:
    NdmsNativePanelDeleteSnapshot(
        const NdmsNativePanelDeleteSnapshot&) = delete;
    NdmsNativePanelDeleteSnapshot& operator=(
        const NdmsNativePanelDeleteSnapshot&) = delete;
    NdmsNativePanelDeleteSnapshot(
        NdmsNativePanelDeleteSnapshot&& other) noexcept;
    NdmsNativePanelDeleteSnapshot& operator=(
        NdmsNativePanelDeleteSnapshot&& other) noexcept;
    ~NdmsNativePanelDeleteSnapshot();

    NdmsNativeTunnelImportKind kind() const noexcept;
    std::string_view marker() const noexcept;
    // Digest of this canonical secret-bearing snapshot. This is deliberately
    // not the firmware RCI full revision used for target CAS.
    std::string_view canonical_revision() const noexcept;
    std::size_t sealed_payload_bytes() const noexcept;
    std::size_t preshared_key_count() const noexcept;
    // True when the required AWG base parameters validated. Optional S3/S4
    // and I1..I5 remain optional and retain their exact presence separately
    // in the sealed canonical configuration.
    bool has_complete_awg_parameters() const noexcept;

private:
    NdmsNativePanelDeleteSnapshot(
        NdmsNativeTunnelImportKind kind,
        std::string marker,
        std::string canonical_revision,
        std::size_t preshared_key_count,
        bool has_complete_awg_parameters,
        std::string sealed_payload) noexcept;

    static NdmsNativePanelDeleteSnapshot from_sealed_payload(
        std::string&& payload,
        const std::string& expected_marker);
    std::string_view sealed_payload_for_store() const noexcept;
    void wipe() noexcept;

    NdmsNativeTunnelImportKind kind_{
        NdmsNativeTunnelImportKind::wireguard};
    std::string marker_;
    std::string canonical_revision_;
    std::size_t preshared_key_count_{0U};
    bool has_complete_awg_parameters_{false};
    std::string sealed_payload_;

    friend NdmsNativePanelDeleteSnapshot
    make_ndms_native_panel_delete_snapshot(
        std::string&&,
        const std::string&);
    friend NdmsNativePreparedImport
    prepare_ndms_native_import(std::string&&);
    friend class NdmsNativeSecretSnapshotStore;
};

// Consumes and wipes an already obtained WG/AWG configuration, validates it
// with the production import parser, and rewrites it into the one canonical
// grammar shared with the stock RCI import request. The ownership marker is
// injected as the exact Name comment and participates in the encrypted AAD.
NdmsNativePanelDeleteSnapshot make_ndms_native_panel_delete_snapshot(
    std::string&& raw_configuration,
    const std::string& ownership_marker);

} // namespace keen_pbr3
