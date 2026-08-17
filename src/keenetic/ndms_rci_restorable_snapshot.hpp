#pragma once

#include "ndms_rci_observation.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

class NdmsRciRestorableSnapshotError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Move-only credential container. The explicit restore accessor makes secret
// use visible at call sites and prevents accidental copies into diagnostics.
class NdmsRciSecret {
public:
    explicit NdmsRciSecret(std::string value);
    ~NdmsRciSecret();

    NdmsRciSecret(const NdmsRciSecret&) = delete;
    NdmsRciSecret& operator=(const NdmsRciSecret&) = delete;

    NdmsRciSecret(NdmsRciSecret&& other) noexcept;
    NdmsRciSecret& operator=(NdmsRciSecret&& other) noexcept;

    const std::string& reveal_for_restore() const noexcept;
    std::string sha256() const;

private:
    void wipe() noexcept;

    std::string value_;
};

// A response is tagged by the firmware interface name used by the caller.
// /show/rc/interface/<name> does not repeat that identity in its JSON body.
struct NdmsRciSnapshotDocument {
    std::string firmware_interface_name;
    NdmsRciReadResponse response;
};

struct NdmsAwgAscParameters {
    std::uint32_t jc{0};
    std::uint32_t jmin{0};
    std::uint32_t jmax{0};
    std::uint32_t s1{0};
    std::uint32_t s2{0};
    std::string h1;
    std::string h2;
    std::string h3;
    std::string h4;
    std::optional<std::uint32_t> s3;
    std::optional<std::uint32_t> s4;
    std::optional<std::string> i1;
    std::optional<std::string> i2;
    std::optional<std::string> i3;
    std::optional<std::string> i4;
    std::optional<std::string> i5;
};

struct NdmsRciPeerSnapshot {
    std::string public_key;
    std::optional<NdmsRciSecret> preshared_key;
    std::string endpoint;
    std::optional<std::string> via_interface;
    std::vector<std::string> allowed_ips;
    std::optional<std::uint16_t> persistent_keepalive;
};

// Composite acquisition input. RC JSON is authoritative for configuration;
// runtime JSON may only supplement a missing peer endpoint. Private key is
// acquired separately (for example, with `wg show <kernel> private-key`).
struct NdmsRciRestorableSnapshotInput {
    NdmsRciSnapshotDocument rc_interface;
    std::optional<NdmsRciSnapshotDocument> runtime_interface;
    std::optional<NdmsRciSnapshotDocument> asc;
    NdmsRciSecret private_key;
};

// Secret-bearing snapshot of the WG/AWG create/edit fields this project may
// explicitly own. It is not a byte-for-byte NDMS object and must not be used
// as evidence that deleting an interface is safe. This foundation is
// deliberately limited to client WG/AWG interfaces.
struct NdmsRciRestorableSnapshot {
    std::string interface_id;
    std::string firmware_interface_name;
    NdmsTunnelKind kind{NdmsTunnelKind::wireguard};
    std::optional<std::string> description;
    std::optional<bool> enabled;
    std::optional<std::uint32_t> mtu;
    std::optional<std::uint16_t> listen_port;
    std::vector<std::string> addresses;
    NdmsRciSecret private_key;
    std::optional<NdmsAwgAscParameters> asc;
    std::vector<NdmsRciPeerSnapshot> peers;
    // Stable digest of the complete canonical snapshot. Credentials
    // participate only through their SHA-256 digests.
    std::string full_revision;
};

NdmsRciRestorableSnapshot parse_ndms_rci_restorable_snapshot(
    NdmsRciRestorableSnapshotInput input,
    const NdmsTunnelInterface& expected_interface);

} // namespace keen_pbr3
