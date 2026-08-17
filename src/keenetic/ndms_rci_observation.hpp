#pragma once

#include "ndms_interface_inventory.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

class NdmsRciObservationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Transport-neutral result of one read-only RCI request. The caller owns the
// endpoint and authentication; this domain layer only validates the response.
struct NdmsRciReadResponse {
    int status_code{0};
    std::string content_type;
    std::string body;
};

// Strictly filtered observation of an existing WG/AWG interface. It is not a
// restorable configuration snapshot: credentials, peer identities, endpoints
// and arbitrary firmware fields are deliberately not retained.
struct NdmsRciTunnelObservation {
    std::string interface_id;
    NdmsTunnelKind kind{NdmsTunnelKind::wireguard};
    std::string firmware_type;
    std::optional<std::string> description;
    std::optional<bool> enabled;
    std::optional<std::uint32_t> mtu;
    std::optional<std::uint16_t> listen_port;
    std::vector<std::string> addresses;
    std::size_t peer_count{0};
    // Digest of the safe fields above. This is diagnostic evidence only and
    // must not be used as a complete optimistic-concurrency revision.
    std::string observation_revision;
};

NdmsRciTunnelObservation parse_ndms_rci_tunnel_observation(
    const NdmsRciReadResponse& response,
    const NdmsTunnelInterface& expected_interface);

using NdmsRciObservationFetcher =
    std::function<NdmsRciReadResponse(const NdmsTunnelInterface&)>;

// Dependency-injected read gateway. It intentionally does not construct an
// RCI command path, expose a mutation method or publish the response.
class NdmsRciObservationGateway {
public:
    explicit NdmsRciObservationGateway(NdmsRciObservationFetcher fetcher);

    NdmsRciTunnelObservation acquire(
        const NdmsTunnelInterface& expected_interface) const;

private:
    NdmsRciObservationFetcher fetcher_;
};

} // namespace keen_pbr3
