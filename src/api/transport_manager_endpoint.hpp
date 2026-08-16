#pragma once

#ifdef WITH_API

#include <string>

namespace keen_pbr3 {

// Where the transport manager listens, read from transports.json beside the
// daemon config. Extracted from handler_transports.cpp when the subscription
// import became a second caller: the manager is the single writer of transport
// configuration, and every HTTP route that talks to it must resolve the same
// endpoint the same way rather than grow its own reader.
struct TransportManagerEndpoint {
    std::string host;
    int port;
    std::string api_key;
};

// Throws ApiError: 503 when transports.json is missing (the manager is not
// installed or not configured), 500 when it is present but unusable. The
// listen address must be loopback - the api_key travels in a header.
TransportManagerEndpoint load_transport_manager_endpoint(
    const std::string& keen_pbr_config_path);

} // namespace keen_pbr3

#endif // WITH_API
