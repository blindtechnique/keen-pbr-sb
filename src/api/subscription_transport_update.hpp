#pragma once
#ifdef WITH_API
#include "transport_manager_endpoint.hpp"
#include "../config/subscription_refresh.hpp"

namespace keen_pbr3 {
// Uses the manager's existing conditional update, which applies the managed
// runtime itself. The caller holds the ordinary transport maintenance lease.
SubscriptionUpdateResult update_subscription_transports(
    const TransportManagerEndpoint& endpoint,
    const std::vector<SubscriptionTransportUpdate>& updates);
std::vector<SubscriptionTransportState> read_subscription_transports(
    const TransportManagerEndpoint& endpoint);
}
#endif
