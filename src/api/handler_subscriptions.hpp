#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <functional>
#include <string>

namespace keen_pbr3 {

// Fetches a subscription body for the preview endpoint. Production builds one
// from HttpClient with the subscription destination policy applied to every
// address actually connected to; tests substitute a local fixture, because the
// policy correctly refuses the loopback addresses a test server lives on.
using SubscriptionFetcher =
    std::function<std::string(const std::string& url)>;

// The production fetcher: 20 s timeout, the 1 MiB subscription bound enforced
// by the transport (a too-large body fails whole, it is not truncated), and
// subscription_destination_permitted consulted for the first connection and
// every redirect hop. Exposed so a test can prove the wiring carries the
// policy - a fetcher without the filter behaves identically on every allowed
// destination and differs only where it must refuse.
SubscriptionFetcher make_subscription_fetcher();

void register_subscriptions_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
void register_subscriptions_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    SubscriptionFetcher fetcher);
#endif

} // namespace keen_pbr3

#endif // WITH_API
