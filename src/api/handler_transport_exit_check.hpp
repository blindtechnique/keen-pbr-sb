#pragma once

#ifdef WITH_API

#include "../health/exit_address_check.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace keen_pbr3 {

struct ApiContext;
class ApiServer;
class HttpTransport;

// Fetches the echo URL through one outbound and reports what came back.
//
// Injected rather than called directly so that everything this endpoint
// decides - which outbound was asked, what counts as an address, which of the
// three verdicts the pair of measurements earns - is testable without a
// network and without a router.
using ExitEchoFetcher = std::function<ExitProbeOutcome(
    const std::string& url, std::uint32_t fwmark, const std::string& device)>;

void register_transport_exit_check_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
ExitProbeOutcome fetch_transport_exit_echo_for_test(
    std::shared_ptr<HttpTransport> transport,
    const std::string& url,
    std::uint32_t fwmark,
    const std::string& device);

void register_transport_exit_check_handler_for_test(ApiServer& server,
                                                    ApiContext& ctx,
                                                    ExitEchoFetcher fetcher);
#endif

}  // namespace keen_pbr3

#endif  // WITH_API
