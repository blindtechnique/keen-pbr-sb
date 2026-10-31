#pragma once

#include "intercept_processor.hpp"

#include <functional>
#include <string_view>

namespace keen_pbr3 {

// Adapted at the daemon boundary from its committed configuration and declared
// dynamic sets. Names/signatures must not be inferred from UI drafts.
struct InterceptListBinding {
    std::string name;
    std::string content_signature;  // identifies the exact domain source/content
    InterceptListTarget target;
};

struct InterceptSnapshotPolicy {
    std::shared_ptr<const InterceptCleanupPolicy> cleanup;
    uint32_t max_ttl_s{86400};
    bool ipv6_enabled{true};
    bool tls{true};
    bool http{true};
    bool quic{true};
    std::string marker_domain;  // empty = do not rewrite diagnostic DNS packets
    std::array<uint8_t, 4> marker_ipv4{127, 0, 0, 88};
};

using InterceptDomainConsumer = std::function<void(std::string_view)>;
// Synchronous streaming reader. False/exception means unavailable, NOT an empty
// list. The caller keeps its last published snapshot if this build fails.
using InterceptDomainReader =
    std::function<bool(const InterceptListBinding&, const InterceptDomainConsumer&)>;

std::shared_ptr<const InterceptSnapshot> build_intercept_snapshot(
    const std::vector<InterceptListBinding>& bindings,
    const InterceptSnapshotPolicy& policy, const InterceptDomainReader& read_domains);

// Immediately detach removed/changed lists before a slow background index build.
// Reuse the old index only for identical content signatures; set targets and
// policy come exclusively from the new committed generation.
std::shared_ptr<const InterceptSnapshot> rebind_intercept_snapshot(
    const std::shared_ptr<const InterceptSnapshot>& previous,
    const std::vector<InterceptListBinding>& bindings,
    const InterceptSnapshotPolicy& policy);

} // namespace keen_pbr3
