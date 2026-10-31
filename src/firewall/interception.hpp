#pragma once

#include "../intercept/intercept_snapshot.hpp"
#include "interception_health.hpp"
#include <memory>

namespace keen_pbr3 {

// Client direction is source for L7 requests and destination for DNS replies.
// An empty CIDR means the exact interface, never all interfaces. Families are
// explicit so an IPv4 native-VPN pool cannot admit IPv6 on the same interface.
struct InterceptionClientSelector {
    uint8_t family{4};
    std::string interface;
    std::string cidr;
};

struct InterceptionClientScope {
    std::vector<InterceptionClientSelector> include;
    std::vector<InterceptionClientSelector> exclude;
};

// Reserved listeners of this process only. A busy binding is never reclaimed
// from another program (notably nfqws); the optional learner stays unavailable.
struct InterceptionHooks {
    static constexpr uint16_t queue = 43053;
    static constexpr uint16_t group = 43054;
    bool dns{false};
    bool l7{false};
    std::vector<std::string> interfaces;
    InterceptionClientScope client_scope;
    bool any() const { return dns || l7; }
};

struct InterceptionRequest {
    bool dns{false}, l7{false};
    std::vector<std::string> interfaces;
};

// Retained from staging through COMMIT by the existing single firewall owner.
// While alive, set writes are paused. Destruction without commit invalidates
// learning; an ambiguous kernel apply must not resume writes to old targets.
class FirewallInterceptionUpdate {
public:
    virtual ~FirewallInterceptionUpdate() = default;
    virtual InterceptionHooks prepare(
        const std::vector<InterceptListBinding>& bindings,
        const InterceptSnapshotPolicy& policy,
        const InterceptDomainReader& reader, bool reuse_index,
        const InterceptionRequest& request = {}) = 0;
    virtual void commit() noexcept = 0;
};

class FirewallInterceptionRuntime {
public:
    virtual ~FirewallInterceptionRuntime() = default;
    virtual std::shared_ptr<FirewallInterceptionUpdate> begin_update() = 0;
    // Called AFTER removing capture hooks, including best effort on failed STOP.
    // Queue rules always have bypass: an unbound listener cannot block DNS.
    virtual void stop() noexcept = 0;
    virtual InterceptionHealth health() const { return {}; }
};

} // namespace keen_pbr3
