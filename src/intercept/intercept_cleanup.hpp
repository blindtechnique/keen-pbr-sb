#pragma once

#include "intercept_service.hpp"
#include "../firewall/firewall.hpp"
#include "../runtime/conntrack_manager.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <functional>
#include <set>

namespace keen_pbr3 {

// Exact ordered classifiers emitted by the committed firewall transaction.
// mark=0 represents a terminal PASS/DROP, never permission to reconnect.
struct InterceptCleanupRule {
    FirewallRuleCriteria criteria;
    uint32_t mark{0};
};
struct InterceptCleanupPolicy {
    uint32_t owned_mask{0};
    bool split_negated_addresses{false}; // xtables expands each address to a separate row
    std::set<uint32_t> owned_marks;
    std::vector<InterceptCleanupRule> rules;
    std::set<std::string> learned_sets;
    std::vector<std::string> excluded_clients;
};

struct InterceptCleanupGrant {
    std::shared_ptr<const InterceptSnapshot> snapshot;
    std::weak_ptr<InterceptService> service;
    std::atomic<bool> active{true};
    bool current() const {
        auto owner = service.lock();
        return active.load(std::memory_order_acquire) && owner && owner->running() &&
               owner->current_snapshot() == snapshot;
    }
};
struct InterceptCleanupTicket {
    static constexpr size_t max_destinations = 64;
    std::shared_ptr<const InterceptCleanupGrant> grant;
    uint8_t family{4};
    std::string client;
    std::vector<std::string> destinations;
    std::chrono::steady_clock::time_point deadline;
    bool current() const {
        return grant && grant->snapshot && grant->snapshot->cleanup &&
               (family != 6 || grant->snapshot->ipv6_enabled) &&
               grant->current() && std::chrono::steady_clock::now() < deadline;
    }
};

// No I/O, retries, worker or scheduler here. The daemon callback admits at most
// one bounded request to its existing physical mutation owner.
class InterceptCleanupChannel final : public ConntrackCleanupSink {
public:
    using Submit = std::function<bool()>;
    explicit InterceptCleanupChannel(Submit submit) : submit_(std::move(submit)) {}
    void revoke() noexcept {
        auto old = std::atomic_exchange(&grant_, std::shared_ptr<InterceptCleanupGrant>{});
        if (old) old->active.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.clear();
    }
    void publish(const std::shared_ptr<InterceptService>& service,
                 const std::shared_ptr<const InterceptSnapshot>& snapshot) {
        revoke();
        if (!snapshot || !snapshot->cleanup) return;
        auto next = std::make_shared<InterceptCleanupGrant>();
        next->snapshot = snapshot;
        next->service = service;
        std::atomic_store(&grant_, std::move(next));
    }
    void request(const std::shared_ptr<const InterceptSnapshot>& snapshot,
                 uint8_t family, const std::array<uint8_t, 16>& client,
                 const std::array<uint8_t, 16>& destination) override {
        auto grant = std::atomic_load(&grant_);
        if (!submit_ || !grant || grant->snapshot != snapshot || !grant->current() ||
            (family != 4 && family != 6) || (family == 6 && !snapshot->ipv6_enabled)) return;
        auto ticket = std::make_shared<InterceptCleanupTicket>();
        ticket->grant = std::move(grant);
        ticket->family = family;
        ticket->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        const int af = family == 6 ? AF_INET6 : AF_INET;
        char text[INET6_ADDRSTRLEN]{};
        if (!inet_ntop(af, client.data(), text, sizeof(text))) return;
        ticket->client = text;
        if (!inet_ntop(af, destination.data(), text, sizeof(text))) return;
        ticket->destinations.emplace_back(text);
        bool notify = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (pending_.size() >= 64) return;
            for (const auto& old : pending_)
                if (old->grant == ticket->grant && old->family == family &&
                    old->client == ticket->client && old->destinations == ticket->destinations) return;
            pending_.push_back(std::move(ticket));
            if (!scheduled_) { scheduled_ = true; notify = true; }
        }
        if (notify) notify_owner();
    }
    std::vector<std::shared_ptr<const InterceptCleanupTicket>> take() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto result = std::move(pending_);
        pending_.clear();
        return result;
    }
    // Exactly one terminal call, including rejected admission. No retry of the
    // consumed batch. New observations may form one bounded trailing batch.
    void finish() noexcept {
        bool notify = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            scheduled_ = !pending_.empty();
            notify = scheduled_;
        }
        if (notify) notify_owner();
    }
private:
    void notify_owner() noexcept {
        try { if (submit_ && submit_()) return; } catch (...) {}
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.clear();
        scheduled_ = false;
    }
    Submit submit_;
    std::shared_ptr<InterceptCleanupGrant> grant_;
    std::mutex mutex_;
    bool scheduled_{false};
    std::vector<std::shared_ptr<const InterceptCleanupTicket>> pending_;
};

inline std::optional<bool> intercept_address_matches(const std::vector<std::string>& cidrs,
                                                    const std::string& address, int family) {
    std::array<uint8_t, 16> host{}, network{};
    if (inet_pton(family, address.c_str(), host.data()) != 1) return {};
    bool match = false;
    for (const auto& cidr : cidrs) {
        const auto slash = cidr.find('/');
        const auto ip = cidr.substr(0, slash);
        const int af = ip.find(':') == std::string::npos ? AF_INET : AF_INET6;
        if (inet_pton(af, ip.c_str(), network.data()) != 1) return {};
        unsigned prefix = af == AF_INET ? 32 : 128;
        if (slash != std::string::npos) {
            const auto bits = cidr.substr(slash + 1);
            if (bits.empty() || bits.size() > 3 || bits.find_first_not_of("0123456789") != std::string::npos) return {};
            const auto parsed = static_cast<unsigned>(std::stoul(bits));
            if (parsed > prefix) return {};
            prefix = parsed;
        }
        if (af != family) continue;
        bool equal = true;
        for (unsigned bit = 0; bit < prefix; ++bit)
            if ((host[bit / 8] ^ network[bit / 8]) & (0x80 >> (bit % 8))) { equal = false; break; }
        match = match || equal;
    }
    return match;
}

// Unknown DSCP/set observations stop evaluation; they are not a negative match
// permitting a lower-priority rule to steal a connection.
using InterceptSetMembership = std::function<std::optional<bool>(const std::string&, const std::string&)>;
using InterceptWriteEvidence = std::function<bool(const std::string&, const std::string&)>;
inline std::optional<uint32_t> intercept_cleanup_mark(
    const InterceptCleanupPolicy& policy, const ConntrackExactForwardedFlow& flow,
    const InterceptSetMembership& membership, const InterceptWriteEvidence& evidence) {
    if (!membership || !evidence || !flow.source_port || !flow.destination_port ||
        (flow.family != ConntrackFlowFamily::Ipv4 && flow.family != ConntrackFlowFamily::Ipv6) ||
        (flow.protocol != ConntrackFlowProtocol::Tcp && flow.protocol != ConntrackFlowProtocol::Udp) ||
        policy.owned_mask == 0 || (flow.mark & ~policy.owned_mask) != 0 ||
        (flow.mark && !policy.owned_marks.count(flow.mark))) return {};
    const int family = flow.family == ConntrackFlowFamily::Ipv6 ? AF_INET6 : AF_INET;
    const auto excluded = intercept_address_matches(policy.excluded_clients, flow.source, family);
    if (!excluded || *excluded) return {};
    const auto ports_match = [](const PortSpec& spec, bool negate, uint16_t port) {
        if (spec.empty()) return true;
        const bool match = std::any_of(spec.ranges.begin(), spec.ranges.end(),
            [port](const auto& range) { return port >= range.from && port <= range.to; });
        return match != negate;
    };
    for (const auto& rule : policy.rules) {
        const auto& c = rule.criteria;
        if (c.family != AF_UNSPEC && c.family != family) continue;
        if ((c.proto == L4Proto::Tcp && flow.protocol != ConntrackFlowProtocol::Tcp) ||
            (c.proto == L4Proto::Udp && flow.protocol != ConntrackFlowProtocol::Udp)) continue;
        if (!ports_match(c.src_port, c.negate_src_port, flow.source_port) ||
            !ports_match(c.dst_port, c.negate_dst_port, flow.destination_port)) continue;
        bool mismatch = false;
        for (const auto source : {true, false}) {
            const auto& cidrs = source ? c.src_addr : c.dst_addr;
            if (cidrs.empty()) continue;
            std::vector<std::string> family_cidrs;
            for (const auto& cidr : cidrs)
                if ((cidr.find(':') != std::string::npos) == (family == AF_INET6)) family_cidrs.push_back(cidr);
            // Both backends omit a classifier with no addresses in this family,
            // including negated selectors. It is not a catch-all in that family.
            if (family_cidrs.empty()) { mismatch = true; break; }
            const bool negate = source ? c.negate_src_addr : c.negate_dst_addr;
            auto match = intercept_address_matches(family_cidrs, source ? flow.source : flow.destination, family);
            if (!match) return {};
            bool accepts = *match != negate;
            if (negate && policy.split_negated_addresses && family_cidrs.size() > 1) {
                accepts = false;
                for (const auto& cidr : family_cidrs) {
                    auto one = intercept_address_matches({cidr}, source ? flow.source : flow.destination, family);
                    if (!one) return {};
                    accepts = accepts || !*one;
                }
            }
            if (!accepts) { mismatch = true; break; }
        }
        if (mismatch) continue;
        if (c.dst_set_name) {
            const auto present = membership(*c.dst_set_name, flow.destination);
            if (!present) return {};
            if (!*present) continue;
        }
        if (c.dscp || c.src_udp_peer_set_name) return {};
        // The first matching classifier is authoritative. An unlearned static
        // match or an explicit client rule must never be overridden by learning.
        if (!rule.mark || !policy.owned_marks.count(rule.mark) || rule.mark == flow.mark ||
            !c.persist_conntrack_mark || !c.dst_set_name ||
            !policy.learned_sets.count(*c.dst_set_name) || !evidence(*c.dst_set_name, flow.destination)) return {};
        return rule.mark;
    }
    return {};
}

struct InterceptCleanupBatch {
    uint64_t runtime_generation{0};
    std::vector<std::shared_ptr<const InterceptCleanupTicket>> tickets;
    bool valid() const noexcept {
        if (!runtime_generation || tickets.empty() || tickets.size() > 64) return false;
        for (const auto& item : tickets)
            if (!item || !item->grant || !item->grant->snapshot || !item->grant->snapshot->cleanup ||
                (item->family != 4 && item->family != 6) || item->client.empty() ||
                item->destinations.empty() || item->destinations.size() > InterceptCleanupTicket::max_destinations) return false;
        return true;
    }
    bool operator==(const InterceptCleanupBatch& other) const noexcept {
        return runtime_generation == other.runtime_generation && tickets == other.tickets;
    }
};
struct InterceptCleanupResult {
    size_t attempted{0}, failed{0};
    bool command_unavailable{false};
    bool valid_for(const InterceptCleanupBatch&) const noexcept { return attempted <= 4 && failed <= attempted; }
    bool operator==(const InterceptCleanupResult& other) const noexcept {
        return attempted == other.attempted && failed == other.failed && command_unavailable == other.command_unavailable;
    }
};
struct InterceptCleanupOperations {
    std::function<bool()> current;
    std::function<ConntrackFlowObservation(const std::vector<std::string>&, uint32_t, const std::set<std::string>&)> observe;
    InterceptSetMembership membership;
    std::function<bool(const InterceptCleanupTicket&, const std::string&, const std::string&)> evidence;
    std::function<ConntrackCleanupResult(const ConntrackExactForwardedFlow&, uint32_t, uint32_t)> erase;
};

// Runs only inside the existing firewall owner's bounded background operation.
// A single read-only snapshot, four exact deletes at most, no retry or global
// mark/destination flush. STOP and set-write evidence are checked per delete.
inline InterceptCleanupResult execute_intercept_cleanup(const InterceptCleanupBatch& batch,
                                                        const InterceptCleanupOperations& ops) {
    InterceptCleanupResult result;
    if (!batch.valid() || !ops.current || !ops.current() || !ops.observe || !ops.membership || !ops.evidence || !ops.erase) return result;
    const auto chosen = std::find_if(batch.tickets.begin(), batch.tickets.end(), [](const auto& ticket) { return ticket->current(); });
    if (chosen == batch.tickets.end()) return result;
    const auto grant = (*chosen)->grant;
    const auto& policy = *grant->snapshot->cleanup;
    if (!policy.owned_mask || policy.rules.size() > 4096) return result;
    std::set<std::string> sources, destinations;
    for (const auto& ticket : batch.tickets) {
        if (ticket->grant != grant || !ticket->current()) continue;
        sources.insert(ticket->client);
        destinations.insert(ticket->destinations.begin(), ticket->destinations.end());
    }
    if (destinations.empty() || destinations.size() > 64) return result;
    const auto observed = ops.observe({destinations.begin(), destinations.end()}, policy.owned_mask, sources);
    if (observed.snapshot_unavailable || observed.snapshot_truncated || observed.line_limit_reached ||
        observed.flow_limit_reached || observed.local_address_scope_missing || observed.invalid_owned_mask ||
        observed.invalid_destination_selectors || observed.destination_input_truncated) return result;
    for (const auto& flow : observed.flows) {
        if (result.attempted == 4 || !ops.current() || !grant->current()) break;
        // The strict observation excludes DNAT and proves zone zero. The exact
        // delete explicitly selects that zone even if another zone has the same tuple.
        if (flow.zone != std::optional<uint16_t>{0} || flow.destination_port == 53 || flow.destination_port == 853) continue;
        auto ticket = std::find_if(batch.tickets.begin(), batch.tickets.end(), [&](const auto& item) {
            return item->grant == grant && item->current() && item->client == flow.source &&
                (item->family == 6) == (flow.family == ConntrackFlowFamily::Ipv6) &&
                std::find(item->destinations.begin(), item->destinations.end(), flow.destination) != item->destinations.end();
        });
        if (ticket == batch.tickets.end()) continue;
        const auto mark = intercept_cleanup_mark(policy, flow, ops.membership,
            [&](const auto& set, const auto& ip) { return ops.evidence(**ticket, set, ip); });
        if (!mark || !ops.current() || !(*ticket)->current()) continue;
        const auto erased = ops.erase(flow, policy.owned_mask, *mark);
        ++result.attempted;
        if (erased != ConntrackCleanupResult::Succeeded) ++result.failed;
        if (erased == ConntrackCleanupResult::CommandUnavailable) { result.command_unavailable = true; break; }
    }
    return result;
}

} // namespace keen_pbr3
