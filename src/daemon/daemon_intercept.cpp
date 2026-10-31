#include "daemon.hpp"
#include "runtime_firewall_operation_owner.hpp"
#include "../netfilter/set_reader.hpp"
#include "../util/safe_exec.hpp"
#include "../log/logger.hpp"

namespace keen_pbr3 {

void Daemon::dispatch_intercept_cleanup() noexcept {
    const auto channel = intercept_cleanup_channel_;
    if (!channel) return;
    try {
        auto tickets = channel->take();
        tickets.erase(std::remove_if(tickets.begin(), tickets.end(), [](const auto& t) { return !t->current(); }), tickets.end());
        if (!tickets.empty() && running_.load(std::memory_order_acquire) && routing_runtime_active() &&
            !runtime_firewall_owner_->shutdown_requested()) {
            auto admitted = runtime_mutation_admission_.try_acquire(
                "intercept-conntrack-cleanup", RuntimeMutationAdmission::Kind::Background);
            if (admitted) {
                auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(std::move(*admitted));
                const auto token = lease->token();
                RuntimeBackgroundPointMutationTarget target;
                target.kind = RuntimeBackgroundPointMutationKind::intercept_cleanup;
                target.target_serial = ++background_point_mutation_serial_;
                if (!target.target_serial) target.target_serial = ++background_point_mutation_serial_;
                target.payload = InterceptCleanupBatch{runtime_generation_.load(std::memory_order_acquire), std::move(tickets)};
                auto transaction = std::make_shared<RuntimeBackgroundPointMutationTransaction>(std::move(target));
                RuntimeFirewallPreownedTerminalContinuation continuation{
                    [this, channel, transaction, token](RuntimeFirewallLifecycleTerminal,
                        std::unique_ptr<RuntimeMutationAdmission::Lease> exact) noexcept {
                        try {
                            if (exact && exact->token() == token && runtime_mutation_admission_.owns(*exact) &&
                                transaction->typed_identity_valid && transaction->result &&
                                transaction->result->control_publishable() && transaction->result->target == transaction->target) {
                                const auto& outcome = std::get<InterceptCleanupResult>(transaction->result->payload);
                                if (outcome.command_unavailable) warn_conntrack_unavailable_once();
                                if (outcome.attempted) Logger::instance().debug(
                                    "Passive learning conntrack cleanup: {} exact attempts, {} failed", outcome.attempted, outcome.failed);
                            }
                        } catch (...) {}
                        channel->finish();
                    }};
                if (begin_preowned_runtime_firewall_background_point_mutation(lease, transaction, continuation)) return;
            }
        }
    } catch (...) {}
    // Busy/STOP/expired requests are dropped, never promoted to health errors
    // or added to the firewall recovery/retry queue.
    channel->finish();
}

InterceptCleanupResult Daemon::execute_intercept_cleanup_batch(const InterceptCleanupBatch& batch) noexcept {
    try {
        KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        const auto current = [this, &batch, deadline] {
            return std::chrono::steady_clock::now() < deadline && running_.load(std::memory_order_acquire) &&
                routing_runtime_active() && !runtime_firewall_owner_->shutdown_requested() &&
                runtime_generation_.load(std::memory_order_acquire) == batch.runtime_generation;
        };
        if (!current() || !firewall_) return {};
        std::vector<std::string> local;
        for (const auto& iface : netlink_.dump_interfaces()) {
            local.insert(local.end(), iface.ipv4_addresses.begin(), iface.ipv4_addresses.end());
            local.insert(local.end(), iface.ipv6_addresses.begin(), iface.ipv6_addresses.end());
        }
        if (local.empty()) return {};
        // Reuse the exact ConntrackManager path, with this operation's remaining
        // budget, instead of a second deletion implementation or global timeout.
        ConntrackManager conntrack([deadline](const auto& args) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (left.count() <= 0) return ConntrackManager::CommandResult{-1, {}};
            const auto reply = safe_exec_capture(args, false, 4096, true, true,
                SafeExecFailureLog::DiagnosticOnly, SafeExecTimeouts{std::min(left, std::chrono::milliseconds(250)), std::chrono::milliseconds(50)});
            return ConntrackManager::CommandResult{
                reply.timed_out || reply.truncated || reply.termination_uncertain ? -1 : reply.exit_code, reply.stdout_output};
        });
        nfnl::SetMembershipReader sets(firewall_->backend() == FirewallBackend::nftables, nfnl::make_netlink_transport());
        InterceptCleanupOperations operations;
        operations.current = current;
        operations.observe = [&](const auto& destinations, uint32_t mask, const auto& sources) {
            ConntrackFlowObservationOptions options;
            options.require_default_zone_no_dnat = true;
            options.ordinary_sources = sources;
            options.max_destination_input_cidrs = 64;
            return conntrack.observe_forwarded_destination_flows(destinations, local, mask, options);
        };
        operations.membership = [&](const auto& set, const auto& ip) -> std::optional<bool> {
            if (!current()) return {};
            return sets.contains(set, ip, deadline);
        };
        operations.evidence = [&](const InterceptCleanupTicket& ticket, const auto& set, const auto& ip) {
            auto service = ticket.grant->service.lock();
            if (!current() || !ticket.current() || !service) return false;
            const auto proof = service->lookup_set_write_evidence(ticket.grant->snapshot, set, ip);
            const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return proof && proof->state == SetElementCache::State::Fresh &&
                (proof->expires_at_ms == SetElementCache::kPermanent || proof->expires_at_ms > now_ms + 2000);
        };
        operations.erase = [&](const auto& flow, uint32_t mask, uint32_t desired) {
            if (!current()) return ConntrackCleanupResult::Failed;
            return conntrack.delete_exact_forwarded_flow(flow, mask, flow.mark ? flow.mark : desired);
        };
        return execute_intercept_cleanup(batch, operations);
    } catch (const std::exception& error) {
        try { Logger::instance().debug("Passive learning cleanup skipped: {}", error.what()); } catch (...) {}
    } catch (...) {}
    return {};
}
} // namespace keen_pbr3
