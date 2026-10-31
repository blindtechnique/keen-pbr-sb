#include "intercept_runtime.hpp"
#include "intercept_cleanup.hpp"
#include "../firewall/firewall.hpp"
#include "../log/logger.hpp"
#include <algorithm>

namespace keen_pbr3 {

class InterceptRuntime::Update final : public FirewallInterceptionUpdate {
public:
    explicit Update(InterceptRuntime& owner) : owner_(owner), generation_(++owner.generation_),
                                               leased_service_(owner.service_) {
        if (owner_.cleanup_) owner_.cleanup_->revoke();
        if (leased_service_)
            pause_ = std::make_unique<InterceptService::WritePause>(leased_service_->pause_writes());
        auto pending = owner_.health();
        if (pending.dns_requested) pending.dns_state = "applying";
        if (pending.l7_requested) pending.l7_state = "applying";
        owner_.publish(std::move(pending));
    }
    ~Update() override {
        if (!committed_ && generation_ == owner_.generation_ && owner_.service_) {
            owner_.service_->invalidate_snapshot();
            owner_.service_->invalidate_set_cache();
        }
        if (!committed_ && generation_ == owner_.generation_) {
            try {
                auto failed = owner_.health();
                if (failed.dns_requested) failed.dns_state = "snapshot_unavailable";
                if (failed.l7_requested) failed.l7_state = "snapshot_unavailable";
                owner_.publish(failed);
            } catch (...) {
                std::atomic_store(&owner_.published_, std::shared_ptr<const Published>{});
            }
        }
    }

    InterceptionHooks prepare(const std::vector<InterceptListBinding>& bindings,
        const InterceptSnapshotPolicy& policy, const InterceptDomainReader& reader,
        bool reuse_index, const InterceptionRequest& request) override {
        if (generation_ != owner_.generation_)
            throw std::logic_error("Passive learning transaction was superseded");
        result_ = {};
        result_.dns_requested = request.dns;
        result_.l7_requested = request.l7;
        result_.interfaces = request.interfaces;
        result_.dns_state = request.dns ? "applying" : "disabled";
        result_.l7_state = request.l7 ? "applying" : "disabled";
        owner_.publish(result_);
        if ((!request.dns && !request.l7) || request.interfaces.empty() || bindings.empty()) {
            const char* reason = request.interfaces.empty() ? "no_interfaces" : "no_lists";
            if (request.dns) result_.dns_state = reason;
            if (request.l7) result_.l7_state = reason;
            candidate_.reset();
            return {};
        }
        if (reuse_index) {
            const auto old = owner_.service_ ? owner_.service_->current_snapshot() : nullptr;
            if (!old || !old->index)
                throw FirewallRulesOnlyError("Passive learning needs a domain-index rebuild");
            const auto& names = old->index->list_names();
            for (const auto& binding : bindings) {
                const auto it = std::find(names.begin(), names.end(), binding.name);
                const auto id = static_cast<std::size_t>(it - names.begin());
                if (it == names.end() || id >= old->list_signatures.size() ||
                    old->list_signatures[id] != binding.content_signature)
                    throw FirewallRulesOnlyError("Passive learning list generation changed");
            }
            candidate_ = rebind_intercept_snapshot(old, bindings, policy);
        } else {
            candidate_ = build_intercept_snapshot(bindings, policy, reader);
        }
        if (!owner_.service_ || owner_.explicitly_stopped_ ||
            request.dns != owner_.listening_dns_ || request.l7 != owner_.listening_l7_) {
            pause_.reset();
            if (owner_.service_) owner_.service_->stop();
            owner_.service_.reset();
            try {
                owner_.service_ = owner_.factory_();
                if (!owner_.service_) throw std::runtime_error("No passive learning service");
                InterceptServiceOptions options;
                if (request.dns) options.queue_num = InterceptionHooks::queue;
                if (request.l7) options.nflog_group = InterceptionHooks::group;
                options.conntrack_cleanup = bool(owner_.cleanup_);
                // Before the verified firewall commit, a listener may ACCEPT
                // stale capture rules but has no authority to learn addresses.
                if (owner_.starter_) owner_.starter_(*owner_.service_, options);
                else owner_.service_->start(options, nullptr);
                owner_.explicitly_stopped_ = false;
                owner_.listening_dns_ = request.dns;
                owner_.listening_l7_ = request.l7;
                leased_service_ = owner_.service_;
                pause_ = std::make_unique<InterceptService::WritePause>(leased_service_->pause_writes());
            } catch (const std::exception& error) {
                Logger::instance().warn("Passive DNS/L7 learning unavailable: {}", error.what());
                capture_probes();
                if (request.dns) { result_.dns_state = "unavailable"; result_.dns_detail = error.what(); }
                if (request.l7) { result_.l7_state = "unavailable"; result_.l7_detail = error.what(); }
                candidate_.reset();
                return {};
            }
        }
        // bypass protects an absent listener; FAIL_OPEN also protects queue
        // saturation while it is present. Old kernels may silently ignore it.
        capture_probes();
        const bool dns = request.dns && owner_.service_->dns_bound() &&
                         owner_.service_->listener_probe().fail_open.is_ok();
        if (owner_.service_->dns_bound() && !dns)
            Logger::instance().warn("Passive DNS hold disabled: kernel FAIL_OPEN is unconfirmed; dnsmasq remains active");
        const bool l7 = request.l7 && owner_.service_->l7_bound();
        if (request.dns) result_.dns_state = dns ? "active" :
            owner_.service_->dns_bound() ? "fail_open_unconfirmed" : "unavailable";
        if (request.l7) result_.l7_state = l7 ? "active" : "unavailable";
        return {dns, l7};
    }

    void commit() noexcept override {
        if (generation_ != owner_.generation_) return;
        if (owner_.service_) {
            try {
                owner_.service_->invalidate_set_cache();
                owner_.service_->discard_l7_pending();
                owner_.service_->update_snapshot(candidate_);
                if (owner_.cleanup_) owner_.cleanup_->publish(owner_.service_, candidate_);
            } catch (...) {
                // Index-slot/event bookkeeping may allocate. The routing
                // COMMIT already succeeded: optional learning must never
                // terminate the daemon or undo ordinary routing on OOM.
                owner_.service_->invalidate_snapshot();
                if (owner_.cleanup_) owner_.cleanup_->revoke();
                try { Logger::instance().warn("Passive learning snapshot publication failed; DNS remains pass-through"); }
                catch (...) {}
            }
            // Release the gate before destroying the service it references.
            pause_.reset();
            if (!candidate_) owner_.stop();
        }
        owner_.publish(result_);
        committed_ = true;
    }

private:
    void capture_probes() {
        if (!owner_.service_) return;
        const auto& probes = owner_.service_->listener_probe();
        result_.nfqueue = nfnl::probe_status_name(probes.nfqueue.status);
        result_.nflog = nfnl::probe_status_name(probes.nflog.status);
        result_.fail_open = nfnl::probe_status_name(probes.fail_open.status);
        result_.dns_detail = probes.nfqueue.reason;
        if (owner_.service_->dns_bound() && !probes.fail_open.is_ok())
            result_.dns_detail = probes.fail_open.reason;
        result_.l7_detail = probes.nflog.reason;
    }
    InterceptRuntime& owner_;
    uint64_t generation_;
    // A superseded attempt may still own a pause while a newer listener starts.
    // Keep its exact service alive until that pause has been released.
    std::shared_ptr<InterceptService> leased_service_;
    std::unique_ptr<InterceptService::WritePause> pause_;
    std::shared_ptr<const InterceptSnapshot> candidate_;
    InterceptionHealth result_;
    bool committed_{false};
};

InterceptRuntime::~InterceptRuntime() { stop(); }
std::shared_ptr<FirewallInterceptionUpdate> InterceptRuntime::begin_update() {
    return std::make_shared<Update>(*this);
}
void InterceptRuntime::stop() noexcept {
    if (cleanup_) cleanup_->revoke();
    ++generation_;
    explicitly_stopped_ = true;
    try {
        auto state = health();
        if (state.dns_requested) state.dns_state = "stopped";
        if (state.l7_requested) state.l7_state = "stopped";
        publish(std::move(state));
    } catch (...) { std::atomic_store(&published_, std::shared_ptr<const Published>{}); }
    if (service_) service_->stop();
    // Keep the stopped object alive for any transaction's outstanding pause.
}

void InterceptRuntime::publish(const InterceptionHealth& health) noexcept {
    try {
        std::shared_ptr<const Published> next =
            std::make_shared<Published>(Published{health, service_});
        std::atomic_store(&published_, std::move(next));
    } catch (...) {
        // Missing diagnostics must not masquerade as healthy or undo COMMIT.
        std::atomic_store(&published_, std::shared_ptr<const Published>{});
    }
}

InterceptionHealth InterceptRuntime::health() const {
    const auto view = std::atomic_load(&published_);
    if (!view) return {};
    auto result = view->health;
    if (!view->service) return result;
    const auto& service = *view->service;
    const auto update = [&](std::string& state, std::string& detail, bool bound) {
        if (state != "active") return;
        if (!bound) { state = "unavailable"; detail = "Listener stopped after apply"; }
        else if (!service.snapshot_ready()) state = "snapshot_unavailable";
    };
    update(result.dns_state, result.dns_detail, service.dns_bound());
    update(result.l7_state, result.l7_detail, service.l7_bound());
    const auto& counters = service.counters();
    result.dns_packets = counters.dns_packets.load(std::memory_order_relaxed);
    result.dns_matched = counters.dns_matched.load(std::memory_order_relaxed);
    result.l7_packets = counters.l7_packets.load(std::memory_order_relaxed);
    result.l7_matched = counters.l7_matched.load(std::memory_order_relaxed);
    result.set_errors = counters.set_errors.load(std::memory_order_relaxed);
    result.dns_hold_timeouts = counters.dns_hold_timeouts.load(std::memory_order_relaxed);
    result.queue_overruns = counters.queue_overruns.load(std::memory_order_relaxed);
    result.log_overruns = counters.log_overruns.load(std::memory_order_relaxed);
    return result;
}

std::shared_ptr<FirewallInterceptionRuntime> make_intercept_runtime(
    bool nftables, std::shared_ptr<InterceptCleanupChannel> cleanup) {
    return std::make_shared<InterceptRuntime>([nftables, cleanup] {
        auto writer = nftables ? nfnl::make_nft_writer() : nfnl::make_ipset_writer();
        auto l7_writer = nftables ? nfnl::make_nft_writer() : nfnl::make_ipset_writer();
        return std::make_unique<InterceptService>(std::move(writer), std::move(l7_writer), nullptr, cleanup);
    }, InterceptRuntime::Starter{}, cleanup);
}

} // namespace keen_pbr3
