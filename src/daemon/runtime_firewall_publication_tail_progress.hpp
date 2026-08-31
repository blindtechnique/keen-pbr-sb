#pragma once

namespace keen_pbr3 {

// Value-only progress for the controller-side tail that follows a worker
// terminal. This is deliberately not a linear state machine: DNS/config may
// publish resolver state before core, START verifies resolver before core, and
// cold boot publishes several checkpoints in one existing atomic callback.
class RuntimeFirewallPublicationTailProgress final {
public:
    bool core_published() const noexcept { return core_published_; }
    void mark_core_published() noexcept { core_published_ = true; }
    void mark_core_restored() noexcept { core_published_ = false; }

    bool internal_vpn_lkg_published() const noexcept {
        return internal_vpn_lkg_published_;
    }
    void mark_internal_vpn_lkg_published() noexcept {
        internal_vpn_lkg_published_ = true;
    }
    void mark_internal_vpn_lkg_restored() noexcept {
        internal_vpn_lkg_published_ = false;
    }

    bool resolver_generation_published() const noexcept {
        return resolver_generation_published_;
    }
    void mark_resolver_generation_published() noexcept {
        resolver_generation_published_ = true;
    }

    bool resolver_tail_finished() const noexcept {
        return resolver_tail_finished_;
    }
    void mark_resolver_tail_finished() noexcept {
        resolver_tail_finished_ = true;
    }

    bool meta_tail_finished() const noexcept {
        return meta_tail_finished_;
    }
    void mark_meta_tail_finished() noexcept {
        meta_tail_finished_ = true;
    }

    bool conntrack_tail_finished() const noexcept {
        return conntrack_tail_finished_;
    }
    void mark_conntrack_tail_finished() noexcept {
        conntrack_tail_finished_ = true;
    }

    bool runtime_incident_tail_finished() const noexcept {
        return runtime_incident_tail_finished_;
    }
    void mark_runtime_incident_tail_finished() noexcept {
        runtime_incident_tail_finished_ = true;
    }

    bool start_candidate_published() const noexcept {
        return start_candidate_published_;
    }
    void mark_start_candidate_published() noexcept {
        start_candidate_published_ = true;
    }

    bool start_finalized() const noexcept { return start_finalized_; }
    void set_start_finalized(bool finalized) noexcept {
        start_finalized_ = finalized;
    }

    bool start_post_success_finished() const noexcept {
        return start_post_success_finished_;
    }
    void mark_start_post_success_finished() noexcept {
        start_post_success_finished_ = true;
    }

private:
    bool core_published_{false};
    bool internal_vpn_lkg_published_{false};
    bool resolver_generation_published_{false};
    bool resolver_tail_finished_{false};
    bool meta_tail_finished_{false};
    bool conntrack_tail_finished_{false};
    bool runtime_incident_tail_finished_{false};
    bool start_candidate_published_{false};
    bool start_finalized_{false};
    bool start_post_success_finished_{false};
};

} // namespace keen_pbr3
