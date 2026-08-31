#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_publication_tail_progress.hpp"

#include <type_traits>
#include <utility>

namespace keen_pbr3 {

static_assert(
    std::is_nothrow_copy_constructible_v<
        RuntimeFirewallPublicationTailProgress>);
static_assert(
    std::is_nothrow_move_assignable_v<
        RuntimeFirewallPublicationTailProgress>);
static_assert(noexcept(
    std::declval<RuntimeFirewallPublicationTailProgress&>()
        .mark_core_published()));
static_assert(noexcept(
    std::declval<RuntimeFirewallPublicationTailProgress&>()
        .mark_runtime_incident_tail_finished()));

TEST_CASE("runtime firewall publication tail starts with no completed phase") {
    const RuntimeFirewallPublicationTailProgress progress;

    CHECK_FALSE(progress.core_published());
    CHECK_FALSE(progress.internal_vpn_lkg_published());
    CHECK_FALSE(progress.resolver_generation_published());
    CHECK_FALSE(progress.resolver_tail_finished());
    CHECK_FALSE(progress.meta_tail_finished());
    CHECK_FALSE(progress.conntrack_tail_finished());
    CHECK_FALSE(progress.runtime_incident_tail_finished());
    CHECK_FALSE(progress.start_candidate_published());
    CHECK_FALSE(progress.start_finalized());
    CHECK_FALSE(progress.start_post_success_finished());
}

TEST_CASE("publication tail records its existing independent phase DAG") {
    RuntimeFirewallPublicationTailProgress progress;

    progress.mark_resolver_generation_published();
    progress.mark_resolver_tail_finished();
    progress.mark_core_published();
    progress.mark_internal_vpn_lkg_published();
    progress.mark_meta_tail_finished();
    progress.mark_conntrack_tail_finished();
    progress.mark_start_candidate_published();
    progress.set_start_finalized(true);
    progress.mark_start_post_success_finished();
    progress.mark_runtime_incident_tail_finished();

    CHECK(progress.resolver_generation_published());
    CHECK(progress.resolver_tail_finished());
    CHECK(progress.core_published());
    CHECK(progress.internal_vpn_lkg_published());
    CHECK(progress.meta_tail_finished());
    CHECK(progress.conntrack_tail_finished());
    CHECK(progress.start_candidate_published());
    CHECK(progress.start_finalized());
    CHECK(progress.start_post_success_finished());
    CHECK(progress.runtime_incident_tail_finished());
}

TEST_CASE("cold boot publication can restore only reversible checkpoints") {
    RuntimeFirewallPublicationTailProgress progress;
    progress.mark_core_published();
    progress.mark_internal_vpn_lkg_published();
    progress.set_start_finalized(true);

    progress.mark_internal_vpn_lkg_restored();
    progress.mark_core_restored();
    progress.set_start_finalized(false);

    CHECK_FALSE(progress.internal_vpn_lkg_published());
    CHECK_FALSE(progress.core_published());
    CHECK_FALSE(progress.start_finalized());
}

} // namespace keen_pbr3
