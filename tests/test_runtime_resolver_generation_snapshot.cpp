#include <doctest/doctest.h>

#include "../src/daemon/runtime_resolver_generation_snapshot.hpp"
#include "../src/runtime/runtime_state_machine.hpp"

#include <memory>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

std::shared_ptr<const ResolverGenerationSnapshot> stream_generation(
    std::uint64_t generation,
    std::uint64_t stream_epoch) {
    auto snapshot = std::make_shared<ResolverGenerationSnapshot>();
    snapshot->generation = generation;
    snapshot->stream_epoch = stream_epoch;
    snapshot->list_cache_snapshot =
        std::make_shared<ListCacheGenerationSnapshot>();
    return snapshot;
}

} // namespace

TEST_CASE("runtime resolver stream selects a private generation only for the exact active attempt") {
    const auto committed = stream_generation(41U, 9U);
    const auto candidate = stream_generation(42U, 10U);
    const std::string exact_attempt(32U, 'a');

    const auto selection = select_runtime_resolver_stream_generation(
        exact_attempt,
        exact_attempt,
        committed,
        candidate);

    REQUIRE(selection);
    CHECK(selection.correlated_attempt);
    CHECK(selection.generation.get() == candidate.get());
    CHECK(selection.generation.get() != committed.get());
    CHECK(selection.stream_epoch == 10U);
    CHECK(runtime_resolver_stream_selection_error_code(selection.error)
              .empty());
}

TEST_CASE("manual resolver stream never observes an active private generation") {
    const auto committed = stream_generation(50U, 20U);
    const auto candidate = stream_generation(51U, 21U);
    const std::string active_attempt(32U, 'b');

    const auto busy = select_runtime_resolver_stream_generation(
        {}, active_attempt, committed, candidate);
    CHECK_FALSE(busy);
    CHECK_FALSE(busy.correlated_attempt);
    CHECK_FALSE(busy.generation);
    CHECK(busy.error == RuntimeResolverStreamSelectionError::stream_busy);
    CHECK(runtime_resolver_stream_selection_error_code(busy.error) ==
          "resolver_stream_busy");

    // Even if an active pointer is left behind after its authority is
    // retired, the absence of an active id makes the committed pointer the
    // sole manual/stale-token source.
    const auto manual = select_runtime_resolver_stream_generation(
        {}, {}, committed, candidate);
    REQUIRE(manual);
    CHECK_FALSE(manual.correlated_attempt);
    CHECK(manual.generation.get() == committed.get());

    const std::string stale_valid_attempt(32U, 'c');
    const auto stale = select_runtime_resolver_stream_generation(
        stale_valid_attempt, {}, committed, candidate);
    REQUIRE(stale);
    CHECK_FALSE(stale.correlated_attempt);
    CHECK(stale.generation.get() == committed.get());
}

TEST_CASE("runtime resolver stream rejects mismatched or unprepared active attempts") {
    const auto committed = stream_generation(60U, 30U);
    const auto candidate = stream_generation(61U, 31U);
    const auto unprepared = stream_generation(61U, 0U);
    const std::string active_attempt(32U, 'd');
    const std::string other_attempt(32U, 'e');

    const auto mismatch = select_runtime_resolver_stream_generation(
        other_attempt, active_attempt, committed, candidate);
    CHECK_FALSE(mismatch);
    CHECK(mismatch.error ==
          RuntimeResolverStreamSelectionError::attempt_mismatch);
    CHECK(runtime_resolver_stream_selection_error_code(mismatch.error) ==
          "resolver_attempt_mismatch");

    const auto missing = select_runtime_resolver_stream_generation(
        active_attempt, active_attempt, committed, nullptr);
    CHECK_FALSE(missing);
    CHECK(missing.error ==
          RuntimeResolverStreamSelectionError::generation_unavailable);

    const auto epoch_zero = select_runtime_resolver_stream_generation(
        active_attempt, active_attempt, committed, unprepared);
    CHECK_FALSE(epoch_zero);
    CHECK(epoch_zero.error ==
          RuntimeResolverStreamSelectionError::generation_unavailable);
}

TEST_CASE("active routing admits only an exact complete private resolver selection") {
    const auto candidate = stream_generation(62U, 32U);
    const std::string exact_attempt(32U, '1');

    const auto exact_private = select_runtime_resolver_stream_generation(
        exact_attempt, exact_attempt, nullptr, candidate);
    REQUIRE(exact_private);
    CHECK(exact_private.correlated_attempt);
    CHECK(runtime_resolver_stream_selection_available(
        RuntimeState::running,
        /*routing_runtime_active=*/true,
        exact_private,
        nullptr,
        nullptr));

    const auto manual_without_committed =
        select_runtime_resolver_stream_generation(
            {}, {}, nullptr, candidate);
    CHECK_FALSE(manual_without_committed);
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::running,
        /*routing_runtime_active=*/true,
        manual_without_committed,
        nullptr,
        nullptr));

    const auto mismatch = select_runtime_resolver_stream_generation(
        std::string(32U, '2'),
        exact_attempt,
        nullptr,
        candidate);
    CHECK_FALSE(mismatch);
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::running,
        /*routing_runtime_active=*/true,
        mismatch,
        nullptr,
        nullptr));

    auto incomplete =
        std::make_shared<ResolverGenerationSnapshot>(*candidate);
    incomplete->list_cache_snapshot.reset();
    const auto incomplete_private =
        select_runtime_resolver_stream_generation(
            exact_attempt, exact_attempt, nullptr, incomplete);
    REQUIRE(incomplete_private);
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::running,
        /*routing_runtime_active=*/true,
        incomplete_private,
        nullptr,
        nullptr));
}

TEST_CASE("resolver availability preserves exact inactive activation boundary") {
    const auto committed = stream_generation(70U, 40U);
    const auto private_candidate = stream_generation(71U, 41U);
    const std::string exact_attempt(32U, '3');

    const auto committed_activation =
        select_runtime_resolver_stream_generation(
            exact_attempt,
            exact_attempt,
            committed,
            committed);
    REQUIRE(committed_activation);
    CHECK(runtime_resolver_stream_selection_available(
        RuntimeState::starting,
        /*routing_runtime_active=*/false,
        committed_activation,
        committed,
        committed));
    CHECK(runtime_resolver_stream_selection_available(
        RuntimeState::applying,
        /*routing_runtime_active=*/false,
        committed_activation,
        committed,
        committed));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::stopped,
        /*routing_runtime_active=*/false,
        committed_activation,
        committed,
        committed));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::shutting_down,
        /*routing_runtime_active=*/false,
        committed_activation,
        committed,
        committed));

    const auto manual = select_runtime_resolver_stream_generation(
        {}, {}, committed, nullptr);
    REQUIRE(manual);
    CHECK(runtime_resolver_stream_selection_available(
        RuntimeState::running,
        /*routing_runtime_active=*/true,
        manual,
        committed,
        nullptr));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::stopped,
        /*routing_runtime_active=*/true,
        manual,
        committed,
        nullptr));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::starting,
        /*routing_runtime_active=*/false,
        manual,
        committed,
        committed));

    const auto private_activation =
        select_runtime_resolver_stream_generation(
            exact_attempt,
            exact_attempt,
            nullptr,
            private_candidate);
    REQUIRE(private_activation);
    CHECK(runtime_resolver_stream_selection_available(
        RuntimeState::starting,
        /*routing_runtime_active=*/false,
        private_activation,
        nullptr,
        private_candidate));
    CHECK(runtime_resolver_stream_selection_available(
        RuntimeState::applying,
        /*routing_runtime_active=*/false,
        private_activation,
        nullptr,
        private_candidate));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::stopped,
        /*routing_runtime_active=*/false,
        private_activation,
        nullptr,
        private_candidate));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::shutting_down,
        /*routing_runtime_active=*/false,
        private_activation,
        nullptr,
        private_candidate));
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::starting,
        /*routing_runtime_active=*/false,
        private_activation,
        nullptr,
        nullptr));

    const auto mismatched_inactive = stream_generation(72U, 42U);
    CHECK_FALSE(runtime_resolver_stream_selection_available(
        RuntimeState::starting,
        /*routing_runtime_active=*/false,
        private_activation,
        nullptr,
        mismatched_inactive));
}

TEST_CASE("runtime resolver completion stays bound to attempt pointer and stream epoch") {
    const auto candidate = stream_generation(71U, 41U);
    const auto replacement = stream_generation(71U, 42U);
    const std::string exact_attempt(32U, 'f');

    CHECK(runtime_resolver_stream_completion_is_exact(
        exact_attempt,
        41U,
        candidate,
        exact_attempt,
        candidate));
    CHECK_FALSE(runtime_resolver_stream_completion_is_exact(
        exact_attempt,
        41U,
        candidate,
        std::string(32U, '0'),
        candidate));
    CHECK_FALSE(runtime_resolver_stream_completion_is_exact(
        exact_attempt,
        41U,
        candidate,
        exact_attempt,
        replacement));
    CHECK_FALSE(runtime_resolver_stream_completion_is_exact(
        exact_attempt,
        42U,
        candidate,
        exact_attempt,
        candidate));
}

TEST_CASE("runtime resolver generation is built only from its candidate input") {
    const auto pinned_lists =
        std::make_shared<ListCacheGenerationSnapshot>();

    DnsServer keenetic_server;
    keenetic_server.tag = "keenetic";
    keenetic_server.type = api::DnsServerType::KEENETIC;
    DnsConfig dns;
    dns.servers = std::vector<DnsServer>{keenetic_server};
    dns.fallback = std::vector<std::string>{"keenetic"};

    RuntimeResolverGenerationInput candidate;
    candidate.config.dns = dns;
    candidate.keenetic_dns.snapshot = KeeneticDnsSnapshot{
        {"192.0.2.53"},
        {},
        {{"candidate.example", "192.0.2.80"}}};
    candidate.keenetic_dns.status = KeeneticDnsCacheStatus::fresh;
    candidate.keenetic_dns.generation = 41U;
    candidate.list_cache_snapshot = pinned_lists;
    candidate.list_max_file_size_bytes = 1024U * 1024U;
    candidate.resolver_type = ResolverType::DNSMASQ_NFTSET;
    candidate.ipv6_policy =
        ResolverIpv6Policy::explicitly_disabled();
    candidate.trusted_dns_interfaces = {"Wireguard9"};
    candidate.generation = 77U;

    const auto prepared =
        build_runtime_resolver_generation_snapshot(candidate);

    REQUIRE(prepared.config.dns.has_value());
    REQUIRE(prepared.keenetic_dns.snapshot.has_value());
    CHECK(prepared.keenetic_dns.snapshot->addresses ==
          std::vector<std::string>{"192.0.2.53"});
    CHECK(prepared.keenetic_dns.generation == 41U);
    CHECK(prepared.list_cache_snapshot.get() == pinned_lists.get());
    CHECK(prepared.resolver_type == ResolverType::DNSMASQ_NFTSET);
    CHECK_FALSE(prepared.ipv6_policy.targets_enabled);
    CHECK(prepared.ipv6_policy.suppress_aaaa);
    CHECK(prepared.trusted_dns_interfaces ==
          std::vector<std::string>{"Wireguard9"});
    CHECK(prepared.generation == 77U);
    CHECK(prepared.stream_epoch == 0U);
    CHECK(prepared.expected_hash.size() == 32U);

    auto other_candidate = candidate;
    other_candidate.keenetic_dns.snapshot->addresses = {"198.51.100.53"};
    other_candidate.trusted_dns_interfaces = {"Wireguard10"};
    other_candidate.generation = 88U;
    const auto other_prepared =
        build_runtime_resolver_generation_snapshot(other_candidate);

    CHECK(other_prepared.generation == 88U);
    CHECK(other_prepared.keenetic_dns.snapshot->addresses ==
          std::vector<std::string>{"198.51.100.53"});
    CHECK(other_prepared.expected_hash != prepared.expected_hash);
    CHECK(prepared.keenetic_dns.snapshot->addresses ==
          std::vector<std::string>{"192.0.2.53"});
    CHECK(prepared.trusted_dns_interfaces ==
          std::vector<std::string>{"Wireguard9"});
}
