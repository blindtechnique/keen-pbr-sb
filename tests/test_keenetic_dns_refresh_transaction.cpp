#include <doctest/doctest.h>

#include "daemon/keenetic_dns_refresh_transaction.hpp"

#include <array>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>

using namespace keen_pbr3;

namespace {

enum class Event {
    install_candidate,
    candidate_firewall,
    candidate_resolver_prepare,
    candidate_resolver_commit,
    candidate_resolver_stream,
    restore_previous,
    rollback_firewall,
    rollback_resolver_commit,
    rollback_resolver_stream,
};

std::string exception_message(const std::exception_ptr& failure) {
    if (!failure) {
        return {};
    }
    try {
        std::rethrow_exception(failure);
    } catch (const std::exception& error) {
        return error.what();
    } catch (...) {
        return "unknown";
    }
}

struct TransactionFixture {
    std::array<Event, 16> events{};
    std::size_t event_count{0};
    int active_dns{1};
    int resolver_generation{1};
    bool fail_candidate_firewall{false};
    bool fail_candidate_prepare{false};
    bool fail_candidate_commit{false};
    bool fail_candidate_stream{false};
    bool fail_rollback_firewall{false};
    bool fail_rollback_resolver{false};
    std::shared_ptr<const int> pinned_list =
        std::make_shared<const int>(42);
    std::shared_ptr<const int> globally_published_list = pinned_list;
    bool every_consumer_saw_pinned_list{true};

    void record(Event event) noexcept {
        REQUIRE(event_count < events.size());
        events[event_count++] = event;
    }

    void observe_pinned_list() noexcept {
        every_consumer_saw_pinned_list =
            every_consumer_saw_pinned_list &&
            pinned_list && *pinned_list == 42;
    }

    KeeneticDnsRefreshTransactionResult run(bool firewall_needed) {
        return run_keenetic_dns_refresh_transaction(
            firewall_needed,
            [this]() noexcept {
                record(Event::install_candidate);
                active_dns = 2;
            },
            [this]() {
                record(Event::candidate_firewall);
                observe_pinned_list();
                globally_published_list = std::make_shared<const int>(43);
                if (fail_candidate_firewall) {
                    throw std::runtime_error("candidate firewall");
                }
            },
            [this](bool& resolver_stream_attempted) {
                record(Event::candidate_resolver_prepare);
                observe_pinned_list();
                if (fail_candidate_prepare) {
                    throw std::runtime_error("candidate prepare");
                }
                record(Event::candidate_resolver_commit);
                resolver_generation = 2;
                if (fail_candidate_commit) {
                    throw std::runtime_error("candidate commit");
                }
                resolver_stream_attempted = true;
                record(Event::candidate_resolver_stream);
                if (fail_candidate_stream) {
                    throw std::runtime_error("candidate stream");
                }
            },
            [this]() noexcept {
                record(Event::restore_previous);
                active_dns = 1;
                resolver_generation = 1;
            },
            [this]() {
                record(Event::rollback_firewall);
                observe_pinned_list();
                if (fail_rollback_firewall) {
                    throw std::runtime_error("rollback firewall");
                }
            },
            [this]() {
                record(Event::rollback_resolver_commit);
                observe_pinned_list();
                record(Event::rollback_resolver_stream);
                if (fail_rollback_resolver) {
                    throw std::runtime_error("rollback resolver");
                }
            });
    }
};

void check_events(
    const TransactionFixture& fixture,
    const std::initializer_list<Event>& expected) {
    REQUIRE(fixture.event_count == expected.size());
    std::size_t index = 0;
    for (const Event event : expected) {
        CHECK(fixture.events[index] == event);
        ++index;
    }
}

} // namespace

TEST_CASE("Keenetic DNS refresh transaction commits one pinned generation") {
    TransactionFixture fixture;

    const auto result = fixture.run(/*firewall_needed=*/true);

    CHECK(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::none);
    CHECK_FALSE(result.primary_failure);
    CHECK(fixture.active_dns == 2);
    CHECK(fixture.resolver_generation == 2);
    CHECK(fixture.every_consumer_saw_pinned_list);
    REQUIRE(static_cast<bool>(fixture.globally_published_list));
    CHECK(*fixture.globally_published_list == 43);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_firewall,
         Event::candidate_resolver_prepare,
         Event::candidate_resolver_commit,
         Event::candidate_resolver_stream});
}

TEST_CASE("Keenetic DNS refresh restores memory before successful external rollback") {
    TransactionFixture fixture;
    fixture.fail_candidate_stream = true;

    const auto result = fixture.run(/*firewall_needed=*/true);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::none);
    CHECK(exception_message(result.primary_failure) == "candidate stream");
    CHECK_FALSE(result.recovery_failure);
    CHECK(fixture.active_dns == 1);
    CHECK(fixture.resolver_generation == 1);
    CHECK(fixture.every_consumer_saw_pinned_list);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_firewall,
         Event::candidate_resolver_prepare,
         Event::candidate_resolver_commit,
         Event::candidate_resolver_stream,
         Event::restore_previous,
         Event::rollback_firewall,
         Event::rollback_resolver_commit,
         Event::rollback_resolver_stream});
}

TEST_CASE("Keenetic DNS refresh rolls back an ambiguous firewall failure") {
    TransactionFixture fixture;
    fixture.fail_candidate_firewall = true;

    const auto result = fixture.run(/*firewall_needed=*/true);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::none);
    CHECK(exception_message(result.primary_failure) ==
          "candidate firewall");
    CHECK_FALSE(result.recovery_failure);
    CHECK(fixture.active_dns == 1);
    CHECK(fixture.resolver_generation == 1);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_firewall,
         Event::restore_previous,
         Event::rollback_firewall});
}

TEST_CASE("Keenetic DNS firewall-only recovery never schedules resolver") {
    TransactionFixture fixture;
    fixture.fail_candidate_firewall = true;
    fixture.fail_rollback_firewall = true;

    const auto result = fixture.run(/*firewall_needed=*/true);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::firewall_only);
    CHECK(exception_message(result.primary_failure) ==
          "candidate firewall");
    CHECK(exception_message(result.recovery_failure) ==
          "rollback firewall");
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_firewall,
         Event::restore_previous,
         Event::rollback_firewall});
}

TEST_CASE("Keenetic DNS refresh gates resolver when firewall rollback fails") {
    TransactionFixture fixture;
    fixture.fail_candidate_stream = true;
    fixture.fail_rollback_firewall = true;

    const auto result = fixture.run(/*firewall_needed=*/true);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery ==
          KeeneticDnsRefreshRecovery::firewall_then_resolver);
    CHECK(exception_message(result.primary_failure) == "candidate stream");
    CHECK(exception_message(result.recovery_failure) ==
          "rollback firewall");
    CHECK(fixture.active_dns == 1);
    CHECK(fixture.resolver_generation == 1);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_firewall,
         Event::candidate_resolver_prepare,
         Event::candidate_resolver_commit,
         Event::candidate_resolver_stream,
         Event::restore_previous,
         Event::rollback_firewall});
}

TEST_CASE("Keenetic DNS metadata-only refresh never churns firewall") {
    TransactionFixture fixture;
    fixture.fail_candidate_stream = true;
    fixture.fail_rollback_resolver = true;

    const auto result = fixture.run(/*firewall_needed=*/false);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::resolver_only);
    CHECK(exception_message(result.primary_failure) == "candidate stream");
    CHECK(exception_message(result.recovery_failure) ==
          "rollback resolver");
    CHECK(fixture.active_dns == 1);
    CHECK(fixture.resolver_generation == 1);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_resolver_prepare,
         Event::candidate_resolver_commit,
         Event::candidate_resolver_stream,
         Event::restore_previous,
         Event::rollback_resolver_commit,
         Event::rollback_resolver_stream});
}

TEST_CASE("Keenetic DNS resolver preparation failure has no external rollback") {
    TransactionFixture fixture;
    fixture.fail_candidate_prepare = true;

    const auto result = fixture.run(/*firewall_needed=*/false);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::none);
    CHECK(exception_message(result.primary_failure) == "candidate prepare");
    CHECK(fixture.active_dns == 1);
    CHECK(fixture.resolver_generation == 1);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_resolver_prepare,
         Event::restore_previous});
}

TEST_CASE("Keenetic DNS resolver commit failure has no external rollback") {
    TransactionFixture fixture;
    fixture.fail_candidate_commit = true;

    const auto result = fixture.run(/*firewall_needed=*/false);

    CHECK_FALSE(result.committed);
    CHECK(result.recovery == KeeneticDnsRefreshRecovery::none);
    CHECK(exception_message(result.primary_failure) == "candidate commit");
    CHECK(fixture.active_dns == 1);
    CHECK(fixture.resolver_generation == 1);
    check_events(
        fixture,
        {Event::install_candidate,
         Event::candidate_resolver_prepare,
         Event::candidate_resolver_commit,
         Event::restore_previous});
}

TEST_CASE("Keenetic DNS recovery dispatch failure preserves ownership boundaries") {
    bool resolver_gated = false;
    int firewall_schedules{0};
    int resolver_schedules{0};

    const std::exception_ptr failure =
        dispatch_keenetic_dns_refresh_recovery(
            KeeneticDnsRefreshRecovery::firewall_then_resolver,
            [&]() noexcept {
                resolver_gated = true;
                return true;
            },
            [&]() noexcept { resolver_gated = false; },
            [&]() {
                ++firewall_schedules;
                throw std::runtime_error("scheduler unavailable");
            },
            [&]() { ++resolver_schedules; });

    CHECK(exception_message(failure) == "scheduler unavailable");
    CHECK_FALSE(resolver_gated);
    CHECK(firewall_schedules == 1);
    CHECK(resolver_schedules == 0);
}

TEST_CASE("Keenetic DNS dispatch keeps a resolver gate owned by earlier recovery") {
    bool resolver_gated = true;
    int ungate_calls{0};

    const std::exception_ptr failure =
        dispatch_keenetic_dns_refresh_recovery(
            KeeneticDnsRefreshRecovery::firewall_then_resolver,
            [&]() noexcept {
                const bool already_gated = resolver_gated;
                resolver_gated = true;
                return !already_gated;
            },
            [&]() noexcept {
                ++ungate_calls;
                resolver_gated = false;
            },
            []() {
                throw std::runtime_error("scheduler unavailable");
            },
            []() {});

    CHECK(exception_message(failure) == "scheduler unavailable");
    CHECK(resolver_gated);
    CHECK(ungate_calls == 0);
}
