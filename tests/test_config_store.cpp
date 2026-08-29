#include <doctest/doctest.h>

#include "../src/daemon/config_store.hpp"
#include "../src/daemon/runtime_config_terminal_policy.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

Config config_named(const std::string& name) {
    Config config;
    config.daemon = DaemonConfig{};
    config.daemon->cache_dir = "/tmp/" + name;
    return config;
}

Config interface_config_named(const std::string& name,
                              const std::string& device) {
    auto config = config_named(name);
    Outbound outbound;
    outbound.tag = "reused-interface";
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = device;
    config.outbounds = std::vector<Outbound>{std::move(outbound)};
    return config;
}

std::string staged_json(const Config& config) {
    return nlohmann::json(config).dump();
}

struct NoexceptPublication {
    bool* called{nullptr};

    void operator()() noexcept { *called = true; }
};

struct ThrowingPublication {
    void operator()() {}
};

constexpr ConfigTerminalOperationIdentity bootstrap_candidate_identity()
    noexcept {
    return {
        ConfigTerminalOperationKind::candidate,
        71U,
        41U,
        42U};
}

ConfigCandidateEvidence bootstrap_candidate_evidence(
    RuntimeFirewallLifecycleTerminal terminal) {
    ConfigCandidateEvidence evidence;
    evidence.expected_identity = bootstrap_candidate_identity();
    evidence.exact_lease_owned = true;
    evidence.published_generation_current = true;
    evidence.terminal = std::move(terminal);
    evidence.exact_rollback_available = false;
    return evidence;
}

RuntimeFirewallLifecycleTerminal verified_bootstrap_candidate() {
    RuntimeFirewallLifecycleTerminal terminal;
    terminal.outcome =
        RuntimeFirewallLifecycleOutcome::verified_success;
    terminal.committed = true;
    terminal.commit_ambiguous = false;
    terminal.observed_config_identity =
        bootstrap_candidate_identity();
    return terminal;
}

template <typename Publication, typename = void>
struct CanCommitPreparedActive : std::false_type {};

template <typename Publication>
struct CanCommitPreparedActive<
    Publication,
    std::void_t<decltype(
        std::declval<ConfigStore&>().commit_prepared_active(
            std::declval<const PreparedActiveConfigCommit&>(),
            std::declval<Publication>()))>> : std::true_type {};

static_assert(CanCommitPreparedActive<NoexceptPublication>::value);
static_assert(!CanCommitPreparedActive<ThrowingPublication>::value);

template <typename Publication, typename = void>
struct CanCommitPreparedActiveRuntimeReload : std::false_type {};

template <typename Publication>
struct CanCommitPreparedActiveRuntimeReload<
    Publication,
    std::void_t<decltype(
        std::declval<ConfigStore&>()
            .commit_prepared_active_runtime_reload(
                std::declval<
                    const PreparedActiveRuntimeReloadCommit&>(),
                std::declval<Publication>()))>> : std::true_type {};

static_assert(
    CanCommitPreparedActiveRuntimeReload<NoexceptPublication>::value);
static_assert(
    !CanCommitPreparedActiveRuntimeReload<ThrowingPublication>::value);
static_assert(std::is_nothrow_swappable_v<Config>);

} // namespace

TEST_CASE("config generations use the no-throw ADL relocation swap") {
    auto left = config_named("swap-left");
    auto right = config_named("swap-right");
    left.api = ApiConfig{};
    left.api->listen = "127.0.0.1:12121";
    right.api = ApiConfig{};
    right.api->listen = "192.0.2.1:12121";
    const auto left_before = staged_json(left);
    const auto right_before = staged_json(right);

    using std::swap;
    swap(left, right);
    CHECK(staged_json(left) == right_before);
    CHECK(staged_json(right) == left_before);

    swap(left, left);
    CHECK(staged_json(left) == right_before);
}

TEST_CASE(
    "prepared active commit publishes and clears the matching staged draft") {
    constexpr std::uint32_t old_mark = 0x10000U;
    constexpr std::uint32_t new_mark = 0x90000U;
    const auto active =
        interface_config_named("prepared-old", "nwg-old");
    const auto candidate =
        interface_config_named("prepared-new", "nwg-new");
    const auto serialized = staged_json(candidate);
    ConfigStore store(active);
    store.replace_active(
        active,
        OutboundMarkMap{{"reused-interface", old_mark}});
    store.stage_config(candidate, serialized);

    const auto base = store.pin_active_snapshot();
    const auto prepared = ConfigStore::prepare_active_commit(
        base,
        candidate,
        OutboundMarkMap{{"reused-interface", new_mark}},
        serialized);
    bool published = false;

    CHECK(
        store.commit_prepared_active(
            prepared,
            NoexceptPublication{&published}) ==
        PreparedActiveConfigCommitResult::committed);
    CHECK(published);
    CHECK_FALSE(store.staged_cas_snapshot().has_value());
    const auto committed = store.pin_active_snapshot();
    CHECK(committed == prepared.candidate);
    CHECK(
        committed->config.outbounds->front().interface ==
        std::optional<std::string>{"nwg-new"});
    CHECK(committed->outbound_marks.at("reused-interface") == new_mark);
}

TEST_CASE(
    "stopped bootstrap orders worker proof before exact ConfigStore publication") {
    const auto active = config_named("bootstrap-active");
    const auto candidate = config_named("bootstrap-candidate");
    const auto serialized = staged_json(candidate);

    SUBCASE("pre-COMMIT rejection retains stopped base and draft") {
        ConfigStore store(active);
        store.stage_config(candidate, serialized);
        const auto base = store.pin_active_snapshot();
        const auto prepared = ConfigStore::prepare_active_commit(
            base, candidate, OutboundMarkMap{}, serialized);
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        terminal.previous_generation_certainly_retained = true;
        terminal.observed_config_identity =
            bootstrap_candidate_identity();
        bool commit_attempted = false;
        bool publication_called = false;

        const auto completion =
            complete_config_bootstrap_publication(
                bootstrap_candidate_evidence(std::move(terminal)),
                [&]() noexcept {
                    commit_attempted = true;
                    return store.commit_prepared_active(
                               prepared,
                               NoexceptPublication{&publication_called}) ==
                        PreparedActiveConfigCommitResult::committed;
                });

        CHECK_FALSE(commit_attempted);
        CHECK_FALSE(completion.commit_attempted);
        CHECK_FALSE(publication_called);
        CHECK_FALSE(completion.candidate_published);
        CHECK(completion.terminal_action ==
              ConfigBootstrapTerminalAction::restore_stopped);
        CHECK(store.pin_active_snapshot() == base);
        CHECK(store.staged_snapshot().has_value());
    }

    SUBCASE("verified candidate plus rejected CAS fails closed") {
        const auto replacement = config_named("bootstrap-replacement");
        ConfigStore store(active);
        store.stage_config(candidate, serialized);
        const auto base = store.pin_active_snapshot();
        const auto prepared = ConfigStore::prepare_active_commit(
            base, candidate, OutboundMarkMap{}, serialized);
        store.stage_config(replacement, staged_json(replacement));
        bool publication_called = false;
        auto cas_result =
            PreparedActiveConfigCommitResult::committed;

        const auto completion =
            complete_config_bootstrap_publication(
                bootstrap_candidate_evidence(
                    verified_bootstrap_candidate()),
                [&]() noexcept {
                    cas_result = store.commit_prepared_active(
                        prepared,
                        NoexceptPublication{&publication_called});
                    return cas_result ==
                        PreparedActiveConfigCommitResult::committed;
                });

        CHECK(completion.commit_attempted);
        CHECK(cas_result ==
              PreparedActiveConfigCommitResult::staged_mismatch);
        CHECK_FALSE(publication_called);
        CHECK_FALSE(completion.candidate_published);
        CHECK(completion.terminal.outcome ==
              RuntimeFirewallLifecycleOutcome::not_verified);
        CHECK_FALSE(
            completion.terminal.previous_generation_certainly_retained);
        CHECK(completion.terminal_action ==
              ConfigBootstrapTerminalAction::fail_closed);
        CHECK(store.pin_active_snapshot() == base);
        const auto staged = store.staged_snapshot();
        REQUIRE(staged.has_value());
        CHECK(staged->first.daemon->cache_dir ==
              "/tmp/bootstrap-replacement");
    }

    SUBCASE("verified candidate publishes candidate before running terminal") {
        ConfigStore store(active);
        store.stage_config(candidate, serialized);
        const auto base = store.pin_active_snapshot();
        const auto prepared = ConfigStore::prepare_active_commit(
            base, candidate, OutboundMarkMap{}, serialized);
        bool publication_called = false;

        const auto completion =
            complete_config_bootstrap_publication(
                bootstrap_candidate_evidence(
                    verified_bootstrap_candidate()),
                [&]() noexcept {
                    return store.commit_prepared_active(
                               prepared,
                               NoexceptPublication{&publication_called}) ==
                        PreparedActiveConfigCommitResult::committed;
                });

        CHECK(completion.commit_attempted);
        CHECK(publication_called);
        CHECK(completion.candidate_published);
        CHECK(completion.terminal_action ==
              ConfigBootstrapTerminalAction::keep_running);
        CHECK(store.pin_active_snapshot() == prepared.candidate);
        CHECK_FALSE(store.staged_snapshot().has_value());
    }
}

TEST_CASE("prepared active commit rejects exact base drift before publication") {
    const auto active = config_named("base-old");
    const auto candidate = config_named("base-candidate");
    const auto serialized = staged_json(candidate);
    ConfigStore store(active);
    store.stage_config(candidate, serialized);
    const auto prepared = ConfigStore::prepare_active_commit(
        store.pin_active_snapshot(),
        candidate,
        OutboundMarkMap{},
        serialized);

    const auto drifted = config_named("base-drifted");
    store.replace_active(drifted, OutboundMarkMap{});
    bool published = false;
    CHECK(
        store.commit_prepared_active(
            prepared,
            NoexceptPublication{&published}) ==
        PreparedActiveConfigCommitResult::base_mismatch);
    CHECK_FALSE(published);
    CHECK(store.staged_cas_snapshot().has_value());
    CHECK(store.active_config().daemon->cache_dir == "/tmp/base-drifted");
}

TEST_CASE(
    "prepared active commit rejects a different staged serialization") {
    const auto active = config_named("staged-old");
    const auto candidate = config_named("staged-candidate");
    const auto replacement_draft = config_named("staged-replacement");
    ConfigStore store(active);
    const auto base = store.pin_active_snapshot();
    const auto prepared = ConfigStore::prepare_active_commit(
        base,
        candidate,
        OutboundMarkMap{},
        staged_json(candidate));
    store.stage_config(replacement_draft, staged_json(replacement_draft));

    bool published = false;
    CHECK(
        store.commit_prepared_active(
            prepared,
            NoexceptPublication{&published}) ==
        PreparedActiveConfigCommitResult::staged_mismatch);
    CHECK_FALSE(published);
    const auto staged = store.staged_snapshot();
    REQUIRE(staged.has_value());
    CHECK(staged->first.daemon->cache_dir == "/tmp/staged-replacement");
    CHECK(store.pin_active_snapshot() == base);
}

TEST_CASE("prepared active commit preserves a pinned old active handle") {
    const auto active = config_named("pinned-prepared-old");
    const auto candidate = config_named("pinned-prepared-new");
    const auto serialized = staged_json(candidate);
    ConfigStore store(active);
    store.stage_config(candidate, serialized);
    const auto pinned_old = store.pin_active_snapshot();
    const auto prepared = ConfigStore::prepare_active_commit(
        pinned_old,
        candidate,
        OutboundMarkMap{},
        serialized);

    bool published = false;
    REQUIRE(
        store.commit_prepared_active(
            prepared,
            NoexceptPublication{&published}) ==
        PreparedActiveConfigCommitResult::committed);
    REQUIRE(published);
    CHECK(pinned_old != store.pin_active_snapshot());
    CHECK(
        pinned_old->config.daemon->cache_dir ==
        "/tmp/pinned-prepared-old");
    CHECK(
        store.active_config().daemon->cache_dir ==
        "/tmp/pinned-prepared-new");
}

TEST_CASE(
    "prepared runtime reload publishes exact base and preserves staged draft") {
    constexpr std::uint32_t old_mark = 0x10000U;
    constexpr std::uint32_t new_mark = 0x90000U;
    const auto active =
        interface_config_named("reload-old", "nwg-old");
    const auto candidate =
        interface_config_named("reload-new", "nwg-new");
    const auto draft = config_named("reload-draft");
    const auto draft_serialized = staged_json(draft);
    ConfigStore store(active);
    store.replace_active(
        active,
        OutboundMarkMap{{"reused-interface", old_mark}});
    const auto base = store.pin_active_snapshot();
    store.stage_config(draft, draft_serialized);
    const auto staged_before = store.staged_cas_snapshot();
    REQUIRE(staged_before.has_value());

    const auto prepared =
        ConfigStore::prepare_active_runtime_reload_commit(
            base,
            candidate,
            OutboundMarkMap{{"reused-interface", new_mark}});
    bool published = false;
    REQUIRE(
        store.commit_prepared_active_runtime_reload(
            prepared,
            NoexceptPublication{&published}) ==
        PreparedActiveRuntimeReloadCommitResult::committed);

    CHECK(published);
    CHECK(store.pin_active_snapshot() == prepared.candidate);
    CHECK(base != store.pin_active_snapshot());
    CHECK(
        base->config.outbounds->front().interface ==
        std::optional<std::string>{"nwg-old"});
    const auto committed = store.pin_active_snapshot();
    CHECK(
        committed->config.outbounds->front().interface ==
        std::optional<std::string>{"nwg-new"});
    CHECK(committed->outbound_marks.at("reused-interface") == new_mark);

    const auto staged_after = store.staged_cas_snapshot();
    REQUIRE(staged_after.has_value());
    CHECK(staged_after->config.daemon->cache_dir == "/tmp/reload-draft");
    CHECK(staged_after->serialized == draft_serialized);
    CHECK(staged_after->base_revision == staged_before->base_revision);
    CHECK(staged_after->active_revision != staged_before->active_revision);
}

TEST_CASE(
    "prepared runtime reload rejects base drift without publishing or touching draft") {
    const auto active = config_named("reload-base-old");
    const auto candidate = config_named("reload-base-candidate");
    const auto drifted = config_named("reload-base-drifted");
    const auto draft = config_named("reload-base-draft");
    const auto draft_serialized = staged_json(draft);
    ConfigStore store(active);
    const auto prepared =
        ConfigStore::prepare_active_runtime_reload_commit(
            store.pin_active_snapshot(),
            candidate,
            OutboundMarkMap{});
    store.stage_config(draft, draft_serialized);
    const auto staged_before = store.staged_cas_snapshot();
    REQUIRE(staged_before.has_value());
    store.replace_active(drifted, OutboundMarkMap{});

    bool published = false;
    CHECK(
        store.commit_prepared_active_runtime_reload(
            prepared,
            NoexceptPublication{&published}) ==
        PreparedActiveRuntimeReloadCommitResult::base_mismatch);
    CHECK_FALSE(published);
    CHECK(
        store.active_config().daemon->cache_dir ==
        "/tmp/reload-base-drifted");
    const auto staged_after = store.staged_cas_snapshot();
    REQUIRE(staged_after.has_value());
    CHECK(
        staged_after->config.daemon->cache_dir ==
        "/tmp/reload-base-draft");
    CHECK(staged_after->serialized == draft_serialized);
    CHECK(staged_after->base_revision == staged_before->base_revision);
}

TEST_CASE(
    "prepared runtime reload rejects missing handles without publication") {
    ConfigStore store(config_named("reload-invalid"));
    bool published = false;
    CHECK(
        store.commit_prepared_active_runtime_reload(
            PreparedActiveRuntimeReloadCommit{},
            NoexceptPublication{&published}) ==
        PreparedActiveRuntimeReloadCommitResult::base_mismatch);
    CHECK_FALSE(published);
    CHECK(
        store.active_config().daemon->cache_dir ==
        "/tmp/reload-invalid");
}

TEST_CASE("config store visible snapshot identifies active and draft states") {
    const auto active = config_named("active");
    ConfigStore store(active);

    const auto active_snapshot = store.visible_snapshot();
    CHECK_FALSE(active_snapshot.is_draft);
    CHECK(active_snapshot.config.daemon->cache_dir == "/tmp/active");
    CHECK(active_snapshot.revision.size() == 64U);
    CHECK(
        active_snapshot.revision ==
        store.visible_snapshot().revision);

    const auto draft = config_named("draft");
    store.stage_config(draft, staged_json(draft));
    const auto draft_snapshot = store.visible_snapshot();
    CHECK(draft_snapshot.is_draft);
    CHECK(draft_snapshot.config.daemon->cache_dir == "/tmp/draft");
    CHECK(draft_snapshot.revision.size() == 64U);
    CHECK(draft_snapshot.revision != active_snapshot.revision);

    const auto staged = store.staged_cas_snapshot();
    REQUIRE(staged.has_value());
    CHECK(staged->base_revision == active_snapshot.revision);
    CHECK(staged->active_revision == active_snapshot.revision);

    const auto reloaded = config_named("reloaded");
    store.replace_active(
        reloaded,
        allocate_outbound_marks(
            reloaded.fwmark.value_or(FwmarkConfig{}),
            reloaded.outbounds.value_or(
                std::vector<Outbound>{})));
    const auto stale = store.staged_cas_snapshot();
    REQUIRE(stale.has_value());
    CHECK(stale->base_revision == active_snapshot.revision);
    CHECK(stale->active_revision != stale->base_revision);
    CHECK(store.visible_config().daemon->cache_dir == "/tmp/draft");
}

TEST_CASE("config store snapshots active and staged dependency views together") {
    const auto active =
        interface_config_named("active", "nwg5");
    ConfigStore store(active);

    const auto project = [](const Config& current,
                            const std::optional<Config>& staged) {
        return std::pair{
            current.outbounds->front().interface.value_or(""),
            staged && staged->outbounds
                ? staged->outbounds->front().interface
                      .value_or("")
                : std::string{},
        };
    };
    const auto without_draft =
        store.project_active_and_staged(project);
    CHECK(without_draft.first == "nwg5");
    CHECK(without_draft.second.empty());

    const auto draft =
        interface_config_named("draft", "nwg6");
    store.stage_config(draft, staged_json(draft));
    const auto with_draft = store.project_active_and_staged(project);
    CHECK(with_draft.first == "nwg5");
    CHECK(with_draft.second == "nwg6");
}

TEST_CASE(
    "config store compare-and-stage rejects stale state without mutation") {
    const auto active = config_named("active");
    ConfigStore store(active);
    const std::string stale_revision =
        store.visible_snapshot().revision;

    const auto reloaded = config_named("reloaded");
    store.replace_active(
        reloaded,
        allocate_outbound_marks(
            reloaded.fwmark.value_or(FwmarkConfig{}),
            reloaded.outbounds.value_or(
                std::vector<Outbound>{})));

    const auto candidate = config_named("candidate");
    CHECK_FALSE(store.stage_config_if_visible_revision(
        stale_revision,
        candidate,
        staged_json(candidate)));
    CHECK_FALSE(store.staged_cas_snapshot().has_value());
    CHECK(
        store.active_config().daemon->cache_dir ==
        "/tmp/reloaded");
}

TEST_CASE(
    "config store compare-and-stage preserves the original draft base") {
    const auto active = config_named("active");
    ConfigStore store(active);
    const std::string active_revision =
        store.visible_snapshot().revision;

    const auto first_draft = config_named("first-draft");
    REQUIRE(store.stage_config_if_visible_revision(
        active_revision,
        first_draft,
        staged_json(first_draft)));
    const std::string first_draft_revision =
        store.visible_snapshot().revision;

    const auto reloaded = config_named("reloaded");
    store.replace_active(
        reloaded,
        allocate_outbound_marks(
            reloaded.fwmark.value_or(FwmarkConfig{}),
            reloaded.outbounds.value_or(
                std::vector<Outbound>{})));

    const auto second_draft = config_named("second-draft");
    REQUIRE(store.stage_config_if_visible_revision(
        first_draft_revision,
        second_draft,
        staged_json(second_draft)));

    const auto staged = store.staged_cas_snapshot();
    REQUIRE(staged.has_value());
    CHECK(staged->base_revision == active_revision);
    CHECK(staged->active_revision != staged->base_revision);
    CHECK(
        staged->config.daemon->cache_dir ==
        "/tmp/second-draft");
}

TEST_CASE("active snapshot keeps a reused interface tag and mark generation together") {
    constexpr std::uint32_t old_mark = 0x10000U;
    constexpr std::uint32_t new_mark = 0x90000U;
    const auto old_config =
        interface_config_named("old-interface", "nwg-old");
    const auto new_config =
        interface_config_named("new-interface", "nwg-new");
    ConfigStore store(old_config);
    store.replace_active(
        old_config,
        OutboundMarkMap{{"reused-interface", old_mark}});

    // This deliberately models the old two-read API shape: an apply can land
    // between reads and pair the old device identity with the new mark.
    const auto independently_read_config = store.active_config();
    store.replace_active(
        new_config,
        OutboundMarkMap{{"reused-interface", new_mark}});
    const auto independently_read_marks = store.outbound_marks();
    REQUIRE(independently_read_config.outbounds.has_value());
    REQUIRE(independently_read_config.outbounds->front().interface.has_value());
    CHECK(*independently_read_config.outbounds->front().interface ==
          "nwg-old");
    CHECK(independently_read_marks.at("reused-interface") == new_mark);

    // The production probe readers now use this one locked generation.
    const auto active = store.pin_active_snapshot();
    REQUIRE(active->config.outbounds.has_value());
    REQUIRE(active->config.outbounds->front().interface.has_value());
    CHECK(*active->config.outbounds->front().interface == "nwg-new");
    CHECK(active->outbound_marks.at("reused-interface") == new_mark);
}

TEST_CASE("pinned active snapshot remains valid after a replacement") {
    constexpr std::uint32_t old_mark = 0x10000U;
    constexpr std::uint32_t new_mark = 0x90000U;
    const auto old_config =
        interface_config_named("old-generation", "nwg-old");
    const auto new_config =
        interface_config_named("new-generation", "nwg-new");
    ConfigStore store(old_config);
    store.replace_active(
        old_config,
        OutboundMarkMap{{"reused-interface", old_mark}});

    const auto pinned_old = store.pin_active_snapshot();
    store.replace_active(
        new_config,
        OutboundMarkMap{{"reused-interface", new_mark}});
    const auto pinned_new = store.pin_active_snapshot();

    REQUIRE(pinned_old != pinned_new);
    REQUIRE(pinned_old->config.outbounds.has_value());
    REQUIRE(pinned_new->config.outbounds.has_value());
    CHECK(
        pinned_old->config.outbounds->front().interface ==
        std::optional<std::string>{"nwg-old"});
    CHECK(
        pinned_new->config.outbounds->front().interface ==
        std::optional<std::string>{"nwg-new"});
    CHECK(
        pinned_old->outbound_marks.at("reused-interface") ==
        old_mark);
    CHECK(
        pinned_new->outbound_marks.at("reused-interface") ==
        new_mark);
}

TEST_CASE(
    "concurrent active snapshot pins never mix config and mark generations") {
    constexpr std::uint32_t left_mark = 0x10000U;
    constexpr std::uint32_t right_mark = 0x90000U;
    const auto left_config =
        interface_config_named("left-generation", "nwg-left");
    const auto right_config =
        interface_config_named("right-generation", "nwg-right");
    ConfigStore store(left_config);
    store.replace_active(
        left_config,
        OutboundMarkMap{{"reused-interface", left_mark}});

    std::atomic<bool> stop{false};
    std::atomic<bool> incoherent{false};
    std::atomic<std::size_t> observations{0U};
    std::promise<void> first_ready_signal;
    std::promise<void> second_ready_signal;
    auto first_ready = first_ready_signal.get_future();
    auto second_ready = second_ready_signal.get_future();
    std::promise<void> start_signal;
    const auto start = start_signal.get_future().share();
    std::promise<void> first_observation_signal;
    auto first_observation = first_observation_signal.get_future();
    std::once_flag first_observation_once;

    const auto reader = [&](std::promise<void>& ready_signal) {
        ready_signal.set_value();
        start.wait();
        while (!stop.load(std::memory_order_acquire)) {
            const auto snapshot = store.pin_active_snapshot();
            if (!snapshot->config.outbounds.has_value() ||
                snapshot->config.outbounds->empty()) {
                incoherent.store(true, std::memory_order_release);
                continue;
            }
            const auto& outbound = snapshot->config.outbounds->front();
            const auto mark =
                snapshot->outbound_marks.find("reused-interface");
            const bool is_left =
                outbound.interface ==
                    std::optional<std::string>{"nwg-left"} &&
                mark != snapshot->outbound_marks.end() &&
                mark->second == left_mark;
            const bool is_right =
                outbound.interface ==
                    std::optional<std::string>{"nwg-right"} &&
                mark != snapshot->outbound_marks.end() &&
                mark->second == right_mark;
            if (!is_left && !is_right) {
                incoherent.store(true, std::memory_order_release);
            }
            observations.fetch_add(1U, std::memory_order_relaxed);
            std::call_once(first_observation_once, [&]() {
                first_observation_signal.set_value();
            });
        }
    };

    std::thread first_reader(reader, std::ref(first_ready_signal));
    std::thread second_reader(reader, std::ref(second_ready_signal));
    constexpr auto wait_budget = std::chrono::seconds{5};
    const auto first_ready_status = first_ready.wait_for(wait_budget);
    const auto second_ready_status = second_ready.wait_for(wait_budget);
    start_signal.set_value();
    for (std::size_t index = 0; index < 2000U; ++index) {
        if (index % 2U == 0U) {
            store.replace_active(
                right_config,
                OutboundMarkMap{{"reused-interface", right_mark}});
        } else {
            store.replace_active(
                left_config,
                OutboundMarkMap{{"reused-interface", left_mark}});
        }
    }
    const auto observation_status =
        first_observation.wait_for(wait_budget);
    stop.store(true, std::memory_order_release);
    first_reader.join();
    second_reader.join();

    CHECK(first_ready_status == std::future_status::ready);
    CHECK(second_ready_status == std::future_status::ready);
    CHECK(observation_status == std::future_status::ready);
    CHECK(observations.load(std::memory_order_relaxed) > 0U);
    CHECK_FALSE(incoherent.load(std::memory_order_acquire));
}

} // namespace keen_pbr3
