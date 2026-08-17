#include <doctest/doctest.h>

#include "../src/daemon/config_store.hpp"

#include <cstdint>
#include <string>
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

} // namespace

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
    const auto active = store.active_snapshot();
    REQUIRE(active.config.outbounds.has_value());
    REQUIRE(active.config.outbounds->front().interface.has_value());
    CHECK(*active.config.outbounds->front().interface == "nwg-new");
    CHECK(active.outbound_marks.at("reused-interface") == new_mark);
}

} // namespace keen_pbr3
