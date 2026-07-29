#include <doctest/doctest.h>

#include "../src/daemon/config_store.hpp"

#include <string>

namespace keen_pbr3 {
namespace {

Config config_named(const std::string& name) {
    Config config;
    config.daemon = DaemonConfig{};
    config.daemon->cache_dir = "/tmp/" + name;
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

} // namespace keen_pbr3
