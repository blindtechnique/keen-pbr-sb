#pragma once

#include "../config/config.hpp"
#include "../util/traced_mutex.hpp"

#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace keen_pbr3 {

struct ActiveConfigSnapshot {
    Config config;
    OutboundMarkMap outbound_marks;
};

using ActiveConfigSnapshotHandle =
    std::shared_ptr<const ActiveConfigSnapshot>;

struct VisibleConfigSnapshot {
    Config config;
    bool is_draft{false};
    std::string revision;
};

struct StagedConfigSnapshot {
    Config config;
    std::string serialized;
    std::string base_revision;
    std::string active_revision;
};

class ConfigStore {
public:
    explicit ConfigStore(Config active_config = {});

    ActiveConfigSnapshotHandle pin_active_snapshot() const;
    ActiveConfigSnapshot active_snapshot() const;
    Config active_config() const;
    OutboundMarkMap outbound_marks() const;
    Config visible_config() const;
    VisibleConfigSnapshot visible_snapshot() const;

    // Runs one narrow projection while both active config and the optional
    // panel draft are protected by the same shared lock. The callback must
    // return owned data and must not retain either reference. This avoids a
    // torn two-read delete decision without copying unrelated multi-megabyte
    // lists, URLs or other configuration into the native mutation boundary.
    template <typename Projection>
    auto project_active_and_staged(Projection&& projection) const
        -> decltype(std::forward<Projection>(projection)(
            std::declval<const Config&>(),
            std::declval<const std::optional<Config>&>())) {
        KPBR_SHARED_LOCK(lock, mutex_);
        return std::forward<Projection>(projection)(
            active_snapshot_->config, staged_config_);
    }
    bool config_is_draft() const;

    void replace_active(Config active_config, OutboundMarkMap outbound_marks);
    void stage_config(Config staged_config, std::string staged_config_json);
    bool stage_config_if_visible_revision(
        const std::string& expected_visible_revision,
        Config staged_config,
        std::string staged_config_json);
    std::optional<std::pair<Config, std::string>> staged_snapshot() const;
    std::optional<StagedConfigSnapshot> staged_cas_snapshot() const;
    void clear_staged();
    void clear_staged_if_matches(const std::string& staged_config_json);

private:
    mutable TracedSharedMutex mutex_;
    ActiveConfigSnapshotHandle active_snapshot_ GUARDED_BY(mutex_);
    std::optional<Config> staged_config_ GUARDED_BY(mutex_);
    std::optional<std::string> staged_config_json_ GUARDED_BY(mutex_);
    std::optional<std::string> staged_base_revision_ GUARDED_BY(mutex_);
};

} // namespace keen_pbr3
