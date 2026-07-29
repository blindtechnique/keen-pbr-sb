#pragma once

#include "../config/config.hpp"
#include "../util/traced_mutex.hpp"

#include <optional>
#include <string>
#include <utility>

namespace keen_pbr3 {

struct ActiveConfigSnapshot {
    Config config;
    OutboundMarkMap outbound_marks;
};

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

    ActiveConfigSnapshot active_snapshot() const;
    Config active_config() const;
    OutboundMarkMap outbound_marks() const;
    Config visible_config() const;
    VisibleConfigSnapshot visible_snapshot() const;
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
    Config active_config_ GUARDED_BY(mutex_);
    OutboundMarkMap active_outbound_marks_ GUARDED_BY(mutex_);
    std::optional<Config> staged_config_ GUARDED_BY(mutex_);
    std::optional<std::string> staged_config_json_ GUARDED_BY(mutex_);
    std::optional<std::string> staged_base_revision_ GUARDED_BY(mutex_);
};

} // namespace keen_pbr3
