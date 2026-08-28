#include "config_store.hpp"

#include "../config/config.hpp"
#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

std::string config_revision(const Config& config) {
    return Sha256::hex(nlohmann::json(config).dump());
}

} // namespace

ConfigStore::ConfigStore(Config active_config) {
    auto outbound_marks = allocate_outbound_marks(
        active_config.fwmark.value_or(FwmarkConfig{}),
        active_config.outbounds.value_or(std::vector<Outbound>{}));
    active_snapshot_ = std::make_shared<const ActiveConfigSnapshot>(
        ActiveConfigSnapshot{
            std::move(active_config),
            std::move(outbound_marks),
        });
}

ActiveConfigSnapshotHandle ConfigStore::pin_active_snapshot() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return active_snapshot_;
}

ActiveConfigSnapshot ConfigStore::active_snapshot() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return *active_snapshot_;
}

Config ConfigStore::active_config() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return active_snapshot_->config;
}

OutboundMarkMap ConfigStore::outbound_marks() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return active_snapshot_->outbound_marks;
}

Config ConfigStore::visible_config() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return staged_config_.has_value()
        ? *staged_config_
        : active_snapshot_->config;
}

VisibleConfigSnapshot ConfigStore::visible_snapshot() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    const bool is_draft = staged_config_.has_value();
    const auto& visible =
        is_draft ? *staged_config_ : active_snapshot_->config;
    return VisibleConfigSnapshot{
        visible,
        is_draft,
        config_revision(visible),
    };
}

bool ConfigStore::config_is_draft() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return staged_config_.has_value();
}

void ConfigStore::replace_active(Config active_config, OutboundMarkMap outbound_marks) {
    auto replacement = std::make_shared<const ActiveConfigSnapshot>(
        ActiveConfigSnapshot{
            std::move(active_config),
            std::move(outbound_marks),
        });
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    active_snapshot_ = std::move(replacement);
}

PreparedActiveConfigCommit ConfigStore::prepare_active_commit(
    ActiveConfigSnapshotHandle base,
    Config candidate_config,
    OutboundMarkMap candidate_outbound_marks,
    std::string staged_serialized) {
    auto candidate = std::make_shared<const ActiveConfigSnapshot>(
        ActiveConfigSnapshot{
            std::move(candidate_config),
            std::move(candidate_outbound_marks),
        });
    return PreparedActiveConfigCommit{
        std::move(base),
        std::move(candidate),
        std::move(staged_serialized),
    };
}

void ConfigStore::stage_config(Config staged_config, std::string staged_config_json) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    staged_config_ = std::move(staged_config);
    staged_config_json_ = std::move(staged_config_json);
    staged_base_revision_ = config_revision(active_snapshot_->config);
}

bool ConfigStore::stage_config_if_visible_revision(
    const std::string& expected_visible_revision,
    Config staged_config,
    std::string staged_config_json) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    const bool replacing_draft = staged_config_.has_value();
    const Config& visible =
        replacing_draft ? *staged_config_ : active_snapshot_->config;
    if (config_revision(visible) != expected_visible_revision) {
        return false;
    }

    staged_config_ = std::move(staged_config);
    staged_config_json_ = std::move(staged_config_json);
    // Editing an existing draft must not launder its original active base.
    // Config save still has to reject the draft if active config changed
    // after the first staging operation.
    if (!replacing_draft || !staged_base_revision_.has_value()) {
        staged_base_revision_ =
            config_revision(active_snapshot_->config);
    }
    return true;
}

std::optional<std::pair<Config, std::string>> ConfigStore::staged_snapshot() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    if (!staged_config_.has_value() || !staged_config_json_.has_value()) {
        return std::nullopt;
    }
    return std::make_optional(std::make_pair(*staged_config_, *staged_config_json_));
}

std::optional<StagedConfigSnapshot> ConfigStore::staged_cas_snapshot() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    if (!staged_config_.has_value() ||
        !staged_config_json_.has_value() ||
        !staged_base_revision_.has_value()) {
        return std::nullopt;
    }
    return StagedConfigSnapshot{
        *staged_config_,
        *staged_config_json_,
        *staged_base_revision_,
        config_revision(active_snapshot_->config),
    };
}

void ConfigStore::clear_staged() {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    staged_config_.reset();
    staged_config_json_.reset();
    staged_base_revision_.reset();
}

void ConfigStore::clear_staged_if_matches(const std::string& staged_config_json) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    if (staged_config_json_.has_value() && *staged_config_json_ == staged_config_json) {
        staged_config_.reset();
        staged_config_json_.reset();
        staged_base_revision_.reset();
    }
}

} // namespace keen_pbr3
