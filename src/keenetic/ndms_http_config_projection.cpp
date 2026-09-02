#include "ndms_http_config_projection.hpp"

#include <nlohmann/json.hpp>
#include <utility>

namespace keen_pbr3 {
namespace {

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : &value[0];
    for (std::size_t offset = 0; offset < value.size(); ++offset) {
        bytes[offset] = 0;
    }
    value.clear();
}

void wipe_json_strings(nlohmann::json& value) noexcept {
    try {
        if (value.is_string()) {
            auto& text = value.get_ref<std::string&>();
            secure_wipe(text);
        } else if (value.is_array()) {
            for (auto& child : value) wipe_json_strings(child);
        } else if (value.is_object()) {
            for (auto& item : value.items()) {
                wipe_json_strings(item.value());
            }
        }
    } catch (...) {
    }
}

class JsonWipeGuard final {
public:
    explicit JsonWipeGuard(nlohmann::json& value) : value_(value) {}
    ~JsonWipeGuard() { wipe_json_strings(value_); }

private:
    nlohmann::json& value_;
};

nlohmann::json parse_document(std::string_view body) {
    return nlohmann::json::parse(body.begin(), body.end());
}

} // namespace

NdmsHttpServiceConfigCache::NdmsHttpServiceConfigCache(
    FetchFn fetch_fn,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : owned_resource_(std::make_unique<NdmsHttpConfigResource>(
          std::move(fetch_fn), cache_ttl, failure_retry,
          std::move(now_fn))),
      resource_(owned_resource_.get()) {}

NdmsHttpServiceConfigCache::NdmsHttpServiceConfigCache(
    NdmsHttpConfigResource& resource)
    : resource_(&resource) {}

NdmsHttpServiceConfigSnapshot
NdmsHttpServiceConfigCache::snapshot_locked(
    const NdmsHttpConfigSnapshot& raw,
    bool refreshed,
    bool changed) const {
    if (!config_) {
        return {
            std::nullopt,
            NdmsCatalogCacheStatus::unavailable,
            false,
            false,
            std::nullopt,
            0U,
            0U,
            0U,
            raw.invalidation_epoch,
        };
    }
    const bool exact_generation =
        source_content_generation_ == raw.content_generation;
    auto status = exact_generation
        ? raw.status
        : NdmsCatalogCacheStatus::stale;
    if (raw.status == NdmsCatalogCacheStatus::unavailable) {
        status = NdmsCatalogCacheStatus::stale;
    }
    return {
        config_,
        status,
        refreshed && exact_generation,
        changed && exact_generation,
        exact_generation ? raw.observed_at : source_observed_at_,
        source_content_generation_,
        exact_generation
            ? raw.observation_generation
            : source_observation_generation_,
        exact_generation ? raw.observation_epoch : source_observation_epoch_,
        raw.invalidation_epoch,
    };
}

NdmsHttpServiceConfigSnapshot NdmsHttpServiceConfigCache::project(
    const NdmsHttpConfigSnapshot& raw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_ && source_content_generation_ == raw.content_generation) {
        source_observed_at_ = raw.observed_at;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
        return snapshot_locked(raw, raw.refreshed, false);
    }

    std::optional<NdmsHttpServiceConfig> parsed;
    if (raw.document && raw.content_generation != 0U &&
        attempted_content_generation_ != raw.content_generation) {
        attempted_content_generation_ = raw.content_generation;
        try {
            auto document = parse_document(raw.document->body());
            JsonWipeGuard wipe(document);
            parsed = parse_ndms_http_service_config(document);
        } catch (const std::bad_alloc&) {
            attempted_content_generation_ = 0U;
            throw;
        } catch (...) {
            // Keep the exact typed LKG and memoize this unusable raw
            // generation instead of reparsing it on every cache-only read.
        }
    }

    bool changed = false;
    if (parsed &&
        (!config_ || raw.content_generation >= source_content_generation_)) {
        changed = raw.content_generation != source_content_generation_;
        config_ = *parsed;
        source_observed_at_ = raw.observed_at;
        source_content_generation_ = raw.content_generation;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
    }
    return snapshot_locked(
        raw, raw.refreshed && parsed.has_value(), changed);
}

NdmsHttpServiceConfigSnapshot NdmsHttpServiceConfigCache::get() {
    return project(resource_->get());
}

NdmsHttpServiceConfigSnapshot
NdmsHttpServiceConfigCache::force_refresh() {
    return project(resource_->force_refresh());
}

NdmsHttpServiceConfigSnapshot NdmsHttpServiceConfigCache::peek() const {
    return project(resource_->peek());
}

void NdmsHttpServiceConfigCache::invalidate() {
    resource_->invalidate();
}

NdmsLockoutPolicyCache::NdmsLockoutPolicyCache(
    FetchFn fetch_fn,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : owned_resource_(std::make_unique<NdmsHttpConfigResource>(
          std::move(fetch_fn), cache_ttl, failure_retry,
          std::move(now_fn))),
      resource_(owned_resource_.get()) {}

NdmsLockoutPolicyCache::NdmsLockoutPolicyCache(
    NdmsHttpConfigResource& resource)
    : resource_(&resource) {}

NdmsLockoutPolicySnapshot NdmsLockoutPolicyCache::snapshot_locked(
    const NdmsHttpConfigSnapshot& raw,
    bool refreshed,
    bool changed) const {
    if (!has_projection_) {
        return {
            std::nullopt,
            NdmsCatalogCacheStatus::unavailable,
            false,
            false,
            std::nullopt,
            0U,
            0U,
            0U,
            raw.invalidation_epoch,
        };
    }
    const bool exact_generation =
        source_content_generation_ == raw.content_generation;
    auto status = exact_generation
        ? raw.status
        : NdmsCatalogCacheStatus::stale;
    if (raw.status == NdmsCatalogCacheStatus::unavailable) {
        status = NdmsCatalogCacheStatus::stale;
    }
    return {
        policy_,
        status,
        refreshed && exact_generation,
        changed && exact_generation,
        exact_generation ? raw.observed_at : source_observed_at_,
        source_content_generation_,
        exact_generation
            ? raw.observation_generation
            : source_observation_generation_,
        exact_generation ? raw.observation_epoch : source_observation_epoch_,
        raw.invalidation_epoch,
    };
}

NdmsLockoutPolicySnapshot NdmsLockoutPolicyCache::project(
    const NdmsHttpConfigSnapshot& raw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (has_projection_ &&
        source_content_generation_ == raw.content_generation) {
        source_observed_at_ = raw.observed_at;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
        return snapshot_locked(raw, raw.refreshed, false);
    }

    bool parsed_generation = false;
    std::optional<NdmsLockoutPolicy> parsed_policy;
    if (raw.document && raw.content_generation != 0U &&
        attempted_content_generation_ != raw.content_generation) {
        attempted_content_generation_ = raw.content_generation;
        try {
            auto document = parse_document(raw.document->body());
            JsonWipeGuard wipe(document);
            parsed_policy = parse_ndms_lockout_policy(document);
            parsed_generation = true;
        } catch (const std::bad_alloc&) {
            attempted_content_generation_ = 0U;
            throw;
        } catch (...) {
            // The raw owner validated this generation. Preserve LKG only for
            // exceptional parse failures; a normal nullopt policy is accepted
            // below as the current fail-closed typed result.
        }
    }

    bool changed = false;
    if (parsed_generation &&
        (!has_projection_ ||
         raw.content_generation >= source_content_generation_)) {
        changed = raw.content_generation != source_content_generation_;
        policy_ = std::move(parsed_policy);
        has_projection_ = true;
        source_observed_at_ = raw.observed_at;
        source_content_generation_ = raw.content_generation;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
    }
    return snapshot_locked(
        raw, raw.refreshed && parsed_generation, changed);
}

NdmsLockoutPolicySnapshot NdmsLockoutPolicyCache::get() {
    return project(resource_->get());
}

NdmsLockoutPolicySnapshot NdmsLockoutPolicyCache::force_refresh() {
    return project(resource_->force_refresh());
}

NdmsLockoutPolicySnapshot NdmsLockoutPolicyCache::peek() const {
    return project(resource_->peek());
}

void NdmsLockoutPolicyCache::invalidate() {
    resource_->invalidate();
}

} // namespace keen_pbr3
