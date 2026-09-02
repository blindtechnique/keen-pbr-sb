#include "ndms_version_projection.hpp"

#include <nlohmann/json.hpp>
#include <utility>

namespace keen_pbr3 {
namespace {

std::string trim(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1U);
}

std::string string_field(const nlohmann::json& object, const char* key) {
    const auto field = object.find(key);
    if (field == object.end() || !field->is_string()) return {};
    return trim(field->get<std::string>());
}

std::optional<NdmsRouterVersionFacts> parse_facts(std::string_view body) {
    const auto document = nlohmann::json::parse(body.begin(), body.end());
    if (!document.is_object()) return std::nullopt;
    const auto ndm = document.find("ndm");
    const bool has_ndm = ndm != document.end() && ndm->is_object();
    const bool authoritative =
        (document.contains("model") && document.at("model").is_string()) ||
        (document.contains("vendor") && document.at("vendor").is_string()) ||
        (document.contains("release") &&
         document.at("release").is_string()) ||
        (document.contains("title") && document.at("title").is_string()) ||
        (document.contains("arch") && document.at("arch").is_string()) ||
        has_ndm;
    if (!authoritative) return std::nullopt;

    NdmsRouterVersionFacts facts;
    facts.model = string_field(document, "model");
    facts.vendor = string_field(document, "vendor");
    facts.hw_id = string_field(document, "hw_id");
    facts.region = string_field(document, "region");
    facts.arch = string_field(document, "arch");
    facts.title = string_field(document, "title");
    facts.release = string_field(document, "release");
    facts.sandbox = string_field(document, "sandbox");
    if (has_ndm) facts.firmware_date = string_field(*ndm, "cdate");
    return facts;
}

struct FirmwareProjection {
    bool valid{false};
    std::optional<std::string> version;
};

FirmwareProjection parse_firmware(std::string_view body) {
    auto legacy = trim(std::string(body));
    if (legacy.empty()) return {};
    if (legacy.front() != '{' && legacy.front() != '[') {
        if (legacy.size() >= 2U &&
            legacy.front() == '"' && legacy.back() == '"') {
            legacy = legacy.substr(1U, legacy.size() - 2U);
        }
        return {!legacy.empty(), legacy.empty()
                                     ? std::nullopt
                                     : std::optional<std::string>(
                                           std::move(legacy))};
    }
    try {
        const auto document = nlohmann::json::parse(body.begin(), body.end());
        if (!document.is_object()) return {};
        for (const char* key : {"title", "release", "version"}) {
            auto version = string_field(document, key);
            if (!version.empty()) return {true, std::move(version)};
        }
        return {true, std::nullopt};
    } catch (...) {
        return {};
    }
}

template <typename Snapshot>
NdmsCatalogCacheStatus projected_status(
    const Snapshot& raw, std::uint64_t source_generation) {
    if (raw.status == NdmsCatalogCacheStatus::unavailable ||
        source_generation != raw.content_generation) {
        return NdmsCatalogCacheStatus::stale;
    }
    return raw.status;
}

} // namespace

NdmsRouterVersionFactsCache::NdmsRouterVersionFactsCache(
    FetchFn fetch_fn, Clock::duration cache_ttl,
    Clock::duration failure_retry, NowFn now_fn)
    : owned_resource_(std::make_unique<NdmsVersionResource>(
          std::move(fetch_fn), cache_ttl, failure_retry,
          std::move(now_fn))),
      resource_(owned_resource_.get()) {}

NdmsRouterVersionFactsCache::NdmsRouterVersionFactsCache(
    NdmsVersionResource& resource)
    : resource_(&resource) {}

NdmsRouterVersionFactsSnapshot
NdmsRouterVersionFactsCache::snapshot_locked(
    const NdmsVersionSnapshot& raw, bool refreshed, bool changed) const {
    if (!facts_) {
        return {std::nullopt, NdmsCatalogCacheStatus::unavailable,
                false, false, std::nullopt, 0U, 0U, 0U,
                raw.invalidation_epoch};
    }
    const bool exact = source_content_generation_ == raw.content_generation;
    return {facts_, projected_status(raw, source_content_generation_),
            refreshed && exact, changed && exact,
            exact ? raw.observed_at : source_observed_at_,
            source_content_generation_,
            exact ? raw.observation_generation
                  : source_observation_generation_,
            exact ? raw.observation_epoch : source_observation_epoch_,
            raw.invalidation_epoch};
}

NdmsRouterVersionFactsSnapshot NdmsRouterVersionFactsCache::project(
    const NdmsVersionSnapshot& raw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (facts_ && source_content_generation_ == raw.content_generation) {
        source_observed_at_ = raw.observed_at;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
        return snapshot_locked(raw, raw.refreshed, false);
    }

    std::optional<NdmsRouterVersionFacts> parsed;
    if (raw.document && raw.content_generation != 0U &&
        attempted_content_generation_ != raw.content_generation) {
        attempted_content_generation_ = raw.content_generation;
        try {
            parsed = parse_facts(raw.document->body());
        } catch (const std::bad_alloc&) {
            attempted_content_generation_ = 0U;
            throw;
        } catch (...) {
        }
    }

    bool changed = false;
    if (parsed &&
        (!facts_ || raw.content_generation >= source_content_generation_)) {
        changed = !facts_ ||
                  raw.content_generation != source_content_generation_;
        facts_ = std::move(parsed);
        source_observed_at_ = raw.observed_at;
        source_content_generation_ = raw.content_generation;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
    }
    return snapshot_locked(raw, raw.refreshed && parsed.has_value(), changed);
}

NdmsRouterVersionFactsSnapshot NdmsRouterVersionFactsCache::get() {
    return project(resource_->get());
}
NdmsRouterVersionFactsSnapshot NdmsRouterVersionFactsCache::force_refresh() {
    return project(resource_->force_refresh());
}
NdmsRouterVersionFactsSnapshot NdmsRouterVersionFactsCache::peek() const {
    return project(resource_->peek());
}
void NdmsRouterVersionFactsCache::invalidate() { resource_->invalidate(); }

NdmsFirmwareVersionCache::NdmsFirmwareVersionCache(
    FetchFn fetch_fn, Clock::duration cache_ttl,
    Clock::duration failure_retry, NowFn now_fn)
    : owned_resource_(std::make_unique<NdmsVersionResource>(
          std::move(fetch_fn), cache_ttl, failure_retry,
          std::move(now_fn))),
      resource_(owned_resource_.get()) {}

NdmsFirmwareVersionCache::NdmsFirmwareVersionCache(
    NdmsVersionResource& resource)
    : resource_(&resource) {}

NdmsFirmwareVersionSnapshot NdmsFirmwareVersionCache::snapshot_locked(
    const NdmsVersionSnapshot& raw, bool refreshed, bool changed) const {
    if (!has_projection_) {
        return {std::nullopt, NdmsCatalogCacheStatus::unavailable,
                false, false, std::nullopt, 0U, 0U, 0U,
                raw.invalidation_epoch};
    }
    const bool exact = source_content_generation_ == raw.content_generation;
    return {version_, projected_status(raw, source_content_generation_),
            refreshed && exact, changed && exact,
            exact ? raw.observed_at : source_observed_at_,
            source_content_generation_,
            exact ? raw.observation_generation
                  : source_observation_generation_,
            exact ? raw.observation_epoch : source_observation_epoch_,
            raw.invalidation_epoch};
}

NdmsFirmwareVersionSnapshot NdmsFirmwareVersionCache::project(
    const NdmsVersionSnapshot& raw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (has_projection_ &&
        source_content_generation_ == raw.content_generation) {
        source_observed_at_ = raw.observed_at;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
        return snapshot_locked(raw, raw.refreshed, false);
    }

    FirmwareProjection parsed;
    if (raw.document && raw.content_generation != 0U &&
        attempted_content_generation_ != raw.content_generation) {
        attempted_content_generation_ = raw.content_generation;
        try {
            parsed = parse_firmware(raw.document->body());
        } catch (const std::bad_alloc&) {
            attempted_content_generation_ = 0U;
            throw;
        } catch (...) {
        }
    }

    bool changed = false;
    if (parsed.valid &&
        (!has_projection_ ||
         raw.content_generation >= source_content_generation_)) {
        changed = !has_projection_ ||
                  raw.content_generation != source_content_generation_;
        version_ = std::move(parsed.version);
        has_projection_ = true;
        source_observed_at_ = raw.observed_at;
        source_content_generation_ = raw.content_generation;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
    }
    return snapshot_locked(raw, raw.refreshed && parsed.valid, changed);
}

NdmsFirmwareVersionSnapshot NdmsFirmwareVersionCache::get() {
    return project(resource_->get());
}
NdmsFirmwareVersionSnapshot NdmsFirmwareVersionCache::force_refresh() {
    return project(resource_->force_refresh());
}
NdmsFirmwareVersionSnapshot NdmsFirmwareVersionCache::peek() const {
    return project(resource_->peek());
}
void NdmsFirmwareVersionCache::invalidate() { resource_->invalidate(); }

} // namespace keen_pbr3
