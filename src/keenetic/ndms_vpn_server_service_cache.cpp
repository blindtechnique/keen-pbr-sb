#include "ndms_vpn_server_service_cache.hpp"

#include <nlohmann/json.hpp>
#include <stdexcept>
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

NdmsVpnServerServiceCatalog parse_catalog_response(
    std::string_view response_body) {
    auto response = nlohmann::json::parse(
        response_body.begin(), response_body.end());
    JsonWipeGuard wipe(response);
    if (!response.is_object() || response.empty() ||
        response.find("error") != response.end()) {
        throw std::runtime_error(
            "NDMS running-config response is unavailable");
    }
    auto catalog = parse_ndms_vpn_server_service_catalog(response);
    if (!catalog.firmware_available) {
        throw std::runtime_error(
            "NDMS VPN service inventory is unavailable");
    }
    return catalog;
}

NdmsVpnServerServiceCatalog unavailable_catalog() {
    return {};
}

} // namespace

NdmsVpnServerServiceCache::NdmsVpnServerServiceCache(
    FetchFn fetch_fn,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : owned_resource_(std::make_unique<NdmsRunningConfigResource>(
          std::move(fetch_fn), cache_ttl, failure_retry,
          std::move(now_fn))),
      resource_(owned_resource_.get()) {}

NdmsVpnServerServiceCache::NdmsVpnServerServiceCache(
    NdmsRunningConfigResource& resource)
    : resource_(&resource) {}

NdmsVpnServerServiceSnapshot
NdmsVpnServerServiceCache::snapshot_locked(
    const NdmsRunningConfigSnapshot& raw,
    bool refreshed,
    bool changed) const {
    if (!catalog_) {
        return {
            unavailable_catalog(),
            NdmsCatalogCacheStatus::unavailable,
            false,
            false,
            0U,
            0U,
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
        *catalog_,
        status,
        refreshed && exact_generation,
        changed && exact_generation,
        source_content_generation_,
        exact_generation
            ? raw.observation_generation
            : source_observation_generation_,
    };
}

NdmsVpnServerServiceSnapshot NdmsVpnServerServiceCache::project(
    const NdmsRunningConfigSnapshot& raw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (catalog_ &&
        source_content_generation_ == raw.content_generation) {
        source_observation_generation_ =
            raw.observation_generation;
        return snapshot_locked(raw, raw.refreshed, false);
    }

    std::optional<NdmsVpnServerServiceCatalog> parsed;
    if (raw.document && raw.content_generation != 0U &&
        attempted_content_generation_ != raw.content_generation) {
        attempted_content_generation_ = raw.content_generation;
        try {
            parsed = parse_catalog_response(raw.document->body());
        } catch (const std::bad_alloc&) {
            attempted_content_generation_ = 0U;
            throw;
        } catch (...) {
            // A new raw generation which does not contain a valid typed VPN
            // inventory must not replace the last accepted projection or be
            // reparsed by every later cache-only reader.
        }
    }

    bool changed = false;
    if (parsed &&
        (!catalog_ ||
         raw.content_generation >= source_content_generation_)) {
        changed = raw.content_generation != source_content_generation_;
        catalog_ = std::move(*parsed);
        source_content_generation_ = raw.content_generation;
        source_observation_generation_ =
            raw.observation_generation;
    }
    return snapshot_locked(
        raw,
        raw.refreshed && parsed.has_value(),
        changed);
}

NdmsVpnServerServiceSnapshot NdmsVpnServerServiceCache::peek() const {
    return project(resource_->peek());
}

NdmsVpnServerServiceSnapshot NdmsVpnServerServiceCache::get() {
    return project(resource_->get());
}

NdmsVpnServerServiceSnapshot
NdmsVpnServerServiceCache::force_refresh() {
    return project(resource_->force_refresh());
}

void NdmsVpnServerServiceCache::invalidate() {
    resource_->invalidate();
}

} // namespace keen_pbr3
