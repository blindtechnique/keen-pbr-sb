#include "ndms_catalog_cache.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string_view>
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

NdmsInterfaceCatalog unavailable_catalog() {
    return parse_ndms_interface_catalog(nlohmann::json{});
}

bool is_rci_error_object(const nlohmann::json& response) {
    if (response.find("error") != response.end()) return true;

    const auto status = response.find("status");
    if (status == response.end() || !status->is_string()) return false;
    auto value = status->get<std::string>();
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    const bool failed = value == "error" || value == "failed";
    secure_wipe(value);
    return failed;
}

NdmsInterfaceCatalog parse_catalog_response(
    const std::string_view response_body) {
    auto response = nlohmann::json::parse(
        response_body.begin(), response_body.end());
    JsonWipeGuard wipe(response);
    if (!response.is_object()) {
        throw std::runtime_error("NDMS RCI response is not an object");
    }
    if (response.empty()) {
        throw std::runtime_error("NDMS RCI response is empty");
    }
    if (is_rci_error_object(response)) {
        throw std::runtime_error("NDMS RCI returned an error object");
    }

    auto catalog = parse_ndms_interface_catalog(response);
    if (!catalog.firmware_available) {
        throw std::runtime_error("NDMS RCI response is unavailable");
    }
    return catalog;
}

} // namespace

NdmsCatalogCache::NdmsCatalogCache(
    FetchFn fetch_fn,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : owned_resource_(std::make_unique<NdmsInterfaceResource>(
          std::move(fetch_fn), cache_ttl, failure_retry,
          std::move(now_fn))),
      resource_(owned_resource_.get()) {}

NdmsCatalogCache::NdmsCatalogCache(NdmsInterfaceResource& resource)
    : resource_(&resource) {}

NdmsCatalogSnapshot NdmsCatalogCache::snapshot_locked(
    const NdmsInterfaceSnapshot& raw,
    const bool refreshed) const {
    if (!catalog_) {
        return {
            unavailable_catalog(),
            NdmsCatalogCacheStatus::unavailable,
            false,
            std::nullopt,
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
        *catalog_,
        status,
        refreshed && exact_generation,
        exact_generation ? raw.observed_at : source_observed_at_,
        exact_generation
            ? raw.observation_generation
            : source_observation_generation_,
        exact_generation
            ? raw.observation_epoch
            : source_observation_epoch_,
        raw.invalidation_epoch,
    };
}

NdmsCatalogSnapshot NdmsCatalogCache::project(
    const NdmsInterfaceSnapshot& raw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (catalog_ &&
        source_content_generation_ == raw.content_generation) {
        source_observed_at_ = raw.observed_at;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
        return snapshot_locked(raw, raw.refreshed);
    }

    std::optional<NdmsInterfaceCatalog> parsed;
    if (raw.document && raw.content_generation != 0U &&
        attempted_content_generation_ != raw.content_generation) {
        attempted_content_generation_ = raw.content_generation;
        try {
            parsed = parse_catalog_response(raw.document->body());
        } catch (const std::bad_alloc&) {
            attempted_content_generation_ = 0U;
            throw;
        } catch (...) {
            // An invalid new raw generation must not replace the last typed
            // catalog or be reparsed by every later cache-only reader.
        }
    }

    if (parsed &&
        (!catalog_ ||
         raw.content_generation >= source_content_generation_)) {
        catalog_ = std::move(*parsed);
        source_observed_at_ = raw.observed_at;
        source_content_generation_ = raw.content_generation;
        source_observation_generation_ = raw.observation_generation;
        source_observation_epoch_ = raw.observation_epoch;
    }
    return snapshot_locked(
        raw, raw.refreshed && parsed.has_value());
}

NdmsCatalogSnapshot NdmsCatalogCache::peek() const {
    return project(resource_->peek());
}

NdmsCatalogSnapshot NdmsCatalogCache::get() {
    return project(resource_->get());
}

NdmsCatalogSnapshot NdmsCatalogCache::force_refresh() {
    return project(resource_->force_refresh());
}

void NdmsCatalogCache::invalidate() {
    resource_->invalidate();
}

} // namespace keen_pbr3
