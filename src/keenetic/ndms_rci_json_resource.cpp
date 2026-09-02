#include "ndms_rci_json_resource.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaximumDocumentBytes = 2U * 1024U * 1024U;

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : &value[0];
    for (std::size_t offset = 0; offset < value.size(); ++offset) {
        bytes[offset] = 0;
    }
    value.clear();
}

class StringWipeGuard final {
public:
    explicit StringWipeGuard(std::string& value) : value_(value) {}
    ~StringWipeGuard() { secure_wipe(value_); }

private:
    std::string& value_;
};

void wipe_json_strings(nlohmann::json& value) noexcept {
    try {
        if (value.is_string()) {
            auto& text = value.get_ref<std::string&>();
            secure_wipe(text);
            return;
        }
        if (value.is_array()) {
            for (auto& child : value) wipe_json_strings(child);
            return;
        }
        if (value.is_object()) {
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

struct ValidatedDocument {
    NdmsRciJsonFailure failure{NdmsRciJsonFailure::malformed_response};
    std::string semantic_digest;
};

ValidatedDocument validate_document(
    const std::string& body,
    NdmsRciJsonShape shape) noexcept {
    if (body.size() > kMaximumDocumentBytes) {
        return {NdmsRciJsonFailure::response_too_large, {}};
    }
    try {
        auto document = nlohmann::json::parse(body);
        JsonWipeGuard wipe(document);
        if (!document.is_object() || document.empty() ||
            document.find("error") != document.end()) {
            return {NdmsRciJsonFailure::malformed_response, {}};
        }
        const auto status = document.find("status");
        if (status != document.end() && status->is_string()) {
            auto value = status->get<std::string>();
            std::transform(
                value.begin(), value.end(), value.begin(),
                [](const unsigned char character) {
                    return static_cast<char>(std::tolower(character));
                });
            const bool failed = value == "error" || value == "failed";
            secure_wipe(value);
            if (failed) {
                return {NdmsRciJsonFailure::malformed_response, {}};
            }
        }
        if (shape == NdmsRciJsonShape::running_config) {
            const auto messages = document.find("message");
            if (messages == document.end() || !messages->is_array() ||
                messages->empty() ||
                !std::all_of(
                    messages->begin(), messages->end(),
                    [](const nlohmann::json& line) {
                        return line.is_string();
                    })) {
                return {NdmsRciJsonFailure::malformed_response, {}};
            }
        }
        auto canonical = document.dump();
        StringWipeGuard canonical_wipe(canonical);
        return {NdmsRciJsonFailure::none, Sha256::hex(canonical)};
    } catch (...) {
        return {NdmsRciJsonFailure::malformed_response, {}};
    }
}

} // namespace

NdmsSensitiveJsonDocument::NdmsSensitiveJsonDocument(std::string body)
    : body_(std::move(body)) {}

NdmsSensitiveJsonDocument::~NdmsSensitiveJsonDocument() {
    secure_wipe(body_);
}

std::string_view NdmsSensitiveJsonDocument::body() const noexcept {
    return body_;
}

NdmsRciJsonResource::NdmsRciJsonResource(
    FetchFn fetch_fn,
    NdmsRciJsonShape shape,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : fetch_fn_(std::move(fetch_fn)),
      now_fn_(std::move(now_fn)),
      shape_(shape),
      cache_ttl_(cache_ttl),
      failure_retry_(failure_retry) {
    if (!fetch_fn_) {
        throw std::invalid_argument("NDMS RCI fetch function is required");
    }
    if (!now_fn_) now_fn_ = [] { return Clock::now(); };
}

NdmsRciJsonSnapshot NdmsRciJsonResource::snapshot_locked(
    bool refreshed,
    bool changed) const {
    auto effective_status = status_;
    if (document_ && effective_status == NdmsCatalogCacheStatus::fresh) {
        try {
            if (now_fn_() >= refresh_after_) {
                effective_status = NdmsCatalogCacheStatus::stale;
            }
        } catch (...) {
            effective_status = NdmsCatalogCacheStatus::stale;
        }
    }
    if (!document_) effective_status = NdmsCatalogCacheStatus::unavailable;
    return {
        document_, effective_status, refreshed, changed, observed_at_,
        content_generation_, observation_generation_, observation_epoch_,
        invalidation_epoch_, last_failure_,
    };
}

NdmsRciJsonSnapshot NdmsRciJsonResource::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_locked();
}

NdmsRciJsonSnapshot NdmsRciJsonResource::get() {
    return get_impl(false);
}

NdmsRciJsonSnapshot NdmsRciJsonResource::force_refresh() {
    return get_impl(true);
}

void NdmsRciJsonResource::invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++invalidation_epoch_;
    if (invalidation_epoch_ == 0U) ++invalidation_epoch_;
    status_ = document_ ? NdmsCatalogCacheStatus::stale
                        : NdmsCatalogCacheStatus::unavailable;
    refresh_after_ = Clock::time_point{};
    forced_refresh_after_ = Clock::time_point{};
    last_failure_ = NdmsRciJsonFailure::none;
}

NdmsRciJsonSnapshot NdmsRciJsonResource::get_impl(bool force_refresh) {
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
        Clock::time_point now;
        try {
            now = now_fn_();
        } catch (...) {
            now = Clock::now();
        }
        if (refresh_attempted_ &&
            ((!force_refresh && now < refresh_after_) ||
             (force_refresh && now < forced_refresh_after_))) {
            return snapshot_locked();
        }
        if (refresh_in_progress_) {
            if (!force_refresh && document_) return snapshot_locked();
            const auto observed_generation = refresh_generation_;
            refresh_finished_.wait(lock, [this, observed_generation] {
                return refresh_generation_ != observed_generation;
            });
            if (force_refresh &&
                last_completed_refresh_epoch_ != invalidation_epoch_) {
                continue;
            }
            return snapshot_locked(
                last_refresh_accepted_, last_refresh_changed_);
        }

        refresh_in_progress_ = true;
        const auto fetch_epoch = invalidation_epoch_;
        lock.unlock();

        std::string fetched_body;
        std::string fetched_digest;
        NdmsRciJsonFailure failure =
            NdmsRciJsonFailure::transport_failed;
        try {
            fetched_body = fetch_fn_();
            auto validated = validate_document(fetched_body, shape_);
            failure = validated.failure;
            fetched_digest = std::move(validated.semantic_digest);
        } catch (...) {
            failure = NdmsRciJsonFailure::transport_failed;
        }
        Clock::time_point completed_at;
        try {
            completed_at = now_fn_();
        } catch (...) {
            completed_at = Clock::now();
        }

        std::shared_ptr<const NdmsSensitiveJsonDocument> fetched_document;
        if (failure == NdmsRciJsonFailure::none) {
            try {
                fetched_document =
                    std::make_shared<const NdmsSensitiveJsonDocument>(
                        std::move(fetched_body));
            } catch (...) {
                failure = NdmsRciJsonFailure::transport_failed;
            }
        }
        secure_wipe(fetched_body);

        lock.lock();
        refresh_attempted_ = true;
        const bool current_epoch = fetch_epoch == invalidation_epoch_;
        const bool accepted = fetched_document && current_epoch;
        bool changed = false;
        if (accepted) {
            changed = !document_ || content_digest_ != fetched_digest;
            if (changed) {
                document_ = std::move(fetched_document);
                content_digest_ = std::move(fetched_digest);
                ++content_generation_;
                if (content_generation_ == 0U) ++content_generation_;
            }
            observed_at_ = completed_at;
            ++observation_generation_;
            if (observation_generation_ == 0U) ++observation_generation_;
            observation_epoch_ = fetch_epoch;
            status_ = NdmsCatalogCacheStatus::fresh;
            refresh_after_ = completed_at + cache_ttl_;
            last_failure_ = NdmsRciJsonFailure::none;
        } else {
            status_ = document_ ? NdmsCatalogCacheStatus::stale
                                : NdmsCatalogCacheStatus::unavailable;
            refresh_after_ = current_epoch
                ? completed_at + failure_retry_
                : Clock::time_point{};
            if (current_epoch) last_failure_ = failure;
        }
        if (!current_epoch) {
            forced_refresh_after_ = Clock::time_point{};
        } else if (force_refresh || !accepted) {
            forced_refresh_after_ = completed_at + failure_retry_;
        }
        refresh_in_progress_ = false;
        last_refresh_accepted_ = accepted;
        last_refresh_changed_ = changed;
        last_completed_refresh_epoch_ = fetch_epoch;
        ++refresh_generation_;
        auto result = snapshot_locked(accepted, changed);
        lock.unlock();
        refresh_finished_.notify_all();
        return result;
    }
}

} // namespace keen_pbr3
