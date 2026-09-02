#include "ndms_running_config_resource.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaximumRunningConfigBytes = 2U * 1024U * 1024U;

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
        // Best effort during cleanup; callers never rely on wipe for control
        // flow and the retained raw buffer is still cleared deterministically.
    }
}

class JsonWipeGuard final {
public:
    explicit JsonWipeGuard(nlohmann::json& value) : value_(value) {}
    ~JsonWipeGuard() { wipe_json_strings(value_); }

private:
    nlohmann::json& value_;
};

struct ValidatedRunningConfig {
    NdmsRunningConfigFailure failure{
        NdmsRunningConfigFailure::malformed_response};
    std::string semantic_digest;
};

ValidatedRunningConfig validate_running_config(
    const std::string& body) noexcept {
    if (body.size() > kMaximumRunningConfigBytes) {
        return {NdmsRunningConfigFailure::response_too_large, {}};
    }
    try {
        auto document = nlohmann::json::parse(body);
        JsonWipeGuard wipe(document);
        if (!document.is_object() || document.empty() ||
            document.find("error") != document.end()) {
            return {NdmsRunningConfigFailure::malformed_response, {}};
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
                return {
                    NdmsRunningConfigFailure::malformed_response, {}};
            }
        }
        const auto messages = document.find("message");
        if (messages == document.end() || !messages->is_array() ||
            messages->empty() ||
            !std::all_of(
                messages->begin(), messages->end(),
                [](const nlohmann::json& line) {
                    return line.is_string();
                })) {
            return {NdmsRunningConfigFailure::malformed_response, {}};
        }
        auto canonical = document.dump();
        StringWipeGuard canonical_wipe(canonical);
        const auto digest = Sha256::hex(canonical);
        return {NdmsRunningConfigFailure::none, digest};
    } catch (...) {
        return {NdmsRunningConfigFailure::malformed_response, {}};
    }
}

} // namespace

NdmsSensitiveRunningConfigDocument::NdmsSensitiveRunningConfigDocument(
    std::string body)
    : body_(std::move(body)) {}

NdmsSensitiveRunningConfigDocument::~NdmsSensitiveRunningConfigDocument() {
    secure_wipe(body_);
}

std::string_view NdmsSensitiveRunningConfigDocument::body() const noexcept {
    return body_;
}

NdmsRunningConfigResource::NdmsRunningConfigResource(
    FetchFn fetch_fn,
    Clock::duration cache_ttl,
    Clock::duration failure_retry,
    NowFn now_fn)
    : fetch_fn_(std::move(fetch_fn)),
      now_fn_(std::move(now_fn)),
      cache_ttl_(cache_ttl),
      failure_retry_(failure_retry) {
    if (!fetch_fn_) {
        throw std::invalid_argument(
            "NDMS running-config fetch function is required");
    }
    if (!now_fn_) {
        now_fn_ = [] { return Clock::now(); };
    }
}

NdmsRunningConfigSnapshot NdmsRunningConfigResource::snapshot_locked(
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
    if (!document_) {
        effective_status = NdmsCatalogCacheStatus::unavailable;
    }
    return {
        document_,
        effective_status,
        refreshed,
        changed,
        observed_at_,
        content_generation_,
        observation_generation_,
        observation_epoch_,
        invalidation_epoch_,
        last_failure_,
    };
}

NdmsRunningConfigSnapshot NdmsRunningConfigResource::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_locked();
}

NdmsRunningConfigSnapshot NdmsRunningConfigResource::get() {
    return get_impl(false);
}

NdmsRunningConfigSnapshot NdmsRunningConfigResource::force_refresh() {
    return get_impl(true);
}

void NdmsRunningConfigResource::invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++invalidation_epoch_;
    if (invalidation_epoch_ == 0U) ++invalidation_epoch_;
    status_ = document_ ? NdmsCatalogCacheStatus::stale
                        : NdmsCatalogCacheStatus::unavailable;
    refresh_after_ = Clock::time_point{};
    forced_refresh_after_ = Clock::time_point{};
    last_failure_ = NdmsRunningConfigFailure::none;
}

NdmsRunningConfigSnapshot NdmsRunningConfigResource::get_impl(
    bool force_refresh) {
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
            // Ordinary readers can use the immutable LKG immediately. A
            // forced reader waits because it must observe completion in the
            // current invalidation epoch rather than merely see old bytes.
            if (!force_refresh && document_) {
                return snapshot_locked();
            }
            const auto observed_generation = refresh_generation_;
            refresh_finished_.wait(
                lock,
                [this, observed_generation] {
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
        NdmsRunningConfigFailure failure =
            NdmsRunningConfigFailure::transport_failed;
        try {
            fetched_body = fetch_fn_();
            auto validated = validate_running_config(fetched_body);
            failure = validated.failure;
            fetched_digest = std::move(validated.semantic_digest);
        } catch (...) {
            failure = NdmsRunningConfigFailure::transport_failed;
        }
        Clock::time_point completed_at;
        try {
            completed_at = now_fn_();
        } catch (...) {
            completed_at = Clock::now();
        }

        std::shared_ptr<const NdmsSensitiveRunningConfigDocument>
            fetched_document;
        if (failure == NdmsRunningConfigFailure::none) {
            try {
                fetched_document =
                    std::make_shared<const NdmsSensitiveRunningConfigDocument>(
                        std::move(fetched_body));
            } catch (...) {
                failure = NdmsRunningConfigFailure::transport_failed;
            }
        }
        secure_wipe(fetched_body);

        lock.lock();
        refresh_attempted_ = true;
        const bool current_epoch = fetch_epoch == invalidation_epoch_;
        const bool accepted = fetched_document && current_epoch;
        bool changed = false;
        if (accepted) {
            changed = !document_ ||
                content_digest_ != fetched_digest;
            if (changed) {
                document_ = std::move(fetched_document);
                content_digest_ = std::move(fetched_digest);
                ++content_generation_;
                if (content_generation_ == 0U) ++content_generation_;
            }
            observed_at_ = completed_at;
            ++observation_generation_;
            if (observation_generation_ == 0U) {
                ++observation_generation_;
            }
            observation_epoch_ = fetch_epoch;
            status_ = NdmsCatalogCacheStatus::fresh;
            refresh_after_ = completed_at + cache_ttl_;
            last_failure_ = NdmsRunningConfigFailure::none;
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
