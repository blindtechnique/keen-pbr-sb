#pragma once

#include <nlohmann/json.hpp>
#include <mutex>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Only provider counters are stored, never subscription bodies or share links.
nlohmann::json parse_subscription_userinfo(const std::string& header);
std::string parse_subscription_title(const std::string& header);
std::string subscription_source_host(const std::string& url);
nlohmann::json public_subscription(nlohmann::json record);

// A small metadata file beside config.json. No daemon config apply, runtime
// owner, worker or recovery journal participates in metadata-only operations.
class SubscriptionStore {
public:
    explicit SubscriptionStore(std::string path) : path_(std::move(path)) {}
    nlohmann::json list();
    nlohmann::json find(const std::string& id);
    nlohmann::json save(const std::string& url, const std::string& name,
                        const nlohmann::json& metadata,
                        const std::vector<std::string>& tags);
    nlohmann::json refresh(const std::string& id, const nlohmann::json& metadata);
    nlohmann::json rename(const std::string& id, const std::string& name);
    void erase(const std::string& id);
private:
    nlohmann::json read() const;
    void write(const nlohmann::json& records) const;
    std::string path_;
    std::mutex mutex_;
};

} // namespace keen_pbr3
