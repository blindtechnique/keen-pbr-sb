#pragma once

#include "subscription_import_plan.hpp"
#include "subscription_store.hpp"

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

class MaintenanceLease;

struct SubscriptionFetchResult {
    std::string body;
    std::map<std::string, std::string> headers;
    SubscriptionFetchResult() = default;
    SubscriptionFetchResult(std::string content) : body(std::move(content)) {}
};
using SubscriptionFetcher =
    std::function<SubscriptionFetchResult(const std::string& url)>;

struct SubscriptionTransportState {
    std::string tag;
    std::string fingerprint;
};

// The link exists only for this apply call. Never serialize this structure in
// source metadata, logs or browser responses.
struct SubscriptionTransportUpdate {
    std::string tag;
    std::string link;
    std::string previous_fingerprint;
    std::string candidate_key;
    std::string next_fingerprint;
};

struct SubscriptionUpdateResult {
    std::vector<std::string> applied_tags;
    // A finite UI code, never a transport response or an exception message.
    std::string error_code;
};
using SubscriptionApplyUpdates = std::function<SubscriptionUpdateResult(
    const std::vector<SubscriptionTransportUpdate>&)>;
using SubscriptionReadTransports =
    std::function<std::vector<SubscriptionTransportState>()>;
// The reader returns every configured tag, including transports without a
// subscription fingerprint. Failure must throw, not masquerade as an empty list.

// Provider headers plus a private, credential-free inventory. The public
// source projection strips all inventory and binding fingerprints.
nlohmann::json subscription_refresh_metadata(
    const SubscriptionFetchResult& fetched, const SubscriptionImportPlan& plan,
    std::int64_t now);
std::string subscription_candidate_key(const SubscriptionImportPlan& plan,
                                       std::size_t index);
nlohmann::json subscription_import_bindings(
    const SubscriptionImportPlan& plan,
    const std::map<std::size_t, std::string>& tags_by_source_line);
bool subscription_candidate_pending(const nlohmann::json& source,
                                    const SubscriptionImportPlan& plan,
                                    std::size_t index);

class SubscriptionRefreshService {
public:
    using Clock = std::function<std::int64_t()>;
    using AccessFactory = std::function<std::unique_ptr<MaintenanceLease>()>;
    SubscriptionRefreshService(std::shared_ptr<SubscriptionStore> store,
                               SubscriptionFetcher fetcher,
                               SubscriptionApplyUpdates apply_updates = {},
                               SubscriptionReadTransports read_transports = {},
                               Clock clock = {},
                               AccessFactory access_factory = {});
    std::shared_ptr<SubscriptionStore> store() const { return store_; }
    // Same core for explicit refresh and one due source from the daemon task.
    // There is no internal timer, polling thread or runtime mutation owner.
    nlohmann::json refresh(const std::string& id);
    std::optional<nlohmann::json> refresh_due_once();

private:
    std::shared_ptr<SubscriptionStore> store_;
    SubscriptionFetcher fetcher_;
    SubscriptionApplyUpdates apply_updates_;
    SubscriptionReadTransports read_transports_;
    Clock clock_;
    AccessFactory access_factory_;
};

} // namespace keen_pbr3
