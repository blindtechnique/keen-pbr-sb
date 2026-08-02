#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../util/traced_mutex.hpp"

#include <atomic>
#include <condition_variable>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct RemoteListsRefreshResult {
    std::vector<std::string> refreshed_lists;
    std::vector<std::string> cached_lists;
    std::vector<std::string> legacy_cached_lists;
    std::vector<std::string> changed_lists;
    std::vector<std::string> unchanged_lists;
    std::vector<std::string> relevant_changed_lists;
    std::vector<std::string> dns_relevant_changed_lists;
    std::vector<std::string> failed_lists;

    bool any_refreshed() const {
        return !refreshed_lists.empty();
    }

    bool any_changed() const {
        return !changed_lists.empty();
    }

    bool any_relevant_changed() const {
        return !relevant_changed_lists.empty();
    }

    bool any_dns_relevant_changed() const {
        return !dns_relevant_changed_lists.empty();
    }

    bool any_failed() const {
        return !failed_lists.empty();
    }
};

enum class RemoteListRefreshProgressStatus {
    Cached,
    Updated,
    Unchanged,
    Failed,
};

struct RemoteListRefreshProgress {
    size_t completed{0};
    size_t total{0};
    std::string list_name;
    RemoteListRefreshProgressStatus status{
        RemoteListRefreshProgressStatus::Unchanged};
};

struct RemoteListRefreshControl {
    HttpCancellationToken cancellation;
    std::function<void(const RemoteListRefreshProgress&)> progress;
    CacheCommitCallback cache_commit;
};

class RemoteListRefreshCancelled : public std::runtime_error {
public:
    explicit RemoteListRefreshCancelled(
        RemoteListsRefreshResult partial_result = {})
        : std::runtime_error("remote list refresh cancelled"),
          partial_result_(std::move(partial_result)) {}

    const RemoteListsRefreshResult& partial_result() const noexcept {
        return partial_result_;
    }

private:
    RemoteListsRefreshResult partial_result_;
};

enum class RemoteListTargetSelectionError {
    None,
    NotFound,
    NotRemote,
};

struct RemoteListTargetSelection {
    RemoteListTargetSelectionError error{RemoteListTargetSelectionError::None};
    std::vector<std::string> list_names;

    bool ok() const {
        return error == RemoteListTargetSelectionError::None;
    }
};

RemoteListTargetSelection select_remote_list_targets(
    const Config& config,
    const std::optional<std::string>& requested_name);

std::set<std::string> collect_relevant_list_names(const Config& config);
std::set<std::string> collect_dns_relevant_list_names(const Config& config);
std::string format_list_names(const std::vector<std::string>& list_names);
bool remote_list_sources_changed(const Config& current, const Config& next);

bool should_reload_runtime_after_list_refresh(
    bool routing_runtime_active,
    const RemoteListsRefreshResult& refresh_result);

std::map<std::string, api::ListRefreshStateValue> build_list_refresh_state_map(
    const Config& config,
    const CacheManager& cache_manager);

class ListService {
public:
    ListService(const std::filesystem::path& cache_dir,
                size_t max_file_size_bytes = kDefaultMaxFileSizeBytes,
                std::shared_ptr<HttpTransport> transport =
                    default_http_transport());

    void ensure_dir();
    const CacheManager& cache_manager() const;

    // Startup only: preserve cached lists and download just the missing ones.
    RemoteListsRefreshResult download_uncached(const Config& config,
                                               const OutboundMarkMap& outbound_marks,
                                               const std::set<std::string>* relevant_lists = nullptr,
                                               const std::set<std::string>* dns_relevant_lists = nullptr,
                                               const RemoteListRefreshControl& control = {});
    RemoteListsRefreshResult refresh_remote_lists(const Config& config,
                                                  const OutboundMarkMap& outbound_marks,
                                                  const std::set<std::string>* relevant_lists = nullptr,
                                                  const std::set<std::string>* target_lists = nullptr,
                                                  const std::set<std::string>* dns_relevant_lists = nullptr,
                                                  const RemoteListRefreshControl& control = {});

private:
    struct RefreshFlight {
        std::string key;
        bool done{false};
        RemoteListsRefreshResult result;
        std::exception_ptr error;
        std::condition_variable_any completed;
    };

    RemoteListsRefreshResult download_remote_lists(const Config& config,
                                                   const OutboundMarkMap& outbound_marks,
                                                   bool only_uncached,
                                                   const std::set<std::string>* relevant_lists,
                                                   const std::set<std::string>* target_lists,
                                                   const std::set<std::string>* dns_relevant_lists,
                                                   const RemoteListRefreshControl& control);

    mutable TracedMutex mutex_;
    std::mutex refresh_mutex_;
    std::condition_variable_any refresh_available_;
    std::shared_ptr<RefreshFlight> refresh_flight_;
    CacheManager cache_manager_;
};

} // namespace keen_pbr3
