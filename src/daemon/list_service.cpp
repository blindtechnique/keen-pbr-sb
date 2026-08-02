#include "list_service.hpp"

#include "../log/logger.hpp"

#include <chrono>
#include <sstream>
#include <tuple>
#include <utility>

namespace keen_pbr3 {

namespace {

const std::map<std::string, ListConfig>& config_lists(const Config& config) {
    static const std::map<std::string, ListConfig> empty_lists;
    return config.lists ? *config.lists : empty_lists;
}

std::string refresh_flight_key(const Config& config,
                               const OutboundMarkMap& outbound_marks,
                               bool only_uncached,
                               const std::set<std::string>* relevant_lists,
                               const std::set<std::string>* target_lists,
                               const std::set<std::string>* dns_relevant_lists) {
    nlohmann::json key;
    key["config"] = config;
    key["marks"] = outbound_marks;
    key["only_uncached"] = only_uncached;
    key["relevant"] = relevant_lists ? nlohmann::json(*relevant_lists) : nlohmann::json(nullptr);
    key["targets"] = target_lists ? nlohmann::json(*target_lists) : nlohmann::json(nullptr);
    key["dns_relevant"] = dns_relevant_lists ? nlohmann::json(*dns_relevant_lists)
                                               : nlohmann::json(nullptr);
    return key.dump();
}

std::vector<std::optional<std::string>> list_download_detours(
    const Config& config,
    const ListConfig& list_config) {
    std::vector<std::optional<std::string>> detours;
    for (const auto& detour :
         effective_list_refresh_detours(config, list_config)) {
        detours.emplace_back(detour);
    }
    if (detours.empty()) {
        detours.emplace_back(std::nullopt);
    }
    return detours;
}

bool cancellation_requested(const RemoteListRefreshControl& control) {
    return control.cancellation &&
           control.cancellation->load(std::memory_order_relaxed);
}

void throw_if_cancelled(const RemoteListRefreshControl& control) {
    if (cancellation_requested(control)) {
        throw RemoteListRefreshCancelled();
    }
}

size_t remote_list_target_count(const Config& config,
                                const std::set<std::string>* target_lists) {
    size_t total = 0;
    for (const auto& [name, list_config] : config_lists(config)) {
        if (list_config.url.has_value() &&
            (!target_lists || target_lists->count(name) > 0)) {
            ++total;
        }
    }
    return total;
}

void report_progress(const RemoteListRefreshControl& control,
                     size_t completed,
                     size_t total,
                     const std::string& list_name,
                     RemoteListRefreshProgressStatus status) noexcept {
    if (!control.progress) {
        return;
    }
    try {
        control.progress(RemoteListRefreshProgress{
            completed, total, list_name, status});
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Remote list refresh progress callback failed: {}",
            error.what());
    } catch (...) {
        Logger::instance().warn(
            "Remote list refresh progress callback failed with an unknown error");
    }
}
} // namespace

RemoteListTargetSelection select_remote_list_targets(
    const Config& config,
    const std::optional<std::string>& requested_name) {
    RemoteListTargetSelection selection;
    const auto& lists = config_lists(config);

    if (requested_name.has_value()) {
        auto it = lists.find(*requested_name);
        if (it == lists.end()) {
            selection.error = RemoteListTargetSelectionError::NotFound;
            return selection;
        }
        if (!it->second.url.has_value()) {
            selection.error = RemoteListTargetSelectionError::NotRemote;
            return selection;
        }

        selection.list_names.push_back(it->first);
        return selection;
    }

    for (const auto& [name, list_cfg] : lists) {
        if (list_cfg.url.has_value()) {
            selection.list_names.push_back(name);
        }
    }

    return selection;
}

std::set<std::string> collect_relevant_list_names(const Config& config) {
    std::set<std::string> relevant_lists;

    for (const auto& rule : config.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{})) {
        if (!route_rule_enabled(rule)) {
            continue;
        }
        const auto& route_lists = route_rule_lists(rule);
        relevant_lists.insert(route_lists.begin(), route_lists.end());
    }

    for (const auto& rule : config.dns.value_or(DnsConfig{}).rules.value_or(std::vector<DnsRule>{})) {
        if (!dns_rule_enabled(rule)) {
            continue;
        }
        relevant_lists.insert(rule.list.begin(), rule.list.end());
    }

    return relevant_lists;
}

std::set<std::string> collect_dns_relevant_list_names(const Config& config) {
    std::set<std::string> relevant_lists;
    for (const auto& rule : config.dns.value_or(DnsConfig{}).rules.value_or(std::vector<DnsRule>{})) {
        if (!dns_rule_enabled(rule)) {
            continue;
        }
        relevant_lists.insert(rule.list.begin(), rule.list.end());
    }
    return relevant_lists;
}

std::string format_list_names(const std::vector<std::string>& list_names) {
    if (list_names.empty()) {
        return "(none)";
    }

    std::ostringstream out;
    for (size_t i = 0; i < list_names.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << list_names[i];
    }
    return out.str();
}

bool remote_list_sources_changed(const Config& current, const Config& next) {
    using RemoteListSource =
        std::tuple<std::string, std::vector<std::string>>;
    const auto sources = [](const Config& config) {
        std::map<std::string, RemoteListSource> result;
        for (const auto& [name, list] : config_lists(config)) {
            if (!list.url.has_value()) {
                continue;
            }
            result.emplace(
                name,
                RemoteListSource{
                    *list.url,
                    effective_list_refresh_detours(config, list)});
        }
        return result;
    };

    return sources(current) != sources(next);
}

bool should_reload_runtime_after_list_refresh(bool routing_runtime_active,
                                              const RemoteListsRefreshResult& refresh_result) {
    return routing_runtime_active && refresh_result.any_relevant_changed();
}

std::map<std::string, api::ListRefreshStateValue> build_list_refresh_state_map(
    const Config& config,
    const CacheManager& cache_manager) {
    std::map<std::string, api::ListRefreshStateValue> refresh_state;

    for (const auto& [name, list_cfg] : config_lists(config)) {
        if (!list_cfg.url.has_value()) {
            continue;
        }

        api::ListRefreshStateValue state;
        const auto metadata = cache_manager.load_metadata(name);
        if (metadata.url.has_value() &&
            *metadata.url == *list_cfg.url) {
            state.last_updated = metadata.download_time;
        }
        if (metadata.last_refresh_url.has_value() &&
            *metadata.last_refresh_url == *list_cfg.url) {
            state.last_attempt = metadata.last_refresh_attempt;
            state.last_error = metadata.last_refresh_error;
            state.last_detour = metadata.last_refresh_detour;
        }
        refresh_state.emplace(name, std::move(state));
    }

    return refresh_state;
}

ListService::ListService(const std::filesystem::path& cache_dir,
                         size_t max_file_size_bytes,
                         std::shared_ptr<HttpTransport> transport)
    : cache_manager_(cache_dir, max_file_size_bytes, std::move(transport)) {}

void ListService::ensure_dir() {
    KPBR_LOCK_GUARD(mutex_);
    cache_manager_.ensure_dir();
}

const CacheManager& ListService::cache_manager() const {
    return cache_manager_;
}

RemoteListsRefreshResult ListService::download_uncached(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::set<std::string>* relevant_lists,
    const std::set<std::string>* dns_relevant_lists,
    const RemoteListRefreshControl& control) {
    return download_remote_lists(
        config, outbound_marks, true, relevant_lists, nullptr,
        dns_relevant_lists, control);
}

RemoteListsRefreshResult ListService::refresh_remote_lists(const Config& config,
                                                           const OutboundMarkMap& outbound_marks,
                                                           const std::set<std::string>* relevant_lists,
                                                           const std::set<std::string>* target_lists,
                                                           const std::set<std::string>* dns_relevant_lists,
                                                           const RemoteListRefreshControl& control) {
    return download_remote_lists(
        config, outbound_marks, false, relevant_lists, target_lists,
        dns_relevant_lists, control);
}

RemoteListsRefreshResult ListService::download_remote_lists(const Config& config,
                                                            const OutboundMarkMap& outbound_marks,
                                                            bool only_uncached,
                                                            const std::set<std::string>* relevant_lists,
                                                            const std::set<std::string>* target_lists,
                                                            const std::set<std::string>* dns_relevant_lists,
                                                            const RemoteListRefreshControl& control) {
    throw_if_cancelled(control);
    // All entry points converge here. Matching callers join one flight and
    // receive its result; different scopes wait so deterministic cache temp
    // paths are never shared by API, scheduled, and startup refreshes.
    std::string flight_key =
        refresh_flight_key(config, outbound_marks, only_uncached, relevant_lists, target_lists,
                           dns_relevant_lists);
    // A cancellable task owns its flight. Otherwise cancelling an IPC task
    // would propagate the owner's exception into an unrelated API/startup
    // caller that happened to request the same scope.
    if (control.cancellation) {
        flight_key += "|cancellable";
    }
    std::shared_ptr<RefreshFlight> flight;
    bool owner = false;
    {
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        while (refresh_flight_ && refresh_flight_->key != flight_key) {
            if (control.cancellation) {
                refresh_available_.wait_for(lock, std::chrono::milliseconds(50));
                throw_if_cancelled(control);
            } else {
                refresh_available_.wait(lock);
            }
        }
        if (refresh_flight_) {
            flight = refresh_flight_;
        } else {
            flight = std::make_shared<RefreshFlight>();
            flight->key = flight_key;
            refresh_flight_ = flight;
            owner = true;
        }
    }

    if (!owner) {
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        while (!flight->done) {
            if (control.cancellation) {
                flight->completed.wait_for(lock, std::chrono::milliseconds(50));
                throw_if_cancelled(control);
            } else {
                flight->completed.wait(lock);
            }
        }
        if (flight->error)
            std::rethrow_exception(flight->error);
        return flight->result;
    }
    RemoteListsRefreshResult result;
    const size_t progress_total = remote_list_target_count(config, target_lists);
    size_t progress_completed = 0;
    try {
        for (const auto& [name, list_cfg] : config_lists(config)) {
            if (!list_cfg.url.has_value()) {
                continue;
            }
            if (target_lists && target_lists->count(name) == 0) {
                continue;
            }
            throw_if_cancelled(control);
            if (only_uncached &&
                cache_manager_.has_current_cache(name, *list_cfg.url)) {
                result.cached_lists.push_back(name);
                report_progress(control, ++progress_completed, progress_total,
                                name, RemoteListRefreshProgressStatus::Cached);
                continue;
            }

            result.refreshed_lists.push_back(name);

            CacheDownloadResult download_result;
            bool attempted = false;
            for (const auto& detour :
                 list_download_detours(config, list_cfg)) {
                throw_if_cancelled(control);
                uint32_t fwmark = 0;
                if (detour.has_value()) {
                    const auto mark_it = outbound_marks.find(*detour);
                    if (mark_it == outbound_marks.end()) {
                        Logger::instance().warn(
                            "List '{}': configured download outbound '{}' "
                            "has no routing mark; refusing an implicit direct "
                            "fallback",
                            name,
                            *detour);
                        continue;
                    }
                    fwmark = mark_it->second;
                }

                attempted = true;
                download_result = cache_manager_.download(
                    name,
                    *list_cfg.url,
                    CacheDownloadOptions{
                        fwmark,
                        detour,
                        control.cancellation,
                        control.cache_commit});
                if (download_result.cancelled()) {
                    throw RemoteListRefreshCancelled();
                }
                if (!download_result.failed()) {
                    break;
                }

                throw_if_cancelled(control);

                Logger::instance().warn(
                    "List '{}': refresh through {} failed: {}",
                    name,
                    detour.value_or("the system default route"),
                    download_result.error_message.empty()
                        ? std::string("unknown error")
                        : download_result.error_message);
                if (!download_result.retryable) {
                    break;
                }
            }
            if (!attempted || download_result.failed()) {
                throw_if_cancelled(control);
                const std::string failure_message =
                    !attempted
                        ? std::string(
                              "no configured download outbound has a routing "
                              "mark")
                        : (download_result.error_message.empty()
                               ? std::string("unknown error")
                               : download_result.error_message);
                if (!attempted) {
                    try {
                        cache_manager_.record_refresh_failure(
                            name, *list_cfg.url, failure_message);
                    } catch (const std::exception& error) {
                        Logger::instance().warn(
                            "List '{}': could not persist refresh failure "
                            "status: {}",
                            name,
                            error.what());
                    }
                }
                if (only_uncached &&
                    cache_manager_.has_usable_same_source_cache(
                        name, *list_cfg.url)) {
                    result.cached_lists.push_back(name);
                    result.legacy_cached_lists.push_back(name);
                    report_progress(
                        control, ++progress_completed, progress_total, name,
                        RemoteListRefreshProgressStatus::Cached);
                    continue;
                }
                result.failed_lists.push_back(name);
                Logger::instance().warn("List '{}': failed to refresh {}: {}",
                                        name,
                                        *list_cfg.url,
                                        failure_message);
                report_progress(control, ++progress_completed, progress_total,
                                name, RemoteListRefreshProgressStatus::Failed);
                throw_if_cancelled(control);
                continue;
            }

            if (!download_result.updated()) {
                result.unchanged_lists.push_back(name);
                report_progress(
                    control, ++progress_completed, progress_total, name,
                    RemoteListRefreshProgressStatus::Unchanged);
                throw_if_cancelled(control);
                continue;
            }

            if (!download_result.warning_message.empty()) {
                Logger::instance().warn("List '{}': {}",
                                        name,
                                        download_result.warning_message);
            }

            result.changed_lists.push_back(name);
            if (relevant_lists && relevant_lists->count(name) > 0) {
                result.relevant_changed_lists.push_back(name);
            }
            if (dns_relevant_lists && dns_relevant_lists->count(name) > 0) {
                result.dns_relevant_changed_lists.push_back(name);
            }
            report_progress(control, ++progress_completed, progress_total,
                            name, RemoteListRefreshProgressStatus::Updated);
            // The cache body and metadata have already been committed. Record
            // that fact before honoring a cancellation which raced the short
            // commit window, so the daemon can reconcile the active runtime.
            throw_if_cancelled(control);
        }
        if (!result.legacy_cached_lists.empty()) {
            Logger::instance().warn(
                "Remote SRS refresh failed; continuing with validated "
                "same-source cache from an older decoder revision: {}",
                format_list_names(result.legacy_cached_lists));
        }
    } catch (const RemoteListRefreshCancelled&) {
        auto cancellation =
            std::make_exception_ptr(RemoteListRefreshCancelled(result));
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        flight->error = cancellation;
        flight->done = true;
        refresh_flight_.reset();
        lock.unlock();
        flight->completed.notify_all();
        refresh_available_.notify_all();
        std::rethrow_exception(cancellation);
    } catch (...) {
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        flight->error = std::current_exception();
        flight->done = true;
        refresh_flight_.reset();
        lock.unlock();
        flight->completed.notify_all();
        refresh_available_.notify_all();
        throw;
    }

    {
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        flight->result = result;
        flight->done = true;
        refresh_flight_.reset();
    }
    flight->completed.notify_all();
    refresh_available_.notify_all();
    return result;
}

} // namespace keen_pbr3
