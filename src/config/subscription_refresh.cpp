#include "subscription_refresh.hpp"
#include "../crypto/sha256.hpp"
#include "../update/maintenance_lock.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <stdexcept>

namespace keen_pbr3 {
namespace {
using json = nlohmann::json;

std::int64_t current_time() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool inventory_candidate(const SubscriptionCandidate& candidate) {
    return candidate.disposition != SubscriptionCandidateDisposition::malformed &&
           candidate.disposition != SubscriptionCandidateDisposition::duplicate_in_document &&
           candidate.disposition != SubscriptionCandidateDisposition::scheme_not_supported;
}

bool stable_candidate(const SubscriptionImportPlan& plan, std::size_t index) {
    const auto& candidate = plan.candidates.at(index);
    if (candidate.remark.empty()) return false;
    return std::count_if(plan.candidates.begin(), plan.candidates.end(), [&](const auto& other) {
        return inventory_candidate(other) && other.scheme == candidate.scheme &&
               other.remark == candidate.remark;
    }) == 1;
}

json inventory(const SubscriptionImportPlan& plan) {
    json result = json::array();
    for (std::size_t i = 0; i < plan.candidates.size(); ++i) {
        if (!inventory_candidate(plan.candidates[i])) continue;
        result.push_back({{"key", subscription_candidate_key(plan, i)},
            {"fingerprint", subscription_link_fingerprint(plan.links.at(i))},
            {"stable", stable_candidate(plan, i)}});
    }
    return result;
}

std::string sync_error_code(const std::string& error) {
    // Never persist a callback exception/response, which may carry a link.
    static const std::set<std::string> allowed{
        "apply_failed", "transport_unavailable", "ambiguous_binding",
        "transport_changed", "apply_unavailable"};
    return allowed.count(error) ? error : "apply_failed";
}

json response_source_version(json source) {
    // These local presentation/scheduling edits do not replace the provider
    // state an in-flight response was fetched for. Everything else, including
    // private bindings and inventory, belongs to that source version.
    for (const char* key : {"name", "name_is_custom", "refresh_interval_seconds"})
        source.erase(key);
    return source;
}

} // namespace

std::string subscription_candidate_key(const SubscriptionImportPlan& plan, std::size_t index) {
    const auto& candidate = plan.candidates.at(index);
    if (stable_candidate(plan, index))
        return "named:" + Sha256::hex(candidate.scheme + "\n" + candidate.remark);
    // Unnamed or duplicate-named entries can be recognized exactly, but never
    // matched to changed credentials/endpoints merely by provider position.
    return "exact:" + subscription_link_fingerprint(plan.links.at(index));
}

json subscription_refresh_metadata(const SubscriptionFetchResult& fetched,
                                   const SubscriptionImportPlan& plan, std::int64_t now) {
    if (plan.kind != SubscriptionDocumentKind::link_list &&
        plan.kind != SubscriptionDocumentKind::base64_link_list &&
        plan.kind != SubscriptionDocumentKind::json_document)
        throw std::invalid_argument("invalid subscription document");
    const auto header = fetched.headers.find("subscription-userinfo");
    auto metadata = parse_subscription_userinfo(header == fetched.headers.end() ? "" : header->second);
    const auto title_header = fetched.headers.find("profile-title");
    const auto title = parse_subscription_title(title_header == fetched.headers.end() ? "" : title_header->second);
    if (!title.empty()) metadata["provider_name"] = title;
    metadata["checked_at"] = now;
    metadata["updated_at"] = now;
    if (plan.kind != SubscriptionDocumentKind::json_document) {
        std::size_t count = 0;
        for (const auto& item : plan.candidates)
            if (item.disposition != SubscriptionCandidateDisposition::duplicate_in_document &&
                item.disposition != SubscriptionCandidateDisposition::malformed) ++count;
        metadata["node_count"] = count;
        metadata["_inventory"] = inventory(plan);
    }
    return metadata;
}

json subscription_import_bindings(const SubscriptionImportPlan& plan,
                                 const std::map<std::size_t, std::string>& tags_by_source_line) {
    json result = json::array();
    for (std::size_t i = 0; i < plan.candidates.size(); ++i) {
        const auto& candidate = plan.candidates[i];
        const auto tag = tags_by_source_line.find(candidate.source_line);
        if (tag == tags_by_source_line.end() || !inventory_candidate(candidate)) continue;
        result.push_back({{"tag", tag->second}, {"key", subscription_candidate_key(plan, i)},
            {"fingerprint", subscription_link_fingerprint(plan.links.at(i))},
            {"stable", stable_candidate(plan, i)}});
    }
    return result;
}

bool subscription_candidate_pending(const json& source, const SubscriptionImportPlan& plan,
                                    std::size_t index) {
    if (!source.contains("_inventory") || !inventory_candidate(plan.candidates.at(index))) return false;
    const auto known = source.value("_known_candidates", std::set<std::string>{});
    return known.count(subscription_candidate_key(plan, index)) == 0;
}

SubscriptionRefreshService::SubscriptionRefreshService(
    std::shared_ptr<SubscriptionStore> store, SubscriptionFetcher fetcher,
    SubscriptionApplyUpdates apply_updates, SubscriptionReadTransports read_transports, Clock clock,
    AccessFactory access_factory)
    : store_(std::move(store)), fetcher_(std::move(fetcher)),
      apply_updates_(std::move(apply_updates)), read_transports_(std::move(read_transports)),
      clock_(clock ? std::move(clock) : Clock(current_time)),
      access_factory_(std::move(access_factory)) {}

json SubscriptionRefreshService::refresh(const std::string& id) {
    auto source = store_->find(id);
    const auto fetched_source_version = response_source_version(source);
    const auto fetched_url = source.at("url").get<std::string>();
    const auto checked_at = clock_();
    SubscriptionImportPlan plan;
    json metadata;
    try {
        const auto& url = fetched_url;
        if (url.size() > 4096U || classify_subscription_url(url) != SubscriptionUrlVerdict::allowed)
            throw std::invalid_argument("invalid subscription URL");
        const auto fetched = fetcher_(url);
        plan = plan_subscription_import(fetched.body, {}, {});
        metadata = subscription_refresh_metadata(fetched, plan, checked_at);
    } catch (const std::invalid_argument&) {
        metadata = {{"checked_at", checked_at}, {"error", "invalid_document"}};
    } catch (...) {
        metadata = {{"checked_at", checked_at}, {"error", "fetch_failed"}};
    }

    // HTTP never holds maintenance. Acquire the existing lease before reading
    // fresh metadata and retain it through manager updates and the final store
    // write. Restore holds the same lease, so no old binding can be committed
    // after it. Metadata-only refreshes do not reserve a config generation.
    auto access = access_factory_ ? access_factory_() : nullptr;
    if (access_factory_ && !access)
        throw std::runtime_error("subscription refresh access unavailable");
    if (access) access->verify_held();
    // A removed source is not resurrected. Compare against the version captured
    // before HTTP, not its completion time: another refresh or restore may have
    // replaced bindings for the same URL, even within the same clock second.
    source = store_->find(id);
    if (response_source_version(source) != fetched_source_version)
        return public_subscription(source);
    if (source.value("checked_at", std::int64_t{0}) > metadata.at("checked_at").get<std::int64_t>())
        return public_subscription(source);
    if (metadata.contains("error")) {
        if (access) access->verify_held();
        return store_->refresh(id, metadata);
    }
    auto bindings = source.value("_bindings", json::array());
    json binding_updates = json::array();
    std::string error;
    auto linked_tags = source.value("transport_tags", std::set<std::string>{});
    std::set<std::string> bound_tags;
    for (const auto& binding : bindings) bound_tags.insert(binding.at("tag").get<std::string>());
    std::optional<std::vector<SubscriptionTransportState>> transports;
    std::vector<std::string> confirmed_absent_tags;
    if (read_transports_ && (!linked_tags.empty() || !bound_tags.empty())) {
        try {
            transports = read_transports_();
            std::set<std::string> existing;
            for (const auto& transport : *transports) existing.insert(transport.tag);
            auto referenced = linked_tags;
            referenced.insert(bound_tags.begin(), bound_tags.end());
            for (const auto& tag : referenced) {
                if (existing.count(tag)) continue;
                confirmed_absent_tags.push_back(tag);
                linked_tags.erase(tag);
                bound_tags.erase(tag);
            }
            bindings.erase(std::remove_if(bindings.begin(), bindings.end(), [&](const auto& binding) {
                return existing.count(binding.at("tag").template get<std::string>()) == 0;
            }), bindings.end());
        } catch (...) { error = "transport_unavailable"; }
    }
    const bool needs_bootstrap = std::any_of(linked_tags.begin(), linked_tags.end(),
        [&](const auto& tag) { return bound_tags.count(tag) == 0; });
    if (needs_bootstrap) {
        if (!transports) error = "transport_unavailable";
        else try {
            for (const auto& transport : *transports) {
                if (!linked_tags.count(transport.tag) || bound_tags.count(transport.tag) ||
                    transport.fingerprint.empty()) continue;
                for (std::size_t i = 0; i < plan.candidates.size(); ++i) {
                    if (!inventory_candidate(plan.candidates[i]) ||
                        subscription_link_fingerprint(plan.links[i]) != transport.fingerprint) continue;
                    auto addition = subscription_import_bindings(plan, {{plan.candidates[i].source_line, transport.tag}});
                    for (const auto& binding : addition) {
                        bindings.push_back(binding);
                        binding_updates.push_back(binding);
                    }
                    bound_tags.insert(transport.tag);
                    break;
                }
            }
        } catch (...) { error = "transport_unavailable"; }
        if (error.empty() && std::any_of(linked_tags.begin(), linked_tags.end(),
            [&](const auto& tag) { return bound_tags.count(tag) == 0; }))
            error = "ambiguous_binding";
    }

    std::map<std::string, std::size_t> candidates;
    for (std::size_t i = 0; i < plan.candidates.size(); ++i)
        if (inventory_candidate(plan.candidates[i])) candidates.emplace(subscription_candidate_key(plan, i), i);
    std::vector<SubscriptionTransportUpdate> updates;
    for (const auto& binding : bindings) {
        const auto found = candidates.find(binding.at("key").get<std::string>());
        if (found == candidates.end()) {
            // A provider may rename its remark without changing the actual
            // connection. Keep the existing VPN and move only its inventory
            // identity, otherwise the identical connection becomes a pending
            // "new" row which the importer correctly marks already configured.
            std::optional<std::size_t> same_connection;
            bool ambiguous = false;
            for (std::size_t i = 0; i < plan.candidates.size(); ++i) {
                if (!inventory_candidate(plan.candidates[i]) ||
                    subscription_link_fingerprint(plan.links[i]) != binding.value("fingerprint", "")) continue;
                if (same_connection) { ambiguous = true; break; }
                same_connection = i;
            }
            if (same_connection && !ambiguous) {
                const auto index = *same_connection;
                binding_updates.push_back({{"tag", binding.at("tag")},
                    {"key", subscription_candidate_key(plan, index)},
                    {"fingerprint", binding.at("fingerprint")},
                    {"stable", stable_candidate(plan, index)}});
            }
        }
        // A provider removing an existing server must never remove its VPN.
        if (found == candidates.end()) continue;
        const auto index = found->second;
        const auto fingerprint = subscription_link_fingerprint(plan.links[index]);
        if (fingerprint == binding.value("fingerprint", "")) continue;
        if (!binding.value("stable", false) || !stable_candidate(plan, index)) {
            error = "ambiguous_binding";
            continue;
        }
        updates.push_back({binding.at("tag").get<std::string>(), plan.links[index],
            binding.value("fingerprint", ""), found->first, fingerprint});
    }
    if (!updates.empty()) {
        if (!apply_updates_) error = "apply_unavailable";
        else try {
            if (access) {
                (void)access->reserve(access->base_generation());
                access->verify_held();
            }
            const auto result = apply_updates_(updates);
            const std::set<std::string> applied(result.applied_tags.begin(), result.applied_tags.end());
            std::size_t applied_count = 0;
            for (const auto& update : updates)
                if (applied.count(update.tag)) {
                    ++applied_count;
                    binding_updates.push_back({{"tag", update.tag}, {"key", update.candidate_key},
                        {"fingerprint", update.next_fingerprint}, {"stable", true}});
                }
            if (!result.error_code.empty()) error = sync_error_code(result.error_code);
            else if (applied_count < updates.size()) error = "apply_failed";
        } catch (...) { error = "apply_failed"; }
    }
    metadata["_binding_updates"] = std::move(binding_updates);
    metadata["last_sync_error"] = error;
    if (access) access->verify_held();
    return store_->refresh(id, metadata, confirmed_absent_tags);
}

std::optional<json> SubscriptionRefreshService::refresh_due_once() {
    const auto source = store_->due(clock_());
    if (!source) return std::nullopt;
    return refresh(source->at("id").get<std::string>());
}

} // namespace keen_pbr3
