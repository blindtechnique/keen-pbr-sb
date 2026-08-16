#ifdef WITH_API

#include "handler_subscriptions.hpp"

#include "generated/api_types.hpp"
#include "maintenance_api.hpp"
#include "transport_manager_endpoint.hpp"

#include "../config/subscription_fetch_policy.hpp"
#include "../config/subscription_import_plan.hpp"
#include "../config/subscription_transport_naming.hpp"
#include "../http/http_client.hpp"
#include "../util/display_name.hpp"

#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <httplib.h>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

// A preview lives long enough for a human to read it and act, and no longer:
// the stored links carry credentials, and daemon memory is the only place
// they are allowed to exist outside transport-manager's own config.
constexpr std::chrono::seconds kPreviewTtl{600};
// An operator compares at most a couple of subscriptions at once. The cap is
// about bounding held credentials, not about capacity.
constexpr std::size_t kMaximumPreviews = 4U;

struct PreviewSession {
    std::chrono::steady_clock::time_point expires;
    SubscriptionImportPlan plan;
    // Lines already turned into transports by an apply. A preview is a
    // one-shot import: re-applying the same line must not duplicate the
    // transport it already created.
    std::set<std::size_t> consumed_lines;
};

struct PreviewRegistry {
    std::mutex mutex;
    std::map<std::string, PreviewSession> sessions;
};

PreviewRegistry& preview_registry() {
    static PreviewRegistry registry;
    return registry;
}

void purge_expired_locked(PreviewRegistry& registry,
                          const std::chrono::steady_clock::time_point now) {
    for (auto it = registry.sessions.begin();
         it != registry.sessions.end();) {
        if (it->second.expires <= now) {
            it = registry.sessions.erase(it);
        } else {
            ++it;
        }
    }
}

std::string random_preview_token() {
    std::array<unsigned char, 32> bytes{};
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        const auto received =
            ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received < 0 && errno == EINTR) continue;
        break;
    }
    if (offset < bytes.size()) {
        const int descriptor = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (descriptor < 0) {
            throw ApiError("cannot generate a preview identifier", 500);
        }
        while (offset < bytes.size()) {
            const auto received = ::read(
                descriptor, bytes.data() + offset, bytes.size() - offset);
            if (received > 0) {
                offset += static_cast<std::size_t>(received);
                continue;
            }
            if (received < 0 && errno == EINTR) continue;
            (void)::close(descriptor);
            throw ApiError("cannot generate a preview identifier", 500);
        }
        (void)::close(descriptor);
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string token(bytes.size() * 2U, '0');
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        token[index * 2U] = hex[bytes[index] >> 4U];
        token[index * 2U + 1U] = hex[bytes[index] & 0x0FU];
    }
    return token;
}

// The transports that already exist, as the two sets the plan and the naming
// need. Read from the manager's redacted state: the tags are public, and the
// identities arrive as link fingerprints precisely so this caller never has
// to see a link. They are sensitive internal metadata and never belong in a
// browser-facing response.
struct ExistingTransports {
    std::set<std::string> tags;
    std::set<std::string> interfaces;
    std::set<std::string> link_fingerprints;
};

ExistingTransports read_existing_transports(
    const TransportManagerEndpoint& endpoint) {
    httplib::Client client(endpoint.host, endpoint.port);
    client.set_connection_timeout(1, 0);
    client.set_read_timeout(5, 0);
    const httplib::Headers headers{
        {"Authorization", "Bearer " + endpoint.api_key},
    };
    const auto response = client.Get("/v1/config/transports", headers);
    if (!response) {
        throw ApiError("transport manager is unavailable", 503);
    }
    if (response->status < 200 || response->status >= 300) {
        throw ApiError("transport manager returned HTTP " +
                           std::to_string(response->status),
                       502);
    }
    ExistingTransports existing;
    try {
        const auto body = nlohmann::json::parse(response->body);
        if (!body.is_array()) {
            throw ApiError(
                "transport manager returned an invalid config response",
                502);
        }
        for (const auto& spec : body) {
            if (spec.contains("tag") && spec["tag"].is_string()) {
                existing.tags.insert(spec["tag"].get<std::string>());
            }
            if (spec.contains("interface") &&
                spec["interface"].is_string()) {
                existing.interfaces.insert(
                    spec["interface"].get<std::string>());
            }
            if (spec.contains("link_fingerprint") &&
                spec["link_fingerprint"].is_string()) {
                const auto fingerprint =
                    spec["link_fingerprint"].get<std::string>();
                if (!fingerprint.empty()) {
                    existing.link_fingerprints.insert(fingerprint);
                }
            }
        }
    } catch (const nlohmann::json::exception&) {
        throw ApiError("transport manager returned malformed JSON", 502);
    }
    return existing;
}

api::DocumentKind response_kind(
    const SubscriptionDocumentKind kind) {
    switch (kind) {
    case SubscriptionDocumentKind::link_list:
        return api::DocumentKind::LINK_LIST;
    case SubscriptionDocumentKind::base64_link_list:
        return api::DocumentKind::BASE64_LINK_LIST;
    case SubscriptionDocumentKind::json_document:
        return api::DocumentKind::JSON_DOCUMENT;
    case SubscriptionDocumentKind::empty:
        return api::DocumentKind::EMPTY;
    case SubscriptionDocumentKind::unrecognized:
        return api::DocumentKind::UNRECOGNIZED;
    case SubscriptionDocumentKind::too_large:
        return api::DocumentKind::TOO_LARGE;
    }
    return api::DocumentKind::UNRECOGNIZED;
}

api::Disposition response_disposition(
    const SubscriptionCandidateDisposition disposition) {
    switch (disposition) {
    case SubscriptionCandidateDisposition::importable:
        return api::Disposition::IMPORTABLE;
    case SubscriptionCandidateDisposition::duplicate_in_document:
        return api::Disposition::DUPLICATE_IN_DOCUMENT;
    case SubscriptionCandidateDisposition::already_configured:
        return api::Disposition::ALREADY_CONFIGURED;
    case SubscriptionCandidateDisposition::tag_conflict:
        return api::Disposition::TAG_CONFLICT;
    case SubscriptionCandidateDisposition::scheme_not_supported:
        return api::Disposition::SCHEME_NOT_SUPPORTED;
    case SubscriptionCandidateDisposition::malformed:
        return api::Disposition::MALFORMED;
    }
    return api::Disposition::MALFORMED;
}

bool valid_override_tag(const std::string& tag) {
    if (tag.empty() || tag.size() > 24U || tag.front() < 'a' ||
        tag.front() > 'z') {
        return false;
    }
    for (const char ch : tag) {
        const bool lowercase = ch >= 'a' && ch <= 'z';
        const bool digit = ch >= '0' && ch <= '9';
        if (!lowercase && !digit && ch != '_') return false;
    }
    return true;
}

// Manager response text is parser-controlled and can echo or transform any
// part of the credential-bearing link (percent-decoding is enough to defeat a
// substring filter). It belongs in the manager's root-only diagnostics, never
// in this browser-facing API.
std::string sanitized_manager_error(const int status) {
    return "transport manager refused this entry (HTTP " +
           std::to_string(status) + ")";
}

void register_subscriptions_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    SubscriptionFetcher fetcher) {
    server.post(
        "/api/subscriptions/preview",
        [&ctx, fetcher = std::move(fetcher)](
            const std::string& request_body) -> std::string {
            api::SubscriptionPreviewRequest request;
            try {
                request = nlohmann::json::parse(request_body)
                              .get<api::SubscriptionPreviewRequest>();
            } catch (const std::exception&) {
                throw ApiError(
                    "subscription preview requires a JSON body with a url",
                    400);
            }

            const auto verdict = classify_subscription_url(request.url);
            if (verdict != SubscriptionUrlVerdict::allowed) {
                throw ApiError(
                    std::string("subscription URL refused: ") +
                        subscription_url_verdict_name(verdict),
                    400,
                    nlohmann::json{
                        {"error", "subscription URL refused"},
                        {"reason", subscription_url_verdict_name(verdict)},
                    }
                        .dump());
            }

            // The manager is consulted before the fetch: without its tags and
            // fingerprints the plan cannot judge conflicts, and a preview
            // that silently skipped that judgement would read as "no
            // conflicts" - the false-green shape this API must not have.
            const auto endpoint =
                load_transport_manager_endpoint(ctx.config_path);
            const auto existing = read_existing_transports(endpoint);

            const std::string body = fetcher(request.url);
            auto plan = plan_subscription_import(
                body, existing.tags, existing.link_fingerprints);

            api::SubscriptionPreviewResponse response;
            response.document_kind = response_kind(plan.kind);
            response.expires_in_seconds = kPreviewTtl.count();
            response.preview_id = random_preview_token();
            response.candidates.reserve(plan.candidates.size());
            for (const auto& candidate : plan.candidates) {
                api::SubscriptionPreviewCandidate entry;
                entry.line = static_cast<int64_t>(candidate.source_line);
                entry.scheme = candidate.scheme;
                entry.endpoint = candidate.endpoint;
                entry.remark = candidate.remark;
                entry.suggested_tag = candidate.suggested_tag;
                entry.disposition =
                    response_disposition(candidate.disposition);
                if (candidate.disposition ==
                    SubscriptionCandidateDisposition::duplicate_in_document) {
                    // The plan records the index of the offered occurrence;
                    // the API speaks in document lines.
                    entry.duplicate_of = static_cast<int64_t>(
                        plan.candidates[candidate.duplicate_of]
                            .source_line);
                }
                response.candidates.push_back(std::move(entry));
            }

            {
                auto& registry = preview_registry();
                std::lock_guard<std::mutex> lock(registry.mutex);
                const auto now = std::chrono::steady_clock::now();
                purge_expired_locked(registry, now);
                while (registry.sessions.size() >= kMaximumPreviews) {
                    // Oldest first: the operator who opened four previews and
                    // starts a fifth has abandoned the first.
                    auto oldest = registry.sessions.begin();
                    for (auto it = registry.sessions.begin();
                         it != registry.sessions.end(); ++it) {
                        if (it->second.expires < oldest->second.expires) {
                            oldest = it;
                        }
                    }
                    registry.sessions.erase(oldest);
                }
                PreviewSession session;
                session.expires = now + kPreviewTtl;
                session.plan = std::move(plan);
                registry.sessions.emplace(response.preview_id,
                                          std::move(session));
            }

            return nlohmann::json(response).dump();
        });

    server.post(
        "/api/subscriptions/apply",
        [&ctx](const std::string& request_body) -> std::string {
            api::SubscriptionApplyRequest request;
            try {
                request = nlohmann::json::parse(request_body)
                              .get<api::SubscriptionApplyRequest>();
            } catch (const std::exception&) {
                throw ApiError(
                    "subscription apply requires a preview_id and selections",
                    400);
            }
            if (request.selections.empty()) {
                throw ApiError("subscription apply requires at least one "
                               "selection",
                               400);
            }
            {
                std::set<int64_t> seen;
                for (const auto& selection : request.selections) {
                    if (!seen.insert(selection.line).second) {
                        throw ApiError(
                            "subscription apply lists line " +
                                std::to_string(selection.line) + " twice",
                            400);
                    }
                }
            }

            // The selections are resolved against the session under its lock,
            // then the lock is dropped for the slow manager calls. Consumed
            // lines are only marked after the manager confirms creation.
            struct ResolvedEntry {
                std::size_t line;
                std::string link;
                std::string scheme;
                std::string remark;
                std::string tag;
            };
            std::vector<ResolvedEntry> entries;
            {
                auto& registry = preview_registry();
                std::lock_guard<std::mutex> lock(registry.mutex);
                purge_expired_locked(registry,
                                     std::chrono::steady_clock::now());
                const auto found =
                    registry.sessions.find(request.preview_id);
                if (found == registry.sessions.end()) {
                    throw ApiError(
                        "the subscription preview has expired; fetch it "
                        "again",
                        410);
                }
                const auto& session = found->second;
                for (const auto& selection : request.selections) {
                    const auto& candidates = session.plan.candidates;
                    std::size_t index = candidates.size();
                    for (std::size_t i = 0U; i < candidates.size(); ++i) {
                        if (static_cast<int64_t>(
                                candidates[i].source_line) ==
                            selection.line) {
                            index = i;
                            break;
                        }
                    }
                    if (index == candidates.size()) {
                        throw ApiError(
                            "line " + std::to_string(selection.line) +
                                " is not part of this preview",
                            400);
                    }
                    const auto& candidate = candidates[index];
                    const bool overridden =
                        selection.tag.has_value() &&
                        !selection.tag->empty();
                    if (overridden && !valid_override_tag(*selection.tag)) {
                        throw ApiError(
                            "line " + std::to_string(selection.line) +
                                ": the tag must match "
                                "^[a-z][a-z0-9_]{0,23}$",
                            400);
                    }
                    // tag_conflict is importable exactly when the operator
                    // resolved it by choosing another name; everything else
                    // that is not importable stays refused - importing a
                    // duplicate or an unsupported scheme does not become
                    // sensible because the caller insists.
                    const bool importable =
                        candidate.disposition ==
                            SubscriptionCandidateDisposition::importable ||
                        (candidate.disposition ==
                             SubscriptionCandidateDisposition::tag_conflict &&
                         overridden);
                    if (!importable) {
                        throw ApiError(
                            "line " + std::to_string(selection.line) +
                                " is not importable: " +
                                subscription_candidate_disposition_name(
                                    candidate.disposition),
                            400);
                    }
                    ResolvedEntry entry;
                    entry.line = candidate.source_line;
                    entry.link = session.plan.links[index];
                    entry.scheme = candidate.scheme;
                    entry.remark = candidate.remark;
                    entry.tag = overridden ? *selection.tag
                                           : candidate.suggested_tag;
                    entries.push_back(std::move(entry));
                }
            }

            const auto endpoint =
                load_transport_manager_endpoint(ctx.config_path);
            auto existing = read_existing_transports(endpoint);
            std::set<std::string> taken = existing.interfaces;
            taken.insert(existing.tags.begin(), existing.tags.end());

            try {
                auto maintenance =
                    ctx.acquire_maintenance_lease("subscription-import");
                (void)maintenance->reserve(maintenance->base_generation());

                httplib::Client client(endpoint.host, endpoint.port);
                client.set_connection_timeout(1, 0);
                client.set_read_timeout(15, 0);
                const httplib::Headers headers{
                    {"Authorization", "Bearer " + endpoint.api_key},
                };

                api::SubscriptionApplyResponse response;
                for (const auto& entry : entries) {
                    api::SubscriptionApplyResultElement result;
                    result.line = static_cast<int64_t>(entry.line);
                    result.tag = entry.tag;

                    bool already_consumed = false;
                    {
                        auto& registry = preview_registry();
                        std::lock_guard<std::mutex> lock(registry.mutex);
                        const auto found =
                            registry.sessions.find(request.preview_id);
                        already_consumed =
                            found != registry.sessions.end() &&
                            found->second.consumed_lines.count(
                                entry.line) != 0U;
                    }
                    if (already_consumed) {
                        // Not a failure: nothing went wrong and there is
                        // nothing to fix. Reporting it as one would teach
                        // the operator to distrust the report.
                        result.outcome = api::Outcome::ALREADY_IMPORTED;
                        response.results.push_back(std::move(result));
                        continue;
                    }

                    const std::string interface_name =
                        derive_subscription_interface(entry.scheme, taken);
                    if (interface_name.empty()) {
                        result.outcome = api::Outcome::FAILED;
                        result.error =
                            "no free interface name could be derived";
                        response.results.push_back(std::move(result));
                        continue;
                    }
                    result.interface = interface_name;

                    nlohmann::json spec{
                        {"tag", entry.tag},
                        {"type", "sing-box"},
                        {"interface", interface_name},
                        {"link", entry.link},
                        {"auto_start", false},
                    };
                    // The provider's label survives as the display alias when
                    // it is one the manager would accept; a name is never a
                    // reason to fail the import.
                    if (!entry.remark.empty() &&
                        display_name::is_valid(entry.remark, false)) {
                        spec["display_name"] = entry.remark;
                    }

                    const auto created = client.Post(
                        "/v1/config/transports",
                        headers,
                        spec.dump(),
                        "application/json");
                    if (!created) {
                        result.outcome = api::Outcome::FAILED;
                        result.error = "transport manager is unavailable";
                    } else if (created->status < 200 ||
                               created->status >= 300) {
                        result.outcome = api::Outcome::FAILED;
                        result.error =
                            sanitized_manager_error(created->status);
                    } else {
                        result.outcome = api::Outcome::CREATED;
                        taken.insert(entry.tag);
                        taken.insert(interface_name);
                        auto& registry = preview_registry();
                        std::lock_guard<std::mutex> lock(registry.mutex);
                        const auto found =
                            registry.sessions.find(request.preview_id);
                        if (found != registry.sessions.end()) {
                            found->second.consumed_lines.insert(entry.line);
                        }
                    }
                    response.results.push_back(std::move(result));
                }

                maintenance->verify_held();
                return nlohmann::json(response).dump();
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
        });
}

} // namespace

SubscriptionFetcher make_subscription_fetcher() {
    return [](const std::string& url) -> std::string {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(20));
        // The transport enforces the bound, so an oversized body fails whole
        // instead of arriving truncated and planning as a shorter document.
        client.set_max_response_size(kSubscriptionMaximumBytes);
        HttpRequestOptions options;
        options.destination_filter = [](const std::string& address) {
            return subscription_destination_permitted(address) ==
                   SubscriptionDestinationVerdict::allowed;
        };
        try {
            return client.download(url, options);
        } catch (const HttpError& error) {
            throw ApiError(
                std::string("subscription fetch failed: ") + error.what(),
                502);
        }
    };
}

void register_subscriptions_handler(ApiServer& server, ApiContext& ctx) {
    register_subscriptions_handler_impl(
        server, ctx, make_subscription_fetcher());
}

#ifdef KEEN_PBR3_TESTING
void register_subscriptions_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    SubscriptionFetcher fetcher) {
    register_subscriptions_handler_impl(server, ctx, std::move(fetcher));
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
