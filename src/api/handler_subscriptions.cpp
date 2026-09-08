#ifdef WITH_API

#include "handler_subscriptions.hpp"

#include "generated/api_types.hpp"
#include "handler_config.hpp"
#include "handler_transports.hpp"
#include "maintenance_api.hpp"
#include "operation_error.hpp"
#include "transport_manager_endpoint.hpp"

#include "../config/subscription_fetch_policy.hpp"
#include "../config/subscription_import_plan.hpp"
#include "../config/subscription_transport_naming.hpp"
#include "../config/subscription_store.hpp"
#include "../http/http_client.hpp"
#include "../util/display_name.hpp"

#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <httplib.h>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
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
// Eight isolated sing-box processes fit the smallest supported routers; a
// larger one-click auto-start batch can exhaust memory before the operator can
// disable any item. Larger subscriptions remain importable in bounded groups.
constexpr std::size_t kMaximumSubscriptionApplyEntries = 8U;

struct TransportIdentity {
    std::optional<std::string> tag;
    std::optional<std::string> interface_name;
};

struct PreviewSession {
    std::chrono::steady_clock::time_point expires;
    SubscriptionImportPlan plan;
    std::string source_url;
    nlohmann::json source_metadata;
    // The exact identities created for lines by an apply. A preview is a
    // one-shot import: re-applying a line must neither duplicate its transport
    // nor relabel that transport with a new override from the retry request.
    std::map<std::size_t, TransportIdentity> imported_lines;
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

// The transports that already exist, as the identities the plan, naming, and
// idempotent result need. Read from the manager's redacted state: tags and
// interfaces are public. Link identities arrive as fingerprints precisely so
// this caller never has to see a link. They are sensitive internal metadata
// and never belong in a browser-facing response.
struct ExistingTransports {
    std::set<std::string> tags;
    std::set<std::string> interfaces;
    std::set<std::string> link_fingerprints;
    std::map<std::string, TransportIdentity> identities_by_fingerprint;
};

void add_core_route_names(
    const Config& config,
    ExistingTransports& existing) {
    for (const auto& outbound :
         config.outbounds.value_or(std::vector<Outbound>{})) {
        existing.tags.insert(outbound.tag);
        if (outbound.type == OutboundType::INTERFACE &&
            outbound.interface.has_value() &&
            !outbound.interface->empty()) {
            existing.interfaces.insert(*outbound.interface);
        }
    }
}

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
        throw operation_error("transport manager is unavailable", 503,
                              "service_unavailable");
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
            TransportIdentity identity;
            if (spec.contains("tag") && spec["tag"].is_string()) {
                identity.tag = spec["tag"].get<std::string>();
                existing.tags.insert(*identity.tag);
            }
            if (spec.contains("interface") &&
                spec["interface"].is_string()) {
                identity.interface_name =
                    spec["interface"].get<std::string>();
                existing.interfaces.insert(*identity.interface_name);
            }
            if (spec.contains("link_fingerprint") &&
                spec["link_fingerprint"].is_string()) {
                const auto fingerprint =
                    spec["link_fingerprint"].get<std::string>();
                if (!fingerprint.empty()) {
                    existing.link_fingerprints.insert(fingerprint);
                    // The manager may expose a fingerprint without one of the
                    // public identity fields. Keep whatever it proved and omit
                    // the rest from an already-imported response.
                    const auto [stored, inserted] =
                        existing.identities_by_fingerprint.try_emplace(
                            fingerprint, std::move(identity));
                    if (!inserted) {
                        // A fingerprint still proves that no POST is needed,
                        // but it cannot identify one transport when the
                        // manager reports more than one match. Do not pick an
                        // arbitrary public identity and present it as actual.
                        stored->second = TransportIdentity{};
                    }
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

class SubscriptionApplyNoMutation final : public std::exception {
public:
    const char* what() const noexcept override {
        return "subscription selection needs no mutation";
    }
};

std::int64_t subscription_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void validate_source_url(const std::string& url) {
    if (url.size() > 4096U || classify_subscription_url(url) != SubscriptionUrlVerdict::allowed)
        throw ApiError("invalid subscription URL", 400);
}

nlohmann::json subscription_metadata(const SubscriptionFetchResult& fetched,
                                     const SubscriptionImportPlan& plan) {
    try { return subscription_refresh_metadata(fetched, plan, subscription_now()); }
    catch (const std::invalid_argument&) { throw ApiError("invalid subscription document", 400); }
}

template <typename Function>
std::string subscription_store_call(Function&& function) {
    try { return function().dump(); }
    catch (const ApiError&) { throw; }
    catch (const nlohmann::json::exception&) { throw ApiError("invalid subscription data", 400); }
    catch (const std::out_of_range&) { throw ApiError("subscription not found", 404); }
    catch (const std::invalid_argument&) { throw ApiError("invalid subscription data", 400); }
    catch (...) { throw ApiError("cannot save subscription metadata", 500); }
}

void register_subscriptions_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    SubscriptionFetcher fetcher,
    std::function<std::string(
        ApiContext&,
        std::string,
        PrepareConfigCommit)> commit_config) {
    const auto service = ctx.subscription_refresh_service ? ctx.subscription_refresh_service :
        std::make_shared<SubscriptionRefreshService>(std::make_shared<SubscriptionStore>(
            (std::filesystem::path(ctx.config_path).parent_path() / "subscriptions.json").string()), fetcher);
    const auto store = service->store();
    server.get("/api/subscriptions", [store]() {
        return subscription_store_call([&] { return store->list(); });
    });
    server.post("/api/subscriptions", [&ctx, store, fetcher](const std::string& body) {
        return subscription_store_call([&] {
            const auto request = nlohmann::json::parse(body);
            const auto url = request.at("url").get<std::string>();
            const auto name = request.value("name", "");
            validate_source_url(url);
            if (!name.empty() && !display_name::is_valid(name, false))
                throw ApiError("invalid subscription name", 400);
            const auto fetched = fetcher(url);
            const auto plan = plan_subscription_import(fetched.body, {}, {});
            const auto metadata = subscription_metadata(fetched, plan);
            std::vector<std::string> tags;
            std::map<std::size_t, std::string> tags_by_line;
            // Linking an old import is advisory and read-only. An unavailable
            // manager does not prevent saving provider limits and the source.
            try {
                const auto existing = read_existing_transports(load_transport_manager_endpoint(ctx.config_path));
                for (std::size_t i = 0; i < plan.links.size(); ++i) {
                    const auto it = existing.identities_by_fingerprint.find(subscription_link_fingerprint(plan.links[i]));
                    if (it != existing.identities_by_fingerprint.end() && it->second.tag) {
                        tags.push_back(*it->second.tag);
                        tags_by_line.emplace(plan.candidates[i].source_line, *it->second.tag);
                    }
                }
            } catch (...) {}
            return store->save(url, name, metadata, tags, subscription_import_bindings(plan, tags_by_line));
        });
    });
    server.post("/api/subscriptions/refresh", [service](const std::string& body) {
        return subscription_store_call([&] {
            const auto id = nlohmann::json::parse(body).at("id").get<std::string>();
            return service->refresh(id);
        });
    });
    server.post("/api/subscriptions/settings", [store](const std::string& body) {
        return subscription_store_call([&] {
            const auto request = nlohmann::json::parse(body);
            const auto& interval = request.at("refresh_interval_seconds");
            if (!interval.is_number_integer()) throw ApiError("invalid subscription refresh interval", 400);
            return store->set_refresh_interval(request.at("id").get<std::string>(), interval.get<std::int64_t>());
        });
    });
    server.post("/api/subscriptions/rename", [store](const std::string& body) {
        return subscription_store_call([&] {
            const auto request = nlohmann::json::parse(body);
            return store->rename(request.at("id").get<std::string>(), request.at("name").get<std::string>());
        });
    });
    server.post("/api/subscriptions/remove", [store](const std::string& body) {
        return subscription_store_call([&] {
            store->erase(nlohmann::json::parse(body).at("id").get<std::string>());
            return nlohmann::json{{"ok", true}};
        });
    });
    server.post(
        "/api/subscriptions/preview",
        [&ctx, store, fetcher = std::move(fetcher)](
            const std::string& request_body) -> std::string {
            api::SubscriptionPreviewRequest request;
            try {
                request = nlohmann::json::parse(request_body)
                              .get<api::SubscriptionPreviewRequest>();
            } catch (const std::exception&) {
                throw ApiError(
                    "subscription preview requires a JSON body with a url, "
                    "document or subscription_id",
                    400);
            }

            const bool has_url =
                request.url.has_value() && !request.url->empty();
            const bool has_document =
                request.document.has_value() && !request.document->empty();
            const bool has_source = request.subscription_id.has_value() && !request.subscription_id->empty();
            // Exactly one, and said so rather than picking a winner: a request
            // carrying both is a caller that does not know which source it
            // meant, and guessing for them would import from a source they did
            // not choose.
            if (static_cast<int>(has_url) + static_cast<int>(has_document) + static_cast<int>(has_source) != 1) {
                throw ApiError(
                    "subscription preview takes exactly one of url, "
                    "document or subscription_id",
                    400);
            }
            if (request.pending_only.value_or(false) && !has_source)
                throw ApiError("pending subscription preview requires a subscription_id", 400);
            nlohmann::json source;
            std::string source_url = request.url.value_or("");
            if (has_source) {
                try { source = store->find(*request.subscription_id); }
                catch (const std::out_of_range&) { throw ApiError("subscription not found", 404); }
                source_url = source.at("url").get<std::string>();
            }

            if (!source_url.empty()) {
                const auto verdict = classify_subscription_url(source_url);
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
            }

            // The manager is consulted before the fetch: without its tags and
            // fingerprints the plan cannot judge conflicts, and a preview
            // that silently skipped that judgement would read as "no
            // conflicts" - the false-green shape this API must not have.
            //
            // Consulted for a document too. The document is not fetched, but
            // the conflicts it can create are the same ones, and a file import
            // that skipped the judgement would be exactly the false green a
            // URL import is not allowed to be.
            const auto endpoint =
                load_transport_manager_endpoint(ctx.config_path);
            auto existing = read_existing_transports(endpoint);
            add_core_route_names(ctx.get_visible_config(), existing);

            // No size check here on purpose. plan_subscription_import already
            // refuses a body over kSubscriptionMaximumBytes and says so as
            // document_kind `too_large`, which is a better answer than a bare
            // 400 - the operator learns what was wrong with their file. A
            // second bound here would be the same contract written twice, and
            // the copy that drifts is always the one nobody is looking at.
            const auto fetched = !source_url.empty() ? fetcher(source_url)
                                        : SubscriptionFetchResult(*request.document);
            auto plan = plan_subscription_import(
                fetched.body, existing.tags, existing.link_fingerprints);

            api::SubscriptionPreviewResponse response;
            response.document_kind = response_kind(plan.kind);
            response.expires_in_seconds = kPreviewTtl.count();
            response.preview_id = random_preview_token();
            const auto title_header = fetched.headers.find("profile-title");
            const auto title = parse_subscription_title(
                title_header == fetched.headers.end() ? "" : title_header->second);
            if (!title.empty()) response.subscription_name = title;
            response.candidates.reserve(plan.candidates.size());
            for (std::size_t index = 0; index < plan.candidates.size(); ++index) {
                const auto& candidate = plan.candidates[index];
                if (request.pending_only.value_or(false) && !subscription_candidate_pending(source, plan, index)) continue;
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
                if (!source_url.empty()) {
                    session.source_url = source_url;
                    // Invalid documents still get their existing explanatory
                    // preview; they cannot reach a successful apply.
                    if (plan.kind == SubscriptionDocumentKind::link_list ||
                        plan.kind == SubscriptionDocumentKind::base64_link_list)
                        session.source_metadata = subscription_metadata(fetched, plan);
                }
                session.plan = std::move(plan);
                registry.sessions.emplace(response.preview_id,
                                          std::move(session));
            }

            return nlohmann::json(response).dump();
        });

    server.post(
        "/api/subscriptions/apply",
        [&ctx, store,
         commit_config](const std::string& request_body) -> std::string {
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
            if (request.subscription_name && !request.subscription_name->empty() &&
                !display_name::is_valid(*request.subscription_name, false))
                throw ApiError("invalid subscription name", 400);
            if (request.selections.size() >
                kMaximumSubscriptionApplyEntries) {
                throw ApiError(
                    "select at most 8 connections per import",
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
                std::string endpoint;
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
                    throw operation_error(
                        "the subscription preview has expired; fetch it "
                        "again",
                        410, "preview_expired");
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
                    entry.endpoint = candidate.endpoint;
                    entry.tag = overridden ? *selection.tag
                                           : candidate.suggested_tag;
                    entries.push_back(std::move(entry));
                }
            }

            api::SubscriptionApplyResponse response;
            const auto finish_response = [&]() -> std::string {
                std::string url;
                nlohmann::json metadata;
                std::map<std::size_t, std::string> tags_by_line;
                for (const auto& result : response.results)
                    if (result.outcome != api::Outcome::FAILED && result.tag)
                        tags_by_line.emplace(static_cast<std::size_t>(result.line), *result.tag);
                nlohmann::json bindings = nlohmann::json::array();
                {
                    auto& registry = preview_registry();
                    std::lock_guard<std::mutex> lock(registry.mutex);
                    const auto found = registry.sessions.find(request.preview_id);
                    if (found != registry.sessions.end()) {
                        url = found->second.source_url;
                        metadata = found->second.source_metadata;
                        bindings = subscription_import_bindings(found->second.plan, tags_by_line);
                    }
                }
                std::vector<std::string> tags;
                for (const auto& result : response.results)
                    if (result.outcome != api::Outcome::FAILED && result.tag) tags.push_back(*result.tag);
                auto output = nlohmann::json(response);
                output.erase("subscription_error");
                if (!url.empty() && !tags.empty()) {
                    try {
                        store->save(url, request.subscription_name.value_or(""), metadata, tags, bindings);
                    } catch (...) {
                        // VPN creation already succeeded. Do not turn a failed
                        // metadata write into a failed/retryable VPN import.
                        output["subscription_error"] = "metadata_save_failed";
                    }
                }
                return output.dump();
            };
            const auto remember_import =
                [&request](const std::size_t line,
                           TransportIdentity identity) {
                    auto& registry = preview_registry();
                    std::lock_guard<std::mutex> lock(registry.mutex);
                    const auto found =
                        registry.sessions.find(request.preview_id);
                    if (found != registry.sessions.end()) {
                        found->second.imported_lines.insert_or_assign(
                            line, std::move(identity));
                    }
                };

            std::vector<ResolvedEntry> pending;
            for (auto& entry : entries) {
                std::optional<TransportIdentity> imported_identity;
                {
                    auto& registry = preview_registry();
                    std::lock_guard<std::mutex> lock(registry.mutex);
                    const auto found =
                        registry.sessions.find(request.preview_id);
                    if (found != registry.sessions.end()) {
                        const auto imported =
                            found->second.imported_lines.find(entry.line);
                        if (imported !=
                            found->second.imported_lines.end()) {
                            imported_identity = imported->second;
                        }
                    }
                }
                if (!imported_identity.has_value()) {
                    pending.push_back(std::move(entry));
                    continue;
                }
                api::SubscriptionApplyResultElement result;
                result.line = static_cast<int64_t>(entry.line);
                result.outcome = api::Outcome::ALREADY_IMPORTED;
                result.tag = imported_identity->tag;
                result.interface = imported_identity->interface_name;
                response.results.push_back(std::move(result));
            }
            if (pending.empty()) {
                return finish_response();
            }

            struct PlannedCreate {
                std::size_t line;
                std::string tag;
                std::string interface_name;
            };
            std::vector<PlannedCreate> planned;
            try {
                (void)commit_config(
                    ctx,
                    "subscription-import",
                    [&]() -> PreparedConfigCommit {
                        // Preview state is advisory. Refresh identities and
                        // derived names only after the existing composite
                        // commit owns maintenance + runtime admission.
                        const auto endpoint =
                            load_transport_manager_endpoint(ctx.config_path);
                        auto existing =
                            read_existing_transports(endpoint);
                        add_core_route_names(
                            ctx.get_visible_config(), existing);
                        std::set<std::string> taken = existing.interfaces;
                        taken.insert(existing.tags.begin(),
                                     existing.tags.end());

                        std::vector<LinkedTransportCreate> creates;
                        for (const auto& entry : pending) {
                            const auto fingerprint =
                                subscription_link_fingerprint(entry.link);
                            if (fingerprint.empty()) {
                                api::SubscriptionApplyResultElement result;
                                result.line =
                                    static_cast<int64_t>(entry.line);
                                result.outcome = api::Outcome::FAILED;
                                result.error =
                                    "cannot derive link identity";
                                result.code = "invalid_connection";
                                response.results.push_back(
                                    std::move(result));
                                continue;
                            }
                            if (existing.link_fingerprints.count(
                                    fingerprint) != 0U) {
                                TransportIdentity identity;
                                const auto actual =
                                    existing.identities_by_fingerprint.find(
                                        fingerprint);
                                if (actual !=
                                    existing.identities_by_fingerprint.end()) {
                                    identity = actual->second;
                                }
                                api::SubscriptionApplyResultElement result;
                                result.line =
                                    static_cast<int64_t>(entry.line);
                                result.outcome =
                                    api::Outcome::ALREADY_IMPORTED;
                                result.tag = identity.tag;
                                result.interface = identity.interface_name;
                                remember_import(
                                    entry.line, std::move(identity));
                                response.results.push_back(
                                    std::move(result));
                                continue;
                            }

                            if (taken.count(entry.tag) != 0U) {
                                api::SubscriptionApplyResultElement result;
                                result.line =
                                    static_cast<int64_t>(entry.line);
                                result.outcome = api::Outcome::FAILED;
                                result.error = "name is already in use";
                                result.code = "name_in_use";
                                response.results.push_back(
                                    std::move(result));
                                continue;
                            }

                            const auto interface_name =
                                derive_subscription_interface(
                                    entry.scheme, taken);
                            if (interface_name.empty()) {
                                api::SubscriptionApplyResultElement result;
                                result.line =
                                    static_cast<int64_t>(entry.line);
                                result.outcome = api::Outcome::FAILED;
                                result.error =
                                    "no free interface name could be derived";
                                result.code = "no_interface_name";
                                response.results.push_back(
                                    std::move(result));
                                continue;
                            }

                            const auto alias =
                                !entry.remark.empty() &&
                                        display_name::is_valid(
                                            entry.remark, false)
                                    ? entry.remark
                                    : (!entry.endpoint.empty() &&
                                               display_name::is_valid(
                                                   entry.endpoint, false)
                                           ? entry.endpoint
                                           : std::string{});
                            nlohmann::json spec{
                                {"tag", entry.tag},
                                {"type", "sing-box"},
                                {"interface", interface_name},
                                {"link", entry.link},
                                {"auto_start", true},
                            };
                            if (!alias.empty()) {
                                spec["display_name"] = alias;
                            }
                            LinkedTransportCreate create;
                            create.transport = std::move(spec);
                            if (!alias.empty()) {
                                create.display_name = alias;
                            }
                            creates.push_back(std::move(create));
                            planned.push_back(
                                {entry.line, entry.tag, interface_name});
                            taken.insert(entry.tag);
                            taken.insert(interface_name);
                            existing.link_fingerprints.insert(fingerprint);
                        }
                        if (creates.empty()) {
                            throw SubscriptionApplyNoMutation{};
                        }
                        const auto valid =
                            validate_linked_transport_create_items(
                                ctx, creates);
                        std::vector<LinkedTransportCreate>
                            accepted_creates;
                        std::vector<PlannedCreate> accepted_planned;
                        accepted_creates.reserve(creates.size());
                        accepted_planned.reserve(planned.size());
                        for (std::size_t index = 0U;
                             index < creates.size();
                             ++index) {
                            if (valid[index]) {
                                accepted_creates.push_back(
                                    std::move(creates[index]));
                                accepted_planned.push_back(
                                    std::move(planned[index]));
                                continue;
                            }
                            api::SubscriptionApplyResultElement result;
                            result.line = static_cast<int64_t>(
                                planned[index].line);
                            result.outcome = api::Outcome::FAILED;
                            result.error =
                                "connection data was not accepted";
                            result.code = "invalid_connection";
                            response.results.push_back(
                                std::move(result));
                        }
                        creates = std::move(accepted_creates);
                        planned = std::move(accepted_planned);
                        if (creates.empty()) {
                            throw SubscriptionApplyNoMutation{};
                        }
                        return prepare_linked_transport_creates(
                            ctx, std::move(creates));
                    });
            } catch (const SubscriptionApplyNoMutation&) {
                return finish_response();
            }

            for (const auto& created : planned) {
                api::SubscriptionApplyResultElement result;
                result.line = static_cast<int64_t>(created.line);
                result.outcome = api::Outcome::CREATED;
                result.tag = created.tag;
                result.interface = created.interface_name;
                response.results.push_back(std::move(result));
                remember_import(
                    created.line,
                    TransportIdentity{
                        created.tag, created.interface_name});
            }
            return finish_response();
        });
}

} // namespace

SubscriptionFetcher make_subscription_fetcher() {
    return [](const std::string& url) -> SubscriptionFetchResult {
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
            auto response = client.download_response(url, options);
            SubscriptionFetchResult result(std::move(response.body));
            result.headers = std::move(response.headers);
            return result;
        } catch (const HttpError& error) {
            throw operation_error(
                std::string("subscription fetch failed") +
                    (error.status_code() > 0 ? ": HTTP " + std::to_string(error.status_code()) :
                     std::string(error.what()).find("destination policy") != std::string::npos ?
                     ": destination policy" : ""),
                502, "subscription_unavailable");
        }
    };
}

void register_subscriptions_handler(ApiServer& server, ApiContext& ctx) {
    register_subscriptions_handler_impl(
        server,
        ctx,
        make_subscription_fetcher(),
        [](ApiContext& commit_ctx,
           std::string operation,
           PrepareConfigCommit prepare) {
            return commit_prepared_config(
                commit_ctx,
                std::move(operation),
                std::move(prepare));
        });
}

#ifdef KEEN_PBR3_TESTING
void register_subscriptions_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    SubscriptionFetcher fetcher,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options) {
    register_subscriptions_handler_impl(
        server,
        ctx,
        std::move(fetcher),
        [write_config_file = std::move(write_config_file),
         options = std::move(options)](
            ApiContext& commit_ctx,
            std::string operation,
            PrepareConfigCommit prepare) {
            return commit_prepared_config_for_test(
                commit_ctx,
                std::move(operation),
                std::move(prepare),
                write_config_file,
                options);
        });
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
