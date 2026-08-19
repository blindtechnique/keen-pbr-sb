#ifdef WITH_API

#include "handler_catalog_setup.hpp"

#include "handler_catalog.hpp"
#include "../crypto/sha256.hpp"
#include "../setup/catalog_setup_planner.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <utility>

namespace keen_pbr3 {

namespace {

using setup::CatalogDnsMode;
using setup::CatalogPresetSelection;
using setup::CatalogSetupErrorCode;
using setup::CatalogSetupIntent;
using setup::CatalogSetupMode;
using setup::CatalogSetupPlan;
using setup::CatalogSetupPlanError;
using setup::CatalogSetupWarningCode;

using CommitCatalogSetup = std::function<std::string(
    ApiContext&,
    std::string,
    PrepareConfigCommit)>;

struct CatalogSetupApplyRequest {
    CatalogSetupIntent intent;
    std::string base_revision;
    std::string candidate_revision;
    std::string preview_token;
    bool accept_warnings{false};
};

[[noreturn]] void bad_request(
    std::string message,
    std::string path = "$") {
    throw ApiError(
        message,
        400,
        nlohmann::json{
            {"error", message},
            {"path", std::move(path)},
        }
            .dump());
}

const nlohmann::json& required_object(
    const nlohmann::json& object,
    const char* key,
    const std::string& path) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_object()) {
        bad_request(
            std::string("Field '") + key + "' must be an object",
            path + "." + key);
    }
    return *found;
}

std::string required_string(
    const nlohmann::json& object,
    const char* key,
    const std::string& path) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_string() ||
        found->get_ref<const std::string&>().empty()) {
        bad_request(
            std::string("Field '") + key +
                "' must be a non-empty string",
            path + "." + key);
    }
    return found->get<std::string>();
}

std::optional<std::string> optional_string(
    const nlohmann::json& object,
    const char* key,
    const std::string& path) {
    const auto found = object.find(key);
    if (found == object.end() || found->is_null()) return std::nullopt;
    if (!found->is_string()) {
        bad_request(
            std::string("Field '") + key +
                "' must be a string or null",
            path + "." + key);
    }
    return found->get<std::string>();
}

CatalogSetupMode parse_mode(const nlohmann::json& intent) {
    const auto mode = required_string(intent, "mode", "$.intent");
    if (mode == "none") return CatalogSetupMode::none;
    if (mode == "outbound") return CatalogSetupMode::outbound;
    if (mode == "block") return CatalogSetupMode::block;
    if (mode == "direct") return CatalogSetupMode::direct;
    bad_request(
        "Unsupported catalog setup mode '" + mode + "'",
        "$.intent.mode");
}

CatalogDnsMode parse_dns_mode(const nlohmann::json& intent) {
    const auto mode = required_string(intent, "dns_mode", "$.intent");
    if (mode == "none") return CatalogDnsMode::none;
    if (mode == "automatic") return CatalogDnsMode::automatic;
    if (mode == "explicit_server") {
        return CatalogDnsMode::explicit_server;
    }
    bad_request(
        "Unsupported catalog DNS mode '" + mode + "'",
        "$.intent.dns_mode");
}

CatalogSetupIntent parse_intent(const nlohmann::json& value) {
    if (!value.is_object()) {
        bad_request("Catalog setup intent must be an object", "$.intent");
    }

    CatalogSetupIntent intent;
    const auto selections = value.find("selections");
    if (selections == value.end() || !selections->is_array()) {
        bad_request(
            "Field 'selections' must be an array",
            "$.intent.selections");
    }
    intent.selections.reserve(selections->size());
    for (std::size_t index = 0; index < selections->size(); ++index) {
        const auto& selection = selections->at(index);
        const auto path =
            "$.intent.selections[" + std::to_string(index) + "]";
        if (!selection.is_object()) {
            bad_request("Catalog selection must be an object", path);
        }
        CatalogPresetSelection parsed;
        parsed.preset_id =
            required_string(selection, "preset_id", path);
        parsed.display_name =
            optional_string(selection, "display_name", path);
        intent.selections.push_back(std::move(parsed));
    }

    intent.mode = parse_mode(value);
    intent.outbound_tag =
        optional_string(value, "outbound_tag", "$.intent");
    intent.dns_mode = parse_dns_mode(value);
    intent.dns_server_tag =
        optional_string(value, "dns_server_tag", "$.intent");
    intent.source_detour_tag =
        optional_string(value, "source_detour_tag", "$.intent");
    intent.route_display_name =
        optional_string(value, "route_display_name", "$.intent");
    intent.dns_display_name =
        optional_string(value, "dns_display_name", "$.intent");
    return intent;
}

nlohmann::json parse_request_body(const std::string& body) {
    try {
        auto request = nlohmann::json::parse(body);
        if (!request.is_object()) {
            bad_request("Request body must be a JSON object");
        }
        return request;
    } catch (const ApiError&) {
        throw;
    } catch (const nlohmann::json::exception& error) {
        bad_request(
            std::string("Invalid JSON request: ") + error.what());
    }
}

bool is_sha256(const std::string& value) {
    return value.size() == 64U &&
           std::all_of(
               value.begin(),
               value.end(),
               [](const unsigned char character) {
                   return std::isdigit(character) != 0 ||
                          (character >= 'a' && character <= 'f');
               });
}

CatalogSetupApplyRequest parse_apply_request(
    const nlohmann::json& request) {
    CatalogSetupApplyRequest result;
    result.intent =
        parse_intent(required_object(request, "intent", "$"));
    result.base_revision =
        required_string(request, "base_revision", "$");
    result.candidate_revision =
        required_string(request, "candidate_revision", "$");
    result.preview_token =
        required_string(request, "preview_token", "$");
    if (!is_sha256(result.base_revision)) {
        bad_request(
            "base_revision must be a lowercase SHA-256 digest",
            "$.base_revision");
    }
    if (!is_sha256(result.candidate_revision)) {
        bad_request(
            "candidate_revision must be a lowercase SHA-256 digest",
            "$.candidate_revision");
    }
    if (!is_sha256(result.preview_token)) {
        bad_request(
            "preview_token must be a lowercase SHA-256 digest",
            "$.preview_token");
    }

    const auto accept = request.find("accept_warnings");
    if (accept != request.end()) {
        if (!accept->is_boolean()) {
            bad_request(
                "accept_warnings must be a boolean",
                "$.accept_warnings");
        }
        result.accept_warnings = accept->get<bool>();
    }
    return result;
}

const char* mode_name(CatalogSetupMode mode) {
    switch (mode) {
    case CatalogSetupMode::none:
        return "none";
    case CatalogSetupMode::outbound:
        return "outbound";
    case CatalogSetupMode::block:
        return "block";
    case CatalogSetupMode::direct:
        return "direct";
    }
    return "none";
}

const char* warning_code_name(CatalogSetupWarningCode code) {
    switch (code) {
    case CatalogSetupWarningCode::source_detour_not_found:
        return "source_detour_not_found";
    case CatalogSetupWarningCode::source_detour_not_routable:
        return "source_detour_not_routable";
    case CatalogSetupWarningCode::source_detour_not_applicable:
        return "source_detour_not_applicable";
    case CatalogSetupWarningCode::dns_automatic_unavailable:
        return "dns_automatic_unavailable";
    case CatalogSetupWarningCode::dns_ignored_for_block:
        return "dns_ignored_for_block";
    case CatalogSetupWarningCode::dns_detour_missing:
        return "dns_detour_missing";
    case CatalogSetupWarningCode::dns_detour_mismatch:
        return "dns_detour_mismatch";
    case CatalogSetupWarningCode::broad_traffic_scope:
        return "broad_traffic_scope";
    }
    return "unknown";
}

const char* error_code_name(CatalogSetupErrorCode code) {
    switch (code) {
    case CatalogSetupErrorCode::invalid_catalog_snapshot:
        return "invalid_catalog_snapshot";
    case CatalogSetupErrorCode::empty_selection:
        return "empty_selection";
    case CatalogSetupErrorCode::duplicate_selection:
        return "duplicate_selection";
    case CatalogSetupErrorCode::preset_not_found:
        return "preset_not_found";
    case CatalogSetupErrorCode::malformed_preset:
        return "malformed_preset";
    case CatalogSetupErrorCode::mixed_catalog_actions:
        return "mixed_catalog_actions";
    case CatalogSetupErrorCode::incompatible_intent:
        return "incompatible_intent";
    case CatalogSetupErrorCode::outbound_required:
        return "outbound_required";
    case CatalogSetupErrorCode::outbound_not_found:
        return "outbound_not_found";
    case CatalogSetupErrorCode::outbound_not_routable:
        return "outbound_not_routable";
    case CatalogSetupErrorCode::dns_server_required:
        return "dns_server_required";
    case CatalogSetupErrorCode::dns_server_not_found:
        return "dns_server_not_found";
    case CatalogSetupErrorCode::dns_automatic_unavailable:
        return "dns_automatic_unavailable";
    case CatalogSetupErrorCode::dns_detour_mismatch:
        return "dns_detour_mismatch";
    }
    return "unknown";
}

nlohmann::json summary_json(const CatalogSetupPlan& plan) {
    nlohmann::json lists = nlohmann::json::array();
    for (const auto& list : plan.summary.lists) {
        nlohmann::json item = {
            {"preset_id", list.preset_id},
            {"technical_id", list.technical_id},
            {"display_name", list.display_name},
            {"already_installed", list.already_installed},
            {"url_backed", list.url_backed},
            {"has_inline_domains", list.has_inline_domains},
            {"has_inline_cidrs", list.has_inline_cidrs},
        };
        if (list.source_detour.has_value()) {
            item["source_detour"] = *list.source_detour;
        }
        lists.push_back(std::move(item));
    }

    nlohmann::json summary = {
        {"mode", mode_name(plan.summary.mode)},
        {"lists", std::move(lists)},
    };
    nlohmann::json route_rules = nlohmann::json::array();
    for (const auto& route : plan.summary.route_rules) {
        route_rules.push_back({
            {"technical_id", route.technical_id},
            {"display_name", route.display_name},
            {"outbound", route.outbound},
            {"insertion_index", route.insertion_index},
            {"blocking", route.blocking},
        });
    }
    if (!route_rules.empty()) {
        summary["route_rules"] = std::move(route_rules);
    }
    nlohmann::json dns_rules = nlohmann::json::array();
    for (const auto& dns : plan.summary.dns_rules) {
        dns_rules.push_back({
            {"technical_id", dns.technical_id},
            {"display_name", dns.display_name},
            {"server", dns.server},
            {"insertion_index", dns.insertion_index},
        });
    }
    if (!dns_rules.empty()) {
        summary["dns_rules"] = std::move(dns_rules);
    }
    if (plan.summary.route_rule.has_value()) {
        const auto& route = *plan.summary.route_rule;
        summary["route_rule"] = {
            {"technical_id", route.technical_id},
            {"display_name", route.display_name},
            {"outbound", route.outbound},
            {"insertion_index", route.insertion_index},
            {"blocking", route.blocking},
        };
    }
    if (plan.summary.dns_rule.has_value()) {
        const auto& dns = *plan.summary.dns_rule;
        summary["dns_rule"] = {
            {"technical_id", dns.technical_id},
            {"display_name", dns.display_name},
            {"server", dns.server},
            {"insertion_index", dns.insertion_index},
        };
    }
    if (plan.summary.dns_server.has_value()) {
        const auto& dns = *plan.summary.dns_server;
        summary["dns_server"] = {
            {"technical_id", dns.technical_id},
            {"display_name", dns.display_name},
            {"address", dns.address},
            {"detour", dns.detour},
            {"created", dns.created},
        };
    }
    if (plan.summary.blackhole.has_value()) {
        summary["blackhole"] = {
            {"tag", plan.summary.blackhole->tag},
            {"created", plan.summary.blackhole->created},
        };
    }
    if (plan.summary.direct_outbound.has_value()) {
        summary["direct_outbound"] = {
            {"tag", plan.summary.direct_outbound->tag},
            {"created", plan.summary.direct_outbound->created},
        };
    }
    return summary;
}

nlohmann::json warnings_json(const CatalogSetupPlan& plan) {
    nlohmann::json warnings = nlohmann::json::array();
    for (const auto& warning : plan.warnings) {
        warnings.push_back({
            {"code", warning_code_name(warning.code)},
            {"path", warning.path},
            {"message", warning.message},
        });
    }
    return warnings;
}

bool catalog_plan_has_changes(const CatalogSetupPlan& plan) {
    return std::any_of(
               plan.summary.lists.begin(),
               plan.summary.lists.end(),
               [](const setup::CatalogListPlanSummary& list) {
                   return !list.already_installed;
               }) ||
           plan.summary.route_rule.has_value() ||
           plan.summary.dns_rule.has_value() ||
           !plan.summary.route_rules.empty() ||
           !plan.summary.dns_rules.empty() ||
           (plan.summary.dns_server.has_value() &&
            plan.summary.dns_server->created) ||
           (plan.summary.blackhole.has_value() &&
            plan.summary.blackhole->created) ||
           (plan.summary.direct_outbound.has_value() &&
            plan.summary.direct_outbound->created);
}

struct CatalogSetupPreview {
    CatalogSetupPlan plan;
    std::string base_revision;
    nlohmann::json summary;
    nlohmann::json warnings;
    std::string preview_token;
};

CatalogSetupPreview build_preview(
    const CatalogSetupIntent& intent,
    const VisibleConfigSnapshot& config_snapshot,
    const nlohmann::json& catalog_snapshot) {
    CatalogSetupPreview preview;
    preview.plan = setup::plan_catalog_setup(
        intent, catalog_snapshot, config_snapshot.config);
    preview.base_revision = config_snapshot.revision;
    preview.summary = summary_json(preview.plan);
    preview.warnings = warnings_json(preview.plan);
    const nlohmann::json token_payload = {
        {"base_revision", preview.base_revision},
        {"candidate_revision", preview.plan.candidate_revision},
        {"summary", preview.summary},
        {"warnings", preview.warnings},
    };
    preview.preview_token = Sha256::hex(token_payload.dump());
    return preview;
}

nlohmann::json preview_json(const CatalogSetupPreview& preview) {
    return {
        {"base_revision", preview.base_revision},
        {"candidate_revision", preview.plan.candidate_revision},
        {"preview_token", preview.preview_token},
        {"requires_warning_acceptance", !preview.plan.warnings.empty()},
        {"summary", preview.summary},
        {"warnings", preview.warnings},
    };
}

[[noreturn]] void throw_plan_error(
    const CatalogSetupPlanError& error) {
    const auto code = error_code_name(error.code());
    throw ApiError(
        error.what(),
        400,
        nlohmann::json{
            {"error", error.what()},
            {"code", code},
            {"path", error.path()},
        }
            .dump());
}

[[noreturn]] void throw_validation_error(
    const ConfigValidationError& error) {
    nlohmann::json issues = nlohmann::json::array();
    for (const auto& issue : error.issues()) {
        issues.push_back({
            {"path", issue.path},
            {"message", issue.message},
        });
    }
    throw ApiError(
        error.what(),
        400,
        nlohmann::json{
            {"error", error.what()},
            {"validation_errors", std::move(issues)},
        }
            .dump());
}

CatalogSetupPreview build_preview_for_api(
    const CatalogSetupIntent& intent,
    const VisibleConfigSnapshot& config_snapshot,
    const CatalogSnapshotProvider& catalog_snapshot_provider) {
    try {
        const auto catalog = catalog_snapshot_provider();
        if (catalog.contains("error") &&
            (!catalog.contains("presets") ||
             !catalog.at("presets").is_array() ||
             catalog.at("presets").empty())) {
            throw ApiError(
                "Catalogue is unavailable",
                503,
                nlohmann::json{
                    {"error", "Catalogue is unavailable"},
                }
                    .dump());
        }
        return build_preview(intent, config_snapshot, catalog);
    } catch (const CatalogSetupPlanError& error) {
        throw_plan_error(error);
    } catch (const ConfigValidationError& error) {
        throw_validation_error(error);
    }
}

[[noreturn]] void stale_preview(
    const std::string& reason,
    const std::optional<CatalogSetupPreview>& current = std::nullopt,
    const std::optional<std::string>& current_base_revision =
        std::nullopt) {
    nlohmann::json body = {
        {"error", "Catalog setup preview is stale"},
        {"reason", reason},
    };
    if (current.has_value()) {
        body["current_base_revision"] = current->base_revision;
        body["current_candidate_revision"] =
            current->plan.candidate_revision;
        body["current_preview_token"] = current->preview_token;
    } else if (current_base_revision.has_value()) {
        body["current_base_revision"] = *current_base_revision;
    }
    throw ApiError(
        "Catalog setup preview is stale", 409, body.dump());
}

void require_no_visible_draft(
    const VisibleConfigSnapshot& snapshot) {
    if (!snapshot.is_draft) return;
    throw ApiError(
        "Save or discard the current configuration draft before using "
        "catalog setup",
        409,
        nlohmann::json{
            {"error",
             "Save or discard the current configuration draft before "
             "using catalog setup"},
            {"reason", "draft_present"},
            {"current_base_revision", snapshot.revision},
        }
            .dump());
}

void register_catalog_setup_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    CatalogSnapshotProvider catalog_snapshot_provider,
    CommitCatalogSetup commit_catalog_setup) {
    server.post(
        "/api/setup/catalog/preview",
        [&ctx, catalog_snapshot_provider](
            const std::string& body) -> std::string {
            const auto request = parse_request_body(body);
            const auto intent = parse_intent(
                required_object(request, "intent", "$"));
            const auto config_snapshot =
                ctx.get_visible_config_snapshot();
            require_no_visible_draft(config_snapshot);
            return preview_json(build_preview_for_api(
                                    intent,
                                    config_snapshot,
                                    catalog_snapshot_provider))
                .dump();
        });

    server.post(
        "/api/setup/catalog/apply",
        [&ctx,
         catalog_snapshot_provider,
         commit_catalog_setup](
            const std::string& body) -> std::string {
            const auto request =
                parse_apply_request(parse_request_body(body));
            return commit_catalog_setup(
                ctx,
                "catalog-setup-apply",
                [&ctx,
                 request,
                 catalog_snapshot_provider]()
                    -> PreparedConfigCommit {
                    const auto config_snapshot =
                        ctx.get_visible_config_snapshot();
                    require_no_visible_draft(config_snapshot);
                    if (config_snapshot.revision !=
                        request.base_revision) {
                        stale_preview(
                            "base_revision_mismatch",
                            std::nullopt,
                            config_snapshot.revision);
                    }

                    const auto preview = build_preview_for_api(
                        request.intent,
                        config_snapshot,
                        catalog_snapshot_provider);
                    if (preview.plan.candidate_revision !=
                        request.candidate_revision) {
                        stale_preview(
                            "candidate_revision_mismatch",
                            preview);
                    }
                    if (preview.preview_token !=
                        request.preview_token) {
                        stale_preview(
                            "preview_token_mismatch",
                            preview);
                    }
                    if (!catalog_plan_has_changes(preview.plan)) {
                        throw ApiError(
                            "Selected catalog presets and requested policies "
                            "are already configured",
                            409,
                            nlohmann::json{
                                {"error",
                                 "Selected catalog presets and requested "
                                 "policies are already configured"},
                                {"reason", "already_installed"},
                                {"summary", preview.summary},
                            }
                                .dump());
                    }
                    if (!preview.plan.warnings.empty() &&
                        !request.accept_warnings) {
                        throw ApiError(
                            "Catalog setup warnings require explicit acceptance",
                            409,
                            nlohmann::json{
                                {"error",
                                 "Catalog setup warnings require explicit acceptance"},
                                {"requires_warning_acceptance", true},
                                {"warnings", preview.warnings},
                            }
                                .dump());
                    }

                    auto serialized =
                        serialize_config_for_persistence(
                            preview.plan.candidate);

                    PreparedConfigCommit prepared;
                    prepared.config =
                        std::move(preview.plan.candidate);
                    prepared.serialized = std::move(serialized);
                    prepared.success_status = "ok";
                    prepared.success_message =
                        "Catalog setup saved and applied";
                    return prepared;
                });
        });
}

} // namespace

void register_catalog_setup_handler(
    ApiServer& server,
    ApiContext& ctx) {
    register_catalog_setup_handler_impl(
        server,
        ctx,
        []() { return load_catalog_snapshot(); },
        [](ApiContext& context,
           std::string operation,
           PrepareConfigCommit prepare) {
            return commit_prepared_config(
                context,
                std::move(operation),
                std::move(prepare));
        });
}

#ifdef KEEN_PBR3_TESTING
void register_catalog_setup_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    CatalogSnapshotProvider catalog_snapshot_provider,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options) {
    register_catalog_setup_handler_impl(
        server,
        ctx,
        std::move(catalog_snapshot_provider),
        [write_config_file = std::move(write_config_file),
         options = std::move(options)](
            ApiContext& context,
            std::string operation,
            PrepareConfigCommit prepare) mutable {
            return commit_prepared_config_for_test(
                context,
                std::move(operation),
                std::move(prepare),
                write_config_file,
                options);
        });
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
