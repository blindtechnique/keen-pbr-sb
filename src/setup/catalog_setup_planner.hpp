#pragma once

#include "../config/config.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3::setup {

enum class CatalogSetupMode {
    none,
    outbound,
    block,
    // Keep the traffic on the router's ordinary route. The destination is not
    // the operator's to pick - it is the main routing table - so this mode
    // carries no outbound tag, exactly as `block` carries none.
    direct,
};

enum class CatalogDnsMode {
    none,
    automatic,
    explicit_server,
};

struct CatalogPresetSelection {
    std::string preset_id;
    std::optional<std::string> display_name;
};

struct CatalogSetupIntent {
    std::vector<CatalogPresetSelection> selections;
    CatalogSetupMode mode{CatalogSetupMode::none};
    std::optional<std::string> outbound_tag;
    CatalogDnsMode dns_mode{CatalogDnsMode::none};
    std::optional<std::string> dns_server_tag;
    std::optional<std::string> source_detour_tag;
    std::optional<std::string> route_display_name;
    std::optional<std::string> dns_display_name;
};

enum class CatalogSetupErrorCode {
    invalid_catalog_snapshot,
    empty_selection,
    duplicate_selection,
    preset_not_found,
    malformed_preset,
    mixed_catalog_actions,
    incompatible_intent,
    outbound_required,
    outbound_not_found,
    outbound_not_routable,
    dns_server_required,
    dns_server_not_found,
    dns_automatic_unavailable,
    dns_detour_mismatch,
};

class CatalogSetupPlanError final : public std::runtime_error {
public:
    CatalogSetupPlanError(CatalogSetupErrorCode code,
                          std::string path,
                          std::string message);

    CatalogSetupErrorCode code() const noexcept { return code_; }
    const std::string& path() const noexcept { return path_; }

private:
    CatalogSetupErrorCode code_;
    std::string path_;
};

enum class CatalogSetupWarningCode {
    source_detour_not_found,
    source_detour_not_routable,
    source_detour_not_applicable,
    dns_automatic_unavailable,
    dns_ignored_for_block,
    dns_detour_missing,
    dns_detour_mismatch,
    broad_traffic_scope,
};

struct CatalogSetupWarning {
    CatalogSetupWarningCode code;
    std::string path;
    std::string message;
};

struct CatalogListPlanSummary {
    std::string preset_id;
    std::string technical_id;
    std::string display_name;
    bool already_installed{false};
    bool url_backed{false};
    bool has_inline_domains{false};
    bool has_inline_cidrs{false};
    std::optional<std::string> source_detour;
};

struct CatalogRouteRulePlanSummary {
    std::string technical_id;
    std::string display_name;
    std::string outbound;
    std::size_t insertion_index{0};
    bool blocking{false};
};

struct CatalogDnsRulePlanSummary {
    std::string technical_id;
    std::string display_name;
    std::string server;
    std::size_t insertion_index{0};
};

struct CatalogDnsServerPlanSummary {
    std::string technical_id;
    std::string display_name;
    std::string address;
    std::string detour;
    bool created{false};
};

struct CatalogBlackholePlanSummary {
    std::string tag;
    bool created{false};
};

// The main-table outbound a `direct` selection routes to. `created` true means
// the router had no outbound on the main table and the plan adds one, so the
// panel can say that a new outbound appears rather than letting it turn up
// unannounced.
struct CatalogDirectOutboundPlanSummary {
    std::string tag;
    bool created{false};
};

struct CatalogSetupSummary {
    CatalogSetupMode mode{CatalogSetupMode::none};
    std::vector<CatalogListPlanSummary> lists;
    // One catalogue setup session receives one independently editable route
    // rule and one DNS rule containing every uncovered list reference. The
    // vectors remain extensible and the singular fields remain compatibility
    // projections for clients predating sb.12.
    std::vector<CatalogRouteRulePlanSummary> route_rules;
    std::vector<CatalogDnsRulePlanSummary> dns_rules;
    std::optional<CatalogRouteRulePlanSummary> route_rule;
    std::optional<CatalogDnsRulePlanSummary> dns_rule;
    std::optional<CatalogDnsServerPlanSummary> dns_server;
    std::optional<CatalogBlackholePlanSummary> blackhole;
    std::optional<CatalogDirectOutboundPlanSummary> direct_outbound;
};

struct CatalogSetupPlan {
    Config candidate;
    CatalogSetupSummary summary;
    std::vector<CatalogSetupWarning> warnings;
    // SHA-256 of the canonical generated Config JSON. This is a preview
    // identity only; the existing config commit coordinator remains the sole
    // owner of compare-and-swap and durable mutation.
    std::string candidate_revision;
};

// Stable provenance for one preset in an authoritative catalogue snapshot.
// The planner and the read-only catalogue response share this helper so the
// UI cannot drift from duplicate-prevention semantics.
std::string catalog_preset_identity(
    const nlohmann::json& catalog_snapshot,
    const std::string& preset_id);

// Pure planner: it performs no I/O and does not stage or save configuration.
// catalog_snapshot accepts either the catalogue array itself or the exact
// GET /api/catalog response object containing a "presets" array.
CatalogSetupPlan plan_catalog_setup(
    const CatalogSetupIntent& intent,
    const nlohmann::json& catalog_snapshot,
    const Config& active_config);

// Validates the deliberately narrow beginner setup contract used by the
// simple list dialog. Advanced editors continue to stage any configuration
// accepted by validate_config(). This separate single-list endpoint still
// requires exactly one dedicated route rule and one dedicated DNS rule; the
// catalogue batch planner is intentionally not constrained by this contract.
void validate_recommended_list_setup(
    const Config& candidate,
    const std::string& list_id);

} // namespace keen_pbr3::setup
