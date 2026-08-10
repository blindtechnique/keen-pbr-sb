// Generated from docs/openapi.yaml via build_scripts/generate_api_types.sh
// Run "make generate" to regenerate (requires Node.js).

//  To parse this JSON data, first install
//
//      json.hpp  https://github.com/nlohmann/json
//
//  Then include this file, and then do
//
//     ApiTypes data = nlohmann::json::parse(jsonString);

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <nlohmann/json.hpp>

#ifndef NLOHMANN_OPT_HELPER
#define NLOHMANN_OPT_HELPER
namespace nlohmann {
    template <typename T>
    struct adl_serializer<std::shared_ptr<T>> {
        static void to_json(json & j, const std::shared_ptr<T> & opt) {
            if (!opt) j = nullptr; else j = *opt;
        }

        static std::shared_ptr<T> from_json(const json & j) {
            if (j.is_null()) return std::shared_ptr<T>(); else return std::make_shared<T>(j.get<T>());
        }
    };
    template <typename T>
    struct adl_serializer<std::optional<T>> {
        static void to_json(json & j, const std::optional<T> & opt) {
            if (!opt) j = nullptr; else j = *opt;
        }

        static std::optional<T> from_json(const json & j) {
            if (j.is_null()) return std::optional<T>(); else return std::make_optional<T>(j.get<T>());
        }
    };
}
#endif

namespace keen_pbr3 {
namespace api {
    using nlohmann::json;

    #ifndef NLOHMANN_UNTYPED_keen_pbr3_api_HELPER
    #define NLOHMANN_UNTYPED_keen_pbr3_api_HELPER
    inline json get_untyped(const json & j, const char * property) {
        if (j.find(property) != j.end()) {
            return j.at(property).get<json>();
        }
        return json();
    }

    inline json get_untyped(const json & j, std::string property) {
        return get_untyped(j, property.data());
    }
    #endif

    #ifndef NLOHMANN_OPTIONAL_keen_pbr3_api_HELPER
    #define NLOHMANN_OPTIONAL_keen_pbr3_api_HELPER
    template <typename T>
    inline std::shared_ptr<T> get_heap_optional(const json & j, const char * property) {
        auto it = j.find(property);
        if (it != j.end() && !it->is_null()) {
            return j.at(property).get<std::shared_ptr<T>>();
        }
        return std::shared_ptr<T>();
    }

    template <typename T>
    inline std::shared_ptr<T> get_heap_optional(const json & j, std::string property) {
        return get_heap_optional<T>(j, property.data());
    }
    template <typename T>
    inline std::optional<T> get_stack_optional(const json & j, const char * property) {
        auto it = j.find(property);
        if (it != j.end() && !it->is_null()) {
            return j.at(property).get<std::optional<T>>();
        }
        return std::optional<T>();
    }

    template <typename T>
    inline std::optional<T> get_stack_optional(const json & j, std::string property) {
        return get_stack_optional<T>(j, property.data());
    }
    #endif

    struct ApiConfig {
        std::optional<bool> enabled;
        std::optional<std::string> listen;
    };

    struct CacheGeneration {
        std::string filename;
        std::string sha256;
        int64_t size = 0;
    };

    struct CacheMetadata {
        std::optional<int64_t> cidrs;
        std::optional<CacheGeneration> current;
        std::optional<int64_t> domains;
        std::optional<std::string> download_time;
        std::optional<std::string> etag;
        std::optional<int64_t> ips;
        std::optional<std::string> last_modified;
        std::optional<std::string> last_refresh_attempt;
        std::optional<std::string> last_refresh_detour;
        std::optional<std::string> last_refresh_error;
        std::optional<std::string> last_refresh_url;
        std::optional<CacheGeneration> previous;
        std::optional<int64_t> srs_decoder_revision;
        std::optional<std::string> url;
    };

    struct CatalogPresetSelection {
        std::optional<std::string> display_name;
        std::string preset_id;
    };

    enum class DnsMode : int { AUTOMATIC, EXPLICIT_SERVER, NONE };

    enum class CatalogSetupModeEnum : int { BLOCK, NONE, OUTBOUND };

    struct Intent {
        std::optional<std::string> dns_display_name;
        DnsMode dns_mode;
        std::optional<std::string> dns_server_tag;
        CatalogSetupModeEnum mode;
        std::optional<std::string> outbound_tag;
        std::optional<std::string> route_display_name;
        std::vector<CatalogPresetSelection> selections;
        std::optional<std::string> source_detour_tag;
    };

    struct CatalogSetupApplyRequest {
        bool accept_warnings = false;
        std::string base_revision;
        std::string candidate_revision;
        Intent intent;
        std::string preview_token;
    };

    struct CatalogSetupApplyResponse {
        bool applied = false;
        std::optional<int64_t> apply_started_ts;
        std::string config_revision;
        std::string message;
        bool rolled_back = false;
        bool saved = false;
        std::string status;
    };

    struct CatalogSetupBlackholeSummary {
        bool created = false;
        std::string tag;
    };

    struct CatalogSetupDnsRuleSummary {
        std::string display_name;
        int64_t insertion_index = 0;
        std::string server;
        std::string technical_id;
    };

    struct CatalogSetupDnsServerSummary {
        std::string address;
        bool created = false;
        std::string detour;
        std::string display_name;
        std::string technical_id;
    };

    struct CatalogSetupListSummary {
        bool already_installed = false;
        std::string display_name;
        bool has_inline_cidrs = false;
        bool has_inline_domains = false;
        std::string preset_id;
        std::optional<std::string> source_detour;
        std::string technical_id;
        bool url_backed = false;
    };

    struct CatalogSetupPreviewRequest {
        Intent intent;
    };

    struct RouteRule {
        bool blocking = false;
        std::string display_name;
        int64_t insertion_index = 0;
        std::string outbound;
        std::string technical_id;
    };

    struct CatalogSetupSummaryClass {
        std::optional<CatalogSetupBlackholeSummary> blackhole;
        std::optional<CatalogSetupDnsRuleSummary> dns_rule;
        std::optional<std::vector<CatalogSetupDnsRuleSummary>> dns_rules;
        std::optional<CatalogSetupDnsServerSummary> dns_server;
        std::vector<CatalogSetupListSummary> lists;
        CatalogSetupModeEnum mode;
        std::optional<RouteRule> route_rule;
        std::optional<std::vector<RouteRule>> route_rules;
    };

    enum class Code : int { BROAD_TRAFFIC_SCOPE, DNS_AUTOMATIC_UNAVAILABLE, DNS_DETOUR_MISMATCH, DNS_DETOUR_MISSING, DNS_IGNORED_FOR_BLOCK, SOURCE_DETOUR_NOT_APPLICABLE, SOURCE_DETOUR_NOT_FOUND, SOURCE_DETOUR_NOT_ROUTABLE };

    struct CatalogSetupWarningElement {
        Code code;
        std::string message;
        std::string path;
    };

    struct CatalogSetupPreviewResponse {
        std::string base_revision;
        std::string candidate_revision;
        std::string preview_token;
        bool requires_warning_acceptance = false;
        CatalogSetupSummaryClass summary;
        std::vector<CatalogSetupWarningElement> warnings;
    };

    enum class CheckStatus : int { MISMATCH, MISSING, OK };

    struct CircuitBreakerConfig {
        std::optional<int64_t> failure_threshold;
        std::optional<int64_t> half_open_max_requests;
        std::optional<int64_t> success_threshold;
        std::optional<int64_t> timeout_ms;
    };

    struct ClientDnsEnforcement {
        std::optional<bool> block_dot;
        std::optional<bool> enabled;
    };

    enum class DaemonConfigFirewallBackend : int { AUTO, IPTABLES, NFTABLES };

    enum class MetaUdp443Policy : int { BALANCED, MESSAGES_FIRST };

    struct Daemon {
        std::optional<std::string> cache_dir;
        std::optional<bool> clear_dynamic_sets_on_apply;
        std::optional<DaemonConfigFirewallBackend> firewall_backend;
        std::optional<int64_t> firewall_verify_max_bytes;
        std::optional<bool> ipv6_enabled;
        std::optional<int64_t> max_file_size_bytes;
        std::optional<MetaUdp443Policy> meta_udp443_policy;
        std::optional<std::string> pid_file;
        std::optional<std::vector<std::string>> reconnect_owned_flows_on_routing_change_lists;
        std::optional<bool> reconnect_unmarked_flows_on_routing_change;
        std::optional<bool> skip_marked_packets;
        std::optional<bool> strict_enforcement;
    };

    struct DnsTestServer {
        std::optional<std::string> answer_ipv4;
        std::string listen;
    };

    struct DnsRuleElement {
        std::optional<bool> allow_domain_rebinding;
        std::optional<std::string> display_name;
        std::optional<bool> enabled;
        std::optional<std::string> id;
        std::vector<std::string> list;
        std::string server;
    };

    enum class DnsServerType : int { KEENETIC, STATIC };

    struct DnsServerElement {
        std::optional<std::string> address;
        std::optional<std::string> detour;
        std::optional<std::string> display_name;
        std::string tag;
        std::optional<DnsServerType> type;
    };

    struct SystemResolver {
        std::string address;
    };

    struct Dns {
        std::optional<ClientDnsEnforcement> client_dns_enforcement;
        std::optional<DnsTestServer> dns_test_server;
        std::optional<std::vector<std::string>> fallback;
        std::optional<std::vector<DnsRuleElement>> rules;
        std::optional<std::vector<DnsServerElement>> servers;
        std::optional<SystemResolver> system_resolver;
    };

    struct Fwmark {
        std::optional<std::string> mask;
        std::optional<std::string> start;
    };

    struct Iproute {
        std::optional<int64_t> table_start;
    };

    struct ListRefresh {
        std::optional<std::string> detour;
        std::optional<std::vector<std::string>> fallback_detours;
    };

    enum class RefreshDetourMode : int { INHERIT, OVERRIDE };

    struct ListConfigValue {
        std::optional<std::string> catalog_identity;
        std::optional<std::string> detour;
        std::optional<std::string> display_name;
        std::optional<std::vector<std::string>> domains;
        std::optional<std::vector<std::string>> fallback_detours;
        std::optional<std::string> file;
        std::optional<std::vector<std::string>> ip_cidrs;
        std::optional<RefreshDetourMode> refresh_detour_mode;
        std::optional<int64_t> ttl_ms;
        std::optional<std::string> url;
    };

    struct ListsAutoupdate {
        std::optional<std::string> cron;
        std::optional<bool> enabled;
    };

    enum class ConntrackOnSwitch : int { DELETE, DELETE_ON_FAILURE, PRESERVE };

    struct OutboundGroupElement {
        std::vector<std::string> outbounds;
        std::optional<int64_t> weight;
    };

    struct Retry {
        std::optional<int64_t> attempts;
        std::optional<int64_t> interval_ms;
    };

    enum class SelectionMode : int { LATENCY, PRIORITY };

    enum class OutboundType : int { BLACKHOLE, IGNORE, INTERFACE, TABLE, URLTEST };

    struct OutboundElement {
        std::optional<CircuitBreakerConfig> circuit_breaker;
        std::optional<ConntrackOnSwitch> conntrack_on_switch;
        std::optional<std::string> display_name;
        std::optional<std::string> gateway;
        std::optional<std::string> gateway6;
        std::optional<std::string> interface;
        std::optional<int64_t> interval_ms;
        std::optional<std::vector<OutboundGroupElement>> outbound_groups;
        std::optional<int64_t> probe_timeout_ms;
        std::optional<Retry> retry;
        std::optional<SelectionMode> selection_mode;
        std::optional<bool> strict_enforcement;
        std::optional<int64_t> table;
        std::string tag;
        std::optional<int64_t> tolerance_ms;
        OutboundType type;
        std::optional<std::string> url;
    };

    struct InternalVpnServerElement {
        std::string interface;
        std::optional<std::string> ndms_id;
        bool process_clients = false;
    };

    struct InternalVpnServiceElement {
        bool process_clients = false;
        std::string service_id;
    };

    struct RouteRuleElement {
        std::optional<std::string> dest_addr;
        std::optional<std::string> dest_port;
        std::optional<std::string> display_name;
        std::optional<int64_t> dscp;
        std::optional<bool> enabled;
        std::optional<std::string> id;
        std::optional<std::vector<std::string>> list;
        std::string outbound;
        std::optional<std::string> proto;
        std::optional<std::string> src_addr;
        std::optional<std::string> src_port;
    };

    struct Route {
        std::optional<std::vector<std::string>> inbound_interfaces;
        std::optional<std::vector<InternalVpnServerElement>> internal_vpn_servers;
        std::optional<std::vector<InternalVpnServiceElement>> internal_vpn_services;
        std::optional<std::vector<RouteRuleElement>> rules;
    };

    struct PlainDnsTemplateElement {
        std::string name;
        std::string primary_ipv4;
        std::optional<std::string> secondary_ipv4;
    };

    struct UiPreferences {
        std::optional<std::vector<std::string>> hidden_native_interface_ids;
        std::optional<std::vector<PlainDnsTemplateElement>> plain_dns_templates;
    };

    struct ConfigObject {
        std::optional<ApiConfig> api;
        std::optional<Daemon> daemon;
        std::optional<Dns> dns;
        std::optional<Fwmark> fwmark;
        std::optional<Iproute> iproute;
        std::optional<ListRefresh> list_refresh;
        std::optional<std::map<std::string, ListConfigValue>> lists;
        std::optional<ListsAutoupdate> lists_autoupdate;
        std::optional<std::vector<OutboundElement>> outbounds;
        std::optional<Route> route;
        std::optional<UiPreferences> ui_preferences;
    };

    struct ListRefreshStateValue {
        std::optional<std::string> last_attempt;
        std::optional<std::string> last_detour;
        std::optional<std::string> last_error;
        std::optional<std::string> last_updated;
    };

    struct ConfigStateResponse {
        ConfigObject config;
        bool is_draft = false;
        std::optional<std::map<std::string, ListRefreshStateValue>> list_refresh_state;
        std::string revision;
    };

    enum class ConfigUpdateResponseStatus : int { OK };

    struct ConfigUpdateResponse {
        std::optional<int64_t> apply_started_ts;
        std::string message;
        ConfigUpdateResponseStatus status;
    };

    struct ConnectionEventState {
        bool available = false;
        int64_t changed_at = 0;
        int64_t revision = 0;
    };

    struct ConnectionRecord {
        bool active = false;
        std::string destination;
        std::vector<std::string> destination_domains;
        int64_t destination_port = 0;
        std::string device;
        int64_t first_seen = 0;
        std::string id;
        int64_t last_seen = 0;
        int64_t mark = 0;
        std::string protocol;
        std::string route;
        std::string source;
        int64_t source_port = 0;
        std::string state;
    };

    struct ConnectionPage {
        std::vector<ConnectionRecord> items;
        std::optional<std::string> next_cursor;
        int64_t snapshot_at = 0;
        int64_t total = 0;
    };

    enum class SortOrder : int { ASC, DESC };

    enum class ConnectionSort : int { DESTINATION, FIRST_SEEN, LAST_SEEN, SOURCE };

    struct ConnectionQueryRequest {
        std::optional<bool> active_only;
        std::optional<std::string> cursor;
        std::optional<std::string> device;
        std::optional<int64_t> limit;
        std::optional<SortOrder> order;
        std::optional<std::string> route;
        std::optional<std::string> search;
        std::optional<ConnectionSort> sort;
        std::optional<std::string> state;
    };

    enum class DependencyEntityKind : int { DNS_SERVER, LIST, OUTBOUND };

    struct DependencyAnalysisTargetRequest {
        std::string id;
        DependencyEntityKind kind;
    };

    struct DependencyAnalysisRequest {
        std::optional<bool> independent;
        std::vector<DependencyAnalysisTargetRequest> targets;
    };

    enum class DependencyConsequence : int { DELETE, DISCONNECT, MODIFY };

    enum class DependencyDependentKind : int { DNS_FALLBACK, DNS_RULE, DNS_SERVER, LIST, LIST_REFRESH, OUTBOUND_GROUP, ROUTING_RULE };

    enum class DependencyRelation : int { CONTAINS_MEMBER, DETOURS_VIA, FALLBACK_TO, ROUTES_TO, USES_DNS_SERVER, USES_LIST };

    struct DependencyTarget {
        bool cascaded = false;
        std::string id;
        DependencyEntityKind kind;
    };

    struct DependencyReference {
        DependencyConsequence consequence;
        std::string dependent_id;
        DependencyDependentKind dependent_kind;
        std::optional<std::string> href;
        std::string path;
        DependencyRelation relation;
        DependencyTarget target;
    };

    struct DependencyAnalysisResponse {
        std::vector<DependencyReference> references;
        bool safe_to_delete = false;
        std::vector<DependencyTarget> targets;
    };

    struct ValidationErrorElement {
        std::string message;
        std::optional<std::string> path;
    };

    struct ErrorResponse {
        std::string error;
        std::optional<std::vector<ValidationErrorElement>> validation_errors;
    };

    struct FirewallChain {
        bool chain_present = false;
        std::optional<std::string> detail;
        bool prerouting_hook_present = false;
    };

    struct FirewallRuleCheck {
        std::string action;
        std::optional<std::string> actual_fwmark;
        std::optional<std::string> detail;
        std::optional<std::string> expected_fwmark;
        std::string set_name;
        CheckStatus status;
    };

    enum class LifecycleOperationStageStatus : int { FAILED, PENDING, RUNNING, SKIPPED, SUCCEEDED };

    struct LifecycleOperationStageElement {
        std::string detail;
        std::string id;
        LifecycleOperationStageStatus status;
        std::string title;
    };

    enum class LifecycleOperationStatus : int { FAILED, RUNNING, SUCCEEDED };

    enum class LifecycleOperationType : int { APPLY_CONFIG, RESTART, START, STOP };

    struct LifecycleOperation {
        std::optional<std::string> error;
        std::optional<int64_t> finished_at;
        std::string id;
        std::vector<LifecycleOperationStageElement> stages;
        int64_t started_at = 0;
        LifecycleOperationStatus status;
        LifecycleOperationType type;
    };

    enum class ResolverConfigProbeStatus : int { INVALID_TXT, MISSING_TXT, NOT_CONFIGURED, QUERY_FAILED, SUCCESS, UNKNOWN };

    enum class ResolverConfigSyncState : int { CONVERGED, CONVERGING, STALE };

    enum class ResolverLiveStatus : int { DEGRADED, HEALTHY, UNAVAILABLE, UNKNOWN };

    enum class RuntimeState : int { APPLYING, BROKEN, RESTART_REQUIRED, RUNNING, SHUTTING_DOWN, STARTING, STOPPED };

    enum class HealthResponseStatus : int { RUNNING, STOPPED };

    struct HealthResponse {
        std::optional<int64_t> apply_started_ts;
        std::string build;
        std::string build_variant;
        std::optional<std::string> commit;
        bool config_is_draft = false;
        std::optional<LifecycleOperation> lifecycle_operation;
        std::string os_type;
        std::string os_version;
        std::optional<std::string> resolver_config_hash;
        std::optional<std::string> resolver_config_hash_actual;
        std::optional<int64_t> resolver_config_hash_actual_ts;
        std::optional<ResolverConfigProbeStatus> resolver_config_probe_status;
        std::optional<ResolverConfigSyncState> resolver_config_sync_state;
        std::optional<int64_t> resolver_last_probe_ts;
        ResolverLiveStatus resolver_live_status;
        RuntimeState runtime_state;
        std::string runtime_state_reason;
        HealthResponseStatus status;
        std::string version;
    };

    struct ListDeleteTargetElement {
        std::string list_id;
        std::optional<std::string> replacement_list_id;
    };

    struct ListDeleteStageRequest {
        std::string base_revision;
        std::vector<ListDeleteTargetElement> targets;
    };

    struct ListDeleteStageSummaryClass {
        std::vector<std::string> deleted_lists;
        int64_t rebound_references = 0;
        int64_t removed_dns_rules = 0;
        int64_t removed_route_rules = 0;
        int64_t updated_dns_rules = 0;
        int64_t updated_route_rules = 0;
    };

    struct ListDeleteStageResponse {
        std::string message;
        bool staged = false;
        ListDeleteStageSummaryClass summary;
    };

    struct ListRefreshRequest {
        std::optional<std::string> name;
    };

    struct ListRefreshResponse {
        std::vector<std::string> changed_lists;
        std::vector<std::string> failed_lists;
        std::string message;
        std::vector<std::string> refreshed_lists;
        bool reloaded = false;
        ConfigUpdateResponseStatus status;
    };

    enum class NdmsCatalogStatus : int { FRESH, STALE, UNAVAILABLE };

    struct NdmsInterfaceCapabilities {
        bool backup_required = false;
        bool can_delete = false;
        bool can_edit = false;
        bool can_hide = false;
    };

    enum class Kind : int { AMNEZIA_WIREGUARD, HTTPS_PROXY, HTTP_PROXY, IKE, L2_TP, OPENCONNECT, OPENVPN, SOCKS5_PROXY, SSTP, WIREGUARD };

    enum class NdmsManagementBlockerElement : int { AUTOMATIC_BACKUP_UNAVAILABLE, KERNEL_IDENTITY_UNRESOLVED, OPTIMISTIC_REVISION_UNAVAILABLE, OWNERSHIP_UNKNOWN, ROLE_UNKNOWN, TYPED_RCI_UNAVAILABLE, UNSUPPORTED_KIND, UNSUPPORTED_ROLE };

    struct NdmsInterfaceManagementReadiness {
        std::vector<NdmsManagementBlockerElement> blockers;
        bool candidate = false;
        bool configuration_snapshot_available = false;
        bool identity_stable = false;
        std::string observed_revision;
    };

    enum class Owner : int { KEENETIC };

    enum class Role : int { CLIENT, SERVER, UNKNOWN };

    struct NdmsTunnelInterfaceElement {
        NdmsInterfaceCapabilities capabilities;
        std::optional<bool> connected;
        std::string firmware_interface_name;
        std::string firmware_type;
        std::string id;
        bool internal_vpn_server_candidate = false;
        bool internal_vpn_server_role_confirmation_required = false;
        std::optional<std::string> kernel_name;
        Kind kind;
        std::string label;
        std::optional<bool> link;
        NdmsInterfaceManagementReadiness management_readiness;
        Owner owner;
        Role role;
    };

    enum class MutationMode : int { DISABLED };

    enum class RequiredGuard : int { AUTOMATIC_BACKUP, OPTIMISTIC_REVISION, OWNERSHIP_CHECK, TYPED_RCI };

    struct NdmsInterfaceInventoryResponse {
        bool available = false;
        NdmsCatalogStatus catalog_status;
        std::vector<NdmsTunnelInterfaceElement> interfaces;
        MutationMode mutation_mode;
        bool read_only = false;
        std::vector<RequiredGuard> required_guards;
    };

    enum class NdmsVpnServerKind : int { IKEV1, IKEV2, L2_TP, OPENCONNECT, SSTP };

    struct NdmsVpnServerService {
        std::optional<std::string> bound_interface_id;
        bool enabled = false;
        std::string id;
        std::string inventory_revision;
        NdmsVpnServerKind kind;
        std::string label;
        std::vector<std::string> source_cidrs;
    };

    struct NdmsVpnServerServiceInventoryResponse {
        bool available = false;
        NdmsCatalogStatus catalog_status;
        bool read_only = false;
        std::vector<NdmsVpnServerService> services;
    };

    enum class LastOutcome : int { ABANDONED, FAILURE, NOOP, SKIPPED, SUCCESS };

    struct PeriodicTaskMetricsEntry {
        int64_t abandoned = 0;
        int64_t failure = 0;
        int64_t in_flight = 0;
        std::string label;
        std::optional<int64_t> last_duration_ms;
        std::optional<std::string> last_error;
        std::optional<int64_t> last_event_at_unix_ms;
        std::optional<int64_t> last_finished_at_unix_ms;
        std::optional<LastOutcome> last_outcome;
        std::optional<int64_t> last_started_at_unix_ms;
        int64_t max_duration_ms = 0;
        int64_t noop = 0;
        int64_t runs = 0;
        int64_t skipped = 0;
        int64_t success = 0;
        int64_t total_duration_ms = 0;
    };

    struct PeriodicTaskMetricsResponse {
        int64_t capacity = 0;
        std::vector<PeriodicTaskMetricsEntry> tasks;
        int64_t tracked = 0;
    };

    struct PolicyRuleCheck {
        std::optional<std::string> detail;
        int64_t expected_table = 0;
        std::string fwmark;
        std::string fwmask;
        int64_t priority = 0;
        bool rule_present_v4 = false;
        bool rule_present_v6 = false;
        CheckStatus status;
    };

    struct RecommendedListSetupRequest {
        std::string base_revision;
        ConfigObject config;
        std::string list_id;
    };

    struct ReloadResponse {
        std::string message;
        ConfigUpdateResponseStatus status;
    };

    struct RouteTableCheck {
        bool default_route_present = false;
        std::optional<std::string> detail;
        std::optional<std::string> expected_destination;
        std::optional<std::string> expected_gateway;
        std::optional<std::string> expected_interface;
        std::optional<int64_t> expected_metric;
        std::optional<std::string> expected_route_type;
        bool gateway_matches = false;
        bool interface_matches = false;
        std::string outbound_tag;
        CheckStatus status;
        bool table_exists = false;
        int64_t table_id = 0;
    };

    enum class RoutingHealthErrorResponseOverall : int { ERROR };

    struct RoutingHealthErrorResponse {
        std::string error;
        RoutingHealthErrorResponseOverall overall;
    };

    enum class RoutingHealthResponseFirewallBackend : int { IPTABLES, NFTABLES };

    enum class RoutingHealthResponseOverall : int { DEGRADED, ERROR, OK };

    struct RoutingHealthResponse {
        FirewallChain firewall;
        RoutingHealthResponseFirewallBackend firewall_backend;
        std::vector<FirewallRuleCheck> firewall_rules;
        RoutingHealthResponseOverall overall;
        std::vector<PolicyRuleCheck> policy_rules;
        std::vector<RouteTableCheck> route_tables;
    };

    enum class Evaluation : int { INSUFFICIENT_CONTEXT, MATCHED, NOT_MATCHED };

    struct ListMatch {
        std::string list;
        std::string via;
    };

    enum class RoutingTestUnknownConditionElement : int { DESTINATION_ADDRESS, DESTINATION_PORT, DSCP, FIREWALL_SET, FIREWALL_STATE, FIREWALL_TOOL, INBOUND_INTERFACE, PROTOCOL, RESOLVED_IP, SOURCE_ADDRESS, SOURCE_PORT };

    struct RoutingTestEntry {
        std::string actual_outbound;
        Evaluation evaluation;
        std::string expected_outbound;
        std::string ip;
        std::optional<ListMatch> list_match;
        bool ok = false;
        std::vector<RoutingTestUnknownConditionElement> unknown_conditions;
    };

    struct RoutingTestRequest {
        std::string target;
    };

    enum class ConfigScope : int { ACTIVE };

    struct RoutingTestRuleIpDiagnosticElement {
        Evaluation evaluation;
        std::optional<bool> in_ipset;
        bool in_lists = false;
        std::string ip;
        std::optional<ListMatch> list_match;
        std::vector<RoutingTestUnknownConditionElement> unknown_conditions;
    };

    struct RoutingTestRuleDiagnosticElement {
        std::string interface_name;
        std::vector<RoutingTestRuleIpDiagnosticElement> ip_rows;
        std::string outbound;
        RouteRuleElement rule;
        int64_t rule_index = 0;
        bool target_in_lists = false;
        std::optional<ListMatch> target_match;
    };

    struct RoutingTestResponse {
        ConfigScope config_scope;
        std::optional<std::string> dns_error;
        bool is_domain = false;
        bool no_matching_rule = false;
        std::vector<std::string> resolved_ips;
        std::vector<RoutingTestEntry> results;
        std::vector<RoutingTestRuleDiagnosticElement> rule_diagnostics;
        std::string target;
        bool unapplied_draft = false;
        std::vector<std::string> warnings;
    };

    enum class LinkUptimeSource : int { FIRMWARE, OBSERVED };

    enum class RuntimeInterfaceInventoryStatusEnum : int { DOWN, UP };

    struct RuntimeInterfaceTrafficPointElement {
        int64_t age_ms = 0;
        int64_t rx_bits_per_second = 0;
        int64_t tx_bits_per_second = 0;
    };

    struct Traffic {
        std::vector<RuntimeInterfaceTrafficPointElement> history;
        std::optional<int64_t> rx_bits_per_second;
        int64_t rx_bytes = 0;
        std::optional<int64_t> sampled_at_unix_ms;
        std::optional<int64_t> tx_bits_per_second;
        int64_t tx_bytes = 0;
    };

    struct RuntimeInterfaceInventoryEntry {
        std::optional<bool> admin_up;
        std::optional<bool> carrier;
        std::optional<std::vector<std::string>> ipv4_addresses;
        std::optional<std::vector<std::string>> ipv6_addresses;
        std::optional<int64_t> link_up_since_unix_ms;
        std::optional<LinkUptimeSource> link_uptime_source;
        std::string name;
        std::optional<std::string> oper_state;
        RuntimeInterfaceInventoryStatusEnum status;
        std::optional<Traffic> traffic;
    };

    struct RuntimeInterfaceInventoryResponse {
        std::vector<RuntimeInterfaceInventoryEntry> interfaces;
    };

    enum class RuntimeInterfaceStatusEnum : int { ACTIVE, BACKUP, DEGRADED, UNAVAILABLE, UNKNOWN };

    struct RuntimeInterfaceState {
        std::optional<std::string> detail;
        std::optional<std::string> interface_name;
        std::optional<int64_t> latency_ms;
        std::string outbound_tag;
        RuntimeInterfaceStatusEnum status;
    };

    struct RuntimeInterfaceTrafficSample {
        bool available = false;
        std::string name;
        std::optional<int64_t> observed_at_unix_ms;
        bool reset = false;
        std::optional<int64_t> rx_bits_per_second;
        std::optional<int64_t> rx_bytes;
        std::optional<int64_t> tx_bits_per_second;
        std::optional<int64_t> tx_bytes;
    };

    struct RuntimeInterfaceTrafficUpdate {
        std::vector<RuntimeInterfaceTrafficSample> interfaces;
        int64_t sampled_at_unix_ms = 0;
    };

    struct RuntimeOutboundStateElement {
        std::optional<std::string> detail;
        std::vector<RuntimeInterfaceState> interfaces;
        ResolverLiveStatus status;
        std::string tag;
        OutboundType type;
    };

    struct RuntimeOutboundsResponse {
        std::vector<RuntimeOutboundStateElement> outbounds;
    };

    struct RuntimeInventoryResponse {
        RuntimeInterfaceInventoryResponse interfaces;
        RuntimeOutboundsResponse outbounds;
        HealthResponse service;
    };

    enum class StatusEventConnectionsType : int { CONNECTIONS };

    struct StatusEventConnections {
        ConnectionEventState data;
        StatusEventConnectionsType type;
    };

    enum class StatusEventInterfaceTrafficType : int { INTERFACE_TRAFFIC };

    struct StatusEventInterfaceTraffic {
        RuntimeInterfaceTrafficUpdate data;
        StatusEventInterfaceTrafficType type;
    };

    enum class StatusEventInterfacesType : int { INTERFACES };

    struct StatusEventInterfaces {
        RuntimeInterfaceInventoryResponse data;
        StatusEventInterfacesType type;
    };

    enum class StatusEventOutboundsType : int { OUTBOUNDS };

    struct StatusEventOutbounds {
        RuntimeOutboundsResponse data;
        StatusEventOutboundsType type;
    };

    enum class StatusEventServiceType : int { SERVICE };

    struct StatusEventService {
        HealthResponse data;
        StatusEventServiceType type;
    };

    enum class StatusEventSnapshotType : int { SNAPSHOT };

    struct StatusEventSnapshot {
        RuntimeInventoryResponse data;
        StatusEventSnapshotType type;
    };

    enum class Action : int { DOWN, RESTART, UP };

    struct TransportActionRequest {
        Action action;
        std::string tag;
    };

    enum class TransportActionResponseStatus : int { ACCEPTED };

    struct TransportActionResponse {
        std::string at;
        TransportActionResponseStatus status;
    };

    enum class TransportLinkedOutboundEnsureMode : int { ENSURE };

    struct LinkedOutbound {
        std::optional<std::string> display_name;
        TransportLinkedOutboundEnsureMode mode;
        std::optional<bool> strict_enforcement;
    };

    enum class TransportConfigApplyRequestOperation : int { CREATE };

    enum class GeoMode : int { AUTO, DISABLED, MANUAL };

    enum class TransportSpecType : int { NATIVE, SING_BOX, SING_BOX_VLESS_REALITY };

    struct Vless {
        std::optional<std::string> fingerprint;
        std::optional<std::string> flow;
        std::optional<int64_t> mtu;
        std::string public_key;
        std::string server;
        std::string server_name;
        int64_t server_port = 0;
        std::optional<std::string> short_id;
        std::optional<std::string> uuid;
    };

    struct Transport {
        std::optional<bool> auto_start;
        std::optional<std::vector<std::string>> bootstrap_dns;
        std::optional<std::string> country;
        std::optional<std::string> country_code;
        std::optional<std::string> display_name;
        std::optional<GeoMode> geo_mode;
        std::string interface;
        std::optional<std::string> link;
        std::optional<int64_t> mtu;
        std::optional<std::string> outbound_json;
        std::string tag;
        std::optional<std::string> tun_address;
        TransportSpecType type;
        std::optional<Vless> vless;
    };

    struct TransportConfigApplyRequest {
        LinkedOutbound linked_outbound;
        TransportConfigApplyRequestOperation operation;
        Transport transport;
    };

    enum class TransportConfigApplyResponseStatus : int { APPLIED };

    struct TransportConfigApplyResponse {
        std::optional<bool> applied;
        std::optional<int64_t> apply_started_ts;
        std::optional<std::string> config_revision;
        std::optional<std::string> message;
        std::optional<bool> rolled_back;
        std::optional<bool> saved;
        TransportConfigApplyResponseStatus status;
        std::optional<std::string> transport_revision;
    };

    enum class TransportConfigOperationOperation : int { CREATE, DELETE, UPDATE };

    struct TransportConfigOperation {
        TransportConfigOperationOperation operation;
        std::optional<std::string> tag;
        std::optional<Transport> transport;
    };

    enum class TransportConfigResponseStatus : int { CREATED, DELETED, UPDATED };

    struct TransportConfigResponse {
        TransportConfigResponseStatus status;
        std::string tag;
    };

    enum class Confidence : int { AMBIGUOUS, DECLARED, DERIVED, UNKNOWN };

    enum class Framing : int { GRPC, HTTP, HTTP2, HTTP_UPGRADE, QUIC, RAW, UNKNOWN, WEBSOCKET, WIREGUARD };

    enum class PayloadNetwork : int { TCP, UDP };

    enum class WireTransport : int { TCP, TCP_UDP, UDP, UNKNOWN };

    struct TransportPath {
        Confidence confidence;
        Framing framing;
        std::optional<std::vector<PayloadNetwork>> payload_networks;
        WireTransport wire_transport;
    };

    enum class Security : int { REALITY, TLS };

    enum class State : int { DEGRADED, DOWN, STARTING, UP };

    struct TransportStatus {
        bool desired_up = false;
        std::optional<std::string> display_name;
        std::optional<std::string> error;
        std::string interface;
        std::optional<std::string> network;
        std::optional<std::string> next_retry_at;
        std::optional<TransportPath> path;
        std::optional<int64_t> pid;
        std::optional<std::string> protocol;
        std::optional<int64_t> retry_count;
        std::optional<Security> security;
        std::optional<std::string> server;
        std::optional<int64_t> server_port;
        std::optional<std::string> sni;
        State state;
        std::string tag;
        std::string type;
        std::string updated_at;
    };

    struct ApiTypes {
        std::optional<ApiConfig> api_config;
        std::optional<CacheGeneration> cache_generation;
        std::optional<CacheMetadata> cache_metadata;
        std::optional<CatalogPresetSelection> catalog_preset_selection;
        std::optional<CatalogSetupApplyRequest> catalog_setup_apply_request;
        std::optional<CatalogSetupApplyResponse> catalog_setup_apply_response;
        std::optional<CatalogSetupBlackholeSummary> catalog_setup_blackhole_summary;
        std::optional<DnsMode> catalog_setup_dns_mode;
        std::optional<CatalogSetupDnsRuleSummary> catalog_setup_dns_rule_summary;
        std::optional<CatalogSetupDnsServerSummary> catalog_setup_dns_server_summary;
        std::optional<Intent> catalog_setup_intent;
        std::optional<CatalogSetupListSummary> catalog_setup_list_summary;
        std::optional<CatalogSetupModeEnum> catalog_setup_mode;
        std::optional<CatalogSetupPreviewRequest> catalog_setup_preview_request;
        std::optional<CatalogSetupPreviewResponse> catalog_setup_preview_response;
        std::optional<RouteRule> catalog_setup_route_rule_summary;
        std::optional<CatalogSetupSummaryClass> catalog_setup_summary;
        std::optional<CatalogSetupWarningElement> catalog_setup_warning;
        std::optional<CheckStatus> check_status;
        std::optional<CircuitBreakerConfig> circuit_breaker_config;
        std::optional<ClientDnsEnforcement> client_dns_enforcement;
        std::optional<ConfigObject> config_object;
        std::optional<ConfigStateResponse> config_state_response;
        std::optional<ConfigUpdateResponse> config_update_response;
        std::optional<ConnectionEventState> connection_event_state;
        std::optional<ConnectionPage> connection_page;
        std::optional<ConnectionQueryRequest> connection_query_request;
        std::optional<ConnectionRecord> connection_record;
        std::optional<ConnectionSort> connection_sort;
        std::optional<ConntrackOnSwitch> conntrack_on_switch;
        std::optional<Daemon> daemon_config;
        std::optional<DependencyAnalysisRequest> dependency_analysis_request;
        std::optional<DependencyAnalysisResponse> dependency_analysis_response;
        std::optional<DependencyAnalysisTargetRequest> dependency_analysis_target_request;
        std::optional<DependencyConsequence> dependency_consequence;
        std::optional<DependencyDependentKind> dependency_dependent_kind;
        std::optional<DependencyEntityKind> dependency_entity_kind;
        std::optional<DependencyReference> dependency_reference;
        std::optional<DependencyRelation> dependency_relation;
        std::optional<DependencyTarget> dependency_target;
        std::optional<Dns> dns_config;
        std::optional<DnsRuleElement> dns_rule;
        std::optional<DnsServerElement> dns_server;
        std::optional<SystemResolver> dns_system_resolver;
        std::optional<DnsTestServer> dns_test_server;
        std::optional<ErrorResponse> error_response;
        std::optional<FirewallChain> firewall_chain;
        std::optional<FirewallRuleCheck> firewall_rule_check;
        std::optional<Fwmark> fwmark_config;
        std::optional<HealthResponse> health_response;
        std::optional<InternalVpnServerElement> internal_vpn_server;
        std::optional<InternalVpnServiceElement> internal_vpn_service;
        std::optional<Iproute> iproute_config;
        std::optional<LifecycleOperation> lifecycle_operation;
        std::optional<LifecycleOperationStageElement> lifecycle_operation_stage;
        std::optional<ListConfigValue> list_config;
        std::optional<ListDeleteStageRequest> list_delete_stage_request;
        std::optional<ListDeleteStageResponse> list_delete_stage_response;
        std::optional<ListDeleteStageSummaryClass> list_delete_stage_summary;
        std::optional<ListDeleteTargetElement> list_delete_target;
        std::optional<ListRefresh> list_refresh_config;
        std::optional<RefreshDetourMode> list_refresh_detour_mode;
        std::optional<ListRefreshRequest> list_refresh_request;
        std::optional<ListRefreshResponse> list_refresh_response;
        std::optional<ListRefreshStateValue> list_refresh_state;
        std::optional<ListsAutoupdate> lists_autoupdate_config;
        std::optional<NdmsCatalogStatus> ndms_catalog_status;
        std::optional<NdmsInterfaceCapabilities> ndms_interface_capabilities;
        std::optional<NdmsInterfaceInventoryResponse> ndms_interface_inventory_response;
        std::optional<NdmsInterfaceManagementReadiness> ndms_interface_management_readiness;
        std::optional<Role> ndms_interface_role;
        std::optional<NdmsManagementBlockerElement> ndms_management_blocker;
        std::optional<NdmsTunnelInterfaceElement> ndms_tunnel_interface;
        std::optional<Kind> ndms_tunnel_kind;
        std::optional<NdmsVpnServerKind> ndms_vpn_server_kind;
        std::optional<NdmsVpnServerService> ndms_vpn_server_service;
        std::optional<NdmsVpnServerServiceInventoryResponse> ndms_vpn_server_service_inventory_response;
        std::optional<OutboundElement> outbound;
        std::optional<OutboundGroupElement> outbound_group;
        std::optional<PeriodicTaskMetricsEntry> periodic_task_metrics_entry;
        std::optional<PeriodicTaskMetricsResponse> periodic_task_metrics_response;
        std::optional<LastOutcome> periodic_task_outcome;
        std::optional<PlainDnsTemplateElement> plain_dns_template;
        std::optional<PolicyRuleCheck> policy_rule_check;
        std::optional<RecommendedListSetupRequest> recommended_list_setup_request;
        std::optional<ReloadResponse> reload_response;
        std::optional<ResolverConfigProbeStatus> resolver_config_probe_status;
        std::optional<ResolverConfigSyncState> resolver_config_sync_state;
        std::optional<Retry> retry_config;
        std::optional<Route> route_config;
        std::optional<RouteRuleElement> route_rule;
        std::optional<RouteTableCheck> route_table_check;
        std::optional<RoutingHealthErrorResponse> routing_health_error_response;
        std::optional<RoutingHealthResponse> routing_health_response;
        std::optional<RoutingTestEntry> routing_test_entry;
        std::optional<Evaluation> routing_test_evaluation;
        std::optional<ListMatch> routing_test_list_match;
        std::optional<RoutingTestRequest> routing_test_request;
        std::optional<RoutingTestResponse> routing_test_response;
        std::optional<RoutingTestRuleDiagnosticElement> routing_test_rule_diagnostic;
        std::optional<RoutingTestRuleIpDiagnosticElement> routing_test_rule_ip_diagnostic;
        std::optional<RoutingTestUnknownConditionElement> routing_test_unknown_condition;
        std::optional<RuntimeInterfaceInventoryEntry> runtime_interface_inventory_entry;
        std::optional<RuntimeInterfaceInventoryResponse> runtime_interface_inventory_response;
        std::optional<RuntimeInterfaceInventoryStatusEnum> runtime_interface_inventory_status;
        std::optional<RuntimeInterfaceState> runtime_interface_state;
        std::optional<RuntimeInterfaceStatusEnum> runtime_interface_status;
        std::optional<Traffic> runtime_interface_traffic;
        std::optional<RuntimeInterfaceTrafficPointElement> runtime_interface_traffic_point;
        std::optional<RuntimeInterfaceTrafficSample> runtime_interface_traffic_sample;
        std::optional<RuntimeInterfaceTrafficUpdate> runtime_interface_traffic_update;
        std::optional<LinkUptimeSource> runtime_interface_uptime_source;
        std::optional<RuntimeInventoryResponse> runtime_inventory_response;
        std::optional<RuntimeOutboundsResponse> runtime_outbounds_response;
        std::optional<RuntimeOutboundStateElement> runtime_outbound_state;
        std::optional<ResolverLiveStatus> runtime_outbound_status;
        std::optional<SortOrder> sort_order;
        std::optional<StatusEventConnections> status_event_connections;
        std::optional<StatusEventInterfaces> status_event_interfaces;
        std::optional<StatusEventInterfaceTraffic> status_event_interface_traffic;
        std::optional<StatusEventOutbounds> status_event_outbounds;
        std::optional<StatusEventService> status_event_service;
        std::optional<StatusEventSnapshot> status_event_snapshot;
        std::optional<TransportActionRequest> transport_action_request;
        std::optional<TransportActionResponse> transport_action_response;
        std::optional<TransportConfigApplyRequest> transport_config_apply_request;
        std::optional<TransportConfigApplyResponse> transport_config_apply_response;
        std::optional<TransportConfigOperation> transport_config_operation;
        std::optional<TransportConfigResponse> transport_config_response;
        std::optional<LinkedOutbound> transport_linked_outbound_ensure;
        std::optional<TransportPath> transport_path;
        std::optional<Transport> transport_spec;
        std::optional<TransportStatus> transport_status;
        std::optional<UiPreferences> ui_preferences_config;
        std::optional<ValidationErrorElement> validation_error;
        std::optional<Vless> vless_reality_spec;
    };
}
}

namespace keen_pbr3 {
namespace api {
    void from_json(const json & j, ApiConfig & x);
    void to_json(json & j, const ApiConfig & x);

    void from_json(const json & j, CacheGeneration & x);
    void to_json(json & j, const CacheGeneration & x);

    void from_json(const json & j, CacheMetadata & x);
    void to_json(json & j, const CacheMetadata & x);

    void from_json(const json & j, CatalogPresetSelection & x);
    void to_json(json & j, const CatalogPresetSelection & x);

    void from_json(const json & j, Intent & x);
    void to_json(json & j, const Intent & x);

    void from_json(const json & j, CatalogSetupApplyRequest & x);
    void to_json(json & j, const CatalogSetupApplyRequest & x);

    void from_json(const json & j, CatalogSetupApplyResponse & x);
    void to_json(json & j, const CatalogSetupApplyResponse & x);

    void from_json(const json & j, CatalogSetupBlackholeSummary & x);
    void to_json(json & j, const CatalogSetupBlackholeSummary & x);

    void from_json(const json & j, CatalogSetupDnsRuleSummary & x);
    void to_json(json & j, const CatalogSetupDnsRuleSummary & x);

    void from_json(const json & j, CatalogSetupDnsServerSummary & x);
    void to_json(json & j, const CatalogSetupDnsServerSummary & x);

    void from_json(const json & j, CatalogSetupListSummary & x);
    void to_json(json & j, const CatalogSetupListSummary & x);

    void from_json(const json & j, CatalogSetupPreviewRequest & x);
    void to_json(json & j, const CatalogSetupPreviewRequest & x);

    void from_json(const json & j, RouteRule & x);
    void to_json(json & j, const RouteRule & x);

    void from_json(const json & j, CatalogSetupSummaryClass & x);
    void to_json(json & j, const CatalogSetupSummaryClass & x);

    void from_json(const json & j, CatalogSetupWarningElement & x);
    void to_json(json & j, const CatalogSetupWarningElement & x);

    void from_json(const json & j, CatalogSetupPreviewResponse & x);
    void to_json(json & j, const CatalogSetupPreviewResponse & x);

    void from_json(const json & j, CircuitBreakerConfig & x);
    void to_json(json & j, const CircuitBreakerConfig & x);

    void from_json(const json & j, ClientDnsEnforcement & x);
    void to_json(json & j, const ClientDnsEnforcement & x);

    void from_json(const json & j, Daemon & x);
    void to_json(json & j, const Daemon & x);

    void from_json(const json & j, DnsTestServer & x);
    void to_json(json & j, const DnsTestServer & x);

    void from_json(const json & j, DnsRuleElement & x);
    void to_json(json & j, const DnsRuleElement & x);

    void from_json(const json & j, DnsServerElement & x);
    void to_json(json & j, const DnsServerElement & x);

    void from_json(const json & j, SystemResolver & x);
    void to_json(json & j, const SystemResolver & x);

    void from_json(const json & j, Dns & x);
    void to_json(json & j, const Dns & x);

    void from_json(const json & j, Fwmark & x);
    void to_json(json & j, const Fwmark & x);

    void from_json(const json & j, Iproute & x);
    void to_json(json & j, const Iproute & x);

    void from_json(const json & j, ListRefresh & x);
    void to_json(json & j, const ListRefresh & x);

    void from_json(const json & j, ListConfigValue & x);
    void to_json(json & j, const ListConfigValue & x);

    void from_json(const json & j, ListsAutoupdate & x);
    void to_json(json & j, const ListsAutoupdate & x);

    void from_json(const json & j, OutboundGroupElement & x);
    void to_json(json & j, const OutboundGroupElement & x);

    void from_json(const json & j, Retry & x);
    void to_json(json & j, const Retry & x);

    void from_json(const json & j, OutboundElement & x);
    void to_json(json & j, const OutboundElement & x);

    void from_json(const json & j, InternalVpnServerElement & x);
    void to_json(json & j, const InternalVpnServerElement & x);

    void from_json(const json & j, InternalVpnServiceElement & x);
    void to_json(json & j, const InternalVpnServiceElement & x);

    void from_json(const json & j, RouteRuleElement & x);
    void to_json(json & j, const RouteRuleElement & x);

    void from_json(const json & j, Route & x);
    void to_json(json & j, const Route & x);

    void from_json(const json & j, PlainDnsTemplateElement & x);
    void to_json(json & j, const PlainDnsTemplateElement & x);

    void from_json(const json & j, UiPreferences & x);
    void to_json(json & j, const UiPreferences & x);

    void from_json(const json & j, ConfigObject & x);
    void to_json(json & j, const ConfigObject & x);

    void from_json(const json & j, ListRefreshStateValue & x);
    void to_json(json & j, const ListRefreshStateValue & x);

    void from_json(const json & j, ConfigStateResponse & x);
    void to_json(json & j, const ConfigStateResponse & x);

    void from_json(const json & j, ConfigUpdateResponse & x);
    void to_json(json & j, const ConfigUpdateResponse & x);

    void from_json(const json & j, ConnectionEventState & x);
    void to_json(json & j, const ConnectionEventState & x);

    void from_json(const json & j, ConnectionRecord & x);
    void to_json(json & j, const ConnectionRecord & x);

    void from_json(const json & j, ConnectionPage & x);
    void to_json(json & j, const ConnectionPage & x);

    void from_json(const json & j, ConnectionQueryRequest & x);
    void to_json(json & j, const ConnectionQueryRequest & x);

    void from_json(const json & j, DependencyAnalysisTargetRequest & x);
    void to_json(json & j, const DependencyAnalysisTargetRequest & x);

    void from_json(const json & j, DependencyAnalysisRequest & x);
    void to_json(json & j, const DependencyAnalysisRequest & x);

    void from_json(const json & j, DependencyTarget & x);
    void to_json(json & j, const DependencyTarget & x);

    void from_json(const json & j, DependencyReference & x);
    void to_json(json & j, const DependencyReference & x);

    void from_json(const json & j, DependencyAnalysisResponse & x);
    void to_json(json & j, const DependencyAnalysisResponse & x);

    void from_json(const json & j, ValidationErrorElement & x);
    void to_json(json & j, const ValidationErrorElement & x);

    void from_json(const json & j, ErrorResponse & x);
    void to_json(json & j, const ErrorResponse & x);

    void from_json(const json & j, FirewallChain & x);
    void to_json(json & j, const FirewallChain & x);

    void from_json(const json & j, FirewallRuleCheck & x);
    void to_json(json & j, const FirewallRuleCheck & x);

    void from_json(const json & j, LifecycleOperationStageElement & x);
    void to_json(json & j, const LifecycleOperationStageElement & x);

    void from_json(const json & j, LifecycleOperation & x);
    void to_json(json & j, const LifecycleOperation & x);

    void from_json(const json & j, HealthResponse & x);
    void to_json(json & j, const HealthResponse & x);

    void from_json(const json & j, ListDeleteTargetElement & x);
    void to_json(json & j, const ListDeleteTargetElement & x);

    void from_json(const json & j, ListDeleteStageRequest & x);
    void to_json(json & j, const ListDeleteStageRequest & x);

    void from_json(const json & j, ListDeleteStageSummaryClass & x);
    void to_json(json & j, const ListDeleteStageSummaryClass & x);

    void from_json(const json & j, ListDeleteStageResponse & x);
    void to_json(json & j, const ListDeleteStageResponse & x);

    void from_json(const json & j, ListRefreshRequest & x);
    void to_json(json & j, const ListRefreshRequest & x);

    void from_json(const json & j, ListRefreshResponse & x);
    void to_json(json & j, const ListRefreshResponse & x);

    void from_json(const json & j, NdmsInterfaceCapabilities & x);
    void to_json(json & j, const NdmsInterfaceCapabilities & x);

    void from_json(const json & j, NdmsInterfaceManagementReadiness & x);
    void to_json(json & j, const NdmsInterfaceManagementReadiness & x);

    void from_json(const json & j, NdmsTunnelInterfaceElement & x);
    void to_json(json & j, const NdmsTunnelInterfaceElement & x);

    void from_json(const json & j, NdmsInterfaceInventoryResponse & x);
    void to_json(json & j, const NdmsInterfaceInventoryResponse & x);

    void from_json(const json & j, NdmsVpnServerService & x);
    void to_json(json & j, const NdmsVpnServerService & x);

    void from_json(const json & j, NdmsVpnServerServiceInventoryResponse & x);
    void to_json(json & j, const NdmsVpnServerServiceInventoryResponse & x);

    void from_json(const json & j, PeriodicTaskMetricsEntry & x);
    void to_json(json & j, const PeriodicTaskMetricsEntry & x);

    void from_json(const json & j, PeriodicTaskMetricsResponse & x);
    void to_json(json & j, const PeriodicTaskMetricsResponse & x);

    void from_json(const json & j, PolicyRuleCheck & x);
    void to_json(json & j, const PolicyRuleCheck & x);

    void from_json(const json & j, RecommendedListSetupRequest & x);
    void to_json(json & j, const RecommendedListSetupRequest & x);

    void from_json(const json & j, ReloadResponse & x);
    void to_json(json & j, const ReloadResponse & x);

    void from_json(const json & j, RouteTableCheck & x);
    void to_json(json & j, const RouteTableCheck & x);

    void from_json(const json & j, RoutingHealthErrorResponse & x);
    void to_json(json & j, const RoutingHealthErrorResponse & x);

    void from_json(const json & j, RoutingHealthResponse & x);
    void to_json(json & j, const RoutingHealthResponse & x);

    void from_json(const json & j, ListMatch & x);
    void to_json(json & j, const ListMatch & x);

    void from_json(const json & j, RoutingTestEntry & x);
    void to_json(json & j, const RoutingTestEntry & x);

    void from_json(const json & j, RoutingTestRequest & x);
    void to_json(json & j, const RoutingTestRequest & x);

    void from_json(const json & j, RoutingTestRuleIpDiagnosticElement & x);
    void to_json(json & j, const RoutingTestRuleIpDiagnosticElement & x);

    void from_json(const json & j, RoutingTestRuleDiagnosticElement & x);
    void to_json(json & j, const RoutingTestRuleDiagnosticElement & x);

    void from_json(const json & j, RoutingTestResponse & x);
    void to_json(json & j, const RoutingTestResponse & x);

    void from_json(const json & j, RuntimeInterfaceTrafficPointElement & x);
    void to_json(json & j, const RuntimeInterfaceTrafficPointElement & x);

    void from_json(const json & j, Traffic & x);
    void to_json(json & j, const Traffic & x);

    void from_json(const json & j, RuntimeInterfaceInventoryEntry & x);
    void to_json(json & j, const RuntimeInterfaceInventoryEntry & x);

    void from_json(const json & j, RuntimeInterfaceInventoryResponse & x);
    void to_json(json & j, const RuntimeInterfaceInventoryResponse & x);

    void from_json(const json & j, RuntimeInterfaceState & x);
    void to_json(json & j, const RuntimeInterfaceState & x);

    void from_json(const json & j, RuntimeInterfaceTrafficSample & x);
    void to_json(json & j, const RuntimeInterfaceTrafficSample & x);

    void from_json(const json & j, RuntimeInterfaceTrafficUpdate & x);
    void to_json(json & j, const RuntimeInterfaceTrafficUpdate & x);

    void from_json(const json & j, RuntimeOutboundStateElement & x);
    void to_json(json & j, const RuntimeOutboundStateElement & x);

    void from_json(const json & j, RuntimeOutboundsResponse & x);
    void to_json(json & j, const RuntimeOutboundsResponse & x);

    void from_json(const json & j, RuntimeInventoryResponse & x);
    void to_json(json & j, const RuntimeInventoryResponse & x);

    void from_json(const json & j, StatusEventConnections & x);
    void to_json(json & j, const StatusEventConnections & x);

    void from_json(const json & j, StatusEventInterfaceTraffic & x);
    void to_json(json & j, const StatusEventInterfaceTraffic & x);

    void from_json(const json & j, StatusEventInterfaces & x);
    void to_json(json & j, const StatusEventInterfaces & x);

    void from_json(const json & j, StatusEventOutbounds & x);
    void to_json(json & j, const StatusEventOutbounds & x);

    void from_json(const json & j, StatusEventService & x);
    void to_json(json & j, const StatusEventService & x);

    void from_json(const json & j, StatusEventSnapshot & x);
    void to_json(json & j, const StatusEventSnapshot & x);

    void from_json(const json & j, TransportActionRequest & x);
    void to_json(json & j, const TransportActionRequest & x);

    void from_json(const json & j, TransportActionResponse & x);
    void to_json(json & j, const TransportActionResponse & x);

    void from_json(const json & j, LinkedOutbound & x);
    void to_json(json & j, const LinkedOutbound & x);

    void from_json(const json & j, Vless & x);
    void to_json(json & j, const Vless & x);

    void from_json(const json & j, Transport & x);
    void to_json(json & j, const Transport & x);

    void from_json(const json & j, TransportConfigApplyRequest & x);
    void to_json(json & j, const TransportConfigApplyRequest & x);

    void from_json(const json & j, TransportConfigApplyResponse & x);
    void to_json(json & j, const TransportConfigApplyResponse & x);

    void from_json(const json & j, TransportConfigOperation & x);
    void to_json(json & j, const TransportConfigOperation & x);

    void from_json(const json & j, TransportConfigResponse & x);
    void to_json(json & j, const TransportConfigResponse & x);

    void from_json(const json & j, TransportPath & x);
    void to_json(json & j, const TransportPath & x);

    void from_json(const json & j, TransportStatus & x);
    void to_json(json & j, const TransportStatus & x);

    void from_json(const json & j, ApiTypes & x);
    void to_json(json & j, const ApiTypes & x);

    void from_json(const json & j, DnsMode & x);
    void to_json(json & j, const DnsMode & x);

    void from_json(const json & j, CatalogSetupModeEnum & x);
    void to_json(json & j, const CatalogSetupModeEnum & x);

    void from_json(const json & j, Code & x);
    void to_json(json & j, const Code & x);

    void from_json(const json & j, CheckStatus & x);
    void to_json(json & j, const CheckStatus & x);

    void from_json(const json & j, DaemonConfigFirewallBackend & x);
    void to_json(json & j, const DaemonConfigFirewallBackend & x);

    void from_json(const json & j, MetaUdp443Policy & x);
    void to_json(json & j, const MetaUdp443Policy & x);

    void from_json(const json & j, DnsServerType & x);
    void to_json(json & j, const DnsServerType & x);

    void from_json(const json & j, RefreshDetourMode & x);
    void to_json(json & j, const RefreshDetourMode & x);

    void from_json(const json & j, ConntrackOnSwitch & x);
    void to_json(json & j, const ConntrackOnSwitch & x);

    void from_json(const json & j, SelectionMode & x);
    void to_json(json & j, const SelectionMode & x);

    void from_json(const json & j, OutboundType & x);
    void to_json(json & j, const OutboundType & x);

    void from_json(const json & j, ConfigUpdateResponseStatus & x);
    void to_json(json & j, const ConfigUpdateResponseStatus & x);

    void from_json(const json & j, SortOrder & x);
    void to_json(json & j, const SortOrder & x);

    void from_json(const json & j, ConnectionSort & x);
    void to_json(json & j, const ConnectionSort & x);

    void from_json(const json & j, DependencyEntityKind & x);
    void to_json(json & j, const DependencyEntityKind & x);

    void from_json(const json & j, DependencyConsequence & x);
    void to_json(json & j, const DependencyConsequence & x);

    void from_json(const json & j, DependencyDependentKind & x);
    void to_json(json & j, const DependencyDependentKind & x);

    void from_json(const json & j, DependencyRelation & x);
    void to_json(json & j, const DependencyRelation & x);

    void from_json(const json & j, LifecycleOperationStageStatus & x);
    void to_json(json & j, const LifecycleOperationStageStatus & x);

    void from_json(const json & j, LifecycleOperationStatus & x);
    void to_json(json & j, const LifecycleOperationStatus & x);

    void from_json(const json & j, LifecycleOperationType & x);
    void to_json(json & j, const LifecycleOperationType & x);

    void from_json(const json & j, ResolverConfigProbeStatus & x);
    void to_json(json & j, const ResolverConfigProbeStatus & x);

    void from_json(const json & j, ResolverConfigSyncState & x);
    void to_json(json & j, const ResolverConfigSyncState & x);

    void from_json(const json & j, ResolverLiveStatus & x);
    void to_json(json & j, const ResolverLiveStatus & x);

    void from_json(const json & j, RuntimeState & x);
    void to_json(json & j, const RuntimeState & x);

    void from_json(const json & j, HealthResponseStatus & x);
    void to_json(json & j, const HealthResponseStatus & x);

    void from_json(const json & j, NdmsCatalogStatus & x);
    void to_json(json & j, const NdmsCatalogStatus & x);

    void from_json(const json & j, Kind & x);
    void to_json(json & j, const Kind & x);

    void from_json(const json & j, NdmsManagementBlockerElement & x);
    void to_json(json & j, const NdmsManagementBlockerElement & x);

    void from_json(const json & j, Owner & x);
    void to_json(json & j, const Owner & x);

    void from_json(const json & j, Role & x);
    void to_json(json & j, const Role & x);

    void from_json(const json & j, MutationMode & x);
    void to_json(json & j, const MutationMode & x);

    void from_json(const json & j, RequiredGuard & x);
    void to_json(json & j, const RequiredGuard & x);

    void from_json(const json & j, NdmsVpnServerKind & x);
    void to_json(json & j, const NdmsVpnServerKind & x);

    void from_json(const json & j, LastOutcome & x);
    void to_json(json & j, const LastOutcome & x);

    void from_json(const json & j, RoutingHealthErrorResponseOverall & x);
    void to_json(json & j, const RoutingHealthErrorResponseOverall & x);

    void from_json(const json & j, RoutingHealthResponseFirewallBackend & x);
    void to_json(json & j, const RoutingHealthResponseFirewallBackend & x);

    void from_json(const json & j, RoutingHealthResponseOverall & x);
    void to_json(json & j, const RoutingHealthResponseOverall & x);

    void from_json(const json & j, Evaluation & x);
    void to_json(json & j, const Evaluation & x);

    void from_json(const json & j, RoutingTestUnknownConditionElement & x);
    void to_json(json & j, const RoutingTestUnknownConditionElement & x);

    void from_json(const json & j, ConfigScope & x);
    void to_json(json & j, const ConfigScope & x);

    void from_json(const json & j, LinkUptimeSource & x);
    void to_json(json & j, const LinkUptimeSource & x);

    void from_json(const json & j, RuntimeInterfaceInventoryStatusEnum & x);
    void to_json(json & j, const RuntimeInterfaceInventoryStatusEnum & x);

    void from_json(const json & j, RuntimeInterfaceStatusEnum & x);
    void to_json(json & j, const RuntimeInterfaceStatusEnum & x);

    void from_json(const json & j, StatusEventConnectionsType & x);
    void to_json(json & j, const StatusEventConnectionsType & x);

    void from_json(const json & j, StatusEventInterfaceTrafficType & x);
    void to_json(json & j, const StatusEventInterfaceTrafficType & x);

    void from_json(const json & j, StatusEventInterfacesType & x);
    void to_json(json & j, const StatusEventInterfacesType & x);

    void from_json(const json & j, StatusEventOutboundsType & x);
    void to_json(json & j, const StatusEventOutboundsType & x);

    void from_json(const json & j, StatusEventServiceType & x);
    void to_json(json & j, const StatusEventServiceType & x);

    void from_json(const json & j, StatusEventSnapshotType & x);
    void to_json(json & j, const StatusEventSnapshotType & x);

    void from_json(const json & j, Action & x);
    void to_json(json & j, const Action & x);

    void from_json(const json & j, TransportActionResponseStatus & x);
    void to_json(json & j, const TransportActionResponseStatus & x);

    void from_json(const json & j, TransportLinkedOutboundEnsureMode & x);
    void to_json(json & j, const TransportLinkedOutboundEnsureMode & x);

    void from_json(const json & j, TransportConfigApplyRequestOperation & x);
    void to_json(json & j, const TransportConfigApplyRequestOperation & x);

    void from_json(const json & j, GeoMode & x);
    void to_json(json & j, const GeoMode & x);

    void from_json(const json & j, TransportSpecType & x);
    void to_json(json & j, const TransportSpecType & x);

    void from_json(const json & j, TransportConfigApplyResponseStatus & x);
    void to_json(json & j, const TransportConfigApplyResponseStatus & x);

    void from_json(const json & j, TransportConfigOperationOperation & x);
    void to_json(json & j, const TransportConfigOperationOperation & x);

    void from_json(const json & j, TransportConfigResponseStatus & x);
    void to_json(json & j, const TransportConfigResponseStatus & x);

    void from_json(const json & j, Confidence & x);
    void to_json(json & j, const Confidence & x);

    void from_json(const json & j, Framing & x);
    void to_json(json & j, const Framing & x);

    void from_json(const json & j, PayloadNetwork & x);
    void to_json(json & j, const PayloadNetwork & x);

    void from_json(const json & j, WireTransport & x);
    void to_json(json & j, const WireTransport & x);

    void from_json(const json & j, Security & x);
    void to_json(json & j, const Security & x);

    void from_json(const json & j, State & x);
    void to_json(json & j, const State & x);

    inline void from_json(const json & j, ApiConfig& x) {
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.listen = get_stack_optional<std::string>(j, "listen");
    }

    inline void to_json(json & j, const ApiConfig & x) {
        j = json::object();
        j["enabled"] = x.enabled;
        j["listen"] = x.listen;
    }

    inline void from_json(const json & j, CacheGeneration& x) {
        x.filename = j.at("filename").get<std::string>();
        x.sha256 = j.at("sha256").get<std::string>();
        x.size = j.at("size").get<int64_t>();
    }

    inline void to_json(json & j, const CacheGeneration & x) {
        j = json::object();
        j["filename"] = x.filename;
        j["sha256"] = x.sha256;
        j["size"] = x.size;
    }

    inline void from_json(const json & j, CacheMetadata& x) {
        x.cidrs = get_stack_optional<int64_t>(j, "cidrs");
        x.current = get_stack_optional<CacheGeneration>(j, "current");
        x.domains = get_stack_optional<int64_t>(j, "domains");
        x.download_time = get_stack_optional<std::string>(j, "download_time");
        x.etag = get_stack_optional<std::string>(j, "etag");
        x.ips = get_stack_optional<int64_t>(j, "ips");
        x.last_modified = get_stack_optional<std::string>(j, "last_modified");
        x.last_refresh_attempt = get_stack_optional<std::string>(j, "last_refresh_attempt");
        x.last_refresh_detour = get_stack_optional<std::string>(j, "last_refresh_detour");
        x.last_refresh_error = get_stack_optional<std::string>(j, "last_refresh_error");
        x.last_refresh_url = get_stack_optional<std::string>(j, "last_refresh_url");
        x.previous = get_stack_optional<CacheGeneration>(j, "previous");
        x.srs_decoder_revision = get_stack_optional<int64_t>(j, "srs_decoder_revision");
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const CacheMetadata & x) {
        j = json::object();
        j["cidrs"] = x.cidrs;
        j["current"] = x.current;
        j["domains"] = x.domains;
        j["download_time"] = x.download_time;
        j["etag"] = x.etag;
        j["ips"] = x.ips;
        j["last_modified"] = x.last_modified;
        j["last_refresh_attempt"] = x.last_refresh_attempt;
        j["last_refresh_detour"] = x.last_refresh_detour;
        j["last_refresh_error"] = x.last_refresh_error;
        j["last_refresh_url"] = x.last_refresh_url;
        j["previous"] = x.previous;
        j["srs_decoder_revision"] = x.srs_decoder_revision;
        j["url"] = x.url;
    }

    inline void from_json(const json & j, CatalogPresetSelection& x) {
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.preset_id = j.at("preset_id").get<std::string>();
    }

    inline void to_json(json & j, const CatalogPresetSelection & x) {
        j = json::object();
        j["display_name"] = x.display_name;
        j["preset_id"] = x.preset_id;
    }

    inline void from_json(const json & j, Intent& x) {
        x.dns_display_name = get_stack_optional<std::string>(j, "dns_display_name");
        x.dns_mode = j.at("dns_mode").get<DnsMode>();
        x.dns_server_tag = get_stack_optional<std::string>(j, "dns_server_tag");
        x.mode = j.at("mode").get<CatalogSetupModeEnum>();
        x.outbound_tag = get_stack_optional<std::string>(j, "outbound_tag");
        x.route_display_name = get_stack_optional<std::string>(j, "route_display_name");
        x.selections = j.at("selections").get<std::vector<CatalogPresetSelection>>();
        x.source_detour_tag = get_stack_optional<std::string>(j, "source_detour_tag");
    }

    inline void to_json(json & j, const Intent & x) {
        j = json::object();
        j["dns_display_name"] = x.dns_display_name;
        j["dns_mode"] = x.dns_mode;
        j["dns_server_tag"] = x.dns_server_tag;
        j["mode"] = x.mode;
        j["outbound_tag"] = x.outbound_tag;
        j["route_display_name"] = x.route_display_name;
        j["selections"] = x.selections;
        j["source_detour_tag"] = x.source_detour_tag;
    }

    inline void from_json(const json & j, CatalogSetupApplyRequest& x) {
        x.accept_warnings = j.at("accept_warnings").get<bool>();
        x.base_revision = j.at("base_revision").get<std::string>();
        x.candidate_revision = j.at("candidate_revision").get<std::string>();
        x.intent = j.at("intent").get<Intent>();
        x.preview_token = j.at("preview_token").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupApplyRequest & x) {
        j = json::object();
        j["accept_warnings"] = x.accept_warnings;
        j["base_revision"] = x.base_revision;
        j["candidate_revision"] = x.candidate_revision;
        j["intent"] = x.intent;
        j["preview_token"] = x.preview_token;
    }

    inline void from_json(const json & j, CatalogSetupApplyResponse& x) {
        x.applied = j.at("applied").get<bool>();
        x.apply_started_ts = get_stack_optional<int64_t>(j, "apply_started_ts");
        x.config_revision = j.at("config_revision").get<std::string>();
        x.message = j.at("message").get<std::string>();
        x.rolled_back = j.at("rolled_back").get<bool>();
        x.saved = j.at("saved").get<bool>();
        x.status = j.at("status").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupApplyResponse & x) {
        j = json::object();
        j["applied"] = x.applied;
        j["apply_started_ts"] = x.apply_started_ts;
        j["config_revision"] = x.config_revision;
        j["message"] = x.message;
        j["rolled_back"] = x.rolled_back;
        j["saved"] = x.saved;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, CatalogSetupBlackholeSummary& x) {
        x.created = j.at("created").get<bool>();
        x.tag = j.at("tag").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupBlackholeSummary & x) {
        j = json::object();
        j["created"] = x.created;
        j["tag"] = x.tag;
    }

    inline void from_json(const json & j, CatalogSetupDnsRuleSummary& x) {
        x.display_name = j.at("display_name").get<std::string>();
        x.insertion_index = j.at("insertion_index").get<int64_t>();
        x.server = j.at("server").get<std::string>();
        x.technical_id = j.at("technical_id").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupDnsRuleSummary & x) {
        j = json::object();
        j["display_name"] = x.display_name;
        j["insertion_index"] = x.insertion_index;
        j["server"] = x.server;
        j["technical_id"] = x.technical_id;
    }

    inline void from_json(const json & j, CatalogSetupDnsServerSummary& x) {
        x.address = j.at("address").get<std::string>();
        x.created = j.at("created").get<bool>();
        x.detour = j.at("detour").get<std::string>();
        x.display_name = j.at("display_name").get<std::string>();
        x.technical_id = j.at("technical_id").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupDnsServerSummary & x) {
        j = json::object();
        j["address"] = x.address;
        j["created"] = x.created;
        j["detour"] = x.detour;
        j["display_name"] = x.display_name;
        j["technical_id"] = x.technical_id;
    }

    inline void from_json(const json & j, CatalogSetupListSummary& x) {
        x.already_installed = j.at("already_installed").get<bool>();
        x.display_name = j.at("display_name").get<std::string>();
        x.has_inline_cidrs = j.at("has_inline_cidrs").get<bool>();
        x.has_inline_domains = j.at("has_inline_domains").get<bool>();
        x.preset_id = j.at("preset_id").get<std::string>();
        x.source_detour = get_stack_optional<std::string>(j, "source_detour");
        x.technical_id = j.at("technical_id").get<std::string>();
        x.url_backed = j.at("url_backed").get<bool>();
    }

    inline void to_json(json & j, const CatalogSetupListSummary & x) {
        j = json::object();
        j["already_installed"] = x.already_installed;
        j["display_name"] = x.display_name;
        j["has_inline_cidrs"] = x.has_inline_cidrs;
        j["has_inline_domains"] = x.has_inline_domains;
        j["preset_id"] = x.preset_id;
        j["source_detour"] = x.source_detour;
        j["technical_id"] = x.technical_id;
        j["url_backed"] = x.url_backed;
    }

    inline void from_json(const json & j, CatalogSetupPreviewRequest& x) {
        x.intent = j.at("intent").get<Intent>();
    }

    inline void to_json(json & j, const CatalogSetupPreviewRequest & x) {
        j = json::object();
        j["intent"] = x.intent;
    }

    inline void from_json(const json & j, RouteRule& x) {
        x.blocking = j.at("blocking").get<bool>();
        x.display_name = j.at("display_name").get<std::string>();
        x.insertion_index = j.at("insertion_index").get<int64_t>();
        x.outbound = j.at("outbound").get<std::string>();
        x.technical_id = j.at("technical_id").get<std::string>();
    }

    inline void to_json(json & j, const RouteRule & x) {
        j = json::object();
        j["blocking"] = x.blocking;
        j["display_name"] = x.display_name;
        j["insertion_index"] = x.insertion_index;
        j["outbound"] = x.outbound;
        j["technical_id"] = x.technical_id;
    }

    inline void from_json(const json & j, CatalogSetupSummaryClass& x) {
        x.blackhole = get_stack_optional<CatalogSetupBlackholeSummary>(j, "blackhole");
        x.dns_rule = get_stack_optional<CatalogSetupDnsRuleSummary>(j, "dns_rule");
        x.dns_rules = get_stack_optional<std::vector<CatalogSetupDnsRuleSummary>>(j, "dns_rules");
        x.dns_server = get_stack_optional<CatalogSetupDnsServerSummary>(j, "dns_server");
        x.lists = j.at("lists").get<std::vector<CatalogSetupListSummary>>();
        x.mode = j.at("mode").get<CatalogSetupModeEnum>();
        x.route_rule = get_stack_optional<RouteRule>(j, "route_rule");
        x.route_rules = get_stack_optional<std::vector<RouteRule>>(j, "route_rules");
    }

    inline void to_json(json & j, const CatalogSetupSummaryClass & x) {
        j = json::object();
        j["blackhole"] = x.blackhole;
        j["dns_rule"] = x.dns_rule;
        j["dns_rules"] = x.dns_rules;
        j["dns_server"] = x.dns_server;
        j["lists"] = x.lists;
        j["mode"] = x.mode;
        j["route_rule"] = x.route_rule;
        j["route_rules"] = x.route_rules;
    }

    inline void from_json(const json & j, CatalogSetupWarningElement& x) {
        x.code = j.at("code").get<Code>();
        x.message = j.at("message").get<std::string>();
        x.path = j.at("path").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupWarningElement & x) {
        j = json::object();
        j["code"] = x.code;
        j["message"] = x.message;
        j["path"] = x.path;
    }

    inline void from_json(const json & j, CatalogSetupPreviewResponse& x) {
        x.base_revision = j.at("base_revision").get<std::string>();
        x.candidate_revision = j.at("candidate_revision").get<std::string>();
        x.preview_token = j.at("preview_token").get<std::string>();
        x.requires_warning_acceptance = j.at("requires_warning_acceptance").get<bool>();
        x.summary = j.at("summary").get<CatalogSetupSummaryClass>();
        x.warnings = j.at("warnings").get<std::vector<CatalogSetupWarningElement>>();
    }

    inline void to_json(json & j, const CatalogSetupPreviewResponse & x) {
        j = json::object();
        j["base_revision"] = x.base_revision;
        j["candidate_revision"] = x.candidate_revision;
        j["preview_token"] = x.preview_token;
        j["requires_warning_acceptance"] = x.requires_warning_acceptance;
        j["summary"] = x.summary;
        j["warnings"] = x.warnings;
    }

    inline void from_json(const json & j, CircuitBreakerConfig& x) {
        x.failure_threshold = get_stack_optional<int64_t>(j, "failure_threshold");
        x.half_open_max_requests = get_stack_optional<int64_t>(j, "half_open_max_requests");
        x.success_threshold = get_stack_optional<int64_t>(j, "success_threshold");
        x.timeout_ms = get_stack_optional<int64_t>(j, "timeout_ms");
    }

    inline void to_json(json & j, const CircuitBreakerConfig & x) {
        j = json::object();
        j["failure_threshold"] = x.failure_threshold;
        j["half_open_max_requests"] = x.half_open_max_requests;
        j["success_threshold"] = x.success_threshold;
        j["timeout_ms"] = x.timeout_ms;
    }

    inline void from_json(const json & j, ClientDnsEnforcement& x) {
        x.block_dot = get_stack_optional<bool>(j, "block_dot");
        x.enabled = get_stack_optional<bool>(j, "enabled");
    }

    inline void to_json(json & j, const ClientDnsEnforcement & x) {
        j = json::object();
        j["block_dot"] = x.block_dot;
        j["enabled"] = x.enabled;
    }

    inline void from_json(const json & j, Daemon& x) {
        x.cache_dir = get_stack_optional<std::string>(j, "cache_dir");
        x.clear_dynamic_sets_on_apply = get_stack_optional<bool>(j, "clear_dynamic_sets_on_apply");
        x.firewall_backend = get_stack_optional<DaemonConfigFirewallBackend>(j, "firewall_backend");
        x.firewall_verify_max_bytes = get_stack_optional<int64_t>(j, "firewall_verify_max_bytes");
        x.ipv6_enabled = get_stack_optional<bool>(j, "ipv6_enabled");
        x.max_file_size_bytes = get_stack_optional<int64_t>(j, "max_file_size_bytes");
        x.meta_udp443_policy = get_stack_optional<MetaUdp443Policy>(j, "meta_udp443_policy");
        x.pid_file = get_stack_optional<std::string>(j, "pid_file");
        x.reconnect_owned_flows_on_routing_change_lists = get_stack_optional<std::vector<std::string>>(j, "reconnect_owned_flows_on_routing_change_lists");
        x.reconnect_unmarked_flows_on_routing_change = get_stack_optional<bool>(j, "reconnect_unmarked_flows_on_routing_change");
        x.skip_marked_packets = get_stack_optional<bool>(j, "skip_marked_packets");
        x.strict_enforcement = get_stack_optional<bool>(j, "strict_enforcement");
    }

    inline void to_json(json & j, const Daemon & x) {
        j = json::object();
        j["cache_dir"] = x.cache_dir;
        j["clear_dynamic_sets_on_apply"] = x.clear_dynamic_sets_on_apply;
        j["firewall_backend"] = x.firewall_backend;
        j["firewall_verify_max_bytes"] = x.firewall_verify_max_bytes;
        j["ipv6_enabled"] = x.ipv6_enabled;
        j["max_file_size_bytes"] = x.max_file_size_bytes;
        j["meta_udp443_policy"] = x.meta_udp443_policy;
        j["pid_file"] = x.pid_file;
        j["reconnect_owned_flows_on_routing_change_lists"] = x.reconnect_owned_flows_on_routing_change_lists;
        j["reconnect_unmarked_flows_on_routing_change"] = x.reconnect_unmarked_flows_on_routing_change;
        j["skip_marked_packets"] = x.skip_marked_packets;
        j["strict_enforcement"] = x.strict_enforcement;
    }

    inline void from_json(const json & j, DnsTestServer& x) {
        x.answer_ipv4 = get_stack_optional<std::string>(j, "answer_ipv4");
        x.listen = j.at("listen").get<std::string>();
    }

    inline void to_json(json & j, const DnsTestServer & x) {
        j = json::object();
        j["answer_ipv4"] = x.answer_ipv4;
        j["listen"] = x.listen;
    }

    inline void from_json(const json & j, DnsRuleElement& x) {
        x.allow_domain_rebinding = get_stack_optional<bool>(j, "allow_domain_rebinding");
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.id = get_stack_optional<std::string>(j, "id");
        x.list = j.at("list").get<std::vector<std::string>>();
        x.server = j.at("server").get<std::string>();
    }

    inline void to_json(json & j, const DnsRuleElement & x) {
        j = json::object();
        j["allow_domain_rebinding"] = x.allow_domain_rebinding;
        j["display_name"] = x.display_name;
        j["enabled"] = x.enabled;
        j["id"] = x.id;
        j["list"] = x.list;
        j["server"] = x.server;
    }

    inline void from_json(const json & j, DnsServerElement& x) {
        x.address = get_stack_optional<std::string>(j, "address");
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.tag = j.at("tag").get<std::string>();
        x.type = get_stack_optional<DnsServerType>(j, "type");
    }

    inline void to_json(json & j, const DnsServerElement & x) {
        j = json::object();
        j["address"] = x.address;
        j["detour"] = x.detour;
        j["display_name"] = x.display_name;
        j["tag"] = x.tag;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, SystemResolver& x) {
        x.address = j.at("address").get<std::string>();
    }

    inline void to_json(json & j, const SystemResolver & x) {
        j = json::object();
        j["address"] = x.address;
    }

    inline void from_json(const json & j, Dns& x) {
        x.client_dns_enforcement = get_stack_optional<ClientDnsEnforcement>(j, "client_dns_enforcement");
        x.dns_test_server = get_stack_optional<DnsTestServer>(j, "dns_test_server");
        x.fallback = get_stack_optional<std::vector<std::string>>(j, "fallback");
        x.rules = get_stack_optional<std::vector<DnsRuleElement>>(j, "rules");
        x.servers = get_stack_optional<std::vector<DnsServerElement>>(j, "servers");
        x.system_resolver = get_stack_optional<SystemResolver>(j, "system_resolver");
    }

    inline void to_json(json & j, const Dns & x) {
        j = json::object();
        j["client_dns_enforcement"] = x.client_dns_enforcement;
        j["dns_test_server"] = x.dns_test_server;
        j["fallback"] = x.fallback;
        j["rules"] = x.rules;
        j["servers"] = x.servers;
        j["system_resolver"] = x.system_resolver;
    }

    inline void from_json(const json & j, Fwmark& x) {
        x.mask = get_stack_optional<std::string>(j, "mask");
        x.start = get_stack_optional<std::string>(j, "start");
    }

    inline void to_json(json & j, const Fwmark & x) {
        j = json::object();
        j["mask"] = x.mask;
        j["start"] = x.start;
    }

    inline void from_json(const json & j, Iproute& x) {
        x.table_start = get_stack_optional<int64_t>(j, "table_start");
    }

    inline void to_json(json & j, const Iproute & x) {
        j = json::object();
        j["table_start"] = x.table_start;
    }

    inline void from_json(const json & j, ListRefresh& x) {
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.fallback_detours = get_stack_optional<std::vector<std::string>>(j, "fallback_detours");
    }

    inline void to_json(json & j, const ListRefresh & x) {
        j = json::object();
        j["detour"] = x.detour;
        j["fallback_detours"] = x.fallback_detours;
    }

    inline void from_json(const json & j, ListConfigValue& x) {
        x.catalog_identity = get_stack_optional<std::string>(j, "catalog_identity");
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.domains = get_stack_optional<std::vector<std::string>>(j, "domains");
        x.fallback_detours = get_stack_optional<std::vector<std::string>>(j, "fallback_detours");
        x.file = get_stack_optional<std::string>(j, "file");
        x.ip_cidrs = get_stack_optional<std::vector<std::string>>(j, "ip_cidrs");
        x.refresh_detour_mode = get_stack_optional<RefreshDetourMode>(j, "refresh_detour_mode");
        x.ttl_ms = get_stack_optional<int64_t>(j, "ttl_ms");
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const ListConfigValue & x) {
        j = json::object();
        j["catalog_identity"] = x.catalog_identity;
        j["detour"] = x.detour;
        j["display_name"] = x.display_name;
        j["domains"] = x.domains;
        j["fallback_detours"] = x.fallback_detours;
        j["file"] = x.file;
        j["ip_cidrs"] = x.ip_cidrs;
        j["refresh_detour_mode"] = x.refresh_detour_mode;
        j["ttl_ms"] = x.ttl_ms;
        j["url"] = x.url;
    }

    inline void from_json(const json & j, ListsAutoupdate& x) {
        x.cron = get_stack_optional<std::string>(j, "cron");
        x.enabled = get_stack_optional<bool>(j, "enabled");
    }

    inline void to_json(json & j, const ListsAutoupdate & x) {
        j = json::object();
        j["cron"] = x.cron;
        j["enabled"] = x.enabled;
    }

    inline void from_json(const json & j, OutboundGroupElement& x) {
        x.outbounds = j.at("outbounds").get<std::vector<std::string>>();
        x.weight = get_stack_optional<int64_t>(j, "weight");
    }

    inline void to_json(json & j, const OutboundGroupElement & x) {
        j = json::object();
        j["outbounds"] = x.outbounds;
        j["weight"] = x.weight;
    }

    inline void from_json(const json & j, Retry& x) {
        x.attempts = get_stack_optional<int64_t>(j, "attempts");
        x.interval_ms = get_stack_optional<int64_t>(j, "interval_ms");
    }

    inline void to_json(json & j, const Retry & x) {
        j = json::object();
        j["attempts"] = x.attempts;
        j["interval_ms"] = x.interval_ms;
    }

    inline void from_json(const json & j, OutboundElement& x) {
        x.circuit_breaker = get_stack_optional<CircuitBreakerConfig>(j, "circuit_breaker");
        x.conntrack_on_switch = get_stack_optional<ConntrackOnSwitch>(j, "conntrack_on_switch");
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.gateway = get_stack_optional<std::string>(j, "gateway");
        x.gateway6 = get_stack_optional<std::string>(j, "gateway6");
        x.interface = get_stack_optional<std::string>(j, "interface");
        x.interval_ms = get_stack_optional<int64_t>(j, "interval_ms");
        x.outbound_groups = get_stack_optional<std::vector<OutboundGroupElement>>(j, "outbound_groups");
        x.probe_timeout_ms = get_stack_optional<int64_t>(j, "probe_timeout_ms");
        x.retry = get_stack_optional<Retry>(j, "retry");
        x.selection_mode = get_stack_optional<SelectionMode>(j, "selection_mode");
        x.strict_enforcement = get_stack_optional<bool>(j, "strict_enforcement");
        x.table = get_stack_optional<int64_t>(j, "table");
        x.tag = j.at("tag").get<std::string>();
        x.tolerance_ms = get_stack_optional<int64_t>(j, "tolerance_ms");
        x.type = j.at("type").get<OutboundType>();
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const OutboundElement & x) {
        j = json::object();
        j["circuit_breaker"] = x.circuit_breaker;
        j["conntrack_on_switch"] = x.conntrack_on_switch;
        j["display_name"] = x.display_name;
        j["gateway"] = x.gateway;
        j["gateway6"] = x.gateway6;
        j["interface"] = x.interface;
        j["interval_ms"] = x.interval_ms;
        j["outbound_groups"] = x.outbound_groups;
        j["probe_timeout_ms"] = x.probe_timeout_ms;
        j["retry"] = x.retry;
        j["selection_mode"] = x.selection_mode;
        j["strict_enforcement"] = x.strict_enforcement;
        j["table"] = x.table;
        j["tag"] = x.tag;
        j["tolerance_ms"] = x.tolerance_ms;
        j["type"] = x.type;
        j["url"] = x.url;
    }

    inline void from_json(const json & j, InternalVpnServerElement& x) {
        x.interface = j.at("interface").get<std::string>();
        x.ndms_id = get_stack_optional<std::string>(j, "ndms_id");
        x.process_clients = j.at("process_clients").get<bool>();
    }

    inline void to_json(json & j, const InternalVpnServerElement & x) {
        j = json::object();
        j["interface"] = x.interface;
        j["ndms_id"] = x.ndms_id;
        j["process_clients"] = x.process_clients;
    }

    inline void from_json(const json & j, InternalVpnServiceElement& x) {
        x.process_clients = j.at("process_clients").get<bool>();
        x.service_id = j.at("service_id").get<std::string>();
    }

    inline void to_json(json & j, const InternalVpnServiceElement & x) {
        j = json::object();
        j["process_clients"] = x.process_clients;
        j["service_id"] = x.service_id;
    }

    inline void from_json(const json & j, RouteRuleElement& x) {
        x.dest_addr = get_stack_optional<std::string>(j, "dest_addr");
        x.dest_port = get_stack_optional<std::string>(j, "dest_port");
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.dscp = get_stack_optional<int64_t>(j, "dscp");
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.id = get_stack_optional<std::string>(j, "id");
        x.list = get_stack_optional<std::vector<std::string>>(j, "list");
        x.outbound = j.at("outbound").get<std::string>();
        x.proto = get_stack_optional<std::string>(j, "proto");
        x.src_addr = get_stack_optional<std::string>(j, "src_addr");
        x.src_port = get_stack_optional<std::string>(j, "src_port");
    }

    inline void to_json(json & j, const RouteRuleElement & x) {
        j = json::object();
        j["dest_addr"] = x.dest_addr;
        j["dest_port"] = x.dest_port;
        j["display_name"] = x.display_name;
        j["dscp"] = x.dscp;
        j["enabled"] = x.enabled;
        j["id"] = x.id;
        j["list"] = x.list;
        j["outbound"] = x.outbound;
        j["proto"] = x.proto;
        j["src_addr"] = x.src_addr;
        j["src_port"] = x.src_port;
    }

    inline void from_json(const json & j, Route& x) {
        x.inbound_interfaces = get_stack_optional<std::vector<std::string>>(j, "inbound_interfaces");
        x.internal_vpn_servers = get_stack_optional<std::vector<InternalVpnServerElement>>(j, "internal_vpn_servers");
        x.internal_vpn_services = get_stack_optional<std::vector<InternalVpnServiceElement>>(j, "internal_vpn_services");
        x.rules = get_stack_optional<std::vector<RouteRuleElement>>(j, "rules");
    }

    inline void to_json(json & j, const Route & x) {
        j = json::object();
        j["inbound_interfaces"] = x.inbound_interfaces;
        j["internal_vpn_servers"] = x.internal_vpn_servers;
        j["internal_vpn_services"] = x.internal_vpn_services;
        j["rules"] = x.rules;
    }

    inline void from_json(const json & j, PlainDnsTemplateElement& x) {
        x.name = j.at("name").get<std::string>();
        x.primary_ipv4 = j.at("primary_ipv4").get<std::string>();
        x.secondary_ipv4 = get_stack_optional<std::string>(j, "secondary_ipv4");
    }

    inline void to_json(json & j, const PlainDnsTemplateElement & x) {
        j = json::object();
        j["name"] = x.name;
        j["primary_ipv4"] = x.primary_ipv4;
        j["secondary_ipv4"] = x.secondary_ipv4;
    }

    inline void from_json(const json & j, UiPreferences& x) {
        x.hidden_native_interface_ids = get_stack_optional<std::vector<std::string>>(j, "hidden_native_interface_ids");
        x.plain_dns_templates = get_stack_optional<std::vector<PlainDnsTemplateElement>>(j, "plain_dns_templates");
    }

    inline void to_json(json & j, const UiPreferences & x) {
        j = json::object();
        j["hidden_native_interface_ids"] = x.hidden_native_interface_ids;
        j["plain_dns_templates"] = x.plain_dns_templates;
    }

    inline void from_json(const json & j, ConfigObject& x) {
        x.api = get_stack_optional<ApiConfig>(j, "api");
        x.daemon = get_stack_optional<Daemon>(j, "daemon");
        x.dns = get_stack_optional<Dns>(j, "dns");
        x.fwmark = get_stack_optional<Fwmark>(j, "fwmark");
        x.iproute = get_stack_optional<Iproute>(j, "iproute");
        x.list_refresh = get_stack_optional<ListRefresh>(j, "list_refresh");
        x.lists = get_stack_optional<std::map<std::string, ListConfigValue>>(j, "lists");
        x.lists_autoupdate = get_stack_optional<ListsAutoupdate>(j, "lists_autoupdate");
        x.outbounds = get_stack_optional<std::vector<OutboundElement>>(j, "outbounds");
        x.route = get_stack_optional<Route>(j, "route");
        x.ui_preferences = get_stack_optional<UiPreferences>(j, "ui_preferences");
    }

    inline void to_json(json & j, const ConfigObject & x) {
        j = json::object();
        j["api"] = x.api;
        j["daemon"] = x.daemon;
        j["dns"] = x.dns;
        j["fwmark"] = x.fwmark;
        j["iproute"] = x.iproute;
        j["list_refresh"] = x.list_refresh;
        j["lists"] = x.lists;
        j["lists_autoupdate"] = x.lists_autoupdate;
        j["outbounds"] = x.outbounds;
        j["route"] = x.route;
        j["ui_preferences"] = x.ui_preferences;
    }

    inline void from_json(const json & j, ListRefreshStateValue& x) {
        x.last_attempt = get_stack_optional<std::string>(j, "last_attempt");
        x.last_detour = get_stack_optional<std::string>(j, "last_detour");
        x.last_error = get_stack_optional<std::string>(j, "last_error");
        x.last_updated = get_stack_optional<std::string>(j, "last_updated");
    }

    inline void to_json(json & j, const ListRefreshStateValue & x) {
        j = json::object();
        j["last_attempt"] = x.last_attempt;
        j["last_detour"] = x.last_detour;
        j["last_error"] = x.last_error;
        j["last_updated"] = x.last_updated;
    }

    inline void from_json(const json & j, ConfigStateResponse& x) {
        x.config = j.at("config").get<ConfigObject>();
        x.is_draft = j.at("is_draft").get<bool>();
        x.list_refresh_state = get_stack_optional<std::map<std::string, ListRefreshStateValue>>(j, "list_refresh_state");
        x.revision = j.at("revision").get<std::string>();
    }

    inline void to_json(json & j, const ConfigStateResponse & x) {
        j = json::object();
        j["config"] = x.config;
        j["is_draft"] = x.is_draft;
        j["list_refresh_state"] = x.list_refresh_state;
        j["revision"] = x.revision;
    }

    inline void from_json(const json & j, ConfigUpdateResponse& x) {
        x.apply_started_ts = get_stack_optional<int64_t>(j, "apply_started_ts");
        x.message = j.at("message").get<std::string>();
        x.status = j.at("status").get<ConfigUpdateResponseStatus>();
    }

    inline void to_json(json & j, const ConfigUpdateResponse & x) {
        j = json::object();
        j["apply_started_ts"] = x.apply_started_ts;
        j["message"] = x.message;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, ConnectionEventState& x) {
        x.available = j.at("available").get<bool>();
        x.changed_at = j.at("changed_at").get<int64_t>();
        x.revision = j.at("revision").get<int64_t>();
    }

    inline void to_json(json & j, const ConnectionEventState & x) {
        j = json::object();
        j["available"] = x.available;
        j["changed_at"] = x.changed_at;
        j["revision"] = x.revision;
    }

    inline void from_json(const json & j, ConnectionRecord& x) {
        x.active = j.at("active").get<bool>();
        x.destination = j.at("destination").get<std::string>();
        x.destination_domains = j.at("destination_domains").get<std::vector<std::string>>();
        x.destination_port = j.at("destination_port").get<int64_t>();
        x.device = j.at("device").get<std::string>();
        x.first_seen = j.at("first_seen").get<int64_t>();
        x.id = j.at("id").get<std::string>();
        x.last_seen = j.at("last_seen").get<int64_t>();
        x.mark = j.at("mark").get<int64_t>();
        x.protocol = j.at("protocol").get<std::string>();
        x.route = j.at("route").get<std::string>();
        x.source = j.at("source").get<std::string>();
        x.source_port = j.at("source_port").get<int64_t>();
        x.state = j.at("state").get<std::string>();
    }

    inline void to_json(json & j, const ConnectionRecord & x) {
        j = json::object();
        j["active"] = x.active;
        j["destination"] = x.destination;
        j["destination_domains"] = x.destination_domains;
        j["destination_port"] = x.destination_port;
        j["device"] = x.device;
        j["first_seen"] = x.first_seen;
        j["id"] = x.id;
        j["last_seen"] = x.last_seen;
        j["mark"] = x.mark;
        j["protocol"] = x.protocol;
        j["route"] = x.route;
        j["source"] = x.source;
        j["source_port"] = x.source_port;
        j["state"] = x.state;
    }

    inline void from_json(const json & j, ConnectionPage& x) {
        x.items = j.at("items").get<std::vector<ConnectionRecord>>();
        x.next_cursor = get_stack_optional<std::string>(j, "next_cursor");
        x.snapshot_at = j.at("snapshot_at").get<int64_t>();
        x.total = j.at("total").get<int64_t>();
    }

    inline void to_json(json & j, const ConnectionPage & x) {
        j = json::object();
        j["items"] = x.items;
        j["next_cursor"] = x.next_cursor;
        j["snapshot_at"] = x.snapshot_at;
        j["total"] = x.total;
    }

    inline void from_json(const json & j, ConnectionQueryRequest& x) {
        x.active_only = get_stack_optional<bool>(j, "active_only");
        x.cursor = get_stack_optional<std::string>(j, "cursor");
        x.device = get_stack_optional<std::string>(j, "device");
        x.limit = get_stack_optional<int64_t>(j, "limit");
        x.order = get_stack_optional<SortOrder>(j, "order");
        x.route = get_stack_optional<std::string>(j, "route");
        x.search = get_stack_optional<std::string>(j, "search");
        x.sort = get_stack_optional<ConnectionSort>(j, "sort");
        x.state = get_stack_optional<std::string>(j, "state");
    }

    inline void to_json(json & j, const ConnectionQueryRequest & x) {
        j = json::object();
        j["active_only"] = x.active_only;
        j["cursor"] = x.cursor;
        j["device"] = x.device;
        j["limit"] = x.limit;
        j["order"] = x.order;
        j["route"] = x.route;
        j["search"] = x.search;
        j["sort"] = x.sort;
        j["state"] = x.state;
    }

    inline void from_json(const json & j, DependencyAnalysisTargetRequest& x) {
        x.id = j.at("id").get<std::string>();
        x.kind = j.at("kind").get<DependencyEntityKind>();
    }

    inline void to_json(json & j, const DependencyAnalysisTargetRequest & x) {
        j = json::object();
        j["id"] = x.id;
        j["kind"] = x.kind;
    }

    inline void from_json(const json & j, DependencyAnalysisRequest& x) {
        x.independent = get_stack_optional<bool>(j, "independent");
        x.targets = j.at("targets").get<std::vector<DependencyAnalysisTargetRequest>>();
    }

    inline void to_json(json & j, const DependencyAnalysisRequest & x) {
        j = json::object();
        j["independent"] = x.independent;
        j["targets"] = x.targets;
    }

    inline void from_json(const json & j, DependencyTarget& x) {
        x.cascaded = j.at("cascaded").get<bool>();
        x.id = j.at("id").get<std::string>();
        x.kind = j.at("kind").get<DependencyEntityKind>();
    }

    inline void to_json(json & j, const DependencyTarget & x) {
        j = json::object();
        j["cascaded"] = x.cascaded;
        j["id"] = x.id;
        j["kind"] = x.kind;
    }

    inline void from_json(const json & j, DependencyReference& x) {
        x.consequence = j.at("consequence").get<DependencyConsequence>();
        x.dependent_id = j.at("dependent_id").get<std::string>();
        x.dependent_kind = j.at("dependent_kind").get<DependencyDependentKind>();
        x.href = get_stack_optional<std::string>(j, "href");
        x.path = j.at("path").get<std::string>();
        x.relation = j.at("relation").get<DependencyRelation>();
        x.target = j.at("target").get<DependencyTarget>();
    }

    inline void to_json(json & j, const DependencyReference & x) {
        j = json::object();
        j["consequence"] = x.consequence;
        j["dependent_id"] = x.dependent_id;
        j["dependent_kind"] = x.dependent_kind;
        j["href"] = x.href;
        j["path"] = x.path;
        j["relation"] = x.relation;
        j["target"] = x.target;
    }

    inline void from_json(const json & j, DependencyAnalysisResponse& x) {
        x.references = j.at("references").get<std::vector<DependencyReference>>();
        x.safe_to_delete = j.at("safe_to_delete").get<bool>();
        x.targets = j.at("targets").get<std::vector<DependencyTarget>>();
    }

    inline void to_json(json & j, const DependencyAnalysisResponse & x) {
        j = json::object();
        j["references"] = x.references;
        j["safe_to_delete"] = x.safe_to_delete;
        j["targets"] = x.targets;
    }

    inline void from_json(const json & j, ValidationErrorElement& x) {
        x.message = j.at("message").get<std::string>();
        x.path = get_stack_optional<std::string>(j, "path");
    }

    inline void to_json(json & j, const ValidationErrorElement & x) {
        j = json::object();
        j["message"] = x.message;
        j["path"] = x.path;
    }

    inline void from_json(const json & j, ErrorResponse& x) {
        x.error = j.at("error").get<std::string>();
        x.validation_errors = get_stack_optional<std::vector<ValidationErrorElement>>(j, "validation_errors");
    }

    inline void to_json(json & j, const ErrorResponse & x) {
        j = json::object();
        j["error"] = x.error;
        j["validation_errors"] = x.validation_errors;
    }

    inline void from_json(const json & j, FirewallChain& x) {
        x.chain_present = j.at("chain_present").get<bool>();
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.prerouting_hook_present = j.at("prerouting_hook_present").get<bool>();
    }

    inline void to_json(json & j, const FirewallChain & x) {
        j = json::object();
        j["chain_present"] = x.chain_present;
        j["detail"] = x.detail;
        j["prerouting_hook_present"] = x.prerouting_hook_present;
    }

    inline void from_json(const json & j, FirewallRuleCheck& x) {
        x.action = j.at("action").get<std::string>();
        x.actual_fwmark = get_stack_optional<std::string>(j, "actual_fwmark");
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.expected_fwmark = get_stack_optional<std::string>(j, "expected_fwmark");
        x.set_name = j.at("set_name").get<std::string>();
        x.status = j.at("status").get<CheckStatus>();
    }

    inline void to_json(json & j, const FirewallRuleCheck & x) {
        j = json::object();
        j["action"] = x.action;
        j["actual_fwmark"] = x.actual_fwmark;
        j["detail"] = x.detail;
        j["expected_fwmark"] = x.expected_fwmark;
        j["set_name"] = x.set_name;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, LifecycleOperationStageElement& x) {
        x.detail = j.at("detail").get<std::string>();
        x.id = j.at("id").get<std::string>();
        x.status = j.at("status").get<LifecycleOperationStageStatus>();
        x.title = j.at("title").get<std::string>();
    }

    inline void to_json(json & j, const LifecycleOperationStageElement & x) {
        j = json::object();
        j["detail"] = x.detail;
        j["id"] = x.id;
        j["status"] = x.status;
        j["title"] = x.title;
    }

    inline void from_json(const json & j, LifecycleOperation& x) {
        x.error = get_stack_optional<std::string>(j, "error");
        x.finished_at = get_stack_optional<int64_t>(j, "finished_at");
        x.id = j.at("id").get<std::string>();
        x.stages = j.at("stages").get<std::vector<LifecycleOperationStageElement>>();
        x.started_at = j.at("started_at").get<int64_t>();
        x.status = j.at("status").get<LifecycleOperationStatus>();
        x.type = j.at("type").get<LifecycleOperationType>();
    }

    inline void to_json(json & j, const LifecycleOperation & x) {
        j = json::object();
        j["error"] = x.error;
        j["finished_at"] = x.finished_at;
        j["id"] = x.id;
        j["stages"] = x.stages;
        j["started_at"] = x.started_at;
        j["status"] = x.status;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, HealthResponse& x) {
        x.apply_started_ts = get_stack_optional<int64_t>(j, "apply_started_ts");
        x.build = j.at("build").get<std::string>();
        x.build_variant = j.at("build_variant").get<std::string>();
        x.commit = get_stack_optional<std::string>(j, "commit");
        x.config_is_draft = j.at("config_is_draft").get<bool>();
        x.lifecycle_operation = get_stack_optional<LifecycleOperation>(j, "lifecycle_operation");
        x.os_type = j.at("os_type").get<std::string>();
        x.os_version = j.at("os_version").get<std::string>();
        x.resolver_config_hash = get_stack_optional<std::string>(j, "resolver_config_hash");
        x.resolver_config_hash_actual = get_stack_optional<std::string>(j, "resolver_config_hash_actual");
        x.resolver_config_hash_actual_ts = get_stack_optional<int64_t>(j, "resolver_config_hash_actual_ts");
        x.resolver_config_probe_status = get_stack_optional<ResolverConfigProbeStatus>(j, "resolver_config_probe_status");
        x.resolver_config_sync_state = get_stack_optional<ResolverConfigSyncState>(j, "resolver_config_sync_state");
        x.resolver_last_probe_ts = get_stack_optional<int64_t>(j, "resolver_last_probe_ts");
        x.resolver_live_status = j.at("resolver_live_status").get<ResolverLiveStatus>();
        x.runtime_state = j.at("runtime_state").get<RuntimeState>();
        x.runtime_state_reason = j.at("runtime_state_reason").get<std::string>();
        x.status = j.at("status").get<HealthResponseStatus>();
        x.version = j.at("version").get<std::string>();
    }

    inline void to_json(json & j, const HealthResponse & x) {
        j = json::object();
        j["apply_started_ts"] = x.apply_started_ts;
        j["build"] = x.build;
        j["build_variant"] = x.build_variant;
        j["commit"] = x.commit;
        j["config_is_draft"] = x.config_is_draft;
        j["lifecycle_operation"] = x.lifecycle_operation;
        j["os_type"] = x.os_type;
        j["os_version"] = x.os_version;
        j["resolver_config_hash"] = x.resolver_config_hash;
        j["resolver_config_hash_actual"] = x.resolver_config_hash_actual;
        j["resolver_config_hash_actual_ts"] = x.resolver_config_hash_actual_ts;
        j["resolver_config_probe_status"] = x.resolver_config_probe_status;
        j["resolver_config_sync_state"] = x.resolver_config_sync_state;
        j["resolver_last_probe_ts"] = x.resolver_last_probe_ts;
        j["resolver_live_status"] = x.resolver_live_status;
        j["runtime_state"] = x.runtime_state;
        j["runtime_state_reason"] = x.runtime_state_reason;
        j["status"] = x.status;
        j["version"] = x.version;
    }

    inline void from_json(const json & j, ListDeleteTargetElement& x) {
        x.list_id = j.at("list_id").get<std::string>();
        x.replacement_list_id = get_stack_optional<std::string>(j, "replacement_list_id");
    }

    inline void to_json(json & j, const ListDeleteTargetElement & x) {
        j = json::object();
        j["list_id"] = x.list_id;
        j["replacement_list_id"] = x.replacement_list_id;
    }

    inline void from_json(const json & j, ListDeleteStageRequest& x) {
        x.base_revision = j.at("base_revision").get<std::string>();
        x.targets = j.at("targets").get<std::vector<ListDeleteTargetElement>>();
    }

    inline void to_json(json & j, const ListDeleteStageRequest & x) {
        j = json::object();
        j["base_revision"] = x.base_revision;
        j["targets"] = x.targets;
    }

    inline void from_json(const json & j, ListDeleteStageSummaryClass& x) {
        x.deleted_lists = j.at("deleted_lists").get<std::vector<std::string>>();
        x.rebound_references = j.at("rebound_references").get<int64_t>();
        x.removed_dns_rules = j.at("removed_dns_rules").get<int64_t>();
        x.removed_route_rules = j.at("removed_route_rules").get<int64_t>();
        x.updated_dns_rules = j.at("updated_dns_rules").get<int64_t>();
        x.updated_route_rules = j.at("updated_route_rules").get<int64_t>();
    }

    inline void to_json(json & j, const ListDeleteStageSummaryClass & x) {
        j = json::object();
        j["deleted_lists"] = x.deleted_lists;
        j["rebound_references"] = x.rebound_references;
        j["removed_dns_rules"] = x.removed_dns_rules;
        j["removed_route_rules"] = x.removed_route_rules;
        j["updated_dns_rules"] = x.updated_dns_rules;
        j["updated_route_rules"] = x.updated_route_rules;
    }

    inline void from_json(const json & j, ListDeleteStageResponse& x) {
        x.message = j.at("message").get<std::string>();
        x.staged = j.at("staged").get<bool>();
        x.summary = j.at("summary").get<ListDeleteStageSummaryClass>();
    }

    inline void to_json(json & j, const ListDeleteStageResponse & x) {
        j = json::object();
        j["message"] = x.message;
        j["staged"] = x.staged;
        j["summary"] = x.summary;
    }

    inline void from_json(const json & j, ListRefreshRequest& x) {
        x.name = get_stack_optional<std::string>(j, "name");
    }

    inline void to_json(json & j, const ListRefreshRequest & x) {
        j = json::object();
        j["name"] = x.name;
    }

    inline void from_json(const json & j, ListRefreshResponse& x) {
        x.changed_lists = j.at("changed_lists").get<std::vector<std::string>>();
        x.failed_lists = j.at("failed_lists").get<std::vector<std::string>>();
        x.message = j.at("message").get<std::string>();
        x.refreshed_lists = j.at("refreshed_lists").get<std::vector<std::string>>();
        x.reloaded = j.at("reloaded").get<bool>();
        x.status = j.at("status").get<ConfigUpdateResponseStatus>();
    }

    inline void to_json(json & j, const ListRefreshResponse & x) {
        j = json::object();
        j["changed_lists"] = x.changed_lists;
        j["failed_lists"] = x.failed_lists;
        j["message"] = x.message;
        j["refreshed_lists"] = x.refreshed_lists;
        j["reloaded"] = x.reloaded;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, NdmsInterfaceCapabilities& x) {
        x.backup_required = j.at("backup_required").get<bool>();
        x.can_delete = j.at("can_delete").get<bool>();
        x.can_edit = j.at("can_edit").get<bool>();
        x.can_hide = j.at("can_hide").get<bool>();
    }

    inline void to_json(json & j, const NdmsInterfaceCapabilities & x) {
        j = json::object();
        j["backup_required"] = x.backup_required;
        j["can_delete"] = x.can_delete;
        j["can_edit"] = x.can_edit;
        j["can_hide"] = x.can_hide;
    }

    inline void from_json(const json & j, NdmsInterfaceManagementReadiness& x) {
        x.blockers = j.at("blockers").get<std::vector<NdmsManagementBlockerElement>>();
        x.candidate = j.at("candidate").get<bool>();
        x.configuration_snapshot_available = j.at("configuration_snapshot_available").get<bool>();
        x.identity_stable = j.at("identity_stable").get<bool>();
        x.observed_revision = j.at("observed_revision").get<std::string>();
    }

    inline void to_json(json & j, const NdmsInterfaceManagementReadiness & x) {
        j = json::object();
        j["blockers"] = x.blockers;
        j["candidate"] = x.candidate;
        j["configuration_snapshot_available"] = x.configuration_snapshot_available;
        j["identity_stable"] = x.identity_stable;
        j["observed_revision"] = x.observed_revision;
    }

    inline void from_json(const json & j, NdmsTunnelInterfaceElement& x) {
        x.capabilities = j.at("capabilities").get<NdmsInterfaceCapabilities>();
        x.connected = get_stack_optional<bool>(j, "connected");
        x.firmware_interface_name = j.at("firmware_interface_name").get<std::string>();
        x.firmware_type = j.at("firmware_type").get<std::string>();
        x.id = j.at("id").get<std::string>();
        x.internal_vpn_server_candidate = j.at("internal_vpn_server_candidate").get<bool>();
        x.internal_vpn_server_role_confirmation_required = j.at("internal_vpn_server_role_confirmation_required").get<bool>();
        x.kernel_name = get_stack_optional<std::string>(j, "kernel_name");
        x.kind = j.at("kind").get<Kind>();
        x.label = j.at("label").get<std::string>();
        x.link = get_stack_optional<bool>(j, "link");
        x.management_readiness = j.at("management_readiness").get<NdmsInterfaceManagementReadiness>();
        x.owner = j.at("owner").get<Owner>();
        x.role = j.at("role").get<Role>();
    }

    inline void to_json(json & j, const NdmsTunnelInterfaceElement & x) {
        j = json::object();
        j["capabilities"] = x.capabilities;
        j["connected"] = x.connected;
        j["firmware_interface_name"] = x.firmware_interface_name;
        j["firmware_type"] = x.firmware_type;
        j["id"] = x.id;
        j["internal_vpn_server_candidate"] = x.internal_vpn_server_candidate;
        j["internal_vpn_server_role_confirmation_required"] = x.internal_vpn_server_role_confirmation_required;
        j["kernel_name"] = x.kernel_name;
        j["kind"] = x.kind;
        j["label"] = x.label;
        j["link"] = x.link;
        j["management_readiness"] = x.management_readiness;
        j["owner"] = x.owner;
        j["role"] = x.role;
    }

    inline void from_json(const json & j, NdmsInterfaceInventoryResponse& x) {
        x.available = j.at("available").get<bool>();
        x.catalog_status = j.at("catalog_status").get<NdmsCatalogStatus>();
        x.interfaces = j.at("interfaces").get<std::vector<NdmsTunnelInterfaceElement>>();
        x.mutation_mode = j.at("mutation_mode").get<MutationMode>();
        x.read_only = j.at("read_only").get<bool>();
        x.required_guards = j.at("required_guards").get<std::vector<RequiredGuard>>();
    }

    inline void to_json(json & j, const NdmsInterfaceInventoryResponse & x) {
        j = json::object();
        j["available"] = x.available;
        j["catalog_status"] = x.catalog_status;
        j["interfaces"] = x.interfaces;
        j["mutation_mode"] = x.mutation_mode;
        j["read_only"] = x.read_only;
        j["required_guards"] = x.required_guards;
    }

    inline void from_json(const json & j, NdmsVpnServerService& x) {
        x.bound_interface_id = get_stack_optional<std::string>(j, "bound_interface_id");
        x.enabled = j.at("enabled").get<bool>();
        x.id = j.at("id").get<std::string>();
        x.inventory_revision = j.at("inventory_revision").get<std::string>();
        x.kind = j.at("kind").get<NdmsVpnServerKind>();
        x.label = j.at("label").get<std::string>();
        x.source_cidrs = j.at("source_cidrs").get<std::vector<std::string>>();
    }

    inline void to_json(json & j, const NdmsVpnServerService & x) {
        j = json::object();
        j["bound_interface_id"] = x.bound_interface_id;
        j["enabled"] = x.enabled;
        j["id"] = x.id;
        j["inventory_revision"] = x.inventory_revision;
        j["kind"] = x.kind;
        j["label"] = x.label;
        j["source_cidrs"] = x.source_cidrs;
    }

    inline void from_json(const json & j, NdmsVpnServerServiceInventoryResponse& x) {
        x.available = j.at("available").get<bool>();
        x.catalog_status = j.at("catalog_status").get<NdmsCatalogStatus>();
        x.read_only = j.at("read_only").get<bool>();
        x.services = j.at("services").get<std::vector<NdmsVpnServerService>>();
    }

    inline void to_json(json & j, const NdmsVpnServerServiceInventoryResponse & x) {
        j = json::object();
        j["available"] = x.available;
        j["catalog_status"] = x.catalog_status;
        j["read_only"] = x.read_only;
        j["services"] = x.services;
    }

    inline void from_json(const json & j, PeriodicTaskMetricsEntry& x) {
        x.abandoned = j.at("abandoned").get<int64_t>();
        x.failure = j.at("failure").get<int64_t>();
        x.in_flight = j.at("in_flight").get<int64_t>();
        x.label = j.at("label").get<std::string>();
        x.last_duration_ms = get_stack_optional<int64_t>(j, "last_duration_ms");
        x.last_error = get_stack_optional<std::string>(j, "last_error");
        x.last_event_at_unix_ms = get_stack_optional<int64_t>(j, "last_event_at_unix_ms");
        x.last_finished_at_unix_ms = get_stack_optional<int64_t>(j, "last_finished_at_unix_ms");
        x.last_outcome = get_stack_optional<LastOutcome>(j, "last_outcome");
        x.last_started_at_unix_ms = get_stack_optional<int64_t>(j, "last_started_at_unix_ms");
        x.max_duration_ms = j.at("max_duration_ms").get<int64_t>();
        x.noop = j.at("noop").get<int64_t>();
        x.runs = j.at("runs").get<int64_t>();
        x.skipped = j.at("skipped").get<int64_t>();
        x.success = j.at("success").get<int64_t>();
        x.total_duration_ms = j.at("total_duration_ms").get<int64_t>();
    }

    inline void to_json(json & j, const PeriodicTaskMetricsEntry & x) {
        j = json::object();
        j["abandoned"] = x.abandoned;
        j["failure"] = x.failure;
        j["in_flight"] = x.in_flight;
        j["label"] = x.label;
        j["last_duration_ms"] = x.last_duration_ms;
        j["last_error"] = x.last_error;
        j["last_event_at_unix_ms"] = x.last_event_at_unix_ms;
        j["last_finished_at_unix_ms"] = x.last_finished_at_unix_ms;
        j["last_outcome"] = x.last_outcome;
        j["last_started_at_unix_ms"] = x.last_started_at_unix_ms;
        j["max_duration_ms"] = x.max_duration_ms;
        j["noop"] = x.noop;
        j["runs"] = x.runs;
        j["skipped"] = x.skipped;
        j["success"] = x.success;
        j["total_duration_ms"] = x.total_duration_ms;
    }

    inline void from_json(const json & j, PeriodicTaskMetricsResponse& x) {
        x.capacity = j.at("capacity").get<int64_t>();
        x.tasks = j.at("tasks").get<std::vector<PeriodicTaskMetricsEntry>>();
        x.tracked = j.at("tracked").get<int64_t>();
    }

    inline void to_json(json & j, const PeriodicTaskMetricsResponse & x) {
        j = json::object();
        j["capacity"] = x.capacity;
        j["tasks"] = x.tasks;
        j["tracked"] = x.tracked;
    }

    inline void from_json(const json & j, PolicyRuleCheck& x) {
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.expected_table = j.at("expected_table").get<int64_t>();
        x.fwmark = j.at("fwmark").get<std::string>();
        x.fwmask = j.at("fwmask").get<std::string>();
        x.priority = j.at("priority").get<int64_t>();
        x.rule_present_v4 = j.at("rule_present_v4").get<bool>();
        x.rule_present_v6 = j.at("rule_present_v6").get<bool>();
        x.status = j.at("status").get<CheckStatus>();
    }

    inline void to_json(json & j, const PolicyRuleCheck & x) {
        j = json::object();
        j["detail"] = x.detail;
        j["expected_table"] = x.expected_table;
        j["fwmark"] = x.fwmark;
        j["fwmask"] = x.fwmask;
        j["priority"] = x.priority;
        j["rule_present_v4"] = x.rule_present_v4;
        j["rule_present_v6"] = x.rule_present_v6;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, RecommendedListSetupRequest& x) {
        x.base_revision = j.at("base_revision").get<std::string>();
        x.config = j.at("config").get<ConfigObject>();
        x.list_id = j.at("list_id").get<std::string>();
    }

    inline void to_json(json & j, const RecommendedListSetupRequest & x) {
        j = json::object();
        j["base_revision"] = x.base_revision;
        j["config"] = x.config;
        j["list_id"] = x.list_id;
    }

    inline void from_json(const json & j, ReloadResponse& x) {
        x.message = j.at("message").get<std::string>();
        x.status = j.at("status").get<ConfigUpdateResponseStatus>();
    }

    inline void to_json(json & j, const ReloadResponse & x) {
        j = json::object();
        j["message"] = x.message;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, RouteTableCheck& x) {
        x.default_route_present = j.at("default_route_present").get<bool>();
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.expected_destination = get_stack_optional<std::string>(j, "expected_destination");
        x.expected_gateway = get_stack_optional<std::string>(j, "expected_gateway");
        x.expected_interface = get_stack_optional<std::string>(j, "expected_interface");
        x.expected_metric = get_stack_optional<int64_t>(j, "expected_metric");
        x.expected_route_type = get_stack_optional<std::string>(j, "expected_route_type");
        x.gateway_matches = j.at("gateway_matches").get<bool>();
        x.interface_matches = j.at("interface_matches").get<bool>();
        x.outbound_tag = j.at("outbound_tag").get<std::string>();
        x.status = j.at("status").get<CheckStatus>();
        x.table_exists = j.at("table_exists").get<bool>();
        x.table_id = j.at("table_id").get<int64_t>();
    }

    inline void to_json(json & j, const RouteTableCheck & x) {
        j = json::object();
        j["default_route_present"] = x.default_route_present;
        j["detail"] = x.detail;
        j["expected_destination"] = x.expected_destination;
        j["expected_gateway"] = x.expected_gateway;
        j["expected_interface"] = x.expected_interface;
        j["expected_metric"] = x.expected_metric;
        j["expected_route_type"] = x.expected_route_type;
        j["gateway_matches"] = x.gateway_matches;
        j["interface_matches"] = x.interface_matches;
        j["outbound_tag"] = x.outbound_tag;
        j["status"] = x.status;
        j["table_exists"] = x.table_exists;
        j["table_id"] = x.table_id;
    }

    inline void from_json(const json & j, RoutingHealthErrorResponse& x) {
        x.error = j.at("error").get<std::string>();
        x.overall = j.at("overall").get<RoutingHealthErrorResponseOverall>();
    }

    inline void to_json(json & j, const RoutingHealthErrorResponse & x) {
        j = json::object();
        j["error"] = x.error;
        j["overall"] = x.overall;
    }

    inline void from_json(const json & j, RoutingHealthResponse& x) {
        x.firewall = j.at("firewall").get<FirewallChain>();
        x.firewall_backend = j.at("firewall_backend").get<RoutingHealthResponseFirewallBackend>();
        x.firewall_rules = j.at("firewall_rules").get<std::vector<FirewallRuleCheck>>();
        x.overall = j.at("overall").get<RoutingHealthResponseOverall>();
        x.policy_rules = j.at("policy_rules").get<std::vector<PolicyRuleCheck>>();
        x.route_tables = j.at("route_tables").get<std::vector<RouteTableCheck>>();
    }

    inline void to_json(json & j, const RoutingHealthResponse & x) {
        j = json::object();
        j["firewall"] = x.firewall;
        j["firewall_backend"] = x.firewall_backend;
        j["firewall_rules"] = x.firewall_rules;
        j["overall"] = x.overall;
        j["policy_rules"] = x.policy_rules;
        j["route_tables"] = x.route_tables;
    }

    inline void from_json(const json & j, ListMatch& x) {
        x.list = j.at("list").get<std::string>();
        x.via = j.at("via").get<std::string>();
    }

    inline void to_json(json & j, const ListMatch & x) {
        j = json::object();
        j["list"] = x.list;
        j["via"] = x.via;
    }

    inline void from_json(const json & j, RoutingTestEntry& x) {
        x.actual_outbound = j.at("actual_outbound").get<std::string>();
        x.evaluation = j.at("evaluation").get<Evaluation>();
        x.expected_outbound = j.at("expected_outbound").get<std::string>();
        x.ip = j.at("ip").get<std::string>();
        x.list_match = get_stack_optional<ListMatch>(j, "list_match");
        x.ok = j.at("ok").get<bool>();
        x.unknown_conditions = j.at("unknown_conditions").get<std::vector<RoutingTestUnknownConditionElement>>();
    }

    inline void to_json(json & j, const RoutingTestEntry & x) {
        j = json::object();
        j["actual_outbound"] = x.actual_outbound;
        j["evaluation"] = x.evaluation;
        j["expected_outbound"] = x.expected_outbound;
        j["ip"] = x.ip;
        j["list_match"] = x.list_match;
        j["ok"] = x.ok;
        j["unknown_conditions"] = x.unknown_conditions;
    }

    inline void from_json(const json & j, RoutingTestRequest& x) {
        x.target = j.at("target").get<std::string>();
    }

    inline void to_json(json & j, const RoutingTestRequest & x) {
        j = json::object();
        j["target"] = x.target;
    }

    inline void from_json(const json & j, RoutingTestRuleIpDiagnosticElement& x) {
        x.evaluation = j.at("evaluation").get<Evaluation>();
        x.in_ipset = get_stack_optional<bool>(j, "in_ipset");
        x.in_lists = j.at("in_lists").get<bool>();
        x.ip = j.at("ip").get<std::string>();
        x.list_match = get_stack_optional<ListMatch>(j, "list_match");
        x.unknown_conditions = j.at("unknown_conditions").get<std::vector<RoutingTestUnknownConditionElement>>();
    }

    inline void to_json(json & j, const RoutingTestRuleIpDiagnosticElement & x) {
        j = json::object();
        j["evaluation"] = x.evaluation;
        j["in_ipset"] = x.in_ipset;
        j["in_lists"] = x.in_lists;
        j["ip"] = x.ip;
        j["list_match"] = x.list_match;
        j["unknown_conditions"] = x.unknown_conditions;
    }

    inline void from_json(const json & j, RoutingTestRuleDiagnosticElement& x) {
        x.interface_name = j.at("interface_name").get<std::string>();
        x.ip_rows = j.at("ip_rows").get<std::vector<RoutingTestRuleIpDiagnosticElement>>();
        x.outbound = j.at("outbound").get<std::string>();
        x.rule = j.at("rule").get<RouteRuleElement>();
        x.rule_index = j.at("rule_index").get<int64_t>();
        x.target_in_lists = j.at("target_in_lists").get<bool>();
        x.target_match = get_stack_optional<ListMatch>(j, "target_match");
    }

    inline void to_json(json & j, const RoutingTestRuleDiagnosticElement & x) {
        j = json::object();
        j["interface_name"] = x.interface_name;
        j["ip_rows"] = x.ip_rows;
        j["outbound"] = x.outbound;
        j["rule"] = x.rule;
        j["rule_index"] = x.rule_index;
        j["target_in_lists"] = x.target_in_lists;
        j["target_match"] = x.target_match;
    }

    inline void from_json(const json & j, RoutingTestResponse& x) {
        x.config_scope = j.at("config_scope").get<ConfigScope>();
        x.dns_error = get_stack_optional<std::string>(j, "dns_error");
        x.is_domain = j.at("is_domain").get<bool>();
        x.no_matching_rule = j.at("no_matching_rule").get<bool>();
        x.resolved_ips = j.at("resolved_ips").get<std::vector<std::string>>();
        x.results = j.at("results").get<std::vector<RoutingTestEntry>>();
        x.rule_diagnostics = j.at("rule_diagnostics").get<std::vector<RoutingTestRuleDiagnosticElement>>();
        x.target = j.at("target").get<std::string>();
        x.unapplied_draft = j.at("unapplied_draft").get<bool>();
        x.warnings = j.at("warnings").get<std::vector<std::string>>();
    }

    inline void to_json(json & j, const RoutingTestResponse & x) {
        j = json::object();
        j["config_scope"] = x.config_scope;
        j["dns_error"] = x.dns_error;
        j["is_domain"] = x.is_domain;
        j["no_matching_rule"] = x.no_matching_rule;
        j["resolved_ips"] = x.resolved_ips;
        j["results"] = x.results;
        j["rule_diagnostics"] = x.rule_diagnostics;
        j["target"] = x.target;
        j["unapplied_draft"] = x.unapplied_draft;
        j["warnings"] = x.warnings;
    }

    inline void from_json(const json & j, RuntimeInterfaceTrafficPointElement& x) {
        x.age_ms = j.at("age_ms").get<int64_t>();
        x.rx_bits_per_second = j.at("rx_bits_per_second").get<int64_t>();
        x.tx_bits_per_second = j.at("tx_bits_per_second").get<int64_t>();
    }

    inline void to_json(json & j, const RuntimeInterfaceTrafficPointElement & x) {
        j = json::object();
        j["age_ms"] = x.age_ms;
        j["rx_bits_per_second"] = x.rx_bits_per_second;
        j["tx_bits_per_second"] = x.tx_bits_per_second;
    }

    inline void from_json(const json & j, Traffic& x) {
        x.history = j.at("history").get<std::vector<RuntimeInterfaceTrafficPointElement>>();
        x.rx_bits_per_second = get_stack_optional<int64_t>(j, "rx_bits_per_second");
        x.rx_bytes = j.at("rx_bytes").get<int64_t>();
        x.sampled_at_unix_ms = get_stack_optional<int64_t>(j, "sampled_at_unix_ms");
        x.tx_bits_per_second = get_stack_optional<int64_t>(j, "tx_bits_per_second");
        x.tx_bytes = j.at("tx_bytes").get<int64_t>();
    }

    inline void to_json(json & j, const Traffic & x) {
        j = json::object();
        j["history"] = x.history;
        j["rx_bits_per_second"] = x.rx_bits_per_second;
        j["rx_bytes"] = x.rx_bytes;
        j["sampled_at_unix_ms"] = x.sampled_at_unix_ms;
        j["tx_bits_per_second"] = x.tx_bits_per_second;
        j["tx_bytes"] = x.tx_bytes;
    }

    inline void from_json(const json & j, RuntimeInterfaceInventoryEntry& x) {
        x.admin_up = get_stack_optional<bool>(j, "admin_up");
        x.carrier = get_stack_optional<bool>(j, "carrier");
        x.ipv4_addresses = get_stack_optional<std::vector<std::string>>(j, "ipv4_addresses");
        x.ipv6_addresses = get_stack_optional<std::vector<std::string>>(j, "ipv6_addresses");
        x.link_up_since_unix_ms = get_stack_optional<int64_t>(j, "link_up_since_unix_ms");
        x.link_uptime_source = get_stack_optional<LinkUptimeSource>(j, "link_uptime_source");
        x.name = j.at("name").get<std::string>();
        x.oper_state = get_stack_optional<std::string>(j, "oper_state");
        x.status = j.at("status").get<RuntimeInterfaceInventoryStatusEnum>();
        x.traffic = get_stack_optional<Traffic>(j, "traffic");
    }

    inline void to_json(json & j, const RuntimeInterfaceInventoryEntry & x) {
        j = json::object();
        j["admin_up"] = x.admin_up;
        j["carrier"] = x.carrier;
        j["ipv4_addresses"] = x.ipv4_addresses;
        j["ipv6_addresses"] = x.ipv6_addresses;
        j["link_up_since_unix_ms"] = x.link_up_since_unix_ms;
        j["link_uptime_source"] = x.link_uptime_source;
        j["name"] = x.name;
        j["oper_state"] = x.oper_state;
        j["status"] = x.status;
        j["traffic"] = x.traffic;
    }

    inline void from_json(const json & j, RuntimeInterfaceInventoryResponse& x) {
        x.interfaces = j.at("interfaces").get<std::vector<RuntimeInterfaceInventoryEntry>>();
    }

    inline void to_json(json & j, const RuntimeInterfaceInventoryResponse & x) {
        j = json::object();
        j["interfaces"] = x.interfaces;
    }

    inline void from_json(const json & j, RuntimeInterfaceState& x) {
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.interface_name = get_stack_optional<std::string>(j, "interface_name");
        x.latency_ms = get_stack_optional<int64_t>(j, "latency_ms");
        x.outbound_tag = j.at("outbound_tag").get<std::string>();
        x.status = j.at("status").get<RuntimeInterfaceStatusEnum>();
    }

    inline void to_json(json & j, const RuntimeInterfaceState & x) {
        j = json::object();
        j["detail"] = x.detail;
        j["interface_name"] = x.interface_name;
        j["latency_ms"] = x.latency_ms;
        j["outbound_tag"] = x.outbound_tag;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, RuntimeInterfaceTrafficSample& x) {
        x.available = j.at("available").get<bool>();
        x.name = j.at("name").get<std::string>();
        x.observed_at_unix_ms = get_stack_optional<int64_t>(j, "observed_at_unix_ms");
        x.reset = j.at("reset").get<bool>();
        x.rx_bits_per_second = get_stack_optional<int64_t>(j, "rx_bits_per_second");
        x.rx_bytes = get_stack_optional<int64_t>(j, "rx_bytes");
        x.tx_bits_per_second = get_stack_optional<int64_t>(j, "tx_bits_per_second");
        x.tx_bytes = get_stack_optional<int64_t>(j, "tx_bytes");
    }

    inline void to_json(json & j, const RuntimeInterfaceTrafficSample & x) {
        j = json::object();
        j["available"] = x.available;
        j["name"] = x.name;
        j["observed_at_unix_ms"] = x.observed_at_unix_ms;
        j["reset"] = x.reset;
        j["rx_bits_per_second"] = x.rx_bits_per_second;
        j["rx_bytes"] = x.rx_bytes;
        j["tx_bits_per_second"] = x.tx_bits_per_second;
        j["tx_bytes"] = x.tx_bytes;
    }

    inline void from_json(const json & j, RuntimeInterfaceTrafficUpdate& x) {
        x.interfaces = j.at("interfaces").get<std::vector<RuntimeInterfaceTrafficSample>>();
        x.sampled_at_unix_ms = j.at("sampled_at_unix_ms").get<int64_t>();
    }

    inline void to_json(json & j, const RuntimeInterfaceTrafficUpdate & x) {
        j = json::object();
        j["interfaces"] = x.interfaces;
        j["sampled_at_unix_ms"] = x.sampled_at_unix_ms;
    }

    inline void from_json(const json & j, RuntimeOutboundStateElement& x) {
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.interfaces = j.at("interfaces").get<std::vector<RuntimeInterfaceState>>();
        x.status = j.at("status").get<ResolverLiveStatus>();
        x.tag = j.at("tag").get<std::string>();
        x.type = j.at("type").get<OutboundType>();
    }

    inline void to_json(json & j, const RuntimeOutboundStateElement & x) {
        j = json::object();
        j["detail"] = x.detail;
        j["interfaces"] = x.interfaces;
        j["status"] = x.status;
        j["tag"] = x.tag;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, RuntimeOutboundsResponse& x) {
        x.outbounds = j.at("outbounds").get<std::vector<RuntimeOutboundStateElement>>();
    }

    inline void to_json(json & j, const RuntimeOutboundsResponse & x) {
        j = json::object();
        j["outbounds"] = x.outbounds;
    }

    inline void from_json(const json & j, RuntimeInventoryResponse& x) {
        x.interfaces = j.at("interfaces").get<RuntimeInterfaceInventoryResponse>();
        x.outbounds = j.at("outbounds").get<RuntimeOutboundsResponse>();
        x.service = j.at("service").get<HealthResponse>();
    }

    inline void to_json(json & j, const RuntimeInventoryResponse & x) {
        j = json::object();
        j["interfaces"] = x.interfaces;
        j["outbounds"] = x.outbounds;
        j["service"] = x.service;
    }

    inline void from_json(const json & j, StatusEventConnections& x) {
        x.data = j.at("data").get<ConnectionEventState>();
        x.type = j.at("type").get<StatusEventConnectionsType>();
    }

    inline void to_json(json & j, const StatusEventConnections & x) {
        j = json::object();
        j["data"] = x.data;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, StatusEventInterfaceTraffic& x) {
        x.data = j.at("data").get<RuntimeInterfaceTrafficUpdate>();
        x.type = j.at("type").get<StatusEventInterfaceTrafficType>();
    }

    inline void to_json(json & j, const StatusEventInterfaceTraffic & x) {
        j = json::object();
        j["data"] = x.data;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, StatusEventInterfaces& x) {
        x.data = j.at("data").get<RuntimeInterfaceInventoryResponse>();
        x.type = j.at("type").get<StatusEventInterfacesType>();
    }

    inline void to_json(json & j, const StatusEventInterfaces & x) {
        j = json::object();
        j["data"] = x.data;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, StatusEventOutbounds& x) {
        x.data = j.at("data").get<RuntimeOutboundsResponse>();
        x.type = j.at("type").get<StatusEventOutboundsType>();
    }

    inline void to_json(json & j, const StatusEventOutbounds & x) {
        j = json::object();
        j["data"] = x.data;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, StatusEventService& x) {
        x.data = j.at("data").get<HealthResponse>();
        x.type = j.at("type").get<StatusEventServiceType>();
    }

    inline void to_json(json & j, const StatusEventService & x) {
        j = json::object();
        j["data"] = x.data;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, StatusEventSnapshot& x) {
        x.data = j.at("data").get<RuntimeInventoryResponse>();
        x.type = j.at("type").get<StatusEventSnapshotType>();
    }

    inline void to_json(json & j, const StatusEventSnapshot & x) {
        j = json::object();
        j["data"] = x.data;
        j["type"] = x.type;
    }

    inline void from_json(const json & j, TransportActionRequest& x) {
        x.action = j.at("action").get<Action>();
        x.tag = j.at("tag").get<std::string>();
    }

    inline void to_json(json & j, const TransportActionRequest & x) {
        j = json::object();
        j["action"] = x.action;
        j["tag"] = x.tag;
    }

    inline void from_json(const json & j, TransportActionResponse& x) {
        x.at = j.at("at").get<std::string>();
        x.status = j.at("status").get<TransportActionResponseStatus>();
    }

    inline void to_json(json & j, const TransportActionResponse & x) {
        j = json::object();
        j["at"] = x.at;
        j["status"] = x.status;
    }

    inline void from_json(const json & j, LinkedOutbound& x) {
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.mode = j.at("mode").get<TransportLinkedOutboundEnsureMode>();
        x.strict_enforcement = get_stack_optional<bool>(j, "strict_enforcement");
    }

    inline void to_json(json & j, const LinkedOutbound & x) {
        j = json::object();
        j["display_name"] = x.display_name;
        j["mode"] = x.mode;
        j["strict_enforcement"] = x.strict_enforcement;
    }

    inline void from_json(const json & j, Vless& x) {
        x.fingerprint = get_stack_optional<std::string>(j, "fingerprint");
        x.flow = get_stack_optional<std::string>(j, "flow");
        x.mtu = get_stack_optional<int64_t>(j, "mtu");
        x.public_key = j.at("public_key").get<std::string>();
        x.server = j.at("server").get<std::string>();
        x.server_name = j.at("server_name").get<std::string>();
        x.server_port = j.at("server_port").get<int64_t>();
        x.short_id = get_stack_optional<std::string>(j, "short_id");
        x.uuid = get_stack_optional<std::string>(j, "uuid");
    }

    inline void to_json(json & j, const Vless & x) {
        j = json::object();
        j["fingerprint"] = x.fingerprint;
        j["flow"] = x.flow;
        j["mtu"] = x.mtu;
        j["public_key"] = x.public_key;
        j["server"] = x.server;
        j["server_name"] = x.server_name;
        j["server_port"] = x.server_port;
        j["short_id"] = x.short_id;
        j["uuid"] = x.uuid;
    }

    inline void from_json(const json & j, Transport& x) {
        x.auto_start = get_stack_optional<bool>(j, "auto_start");
        x.bootstrap_dns = get_stack_optional<std::vector<std::string>>(j, "bootstrap_dns");
        x.country = get_stack_optional<std::string>(j, "country");
        x.country_code = get_stack_optional<std::string>(j, "country_code");
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.geo_mode = get_stack_optional<GeoMode>(j, "geo_mode");
        x.interface = j.at("interface").get<std::string>();
        x.link = get_stack_optional<std::string>(j, "link");
        x.mtu = get_stack_optional<int64_t>(j, "mtu");
        x.outbound_json = get_stack_optional<std::string>(j, "outbound_json");
        x.tag = j.at("tag").get<std::string>();
        x.tun_address = get_stack_optional<std::string>(j, "tun_address");
        x.type = j.at("type").get<TransportSpecType>();
        x.vless = get_stack_optional<Vless>(j, "vless");
    }

    inline void to_json(json & j, const Transport & x) {
        j = json::object();
        j["auto_start"] = x.auto_start;
        j["bootstrap_dns"] = x.bootstrap_dns;
        j["country"] = x.country;
        j["country_code"] = x.country_code;
        j["display_name"] = x.display_name;
        j["geo_mode"] = x.geo_mode;
        j["interface"] = x.interface;
        j["link"] = x.link;
        j["mtu"] = x.mtu;
        j["outbound_json"] = x.outbound_json;
        j["tag"] = x.tag;
        j["tun_address"] = x.tun_address;
        j["type"] = x.type;
        j["vless"] = x.vless;
    }

    inline void from_json(const json & j, TransportConfigApplyRequest& x) {
        x.linked_outbound = j.at("linked_outbound").get<LinkedOutbound>();
        x.operation = j.at("operation").get<TransportConfigApplyRequestOperation>();
        x.transport = j.at("transport").get<Transport>();
    }

    inline void to_json(json & j, const TransportConfigApplyRequest & x) {
        j = json::object();
        j["linked_outbound"] = x.linked_outbound;
        j["operation"] = x.operation;
        j["transport"] = x.transport;
    }

    inline void from_json(const json & j, TransportConfigApplyResponse& x) {
        x.applied = get_stack_optional<bool>(j, "applied");
        x.apply_started_ts = get_stack_optional<int64_t>(j, "apply_started_ts");
        x.config_revision = get_stack_optional<std::string>(j, "config_revision");
        x.message = get_stack_optional<std::string>(j, "message");
        x.rolled_back = get_stack_optional<bool>(j, "rolled_back");
        x.saved = get_stack_optional<bool>(j, "saved");
        x.status = j.at("status").get<TransportConfigApplyResponseStatus>();
        x.transport_revision = get_stack_optional<std::string>(j, "transport_revision");
    }

    inline void to_json(json & j, const TransportConfigApplyResponse & x) {
        j = json::object();
        j["applied"] = x.applied;
        j["apply_started_ts"] = x.apply_started_ts;
        j["config_revision"] = x.config_revision;
        j["message"] = x.message;
        j["rolled_back"] = x.rolled_back;
        j["saved"] = x.saved;
        j["status"] = x.status;
        j["transport_revision"] = x.transport_revision;
    }

    inline void from_json(const json & j, TransportConfigOperation& x) {
        x.operation = j.at("operation").get<TransportConfigOperationOperation>();
        x.tag = get_stack_optional<std::string>(j, "tag");
        x.transport = get_stack_optional<Transport>(j, "transport");
    }

    inline void to_json(json & j, const TransportConfigOperation & x) {
        j = json::object();
        j["operation"] = x.operation;
        j["tag"] = x.tag;
        j["transport"] = x.transport;
    }

    inline void from_json(const json & j, TransportConfigResponse& x) {
        x.status = j.at("status").get<TransportConfigResponseStatus>();
        x.tag = j.at("tag").get<std::string>();
    }

    inline void to_json(json & j, const TransportConfigResponse & x) {
        j = json::object();
        j["status"] = x.status;
        j["tag"] = x.tag;
    }

    inline void from_json(const json & j, TransportPath& x) {
        x.confidence = j.at("confidence").get<Confidence>();
        x.framing = j.at("framing").get<Framing>();
        x.payload_networks = get_stack_optional<std::vector<PayloadNetwork>>(j, "payload_networks");
        x.wire_transport = j.at("wire_transport").get<WireTransport>();
    }

    inline void to_json(json & j, const TransportPath & x) {
        j = json::object();
        j["confidence"] = x.confidence;
        j["framing"] = x.framing;
        j["payload_networks"] = x.payload_networks;
        j["wire_transport"] = x.wire_transport;
    }

    inline void from_json(const json & j, TransportStatus& x) {
        x.desired_up = j.at("desired_up").get<bool>();
        x.display_name = get_stack_optional<std::string>(j, "display_name");
        x.error = get_stack_optional<std::string>(j, "error");
        x.interface = j.at("interface").get<std::string>();
        x.network = get_stack_optional<std::string>(j, "network");
        x.next_retry_at = get_stack_optional<std::string>(j, "next_retry_at");
        x.path = get_stack_optional<TransportPath>(j, "path");
        x.pid = get_stack_optional<int64_t>(j, "pid");
        x.protocol = get_stack_optional<std::string>(j, "protocol");
        x.retry_count = get_stack_optional<int64_t>(j, "retry_count");
        x.security = get_stack_optional<Security>(j, "security");
        x.server = get_stack_optional<std::string>(j, "server");
        x.server_port = get_stack_optional<int64_t>(j, "server_port");
        x.sni = get_stack_optional<std::string>(j, "sni");
        x.state = j.at("state").get<State>();
        x.tag = j.at("tag").get<std::string>();
        x.type = j.at("type").get<std::string>();
        x.updated_at = j.at("updated_at").get<std::string>();
    }

    inline void to_json(json & j, const TransportStatus & x) {
        j = json::object();
        j["desired_up"] = x.desired_up;
        j["display_name"] = x.display_name;
        j["error"] = x.error;
        j["interface"] = x.interface;
        j["network"] = x.network;
        j["next_retry_at"] = x.next_retry_at;
        j["path"] = x.path;
        j["pid"] = x.pid;
        j["protocol"] = x.protocol;
        j["retry_count"] = x.retry_count;
        j["security"] = x.security;
        j["server"] = x.server;
        j["server_port"] = x.server_port;
        j["sni"] = x.sni;
        j["state"] = x.state;
        j["tag"] = x.tag;
        j["type"] = x.type;
        j["updated_at"] = x.updated_at;
    }

    inline void from_json(const json & j, ApiTypes& x) {
        x.api_config = get_stack_optional<ApiConfig>(j, "ApiConfig");
        x.cache_generation = get_stack_optional<CacheGeneration>(j, "CacheGeneration");
        x.cache_metadata = get_stack_optional<CacheMetadata>(j, "CacheMetadata");
        x.catalog_preset_selection = get_stack_optional<CatalogPresetSelection>(j, "CatalogPresetSelection");
        x.catalog_setup_apply_request = get_stack_optional<CatalogSetupApplyRequest>(j, "CatalogSetupApplyRequest");
        x.catalog_setup_apply_response = get_stack_optional<CatalogSetupApplyResponse>(j, "CatalogSetupApplyResponse");
        x.catalog_setup_blackhole_summary = get_stack_optional<CatalogSetupBlackholeSummary>(j, "CatalogSetupBlackholeSummary");
        x.catalog_setup_dns_mode = get_stack_optional<DnsMode>(j, "CatalogSetupDnsMode");
        x.catalog_setup_dns_rule_summary = get_stack_optional<CatalogSetupDnsRuleSummary>(j, "CatalogSetupDnsRuleSummary");
        x.catalog_setup_dns_server_summary = get_stack_optional<CatalogSetupDnsServerSummary>(j, "CatalogSetupDnsServerSummary");
        x.catalog_setup_intent = get_stack_optional<Intent>(j, "CatalogSetupIntent");
        x.catalog_setup_list_summary = get_stack_optional<CatalogSetupListSummary>(j, "CatalogSetupListSummary");
        x.catalog_setup_mode = get_stack_optional<CatalogSetupModeEnum>(j, "CatalogSetupMode");
        x.catalog_setup_preview_request = get_stack_optional<CatalogSetupPreviewRequest>(j, "CatalogSetupPreviewRequest");
        x.catalog_setup_preview_response = get_stack_optional<CatalogSetupPreviewResponse>(j, "CatalogSetupPreviewResponse");
        x.catalog_setup_route_rule_summary = get_stack_optional<RouteRule>(j, "CatalogSetupRouteRuleSummary");
        x.catalog_setup_summary = get_stack_optional<CatalogSetupSummaryClass>(j, "CatalogSetupSummary");
        x.catalog_setup_warning = get_stack_optional<CatalogSetupWarningElement>(j, "CatalogSetupWarning");
        x.check_status = get_stack_optional<CheckStatus>(j, "CheckStatus");
        x.circuit_breaker_config = get_stack_optional<CircuitBreakerConfig>(j, "CircuitBreakerConfig");
        x.client_dns_enforcement = get_stack_optional<ClientDnsEnforcement>(j, "ClientDnsEnforcement");
        x.config_object = get_stack_optional<ConfigObject>(j, "ConfigObject");
        x.config_state_response = get_stack_optional<ConfigStateResponse>(j, "ConfigStateResponse");
        x.config_update_response = get_stack_optional<ConfigUpdateResponse>(j, "ConfigUpdateResponse");
        x.connection_event_state = get_stack_optional<ConnectionEventState>(j, "ConnectionEventState");
        x.connection_page = get_stack_optional<ConnectionPage>(j, "ConnectionPage");
        x.connection_query_request = get_stack_optional<ConnectionQueryRequest>(j, "ConnectionQueryRequest");
        x.connection_record = get_stack_optional<ConnectionRecord>(j, "ConnectionRecord");
        x.connection_sort = get_stack_optional<ConnectionSort>(j, "ConnectionSort");
        x.conntrack_on_switch = get_stack_optional<ConntrackOnSwitch>(j, "ConntrackOnSwitch");
        x.daemon_config = get_stack_optional<Daemon>(j, "DaemonConfig");
        x.dependency_analysis_request = get_stack_optional<DependencyAnalysisRequest>(j, "DependencyAnalysisRequest");
        x.dependency_analysis_response = get_stack_optional<DependencyAnalysisResponse>(j, "DependencyAnalysisResponse");
        x.dependency_analysis_target_request = get_stack_optional<DependencyAnalysisTargetRequest>(j, "DependencyAnalysisTargetRequest");
        x.dependency_consequence = get_stack_optional<DependencyConsequence>(j, "DependencyConsequence");
        x.dependency_dependent_kind = get_stack_optional<DependencyDependentKind>(j, "DependencyDependentKind");
        x.dependency_entity_kind = get_stack_optional<DependencyEntityKind>(j, "DependencyEntityKind");
        x.dependency_reference = get_stack_optional<DependencyReference>(j, "DependencyReference");
        x.dependency_relation = get_stack_optional<DependencyRelation>(j, "DependencyRelation");
        x.dependency_target = get_stack_optional<DependencyTarget>(j, "DependencyTarget");
        x.dns_config = get_stack_optional<Dns>(j, "DnsConfig");
        x.dns_rule = get_stack_optional<DnsRuleElement>(j, "DnsRule");
        x.dns_server = get_stack_optional<DnsServerElement>(j, "DnsServer");
        x.dns_system_resolver = get_stack_optional<SystemResolver>(j, "DnsSystemResolver");
        x.dns_test_server = get_stack_optional<DnsTestServer>(j, "DnsTestServer");
        x.error_response = get_stack_optional<ErrorResponse>(j, "ErrorResponse");
        x.firewall_chain = get_stack_optional<FirewallChain>(j, "FirewallChain");
        x.firewall_rule_check = get_stack_optional<FirewallRuleCheck>(j, "FirewallRuleCheck");
        x.fwmark_config = get_stack_optional<Fwmark>(j, "FwmarkConfig");
        x.health_response = get_stack_optional<HealthResponse>(j, "HealthResponse");
        x.internal_vpn_server = get_stack_optional<InternalVpnServerElement>(j, "InternalVpnServer");
        x.internal_vpn_service = get_stack_optional<InternalVpnServiceElement>(j, "InternalVpnService");
        x.iproute_config = get_stack_optional<Iproute>(j, "IprouteConfig");
        x.lifecycle_operation = get_stack_optional<LifecycleOperation>(j, "LifecycleOperation");
        x.lifecycle_operation_stage = get_stack_optional<LifecycleOperationStageElement>(j, "LifecycleOperationStage");
        x.list_config = get_stack_optional<ListConfigValue>(j, "ListConfig");
        x.list_delete_stage_request = get_stack_optional<ListDeleteStageRequest>(j, "ListDeleteStageRequest");
        x.list_delete_stage_response = get_stack_optional<ListDeleteStageResponse>(j, "ListDeleteStageResponse");
        x.list_delete_stage_summary = get_stack_optional<ListDeleteStageSummaryClass>(j, "ListDeleteStageSummary");
        x.list_delete_target = get_stack_optional<ListDeleteTargetElement>(j, "ListDeleteTarget");
        x.list_refresh_config = get_stack_optional<ListRefresh>(j, "ListRefreshConfig");
        x.list_refresh_detour_mode = get_stack_optional<RefreshDetourMode>(j, "ListRefreshDetourMode");
        x.list_refresh_request = get_stack_optional<ListRefreshRequest>(j, "ListRefreshRequest");
        x.list_refresh_response = get_stack_optional<ListRefreshResponse>(j, "ListRefreshResponse");
        x.list_refresh_state = get_stack_optional<ListRefreshStateValue>(j, "ListRefreshState");
        x.lists_autoupdate_config = get_stack_optional<ListsAutoupdate>(j, "ListsAutoupdateConfig");
        x.ndms_catalog_status = get_stack_optional<NdmsCatalogStatus>(j, "NdmsCatalogStatus");
        x.ndms_interface_capabilities = get_stack_optional<NdmsInterfaceCapabilities>(j, "NdmsInterfaceCapabilities");
        x.ndms_interface_inventory_response = get_stack_optional<NdmsInterfaceInventoryResponse>(j, "NdmsInterfaceInventoryResponse");
        x.ndms_interface_management_readiness = get_stack_optional<NdmsInterfaceManagementReadiness>(j, "NdmsInterfaceManagementReadiness");
        x.ndms_interface_role = get_stack_optional<Role>(j, "NdmsInterfaceRole");
        x.ndms_management_blocker = get_stack_optional<NdmsManagementBlockerElement>(j, "NdmsManagementBlocker");
        x.ndms_tunnel_interface = get_stack_optional<NdmsTunnelInterfaceElement>(j, "NdmsTunnelInterface");
        x.ndms_tunnel_kind = get_stack_optional<Kind>(j, "NdmsTunnelKind");
        x.ndms_vpn_server_kind = get_stack_optional<NdmsVpnServerKind>(j, "NdmsVpnServerKind");
        x.ndms_vpn_server_service = get_stack_optional<NdmsVpnServerService>(j, "NdmsVpnServerService");
        x.ndms_vpn_server_service_inventory_response = get_stack_optional<NdmsVpnServerServiceInventoryResponse>(j, "NdmsVpnServerServiceInventoryResponse");
        x.outbound = get_stack_optional<OutboundElement>(j, "Outbound");
        x.outbound_group = get_stack_optional<OutboundGroupElement>(j, "OutboundGroup");
        x.periodic_task_metrics_entry = get_stack_optional<PeriodicTaskMetricsEntry>(j, "PeriodicTaskMetricsEntry");
        x.periodic_task_metrics_response = get_stack_optional<PeriodicTaskMetricsResponse>(j, "PeriodicTaskMetricsResponse");
        x.periodic_task_outcome = get_stack_optional<LastOutcome>(j, "PeriodicTaskOutcome");
        x.plain_dns_template = get_stack_optional<PlainDnsTemplateElement>(j, "PlainDnsTemplate");
        x.policy_rule_check = get_stack_optional<PolicyRuleCheck>(j, "PolicyRuleCheck");
        x.recommended_list_setup_request = get_stack_optional<RecommendedListSetupRequest>(j, "RecommendedListSetupRequest");
        x.reload_response = get_stack_optional<ReloadResponse>(j, "ReloadResponse");
        x.resolver_config_probe_status = get_stack_optional<ResolverConfigProbeStatus>(j, "ResolverConfigProbeStatus");
        x.resolver_config_sync_state = get_stack_optional<ResolverConfigSyncState>(j, "ResolverConfigSyncState");
        x.retry_config = get_stack_optional<Retry>(j, "RetryConfig");
        x.route_config = get_stack_optional<Route>(j, "RouteConfig");
        x.route_rule = get_stack_optional<RouteRuleElement>(j, "RouteRule");
        x.route_table_check = get_stack_optional<RouteTableCheck>(j, "RouteTableCheck");
        x.routing_health_error_response = get_stack_optional<RoutingHealthErrorResponse>(j, "RoutingHealthErrorResponse");
        x.routing_health_response = get_stack_optional<RoutingHealthResponse>(j, "RoutingHealthResponse");
        x.routing_test_entry = get_stack_optional<RoutingTestEntry>(j, "RoutingTestEntry");
        x.routing_test_evaluation = get_stack_optional<Evaluation>(j, "RoutingTestEvaluation");
        x.routing_test_list_match = get_stack_optional<ListMatch>(j, "RoutingTestListMatch");
        x.routing_test_request = get_stack_optional<RoutingTestRequest>(j, "RoutingTestRequest");
        x.routing_test_response = get_stack_optional<RoutingTestResponse>(j, "RoutingTestResponse");
        x.routing_test_rule_diagnostic = get_stack_optional<RoutingTestRuleDiagnosticElement>(j, "RoutingTestRuleDiagnostic");
        x.routing_test_rule_ip_diagnostic = get_stack_optional<RoutingTestRuleIpDiagnosticElement>(j, "RoutingTestRuleIpDiagnostic");
        x.routing_test_unknown_condition = get_stack_optional<RoutingTestUnknownConditionElement>(j, "RoutingTestUnknownCondition");
        x.runtime_interface_inventory_entry = get_stack_optional<RuntimeInterfaceInventoryEntry>(j, "RuntimeInterfaceInventoryEntry");
        x.runtime_interface_inventory_response = get_stack_optional<RuntimeInterfaceInventoryResponse>(j, "RuntimeInterfaceInventoryResponse");
        x.runtime_interface_inventory_status = get_stack_optional<RuntimeInterfaceInventoryStatusEnum>(j, "RuntimeInterfaceInventoryStatus");
        x.runtime_interface_state = get_stack_optional<RuntimeInterfaceState>(j, "RuntimeInterfaceState");
        x.runtime_interface_status = get_stack_optional<RuntimeInterfaceStatusEnum>(j, "RuntimeInterfaceStatus");
        x.runtime_interface_traffic = get_stack_optional<Traffic>(j, "RuntimeInterfaceTraffic");
        x.runtime_interface_traffic_point = get_stack_optional<RuntimeInterfaceTrafficPointElement>(j, "RuntimeInterfaceTrafficPoint");
        x.runtime_interface_traffic_sample = get_stack_optional<RuntimeInterfaceTrafficSample>(j, "RuntimeInterfaceTrafficSample");
        x.runtime_interface_traffic_update = get_stack_optional<RuntimeInterfaceTrafficUpdate>(j, "RuntimeInterfaceTrafficUpdate");
        x.runtime_interface_uptime_source = get_stack_optional<LinkUptimeSource>(j, "RuntimeInterfaceUptimeSource");
        x.runtime_inventory_response = get_stack_optional<RuntimeInventoryResponse>(j, "RuntimeInventoryResponse");
        x.runtime_outbounds_response = get_stack_optional<RuntimeOutboundsResponse>(j, "RuntimeOutboundsResponse");
        x.runtime_outbound_state = get_stack_optional<RuntimeOutboundStateElement>(j, "RuntimeOutboundState");
        x.runtime_outbound_status = get_stack_optional<ResolverLiveStatus>(j, "RuntimeOutboundStatus");
        x.sort_order = get_stack_optional<SortOrder>(j, "SortOrder");
        x.status_event_connections = get_stack_optional<StatusEventConnections>(j, "StatusEventConnections");
        x.status_event_interfaces = get_stack_optional<StatusEventInterfaces>(j, "StatusEventInterfaces");
        x.status_event_interface_traffic = get_stack_optional<StatusEventInterfaceTraffic>(j, "StatusEventInterfaceTraffic");
        x.status_event_outbounds = get_stack_optional<StatusEventOutbounds>(j, "StatusEventOutbounds");
        x.status_event_service = get_stack_optional<StatusEventService>(j, "StatusEventService");
        x.status_event_snapshot = get_stack_optional<StatusEventSnapshot>(j, "StatusEventSnapshot");
        x.transport_action_request = get_stack_optional<TransportActionRequest>(j, "TransportActionRequest");
        x.transport_action_response = get_stack_optional<TransportActionResponse>(j, "TransportActionResponse");
        x.transport_config_apply_request = get_stack_optional<TransportConfigApplyRequest>(j, "TransportConfigApplyRequest");
        x.transport_config_apply_response = get_stack_optional<TransportConfigApplyResponse>(j, "TransportConfigApplyResponse");
        x.transport_config_operation = get_stack_optional<TransportConfigOperation>(j, "TransportConfigOperation");
        x.transport_config_response = get_stack_optional<TransportConfigResponse>(j, "TransportConfigResponse");
        x.transport_linked_outbound_ensure = get_stack_optional<LinkedOutbound>(j, "TransportLinkedOutboundEnsure");
        x.transport_path = get_stack_optional<TransportPath>(j, "TransportPath");
        x.transport_spec = get_stack_optional<Transport>(j, "TransportSpec");
        x.transport_status = get_stack_optional<TransportStatus>(j, "TransportStatus");
        x.ui_preferences_config = get_stack_optional<UiPreferences>(j, "UiPreferencesConfig");
        x.validation_error = get_stack_optional<ValidationErrorElement>(j, "ValidationError");
        x.vless_reality_spec = get_stack_optional<Vless>(j, "VlessRealitySpec");
    }

    inline void to_json(json & j, const ApiTypes & x) {
        j = json::object();
        j["ApiConfig"] = x.api_config;
        j["CacheGeneration"] = x.cache_generation;
        j["CacheMetadata"] = x.cache_metadata;
        j["CatalogPresetSelection"] = x.catalog_preset_selection;
        j["CatalogSetupApplyRequest"] = x.catalog_setup_apply_request;
        j["CatalogSetupApplyResponse"] = x.catalog_setup_apply_response;
        j["CatalogSetupBlackholeSummary"] = x.catalog_setup_blackhole_summary;
        j["CatalogSetupDnsMode"] = x.catalog_setup_dns_mode;
        j["CatalogSetupDnsRuleSummary"] = x.catalog_setup_dns_rule_summary;
        j["CatalogSetupDnsServerSummary"] = x.catalog_setup_dns_server_summary;
        j["CatalogSetupIntent"] = x.catalog_setup_intent;
        j["CatalogSetupListSummary"] = x.catalog_setup_list_summary;
        j["CatalogSetupMode"] = x.catalog_setup_mode;
        j["CatalogSetupPreviewRequest"] = x.catalog_setup_preview_request;
        j["CatalogSetupPreviewResponse"] = x.catalog_setup_preview_response;
        j["CatalogSetupRouteRuleSummary"] = x.catalog_setup_route_rule_summary;
        j["CatalogSetupSummary"] = x.catalog_setup_summary;
        j["CatalogSetupWarning"] = x.catalog_setup_warning;
        j["CheckStatus"] = x.check_status;
        j["CircuitBreakerConfig"] = x.circuit_breaker_config;
        j["ClientDnsEnforcement"] = x.client_dns_enforcement;
        j["ConfigObject"] = x.config_object;
        j["ConfigStateResponse"] = x.config_state_response;
        j["ConfigUpdateResponse"] = x.config_update_response;
        j["ConnectionEventState"] = x.connection_event_state;
        j["ConnectionPage"] = x.connection_page;
        j["ConnectionQueryRequest"] = x.connection_query_request;
        j["ConnectionRecord"] = x.connection_record;
        j["ConnectionSort"] = x.connection_sort;
        j["ConntrackOnSwitch"] = x.conntrack_on_switch;
        j["DaemonConfig"] = x.daemon_config;
        j["DependencyAnalysisRequest"] = x.dependency_analysis_request;
        j["DependencyAnalysisResponse"] = x.dependency_analysis_response;
        j["DependencyAnalysisTargetRequest"] = x.dependency_analysis_target_request;
        j["DependencyConsequence"] = x.dependency_consequence;
        j["DependencyDependentKind"] = x.dependency_dependent_kind;
        j["DependencyEntityKind"] = x.dependency_entity_kind;
        j["DependencyReference"] = x.dependency_reference;
        j["DependencyRelation"] = x.dependency_relation;
        j["DependencyTarget"] = x.dependency_target;
        j["DnsConfig"] = x.dns_config;
        j["DnsRule"] = x.dns_rule;
        j["DnsServer"] = x.dns_server;
        j["DnsSystemResolver"] = x.dns_system_resolver;
        j["DnsTestServer"] = x.dns_test_server;
        j["ErrorResponse"] = x.error_response;
        j["FirewallChain"] = x.firewall_chain;
        j["FirewallRuleCheck"] = x.firewall_rule_check;
        j["FwmarkConfig"] = x.fwmark_config;
        j["HealthResponse"] = x.health_response;
        j["InternalVpnServer"] = x.internal_vpn_server;
        j["InternalVpnService"] = x.internal_vpn_service;
        j["IprouteConfig"] = x.iproute_config;
        j["LifecycleOperation"] = x.lifecycle_operation;
        j["LifecycleOperationStage"] = x.lifecycle_operation_stage;
        j["ListConfig"] = x.list_config;
        j["ListDeleteStageRequest"] = x.list_delete_stage_request;
        j["ListDeleteStageResponse"] = x.list_delete_stage_response;
        j["ListDeleteStageSummary"] = x.list_delete_stage_summary;
        j["ListDeleteTarget"] = x.list_delete_target;
        j["ListRefreshConfig"] = x.list_refresh_config;
        j["ListRefreshDetourMode"] = x.list_refresh_detour_mode;
        j["ListRefreshRequest"] = x.list_refresh_request;
        j["ListRefreshResponse"] = x.list_refresh_response;
        j["ListRefreshState"] = x.list_refresh_state;
        j["ListsAutoupdateConfig"] = x.lists_autoupdate_config;
        j["NdmsCatalogStatus"] = x.ndms_catalog_status;
        j["NdmsInterfaceCapabilities"] = x.ndms_interface_capabilities;
        j["NdmsInterfaceInventoryResponse"] = x.ndms_interface_inventory_response;
        j["NdmsInterfaceManagementReadiness"] = x.ndms_interface_management_readiness;
        j["NdmsInterfaceRole"] = x.ndms_interface_role;
        j["NdmsManagementBlocker"] = x.ndms_management_blocker;
        j["NdmsTunnelInterface"] = x.ndms_tunnel_interface;
        j["NdmsTunnelKind"] = x.ndms_tunnel_kind;
        j["NdmsVpnServerKind"] = x.ndms_vpn_server_kind;
        j["NdmsVpnServerService"] = x.ndms_vpn_server_service;
        j["NdmsVpnServerServiceInventoryResponse"] = x.ndms_vpn_server_service_inventory_response;
        j["Outbound"] = x.outbound;
        j["OutboundGroup"] = x.outbound_group;
        j["PeriodicTaskMetricsEntry"] = x.periodic_task_metrics_entry;
        j["PeriodicTaskMetricsResponse"] = x.periodic_task_metrics_response;
        j["PeriodicTaskOutcome"] = x.periodic_task_outcome;
        j["PlainDnsTemplate"] = x.plain_dns_template;
        j["PolicyRuleCheck"] = x.policy_rule_check;
        j["RecommendedListSetupRequest"] = x.recommended_list_setup_request;
        j["ReloadResponse"] = x.reload_response;
        j["ResolverConfigProbeStatus"] = x.resolver_config_probe_status;
        j["ResolverConfigSyncState"] = x.resolver_config_sync_state;
        j["RetryConfig"] = x.retry_config;
        j["RouteConfig"] = x.route_config;
        j["RouteRule"] = x.route_rule;
        j["RouteTableCheck"] = x.route_table_check;
        j["RoutingHealthErrorResponse"] = x.routing_health_error_response;
        j["RoutingHealthResponse"] = x.routing_health_response;
        j["RoutingTestEntry"] = x.routing_test_entry;
        j["RoutingTestEvaluation"] = x.routing_test_evaluation;
        j["RoutingTestListMatch"] = x.routing_test_list_match;
        j["RoutingTestRequest"] = x.routing_test_request;
        j["RoutingTestResponse"] = x.routing_test_response;
        j["RoutingTestRuleDiagnostic"] = x.routing_test_rule_diagnostic;
        j["RoutingTestRuleIpDiagnostic"] = x.routing_test_rule_ip_diagnostic;
        j["RoutingTestUnknownCondition"] = x.routing_test_unknown_condition;
        j["RuntimeInterfaceInventoryEntry"] = x.runtime_interface_inventory_entry;
        j["RuntimeInterfaceInventoryResponse"] = x.runtime_interface_inventory_response;
        j["RuntimeInterfaceInventoryStatus"] = x.runtime_interface_inventory_status;
        j["RuntimeInterfaceState"] = x.runtime_interface_state;
        j["RuntimeInterfaceStatus"] = x.runtime_interface_status;
        j["RuntimeInterfaceTraffic"] = x.runtime_interface_traffic;
        j["RuntimeInterfaceTrafficPoint"] = x.runtime_interface_traffic_point;
        j["RuntimeInterfaceTrafficSample"] = x.runtime_interface_traffic_sample;
        j["RuntimeInterfaceTrafficUpdate"] = x.runtime_interface_traffic_update;
        j["RuntimeInterfaceUptimeSource"] = x.runtime_interface_uptime_source;
        j["RuntimeInventoryResponse"] = x.runtime_inventory_response;
        j["RuntimeOutboundsResponse"] = x.runtime_outbounds_response;
        j["RuntimeOutboundState"] = x.runtime_outbound_state;
        j["RuntimeOutboundStatus"] = x.runtime_outbound_status;
        j["SortOrder"] = x.sort_order;
        j["StatusEventConnections"] = x.status_event_connections;
        j["StatusEventInterfaces"] = x.status_event_interfaces;
        j["StatusEventInterfaceTraffic"] = x.status_event_interface_traffic;
        j["StatusEventOutbounds"] = x.status_event_outbounds;
        j["StatusEventService"] = x.status_event_service;
        j["StatusEventSnapshot"] = x.status_event_snapshot;
        j["TransportActionRequest"] = x.transport_action_request;
        j["TransportActionResponse"] = x.transport_action_response;
        j["TransportConfigApplyRequest"] = x.transport_config_apply_request;
        j["TransportConfigApplyResponse"] = x.transport_config_apply_response;
        j["TransportConfigOperation"] = x.transport_config_operation;
        j["TransportConfigResponse"] = x.transport_config_response;
        j["TransportLinkedOutboundEnsure"] = x.transport_linked_outbound_ensure;
        j["TransportPath"] = x.transport_path;
        j["TransportSpec"] = x.transport_spec;
        j["TransportStatus"] = x.transport_status;
        j["UiPreferencesConfig"] = x.ui_preferences_config;
        j["ValidationError"] = x.validation_error;
        j["VlessRealitySpec"] = x.vless_reality_spec;
    }

    inline void from_json(const json & j, DnsMode & x) {
        if (j == "automatic") x = DnsMode::AUTOMATIC;
        else if (j == "explicit_server") x = DnsMode::EXPLICIT_SERVER;
        else if (j == "none") x = DnsMode::NONE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DnsMode\""); }
    }

    inline void to_json(json & j, const DnsMode & x) {
        switch (x) {
            case DnsMode::AUTOMATIC: j = "automatic"; break;
            case DnsMode::EXPLICIT_SERVER: j = "explicit_server"; break;
            case DnsMode::NONE: j = "none"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DnsMode\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, CatalogSetupModeEnum & x) {
        if (j == "block") x = CatalogSetupModeEnum::BLOCK;
        else if (j == "none") x = CatalogSetupModeEnum::NONE;
        else if (j == "outbound") x = CatalogSetupModeEnum::OUTBOUND;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"CatalogSetupModeEnum\""); }
    }

    inline void to_json(json & j, const CatalogSetupModeEnum & x) {
        switch (x) {
            case CatalogSetupModeEnum::BLOCK: j = "block"; break;
            case CatalogSetupModeEnum::NONE: j = "none"; break;
            case CatalogSetupModeEnum::OUTBOUND: j = "outbound"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"CatalogSetupModeEnum\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Code & x) {
        if (j == "broad_traffic_scope") x = Code::BROAD_TRAFFIC_SCOPE;
        else if (j == "dns_automatic_unavailable") x = Code::DNS_AUTOMATIC_UNAVAILABLE;
        else if (j == "dns_detour_mismatch") x = Code::DNS_DETOUR_MISMATCH;
        else if (j == "dns_detour_missing") x = Code::DNS_DETOUR_MISSING;
        else if (j == "dns_ignored_for_block") x = Code::DNS_IGNORED_FOR_BLOCK;
        else if (j == "source_detour_not_applicable") x = Code::SOURCE_DETOUR_NOT_APPLICABLE;
        else if (j == "source_detour_not_found") x = Code::SOURCE_DETOUR_NOT_FOUND;
        else if (j == "source_detour_not_routable") x = Code::SOURCE_DETOUR_NOT_ROUTABLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Code\""); }
    }

    inline void to_json(json & j, const Code & x) {
        switch (x) {
            case Code::BROAD_TRAFFIC_SCOPE: j = "broad_traffic_scope"; break;
            case Code::DNS_AUTOMATIC_UNAVAILABLE: j = "dns_automatic_unavailable"; break;
            case Code::DNS_DETOUR_MISMATCH: j = "dns_detour_mismatch"; break;
            case Code::DNS_DETOUR_MISSING: j = "dns_detour_missing"; break;
            case Code::DNS_IGNORED_FOR_BLOCK: j = "dns_ignored_for_block"; break;
            case Code::SOURCE_DETOUR_NOT_APPLICABLE: j = "source_detour_not_applicable"; break;
            case Code::SOURCE_DETOUR_NOT_FOUND: j = "source_detour_not_found"; break;
            case Code::SOURCE_DETOUR_NOT_ROUTABLE: j = "source_detour_not_routable"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Code\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, CheckStatus & x) {
        if (j == "mismatch") x = CheckStatus::MISMATCH;
        else if (j == "missing") x = CheckStatus::MISSING;
        else if (j == "ok") x = CheckStatus::OK;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"CheckStatus\""); }
    }

    inline void to_json(json & j, const CheckStatus & x) {
        switch (x) {
            case CheckStatus::MISMATCH: j = "mismatch"; break;
            case CheckStatus::MISSING: j = "missing"; break;
            case CheckStatus::OK: j = "ok"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"CheckStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DaemonConfigFirewallBackend & x) {
        if (j == "auto") x = DaemonConfigFirewallBackend::AUTO;
        else if (j == "iptables") x = DaemonConfigFirewallBackend::IPTABLES;
        else if (j == "nftables") x = DaemonConfigFirewallBackend::NFTABLES;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DaemonConfigFirewallBackend\""); }
    }

    inline void to_json(json & j, const DaemonConfigFirewallBackend & x) {
        switch (x) {
            case DaemonConfigFirewallBackend::AUTO: j = "auto"; break;
            case DaemonConfigFirewallBackend::IPTABLES: j = "iptables"; break;
            case DaemonConfigFirewallBackend::NFTABLES: j = "nftables"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DaemonConfigFirewallBackend\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, MetaUdp443Policy & x) {
        if (j == "balanced") x = MetaUdp443Policy::BALANCED;
        else if (j == "messages_first") x = MetaUdp443Policy::MESSAGES_FIRST;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"MetaUdp443Policy\""); }
    }

    inline void to_json(json & j, const MetaUdp443Policy & x) {
        switch (x) {
            case MetaUdp443Policy::BALANCED: j = "balanced"; break;
            case MetaUdp443Policy::MESSAGES_FIRST: j = "messages_first"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"MetaUdp443Policy\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DnsServerType & x) {
        if (j == "keenetic") x = DnsServerType::KEENETIC;
        else if (j == "static") x = DnsServerType::STATIC;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DnsServerType\""); }
    }

    inline void to_json(json & j, const DnsServerType & x) {
        switch (x) {
            case DnsServerType::KEENETIC: j = "keenetic"; break;
            case DnsServerType::STATIC: j = "static"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DnsServerType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RefreshDetourMode & x) {
        if (j == "inherit") x = RefreshDetourMode::INHERIT;
        else if (j == "override") x = RefreshDetourMode::OVERRIDE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RefreshDetourMode\""); }
    }

    inline void to_json(json & j, const RefreshDetourMode & x) {
        switch (x) {
            case RefreshDetourMode::INHERIT: j = "inherit"; break;
            case RefreshDetourMode::OVERRIDE: j = "override"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RefreshDetourMode\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ConntrackOnSwitch & x) {
        if (j == "delete") x = ConntrackOnSwitch::DELETE;
        else if (j == "delete_on_failure") x = ConntrackOnSwitch::DELETE_ON_FAILURE;
        else if (j == "preserve") x = ConntrackOnSwitch::PRESERVE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ConntrackOnSwitch\""); }
    }

    inline void to_json(json & j, const ConntrackOnSwitch & x) {
        switch (x) {
            case ConntrackOnSwitch::DELETE: j = "delete"; break;
            case ConntrackOnSwitch::DELETE_ON_FAILURE: j = "delete_on_failure"; break;
            case ConntrackOnSwitch::PRESERVE: j = "preserve"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ConntrackOnSwitch\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, SelectionMode & x) {
        if (j == "latency") x = SelectionMode::LATENCY;
        else if (j == "priority") x = SelectionMode::PRIORITY;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"SelectionMode\""); }
    }

    inline void to_json(json & j, const SelectionMode & x) {
        switch (x) {
            case SelectionMode::LATENCY: j = "latency"; break;
            case SelectionMode::PRIORITY: j = "priority"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"SelectionMode\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, OutboundType & x) {
        if (j == "blackhole") x = OutboundType::BLACKHOLE;
        else if (j == "ignore") x = OutboundType::IGNORE;
        else if (j == "interface") x = OutboundType::INTERFACE;
        else if (j == "table") x = OutboundType::TABLE;
        else if (j == "urltest") x = OutboundType::URLTEST;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"OutboundType\""); }
    }

    inline void to_json(json & j, const OutboundType & x) {
        switch (x) {
            case OutboundType::BLACKHOLE: j = "blackhole"; break;
            case OutboundType::IGNORE: j = "ignore"; break;
            case OutboundType::INTERFACE: j = "interface"; break;
            case OutboundType::TABLE: j = "table"; break;
            case OutboundType::URLTEST: j = "urltest"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"OutboundType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ConfigUpdateResponseStatus & x) {
        if (j == "ok") x = ConfigUpdateResponseStatus::OK;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ConfigUpdateResponseStatus\""); }
    }

    inline void to_json(json & j, const ConfigUpdateResponseStatus & x) {
        switch (x) {
            case ConfigUpdateResponseStatus::OK: j = "ok"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ConfigUpdateResponseStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, SortOrder & x) {
        if (j == "asc") x = SortOrder::ASC;
        else if (j == "desc") x = SortOrder::DESC;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"SortOrder\""); }
    }

    inline void to_json(json & j, const SortOrder & x) {
        switch (x) {
            case SortOrder::ASC: j = "asc"; break;
            case SortOrder::DESC: j = "desc"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"SortOrder\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ConnectionSort & x) {
        if (j == "destination") x = ConnectionSort::DESTINATION;
        else if (j == "first_seen") x = ConnectionSort::FIRST_SEEN;
        else if (j == "last_seen") x = ConnectionSort::LAST_SEEN;
        else if (j == "source") x = ConnectionSort::SOURCE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ConnectionSort\""); }
    }

    inline void to_json(json & j, const ConnectionSort & x) {
        switch (x) {
            case ConnectionSort::DESTINATION: j = "destination"; break;
            case ConnectionSort::FIRST_SEEN: j = "first_seen"; break;
            case ConnectionSort::LAST_SEEN: j = "last_seen"; break;
            case ConnectionSort::SOURCE: j = "source"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ConnectionSort\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DependencyEntityKind & x) {
        if (j == "dns_server") x = DependencyEntityKind::DNS_SERVER;
        else if (j == "list") x = DependencyEntityKind::LIST;
        else if (j == "outbound") x = DependencyEntityKind::OUTBOUND;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DependencyEntityKind\""); }
    }

    inline void to_json(json & j, const DependencyEntityKind & x) {
        switch (x) {
            case DependencyEntityKind::DNS_SERVER: j = "dns_server"; break;
            case DependencyEntityKind::LIST: j = "list"; break;
            case DependencyEntityKind::OUTBOUND: j = "outbound"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DependencyEntityKind\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DependencyConsequence & x) {
        if (j == "delete") x = DependencyConsequence::DELETE;
        else if (j == "disconnect") x = DependencyConsequence::DISCONNECT;
        else if (j == "modify") x = DependencyConsequence::MODIFY;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DependencyConsequence\""); }
    }

    inline void to_json(json & j, const DependencyConsequence & x) {
        switch (x) {
            case DependencyConsequence::DELETE: j = "delete"; break;
            case DependencyConsequence::DISCONNECT: j = "disconnect"; break;
            case DependencyConsequence::MODIFY: j = "modify"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DependencyConsequence\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DependencyDependentKind & x) {
        if (j == "dns_fallback") x = DependencyDependentKind::DNS_FALLBACK;
        else if (j == "dns_rule") x = DependencyDependentKind::DNS_RULE;
        else if (j == "dns_server") x = DependencyDependentKind::DNS_SERVER;
        else if (j == "list") x = DependencyDependentKind::LIST;
        else if (j == "list_refresh") x = DependencyDependentKind::LIST_REFRESH;
        else if (j == "outbound_group") x = DependencyDependentKind::OUTBOUND_GROUP;
        else if (j == "routing_rule") x = DependencyDependentKind::ROUTING_RULE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DependencyDependentKind\""); }
    }

    inline void to_json(json & j, const DependencyDependentKind & x) {
        switch (x) {
            case DependencyDependentKind::DNS_FALLBACK: j = "dns_fallback"; break;
            case DependencyDependentKind::DNS_RULE: j = "dns_rule"; break;
            case DependencyDependentKind::DNS_SERVER: j = "dns_server"; break;
            case DependencyDependentKind::LIST: j = "list"; break;
            case DependencyDependentKind::LIST_REFRESH: j = "list_refresh"; break;
            case DependencyDependentKind::OUTBOUND_GROUP: j = "outbound_group"; break;
            case DependencyDependentKind::ROUTING_RULE: j = "routing_rule"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DependencyDependentKind\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DependencyRelation & x) {
        if (j == "contains_member") x = DependencyRelation::CONTAINS_MEMBER;
        else if (j == "detours_via") x = DependencyRelation::DETOURS_VIA;
        else if (j == "fallback_to") x = DependencyRelation::FALLBACK_TO;
        else if (j == "routes_to") x = DependencyRelation::ROUTES_TO;
        else if (j == "uses_dns_server") x = DependencyRelation::USES_DNS_SERVER;
        else if (j == "uses_list") x = DependencyRelation::USES_LIST;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DependencyRelation\""); }
    }

    inline void to_json(json & j, const DependencyRelation & x) {
        switch (x) {
            case DependencyRelation::CONTAINS_MEMBER: j = "contains_member"; break;
            case DependencyRelation::DETOURS_VIA: j = "detours_via"; break;
            case DependencyRelation::FALLBACK_TO: j = "fallback_to"; break;
            case DependencyRelation::ROUTES_TO: j = "routes_to"; break;
            case DependencyRelation::USES_DNS_SERVER: j = "uses_dns_server"; break;
            case DependencyRelation::USES_LIST: j = "uses_list"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DependencyRelation\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, LifecycleOperationStageStatus & x) {
        if (j == "failed") x = LifecycleOperationStageStatus::FAILED;
        else if (j == "pending") x = LifecycleOperationStageStatus::PENDING;
        else if (j == "running") x = LifecycleOperationStageStatus::RUNNING;
        else if (j == "skipped") x = LifecycleOperationStageStatus::SKIPPED;
        else if (j == "succeeded") x = LifecycleOperationStageStatus::SUCCEEDED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"LifecycleOperationStageStatus\""); }
    }

    inline void to_json(json & j, const LifecycleOperationStageStatus & x) {
        switch (x) {
            case LifecycleOperationStageStatus::FAILED: j = "failed"; break;
            case LifecycleOperationStageStatus::PENDING: j = "pending"; break;
            case LifecycleOperationStageStatus::RUNNING: j = "running"; break;
            case LifecycleOperationStageStatus::SKIPPED: j = "skipped"; break;
            case LifecycleOperationStageStatus::SUCCEEDED: j = "succeeded"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"LifecycleOperationStageStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, LifecycleOperationStatus & x) {
        if (j == "failed") x = LifecycleOperationStatus::FAILED;
        else if (j == "running") x = LifecycleOperationStatus::RUNNING;
        else if (j == "succeeded") x = LifecycleOperationStatus::SUCCEEDED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"LifecycleOperationStatus\""); }
    }

    inline void to_json(json & j, const LifecycleOperationStatus & x) {
        switch (x) {
            case LifecycleOperationStatus::FAILED: j = "failed"; break;
            case LifecycleOperationStatus::RUNNING: j = "running"; break;
            case LifecycleOperationStatus::SUCCEEDED: j = "succeeded"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"LifecycleOperationStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, LifecycleOperationType & x) {
        if (j == "apply_config") x = LifecycleOperationType::APPLY_CONFIG;
        else if (j == "restart") x = LifecycleOperationType::RESTART;
        else if (j == "start") x = LifecycleOperationType::START;
        else if (j == "stop") x = LifecycleOperationType::STOP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"LifecycleOperationType\""); }
    }

    inline void to_json(json & j, const LifecycleOperationType & x) {
        switch (x) {
            case LifecycleOperationType::APPLY_CONFIG: j = "apply_config"; break;
            case LifecycleOperationType::RESTART: j = "restart"; break;
            case LifecycleOperationType::START: j = "start"; break;
            case LifecycleOperationType::STOP: j = "stop"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"LifecycleOperationType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ResolverConfigProbeStatus & x) {
        if (j == "invalid_txt") x = ResolverConfigProbeStatus::INVALID_TXT;
        else if (j == "missing_txt") x = ResolverConfigProbeStatus::MISSING_TXT;
        else if (j == "not_configured") x = ResolverConfigProbeStatus::NOT_CONFIGURED;
        else if (j == "query_failed") x = ResolverConfigProbeStatus::QUERY_FAILED;
        else if (j == "success") x = ResolverConfigProbeStatus::SUCCESS;
        else if (j == "unknown") x = ResolverConfigProbeStatus::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ResolverConfigProbeStatus\""); }
    }

    inline void to_json(json & j, const ResolverConfigProbeStatus & x) {
        switch (x) {
            case ResolverConfigProbeStatus::INVALID_TXT: j = "invalid_txt"; break;
            case ResolverConfigProbeStatus::MISSING_TXT: j = "missing_txt"; break;
            case ResolverConfigProbeStatus::NOT_CONFIGURED: j = "not_configured"; break;
            case ResolverConfigProbeStatus::QUERY_FAILED: j = "query_failed"; break;
            case ResolverConfigProbeStatus::SUCCESS: j = "success"; break;
            case ResolverConfigProbeStatus::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ResolverConfigProbeStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ResolverConfigSyncState & x) {
        if (j == "converged") x = ResolverConfigSyncState::CONVERGED;
        else if (j == "converging") x = ResolverConfigSyncState::CONVERGING;
        else if (j == "stale") x = ResolverConfigSyncState::STALE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ResolverConfigSyncState\""); }
    }

    inline void to_json(json & j, const ResolverConfigSyncState & x) {
        switch (x) {
            case ResolverConfigSyncState::CONVERGED: j = "converged"; break;
            case ResolverConfigSyncState::CONVERGING: j = "converging"; break;
            case ResolverConfigSyncState::STALE: j = "stale"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ResolverConfigSyncState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ResolverLiveStatus & x) {
        if (j == "degraded") x = ResolverLiveStatus::DEGRADED;
        else if (j == "healthy") x = ResolverLiveStatus::HEALTHY;
        else if (j == "unavailable") x = ResolverLiveStatus::UNAVAILABLE;
        else if (j == "unknown") x = ResolverLiveStatus::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ResolverLiveStatus\""); }
    }

    inline void to_json(json & j, const ResolverLiveStatus & x) {
        switch (x) {
            case ResolverLiveStatus::DEGRADED: j = "degraded"; break;
            case ResolverLiveStatus::HEALTHY: j = "healthy"; break;
            case ResolverLiveStatus::UNAVAILABLE: j = "unavailable"; break;
            case ResolverLiveStatus::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ResolverLiveStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RuntimeState & x) {
        if (j == "applying") x = RuntimeState::APPLYING;
        else if (j == "broken") x = RuntimeState::BROKEN;
        else if (j == "restart_required") x = RuntimeState::RESTART_REQUIRED;
        else if (j == "running") x = RuntimeState::RUNNING;
        else if (j == "shutting_down") x = RuntimeState::SHUTTING_DOWN;
        else if (j == "starting") x = RuntimeState::STARTING;
        else if (j == "stopped") x = RuntimeState::STOPPED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RuntimeState\""); }
    }

    inline void to_json(json & j, const RuntimeState & x) {
        switch (x) {
            case RuntimeState::APPLYING: j = "applying"; break;
            case RuntimeState::BROKEN: j = "broken"; break;
            case RuntimeState::RESTART_REQUIRED: j = "restart_required"; break;
            case RuntimeState::RUNNING: j = "running"; break;
            case RuntimeState::SHUTTING_DOWN: j = "shutting_down"; break;
            case RuntimeState::STARTING: j = "starting"; break;
            case RuntimeState::STOPPED: j = "stopped"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RuntimeState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, HealthResponseStatus & x) {
        if (j == "running") x = HealthResponseStatus::RUNNING;
        else if (j == "stopped") x = HealthResponseStatus::STOPPED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"HealthResponseStatus\""); }
    }

    inline void to_json(json & j, const HealthResponseStatus & x) {
        switch (x) {
            case HealthResponseStatus::RUNNING: j = "running"; break;
            case HealthResponseStatus::STOPPED: j = "stopped"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"HealthResponseStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsCatalogStatus & x) {
        if (j == "fresh") x = NdmsCatalogStatus::FRESH;
        else if (j == "stale") x = NdmsCatalogStatus::STALE;
        else if (j == "unavailable") x = NdmsCatalogStatus::UNAVAILABLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsCatalogStatus\""); }
    }

    inline void to_json(json & j, const NdmsCatalogStatus & x) {
        switch (x) {
            case NdmsCatalogStatus::FRESH: j = "fresh"; break;
            case NdmsCatalogStatus::STALE: j = "stale"; break;
            case NdmsCatalogStatus::UNAVAILABLE: j = "unavailable"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsCatalogStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Kind & x) {
        if (j == "amnezia_wireguard") x = Kind::AMNEZIA_WIREGUARD;
        else if (j == "https_proxy") x = Kind::HTTPS_PROXY;
        else if (j == "http_proxy") x = Kind::HTTP_PROXY;
        else if (j == "ike") x = Kind::IKE;
        else if (j == "l2tp") x = Kind::L2_TP;
        else if (j == "openconnect") x = Kind::OPENCONNECT;
        else if (j == "openvpn") x = Kind::OPENVPN;
        else if (j == "socks5_proxy") x = Kind::SOCKS5_PROXY;
        else if (j == "sstp") x = Kind::SSTP;
        else if (j == "wireguard") x = Kind::WIREGUARD;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Kind\""); }
    }

    inline void to_json(json & j, const Kind & x) {
        switch (x) {
            case Kind::AMNEZIA_WIREGUARD: j = "amnezia_wireguard"; break;
            case Kind::HTTPS_PROXY: j = "https_proxy"; break;
            case Kind::HTTP_PROXY: j = "http_proxy"; break;
            case Kind::IKE: j = "ike"; break;
            case Kind::L2_TP: j = "l2tp"; break;
            case Kind::OPENCONNECT: j = "openconnect"; break;
            case Kind::OPENVPN: j = "openvpn"; break;
            case Kind::SOCKS5_PROXY: j = "socks5_proxy"; break;
            case Kind::SSTP: j = "sstp"; break;
            case Kind::WIREGUARD: j = "wireguard"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Kind\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsManagementBlockerElement & x) {
        if (j == "automatic_backup_unavailable") x = NdmsManagementBlockerElement::AUTOMATIC_BACKUP_UNAVAILABLE;
        else if (j == "kernel_identity_unresolved") x = NdmsManagementBlockerElement::KERNEL_IDENTITY_UNRESOLVED;
        else if (j == "optimistic_revision_unavailable") x = NdmsManagementBlockerElement::OPTIMISTIC_REVISION_UNAVAILABLE;
        else if (j == "ownership_unknown") x = NdmsManagementBlockerElement::OWNERSHIP_UNKNOWN;
        else if (j == "role_unknown") x = NdmsManagementBlockerElement::ROLE_UNKNOWN;
        else if (j == "typed_rci_unavailable") x = NdmsManagementBlockerElement::TYPED_RCI_UNAVAILABLE;
        else if (j == "unsupported_kind") x = NdmsManagementBlockerElement::UNSUPPORTED_KIND;
        else if (j == "unsupported_role") x = NdmsManagementBlockerElement::UNSUPPORTED_ROLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsManagementBlockerElement\""); }
    }

    inline void to_json(json & j, const NdmsManagementBlockerElement & x) {
        switch (x) {
            case NdmsManagementBlockerElement::AUTOMATIC_BACKUP_UNAVAILABLE: j = "automatic_backup_unavailable"; break;
            case NdmsManagementBlockerElement::KERNEL_IDENTITY_UNRESOLVED: j = "kernel_identity_unresolved"; break;
            case NdmsManagementBlockerElement::OPTIMISTIC_REVISION_UNAVAILABLE: j = "optimistic_revision_unavailable"; break;
            case NdmsManagementBlockerElement::OWNERSHIP_UNKNOWN: j = "ownership_unknown"; break;
            case NdmsManagementBlockerElement::ROLE_UNKNOWN: j = "role_unknown"; break;
            case NdmsManagementBlockerElement::TYPED_RCI_UNAVAILABLE: j = "typed_rci_unavailable"; break;
            case NdmsManagementBlockerElement::UNSUPPORTED_KIND: j = "unsupported_kind"; break;
            case NdmsManagementBlockerElement::UNSUPPORTED_ROLE: j = "unsupported_role"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsManagementBlockerElement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Owner & x) {
        if (j == "keenetic") x = Owner::KEENETIC;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Owner\""); }
    }

    inline void to_json(json & j, const Owner & x) {
        switch (x) {
            case Owner::KEENETIC: j = "keenetic"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Owner\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Role & x) {
        if (j == "client") x = Role::CLIENT;
        else if (j == "server") x = Role::SERVER;
        else if (j == "unknown") x = Role::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Role\""); }
    }

    inline void to_json(json & j, const Role & x) {
        switch (x) {
            case Role::CLIENT: j = "client"; break;
            case Role::SERVER: j = "server"; break;
            case Role::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Role\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, MutationMode & x) {
        if (j == "disabled") x = MutationMode::DISABLED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"MutationMode\""); }
    }

    inline void to_json(json & j, const MutationMode & x) {
        switch (x) {
            case MutationMode::DISABLED: j = "disabled"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"MutationMode\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RequiredGuard & x) {
        if (j == "automatic_backup") x = RequiredGuard::AUTOMATIC_BACKUP;
        else if (j == "optimistic_revision") x = RequiredGuard::OPTIMISTIC_REVISION;
        else if (j == "ownership_check") x = RequiredGuard::OWNERSHIP_CHECK;
        else if (j == "typed_rci") x = RequiredGuard::TYPED_RCI;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RequiredGuard\""); }
    }

    inline void to_json(json & j, const RequiredGuard & x) {
        switch (x) {
            case RequiredGuard::AUTOMATIC_BACKUP: j = "automatic_backup"; break;
            case RequiredGuard::OPTIMISTIC_REVISION: j = "optimistic_revision"; break;
            case RequiredGuard::OWNERSHIP_CHECK: j = "ownership_check"; break;
            case RequiredGuard::TYPED_RCI: j = "typed_rci"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RequiredGuard\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsVpnServerKind & x) {
        if (j == "ikev1") x = NdmsVpnServerKind::IKEV1;
        else if (j == "ikev2") x = NdmsVpnServerKind::IKEV2;
        else if (j == "l2tp") x = NdmsVpnServerKind::L2_TP;
        else if (j == "openconnect") x = NdmsVpnServerKind::OPENCONNECT;
        else if (j == "sstp") x = NdmsVpnServerKind::SSTP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsVpnServerKind\""); }
    }

    inline void to_json(json & j, const NdmsVpnServerKind & x) {
        switch (x) {
            case NdmsVpnServerKind::IKEV1: j = "ikev1"; break;
            case NdmsVpnServerKind::IKEV2: j = "ikev2"; break;
            case NdmsVpnServerKind::L2_TP: j = "l2tp"; break;
            case NdmsVpnServerKind::OPENCONNECT: j = "openconnect"; break;
            case NdmsVpnServerKind::SSTP: j = "sstp"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsVpnServerKind\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, LastOutcome & x) {
        if (j == "abandoned") x = LastOutcome::ABANDONED;
        else if (j == "failure") x = LastOutcome::FAILURE;
        else if (j == "noop") x = LastOutcome::NOOP;
        else if (j == "skipped") x = LastOutcome::SKIPPED;
        else if (j == "success") x = LastOutcome::SUCCESS;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"LastOutcome\""); }
    }

    inline void to_json(json & j, const LastOutcome & x) {
        switch (x) {
            case LastOutcome::ABANDONED: j = "abandoned"; break;
            case LastOutcome::FAILURE: j = "failure"; break;
            case LastOutcome::NOOP: j = "noop"; break;
            case LastOutcome::SKIPPED: j = "skipped"; break;
            case LastOutcome::SUCCESS: j = "success"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"LastOutcome\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RoutingHealthErrorResponseOverall & x) {
        if (j == "error") x = RoutingHealthErrorResponseOverall::ERROR;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RoutingHealthErrorResponseOverall\""); }
    }

    inline void to_json(json & j, const RoutingHealthErrorResponseOverall & x) {
        switch (x) {
            case RoutingHealthErrorResponseOverall::ERROR: j = "error"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RoutingHealthErrorResponseOverall\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RoutingHealthResponseFirewallBackend & x) {
        if (j == "iptables") x = RoutingHealthResponseFirewallBackend::IPTABLES;
        else if (j == "nftables") x = RoutingHealthResponseFirewallBackend::NFTABLES;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RoutingHealthResponseFirewallBackend\""); }
    }

    inline void to_json(json & j, const RoutingHealthResponseFirewallBackend & x) {
        switch (x) {
            case RoutingHealthResponseFirewallBackend::IPTABLES: j = "iptables"; break;
            case RoutingHealthResponseFirewallBackend::NFTABLES: j = "nftables"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RoutingHealthResponseFirewallBackend\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RoutingHealthResponseOverall & x) {
        if (j == "degraded") x = RoutingHealthResponseOverall::DEGRADED;
        else if (j == "error") x = RoutingHealthResponseOverall::ERROR;
        else if (j == "ok") x = RoutingHealthResponseOverall::OK;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RoutingHealthResponseOverall\""); }
    }

    inline void to_json(json & j, const RoutingHealthResponseOverall & x) {
        switch (x) {
            case RoutingHealthResponseOverall::DEGRADED: j = "degraded"; break;
            case RoutingHealthResponseOverall::ERROR: j = "error"; break;
            case RoutingHealthResponseOverall::OK: j = "ok"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RoutingHealthResponseOverall\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Evaluation & x) {
        if (j == "insufficient_context") x = Evaluation::INSUFFICIENT_CONTEXT;
        else if (j == "matched") x = Evaluation::MATCHED;
        else if (j == "not_matched") x = Evaluation::NOT_MATCHED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Evaluation\""); }
    }

    inline void to_json(json & j, const Evaluation & x) {
        switch (x) {
            case Evaluation::INSUFFICIENT_CONTEXT: j = "insufficient_context"; break;
            case Evaluation::MATCHED: j = "matched"; break;
            case Evaluation::NOT_MATCHED: j = "not_matched"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Evaluation\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RoutingTestUnknownConditionElement & x) {
        if (j == "destination_address") x = RoutingTestUnknownConditionElement::DESTINATION_ADDRESS;
        else if (j == "destination_port") x = RoutingTestUnknownConditionElement::DESTINATION_PORT;
        else if (j == "dscp") x = RoutingTestUnknownConditionElement::DSCP;
        else if (j == "firewall_set") x = RoutingTestUnknownConditionElement::FIREWALL_SET;
        else if (j == "firewall_state") x = RoutingTestUnknownConditionElement::FIREWALL_STATE;
        else if (j == "firewall_tool") x = RoutingTestUnknownConditionElement::FIREWALL_TOOL;
        else if (j == "inbound_interface") x = RoutingTestUnknownConditionElement::INBOUND_INTERFACE;
        else if (j == "protocol") x = RoutingTestUnknownConditionElement::PROTOCOL;
        else if (j == "resolved_ip") x = RoutingTestUnknownConditionElement::RESOLVED_IP;
        else if (j == "source_address") x = RoutingTestUnknownConditionElement::SOURCE_ADDRESS;
        else if (j == "source_port") x = RoutingTestUnknownConditionElement::SOURCE_PORT;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RoutingTestUnknownConditionElement\""); }
    }

    inline void to_json(json & j, const RoutingTestUnknownConditionElement & x) {
        switch (x) {
            case RoutingTestUnknownConditionElement::DESTINATION_ADDRESS: j = "destination_address"; break;
            case RoutingTestUnknownConditionElement::DESTINATION_PORT: j = "destination_port"; break;
            case RoutingTestUnknownConditionElement::DSCP: j = "dscp"; break;
            case RoutingTestUnknownConditionElement::FIREWALL_SET: j = "firewall_set"; break;
            case RoutingTestUnknownConditionElement::FIREWALL_STATE: j = "firewall_state"; break;
            case RoutingTestUnknownConditionElement::FIREWALL_TOOL: j = "firewall_tool"; break;
            case RoutingTestUnknownConditionElement::INBOUND_INTERFACE: j = "inbound_interface"; break;
            case RoutingTestUnknownConditionElement::PROTOCOL: j = "protocol"; break;
            case RoutingTestUnknownConditionElement::RESOLVED_IP: j = "resolved_ip"; break;
            case RoutingTestUnknownConditionElement::SOURCE_ADDRESS: j = "source_address"; break;
            case RoutingTestUnknownConditionElement::SOURCE_PORT: j = "source_port"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RoutingTestUnknownConditionElement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ConfigScope & x) {
        if (j == "active") x = ConfigScope::ACTIVE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ConfigScope\""); }
    }

    inline void to_json(json & j, const ConfigScope & x) {
        switch (x) {
            case ConfigScope::ACTIVE: j = "active"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ConfigScope\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, LinkUptimeSource & x) {
        if (j == "firmware") x = LinkUptimeSource::FIRMWARE;
        else if (j == "observed") x = LinkUptimeSource::OBSERVED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"LinkUptimeSource\""); }
    }

    inline void to_json(json & j, const LinkUptimeSource & x) {
        switch (x) {
            case LinkUptimeSource::FIRMWARE: j = "firmware"; break;
            case LinkUptimeSource::OBSERVED: j = "observed"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"LinkUptimeSource\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RuntimeInterfaceInventoryStatusEnum & x) {
        if (j == "down") x = RuntimeInterfaceInventoryStatusEnum::DOWN;
        else if (j == "up") x = RuntimeInterfaceInventoryStatusEnum::UP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RuntimeInterfaceInventoryStatusEnum\""); }
    }

    inline void to_json(json & j, const RuntimeInterfaceInventoryStatusEnum & x) {
        switch (x) {
            case RuntimeInterfaceInventoryStatusEnum::DOWN: j = "down"; break;
            case RuntimeInterfaceInventoryStatusEnum::UP: j = "up"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RuntimeInterfaceInventoryStatusEnum\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RuntimeInterfaceStatusEnum & x) {
        if (j == "active") x = RuntimeInterfaceStatusEnum::ACTIVE;
        else if (j == "backup") x = RuntimeInterfaceStatusEnum::BACKUP;
        else if (j == "degraded") x = RuntimeInterfaceStatusEnum::DEGRADED;
        else if (j == "unavailable") x = RuntimeInterfaceStatusEnum::UNAVAILABLE;
        else if (j == "unknown") x = RuntimeInterfaceStatusEnum::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RuntimeInterfaceStatusEnum\""); }
    }

    inline void to_json(json & j, const RuntimeInterfaceStatusEnum & x) {
        switch (x) {
            case RuntimeInterfaceStatusEnum::ACTIVE: j = "active"; break;
            case RuntimeInterfaceStatusEnum::BACKUP: j = "backup"; break;
            case RuntimeInterfaceStatusEnum::DEGRADED: j = "degraded"; break;
            case RuntimeInterfaceStatusEnum::UNAVAILABLE: j = "unavailable"; break;
            case RuntimeInterfaceStatusEnum::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RuntimeInterfaceStatusEnum\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, StatusEventConnectionsType & x) {
        if (j == "connections") x = StatusEventConnectionsType::CONNECTIONS;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"StatusEventConnectionsType\""); }
    }

    inline void to_json(json & j, const StatusEventConnectionsType & x) {
        switch (x) {
            case StatusEventConnectionsType::CONNECTIONS: j = "connections"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"StatusEventConnectionsType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, StatusEventInterfaceTrafficType & x) {
        if (j == "interface_traffic") x = StatusEventInterfaceTrafficType::INTERFACE_TRAFFIC;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"StatusEventInterfaceTrafficType\""); }
    }

    inline void to_json(json & j, const StatusEventInterfaceTrafficType & x) {
        switch (x) {
            case StatusEventInterfaceTrafficType::INTERFACE_TRAFFIC: j = "interface_traffic"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"StatusEventInterfaceTrafficType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, StatusEventInterfacesType & x) {
        if (j == "interfaces") x = StatusEventInterfacesType::INTERFACES;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"StatusEventInterfacesType\""); }
    }

    inline void to_json(json & j, const StatusEventInterfacesType & x) {
        switch (x) {
            case StatusEventInterfacesType::INTERFACES: j = "interfaces"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"StatusEventInterfacesType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, StatusEventOutboundsType & x) {
        if (j == "outbounds") x = StatusEventOutboundsType::OUTBOUNDS;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"StatusEventOutboundsType\""); }
    }

    inline void to_json(json & j, const StatusEventOutboundsType & x) {
        switch (x) {
            case StatusEventOutboundsType::OUTBOUNDS: j = "outbounds"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"StatusEventOutboundsType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, StatusEventServiceType & x) {
        if (j == "service") x = StatusEventServiceType::SERVICE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"StatusEventServiceType\""); }
    }

    inline void to_json(json & j, const StatusEventServiceType & x) {
        switch (x) {
            case StatusEventServiceType::SERVICE: j = "service"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"StatusEventServiceType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, StatusEventSnapshotType & x) {
        if (j == "snapshot") x = StatusEventSnapshotType::SNAPSHOT;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"StatusEventSnapshotType\""); }
    }

    inline void to_json(json & j, const StatusEventSnapshotType & x) {
        switch (x) {
            case StatusEventSnapshotType::SNAPSHOT: j = "snapshot"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"StatusEventSnapshotType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Action & x) {
        if (j == "down") x = Action::DOWN;
        else if (j == "restart") x = Action::RESTART;
        else if (j == "up") x = Action::UP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Action\""); }
    }

    inline void to_json(json & j, const Action & x) {
        switch (x) {
            case Action::DOWN: j = "down"; break;
            case Action::RESTART: j = "restart"; break;
            case Action::UP: j = "up"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Action\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportActionResponseStatus & x) {
        if (j == "accepted") x = TransportActionResponseStatus::ACCEPTED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportActionResponseStatus\""); }
    }

    inline void to_json(json & j, const TransportActionResponseStatus & x) {
        switch (x) {
            case TransportActionResponseStatus::ACCEPTED: j = "accepted"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportActionResponseStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportLinkedOutboundEnsureMode & x) {
        if (j == "ensure") x = TransportLinkedOutboundEnsureMode::ENSURE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportLinkedOutboundEnsureMode\""); }
    }

    inline void to_json(json & j, const TransportLinkedOutboundEnsureMode & x) {
        switch (x) {
            case TransportLinkedOutboundEnsureMode::ENSURE: j = "ensure"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportLinkedOutboundEnsureMode\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportConfigApplyRequestOperation & x) {
        if (j == "create") x = TransportConfigApplyRequestOperation::CREATE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportConfigApplyRequestOperation\""); }
    }

    inline void to_json(json & j, const TransportConfigApplyRequestOperation & x) {
        switch (x) {
            case TransportConfigApplyRequestOperation::CREATE: j = "create"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportConfigApplyRequestOperation\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, GeoMode & x) {
        if (j == "auto") x = GeoMode::AUTO;
        else if (j == "disabled") x = GeoMode::DISABLED;
        else if (j == "manual") x = GeoMode::MANUAL;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"GeoMode\""); }
    }

    inline void to_json(json & j, const GeoMode & x) {
        switch (x) {
            case GeoMode::AUTO: j = "auto"; break;
            case GeoMode::DISABLED: j = "disabled"; break;
            case GeoMode::MANUAL: j = "manual"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"GeoMode\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportSpecType & x) {
        if (j == "native") x = TransportSpecType::NATIVE;
        else if (j == "sing-box") x = TransportSpecType::SING_BOX;
        else if (j == "sing-box-vless-reality") x = TransportSpecType::SING_BOX_VLESS_REALITY;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportSpecType\""); }
    }

    inline void to_json(json & j, const TransportSpecType & x) {
        switch (x) {
            case TransportSpecType::NATIVE: j = "native"; break;
            case TransportSpecType::SING_BOX: j = "sing-box"; break;
            case TransportSpecType::SING_BOX_VLESS_REALITY: j = "sing-box-vless-reality"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportSpecType\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportConfigApplyResponseStatus & x) {
        if (j == "applied") x = TransportConfigApplyResponseStatus::APPLIED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportConfigApplyResponseStatus\""); }
    }

    inline void to_json(json & j, const TransportConfigApplyResponseStatus & x) {
        switch (x) {
            case TransportConfigApplyResponseStatus::APPLIED: j = "applied"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportConfigApplyResponseStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportConfigOperationOperation & x) {
        if (j == "create") x = TransportConfigOperationOperation::CREATE;
        else if (j == "delete") x = TransportConfigOperationOperation::DELETE;
        else if (j == "update") x = TransportConfigOperationOperation::UPDATE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportConfigOperationOperation\""); }
    }

    inline void to_json(json & j, const TransportConfigOperationOperation & x) {
        switch (x) {
            case TransportConfigOperationOperation::CREATE: j = "create"; break;
            case TransportConfigOperationOperation::DELETE: j = "delete"; break;
            case TransportConfigOperationOperation::UPDATE: j = "update"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportConfigOperationOperation\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportConfigResponseStatus & x) {
        if (j == "created") x = TransportConfigResponseStatus::CREATED;
        else if (j == "deleted") x = TransportConfigResponseStatus::DELETED;
        else if (j == "updated") x = TransportConfigResponseStatus::UPDATED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportConfigResponseStatus\""); }
    }

    inline void to_json(json & j, const TransportConfigResponseStatus & x) {
        switch (x) {
            case TransportConfigResponseStatus::CREATED: j = "created"; break;
            case TransportConfigResponseStatus::DELETED: j = "deleted"; break;
            case TransportConfigResponseStatus::UPDATED: j = "updated"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportConfigResponseStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Confidence & x) {
        if (j == "ambiguous") x = Confidence::AMBIGUOUS;
        else if (j == "declared") x = Confidence::DECLARED;
        else if (j == "derived") x = Confidence::DERIVED;
        else if (j == "unknown") x = Confidence::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Confidence\""); }
    }

    inline void to_json(json & j, const Confidence & x) {
        switch (x) {
            case Confidence::AMBIGUOUS: j = "ambiguous"; break;
            case Confidence::DECLARED: j = "declared"; break;
            case Confidence::DERIVED: j = "derived"; break;
            case Confidence::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Confidence\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Framing & x) {
        if (j == "grpc") x = Framing::GRPC;
        else if (j == "http") x = Framing::HTTP;
        else if (j == "http2") x = Framing::HTTP2;
        else if (j == "http_upgrade") x = Framing::HTTP_UPGRADE;
        else if (j == "quic") x = Framing::QUIC;
        else if (j == "raw") x = Framing::RAW;
        else if (j == "unknown") x = Framing::UNKNOWN;
        else if (j == "websocket") x = Framing::WEBSOCKET;
        else if (j == "wireguard") x = Framing::WIREGUARD;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Framing\""); }
    }

    inline void to_json(json & j, const Framing & x) {
        switch (x) {
            case Framing::GRPC: j = "grpc"; break;
            case Framing::HTTP: j = "http"; break;
            case Framing::HTTP2: j = "http2"; break;
            case Framing::HTTP_UPGRADE: j = "http_upgrade"; break;
            case Framing::QUIC: j = "quic"; break;
            case Framing::RAW: j = "raw"; break;
            case Framing::UNKNOWN: j = "unknown"; break;
            case Framing::WEBSOCKET: j = "websocket"; break;
            case Framing::WIREGUARD: j = "wireguard"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Framing\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, PayloadNetwork & x) {
        if (j == "tcp") x = PayloadNetwork::TCP;
        else if (j == "udp") x = PayloadNetwork::UDP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"PayloadNetwork\""); }
    }

    inline void to_json(json & j, const PayloadNetwork & x) {
        switch (x) {
            case PayloadNetwork::TCP: j = "tcp"; break;
            case PayloadNetwork::UDP: j = "udp"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"PayloadNetwork\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, WireTransport & x) {
        if (j == "tcp") x = WireTransport::TCP;
        else if (j == "tcp_udp") x = WireTransport::TCP_UDP;
        else if (j == "udp") x = WireTransport::UDP;
        else if (j == "unknown") x = WireTransport::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"WireTransport\""); }
    }

    inline void to_json(json & j, const WireTransport & x) {
        switch (x) {
            case WireTransport::TCP: j = "tcp"; break;
            case WireTransport::TCP_UDP: j = "tcp_udp"; break;
            case WireTransport::UDP: j = "udp"; break;
            case WireTransport::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"WireTransport\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Security & x) {
        if (j == "reality") x = Security::REALITY;
        else if (j == "tls") x = Security::TLS;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Security\""); }
    }

    inline void to_json(json & j, const Security & x) {
        switch (x) {
            case Security::REALITY: j = "reality"; break;
            case Security::TLS: j = "tls"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Security\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, State & x) {
        if (j == "degraded") x = State::DEGRADED;
        else if (j == "down") x = State::DOWN;
        else if (j == "starting") x = State::STARTING;
        else if (j == "up") x = State::UP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"State\""); }
    }

    inline void to_json(json & j, const State & x) {
        switch (x) {
            case State::DEGRADED: j = "degraded"; break;
            case State::DOWN: j = "down"; break;
            case State::STARTING: j = "starting"; break;
            case State::UP: j = "up"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"State\": " + std::to_string(static_cast<int>(x)));
        }
    }
}
}
