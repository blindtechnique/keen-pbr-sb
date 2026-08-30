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
#include <variant>
#include <nlohmann/json.hpp>

#include <unordered_map>

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

    struct AuthCredentials {
        std::string password;
        std::string username;
    };

    struct AuthSettingsRequest {
        std::optional<bool> enabled;
        std::optional<std::string> keenetic_endpoint;
        std::optional<std::string> password;
        std::string provider;
        std::optional<std::string> username;
    };

    struct AuthSettingsResponse {
        bool durable = false;
        std::optional<int64_t> remote_access_generation;
        std::optional<bool> remote_access_pending;
        std::optional<std::string> restart_detail;
        std::optional<bool> restart_required;
        std::optional<bool> runtime_auth_enabled;
        bool saved = false;
        std::optional<std::string> warning;
    };

    enum class KeeneticEndpointSource : int { FALLBACK, NDMS };

    struct AuthStatus {
        bool authenticated = false;
        bool enabled = false;
        std::optional<std::string> error;
        std::optional<std::string> keenetic_endpoint;
        std::optional<std::string> keenetic_endpoint_mode;
        std::optional<KeeneticEndpointSource> keenetic_endpoint_source;
        std::optional<bool> network_api_blocked;
        std::optional<std::string> no_auth_scope;
        std::string provider;
        bool trusted_local_connection = false;
        std::optional<std::string> trusted_local_connection_generation;
        std::optional<int64_t> trusted_local_connection_valid_for_seconds;
    };

    struct AuthenticatedResponse {
        bool authenticated = false;
    };

    struct Data {
        std::optional<std::map<std::string, nlohmann::json>> dns;
        std::optional<std::map<std::string, nlohmann::json>> general;
        std::optional<std::map<std::string, nlohmann::json>> lists;
        std::optional<std::map<std::string, nlohmann::json>> nfqws;
        std::optional<std::vector<std::map<std::string, nlohmann::json>>> outbounds;
        std::optional<std::map<std::string, nlohmann::json>> route;
        std::optional<std::map<std::string, nlohmann::json>> transports;
    };

    enum class Format : int { KEEN_PBR_SB_BACKUP };

    struct Groups {
        std::optional<bool> dns;
        std::optional<bool> general;
        std::optional<bool> nfqws;
        std::optional<bool> nfqws_config;
        std::optional<bool> nfqws_lists;
        std::optional<bool> outbounds;
        std::optional<bool> routing;
        std::optional<bool> transports;
    };

    struct BackupDocument {
        std::optional<int64_t> created_at;
        Data data;
        Format format;
        std::optional<Groups> groups;
        int64_t schema = 0;
    };

    struct BackupReadRequest {
        std::optional<Groups> groups;
    };

    struct BackupRollbackAvailability {
        bool available = false;
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

    struct CatalogRefreshRequest {
        std::optional<std::string> detour;
    };

    struct CatalogRefreshResult {
        std::optional<std::string> detour;
        std::optional<std::string> error;
        std::optional<bool> packaged;
        std::optional<bool> settings_durable;
        std::optional<bool> updated;
        std::optional<std::string> warning;
    };

    enum class DnsMode : int { AUTOMATIC, EXPLICIT_SERVER, NONE };

    enum class CatalogSetupModeEnum : int { BLOCK, DIRECT, NONE, OUTBOUND };

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

    struct CatalogSetupDirectOutboundSummary {
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
        std::optional<CatalogSetupDirectOutboundSummary> direct_outbound;
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

    enum class PpeDeoffloadMode : int { AUTO, OFF };

    struct Daemon {
        std::optional<std::string> cache_dir;
        std::optional<bool> clear_dynamic_sets_on_apply;
        std::optional<DaemonConfigFirewallBackend> firewall_backend;
        std::optional<int64_t> firewall_verify_max_bytes;
        std::optional<int64_t> ipset_hashsize;
        std::optional<int64_t> ipset_maxelem;
        std::optional<bool> ipv6_enabled;
        std::optional<int64_t> max_file_size_bytes;
        std::optional<MetaUdp443Policy> meta_udp443_policy;
        std::optional<std::string> pid_file;
        std::optional<PpeDeoffloadMode> ppe_deoffload_mode;
        std::optional<bool> ppe_deoffload_quic_enabled;
        std::optional<std::vector<std::string>> reconnect_owned_flows_on_routing_change_lists;
        std::optional<bool> reconnect_unmarked_flows_on_routing_change;
        std::optional<bool> reuse_static_sets_on_runtime_refresh;
        std::optional<bool> skip_marked_packets;
        std::optional<bool> strict_enforcement;
        std::optional<bool> ttl_bypass_enabled;
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

    struct TunnelProbe {
        std::optional<bool> enabled;
        std::optional<int64_t> interval_ms;
        std::optional<std::string> list;
        std::optional<int64_t> max_probes_per_pass;
        std::optional<std::string> outbound;
        std::optional<bool> require_registry_confirmation;
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
        std::optional<TunnelProbe> tunnel_probe;
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

    struct ConnectionEntry {
        std::optional<bool> active;
        std::optional<std::string> destination;
        std::optional<std::vector<std::string>> destination_domains;
        std::optional<int64_t> destination_port;
        std::optional<std::string> device;
        std::optional<int64_t> first_seen;
        std::optional<std::string> id;
        std::optional<int64_t> last_seen;
        std::optional<int64_t> mark;
        std::optional<std::string> protocol;
        std::optional<std::string> route;
        std::optional<std::string> source;
        std::optional<int64_t> source_port;
        std::optional<std::string> state;
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

    struct GeoLocation {
        std::optional<int64_t> checked_at;
        std::optional<std::string> country;
        std::optional<std::string> country_code;
        std::optional<std::string> emoji;
    };

    struct GeoLookupRequest {
        std::optional<bool> allow_external_lookup;
        std::optional<std::vector<std::string>> hosts;
    };

    enum class GeoLookupResultError : int { INVALID_REQUEST };

    struct GeoLookupResult {
        std::optional<GeoLookupResultError> error;
        std::optional<std::map<std::string, GeoLocation>> locations;
        std::optional<bool> pending;
    };

    struct GrantedResponse {
        std::optional<int64_t> expires_in_seconds;
        bool granted = false;
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

    enum class CatalogStatus : int { FRESH, STALE, UNAVAILABLE };

    struct InterfaceNames {
        bool available = false;
        CatalogStatus catalog_status;
        std::map<std::string, std::string> names;
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

    enum class LogLevel : int { DEBUG, ERROR, INFO, VERBOSE, WARN };

    struct LogSettings {
        bool file_enabled = false;
        LogLevel level;
    };

    struct LogSettingsRequest {
        std::optional<bool> file_enabled;
        std::optional<LogLevel> level;
    };

    struct LogSettingsResult {
        std::optional<bool> durable;
        std::optional<std::string> error;
        std::optional<bool> ok;
        std::optional<LogSettings> settings;
        std::optional<std::string> warning;
    };

    struct LogTail {
        bool exists = false;
        std::optional<std::map<std::string, nlohmann::json>> last_command_failure;
        std::vector<std::string> lines;
        std::string path;
        int64_t size_bytes = 0;
    };

    enum class NaiveComponentInstallResultError : int { INSTALL_FAILED, SCRIPT_MISSING };

    struct NaiveComponentInstallResult {
        std::optional<NaiveComponentInstallResultError> error;
        bool installed = false;
        std::optional<std::string> log;
        std::optional<int64_t> size;
    };

    struct NaiveComponentState {
        bool installed = false;
        std::string path;
        int64_t size = 0;
    };

    struct NdmsInterfaceCapabilities {
        bool backup_required = false;
        bool can_delete = false;
        bool can_edit = false;
        bool can_hide = false;
    };

    enum class NdmsTunnelKindEnum : int { AMNEZIA_WIREGUARD, HTTPS_PROXY, HTTP_PROXY, IKE, L2_TP, OPENCONNECT, OPENVPN, SOCKS5_PROXY, SSTP, WIREGUARD };

    enum class NdmsManagementBlockerElement : int { AUTOMATIC_BACKUP_UNAVAILABLE, KERNEL_IDENTITY_UNRESOLVED, OPTIMISTIC_REVISION_UNAVAILABLE, OWNERSHIP_UNKNOWN, ROLE_UNKNOWN, TYPED_RCI_UNAVAILABLE, UNSUPPORTED_KIND, UNSUPPORTED_ROLE };

    struct NdmsInterfaceManagementReadiness {
        std::vector<NdmsManagementBlockerElement> blockers;
        bool candidate = false;
        bool configuration_snapshot_available = false;
        bool identity_stable = false;
        std::string observed_revision;
    };

    enum class NdmsNativeInventoryDeferredDeleteCheckElement : int { DIRECT_NDMS_STATE, ENCRYPTED_SNAPSHOT, KEEN_PBR_DEPENDENCIES };

    enum class NdmsNativeInventoryDeleteBlockerElement : int { CATALOG_NOT_FRESH, DELETE_JOURNAL_UNSAFE, DELETE_RECOVERY_REQUIRED, IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN, IMPORT_JOURNAL_UNAVAILABLE, IMPORT_JOURNAL_UNSAFE, IMPORT_RECOVERY_REQUIRED, INVALID_OR_PROTECTED_TARGET, OWNERSHIP_ABSENT, OWNERSHIP_INVENTORY_UNAVAILABLE, OWNERSHIP_KIND_MISMATCH, OWNERSHIP_NOT_ACTIVE, UNSUPPORTED_KIND };

    enum class OwnershipLifecycle : int { ACTIVE_RUNNING_ONLY, ACTIVE_SAVE_ACKNOWLEDGED_UNVERIFIED, DELETED_SAVE_ACKNOWLEDGED_UNVERIFIED };

    enum class OwnershipState : int { FOREIGN, NOT_APPLICABLE, PANEL_OWNED_ACTIVE, PANEL_OWNED_TOMBSTONE, UNAVAILABLE };

    struct NativeMutation {
        std::vector<NdmsNativeInventoryDeferredDeleteCheckElement> deferred_authoritative_checks;
        std::vector<NdmsNativeInventoryDeleteBlockerElement> delete_blockers;
        bool delete_candidate = false;
        std::optional<OwnershipLifecycle> ownership_lifecycle;
        std::optional<std::string> ownership_revision;
        OwnershipState ownership_state;
    };

    enum class Owner : int { KEENETIC };

    enum class NdmsInterfaceRoleEnum : int { CLIENT, SERVER, UNKNOWN };

    struct NdmsTunnelInterfaceElement {
        NdmsInterfaceCapabilities capabilities;
        std::optional<bool> connected;
        std::string firmware_interface_name;
        std::string firmware_type;
        std::string id;
        bool internal_vpn_server_candidate = false;
        bool internal_vpn_server_role_confirmation_required = false;
        std::optional<std::string> kernel_name;
        NdmsTunnelKindEnum kind;
        std::string label;
        std::optional<bool> link;
        NdmsInterfaceManagementReadiness management_readiness;
        NativeMutation native_mutation;
        Owner owner;
        NdmsInterfaceRoleEnum role;
    };

    enum class MutationMode : int { DISABLED };

    enum class NdmsNativeImportTargetPrefix : int { WIREGUARD };

    struct NdmsNativeImportTargetRange {
        int64_t first_index = 0;
        int64_t last_index = 0;
        NdmsNativeImportTargetPrefix prefix;
    };

    enum class NdmsNativeImportBlocker : int { ALLOCATOR_RANGE_UNFENCED, RECONCILE_BARRIER_NOT_INTEGRATED, RECOVERY_JOURNAL_NOT_INTEGRATED, WRITER_DISABLED };

    enum class NdmsNativeImportJournalState : int { CLEAN, CLEAN_NEVER_ACTIVATED, DORMANT, RECOVERY_REQUIRED, UNAVAILABLE, UNSAFE };

    enum class NdmsNativeImportReconcileBarrierState : int { DORMANT };

    struct NdmsNativeImportReadiness {
        NdmsNativeImportTargetRange allocator_range;
        bool apply_available = false;
        std::vector<NdmsNativeImportBlocker> blockers;
        NdmsNativeImportTargetRange eligible_returned_targets;
        NdmsNativeImportJournalState journal_state;
        std::string operation;
        bool preview_only = false;
        std::vector<NdmsNativeImportTargetRange> protected_targets;
        NdmsNativeImportReconcileBarrierState reconcile_barrier_state;
        std::string request_name;
    };

    enum class ObservedDeleteJournalState : int { CLEAN, RECOVERY_REQUIRED, UNAVAILABLE, UNSAFE };

    struct NativeMutationStatus {
        bool advisory = false;
        ObservedDeleteJournalState observed_delete_journal_state;
        NdmsNativeImportJournalState observed_import_journal_state;
        bool ownership_inventory_available = false;
    };

    enum class RequiredGuard : int { AUTOMATIC_BACKUP, OPTIMISTIC_REVISION, OWNERSHIP_CHECK, TYPED_RCI };

    enum class NdmsNativeRetainedDeletionDeferredCheckElement : int { ENCRYPTED_SNAPSHOT_OR_ABSENCE, FRESH_DUAL_SCOPE_ABSENCE, KEEN_PBR_DEPENDENCIES, RETAINED_KERNEL_INTERFACE_ABSENCE };

    enum class NdmsNativeRetainedDeletionBlockerElement : int { CATALOG_NOT_FRESH, DELETE_JOURNAL_UNSAFE, DELETE_RECOVERY_REQUIRED, IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN, IMPORT_JOURNAL_UNAVAILABLE, IMPORT_JOURNAL_UNSAFE, IMPORT_RECOVERY_REQUIRED, OWNERSHIP_SCHEMA_NOT_FORGET_CAPABLE, TARGET_PRESENT };

    struct NdmsNativeRetainedDeletionElement {
        std::vector<NdmsNativeRetainedDeletionDeferredCheckElement> deferred_authoritative_checks;
        std::vector<NdmsNativeRetainedDeletionBlockerElement> forget_blockers;
        bool forget_candidate = false;
        std::string interface_name;
        std::string ownership_revision;
    };

    struct NdmsInterfaceInventoryResponse {
        bool available = false;
        CatalogStatus catalog_status;
        std::vector<NdmsTunnelInterfaceElement> interfaces;
        MutationMode mutation_mode;
        NdmsNativeImportReadiness native_import_readiness;
        NativeMutationStatus native_mutation_status;
        bool read_only = false;
        std::vector<RequiredGuard> required_guards;
        std::vector<NdmsNativeRetainedDeletionElement> retained_deletions;
    };

    enum class NdmsNativeDeletePhase : int { CLEANUP, DELETE_MAY_BE_INFLIGHT, PREPARED, RUNNING_ABSENCE_VERIFIED, SAVE_ACKNOWLEDGED_UNVERIFIED, SAVE_MAY_BE_INFLIGHT };

    struct NdmsNativeDeleteRequest {
        std::string confirm_label;
        std::string expected_ownership_revision;
        std::string interface_name;
    };

    enum class NdmsNativeMutationKind : int { AMNEZIA_WIREGUARD, WIREGUARD };

    enum class NdmsNativeDirectObservationFailure : int { AMBIGUOUS_MARKER, CATALOG_MALFORMED, CATALOG_UNAVAILABLE, CATALOG_UNSAFE, DUPLICATE_JSON_KEY, EMPTY_RESPONSE, INVALID_MARKER, INVALID_TARGET, MALFORMED_JSON, MARKER_TARGET_NOT_MANAGED_WIREGUARD, NONE, RCI_ERROR_RESPONSE, RESPONSE_NOT_OBJECT, RESPONSE_TOO_LARGE, TARGET_EVIDENCE_REFUSED, TRANSPORT_FAILED };

    enum class NdmsNativeDeleteStatus : int { BLOCKED, RECOVERY_REQUIRED, SAVE_ACKNOWLEDGED_UNVERIFIED };

    enum class NdmsNativeDeleteStop : int { DELETE_GUARD_REJECTED, DELETE_TRANSPORT_AMBIGUOUS, DELETE_WAL_CLEANUP_FAILED, DELETE_WAL_PUBLISH_FAILED, DELETE_WAL_UNFINISHED, DELETE_WAL_UNSAFE, DURABLE_OBSERVATION_FAILED, EXTERNAL_WRITER_RACE_NOT_ACCEPTED, IMPORT_WAL_NOT_AUTHORITATIVELY_CLEAN, INVALID_OR_PROTECTED_TARGET, KEEN_PBR_DEPENDENCIES_PRESENT, KEEN_PBR_DEPENDENCY_CHANGED, KEEN_PBR_DEPENDENCY_SCAN_INCOMPLETE, NONE, NO_DELETE_TRANSACTION, OBSERVATION_SCOPE_MISMATCH, OBSERVED_TARGET_DRIFTED, OBSERVED_TARGET_MISMATCH, OBSERVED_TARGET_REAPPEARED_AFTER_SAVE, OWNERSHIP_ABSENT, OWNERSHIP_CHANGED, OWNERSHIP_NOT_ACTIVE, OWNERSHIP_UNREADABLE, OWNER_GLOBAL_SAVE_NOT_ACKNOWLEDGED, RUNNING_CONFIG_OBSERVATION_FAILED, RUNTIME_OBSERVATION_FAILED, SAVE_GUARD_REJECTED, SAVE_RECONFIRMATION_REQUIRED, SAVE_TRANSPORT_AMBIGUOUS, SNAPSHOT_ABSENT, SNAPSHOT_MISMATCH, SNAPSHOT_UNREADABLE, TOMBSTONE_MISMATCH, TOMBSTONE_PUBLISH_FAILED, UNEXPECTED_FAILURE, WRITER_LOST, WRITER_MISSING };

    enum class NdmsNativeDeleteTransportOutcome : int { ACKNOWLEDGED_NEEDS_OBSERVATION, BODY_EMPTY, BODY_TOO_LARGE, CONTENT_TYPE_NOT_JSON, GUARD_REJECTED, HTTP_STATUS_NOT_200, SHAPE_NOT_ACKNOWLEDGED, TRANSPORT_FAILED };

    struct NdmsNativeDeleteResponse {
        bool delete_perform_started = false;
        bool external_writer_race_accepted = false;
        bool external_writer_race_excluded = false;
        bool global_save_scope_acknowledged = false;
        std::optional<std::string> interface_name;
        std::optional<NdmsNativeMutationKind> kind;
        std::optional<NdmsNativeDirectObservationFailure> observation_failure;
        bool ownership_tombstone_durable = false;
        std::optional<NdmsNativeDeletePhase> phase;
        bool request_may_have_been_dispatched = false;
        bool rollback_snapshot_retained = false;
        bool save_perform_started = false;
        NdmsNativeDeleteStatus status;
        NdmsNativeDeleteStop stop;
        bool system_configuration_save_acknowledged = false;
        std::optional<NdmsNativeDeleteTransportOutcome> transport_outcome;
    };

    struct NdmsNativeImportPreflightResponse {
        bool admitted = false;
        bool external_ndms_writer_race_excluded = false;
        bool owner_risk_acceptance_required = false;
    };

    enum class NdmsNativeImportRecoveryAction : int { ABORT_WITHOUT_MUTATION, BLOCK_UNKNOWN, COMPLETE_ROLLBACK, RESUME_FORWARD_RECONCILE, RETRY_EXACT_OWNED_DELETE, RETRY_READ_ONLY_OBSERVATION, ROLLBACK_DELETE_EXACT_OWNED };

    enum class NdmsNativeImportRecoveryAdmissionState : int { ACTION_NOT_ACTIONABLE, ADMITTED, INVENTORY_NOT_READY, LEASE_BUSY, LEASE_IO_ERROR, RECORD_CHANGED, RECORD_MISSING };

    enum class NdmsNativeImportRecoveryDispatchState : int { COMPLETED, LEASE_NOT_HELD, OWNERSHIP_STORE_MISSING, PLAN_EMPTY, SNAPSHOT_RETIRER_MISSING, STEP_FAILED, TARGET_MISSING, TARGET_NOT_ELIGIBLE };

    enum class NdmsNativeImportRecoveryPhase : int { ABSENCE_VERIFIED, DELETE_MAY_BE_INFLIGHT, IMPORT_MAY_BE_INFLIGHT, OWNERSHIP_PUBLISHED, PREPARED, RESPONSE_RECORDED, ROLLBACK_REQUESTED, TARGET_VERIFIED };

    enum class NdmsNativeWalReadiness : int { CLEAN, UNFINISHED, UNSAFE };

    enum class NdmsNativeImportRecoveryStep : int { ADVANCE_WAL_ABSENCE_VERIFIED, ADVANCE_WAL_DELETE_MAY_BE_INFLIGHT, ADVANCE_WAL_OWNERSHIP_PUBLISHED, ADVANCE_WAL_ROLLBACK_REQUESTED, ADVANCE_WAL_TARGET_VERIFIED, DELETE_EXACT_OWNED_TARGET, PUBLISH_OWNERSHIP, REMOVE_OWNERSHIP_CLAIM, REMOVE_WAL_RECORD };

    enum class NdmsNativeImportRecoveryStatus : int { BLOCKED, COMPLETED, NO_WORK, RECOVERY_REQUIRED };

    enum class NdmsNativeImportRecoveryStop : int { ABSENCE_WAL_PUBLISH_FAILED, DELETE_GUARD_REJECTED, DELETE_TRANSPORT_AMBIGUOUS, DELETE_WAL_NOT_CLEAN, DELETE_WAL_PUBLISH_FAILED, DURABLE_OBSERVATION_FAILED, EXPECTED_TARGET_NOT_MANAGED, EXTERNAL_WRITER_RACE_NOT_ACCEPTED, FIRST_OBSERVATION_FAILED, FORWARD_ADMISSION_FAILED, IMPORT_WAL_NOT_SINGLE_SAFE, NONE, OBSERVATION_KIND_MISMATCH, OBSERVATION_UNSTABLE, OWNERSHIP_NOT_EXACT, OWNERSHIP_PUBLISH_FAILED, OWNERSHIP_RETRACT_FAILED, OWNERSHIP_WAL_PUBLISH_FAILED, PHASE_NOT_FORWARD_ONLY, RECORD_NOT_COOPERATIVE, RECOVERY_ACTION_NOT_ACTIONABLE, RECOVERY_ACTION_NOT_FORWARD_ONLY, RECOVERY_ADMISSION_FAILED, ROLLBACK_WAL_PUBLISH_FAILED, SECOND_OBSERVATION_FAILED, SNAPSHOT_NOT_EXACT, SNAPSHOT_RETIREMENT_FAILED, TARGET_VERIFIED_WAL_PUBLISH_FAILED, UNEXPECTED_FAILURE, WAL_CLEANUP_FAILED, WRITER_LOST, WRITER_MISSING };

    struct NdmsNativeImportRecoveryResponse {
        std::optional<std::string> created_interface;
        std::optional<std::string> created_kernel_interface;
        bool delete_perform_started = false;
        std::optional<NdmsNativeDeleteTransportOutcome> delete_transport_outcome;
        std::optional<NdmsNativeWalReadiness> delete_wal_readiness;
        std::optional<NdmsNativeDirectObservationFailure> direct_observation_failure;
        std::optional<std::string> expected_interface;
        bool external_ndms_writer_race_accepted = false;
        bool external_ndms_writer_race_excluded = false;
        std::optional<NdmsNativeImportRecoveryAdmissionState> forward_admission_state;
        std::optional<NdmsNativeImportRecoveryDispatchState> forward_dispatch_state;
        std::optional<NdmsNativeImportRecoveryStep> forward_failed_step;
        std::optional<NdmsNativeWalReadiness> import_wal_readiness;
        std::optional<NdmsNativeMutationKind> kind;
        bool ndms_delete_dispatched = false;
        bool ndms_import_request_dispatched = false;
        bool ownership_published = false;
        std::optional<NdmsNativeImportRecoveryPhase> phase;
        std::optional<NdmsNativeImportRecoveryAction> recovery_action;
        std::optional<NdmsNativeImportRecoveryAdmissionState> recovery_admission_state;
        std::optional<NdmsNativeImportRecoveryDispatchState> recovery_dispatch_state;
        std::optional<NdmsNativeImportRecoveryStep> recovery_failed_step;
        bool request_may_have_been_dispatched = false;
        bool rollback_snapshot_retired = false;
        NdmsNativeImportRecoveryStatus status;
        NdmsNativeImportRecoveryStop stop;
        bool system_configuration_save_performed = false;
        bool wal_may_require_recovery = false;
        bool wal_removed = false;
    };

    enum class RequestError : int { DANGEROUS_DIRECTIVE, DUPLICATE_FIELD, DUPLICATE_PEER, DUPLICATE_SECTION, INPUT_TOO_LARGE, INVALID_BASE64, INVALID_COMPRESSION, INVALID_ENCODING, INVALID_FIELD, INVALID_JSON, LIMIT_EXCEEDED, MALFORMED_LINE, MISSING_REQUIRED_FIELD, UNKNOWN_FIELD, UNKNOWN_SECTION, UNSUPPORTED_JSON_SCHEMA, UNSUPPORTED_URI };

    enum class NdmsNativeImportStatus : int { BLOCKED, COMPLETED, RECOVERY_REQUIRED };

    enum class NdmsNativeImportStop : int { COOPERATIVE_BASELINE_FAILED, COOPERATIVE_WRITER_ADMISSION_FAILED, DELETE_WAL_NOT_CLEAN, DURABLE_OBSERVATION_FAILED, EXECUTOR_BLOCKED, EXTERNAL_WRITER_RACE_NOT_ACCEPTED, FIRST_FREE_TARGET_NOT_MANAGED, FIRST_POST_OBSERVATION_FAILED, FORWARD_ADMISSION_FAILED, FORWARD_COMPLETION_BLOCKED, IMPORT_WAL_NOT_CLEAN, MARKER_COLLISION, NONE, OWNERSHIP_PUBLISH_FAILED, OWNERSHIP_TARGET_NOT_AVAILABLE, OWNERSHIP_WAL_PUBLISH_FAILED, POST_OBSERVATION_KIND_MISMATCH, POST_OBSERVATION_UNSTABLE, PREWRITE_CATALOG_DIVERGED, PREWRITE_CATALOG_UNSAFE, REQUEST_INVALID, RUNNING_CONFIG_CATALOG_FAILED, RUNTIME_CATALOG_FAILED, SECOND_POST_OBSERVATION_FAILED, SNAPSHOT_TARGET_NOT_AVAILABLE, TARGET_VERIFIED_WAL_PUBLISH_FAILED, UNEXPECTED_FAILURE, WAL_CLEANUP_FAILED, WAL_RECORD_UNAVAILABLE, WRITER_LOST, WRITER_MISSING };

    struct NdmsNativeImportResponse {
        std::optional<std::string> baseline_error;
        std::optional<std::string> created_interface;
        std::optional<std::string> created_kernel_interface;
        std::optional<NdmsNativeWalReadiness> delete_wal_readiness;
        std::optional<NdmsNativeDirectObservationFailure> direct_observation_failure;
        std::optional<std::string> executor_stop;
        std::optional<std::string> expected_interface;
        bool external_ndms_writer_race_accepted = false;
        bool external_ndms_writer_race_excluded = false;
        std::optional<NdmsNativeImportRecoveryAdmissionState> forward_admission_state;
        std::optional<NdmsNativeImportRecoveryDispatchState> forward_dispatch_state;
        std::optional<NdmsNativeImportRecoveryStep> forward_failed_step;
        std::optional<NdmsNativeWalReadiness> import_wal_readiness;
        std::optional<NdmsNativeMutationKind> kind;
        bool ownership_published = false;
        std::optional<RequestError> request_error;
        bool request_may_have_been_dispatched = false;
        bool rollback_snapshot_may_be_retained = false;
        NdmsNativeImportStatus status;
        NdmsNativeImportStop stop;
        bool system_configuration_save_performed = false;
        bool wal_may_require_recovery = false;
    };

    enum class NdmsNativeTombstoneForgetArtifactState : int { ABSENT_DURABLE, RETAINED, UNKNOWN };

    enum class ForeignReappearanceAcknowledgement : int { ACCEPTED_REAPPEARANCE_IS_FOREIGN };

    enum class RollbackDiscardAcknowledgement : int { PERMANENTLY_DISCARD_ROLLBACK_DATA };

    struct NdmsNativeTombstoneForgetRequest {
        std::string confirm_interface_name;
        std::string expected_ownership_revision;
        ForeignReappearanceAcknowledgement foreign_reappearance_acknowledgement;
        std::string interface_name;
        RollbackDiscardAcknowledgement rollback_discard_acknowledgement;
    };

    enum class NdmsNativeTombstoneForgetStatus : int { BLOCKED, FORGOTTEN, RECOVERY_REQUIRED };

    enum class NdmsNativeTombstoneForgetStop : int { DELETE_WAL_UNFINISHED, DELETE_WAL_UNSAFE, IMPORT_WAL_NOT_AUTHORITATIVELY_CLEAN, KEEN_PBR_DEPENDENCIES_PRESENT, KEEN_PBR_DEPENDENCY_SCAN_INCOMPLETE, KERNEL_INVENTORY_UNAVAILABLE, NONE, OBSERVATION_SCOPE_MISMATCH, OBSERVED_CATALOG_UNSAFE, OBSERVED_MARKER_PRESENT, OBSERVED_TARGET_PRESENT, OWNERSHIP_ABSENT, OWNERSHIP_CHANGED, OWNERSHIP_NOT_FORGET_CAPABLE, OWNERSHIP_UNREADABLE, RETAINED_KERNEL_INTERFACE_PRESENT, RUNNING_CONFIG_OBSERVATION_FAILED, RUNTIME_OBSERVATION_FAILED, SNAPSHOT_MISMATCH, SNAPSHOT_RETIREMENT_FAILED, SNAPSHOT_UNREADABLE, TOMBSTONE_RETIREMENT_FAILED, UNEXPECTED_FAILURE, WRITER_LOST, WRITER_MISSING };

    struct NdmsNativeTombstoneForgetResponse {
        bool future_reappearance_is_foreign = false;
        std::string interface_name;
        bool router_mutation_attempted = false;
        NdmsNativeTombstoneForgetArtifactState snapshot_state;
        NdmsNativeTombstoneForgetStatus status;
        NdmsNativeTombstoneForgetStop stop;
        bool system_configuration_save_acknowledged = false;
        NdmsNativeTombstoneForgetArtifactState tombstone_state;
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
        CatalogStatus catalog_status;
        bool read_only = false;
        std::vector<NdmsVpnServerService> services;
    };

    enum class NfqwsActionRequestAction : int { APPLY_STRATEGY, CAPTURE_RESTORE_POINT, CHECK_UPDATE, CHECK_URL, CLEAR_LOG, CREATE_FILE, DELETE_FILE, DELETE_STRATEGY, IMPORT_BUNDLE, IMPORT_LISTS, INSTALL, READ_FILE, RESTORE_COMPONENT, SAVE_FILE, SAVE_FILES, SAVE_STRATEGY, SERVICE, UPGRADE };

    enum class NfqwsActionRequestCategory : int { CONFIG, LIST, LOG, LUA };

    enum class Command : int { RELOAD, RESTART, START, STOP };

    enum class NfqwsFileEntryCategory : int { LIST, LUA };

    struct NfqwsFileEntryElement {
        NfqwsFileEntryCategory category;
        std::string content;
        std::string name;
    };

    using Files = std::variant<std::vector<NfqwsFileEntryElement>, std::map<std::string, nlohmann::json>>;

    struct NfqwsActionRequest {
        NfqwsActionRequestAction action;
        std::optional<NfqwsActionRequestCategory> category;
        std::optional<Command> command;
        std::optional<std::string> content;
        std::optional<Files> files;
        std::optional<bool> force;
        std::optional<std::string> name;
        std::optional<bool> restart;
        std::optional<std::string> url;
    };

    struct NfqwsActionResult {
        std::optional<int64_t> captured;
        std::optional<std::string> content;
        std::optional<bool> durable;
        std::optional<std::string> error;
        std::optional<bool> exact_package_state;
        std::optional<int64_t> failed;
        std::optional<bool> files_restored;
        std::optional<bool> firewall_reconcile_pending;
        std::optional<int64_t> installed_blobs;
        std::optional<bool> journal_retained;
        std::optional<bool> ok;
        std::optional<std::string> output;
        std::optional<bool> package_metadata_verified;
        std::optional<int64_t> preserved_blobs;
        std::optional<bool> reachable;
        std::optional<std::string> restore_point;
        std::optional<int64_t> restored;
        std::optional<bool> runtime_verified;
        std::optional<int64_t> status;
        std::optional<std::string> warning;
    };

    struct NfqwsStatus {
        std::optional<std::map<std::string, nlohmann::json>> active_strategy;
        std::optional<std::vector<std::map<std::string, nlohmann::json>>> files;
        bool installed = false;
        std::optional<bool> package_metadata_verified;
        bool process_running = false;
        bool queue_active = false;
        std::optional<std::map<std::string, nlohmann::json>> restore_capability;
        std::optional<std::string> restore_point;
        std::optional<std::map<std::string, nlohmann::json>> rotator_state;
        bool running = false;
        std::optional<std::vector<std::map<std::string, nlohmann::json>>> strategies;
        std::optional<std::string> transaction_state;
        std::optional<std::map<std::string, nlohmann::json>> upgrade_capability;
        std::optional<std::string> version;
    };

    struct OkResponse {
        bool ok = false;
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

    enum class PpeDeoffloadCapability : int { SUPPORTED, UNKNOWN, UNSUPPORTED };

    struct PpeDeoffloadCounter {
        std::optional<int64_t> bytes;
        std::optional<int64_t> packets;
    };

    struct PpeDeoffloadProtocolHealth {
        bool active = false;
        std::vector<std::string> applied_ports;
        std::optional<PpeDeoffloadCounter> counters;
        std::vector<std::string> desired_ports;
    };

    enum class PpeDeoffloadHealthState : int { ACTIVE, ADMISSIBLE, DEGRADED, INACTIVE, OFF, UNKNOWN };

    struct PpeDeoffloadHealth {
        PpeDeoffloadCapability capability;
        std::optional<int64_t> connskip_packets;
        std::optional<std::string> detail;
        std::optional<PpeDeoffloadCounter> forward;
        std::optional<int64_t> last_reconcile_ts;
        PpeDeoffloadMode mode;
        std::optional<int64_t> observed_at;
        std::optional<PpeDeoffloadCounter> prerouting;
        PpeDeoffloadProtocolHealth quic;
        std::optional<std::string> reason;
        PpeDeoffloadHealthState state;
        PpeDeoffloadProtocolHealth tcp;
    };

    struct RecommendedListSetupRequest {
        std::string base_revision;
        ConfigObject config;
        std::string list_id;
    };

    struct RegistryCheckRequest {
        std::optional<std::string> detour;
        std::string target;
    };

    enum class Reason : int { LOOKUP_FAILED, REGISTRY_LOOKUP_DISABLED, UNREADABLE_RESPONSE };

    struct RegistryCheckResponse {
        std::optional<bool> blocked;
        std::optional<std::vector<std::string>> blocked_subnets;
        std::optional<bool> cached;
        std::optional<std::vector<std::string>> cdn_providers;
        bool checked = false;
        std::optional<std::string> error;
        std::optional<std::vector<std::string>> ips;
        std::optional<std::string> organisation;
        std::optional<Reason> reason;
        std::optional<std::string> rkn_domain;
        std::string service;
        std::optional<std::string> target;
    };

    struct RegistryConsentRequest {
        bool enabled = false;
    };

    struct RegistryConsentResponse {
        bool durable = false;
        bool enabled = false;
    };

    struct ReloadResponse {
        std::string message;
        ConfigUpdateResponseStatus status;
    };

    struct RemoteAccessRequest {
        std::optional<bool> enabled;
        std::optional<int64_t> port;
    };

    struct Settings {
        bool enabled = false;
        int64_t port = 0;
    };

    struct RemoteAccessResult {
        std::optional<bool> degraded;
        std::optional<std::string> detail;
        std::optional<bool> durable;
        std::optional<std::string> error;
        std::optional<int64_t> generation;
        std::optional<std::string> listen;
        std::optional<bool> maintenance;
        std::optional<bool> ok;
        std::optional<bool> pending;
        std::optional<std::string> phase;
        std::optional<bool> recovery_owned;
        std::optional<int64_t> retry_after_ms;
        std::optional<bool> retry_scheduled;
        std::optional<Settings> settings;
        std::optional<int64_t> supported_port;
        std::optional<std::string> warning;
    };

    struct RemoteAccessRuntime {
        std::optional<int64_t> applied_generation;
        std::optional<int64_t> attempt;
        std::optional<int64_t> command_exit_code;
        std::optional<int64_t> desired_generation;
        std::optional<std::string> error;
        std::optional<bool> incident_active;
        std::optional<std::string> interface;
        std::optional<bool> maintenance;
        std::optional<std::string> phase;
        std::optional<bool> recovery_owned;
        std::optional<std::string> state;
    };

    enum class BlockedReason : int { AUTH_STATE_UNAVAILABLE, KEENETIC_AUTH_PLAINTEXT_WAN, LISTEN_LOOPBACK, LOGIN_DISABLED };

    struct RemoteAccessState {
        std::optional<std::string> auth_provider;
        std::optional<BlockedReason> blocked_reason;
        std::optional<bool> custom_port_supported;
        std::optional<bool> enabled;
        std::optional<int64_t> internal_port;
        std::optional<bool> keenetic_auth_switch_allowed;
        std::optional<std::string> listen;
        std::optional<bool> listen_reachable;
        std::optional<bool> login_required;
        std::optional<int64_t> port;
        std::optional<RemoteAccessRuntime> runtime;
        std::optional<int64_t> supported_port;
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

    struct RouterInfo {
        std::optional<std::string> arch;
        std::optional<int64_t> cpu_load_percent;
        std::optional<std::string> cpu_model;
        std::optional<double> cpu_temperature_c;
        std::optional<int64_t> disk_total_mb;
        std::optional<int64_t> disk_used_mb;
        std::optional<int64_t> disk_used_percent;
        std::optional<std::string> firmware_channel;
        std::optional<std::string> firmware_date;
        std::optional<std::string> firmware_release;
        std::optional<std::string> firmware_title;
        std::optional<std::string> hw_id;
        std::optional<int64_t> memory_total_mb;
        std::optional<int64_t> memory_used_mb;
        std::optional<int64_t> memory_used_percent;
        std::optional<std::string> model;
        std::optional<std::string> region;
        std::optional<int64_t> uptime_seconds;
        std::optional<std::string> vendor;
    };

    enum class RoutingHealthErrorResponseOverall : int { ERROR };

    struct RoutingHealthErrorResponse {
        std::string error;
        RoutingHealthErrorResponseOverall overall;
    };

    enum class RoutingHealthResponseFirewallBackend : int { IPTABLES, NFTABLES };

    enum class RoutingHealthResponseOverall : int { DEGRADED, ERROR, OK };

    enum class SystemAuthState : int { CHALLENGE_ABSENT, ENDPOINT_UNPROVEN, FIRMWARE_POLICY_UNKNOWN, LOCKOUT_BUDGET_UNSAFE, LOOPBACK_NOT_ACCEPTED, USABLE };

    enum class TtlBypassState : int { ACTIVE, CHAIN_ABSENT, CONFLICT, DISABLED, MISSING, UNKNOWN, UNSUPPORTED };

    struct RoutingHealthResponse {
        FirewallChain firewall;
        RoutingHealthResponseFirewallBackend firewall_backend;
        std::vector<FirewallRuleCheck> firewall_rules;
        RoutingHealthResponseOverall overall;
        std::vector<PolicyRuleCheck> policy_rules;
        std::optional<PpeDeoffloadHealth> ppe_deoffload;
        std::vector<RouteTableCheck> route_tables;
        std::optional<std::string> system_auth_detail;
        std::optional<int64_t> system_auth_forwarded_failures_per_window;
        std::optional<SystemAuthState> system_auth_state;
        std::optional<std::string> ttl_bypass_detail;
        std::optional<TtlBypassState> ttl_bypass_state;
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

    enum class RoutingTestNfqwsMatchRole : int { HOSTLIST, HOSTLIST_AUTO, HOSTLIST_EXCLUDE, IPSET, IPSET_EXCLUDE };

    struct RoutingTestNfqwsMatchElement {
        std::string entry;
        bool exact = false;
        bool includes = false;
        std::string list;
        std::string matched;
        RoutingTestNfqwsMatchRole role;
    };

    struct RoutingTestNfqws {
        bool available = false;
        std::vector<RoutingTestNfqwsMatchElement> matches;
        std::optional<std::string> reason;
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
        std::optional<RoutingTestNfqws> nfqws;
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

    enum class Blocker : int { ARCHITECTURE_UNSUPPORTED, ENTWARE_ABSENT, FOREIGN_BINARY_PRESENT, TARGET_NOT_WRITABLE, TRANSPORTS_RUNNING, TRANSPORT_STATE_UNKNOWN };

    enum class SingBoxInstallCapabilityOperation : int { INSTALL, REINSTALL_SAME_VERSION, REPLACE };

    struct SingBoxInstallCapability {
        std::optional<std::string> asset_architecture;
        bool available = false;
        std::vector<Blocker> blockers;
        bool exact_rollback = false;
        std::optional<std::string> installed_version;
        SingBoxInstallCapabilityOperation operation;
        std::string pinned_version;
        std::optional<int64_t> running_transports;
        bool signed_release = false;
        bool verified_archive_checksum = false;
    };

    struct SingBoxInstallRequest {
        std::optional<bool> stop_running_transports;
    };

    enum class InstallOutcome : int { ARCHIVE_UNUSABLE, CANCELLED, CHECKSUM_MISMATCH, DOWNLOAD_FAILED, INSTALLED, INSTALL_FAILED, MARKER_NOT_WRITTEN, RELEASE_REFUSED, STAGED_VERSION_MISMATCH };

    enum class ReleaseVerdict : int { ARCHIVE_MISSING, CHECKSUMS_MISSING, CHECKSUM_MISMATCH, CHECKSUM_UNUSABLE, READY, RELEASE_UNREADABLE };

    struct SingBoxInstallResult {
        std::optional<bool> durable;
        InstallOutcome install_outcome;
        std::string pinned_version;
        std::optional<ReleaseVerdict> release_verdict;
        std::optional<std::string> staged_version;
        std::optional<std::vector<std::string>> stopped_transports;
        std::optional<std::vector<std::string>> transports_left_down;
    };

    enum class SingBoxProcessMode : int { ISOLATED, SHARED };

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

    struct SubscriptionApplySelectionElement {
        int64_t line = 0;
        std::optional<std::string> tag;
    };

    struct SubscriptionApplyRequest {
        std::string preview_id;
        std::vector<SubscriptionApplySelectionElement> selections;
    };

    enum class Outcome : int { ALREADY_IMPORTED, CREATED, FAILED };

    struct SubscriptionApplyResultElement {
        std::optional<std::string> error;
        std::optional<std::string> interface;
        int64_t line = 0;
        Outcome outcome;
        std::optional<std::string> tag;
    };

    struct SubscriptionApplyResponse {
        std::vector<SubscriptionApplyResultElement> results;
    };

    enum class Disposition : int { ALREADY_CONFIGURED, DUPLICATE_IN_DOCUMENT, IMPORTABLE, MALFORMED, SCHEME_NOT_SUPPORTED, TAG_CONFLICT };

    struct SubscriptionPreviewCandidate {
        Disposition disposition;
        std::optional<int64_t> duplicate_of;
        std::optional<std::string> endpoint;
        int64_t line = 0;
        std::optional<std::string> remark;
        std::optional<std::string> scheme;
        std::optional<std::string> suggested_tag;
    };

    struct SubscriptionPreviewRequest {
        std::optional<std::string> document;
        std::optional<std::string> url;
    };

    enum class DocumentKind : int { BASE64_LINK_LIST, EMPTY, JSON_DOCUMENT, LINK_LIST, TOO_LARGE, UNRECOGNIZED };

    struct SubscriptionPreviewResponse {
        std::vector<SubscriptionPreviewCandidate> candidates;
        DocumentKind document_kind;
        int64_t expires_in_seconds = 0;
        std::string preview_id;
    };

    enum class PackageRollbackState : int { AVAILABLE, HELPER_MISSING, NEVER_CAPTURED, PACKAGE_UNVERIFIED, RECOVERY_PENDING, RECOVERY_UNKNOWN, SNAPSHOT_UNVERIFIED };

    struct SystemUpdateLocalStatus {
        std::string log;
        bool package_recovery_pending = false;
        bool package_recovery_unknown = false;
        bool package_rescue_ready = false;
        bool package_rollback_available = false;
        PackageRollbackState package_rollback_state;
        bool running = false;
    };

    struct SystemUpdateStatus {
        std::string log;
        bool package_recovery_pending = false;
        bool package_recovery_unknown = false;
        bool package_rescue_ready = false;
        bool package_rollback_available = false;
        PackageRollbackState package_rollback_state;
        bool running = false;
        bool available = false;
        bool cached = false;
        std::string changelog_url;
        std::string check_error;
        std::string current;
        bool current_ahead = false;
        std::string latest;
        std::string release_name;
        std::string release_notes;
        std::string release_url;
    };

    enum class TransportActionRequestAction : int { DOWN, RESTART, UP };

    struct TransportActionRequest {
        TransportActionRequestAction action;
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

    struct TransportExitCheckProbe {
        std::string address;
        bool attributed = false;
        std::string error;
        int64_t latency_ms = 0;
        bool ok = false;
    };

    struct TransportExitCheckRequest {
        std::optional<std::string> interface;
        std::optional<std::string> outbound;
    };

    enum class ExitAddress : int { CHANGED, SAME, UNKNOWN };

    enum class Verdict : int { UNATTRIBUTED, UNREACHABLE, WORKING };

    struct TransportExitCheckResponse {
        TransportExitCheckProbe direct;
        ExitAddress exit_address;
        std::string outbound;
        TransportExitCheckProbe through;
        Verdict verdict;
    };

    struct TransportManagerSettings {
        bool restart_required = false;
        SingBoxProcessMode running_sing_box_process_mode;
        bool runtime_ready = false;
        SingBoxProcessMode sing_box_process_mode;
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

    struct TransportProcessModeRequest {
        SingBoxProcessMode sing_box_process_mode;
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

    struct TransportsEnvironment {
        std::string pinned_version;
        std::string sing_box_binary;
        bool sing_box_installed = false;
        std::string tested_version;
        int64_t transport_api_version = 0;
    };

    struct UpdateStartedResponse {
        bool ok = false;
        bool started = false;
    };

    struct ApiTypes {
        std::optional<ApiConfig> api_config;
        std::optional<AuthCredentials> auth_credentials;
        std::optional<AuthenticatedResponse> authenticated_response;
        std::optional<AuthSettingsRequest> auth_settings_request;
        std::optional<AuthSettingsResponse> auth_settings_response;
        std::optional<AuthStatus> auth_status;
        std::optional<BackupDocument> backup_document;
        std::optional<Groups> backup_group_selection;
        std::optional<BackupReadRequest> backup_read_request;
        std::optional<BackupRollbackAvailability> backup_rollback_availability;
        std::optional<CacheGeneration> cache_generation;
        std::optional<CacheMetadata> cache_metadata;
        std::optional<CatalogPresetSelection> catalog_preset_selection;
        std::optional<CatalogRefreshRequest> catalog_refresh_request;
        std::optional<CatalogRefreshResult> catalog_refresh_result;
        std::optional<CatalogSetupApplyRequest> catalog_setup_apply_request;
        std::optional<CatalogSetupApplyResponse> catalog_setup_apply_response;
        std::optional<CatalogSetupBlackholeSummary> catalog_setup_blackhole_summary;
        std::optional<CatalogSetupDirectOutboundSummary> catalog_setup_direct_outbound_summary;
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
        std::optional<ConnectionEntry> connection_entry;
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
        std::optional<GeoLocation> geo_location;
        std::optional<GeoLookupRequest> geo_lookup_request;
        std::optional<GeoLookupResult> geo_lookup_result;
        std::optional<GrantedResponse> granted_response;
        std::optional<HealthResponse> health_response;
        std::optional<InterfaceNames> interface_names;
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
        std::optional<LogLevel> log_level;
        std::optional<LogSettings> log_settings;
        std::optional<LogSettingsRequest> log_settings_request;
        std::optional<LogSettingsResult> log_settings_result;
        std::optional<LogTail> log_tail;
        std::optional<NaiveComponentInstallResult> naive_component_install_result;
        std::optional<NaiveComponentState> naive_component_state;
        std::optional<CatalogStatus> ndms_catalog_status;
        std::optional<NdmsInterfaceCapabilities> ndms_interface_capabilities;
        std::optional<NdmsInterfaceInventoryResponse> ndms_interface_inventory_response;
        std::optional<NdmsInterfaceManagementReadiness> ndms_interface_management_readiness;
        std::optional<NdmsInterfaceRoleEnum> ndms_interface_role;
        std::optional<NdmsManagementBlockerElement> ndms_management_blocker;
        std::optional<ObservedDeleteJournalState> ndms_native_delete_journal_state;
        std::optional<NdmsNativeDeletePhase> ndms_native_delete_phase;
        std::optional<NdmsNativeDeleteRequest> ndms_native_delete_request;
        std::optional<NdmsNativeDeleteResponse> ndms_native_delete_response;
        std::optional<NdmsNativeDeleteStatus> ndms_native_delete_status;
        std::optional<NdmsNativeDeleteStop> ndms_native_delete_stop;
        std::optional<NdmsNativeDeleteTransportOutcome> ndms_native_delete_transport_outcome;
        std::optional<NdmsNativeDirectObservationFailure> ndms_native_direct_observation_failure;
        std::optional<NdmsNativeImportPreflightResponse> ndms_native_import_preflight_response;
        std::optional<NdmsNativeImportReadiness> ndms_native_import_readiness;
        std::optional<NdmsNativeImportJournalState> ndms_native_import_readiness_journal_state;
        std::optional<NdmsNativeImportRecoveryAction> ndms_native_import_recovery_action;
        std::optional<NdmsNativeImportRecoveryAdmissionState> ndms_native_import_recovery_admission_state;
        std::optional<NdmsNativeImportRecoveryDispatchState> ndms_native_import_recovery_dispatch_state;
        std::optional<NdmsNativeImportRecoveryPhase> ndms_native_import_recovery_phase;
        std::optional<NdmsNativeImportRecoveryResponse> ndms_native_import_recovery_response;
        std::optional<NdmsNativeImportRecoveryStatus> ndms_native_import_recovery_status;
        std::optional<NdmsNativeImportRecoveryStep> ndms_native_import_recovery_step;
        std::optional<NdmsNativeImportRecoveryStop> ndms_native_import_recovery_stop;
        std::optional<NdmsNativeImportResponse> ndms_native_import_response;
        std::optional<NdmsNativeImportStatus> ndms_native_import_status;
        std::optional<NdmsNativeImportStop> ndms_native_import_stop;
        std::optional<NdmsNativeImportTargetRange> ndms_native_import_target_range;
        std::optional<NativeMutation> ndms_native_interface_mutation_projection;
        std::optional<NdmsNativeInventoryDeferredDeleteCheckElement> ndms_native_inventory_deferred_delete_check;
        std::optional<NdmsNativeInventoryDeleteBlockerElement> ndms_native_inventory_delete_blocker;
        std::optional<OwnershipState> ndms_native_inventory_ownership_state;
        std::optional<std::string> ndms_native_kernel_interface_name;
        std::optional<std::string> ndms_native_managed_interface_name;
        std::optional<NativeMutationStatus> ndms_native_mutation_inventory_status;
        std::optional<NdmsNativeMutationKind> ndms_native_mutation_kind;
        std::optional<OwnershipLifecycle> ndms_native_ownership_lifecycle;
        std::optional<NdmsNativeRetainedDeletionElement> ndms_native_retained_deletion;
        std::optional<NdmsNativeRetainedDeletionBlockerElement> ndms_native_retained_deletion_blocker;
        std::optional<NdmsNativeRetainedDeletionDeferredCheckElement> ndms_native_retained_deletion_deferred_check;
        std::optional<NdmsNativeTombstoneForgetArtifactState> ndms_native_tombstone_forget_artifact_state;
        std::optional<NdmsNativeTombstoneForgetRequest> ndms_native_tombstone_forget_request;
        std::optional<NdmsNativeTombstoneForgetResponse> ndms_native_tombstone_forget_response;
        std::optional<NdmsNativeTombstoneForgetStatus> ndms_native_tombstone_forget_status;
        std::optional<NdmsNativeTombstoneForgetStop> ndms_native_tombstone_forget_stop;
        std::optional<NdmsNativeWalReadiness> ndms_native_wal_readiness;
        std::optional<NdmsTunnelInterfaceElement> ndms_tunnel_interface;
        std::optional<NdmsTunnelKindEnum> ndms_tunnel_kind;
        std::optional<NdmsVpnServerKind> ndms_vpn_server_kind;
        std::optional<NdmsVpnServerService> ndms_vpn_server_service;
        std::optional<NdmsVpnServerServiceInventoryResponse> ndms_vpn_server_service_inventory_response;
        std::optional<NfqwsActionRequest> nfqws_action_request;
        std::optional<NfqwsActionResult> nfqws_action_result;
        std::optional<NfqwsFileEntryElement> nfqws_file_entry;
        std::optional<NfqwsStatus> nfqws_status;
        std::optional<OkResponse> ok_response;
        std::optional<OutboundElement> outbound;
        std::optional<OutboundGroupElement> outbound_group;
        std::optional<PeriodicTaskMetricsEntry> periodic_task_metrics_entry;
        std::optional<PeriodicTaskMetricsResponse> periodic_task_metrics_response;
        std::optional<LastOutcome> periodic_task_outcome;
        std::optional<PlainDnsTemplateElement> plain_dns_template;
        std::optional<PolicyRuleCheck> policy_rule_check;
        std::optional<PpeDeoffloadCapability> ppe_deoffload_capability;
        std::optional<PpeDeoffloadCounter> ppe_deoffload_counter;
        std::optional<PpeDeoffloadHealth> ppe_deoffload_health;
        std::optional<PpeDeoffloadMode> ppe_deoffload_mode;
        std::optional<PpeDeoffloadProtocolHealth> ppe_deoffload_protocol_health;
        std::optional<RecommendedListSetupRequest> recommended_list_setup_request;
        std::optional<RegistryCheckRequest> registry_check_request;
        std::optional<RegistryCheckResponse> registry_check_response;
        std::optional<RegistryConsentRequest> registry_consent_request;
        std::optional<RegistryConsentResponse> registry_consent_response;
        std::optional<ReloadResponse> reload_response;
        std::optional<RemoteAccessRequest> remote_access_request;
        std::optional<RemoteAccessResult> remote_access_result;
        std::optional<RemoteAccessRuntime> remote_access_runtime;
        std::optional<Settings> remote_access_settings;
        std::optional<RemoteAccessState> remote_access_state;
        std::optional<ResolverConfigProbeStatus> resolver_config_probe_status;
        std::optional<ResolverConfigSyncState> resolver_config_sync_state;
        std::optional<Retry> retry_config;
        std::optional<Route> route_config;
        std::optional<RouterInfo> router_info;
        std::optional<RouteRuleElement> route_rule;
        std::optional<RouteTableCheck> route_table_check;
        std::optional<RoutingHealthErrorResponse> routing_health_error_response;
        std::optional<RoutingHealthResponse> routing_health_response;
        std::optional<RoutingTestEntry> routing_test_entry;
        std::optional<Evaluation> routing_test_evaluation;
        std::optional<ListMatch> routing_test_list_match;
        std::optional<RoutingTestNfqws> routing_test_nfqws;
        std::optional<RoutingTestNfqwsMatchElement> routing_test_nfqws_match;
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
        std::optional<SingBoxInstallCapability> sing_box_install_capability;
        std::optional<SingBoxInstallRequest> sing_box_install_request;
        std::optional<SingBoxInstallResult> sing_box_install_result;
        std::optional<SingBoxProcessMode> sing_box_process_mode;
        std::optional<SortOrder> sort_order;
        std::optional<StatusEventConnections> status_event_connections;
        std::optional<StatusEventInterfaces> status_event_interfaces;
        std::optional<StatusEventInterfaceTraffic> status_event_interface_traffic;
        std::optional<StatusEventOutbounds> status_event_outbounds;
        std::optional<StatusEventService> status_event_service;
        std::optional<StatusEventSnapshot> status_event_snapshot;
        std::optional<SubscriptionApplyRequest> subscription_apply_request;
        std::optional<SubscriptionApplyResponse> subscription_apply_response;
        std::optional<SubscriptionApplyResultElement> subscription_apply_result;
        std::optional<SubscriptionApplySelectionElement> subscription_apply_selection;
        std::optional<SubscriptionPreviewCandidate> subscription_preview_candidate;
        std::optional<SubscriptionPreviewRequest> subscription_preview_request;
        std::optional<SubscriptionPreviewResponse> subscription_preview_response;
        std::optional<SystemUpdateLocalStatus> system_update_local_status;
        std::optional<SystemUpdateStatus> system_update_status;
        std::optional<TransportActionRequest> transport_action_request;
        std::optional<TransportActionResponse> transport_action_response;
        std::optional<TransportConfigApplyRequest> transport_config_apply_request;
        std::optional<TransportConfigApplyResponse> transport_config_apply_response;
        std::optional<TransportConfigOperation> transport_config_operation;
        std::optional<TransportConfigResponse> transport_config_response;
        std::optional<TransportExitCheckProbe> transport_exit_check_probe;
        std::optional<TransportExitCheckRequest> transport_exit_check_request;
        std::optional<TransportExitCheckResponse> transport_exit_check_response;
        std::optional<LinkedOutbound> transport_linked_outbound_ensure;
        std::optional<TransportManagerSettings> transport_manager_settings;
        std::optional<TransportPath> transport_path;
        std::optional<TransportProcessModeRequest> transport_process_mode_request;
        std::optional<TransportsEnvironment> transports_environment;
        std::optional<Transport> transport_spec;
        std::optional<TransportStatus> transport_status;
        std::optional<TunnelProbe> tunnel_probe_config;
        std::optional<UiPreferences> ui_preferences_config;
        std::optional<UpdateStartedResponse> update_started_response;
        std::optional<ValidationErrorElement> validation_error;
        std::optional<Vless> vless_reality_spec;
    };
}
}

namespace keen_pbr3 {
namespace api {
void from_json(const json & j, ApiConfig & x);
void to_json(json & j, const ApiConfig & x);

void from_json(const json & j, AuthCredentials & x);
void to_json(json & j, const AuthCredentials & x);

void from_json(const json & j, AuthSettingsRequest & x);
void to_json(json & j, const AuthSettingsRequest & x);

void from_json(const json & j, AuthSettingsResponse & x);
void to_json(json & j, const AuthSettingsResponse & x);

void from_json(const json & j, AuthStatus & x);
void to_json(json & j, const AuthStatus & x);

void from_json(const json & j, AuthenticatedResponse & x);
void to_json(json & j, const AuthenticatedResponse & x);

void from_json(const json & j, Data & x);
void to_json(json & j, const Data & x);

void from_json(const json & j, Groups & x);
void to_json(json & j, const Groups & x);

void from_json(const json & j, BackupDocument & x);
void to_json(json & j, const BackupDocument & x);

void from_json(const json & j, BackupReadRequest & x);
void to_json(json & j, const BackupReadRequest & x);

void from_json(const json & j, BackupRollbackAvailability & x);
void to_json(json & j, const BackupRollbackAvailability & x);

void from_json(const json & j, CacheGeneration & x);
void to_json(json & j, const CacheGeneration & x);

void from_json(const json & j, CacheMetadata & x);
void to_json(json & j, const CacheMetadata & x);

void from_json(const json & j, CatalogPresetSelection & x);
void to_json(json & j, const CatalogPresetSelection & x);

void from_json(const json & j, CatalogRefreshRequest & x);
void to_json(json & j, const CatalogRefreshRequest & x);

void from_json(const json & j, CatalogRefreshResult & x);
void to_json(json & j, const CatalogRefreshResult & x);

void from_json(const json & j, Intent & x);
void to_json(json & j, const Intent & x);

void from_json(const json & j, CatalogSetupApplyRequest & x);
void to_json(json & j, const CatalogSetupApplyRequest & x);

void from_json(const json & j, CatalogSetupApplyResponse & x);
void to_json(json & j, const CatalogSetupApplyResponse & x);

void from_json(const json & j, CatalogSetupBlackholeSummary & x);
void to_json(json & j, const CatalogSetupBlackholeSummary & x);

void from_json(const json & j, CatalogSetupDirectOutboundSummary & x);
void to_json(json & j, const CatalogSetupDirectOutboundSummary & x);

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

void from_json(const json & j, TunnelProbe & x);
void to_json(json & j, const TunnelProbe & x);

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

void from_json(const json & j, ConnectionEntry & x);
void to_json(json & j, const ConnectionEntry & x);

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

void from_json(const json & j, GeoLocation & x);
void to_json(json & j, const GeoLocation & x);

void from_json(const json & j, GeoLookupRequest & x);
void to_json(json & j, const GeoLookupRequest & x);

void from_json(const json & j, GeoLookupResult & x);
void to_json(json & j, const GeoLookupResult & x);

void from_json(const json & j, GrantedResponse & x);
void to_json(json & j, const GrantedResponse & x);

void from_json(const json & j, LifecycleOperationStageElement & x);
void to_json(json & j, const LifecycleOperationStageElement & x);

void from_json(const json & j, LifecycleOperation & x);
void to_json(json & j, const LifecycleOperation & x);

void from_json(const json & j, HealthResponse & x);
void to_json(json & j, const HealthResponse & x);

void from_json(const json & j, InterfaceNames & x);
void to_json(json & j, const InterfaceNames & x);

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

void from_json(const json & j, LogSettings & x);
void to_json(json & j, const LogSettings & x);

void from_json(const json & j, LogSettingsRequest & x);
void to_json(json & j, const LogSettingsRequest & x);

void from_json(const json & j, LogSettingsResult & x);
void to_json(json & j, const LogSettingsResult & x);

void from_json(const json & j, LogTail & x);
void to_json(json & j, const LogTail & x);

void from_json(const json & j, NaiveComponentInstallResult & x);
void to_json(json & j, const NaiveComponentInstallResult & x);

void from_json(const json & j, NaiveComponentState & x);
void to_json(json & j, const NaiveComponentState & x);

void from_json(const json & j, NdmsInterfaceCapabilities & x);
void to_json(json & j, const NdmsInterfaceCapabilities & x);

void from_json(const json & j, NdmsInterfaceManagementReadiness & x);
void to_json(json & j, const NdmsInterfaceManagementReadiness & x);

void from_json(const json & j, NativeMutation & x);
void to_json(json & j, const NativeMutation & x);

void from_json(const json & j, NdmsTunnelInterfaceElement & x);
void to_json(json & j, const NdmsTunnelInterfaceElement & x);

void from_json(const json & j, NdmsNativeImportTargetRange & x);
void to_json(json & j, const NdmsNativeImportTargetRange & x);

void from_json(const json & j, NdmsNativeImportReadiness & x);
void to_json(json & j, const NdmsNativeImportReadiness & x);

void from_json(const json & j, NativeMutationStatus & x);
void to_json(json & j, const NativeMutationStatus & x);

void from_json(const json & j, NdmsNativeRetainedDeletionElement & x);
void to_json(json & j, const NdmsNativeRetainedDeletionElement & x);

void from_json(const json & j, NdmsInterfaceInventoryResponse & x);
void to_json(json & j, const NdmsInterfaceInventoryResponse & x);

void from_json(const json & j, NdmsNativeDeleteRequest & x);
void to_json(json & j, const NdmsNativeDeleteRequest & x);

void from_json(const json & j, NdmsNativeDeleteResponse & x);
void to_json(json & j, const NdmsNativeDeleteResponse & x);

void from_json(const json & j, NdmsNativeImportPreflightResponse & x);
void to_json(json & j, const NdmsNativeImportPreflightResponse & x);

void from_json(const json & j, NdmsNativeImportRecoveryResponse & x);
void to_json(json & j, const NdmsNativeImportRecoveryResponse & x);

void from_json(const json & j, NdmsNativeImportResponse & x);
void to_json(json & j, const NdmsNativeImportResponse & x);

void from_json(const json & j, NdmsNativeTombstoneForgetRequest & x);
void to_json(json & j, const NdmsNativeTombstoneForgetRequest & x);

void from_json(const json & j, NdmsNativeTombstoneForgetResponse & x);
void to_json(json & j, const NdmsNativeTombstoneForgetResponse & x);

void from_json(const json & j, NdmsVpnServerService & x);
void to_json(json & j, const NdmsVpnServerService & x);

void from_json(const json & j, NdmsVpnServerServiceInventoryResponse & x);
void to_json(json & j, const NdmsVpnServerServiceInventoryResponse & x);

void from_json(const json & j, NfqwsFileEntryElement & x);
void to_json(json & j, const NfqwsFileEntryElement & x);

void from_json(const json & j, NfqwsActionRequest & x);
void to_json(json & j, const NfqwsActionRequest & x);

void from_json(const json & j, NfqwsActionResult & x);
void to_json(json & j, const NfqwsActionResult & x);

void from_json(const json & j, NfqwsStatus & x);
void to_json(json & j, const NfqwsStatus & x);

void from_json(const json & j, OkResponse & x);
void to_json(json & j, const OkResponse & x);

void from_json(const json & j, PeriodicTaskMetricsEntry & x);
void to_json(json & j, const PeriodicTaskMetricsEntry & x);

void from_json(const json & j, PeriodicTaskMetricsResponse & x);
void to_json(json & j, const PeriodicTaskMetricsResponse & x);

void from_json(const json & j, PolicyRuleCheck & x);
void to_json(json & j, const PolicyRuleCheck & x);

void from_json(const json & j, PpeDeoffloadCounter & x);
void to_json(json & j, const PpeDeoffloadCounter & x);

void from_json(const json & j, PpeDeoffloadProtocolHealth & x);
void to_json(json & j, const PpeDeoffloadProtocolHealth & x);

void from_json(const json & j, PpeDeoffloadHealth & x);
void to_json(json & j, const PpeDeoffloadHealth & x);

void from_json(const json & j, RecommendedListSetupRequest & x);
void to_json(json & j, const RecommendedListSetupRequest & x);

void from_json(const json & j, RegistryCheckRequest & x);
void to_json(json & j, const RegistryCheckRequest & x);

void from_json(const json & j, RegistryCheckResponse & x);
void to_json(json & j, const RegistryCheckResponse & x);

void from_json(const json & j, RegistryConsentRequest & x);
void to_json(json & j, const RegistryConsentRequest & x);

void from_json(const json & j, RegistryConsentResponse & x);
void to_json(json & j, const RegistryConsentResponse & x);

void from_json(const json & j, ReloadResponse & x);
void to_json(json & j, const ReloadResponse & x);

void from_json(const json & j, RemoteAccessRequest & x);
void to_json(json & j, const RemoteAccessRequest & x);

void from_json(const json & j, Settings & x);
void to_json(json & j, const Settings & x);

void from_json(const json & j, RemoteAccessResult & x);
void to_json(json & j, const RemoteAccessResult & x);

void from_json(const json & j, RemoteAccessRuntime & x);
void to_json(json & j, const RemoteAccessRuntime & x);

void from_json(const json & j, RemoteAccessState & x);
void to_json(json & j, const RemoteAccessState & x);

void from_json(const json & j, RouteTableCheck & x);
void to_json(json & j, const RouteTableCheck & x);

void from_json(const json & j, RouterInfo & x);
void to_json(json & j, const RouterInfo & x);

void from_json(const json & j, RoutingHealthErrorResponse & x);
void to_json(json & j, const RoutingHealthErrorResponse & x);

void from_json(const json & j, RoutingHealthResponse & x);
void to_json(json & j, const RoutingHealthResponse & x);

void from_json(const json & j, ListMatch & x);
void to_json(json & j, const ListMatch & x);

void from_json(const json & j, RoutingTestEntry & x);
void to_json(json & j, const RoutingTestEntry & x);

void from_json(const json & j, RoutingTestNfqwsMatchElement & x);
void to_json(json & j, const RoutingTestNfqwsMatchElement & x);

void from_json(const json & j, RoutingTestNfqws & x);
void to_json(json & j, const RoutingTestNfqws & x);

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

void from_json(const json & j, SingBoxInstallCapability & x);
void to_json(json & j, const SingBoxInstallCapability & x);

void from_json(const json & j, SingBoxInstallRequest & x);
void to_json(json & j, const SingBoxInstallRequest & x);

void from_json(const json & j, SingBoxInstallResult & x);
void to_json(json & j, const SingBoxInstallResult & x);

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

void from_json(const json & j, SubscriptionApplySelectionElement & x);
void to_json(json & j, const SubscriptionApplySelectionElement & x);

void from_json(const json & j, SubscriptionApplyRequest & x);
void to_json(json & j, const SubscriptionApplyRequest & x);

void from_json(const json & j, SubscriptionApplyResultElement & x);
void to_json(json & j, const SubscriptionApplyResultElement & x);

void from_json(const json & j, SubscriptionApplyResponse & x);
void to_json(json & j, const SubscriptionApplyResponse & x);

void from_json(const json & j, SubscriptionPreviewCandidate & x);
void to_json(json & j, const SubscriptionPreviewCandidate & x);

void from_json(const json & j, SubscriptionPreviewRequest & x);
void to_json(json & j, const SubscriptionPreviewRequest & x);

void from_json(const json & j, SubscriptionPreviewResponse & x);
void to_json(json & j, const SubscriptionPreviewResponse & x);

void from_json(const json & j, SystemUpdateLocalStatus & x);
void to_json(json & j, const SystemUpdateLocalStatus & x);

void from_json(const json & j, SystemUpdateStatus & x);
void to_json(json & j, const SystemUpdateStatus & x);

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

void from_json(const json & j, TransportExitCheckProbe & x);
void to_json(json & j, const TransportExitCheckProbe & x);

void from_json(const json & j, TransportExitCheckRequest & x);
void to_json(json & j, const TransportExitCheckRequest & x);

void from_json(const json & j, TransportExitCheckResponse & x);
void to_json(json & j, const TransportExitCheckResponse & x);

void from_json(const json & j, TransportManagerSettings & x);
void to_json(json & j, const TransportManagerSettings & x);

void from_json(const json & j, TransportPath & x);
void to_json(json & j, const TransportPath & x);

void from_json(const json & j, TransportProcessModeRequest & x);
void to_json(json & j, const TransportProcessModeRequest & x);

void from_json(const json & j, TransportStatus & x);
void to_json(json & j, const TransportStatus & x);

void from_json(const json & j, TransportsEnvironment & x);
void to_json(json & j, const TransportsEnvironment & x);

void from_json(const json & j, UpdateStartedResponse & x);
void to_json(json & j, const UpdateStartedResponse & x);

void from_json(const json & j, ApiTypes & x);
void to_json(json & j, const ApiTypes & x);

void from_json(const json & j, KeeneticEndpointSource & x);
void to_json(json & j, const KeeneticEndpointSource & x);

void from_json(const json & j, Format & x);
void to_json(json & j, const Format & x);

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

void from_json(const json & j, PpeDeoffloadMode & x);
void to_json(json & j, const PpeDeoffloadMode & x);

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

void from_json(const json & j, GeoLookupResultError & x);
void to_json(json & j, const GeoLookupResultError & x);

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

void from_json(const json & j, CatalogStatus & x);
void to_json(json & j, const CatalogStatus & x);

void from_json(const json & j, LogLevel & x);
void to_json(json & j, const LogLevel & x);

void from_json(const json & j, NaiveComponentInstallResultError & x);
void to_json(json & j, const NaiveComponentInstallResultError & x);

void from_json(const json & j, NdmsTunnelKindEnum & x);
void to_json(json & j, const NdmsTunnelKindEnum & x);

void from_json(const json & j, NdmsManagementBlockerElement & x);
void to_json(json & j, const NdmsManagementBlockerElement & x);

void from_json(const json & j, NdmsNativeInventoryDeferredDeleteCheckElement & x);
void to_json(json & j, const NdmsNativeInventoryDeferredDeleteCheckElement & x);

void from_json(const json & j, NdmsNativeInventoryDeleteBlockerElement & x);
void to_json(json & j, const NdmsNativeInventoryDeleteBlockerElement & x);

void from_json(const json & j, OwnershipLifecycle & x);
void to_json(json & j, const OwnershipLifecycle & x);

void from_json(const json & j, OwnershipState & x);
void to_json(json & j, const OwnershipState & x);

void from_json(const json & j, Owner & x);
void to_json(json & j, const Owner & x);

void from_json(const json & j, NdmsInterfaceRoleEnum & x);
void to_json(json & j, const NdmsInterfaceRoleEnum & x);

void from_json(const json & j, MutationMode & x);
void to_json(json & j, const MutationMode & x);

void from_json(const json & j, NdmsNativeImportTargetPrefix & x);
void to_json(json & j, const NdmsNativeImportTargetPrefix & x);

void from_json(const json & j, NdmsNativeImportBlocker & x);
void to_json(json & j, const NdmsNativeImportBlocker & x);

void from_json(const json & j, NdmsNativeImportJournalState & x);
void to_json(json & j, const NdmsNativeImportJournalState & x);

void from_json(const json & j, NdmsNativeImportReconcileBarrierState & x);
void to_json(json & j, const NdmsNativeImportReconcileBarrierState & x);

void from_json(const json & j, ObservedDeleteJournalState & x);
void to_json(json & j, const ObservedDeleteJournalState & x);

void from_json(const json & j, RequiredGuard & x);
void to_json(json & j, const RequiredGuard & x);

void from_json(const json & j, NdmsNativeRetainedDeletionDeferredCheckElement & x);
void to_json(json & j, const NdmsNativeRetainedDeletionDeferredCheckElement & x);

void from_json(const json & j, NdmsNativeRetainedDeletionBlockerElement & x);
void to_json(json & j, const NdmsNativeRetainedDeletionBlockerElement & x);

void from_json(const json & j, NdmsNativeDeletePhase & x);
void to_json(json & j, const NdmsNativeDeletePhase & x);

void from_json(const json & j, NdmsNativeMutationKind & x);
void to_json(json & j, const NdmsNativeMutationKind & x);

void from_json(const json & j, NdmsNativeDirectObservationFailure & x);
void to_json(json & j, const NdmsNativeDirectObservationFailure & x);

void from_json(const json & j, NdmsNativeDeleteStatus & x);
void to_json(json & j, const NdmsNativeDeleteStatus & x);

void from_json(const json & j, NdmsNativeDeleteStop & x);
void to_json(json & j, const NdmsNativeDeleteStop & x);

void from_json(const json & j, NdmsNativeDeleteTransportOutcome & x);
void to_json(json & j, const NdmsNativeDeleteTransportOutcome & x);

void from_json(const json & j, NdmsNativeImportRecoveryAction & x);
void to_json(json & j, const NdmsNativeImportRecoveryAction & x);

void from_json(const json & j, NdmsNativeImportRecoveryAdmissionState & x);
void to_json(json & j, const NdmsNativeImportRecoveryAdmissionState & x);

void from_json(const json & j, NdmsNativeImportRecoveryDispatchState & x);
void to_json(json & j, const NdmsNativeImportRecoveryDispatchState & x);

void from_json(const json & j, NdmsNativeImportRecoveryPhase & x);
void to_json(json & j, const NdmsNativeImportRecoveryPhase & x);

void from_json(const json & j, NdmsNativeWalReadiness & x);
void to_json(json & j, const NdmsNativeWalReadiness & x);

void from_json(const json & j, NdmsNativeImportRecoveryStep & x);
void to_json(json & j, const NdmsNativeImportRecoveryStep & x);

void from_json(const json & j, NdmsNativeImportRecoveryStatus & x);
void to_json(json & j, const NdmsNativeImportRecoveryStatus & x);

void from_json(const json & j, NdmsNativeImportRecoveryStop & x);
void to_json(json & j, const NdmsNativeImportRecoveryStop & x);

void from_json(const json & j, RequestError & x);
void to_json(json & j, const RequestError & x);

void from_json(const json & j, NdmsNativeImportStatus & x);
void to_json(json & j, const NdmsNativeImportStatus & x);

void from_json(const json & j, NdmsNativeImportStop & x);
void to_json(json & j, const NdmsNativeImportStop & x);

void from_json(const json & j, NdmsNativeTombstoneForgetArtifactState & x);
void to_json(json & j, const NdmsNativeTombstoneForgetArtifactState & x);

void from_json(const json & j, ForeignReappearanceAcknowledgement & x);
void to_json(json & j, const ForeignReappearanceAcknowledgement & x);

void from_json(const json & j, RollbackDiscardAcknowledgement & x);
void to_json(json & j, const RollbackDiscardAcknowledgement & x);

void from_json(const json & j, NdmsNativeTombstoneForgetStatus & x);
void to_json(json & j, const NdmsNativeTombstoneForgetStatus & x);

void from_json(const json & j, NdmsNativeTombstoneForgetStop & x);
void to_json(json & j, const NdmsNativeTombstoneForgetStop & x);

void from_json(const json & j, NdmsVpnServerKind & x);
void to_json(json & j, const NdmsVpnServerKind & x);

void from_json(const json & j, NfqwsActionRequestAction & x);
void to_json(json & j, const NfqwsActionRequestAction & x);

void from_json(const json & j, NfqwsActionRequestCategory & x);
void to_json(json & j, const NfqwsActionRequestCategory & x);

void from_json(const json & j, Command & x);
void to_json(json & j, const Command & x);

void from_json(const json & j, NfqwsFileEntryCategory & x);
void to_json(json & j, const NfqwsFileEntryCategory & x);

void from_json(const json & j, LastOutcome & x);
void to_json(json & j, const LastOutcome & x);

void from_json(const json & j, PpeDeoffloadCapability & x);
void to_json(json & j, const PpeDeoffloadCapability & x);

void from_json(const json & j, PpeDeoffloadHealthState & x);
void to_json(json & j, const PpeDeoffloadHealthState & x);

void from_json(const json & j, Reason & x);
void to_json(json & j, const Reason & x);

void from_json(const json & j, BlockedReason & x);
void to_json(json & j, const BlockedReason & x);

void from_json(const json & j, RoutingHealthErrorResponseOverall & x);
void to_json(json & j, const RoutingHealthErrorResponseOverall & x);

void from_json(const json & j, RoutingHealthResponseFirewallBackend & x);
void to_json(json & j, const RoutingHealthResponseFirewallBackend & x);

void from_json(const json & j, RoutingHealthResponseOverall & x);
void to_json(json & j, const RoutingHealthResponseOverall & x);

void from_json(const json & j, SystemAuthState & x);
void to_json(json & j, const SystemAuthState & x);

void from_json(const json & j, TtlBypassState & x);
void to_json(json & j, const TtlBypassState & x);

void from_json(const json & j, Evaluation & x);
void to_json(json & j, const Evaluation & x);

void from_json(const json & j, RoutingTestUnknownConditionElement & x);
void to_json(json & j, const RoutingTestUnknownConditionElement & x);

void from_json(const json & j, RoutingTestNfqwsMatchRole & x);
void to_json(json & j, const RoutingTestNfqwsMatchRole & x);

void from_json(const json & j, ConfigScope & x);
void to_json(json & j, const ConfigScope & x);

void from_json(const json & j, LinkUptimeSource & x);
void to_json(json & j, const LinkUptimeSource & x);

void from_json(const json & j, RuntimeInterfaceInventoryStatusEnum & x);
void to_json(json & j, const RuntimeInterfaceInventoryStatusEnum & x);

void from_json(const json & j, RuntimeInterfaceStatusEnum & x);
void to_json(json & j, const RuntimeInterfaceStatusEnum & x);

void from_json(const json & j, Blocker & x);
void to_json(json & j, const Blocker & x);

void from_json(const json & j, SingBoxInstallCapabilityOperation & x);
void to_json(json & j, const SingBoxInstallCapabilityOperation & x);

void from_json(const json & j, InstallOutcome & x);
void to_json(json & j, const InstallOutcome & x);

void from_json(const json & j, ReleaseVerdict & x);
void to_json(json & j, const ReleaseVerdict & x);

void from_json(const json & j, SingBoxProcessMode & x);
void to_json(json & j, const SingBoxProcessMode & x);

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

void from_json(const json & j, Outcome & x);
void to_json(json & j, const Outcome & x);

void from_json(const json & j, Disposition & x);
void to_json(json & j, const Disposition & x);

void from_json(const json & j, DocumentKind & x);
void to_json(json & j, const DocumentKind & x);

void from_json(const json & j, PackageRollbackState & x);
void to_json(json & j, const PackageRollbackState & x);

void from_json(const json & j, TransportActionRequestAction & x);
void to_json(json & j, const TransportActionRequestAction & x);

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

void from_json(const json & j, ExitAddress & x);
void to_json(json & j, const ExitAddress & x);

void from_json(const json & j, Verdict & x);
void to_json(json & j, const Verdict & x);

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
}
}
namespace nlohmann {
template <>
struct adl_serializer<std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>>> {
    static void from_json(const json & j, std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>> & x);
    static void to_json(json & j, const std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>> & x);
};
}
namespace keen_pbr3 {
namespace api {
    inline void from_json(const json & j, ApiConfig& x) {
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.listen = get_stack_optional<std::string>(j, "listen");
    }

    inline void to_json(json & j, const ApiConfig & x) {
        j = json::object();
        j["enabled"] = x.enabled;
        j["listen"] = x.listen;
    }

    inline void from_json(const json & j, AuthCredentials& x) {
        x.password = j.at("password").get<std::string>();
        x.username = j.at("username").get<std::string>();
    }

    inline void to_json(json & j, const AuthCredentials & x) {
        j = json::object();
        j["password"] = x.password;
        j["username"] = x.username;
    }

    inline void from_json(const json & j, AuthSettingsRequest& x) {
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.keenetic_endpoint = get_stack_optional<std::string>(j, "keenetic_endpoint");
        x.password = get_stack_optional<std::string>(j, "password");
        x.provider = j.at("provider").get<std::string>();
        x.username = get_stack_optional<std::string>(j, "username");
    }

    inline void to_json(json & j, const AuthSettingsRequest & x) {
        j = json::object();
        j["enabled"] = x.enabled;
        j["keenetic_endpoint"] = x.keenetic_endpoint;
        j["password"] = x.password;
        j["provider"] = x.provider;
        j["username"] = x.username;
    }

    inline void from_json(const json & j, AuthSettingsResponse& x) {
        x.durable = j.at("durable").get<bool>();
        x.remote_access_generation = get_stack_optional<int64_t>(j, "remote_access_generation");
        x.remote_access_pending = get_stack_optional<bool>(j, "remote_access_pending");
        x.restart_detail = get_stack_optional<std::string>(j, "restart_detail");
        x.restart_required = get_stack_optional<bool>(j, "restart_required");
        x.runtime_auth_enabled = get_stack_optional<bool>(j, "runtime_auth_enabled");
        x.saved = j.at("saved").get<bool>();
        x.warning = get_stack_optional<std::string>(j, "warning");
    }

    inline void to_json(json & j, const AuthSettingsResponse & x) {
        j = json::object();
        j["durable"] = x.durable;
        j["remote_access_generation"] = x.remote_access_generation;
        j["remote_access_pending"] = x.remote_access_pending;
        j["restart_detail"] = x.restart_detail;
        j["restart_required"] = x.restart_required;
        j["runtime_auth_enabled"] = x.runtime_auth_enabled;
        j["saved"] = x.saved;
        j["warning"] = x.warning;
    }

    inline void from_json(const json & j, AuthStatus& x) {
        x.authenticated = j.at("authenticated").get<bool>();
        x.enabled = j.at("enabled").get<bool>();
        x.error = get_stack_optional<std::string>(j, "error");
        x.keenetic_endpoint = get_stack_optional<std::string>(j, "keenetic_endpoint");
        x.keenetic_endpoint_mode = get_stack_optional<std::string>(j, "keenetic_endpoint_mode");
        x.keenetic_endpoint_source = get_stack_optional<KeeneticEndpointSource>(j, "keenetic_endpoint_source");
        x.network_api_blocked = get_stack_optional<bool>(j, "network_api_blocked");
        x.no_auth_scope = get_stack_optional<std::string>(j, "no_auth_scope");
        x.provider = j.at("provider").get<std::string>();
        x.trusted_local_connection = j.at("trusted_local_connection").get<bool>();
        x.trusted_local_connection_generation = get_stack_optional<std::string>(j, "trusted_local_connection_generation");
        x.trusted_local_connection_valid_for_seconds = get_stack_optional<int64_t>(j, "trusted_local_connection_valid_for_seconds");
    }

    inline void to_json(json & j, const AuthStatus & x) {
        j = json::object();
        j["authenticated"] = x.authenticated;
        j["enabled"] = x.enabled;
        j["error"] = x.error;
        j["keenetic_endpoint"] = x.keenetic_endpoint;
        j["keenetic_endpoint_mode"] = x.keenetic_endpoint_mode;
        j["keenetic_endpoint_source"] = x.keenetic_endpoint_source;
        j["network_api_blocked"] = x.network_api_blocked;
        j["no_auth_scope"] = x.no_auth_scope;
        j["provider"] = x.provider;
        j["trusted_local_connection"] = x.trusted_local_connection;
        j["trusted_local_connection_generation"] = x.trusted_local_connection_generation;
        j["trusted_local_connection_valid_for_seconds"] = x.trusted_local_connection_valid_for_seconds;
    }

    inline void from_json(const json & j, AuthenticatedResponse& x) {
        x.authenticated = j.at("authenticated").get<bool>();
    }

    inline void to_json(json & j, const AuthenticatedResponse & x) {
        j = json::object();
        j["authenticated"] = x.authenticated;
    }

    inline void from_json(const json & j, Data& x) {
        x.dns = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "dns");
        x.general = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "general");
        x.lists = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "lists");
        x.nfqws = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "nfqws");
        x.outbounds = get_stack_optional<std::vector<std::map<std::string, nlohmann::json>>>(j, "outbounds");
        x.route = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "route");
        x.transports = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "transports");
    }

    inline void to_json(json & j, const Data & x) {
        j = json::object();
        j["dns"] = x.dns;
        j["general"] = x.general;
        j["lists"] = x.lists;
        j["nfqws"] = x.nfqws;
        j["outbounds"] = x.outbounds;
        j["route"] = x.route;
        j["transports"] = x.transports;
    }

    inline void from_json(const json & j, Groups& x) {
        x.dns = get_stack_optional<bool>(j, "dns");
        x.general = get_stack_optional<bool>(j, "general");
        x.nfqws = get_stack_optional<bool>(j, "nfqws");
        x.nfqws_config = get_stack_optional<bool>(j, "nfqws_config");
        x.nfqws_lists = get_stack_optional<bool>(j, "nfqws_lists");
        x.outbounds = get_stack_optional<bool>(j, "outbounds");
        x.routing = get_stack_optional<bool>(j, "routing");
        x.transports = get_stack_optional<bool>(j, "transports");
    }

    inline void to_json(json & j, const Groups & x) {
        j = json::object();
        j["dns"] = x.dns;
        j["general"] = x.general;
        j["nfqws"] = x.nfqws;
        j["nfqws_config"] = x.nfqws_config;
        j["nfqws_lists"] = x.nfqws_lists;
        j["outbounds"] = x.outbounds;
        j["routing"] = x.routing;
        j["transports"] = x.transports;
    }

    inline void from_json(const json & j, BackupDocument& x) {
        x.created_at = get_stack_optional<int64_t>(j, "created_at");
        x.data = j.at("data").get<Data>();
        x.format = j.at("format").get<Format>();
        x.groups = get_stack_optional<Groups>(j, "groups");
        x.schema = j.at("schema").get<int64_t>();
    }

    inline void to_json(json & j, const BackupDocument & x) {
        j = json::object();
        j["created_at"] = x.created_at;
        j["data"] = x.data;
        j["format"] = x.format;
        j["groups"] = x.groups;
        j["schema"] = x.schema;
    }

    inline void from_json(const json & j, BackupReadRequest& x) {
        x.groups = get_stack_optional<Groups>(j, "groups");
    }

    inline void to_json(json & j, const BackupReadRequest & x) {
        j = json::object();
        j["groups"] = x.groups;
    }

    inline void from_json(const json & j, BackupRollbackAvailability& x) {
        x.available = j.at("available").get<bool>();
    }

    inline void to_json(json & j, const BackupRollbackAvailability & x) {
        j = json::object();
        j["available"] = x.available;
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

    inline void from_json(const json & j, CatalogRefreshRequest& x) {
        x.detour = get_stack_optional<std::string>(j, "detour");
    }

    inline void to_json(json & j, const CatalogRefreshRequest & x) {
        j = json::object();
        j["detour"] = x.detour;
    }

    inline void from_json(const json & j, CatalogRefreshResult& x) {
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.error = get_stack_optional<std::string>(j, "error");
        x.packaged = get_stack_optional<bool>(j, "packaged");
        x.settings_durable = get_stack_optional<bool>(j, "settings_durable");
        x.updated = get_stack_optional<bool>(j, "updated");
        x.warning = get_stack_optional<std::string>(j, "warning");
    }

    inline void to_json(json & j, const CatalogRefreshResult & x) {
        j = json::object();
        j["detour"] = x.detour;
        j["error"] = x.error;
        j["packaged"] = x.packaged;
        j["settings_durable"] = x.settings_durable;
        j["updated"] = x.updated;
        j["warning"] = x.warning;
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

    inline void from_json(const json & j, CatalogSetupDirectOutboundSummary& x) {
        x.created = j.at("created").get<bool>();
        x.tag = j.at("tag").get<std::string>();
    }

    inline void to_json(json & j, const CatalogSetupDirectOutboundSummary & x) {
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
        x.direct_outbound = get_stack_optional<CatalogSetupDirectOutboundSummary>(j, "direct_outbound");
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
        j["direct_outbound"] = x.direct_outbound;
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
        x.ipset_hashsize = get_stack_optional<int64_t>(j, "ipset_hashsize");
        x.ipset_maxelem = get_stack_optional<int64_t>(j, "ipset_maxelem");
        x.ipv6_enabled = get_stack_optional<bool>(j, "ipv6_enabled");
        x.max_file_size_bytes = get_stack_optional<int64_t>(j, "max_file_size_bytes");
        x.meta_udp443_policy = get_stack_optional<MetaUdp443Policy>(j, "meta_udp443_policy");
        x.pid_file = get_stack_optional<std::string>(j, "pid_file");
        x.ppe_deoffload_mode = get_stack_optional<PpeDeoffloadMode>(j, "ppe_deoffload_mode");
        x.ppe_deoffload_quic_enabled = get_stack_optional<bool>(j, "ppe_deoffload_quic_enabled");
        x.reconnect_owned_flows_on_routing_change_lists = get_stack_optional<std::vector<std::string>>(j, "reconnect_owned_flows_on_routing_change_lists");
        x.reconnect_unmarked_flows_on_routing_change = get_stack_optional<bool>(j, "reconnect_unmarked_flows_on_routing_change");
        x.reuse_static_sets_on_runtime_refresh = get_stack_optional<bool>(j, "reuse_static_sets_on_runtime_refresh");
        x.skip_marked_packets = get_stack_optional<bool>(j, "skip_marked_packets");
        x.strict_enforcement = get_stack_optional<bool>(j, "strict_enforcement");
        x.ttl_bypass_enabled = get_stack_optional<bool>(j, "ttl_bypass_enabled");
    }

    inline void to_json(json & j, const Daemon & x) {
        j = json::object();
        j["cache_dir"] = x.cache_dir;
        j["clear_dynamic_sets_on_apply"] = x.clear_dynamic_sets_on_apply;
        j["firewall_backend"] = x.firewall_backend;
        j["firewall_verify_max_bytes"] = x.firewall_verify_max_bytes;
        j["ipset_hashsize"] = x.ipset_hashsize;
        j["ipset_maxelem"] = x.ipset_maxelem;
        j["ipv6_enabled"] = x.ipv6_enabled;
        j["max_file_size_bytes"] = x.max_file_size_bytes;
        j["meta_udp443_policy"] = x.meta_udp443_policy;
        j["pid_file"] = x.pid_file;
        j["ppe_deoffload_mode"] = x.ppe_deoffload_mode;
        j["ppe_deoffload_quic_enabled"] = x.ppe_deoffload_quic_enabled;
        j["reconnect_owned_flows_on_routing_change_lists"] = x.reconnect_owned_flows_on_routing_change_lists;
        j["reconnect_unmarked_flows_on_routing_change"] = x.reconnect_unmarked_flows_on_routing_change;
        j["reuse_static_sets_on_runtime_refresh"] = x.reuse_static_sets_on_runtime_refresh;
        j["skip_marked_packets"] = x.skip_marked_packets;
        j["strict_enforcement"] = x.strict_enforcement;
        j["ttl_bypass_enabled"] = x.ttl_bypass_enabled;
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

    inline void from_json(const json & j, TunnelProbe& x) {
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.interval_ms = get_stack_optional<int64_t>(j, "interval_ms");
        x.list = get_stack_optional<std::string>(j, "list");
        x.max_probes_per_pass = get_stack_optional<int64_t>(j, "max_probes_per_pass");
        x.outbound = get_stack_optional<std::string>(j, "outbound");
        x.require_registry_confirmation = get_stack_optional<bool>(j, "require_registry_confirmation");
    }

    inline void to_json(json & j, const TunnelProbe & x) {
        j = json::object();
        j["enabled"] = x.enabled;
        j["interval_ms"] = x.interval_ms;
        j["list"] = x.list;
        j["max_probes_per_pass"] = x.max_probes_per_pass;
        j["outbound"] = x.outbound;
        j["require_registry_confirmation"] = x.require_registry_confirmation;
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
        x.tunnel_probe = get_stack_optional<TunnelProbe>(j, "tunnel_probe");
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
        j["tunnel_probe"] = x.tunnel_probe;
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

    inline void from_json(const json & j, ConnectionEntry& x) {
        x.active = get_stack_optional<bool>(j, "active");
        x.destination = get_stack_optional<std::string>(j, "destination");
        x.destination_domains = get_stack_optional<std::vector<std::string>>(j, "destination_domains");
        x.destination_port = get_stack_optional<int64_t>(j, "destination_port");
        x.device = get_stack_optional<std::string>(j, "device");
        x.first_seen = get_stack_optional<int64_t>(j, "first_seen");
        x.id = get_stack_optional<std::string>(j, "id");
        x.last_seen = get_stack_optional<int64_t>(j, "last_seen");
        x.mark = get_stack_optional<int64_t>(j, "mark");
        x.protocol = get_stack_optional<std::string>(j, "protocol");
        x.route = get_stack_optional<std::string>(j, "route");
        x.source = get_stack_optional<std::string>(j, "source");
        x.source_port = get_stack_optional<int64_t>(j, "source_port");
        x.state = get_stack_optional<std::string>(j, "state");
    }

    inline void to_json(json & j, const ConnectionEntry & x) {
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

    inline void from_json(const json & j, GeoLocation& x) {
        x.checked_at = get_stack_optional<int64_t>(j, "checked_at");
        x.country = get_stack_optional<std::string>(j, "country");
        x.country_code = get_stack_optional<std::string>(j, "country_code");
        x.emoji = get_stack_optional<std::string>(j, "emoji");
    }

    inline void to_json(json & j, const GeoLocation & x) {
        j = json::object();
        j["checked_at"] = x.checked_at;
        j["country"] = x.country;
        j["country_code"] = x.country_code;
        j["emoji"] = x.emoji;
    }

    inline void from_json(const json & j, GeoLookupRequest& x) {
        x.allow_external_lookup = get_stack_optional<bool>(j, "allow_external_lookup");
        x.hosts = get_stack_optional<std::vector<std::string>>(j, "hosts");
    }

    inline void to_json(json & j, const GeoLookupRequest & x) {
        j = json::object();
        j["allow_external_lookup"] = x.allow_external_lookup;
        j["hosts"] = x.hosts;
    }

    inline void from_json(const json & j, GeoLookupResult& x) {
        x.error = get_stack_optional<GeoLookupResultError>(j, "error");
        x.locations = get_stack_optional<std::map<std::string, GeoLocation>>(j, "locations");
        x.pending = get_stack_optional<bool>(j, "pending");
    }

    inline void to_json(json & j, const GeoLookupResult & x) {
        j = json::object();
        j["error"] = x.error;
        j["locations"] = x.locations;
        j["pending"] = x.pending;
    }

    inline void from_json(const json & j, GrantedResponse& x) {
        x.expires_in_seconds = get_stack_optional<int64_t>(j, "expires_in_seconds");
        x.granted = j.at("granted").get<bool>();
    }

    inline void to_json(json & j, const GrantedResponse & x) {
        j = json::object();
        j["expires_in_seconds"] = x.expires_in_seconds;
        j["granted"] = x.granted;
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

    inline void from_json(const json & j, InterfaceNames& x) {
        x.available = j.at("available").get<bool>();
        x.catalog_status = j.at("catalog_status").get<CatalogStatus>();
        x.names = j.at("names").get<std::map<std::string, std::string>>();
    }

    inline void to_json(json & j, const InterfaceNames & x) {
        j = json::object();
        j["available"] = x.available;
        j["catalog_status"] = x.catalog_status;
        j["names"] = x.names;
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

    inline void from_json(const json & j, LogSettings& x) {
        x.file_enabled = j.at("file_enabled").get<bool>();
        x.level = j.at("level").get<LogLevel>();
    }

    inline void to_json(json & j, const LogSettings & x) {
        j = json::object();
        j["file_enabled"] = x.file_enabled;
        j["level"] = x.level;
    }

    inline void from_json(const json & j, LogSettingsRequest& x) {
        x.file_enabled = get_stack_optional<bool>(j, "file_enabled");
        x.level = get_stack_optional<LogLevel>(j, "level");
    }

    inline void to_json(json & j, const LogSettingsRequest & x) {
        j = json::object();
        j["file_enabled"] = x.file_enabled;
        j["level"] = x.level;
    }

    inline void from_json(const json & j, LogSettingsResult& x) {
        x.durable = get_stack_optional<bool>(j, "durable");
        x.error = get_stack_optional<std::string>(j, "error");
        x.ok = get_stack_optional<bool>(j, "ok");
        x.settings = get_stack_optional<LogSettings>(j, "settings");
        x.warning = get_stack_optional<std::string>(j, "warning");
    }

    inline void to_json(json & j, const LogSettingsResult & x) {
        j = json::object();
        j["durable"] = x.durable;
        j["error"] = x.error;
        j["ok"] = x.ok;
        j["settings"] = x.settings;
        j["warning"] = x.warning;
    }

    inline void from_json(const json & j, LogTail& x) {
        x.exists = j.at("exists").get<bool>();
        x.last_command_failure = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "last_command_failure");
        x.lines = j.at("lines").get<std::vector<std::string>>();
        x.path = j.at("path").get<std::string>();
        x.size_bytes = j.at("size_bytes").get<int64_t>();
    }

    inline void to_json(json & j, const LogTail & x) {
        j = json::object();
        j["exists"] = x.exists;
        j["last_command_failure"] = x.last_command_failure;
        j["lines"] = x.lines;
        j["path"] = x.path;
        j["size_bytes"] = x.size_bytes;
    }

    inline void from_json(const json & j, NaiveComponentInstallResult& x) {
        x.error = get_stack_optional<NaiveComponentInstallResultError>(j, "error");
        x.installed = j.at("installed").get<bool>();
        x.log = get_stack_optional<std::string>(j, "log");
        x.size = get_stack_optional<int64_t>(j, "size");
    }

    inline void to_json(json & j, const NaiveComponentInstallResult & x) {
        j = json::object();
        j["error"] = x.error;
        j["installed"] = x.installed;
        j["log"] = x.log;
        j["size"] = x.size;
    }

    inline void from_json(const json & j, NaiveComponentState& x) {
        x.installed = j.at("installed").get<bool>();
        x.path = j.at("path").get<std::string>();
        x.size = j.at("size").get<int64_t>();
    }

    inline void to_json(json & j, const NaiveComponentState & x) {
        j = json::object();
        j["installed"] = x.installed;
        j["path"] = x.path;
        j["size"] = x.size;
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

    inline void from_json(const json & j, NativeMutation& x) {
        x.deferred_authoritative_checks = j.at("deferred_authoritative_checks").get<std::vector<NdmsNativeInventoryDeferredDeleteCheckElement>>();
        x.delete_blockers = j.at("delete_blockers").get<std::vector<NdmsNativeInventoryDeleteBlockerElement>>();
        x.delete_candidate = j.at("delete_candidate").get<bool>();
        x.ownership_lifecycle = get_stack_optional<OwnershipLifecycle>(j, "ownership_lifecycle");
        x.ownership_revision = get_stack_optional<std::string>(j, "ownership_revision");
        x.ownership_state = j.at("ownership_state").get<OwnershipState>();
    }

    inline void to_json(json & j, const NativeMutation & x) {
        j = json::object();
        j["deferred_authoritative_checks"] = x.deferred_authoritative_checks;
        j["delete_blockers"] = x.delete_blockers;
        j["delete_candidate"] = x.delete_candidate;
        j["ownership_lifecycle"] = x.ownership_lifecycle;
        j["ownership_revision"] = x.ownership_revision;
        j["ownership_state"] = x.ownership_state;
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
        x.kind = j.at("kind").get<NdmsTunnelKindEnum>();
        x.label = j.at("label").get<std::string>();
        x.link = get_stack_optional<bool>(j, "link");
        x.management_readiness = j.at("management_readiness").get<NdmsInterfaceManagementReadiness>();
        x.native_mutation = j.at("native_mutation").get<NativeMutation>();
        x.owner = j.at("owner").get<Owner>();
        x.role = j.at("role").get<NdmsInterfaceRoleEnum>();
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
        j["native_mutation"] = x.native_mutation;
        j["owner"] = x.owner;
        j["role"] = x.role;
    }

    inline void from_json(const json & j, NdmsNativeImportTargetRange& x) {
        x.first_index = j.at("first_index").get<int64_t>();
        x.last_index = j.at("last_index").get<int64_t>();
        x.prefix = j.at("prefix").get<NdmsNativeImportTargetPrefix>();
    }

    inline void to_json(json & j, const NdmsNativeImportTargetRange & x) {
        j = json::object();
        j["first_index"] = x.first_index;
        j["last_index"] = x.last_index;
        j["prefix"] = x.prefix;
    }

    inline void from_json(const json & j, NdmsNativeImportReadiness& x) {
        x.allocator_range = j.at("allocator_range").get<NdmsNativeImportTargetRange>();
        x.apply_available = j.at("apply_available").get<bool>();
        x.blockers = j.at("blockers").get<std::vector<NdmsNativeImportBlocker>>();
        x.eligible_returned_targets = j.at("eligible_returned_targets").get<NdmsNativeImportTargetRange>();
        x.journal_state = j.at("journal_state").get<NdmsNativeImportJournalState>();
        x.operation = j.at("operation").get<std::string>();
        x.preview_only = j.at("preview_only").get<bool>();
        x.protected_targets = j.at("protected_targets").get<std::vector<NdmsNativeImportTargetRange>>();
        x.reconcile_barrier_state = j.at("reconcile_barrier_state").get<NdmsNativeImportReconcileBarrierState>();
        x.request_name = j.at("request_name").get<std::string>();
    }

    inline void to_json(json & j, const NdmsNativeImportReadiness & x) {
        j = json::object();
        j["allocator_range"] = x.allocator_range;
        j["apply_available"] = x.apply_available;
        j["blockers"] = x.blockers;
        j["eligible_returned_targets"] = x.eligible_returned_targets;
        j["journal_state"] = x.journal_state;
        j["operation"] = x.operation;
        j["preview_only"] = x.preview_only;
        j["protected_targets"] = x.protected_targets;
        j["reconcile_barrier_state"] = x.reconcile_barrier_state;
        j["request_name"] = x.request_name;
    }

    inline void from_json(const json & j, NativeMutationStatus& x) {
        x.advisory = j.at("advisory").get<bool>();
        x.observed_delete_journal_state = j.at("observed_delete_journal_state").get<ObservedDeleteJournalState>();
        x.observed_import_journal_state = j.at("observed_import_journal_state").get<NdmsNativeImportJournalState>();
        x.ownership_inventory_available = j.at("ownership_inventory_available").get<bool>();
    }

    inline void to_json(json & j, const NativeMutationStatus & x) {
        j = json::object();
        j["advisory"] = x.advisory;
        j["observed_delete_journal_state"] = x.observed_delete_journal_state;
        j["observed_import_journal_state"] = x.observed_import_journal_state;
        j["ownership_inventory_available"] = x.ownership_inventory_available;
    }

    inline void from_json(const json & j, NdmsNativeRetainedDeletionElement& x) {
        x.deferred_authoritative_checks = j.at("deferred_authoritative_checks").get<std::vector<NdmsNativeRetainedDeletionDeferredCheckElement>>();
        x.forget_blockers = j.at("forget_blockers").get<std::vector<NdmsNativeRetainedDeletionBlockerElement>>();
        x.forget_candidate = j.at("forget_candidate").get<bool>();
        x.interface_name = j.at("interface_name").get<std::string>();
        x.ownership_revision = j.at("ownership_revision").get<std::string>();
    }

    inline void to_json(json & j, const NdmsNativeRetainedDeletionElement & x) {
        j = json::object();
        j["deferred_authoritative_checks"] = x.deferred_authoritative_checks;
        j["forget_blockers"] = x.forget_blockers;
        j["forget_candidate"] = x.forget_candidate;
        j["interface_name"] = x.interface_name;
        j["ownership_revision"] = x.ownership_revision;
    }

    inline void from_json(const json & j, NdmsInterfaceInventoryResponse& x) {
        x.available = j.at("available").get<bool>();
        x.catalog_status = j.at("catalog_status").get<CatalogStatus>();
        x.interfaces = j.at("interfaces").get<std::vector<NdmsTunnelInterfaceElement>>();
        x.mutation_mode = j.at("mutation_mode").get<MutationMode>();
        x.native_import_readiness = j.at("native_import_readiness").get<NdmsNativeImportReadiness>();
        x.native_mutation_status = j.at("native_mutation_status").get<NativeMutationStatus>();
        x.read_only = j.at("read_only").get<bool>();
        x.required_guards = j.at("required_guards").get<std::vector<RequiredGuard>>();
        x.retained_deletions = j.at("retained_deletions").get<std::vector<NdmsNativeRetainedDeletionElement>>();
    }

    inline void to_json(json & j, const NdmsInterfaceInventoryResponse & x) {
        j = json::object();
        j["available"] = x.available;
        j["catalog_status"] = x.catalog_status;
        j["interfaces"] = x.interfaces;
        j["mutation_mode"] = x.mutation_mode;
        j["native_import_readiness"] = x.native_import_readiness;
        j["native_mutation_status"] = x.native_mutation_status;
        j["read_only"] = x.read_only;
        j["required_guards"] = x.required_guards;
        j["retained_deletions"] = x.retained_deletions;
    }

    inline void from_json(const json & j, NdmsNativeDeleteRequest& x) {
        x.confirm_label = j.at("confirm_label").get<std::string>();
        x.expected_ownership_revision = j.at("expected_ownership_revision").get<std::string>();
        x.interface_name = j.at("interface_name").get<std::string>();
    }

    inline void to_json(json & j, const NdmsNativeDeleteRequest & x) {
        j = json::object();
        j["confirm_label"] = x.confirm_label;
        j["expected_ownership_revision"] = x.expected_ownership_revision;
        j["interface_name"] = x.interface_name;
    }

    inline void from_json(const json & j, NdmsNativeDeleteResponse& x) {
        x.delete_perform_started = j.at("delete_perform_started").get<bool>();
        x.external_writer_race_accepted = j.at("external_writer_race_accepted").get<bool>();
        x.external_writer_race_excluded = j.at("external_writer_race_excluded").get<bool>();
        x.global_save_scope_acknowledged = j.at("global_save_scope_acknowledged").get<bool>();
        x.interface_name = get_stack_optional<std::string>(j, "interface_name");
        x.kind = get_stack_optional<NdmsNativeMutationKind>(j, "kind");
        x.observation_failure = get_stack_optional<NdmsNativeDirectObservationFailure>(j, "observation_failure");
        x.ownership_tombstone_durable = j.at("ownership_tombstone_durable").get<bool>();
        x.phase = get_stack_optional<NdmsNativeDeletePhase>(j, "phase");
        x.request_may_have_been_dispatched = j.at("request_may_have_been_dispatched").get<bool>();
        x.rollback_snapshot_retained = j.at("rollback_snapshot_retained").get<bool>();
        x.save_perform_started = j.at("save_perform_started").get<bool>();
        x.status = j.at("status").get<NdmsNativeDeleteStatus>();
        x.stop = j.at("stop").get<NdmsNativeDeleteStop>();
        x.system_configuration_save_acknowledged = j.at("system_configuration_save_acknowledged").get<bool>();
        x.transport_outcome = get_stack_optional<NdmsNativeDeleteTransportOutcome>(j, "transport_outcome");
    }

    inline void to_json(json & j, const NdmsNativeDeleteResponse & x) {
        j = json::object();
        j["delete_perform_started"] = x.delete_perform_started;
        j["external_writer_race_accepted"] = x.external_writer_race_accepted;
        j["external_writer_race_excluded"] = x.external_writer_race_excluded;
        j["global_save_scope_acknowledged"] = x.global_save_scope_acknowledged;
        j["interface_name"] = x.interface_name;
        j["kind"] = x.kind;
        j["observation_failure"] = x.observation_failure;
        j["ownership_tombstone_durable"] = x.ownership_tombstone_durable;
        j["phase"] = x.phase;
        j["request_may_have_been_dispatched"] = x.request_may_have_been_dispatched;
        j["rollback_snapshot_retained"] = x.rollback_snapshot_retained;
        j["save_perform_started"] = x.save_perform_started;
        j["status"] = x.status;
        j["stop"] = x.stop;
        j["system_configuration_save_acknowledged"] = x.system_configuration_save_acknowledged;
        j["transport_outcome"] = x.transport_outcome;
    }

    inline void from_json(const json & j, NdmsNativeImportPreflightResponse& x) {
        x.admitted = j.at("admitted").get<bool>();
        x.external_ndms_writer_race_excluded = j.at("external_ndms_writer_race_excluded").get<bool>();
        x.owner_risk_acceptance_required = j.at("owner_risk_acceptance_required").get<bool>();
    }

    inline void to_json(json & j, const NdmsNativeImportPreflightResponse & x) {
        j = json::object();
        j["admitted"] = x.admitted;
        j["external_ndms_writer_race_excluded"] = x.external_ndms_writer_race_excluded;
        j["owner_risk_acceptance_required"] = x.owner_risk_acceptance_required;
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryResponse& x) {
        x.created_interface = get_stack_optional<std::string>(j, "created_interface");
        x.created_kernel_interface = get_stack_optional<std::string>(j, "created_kernel_interface");
        x.delete_perform_started = j.at("delete_perform_started").get<bool>();
        x.delete_transport_outcome = get_stack_optional<NdmsNativeDeleteTransportOutcome>(j, "delete_transport_outcome");
        x.delete_wal_readiness = get_stack_optional<NdmsNativeWalReadiness>(j, "delete_wal_readiness");
        x.direct_observation_failure = get_stack_optional<NdmsNativeDirectObservationFailure>(j, "direct_observation_failure");
        x.expected_interface = get_stack_optional<std::string>(j, "expected_interface");
        x.external_ndms_writer_race_accepted = j.at("external_ndms_writer_race_accepted").get<bool>();
        x.external_ndms_writer_race_excluded = j.at("external_ndms_writer_race_excluded").get<bool>();
        x.forward_admission_state = get_stack_optional<NdmsNativeImportRecoveryAdmissionState>(j, "forward_admission_state");
        x.forward_dispatch_state = get_stack_optional<NdmsNativeImportRecoveryDispatchState>(j, "forward_dispatch_state");
        x.forward_failed_step = get_stack_optional<NdmsNativeImportRecoveryStep>(j, "forward_failed_step");
        x.import_wal_readiness = get_stack_optional<NdmsNativeWalReadiness>(j, "import_wal_readiness");
        x.kind = get_stack_optional<NdmsNativeMutationKind>(j, "kind");
        x.ndms_delete_dispatched = j.at("ndms_delete_dispatched").get<bool>();
        x.ndms_import_request_dispatched = j.at("ndms_import_request_dispatched").get<bool>();
        x.ownership_published = j.at("ownership_published").get<bool>();
        x.phase = get_stack_optional<NdmsNativeImportRecoveryPhase>(j, "phase");
        x.recovery_action = get_stack_optional<NdmsNativeImportRecoveryAction>(j, "recovery_action");
        x.recovery_admission_state = get_stack_optional<NdmsNativeImportRecoveryAdmissionState>(j, "recovery_admission_state");
        x.recovery_dispatch_state = get_stack_optional<NdmsNativeImportRecoveryDispatchState>(j, "recovery_dispatch_state");
        x.recovery_failed_step = get_stack_optional<NdmsNativeImportRecoveryStep>(j, "recovery_failed_step");
        x.request_may_have_been_dispatched = j.at("request_may_have_been_dispatched").get<bool>();
        x.rollback_snapshot_retired = j.at("rollback_snapshot_retired").get<bool>();
        x.status = j.at("status").get<NdmsNativeImportRecoveryStatus>();
        x.stop = j.at("stop").get<NdmsNativeImportRecoveryStop>();
        x.system_configuration_save_performed = j.at("system_configuration_save_performed").get<bool>();
        x.wal_may_require_recovery = j.at("wal_may_require_recovery").get<bool>();
        x.wal_removed = j.at("wal_removed").get<bool>();
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryResponse & x) {
        j = json::object();
        j["created_interface"] = x.created_interface;
        j["created_kernel_interface"] = x.created_kernel_interface;
        j["delete_perform_started"] = x.delete_perform_started;
        j["delete_transport_outcome"] = x.delete_transport_outcome;
        j["delete_wal_readiness"] = x.delete_wal_readiness;
        j["direct_observation_failure"] = x.direct_observation_failure;
        j["expected_interface"] = x.expected_interface;
        j["external_ndms_writer_race_accepted"] = x.external_ndms_writer_race_accepted;
        j["external_ndms_writer_race_excluded"] = x.external_ndms_writer_race_excluded;
        j["forward_admission_state"] = x.forward_admission_state;
        j["forward_dispatch_state"] = x.forward_dispatch_state;
        j["forward_failed_step"] = x.forward_failed_step;
        j["import_wal_readiness"] = x.import_wal_readiness;
        j["kind"] = x.kind;
        j["ndms_delete_dispatched"] = x.ndms_delete_dispatched;
        j["ndms_import_request_dispatched"] = x.ndms_import_request_dispatched;
        j["ownership_published"] = x.ownership_published;
        j["phase"] = x.phase;
        j["recovery_action"] = x.recovery_action;
        j["recovery_admission_state"] = x.recovery_admission_state;
        j["recovery_dispatch_state"] = x.recovery_dispatch_state;
        j["recovery_failed_step"] = x.recovery_failed_step;
        j["request_may_have_been_dispatched"] = x.request_may_have_been_dispatched;
        j["rollback_snapshot_retired"] = x.rollback_snapshot_retired;
        j["status"] = x.status;
        j["stop"] = x.stop;
        j["system_configuration_save_performed"] = x.system_configuration_save_performed;
        j["wal_may_require_recovery"] = x.wal_may_require_recovery;
        j["wal_removed"] = x.wal_removed;
    }

    inline void from_json(const json & j, NdmsNativeImportResponse& x) {
        x.baseline_error = get_stack_optional<std::string>(j, "baseline_error");
        x.created_interface = get_stack_optional<std::string>(j, "created_interface");
        x.created_kernel_interface = get_stack_optional<std::string>(j, "created_kernel_interface");
        x.delete_wal_readiness = get_stack_optional<NdmsNativeWalReadiness>(j, "delete_wal_readiness");
        x.direct_observation_failure = get_stack_optional<NdmsNativeDirectObservationFailure>(j, "direct_observation_failure");
        x.executor_stop = get_stack_optional<std::string>(j, "executor_stop");
        x.expected_interface = get_stack_optional<std::string>(j, "expected_interface");
        x.external_ndms_writer_race_accepted = j.at("external_ndms_writer_race_accepted").get<bool>();
        x.external_ndms_writer_race_excluded = j.at("external_ndms_writer_race_excluded").get<bool>();
        x.forward_admission_state = get_stack_optional<NdmsNativeImportRecoveryAdmissionState>(j, "forward_admission_state");
        x.forward_dispatch_state = get_stack_optional<NdmsNativeImportRecoveryDispatchState>(j, "forward_dispatch_state");
        x.forward_failed_step = get_stack_optional<NdmsNativeImportRecoveryStep>(j, "forward_failed_step");
        x.import_wal_readiness = get_stack_optional<NdmsNativeWalReadiness>(j, "import_wal_readiness");
        x.kind = get_stack_optional<NdmsNativeMutationKind>(j, "kind");
        x.ownership_published = j.at("ownership_published").get<bool>();
        x.request_error = get_stack_optional<RequestError>(j, "request_error");
        x.request_may_have_been_dispatched = j.at("request_may_have_been_dispatched").get<bool>();
        x.rollback_snapshot_may_be_retained = j.at("rollback_snapshot_may_be_retained").get<bool>();
        x.status = j.at("status").get<NdmsNativeImportStatus>();
        x.stop = j.at("stop").get<NdmsNativeImportStop>();
        x.system_configuration_save_performed = j.at("system_configuration_save_performed").get<bool>();
        x.wal_may_require_recovery = j.at("wal_may_require_recovery").get<bool>();
    }

    inline void to_json(json & j, const NdmsNativeImportResponse & x) {
        j = json::object();
        j["baseline_error"] = x.baseline_error;
        j["created_interface"] = x.created_interface;
        j["created_kernel_interface"] = x.created_kernel_interface;
        j["delete_wal_readiness"] = x.delete_wal_readiness;
        j["direct_observation_failure"] = x.direct_observation_failure;
        j["executor_stop"] = x.executor_stop;
        j["expected_interface"] = x.expected_interface;
        j["external_ndms_writer_race_accepted"] = x.external_ndms_writer_race_accepted;
        j["external_ndms_writer_race_excluded"] = x.external_ndms_writer_race_excluded;
        j["forward_admission_state"] = x.forward_admission_state;
        j["forward_dispatch_state"] = x.forward_dispatch_state;
        j["forward_failed_step"] = x.forward_failed_step;
        j["import_wal_readiness"] = x.import_wal_readiness;
        j["kind"] = x.kind;
        j["ownership_published"] = x.ownership_published;
        j["request_error"] = x.request_error;
        j["request_may_have_been_dispatched"] = x.request_may_have_been_dispatched;
        j["rollback_snapshot_may_be_retained"] = x.rollback_snapshot_may_be_retained;
        j["status"] = x.status;
        j["stop"] = x.stop;
        j["system_configuration_save_performed"] = x.system_configuration_save_performed;
        j["wal_may_require_recovery"] = x.wal_may_require_recovery;
    }

    inline void from_json(const json & j, NdmsNativeTombstoneForgetRequest& x) {
        x.confirm_interface_name = j.at("confirm_interface_name").get<std::string>();
        x.expected_ownership_revision = j.at("expected_ownership_revision").get<std::string>();
        x.foreign_reappearance_acknowledgement = j.at("foreign_reappearance_acknowledgement").get<ForeignReappearanceAcknowledgement>();
        x.interface_name = j.at("interface_name").get<std::string>();
        x.rollback_discard_acknowledgement = j.at("rollback_discard_acknowledgement").get<RollbackDiscardAcknowledgement>();
    }

    inline void to_json(json & j, const NdmsNativeTombstoneForgetRequest & x) {
        j = json::object();
        j["confirm_interface_name"] = x.confirm_interface_name;
        j["expected_ownership_revision"] = x.expected_ownership_revision;
        j["foreign_reappearance_acknowledgement"] = x.foreign_reappearance_acknowledgement;
        j["interface_name"] = x.interface_name;
        j["rollback_discard_acknowledgement"] = x.rollback_discard_acknowledgement;
    }

    inline void from_json(const json & j, NdmsNativeTombstoneForgetResponse& x) {
        x.future_reappearance_is_foreign = j.at("future_reappearance_is_foreign").get<bool>();
        x.interface_name = j.at("interface_name").get<std::string>();
        x.router_mutation_attempted = j.at("router_mutation_attempted").get<bool>();
        x.snapshot_state = j.at("snapshot_state").get<NdmsNativeTombstoneForgetArtifactState>();
        x.status = j.at("status").get<NdmsNativeTombstoneForgetStatus>();
        x.stop = j.at("stop").get<NdmsNativeTombstoneForgetStop>();
        x.system_configuration_save_acknowledged = j.at("system_configuration_save_acknowledged").get<bool>();
        x.tombstone_state = j.at("tombstone_state").get<NdmsNativeTombstoneForgetArtifactState>();
    }

    inline void to_json(json & j, const NdmsNativeTombstoneForgetResponse & x) {
        j = json::object();
        j["future_reappearance_is_foreign"] = x.future_reappearance_is_foreign;
        j["interface_name"] = x.interface_name;
        j["router_mutation_attempted"] = x.router_mutation_attempted;
        j["snapshot_state"] = x.snapshot_state;
        j["status"] = x.status;
        j["stop"] = x.stop;
        j["system_configuration_save_acknowledged"] = x.system_configuration_save_acknowledged;
        j["tombstone_state"] = x.tombstone_state;
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
        x.catalog_status = j.at("catalog_status").get<CatalogStatus>();
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

    inline void from_json(const json & j, NfqwsFileEntryElement& x) {
        x.category = j.at("category").get<NfqwsFileEntryCategory>();
        x.content = j.at("content").get<std::string>();
        x.name = j.at("name").get<std::string>();
    }

    inline void to_json(json & j, const NfqwsFileEntryElement & x) {
        j = json::object();
        j["category"] = x.category;
        j["content"] = x.content;
        j["name"] = x.name;
    }

    inline void from_json(const json & j, NfqwsActionRequest& x) {
        x.action = j.at("action").get<NfqwsActionRequestAction>();
        x.category = get_stack_optional<NfqwsActionRequestCategory>(j, "category");
        x.command = get_stack_optional<Command>(j, "command");
        x.content = get_stack_optional<std::string>(j, "content");
        x.files = get_stack_optional<std::variant<std::vector<NfqwsFileEntryElement>, std::map<std::string, nlohmann::json>>>(j, "files");
        x.force = get_stack_optional<bool>(j, "force");
        x.name = get_stack_optional<std::string>(j, "name");
        x.restart = get_stack_optional<bool>(j, "restart");
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const NfqwsActionRequest & x) {
        j = json::object();
        j["action"] = x.action;
        j["category"] = x.category;
        j["command"] = x.command;
        j["content"] = x.content;
        j["files"] = x.files;
        j["force"] = x.force;
        j["name"] = x.name;
        j["restart"] = x.restart;
        j["url"] = x.url;
    }

    inline void from_json(const json & j, NfqwsActionResult& x) {
        x.captured = get_stack_optional<int64_t>(j, "captured");
        x.content = get_stack_optional<std::string>(j, "content");
        x.durable = get_stack_optional<bool>(j, "durable");
        x.error = get_stack_optional<std::string>(j, "error");
        x.exact_package_state = get_stack_optional<bool>(j, "exact_package_state");
        x.failed = get_stack_optional<int64_t>(j, "failed");
        x.files_restored = get_stack_optional<bool>(j, "files_restored");
        x.firewall_reconcile_pending = get_stack_optional<bool>(j, "firewall_reconcile_pending");
        x.installed_blobs = get_stack_optional<int64_t>(j, "installed_blobs");
        x.journal_retained = get_stack_optional<bool>(j, "journal_retained");
        x.ok = get_stack_optional<bool>(j, "ok");
        x.output = get_stack_optional<std::string>(j, "output");
        x.package_metadata_verified = get_stack_optional<bool>(j, "package_metadata_verified");
        x.preserved_blobs = get_stack_optional<int64_t>(j, "preserved_blobs");
        x.reachable = get_stack_optional<bool>(j, "reachable");
        x.restore_point = get_stack_optional<std::string>(j, "restore_point");
        x.restored = get_stack_optional<int64_t>(j, "restored");
        x.runtime_verified = get_stack_optional<bool>(j, "runtime_verified");
        x.status = get_stack_optional<int64_t>(j, "status");
        x.warning = get_stack_optional<std::string>(j, "warning");
    }

    inline void to_json(json & j, const NfqwsActionResult & x) {
        j = json::object();
        j["captured"] = x.captured;
        j["content"] = x.content;
        j["durable"] = x.durable;
        j["error"] = x.error;
        j["exact_package_state"] = x.exact_package_state;
        j["failed"] = x.failed;
        j["files_restored"] = x.files_restored;
        j["firewall_reconcile_pending"] = x.firewall_reconcile_pending;
        j["installed_blobs"] = x.installed_blobs;
        j["journal_retained"] = x.journal_retained;
        j["ok"] = x.ok;
        j["output"] = x.output;
        j["package_metadata_verified"] = x.package_metadata_verified;
        j["preserved_blobs"] = x.preserved_blobs;
        j["reachable"] = x.reachable;
        j["restore_point"] = x.restore_point;
        j["restored"] = x.restored;
        j["runtime_verified"] = x.runtime_verified;
        j["status"] = x.status;
        j["warning"] = x.warning;
    }

    inline void from_json(const json & j, NfqwsStatus& x) {
        x.active_strategy = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "active_strategy");
        x.files = get_stack_optional<std::vector<std::map<std::string, nlohmann::json>>>(j, "files");
        x.installed = j.at("installed").get<bool>();
        x.package_metadata_verified = get_stack_optional<bool>(j, "package_metadata_verified");
        x.process_running = j.at("process_running").get<bool>();
        x.queue_active = j.at("queue_active").get<bool>();
        x.restore_capability = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "restore_capability");
        x.restore_point = get_stack_optional<std::string>(j, "restore_point");
        x.rotator_state = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "rotator_state");
        x.running = j.at("running").get<bool>();
        x.strategies = get_stack_optional<std::vector<std::map<std::string, nlohmann::json>>>(j, "strategies");
        x.transaction_state = get_stack_optional<std::string>(j, "transaction_state");
        x.upgrade_capability = get_stack_optional<std::map<std::string, nlohmann::json>>(j, "upgrade_capability");
        x.version = get_stack_optional<std::string>(j, "version");
    }

    inline void to_json(json & j, const NfqwsStatus & x) {
        j = json::object();
        j["active_strategy"] = x.active_strategy;
        j["files"] = x.files;
        j["installed"] = x.installed;
        j["package_metadata_verified"] = x.package_metadata_verified;
        j["process_running"] = x.process_running;
        j["queue_active"] = x.queue_active;
        j["restore_capability"] = x.restore_capability;
        j["restore_point"] = x.restore_point;
        j["rotator_state"] = x.rotator_state;
        j["running"] = x.running;
        j["strategies"] = x.strategies;
        j["transaction_state"] = x.transaction_state;
        j["upgrade_capability"] = x.upgrade_capability;
        j["version"] = x.version;
    }

    inline void from_json(const json & j, OkResponse& x) {
        x.ok = j.at("ok").get<bool>();
    }

    inline void to_json(json & j, const OkResponse & x) {
        j = json::object();
        j["ok"] = x.ok;
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

    inline void from_json(const json & j, PpeDeoffloadCounter& x) {
        x.bytes = get_stack_optional<int64_t>(j, "bytes");
        x.packets = get_stack_optional<int64_t>(j, "packets");
    }

    inline void to_json(json & j, const PpeDeoffloadCounter & x) {
        j = json::object();
        j["bytes"] = x.bytes;
        j["packets"] = x.packets;
    }

    inline void from_json(const json & j, PpeDeoffloadProtocolHealth& x) {
        x.active = j.at("active").get<bool>();
        x.applied_ports = j.at("applied_ports").get<std::vector<std::string>>();
        x.counters = get_stack_optional<PpeDeoffloadCounter>(j, "counters");
        x.desired_ports = j.at("desired_ports").get<std::vector<std::string>>();
    }

    inline void to_json(json & j, const PpeDeoffloadProtocolHealth & x) {
        j = json::object();
        j["active"] = x.active;
        j["applied_ports"] = x.applied_ports;
        j["counters"] = x.counters;
        j["desired_ports"] = x.desired_ports;
    }

    inline void from_json(const json & j, PpeDeoffloadHealth& x) {
        x.capability = j.at("capability").get<PpeDeoffloadCapability>();
        x.connskip_packets = get_stack_optional<int64_t>(j, "connskip_packets");
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.forward = get_stack_optional<PpeDeoffloadCounter>(j, "forward");
        x.last_reconcile_ts = get_stack_optional<int64_t>(j, "last_reconcile_ts");
        x.mode = j.at("mode").get<PpeDeoffloadMode>();
        x.observed_at = get_stack_optional<int64_t>(j, "observed_at");
        x.prerouting = get_stack_optional<PpeDeoffloadCounter>(j, "prerouting");
        x.quic = j.at("quic").get<PpeDeoffloadProtocolHealth>();
        x.reason = get_stack_optional<std::string>(j, "reason");
        x.state = j.at("state").get<PpeDeoffloadHealthState>();
        x.tcp = j.at("tcp").get<PpeDeoffloadProtocolHealth>();
    }

    inline void to_json(json & j, const PpeDeoffloadHealth & x) {
        j = json::object();
        j["capability"] = x.capability;
        j["connskip_packets"] = x.connskip_packets;
        j["detail"] = x.detail;
        j["forward"] = x.forward;
        j["last_reconcile_ts"] = x.last_reconcile_ts;
        j["mode"] = x.mode;
        j["observed_at"] = x.observed_at;
        j["prerouting"] = x.prerouting;
        j["quic"] = x.quic;
        j["reason"] = x.reason;
        j["state"] = x.state;
        j["tcp"] = x.tcp;
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

    inline void from_json(const json & j, RegistryCheckRequest& x) {
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.target = j.at("target").get<std::string>();
    }

    inline void to_json(json & j, const RegistryCheckRequest & x) {
        j = json::object();
        j["detour"] = x.detour;
        j["target"] = x.target;
    }

    inline void from_json(const json & j, RegistryCheckResponse& x) {
        x.blocked = get_stack_optional<bool>(j, "blocked");
        x.blocked_subnets = get_stack_optional<std::vector<std::string>>(j, "blocked_subnets");
        x.cached = get_stack_optional<bool>(j, "cached");
        x.cdn_providers = get_stack_optional<std::vector<std::string>>(j, "cdn_providers");
        x.checked = j.at("checked").get<bool>();
        x.error = get_stack_optional<std::string>(j, "error");
        x.ips = get_stack_optional<std::vector<std::string>>(j, "ips");
        x.organisation = get_stack_optional<std::string>(j, "organisation");
        x.reason = get_stack_optional<Reason>(j, "reason");
        x.rkn_domain = get_stack_optional<std::string>(j, "rkn_domain");
        x.service = j.at("service").get<std::string>();
        x.target = get_stack_optional<std::string>(j, "target");
    }

    inline void to_json(json & j, const RegistryCheckResponse & x) {
        j = json::object();
        j["blocked"] = x.blocked;
        j["blocked_subnets"] = x.blocked_subnets;
        j["cached"] = x.cached;
        j["cdn_providers"] = x.cdn_providers;
        j["checked"] = x.checked;
        j["error"] = x.error;
        j["ips"] = x.ips;
        j["organisation"] = x.organisation;
        j["reason"] = x.reason;
        j["rkn_domain"] = x.rkn_domain;
        j["service"] = x.service;
        j["target"] = x.target;
    }

    inline void from_json(const json & j, RegistryConsentRequest& x) {
        x.enabled = j.at("enabled").get<bool>();
    }

    inline void to_json(json & j, const RegistryConsentRequest & x) {
        j = json::object();
        j["enabled"] = x.enabled;
    }

    inline void from_json(const json & j, RegistryConsentResponse& x) {
        x.durable = j.at("durable").get<bool>();
        x.enabled = j.at("enabled").get<bool>();
    }

    inline void to_json(json & j, const RegistryConsentResponse & x) {
        j = json::object();
        j["durable"] = x.durable;
        j["enabled"] = x.enabled;
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

    inline void from_json(const json & j, RemoteAccessRequest& x) {
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.port = get_stack_optional<int64_t>(j, "port");
    }

    inline void to_json(json & j, const RemoteAccessRequest & x) {
        j = json::object();
        j["enabled"] = x.enabled;
        j["port"] = x.port;
    }

    inline void from_json(const json & j, Settings& x) {
        x.enabled = j.at("enabled").get<bool>();
        x.port = j.at("port").get<int64_t>();
    }

    inline void to_json(json & j, const Settings & x) {
        j = json::object();
        j["enabled"] = x.enabled;
        j["port"] = x.port;
    }

    inline void from_json(const json & j, RemoteAccessResult& x) {
        x.degraded = get_stack_optional<bool>(j, "degraded");
        x.detail = get_stack_optional<std::string>(j, "detail");
        x.durable = get_stack_optional<bool>(j, "durable");
        x.error = get_stack_optional<std::string>(j, "error");
        x.generation = get_stack_optional<int64_t>(j, "generation");
        x.listen = get_stack_optional<std::string>(j, "listen");
        x.maintenance = get_stack_optional<bool>(j, "maintenance");
        x.ok = get_stack_optional<bool>(j, "ok");
        x.pending = get_stack_optional<bool>(j, "pending");
        x.phase = get_stack_optional<std::string>(j, "phase");
        x.recovery_owned = get_stack_optional<bool>(j, "recovery_owned");
        x.retry_after_ms = get_stack_optional<int64_t>(j, "retry_after_ms");
        x.retry_scheduled = get_stack_optional<bool>(j, "retry_scheduled");
        x.settings = get_stack_optional<Settings>(j, "settings");
        x.supported_port = get_stack_optional<int64_t>(j, "supported_port");
        x.warning = get_stack_optional<std::string>(j, "warning");
    }

    inline void to_json(json & j, const RemoteAccessResult & x) {
        j = json::object();
        j["degraded"] = x.degraded;
        j["detail"] = x.detail;
        j["durable"] = x.durable;
        j["error"] = x.error;
        j["generation"] = x.generation;
        j["listen"] = x.listen;
        j["maintenance"] = x.maintenance;
        j["ok"] = x.ok;
        j["pending"] = x.pending;
        j["phase"] = x.phase;
        j["recovery_owned"] = x.recovery_owned;
        j["retry_after_ms"] = x.retry_after_ms;
        j["retry_scheduled"] = x.retry_scheduled;
        j["settings"] = x.settings;
        j["supported_port"] = x.supported_port;
        j["warning"] = x.warning;
    }

    inline void from_json(const json & j, RemoteAccessRuntime& x) {
        x.applied_generation = get_stack_optional<int64_t>(j, "applied_generation");
        x.attempt = get_stack_optional<int64_t>(j, "attempt");
        x.command_exit_code = get_stack_optional<int64_t>(j, "command_exit_code");
        x.desired_generation = get_stack_optional<int64_t>(j, "desired_generation");
        x.error = get_stack_optional<std::string>(j, "error");
        x.incident_active = get_stack_optional<bool>(j, "incident_active");
        x.interface = get_stack_optional<std::string>(j, "interface");
        x.maintenance = get_stack_optional<bool>(j, "maintenance");
        x.phase = get_stack_optional<std::string>(j, "phase");
        x.recovery_owned = get_stack_optional<bool>(j, "recovery_owned");
        x.state = get_stack_optional<std::string>(j, "state");
    }

    inline void to_json(json & j, const RemoteAccessRuntime & x) {
        j = json::object();
        j["applied_generation"] = x.applied_generation;
        j["attempt"] = x.attempt;
        j["command_exit_code"] = x.command_exit_code;
        j["desired_generation"] = x.desired_generation;
        j["error"] = x.error;
        j["incident_active"] = x.incident_active;
        j["interface"] = x.interface;
        j["maintenance"] = x.maintenance;
        j["phase"] = x.phase;
        j["recovery_owned"] = x.recovery_owned;
        j["state"] = x.state;
    }

    inline void from_json(const json & j, RemoteAccessState& x) {
        x.auth_provider = get_stack_optional<std::string>(j, "auth_provider");
        x.blocked_reason = get_stack_optional<BlockedReason>(j, "blocked_reason");
        x.custom_port_supported = get_stack_optional<bool>(j, "custom_port_supported");
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.internal_port = get_stack_optional<int64_t>(j, "internal_port");
        x.keenetic_auth_switch_allowed = get_stack_optional<bool>(j, "keenetic_auth_switch_allowed");
        x.listen = get_stack_optional<std::string>(j, "listen");
        x.listen_reachable = get_stack_optional<bool>(j, "listen_reachable");
        x.login_required = get_stack_optional<bool>(j, "login_required");
        x.port = get_stack_optional<int64_t>(j, "port");
        x.runtime = get_stack_optional<RemoteAccessRuntime>(j, "runtime");
        x.supported_port = get_stack_optional<int64_t>(j, "supported_port");
    }

    inline void to_json(json & j, const RemoteAccessState & x) {
        j = json::object();
        j["auth_provider"] = x.auth_provider;
        j["blocked_reason"] = x.blocked_reason;
        j["custom_port_supported"] = x.custom_port_supported;
        j["enabled"] = x.enabled;
        j["internal_port"] = x.internal_port;
        j["keenetic_auth_switch_allowed"] = x.keenetic_auth_switch_allowed;
        j["listen"] = x.listen;
        j["listen_reachable"] = x.listen_reachable;
        j["login_required"] = x.login_required;
        j["port"] = x.port;
        j["runtime"] = x.runtime;
        j["supported_port"] = x.supported_port;
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

    inline void from_json(const json & j, RouterInfo& x) {
        x.arch = get_stack_optional<std::string>(j, "arch");
        x.cpu_load_percent = get_stack_optional<int64_t>(j, "cpu_load_percent");
        x.cpu_model = get_stack_optional<std::string>(j, "cpu_model");
        x.cpu_temperature_c = get_stack_optional<double>(j, "cpu_temperature_c");
        x.disk_total_mb = get_stack_optional<int64_t>(j, "disk_total_mb");
        x.disk_used_mb = get_stack_optional<int64_t>(j, "disk_used_mb");
        x.disk_used_percent = get_stack_optional<int64_t>(j, "disk_used_percent");
        x.firmware_channel = get_stack_optional<std::string>(j, "firmware_channel");
        x.firmware_date = get_stack_optional<std::string>(j, "firmware_date");
        x.firmware_release = get_stack_optional<std::string>(j, "firmware_release");
        x.firmware_title = get_stack_optional<std::string>(j, "firmware_title");
        x.hw_id = get_stack_optional<std::string>(j, "hw_id");
        x.memory_total_mb = get_stack_optional<int64_t>(j, "memory_total_mb");
        x.memory_used_mb = get_stack_optional<int64_t>(j, "memory_used_mb");
        x.memory_used_percent = get_stack_optional<int64_t>(j, "memory_used_percent");
        x.model = get_stack_optional<std::string>(j, "model");
        x.region = get_stack_optional<std::string>(j, "region");
        x.uptime_seconds = get_stack_optional<int64_t>(j, "uptime_seconds");
        x.vendor = get_stack_optional<std::string>(j, "vendor");
    }

    inline void to_json(json & j, const RouterInfo & x) {
        j = json::object();
        j["arch"] = x.arch;
        j["cpu_load_percent"] = x.cpu_load_percent;
        j["cpu_model"] = x.cpu_model;
        j["cpu_temperature_c"] = x.cpu_temperature_c;
        j["disk_total_mb"] = x.disk_total_mb;
        j["disk_used_mb"] = x.disk_used_mb;
        j["disk_used_percent"] = x.disk_used_percent;
        j["firmware_channel"] = x.firmware_channel;
        j["firmware_date"] = x.firmware_date;
        j["firmware_release"] = x.firmware_release;
        j["firmware_title"] = x.firmware_title;
        j["hw_id"] = x.hw_id;
        j["memory_total_mb"] = x.memory_total_mb;
        j["memory_used_mb"] = x.memory_used_mb;
        j["memory_used_percent"] = x.memory_used_percent;
        j["model"] = x.model;
        j["region"] = x.region;
        j["uptime_seconds"] = x.uptime_seconds;
        j["vendor"] = x.vendor;
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
        x.ppe_deoffload = get_stack_optional<PpeDeoffloadHealth>(j, "ppe_deoffload");
        x.route_tables = j.at("route_tables").get<std::vector<RouteTableCheck>>();
        x.system_auth_detail = get_stack_optional<std::string>(j, "system_auth_detail");
        x.system_auth_forwarded_failures_per_window = get_stack_optional<int64_t>(j, "system_auth_forwarded_failures_per_window");
        x.system_auth_state = get_stack_optional<SystemAuthState>(j, "system_auth_state");
        x.ttl_bypass_detail = get_stack_optional<std::string>(j, "ttl_bypass_detail");
        x.ttl_bypass_state = get_stack_optional<TtlBypassState>(j, "ttl_bypass_state");
    }

    inline void to_json(json & j, const RoutingHealthResponse & x) {
        j = json::object();
        j["firewall"] = x.firewall;
        j["firewall_backend"] = x.firewall_backend;
        j["firewall_rules"] = x.firewall_rules;
        j["overall"] = x.overall;
        j["policy_rules"] = x.policy_rules;
        j["ppe_deoffload"] = x.ppe_deoffload;
        j["route_tables"] = x.route_tables;
        j["system_auth_detail"] = x.system_auth_detail;
        j["system_auth_forwarded_failures_per_window"] = x.system_auth_forwarded_failures_per_window;
        j["system_auth_state"] = x.system_auth_state;
        j["ttl_bypass_detail"] = x.ttl_bypass_detail;
        j["ttl_bypass_state"] = x.ttl_bypass_state;
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

    inline void from_json(const json & j, RoutingTestNfqwsMatchElement& x) {
        x.entry = j.at("entry").get<std::string>();
        x.exact = j.at("exact").get<bool>();
        x.includes = j.at("includes").get<bool>();
        x.list = j.at("list").get<std::string>();
        x.matched = j.at("matched").get<std::string>();
        x.role = j.at("role").get<RoutingTestNfqwsMatchRole>();
    }

    inline void to_json(json & j, const RoutingTestNfqwsMatchElement & x) {
        j = json::object();
        j["entry"] = x.entry;
        j["exact"] = x.exact;
        j["includes"] = x.includes;
        j["list"] = x.list;
        j["matched"] = x.matched;
        j["role"] = x.role;
    }

    inline void from_json(const json & j, RoutingTestNfqws& x) {
        x.available = j.at("available").get<bool>();
        x.matches = j.at("matches").get<std::vector<RoutingTestNfqwsMatchElement>>();
        x.reason = get_stack_optional<std::string>(j, "reason");
    }

    inline void to_json(json & j, const RoutingTestNfqws & x) {
        j = json::object();
        j["available"] = x.available;
        j["matches"] = x.matches;
        j["reason"] = x.reason;
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
        x.nfqws = get_stack_optional<RoutingTestNfqws>(j, "nfqws");
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
        j["nfqws"] = x.nfqws;
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

    inline void from_json(const json & j, SingBoxInstallCapability& x) {
        x.asset_architecture = get_stack_optional<std::string>(j, "asset_architecture");
        x.available = j.at("available").get<bool>();
        x.blockers = j.at("blockers").get<std::vector<Blocker>>();
        x.exact_rollback = j.at("exact_rollback").get<bool>();
        x.installed_version = get_stack_optional<std::string>(j, "installed_version");
        x.operation = j.at("operation").get<SingBoxInstallCapabilityOperation>();
        x.pinned_version = j.at("pinned_version").get<std::string>();
        x.running_transports = get_stack_optional<int64_t>(j, "running_transports");
        x.signed_release = j.at("signed_release").get<bool>();
        x.verified_archive_checksum = j.at("verified_archive_checksum").get<bool>();
    }

    inline void to_json(json & j, const SingBoxInstallCapability & x) {
        j = json::object();
        j["asset_architecture"] = x.asset_architecture;
        j["available"] = x.available;
        j["blockers"] = x.blockers;
        j["exact_rollback"] = x.exact_rollback;
        j["installed_version"] = x.installed_version;
        j["operation"] = x.operation;
        j["pinned_version"] = x.pinned_version;
        j["running_transports"] = x.running_transports;
        j["signed_release"] = x.signed_release;
        j["verified_archive_checksum"] = x.verified_archive_checksum;
    }

    inline void from_json(const json & j, SingBoxInstallRequest& x) {
        x.stop_running_transports = get_stack_optional<bool>(j, "stop_running_transports");
    }

    inline void to_json(json & j, const SingBoxInstallRequest & x) {
        j = json::object();
        j["stop_running_transports"] = x.stop_running_transports;
    }

    inline void from_json(const json & j, SingBoxInstallResult& x) {
        x.durable = get_stack_optional<bool>(j, "durable");
        x.install_outcome = j.at("install_outcome").get<InstallOutcome>();
        x.pinned_version = j.at("pinned_version").get<std::string>();
        x.release_verdict = get_stack_optional<ReleaseVerdict>(j, "release_verdict");
        x.staged_version = get_stack_optional<std::string>(j, "staged_version");
        x.stopped_transports = get_stack_optional<std::vector<std::string>>(j, "stopped_transports");
        x.transports_left_down = get_stack_optional<std::vector<std::string>>(j, "transports_left_down");
    }

    inline void to_json(json & j, const SingBoxInstallResult & x) {
        j = json::object();
        j["durable"] = x.durable;
        j["install_outcome"] = x.install_outcome;
        j["pinned_version"] = x.pinned_version;
        j["release_verdict"] = x.release_verdict;
        j["staged_version"] = x.staged_version;
        j["stopped_transports"] = x.stopped_transports;
        j["transports_left_down"] = x.transports_left_down;
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

    inline void from_json(const json & j, SubscriptionApplySelectionElement& x) {
        x.line = j.at("line").get<int64_t>();
        x.tag = get_stack_optional<std::string>(j, "tag");
    }

    inline void to_json(json & j, const SubscriptionApplySelectionElement & x) {
        j = json::object();
        j["line"] = x.line;
        j["tag"] = x.tag;
    }

    inline void from_json(const json & j, SubscriptionApplyRequest& x) {
        x.preview_id = j.at("preview_id").get<std::string>();
        x.selections = j.at("selections").get<std::vector<SubscriptionApplySelectionElement>>();
    }

    inline void to_json(json & j, const SubscriptionApplyRequest & x) {
        j = json::object();
        j["preview_id"] = x.preview_id;
        j["selections"] = x.selections;
    }

    inline void from_json(const json & j, SubscriptionApplyResultElement& x) {
        x.error = get_stack_optional<std::string>(j, "error");
        x.interface = get_stack_optional<std::string>(j, "interface");
        x.line = j.at("line").get<int64_t>();
        x.outcome = j.at("outcome").get<Outcome>();
        x.tag = get_stack_optional<std::string>(j, "tag");
    }

    inline void to_json(json & j, const SubscriptionApplyResultElement & x) {
        j = json::object();
        j["error"] = x.error;
        j["interface"] = x.interface;
        j["line"] = x.line;
        j["outcome"] = x.outcome;
        j["tag"] = x.tag;
    }

    inline void from_json(const json & j, SubscriptionApplyResponse& x) {
        x.results = j.at("results").get<std::vector<SubscriptionApplyResultElement>>();
    }

    inline void to_json(json & j, const SubscriptionApplyResponse & x) {
        j = json::object();
        j["results"] = x.results;
    }

    inline void from_json(const json & j, SubscriptionPreviewCandidate& x) {
        x.disposition = j.at("disposition").get<Disposition>();
        x.duplicate_of = get_stack_optional<int64_t>(j, "duplicate_of");
        x.endpoint = get_stack_optional<std::string>(j, "endpoint");
        x.line = j.at("line").get<int64_t>();
        x.remark = get_stack_optional<std::string>(j, "remark");
        x.scheme = get_stack_optional<std::string>(j, "scheme");
        x.suggested_tag = get_stack_optional<std::string>(j, "suggested_tag");
    }

    inline void to_json(json & j, const SubscriptionPreviewCandidate & x) {
        j = json::object();
        j["disposition"] = x.disposition;
        j["duplicate_of"] = x.duplicate_of;
        j["endpoint"] = x.endpoint;
        j["line"] = x.line;
        j["remark"] = x.remark;
        j["scheme"] = x.scheme;
        j["suggested_tag"] = x.suggested_tag;
    }

    inline void from_json(const json & j, SubscriptionPreviewRequest& x) {
        x.document = get_stack_optional<std::string>(j, "document");
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const SubscriptionPreviewRequest & x) {
        j = json::object();
        j["document"] = x.document;
        j["url"] = x.url;
    }

    inline void from_json(const json & j, SubscriptionPreviewResponse& x) {
        x.candidates = j.at("candidates").get<std::vector<SubscriptionPreviewCandidate>>();
        x.document_kind = j.at("document_kind").get<DocumentKind>();
        x.expires_in_seconds = j.at("expires_in_seconds").get<int64_t>();
        x.preview_id = j.at("preview_id").get<std::string>();
    }

    inline void to_json(json & j, const SubscriptionPreviewResponse & x) {
        j = json::object();
        j["candidates"] = x.candidates;
        j["document_kind"] = x.document_kind;
        j["expires_in_seconds"] = x.expires_in_seconds;
        j["preview_id"] = x.preview_id;
    }

    inline void from_json(const json & j, SystemUpdateLocalStatus& x) {
        x.log = j.at("log").get<std::string>();
        x.package_recovery_pending = j.at("package_recovery_pending").get<bool>();
        x.package_recovery_unknown = j.at("package_recovery_unknown").get<bool>();
        x.package_rescue_ready = j.at("package_rescue_ready").get<bool>();
        x.package_rollback_available = j.at("package_rollback_available").get<bool>();
        x.package_rollback_state = j.at("package_rollback_state").get<PackageRollbackState>();
        x.running = j.at("running").get<bool>();
    }

    inline void to_json(json & j, const SystemUpdateLocalStatus & x) {
        j = json::object();
        j["log"] = x.log;
        j["package_recovery_pending"] = x.package_recovery_pending;
        j["package_recovery_unknown"] = x.package_recovery_unknown;
        j["package_rescue_ready"] = x.package_rescue_ready;
        j["package_rollback_available"] = x.package_rollback_available;
        j["package_rollback_state"] = x.package_rollback_state;
        j["running"] = x.running;
    }

    inline void from_json(const json & j, SystemUpdateStatus& x) {
        x.log = j.at("log").get<std::string>();
        x.package_recovery_pending = j.at("package_recovery_pending").get<bool>();
        x.package_recovery_unknown = j.at("package_recovery_unknown").get<bool>();
        x.package_rescue_ready = j.at("package_rescue_ready").get<bool>();
        x.package_rollback_available = j.at("package_rollback_available").get<bool>();
        x.package_rollback_state = j.at("package_rollback_state").get<PackageRollbackState>();
        x.running = j.at("running").get<bool>();
        x.available = j.at("available").get<bool>();
        x.cached = j.at("cached").get<bool>();
        x.changelog_url = j.at("changelog_url").get<std::string>();
        x.check_error = j.at("check_error").get<std::string>();
        x.current = j.at("current").get<std::string>();
        x.current_ahead = j.at("current_ahead").get<bool>();
        x.latest = j.at("latest").get<std::string>();
        x.release_name = j.at("release_name").get<std::string>();
        x.release_notes = j.at("release_notes").get<std::string>();
        x.release_url = j.at("release_url").get<std::string>();
    }

    inline void to_json(json & j, const SystemUpdateStatus & x) {
        j = json::object();
        j["log"] = x.log;
        j["package_recovery_pending"] = x.package_recovery_pending;
        j["package_recovery_unknown"] = x.package_recovery_unknown;
        j["package_rescue_ready"] = x.package_rescue_ready;
        j["package_rollback_available"] = x.package_rollback_available;
        j["package_rollback_state"] = x.package_rollback_state;
        j["running"] = x.running;
        j["available"] = x.available;
        j["cached"] = x.cached;
        j["changelog_url"] = x.changelog_url;
        j["check_error"] = x.check_error;
        j["current"] = x.current;
        j["current_ahead"] = x.current_ahead;
        j["latest"] = x.latest;
        j["release_name"] = x.release_name;
        j["release_notes"] = x.release_notes;
        j["release_url"] = x.release_url;
    }

    inline void from_json(const json & j, TransportActionRequest& x) {
        x.action = j.at("action").get<TransportActionRequestAction>();
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

    inline void from_json(const json & j, TransportExitCheckProbe& x) {
        x.address = j.at("address").get<std::string>();
        x.attributed = j.at("attributed").get<bool>();
        x.error = j.at("error").get<std::string>();
        x.latency_ms = j.at("latency_ms").get<int64_t>();
        x.ok = j.at("ok").get<bool>();
    }

    inline void to_json(json & j, const TransportExitCheckProbe & x) {
        j = json::object();
        j["address"] = x.address;
        j["attributed"] = x.attributed;
        j["error"] = x.error;
        j["latency_ms"] = x.latency_ms;
        j["ok"] = x.ok;
    }

    inline void from_json(const json & j, TransportExitCheckRequest& x) {
        x.interface = get_stack_optional<std::string>(j, "interface");
        x.outbound = get_stack_optional<std::string>(j, "outbound");
    }

    inline void to_json(json & j, const TransportExitCheckRequest & x) {
        j = json::object();
        j["interface"] = x.interface;
        j["outbound"] = x.outbound;
    }

    inline void from_json(const json & j, TransportExitCheckResponse& x) {
        x.direct = j.at("direct").get<TransportExitCheckProbe>();
        x.exit_address = j.at("exit_address").get<ExitAddress>();
        x.outbound = j.at("outbound").get<std::string>();
        x.through = j.at("through").get<TransportExitCheckProbe>();
        x.verdict = j.at("verdict").get<Verdict>();
    }

    inline void to_json(json & j, const TransportExitCheckResponse & x) {
        j = json::object();
        j["direct"] = x.direct;
        j["exit_address"] = x.exit_address;
        j["outbound"] = x.outbound;
        j["through"] = x.through;
        j["verdict"] = x.verdict;
    }

    inline void from_json(const json & j, TransportManagerSettings& x) {
        x.restart_required = j.at("restart_required").get<bool>();
        x.running_sing_box_process_mode = j.at("running_sing_box_process_mode").get<SingBoxProcessMode>();
        x.runtime_ready = j.at("runtime_ready").get<bool>();
        x.sing_box_process_mode = j.at("sing_box_process_mode").get<SingBoxProcessMode>();
    }

    inline void to_json(json & j, const TransportManagerSettings & x) {
        j = json::object();
        j["restart_required"] = x.restart_required;
        j["running_sing_box_process_mode"] = x.running_sing_box_process_mode;
        j["runtime_ready"] = x.runtime_ready;
        j["sing_box_process_mode"] = x.sing_box_process_mode;
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

    inline void from_json(const json & j, TransportProcessModeRequest& x) {
        x.sing_box_process_mode = j.at("sing_box_process_mode").get<SingBoxProcessMode>();
    }

    inline void to_json(json & j, const TransportProcessModeRequest & x) {
        j = json::object();
        j["sing_box_process_mode"] = x.sing_box_process_mode;
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

    inline void from_json(const json & j, TransportsEnvironment& x) {
        x.pinned_version = j.at("pinned_version").get<std::string>();
        x.sing_box_binary = j.at("sing_box_binary").get<std::string>();
        x.sing_box_installed = j.at("sing_box_installed").get<bool>();
        x.tested_version = j.at("tested_version").get<std::string>();
        x.transport_api_version = j.at("transport_api_version").get<int64_t>();
    }

    inline void to_json(json & j, const TransportsEnvironment & x) {
        j = json::object();
        j["pinned_version"] = x.pinned_version;
        j["sing_box_binary"] = x.sing_box_binary;
        j["sing_box_installed"] = x.sing_box_installed;
        j["tested_version"] = x.tested_version;
        j["transport_api_version"] = x.transport_api_version;
    }

    inline void from_json(const json & j, UpdateStartedResponse& x) {
        x.ok = j.at("ok").get<bool>();
        x.started = j.at("started").get<bool>();
    }

    inline void to_json(json & j, const UpdateStartedResponse & x) {
        j = json::object();
        j["ok"] = x.ok;
        j["started"] = x.started;
    }

    inline void from_json(const json & j, ApiTypes& x) {
        x.api_config = get_stack_optional<ApiConfig>(j, "ApiConfig");
        x.auth_credentials = get_stack_optional<AuthCredentials>(j, "AuthCredentials");
        x.authenticated_response = get_stack_optional<AuthenticatedResponse>(j, "AuthenticatedResponse");
        x.auth_settings_request = get_stack_optional<AuthSettingsRequest>(j, "AuthSettingsRequest");
        x.auth_settings_response = get_stack_optional<AuthSettingsResponse>(j, "AuthSettingsResponse");
        x.auth_status = get_stack_optional<AuthStatus>(j, "AuthStatus");
        x.backup_document = get_stack_optional<BackupDocument>(j, "BackupDocument");
        x.backup_group_selection = get_stack_optional<Groups>(j, "BackupGroupSelection");
        x.backup_read_request = get_stack_optional<BackupReadRequest>(j, "BackupReadRequest");
        x.backup_rollback_availability = get_stack_optional<BackupRollbackAvailability>(j, "BackupRollbackAvailability");
        x.cache_generation = get_stack_optional<CacheGeneration>(j, "CacheGeneration");
        x.cache_metadata = get_stack_optional<CacheMetadata>(j, "CacheMetadata");
        x.catalog_preset_selection = get_stack_optional<CatalogPresetSelection>(j, "CatalogPresetSelection");
        x.catalog_refresh_request = get_stack_optional<CatalogRefreshRequest>(j, "CatalogRefreshRequest");
        x.catalog_refresh_result = get_stack_optional<CatalogRefreshResult>(j, "CatalogRefreshResult");
        x.catalog_setup_apply_request = get_stack_optional<CatalogSetupApplyRequest>(j, "CatalogSetupApplyRequest");
        x.catalog_setup_apply_response = get_stack_optional<CatalogSetupApplyResponse>(j, "CatalogSetupApplyResponse");
        x.catalog_setup_blackhole_summary = get_stack_optional<CatalogSetupBlackholeSummary>(j, "CatalogSetupBlackholeSummary");
        x.catalog_setup_direct_outbound_summary = get_stack_optional<CatalogSetupDirectOutboundSummary>(j, "CatalogSetupDirectOutboundSummary");
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
        x.connection_entry = get_stack_optional<ConnectionEntry>(j, "ConnectionEntry");
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
        x.geo_location = get_stack_optional<GeoLocation>(j, "GeoLocation");
        x.geo_lookup_request = get_stack_optional<GeoLookupRequest>(j, "GeoLookupRequest");
        x.geo_lookup_result = get_stack_optional<GeoLookupResult>(j, "GeoLookupResult");
        x.granted_response = get_stack_optional<GrantedResponse>(j, "GrantedResponse");
        x.health_response = get_stack_optional<HealthResponse>(j, "HealthResponse");
        x.interface_names = get_stack_optional<InterfaceNames>(j, "InterfaceNames");
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
        x.log_level = get_stack_optional<LogLevel>(j, "LogLevel");
        x.log_settings = get_stack_optional<LogSettings>(j, "LogSettings");
        x.log_settings_request = get_stack_optional<LogSettingsRequest>(j, "LogSettingsRequest");
        x.log_settings_result = get_stack_optional<LogSettingsResult>(j, "LogSettingsResult");
        x.log_tail = get_stack_optional<LogTail>(j, "LogTail");
        x.naive_component_install_result = get_stack_optional<NaiveComponentInstallResult>(j, "NaiveComponentInstallResult");
        x.naive_component_state = get_stack_optional<NaiveComponentState>(j, "NaiveComponentState");
        x.ndms_catalog_status = get_stack_optional<CatalogStatus>(j, "NdmsCatalogStatus");
        x.ndms_interface_capabilities = get_stack_optional<NdmsInterfaceCapabilities>(j, "NdmsInterfaceCapabilities");
        x.ndms_interface_inventory_response = get_stack_optional<NdmsInterfaceInventoryResponse>(j, "NdmsInterfaceInventoryResponse");
        x.ndms_interface_management_readiness = get_stack_optional<NdmsInterfaceManagementReadiness>(j, "NdmsInterfaceManagementReadiness");
        x.ndms_interface_role = get_stack_optional<NdmsInterfaceRoleEnum>(j, "NdmsInterfaceRole");
        x.ndms_management_blocker = get_stack_optional<NdmsManagementBlockerElement>(j, "NdmsManagementBlocker");
        x.ndms_native_delete_journal_state = get_stack_optional<ObservedDeleteJournalState>(j, "NdmsNativeDeleteJournalState");
        x.ndms_native_delete_phase = get_stack_optional<NdmsNativeDeletePhase>(j, "NdmsNativeDeletePhase");
        x.ndms_native_delete_request = get_stack_optional<NdmsNativeDeleteRequest>(j, "NdmsNativeDeleteRequest");
        x.ndms_native_delete_response = get_stack_optional<NdmsNativeDeleteResponse>(j, "NdmsNativeDeleteResponse");
        x.ndms_native_delete_status = get_stack_optional<NdmsNativeDeleteStatus>(j, "NdmsNativeDeleteStatus");
        x.ndms_native_delete_stop = get_stack_optional<NdmsNativeDeleteStop>(j, "NdmsNativeDeleteStop");
        x.ndms_native_delete_transport_outcome = get_stack_optional<NdmsNativeDeleteTransportOutcome>(j, "NdmsNativeDeleteTransportOutcome");
        x.ndms_native_direct_observation_failure = get_stack_optional<NdmsNativeDirectObservationFailure>(j, "NdmsNativeDirectObservationFailure");
        x.ndms_native_import_preflight_response = get_stack_optional<NdmsNativeImportPreflightResponse>(j, "NdmsNativeImportPreflightResponse");
        x.ndms_native_import_readiness = get_stack_optional<NdmsNativeImportReadiness>(j, "NdmsNativeImportReadiness");
        x.ndms_native_import_readiness_journal_state = get_stack_optional<NdmsNativeImportJournalState>(j, "NdmsNativeImportReadinessJournalState");
        x.ndms_native_import_recovery_action = get_stack_optional<NdmsNativeImportRecoveryAction>(j, "NdmsNativeImportRecoveryAction");
        x.ndms_native_import_recovery_admission_state = get_stack_optional<NdmsNativeImportRecoveryAdmissionState>(j, "NdmsNativeImportRecoveryAdmissionState");
        x.ndms_native_import_recovery_dispatch_state = get_stack_optional<NdmsNativeImportRecoveryDispatchState>(j, "NdmsNativeImportRecoveryDispatchState");
        x.ndms_native_import_recovery_phase = get_stack_optional<NdmsNativeImportRecoveryPhase>(j, "NdmsNativeImportRecoveryPhase");
        x.ndms_native_import_recovery_response = get_stack_optional<NdmsNativeImportRecoveryResponse>(j, "NdmsNativeImportRecoveryResponse");
        x.ndms_native_import_recovery_status = get_stack_optional<NdmsNativeImportRecoveryStatus>(j, "NdmsNativeImportRecoveryStatus");
        x.ndms_native_import_recovery_step = get_stack_optional<NdmsNativeImportRecoveryStep>(j, "NdmsNativeImportRecoveryStep");
        x.ndms_native_import_recovery_stop = get_stack_optional<NdmsNativeImportRecoveryStop>(j, "NdmsNativeImportRecoveryStop");
        x.ndms_native_import_response = get_stack_optional<NdmsNativeImportResponse>(j, "NdmsNativeImportResponse");
        x.ndms_native_import_status = get_stack_optional<NdmsNativeImportStatus>(j, "NdmsNativeImportStatus");
        x.ndms_native_import_stop = get_stack_optional<NdmsNativeImportStop>(j, "NdmsNativeImportStop");
        x.ndms_native_import_target_range = get_stack_optional<NdmsNativeImportTargetRange>(j, "NdmsNativeImportTargetRange");
        x.ndms_native_interface_mutation_projection = get_stack_optional<NativeMutation>(j, "NdmsNativeInterfaceMutationProjection");
        x.ndms_native_inventory_deferred_delete_check = get_stack_optional<NdmsNativeInventoryDeferredDeleteCheckElement>(j, "NdmsNativeInventoryDeferredDeleteCheck");
        x.ndms_native_inventory_delete_blocker = get_stack_optional<NdmsNativeInventoryDeleteBlockerElement>(j, "NdmsNativeInventoryDeleteBlocker");
        x.ndms_native_inventory_ownership_state = get_stack_optional<OwnershipState>(j, "NdmsNativeInventoryOwnershipState");
        x.ndms_native_kernel_interface_name = get_stack_optional<std::string>(j, "NdmsNativeKernelInterfaceName");
        x.ndms_native_managed_interface_name = get_stack_optional<std::string>(j, "NdmsNativeManagedInterfaceName");
        x.ndms_native_mutation_inventory_status = get_stack_optional<NativeMutationStatus>(j, "NdmsNativeMutationInventoryStatus");
        x.ndms_native_mutation_kind = get_stack_optional<NdmsNativeMutationKind>(j, "NdmsNativeMutationKind");
        x.ndms_native_ownership_lifecycle = get_stack_optional<OwnershipLifecycle>(j, "NdmsNativeOwnershipLifecycle");
        x.ndms_native_retained_deletion = get_stack_optional<NdmsNativeRetainedDeletionElement>(j, "NdmsNativeRetainedDeletion");
        x.ndms_native_retained_deletion_blocker = get_stack_optional<NdmsNativeRetainedDeletionBlockerElement>(j, "NdmsNativeRetainedDeletionBlocker");
        x.ndms_native_retained_deletion_deferred_check = get_stack_optional<NdmsNativeRetainedDeletionDeferredCheckElement>(j, "NdmsNativeRetainedDeletionDeferredCheck");
        x.ndms_native_tombstone_forget_artifact_state = get_stack_optional<NdmsNativeTombstoneForgetArtifactState>(j, "NdmsNativeTombstoneForgetArtifactState");
        x.ndms_native_tombstone_forget_request = get_stack_optional<NdmsNativeTombstoneForgetRequest>(j, "NdmsNativeTombstoneForgetRequest");
        x.ndms_native_tombstone_forget_response = get_stack_optional<NdmsNativeTombstoneForgetResponse>(j, "NdmsNativeTombstoneForgetResponse");
        x.ndms_native_tombstone_forget_status = get_stack_optional<NdmsNativeTombstoneForgetStatus>(j, "NdmsNativeTombstoneForgetStatus");
        x.ndms_native_tombstone_forget_stop = get_stack_optional<NdmsNativeTombstoneForgetStop>(j, "NdmsNativeTombstoneForgetStop");
        x.ndms_native_wal_readiness = get_stack_optional<NdmsNativeWalReadiness>(j, "NdmsNativeWalReadiness");
        x.ndms_tunnel_interface = get_stack_optional<NdmsTunnelInterfaceElement>(j, "NdmsTunnelInterface");
        x.ndms_tunnel_kind = get_stack_optional<NdmsTunnelKindEnum>(j, "NdmsTunnelKind");
        x.ndms_vpn_server_kind = get_stack_optional<NdmsVpnServerKind>(j, "NdmsVpnServerKind");
        x.ndms_vpn_server_service = get_stack_optional<NdmsVpnServerService>(j, "NdmsVpnServerService");
        x.ndms_vpn_server_service_inventory_response = get_stack_optional<NdmsVpnServerServiceInventoryResponse>(j, "NdmsVpnServerServiceInventoryResponse");
        x.nfqws_action_request = get_stack_optional<NfqwsActionRequest>(j, "NfqwsActionRequest");
        x.nfqws_action_result = get_stack_optional<NfqwsActionResult>(j, "NfqwsActionResult");
        x.nfqws_file_entry = get_stack_optional<NfqwsFileEntryElement>(j, "NfqwsFileEntry");
        x.nfqws_status = get_stack_optional<NfqwsStatus>(j, "NfqwsStatus");
        x.ok_response = get_stack_optional<OkResponse>(j, "OkResponse");
        x.outbound = get_stack_optional<OutboundElement>(j, "Outbound");
        x.outbound_group = get_stack_optional<OutboundGroupElement>(j, "OutboundGroup");
        x.periodic_task_metrics_entry = get_stack_optional<PeriodicTaskMetricsEntry>(j, "PeriodicTaskMetricsEntry");
        x.periodic_task_metrics_response = get_stack_optional<PeriodicTaskMetricsResponse>(j, "PeriodicTaskMetricsResponse");
        x.periodic_task_outcome = get_stack_optional<LastOutcome>(j, "PeriodicTaskOutcome");
        x.plain_dns_template = get_stack_optional<PlainDnsTemplateElement>(j, "PlainDnsTemplate");
        x.policy_rule_check = get_stack_optional<PolicyRuleCheck>(j, "PolicyRuleCheck");
        x.ppe_deoffload_capability = get_stack_optional<PpeDeoffloadCapability>(j, "PpeDeoffloadCapability");
        x.ppe_deoffload_counter = get_stack_optional<PpeDeoffloadCounter>(j, "PpeDeoffloadCounter");
        x.ppe_deoffload_health = get_stack_optional<PpeDeoffloadHealth>(j, "PpeDeoffloadHealth");
        x.ppe_deoffload_mode = get_stack_optional<PpeDeoffloadMode>(j, "PpeDeoffloadMode");
        x.ppe_deoffload_protocol_health = get_stack_optional<PpeDeoffloadProtocolHealth>(j, "PpeDeoffloadProtocolHealth");
        x.recommended_list_setup_request = get_stack_optional<RecommendedListSetupRequest>(j, "RecommendedListSetupRequest");
        x.registry_check_request = get_stack_optional<RegistryCheckRequest>(j, "RegistryCheckRequest");
        x.registry_check_response = get_stack_optional<RegistryCheckResponse>(j, "RegistryCheckResponse");
        x.registry_consent_request = get_stack_optional<RegistryConsentRequest>(j, "RegistryConsentRequest");
        x.registry_consent_response = get_stack_optional<RegistryConsentResponse>(j, "RegistryConsentResponse");
        x.reload_response = get_stack_optional<ReloadResponse>(j, "ReloadResponse");
        x.remote_access_request = get_stack_optional<RemoteAccessRequest>(j, "RemoteAccessRequest");
        x.remote_access_result = get_stack_optional<RemoteAccessResult>(j, "RemoteAccessResult");
        x.remote_access_runtime = get_stack_optional<RemoteAccessRuntime>(j, "RemoteAccessRuntime");
        x.remote_access_settings = get_stack_optional<Settings>(j, "RemoteAccessSettings");
        x.remote_access_state = get_stack_optional<RemoteAccessState>(j, "RemoteAccessState");
        x.resolver_config_probe_status = get_stack_optional<ResolverConfigProbeStatus>(j, "ResolverConfigProbeStatus");
        x.resolver_config_sync_state = get_stack_optional<ResolverConfigSyncState>(j, "ResolverConfigSyncState");
        x.retry_config = get_stack_optional<Retry>(j, "RetryConfig");
        x.route_config = get_stack_optional<Route>(j, "RouteConfig");
        x.router_info = get_stack_optional<RouterInfo>(j, "RouterInfo");
        x.route_rule = get_stack_optional<RouteRuleElement>(j, "RouteRule");
        x.route_table_check = get_stack_optional<RouteTableCheck>(j, "RouteTableCheck");
        x.routing_health_error_response = get_stack_optional<RoutingHealthErrorResponse>(j, "RoutingHealthErrorResponse");
        x.routing_health_response = get_stack_optional<RoutingHealthResponse>(j, "RoutingHealthResponse");
        x.routing_test_entry = get_stack_optional<RoutingTestEntry>(j, "RoutingTestEntry");
        x.routing_test_evaluation = get_stack_optional<Evaluation>(j, "RoutingTestEvaluation");
        x.routing_test_list_match = get_stack_optional<ListMatch>(j, "RoutingTestListMatch");
        x.routing_test_nfqws = get_stack_optional<RoutingTestNfqws>(j, "RoutingTestNfqws");
        x.routing_test_nfqws_match = get_stack_optional<RoutingTestNfqwsMatchElement>(j, "RoutingTestNfqwsMatch");
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
        x.sing_box_install_capability = get_stack_optional<SingBoxInstallCapability>(j, "SingBoxInstallCapability");
        x.sing_box_install_request = get_stack_optional<SingBoxInstallRequest>(j, "SingBoxInstallRequest");
        x.sing_box_install_result = get_stack_optional<SingBoxInstallResult>(j, "SingBoxInstallResult");
        x.sing_box_process_mode = get_stack_optional<SingBoxProcessMode>(j, "SingBoxProcessMode");
        x.sort_order = get_stack_optional<SortOrder>(j, "SortOrder");
        x.status_event_connections = get_stack_optional<StatusEventConnections>(j, "StatusEventConnections");
        x.status_event_interfaces = get_stack_optional<StatusEventInterfaces>(j, "StatusEventInterfaces");
        x.status_event_interface_traffic = get_stack_optional<StatusEventInterfaceTraffic>(j, "StatusEventInterfaceTraffic");
        x.status_event_outbounds = get_stack_optional<StatusEventOutbounds>(j, "StatusEventOutbounds");
        x.status_event_service = get_stack_optional<StatusEventService>(j, "StatusEventService");
        x.status_event_snapshot = get_stack_optional<StatusEventSnapshot>(j, "StatusEventSnapshot");
        x.subscription_apply_request = get_stack_optional<SubscriptionApplyRequest>(j, "SubscriptionApplyRequest");
        x.subscription_apply_response = get_stack_optional<SubscriptionApplyResponse>(j, "SubscriptionApplyResponse");
        x.subscription_apply_result = get_stack_optional<SubscriptionApplyResultElement>(j, "SubscriptionApplyResult");
        x.subscription_apply_selection = get_stack_optional<SubscriptionApplySelectionElement>(j, "SubscriptionApplySelection");
        x.subscription_preview_candidate = get_stack_optional<SubscriptionPreviewCandidate>(j, "SubscriptionPreviewCandidate");
        x.subscription_preview_request = get_stack_optional<SubscriptionPreviewRequest>(j, "SubscriptionPreviewRequest");
        x.subscription_preview_response = get_stack_optional<SubscriptionPreviewResponse>(j, "SubscriptionPreviewResponse");
        x.system_update_local_status = get_stack_optional<SystemUpdateLocalStatus>(j, "SystemUpdateLocalStatus");
        x.system_update_status = get_stack_optional<SystemUpdateStatus>(j, "SystemUpdateStatus");
        x.transport_action_request = get_stack_optional<TransportActionRequest>(j, "TransportActionRequest");
        x.transport_action_response = get_stack_optional<TransportActionResponse>(j, "TransportActionResponse");
        x.transport_config_apply_request = get_stack_optional<TransportConfigApplyRequest>(j, "TransportConfigApplyRequest");
        x.transport_config_apply_response = get_stack_optional<TransportConfigApplyResponse>(j, "TransportConfigApplyResponse");
        x.transport_config_operation = get_stack_optional<TransportConfigOperation>(j, "TransportConfigOperation");
        x.transport_config_response = get_stack_optional<TransportConfigResponse>(j, "TransportConfigResponse");
        x.transport_exit_check_probe = get_stack_optional<TransportExitCheckProbe>(j, "TransportExitCheckProbe");
        x.transport_exit_check_request = get_stack_optional<TransportExitCheckRequest>(j, "TransportExitCheckRequest");
        x.transport_exit_check_response = get_stack_optional<TransportExitCheckResponse>(j, "TransportExitCheckResponse");
        x.transport_linked_outbound_ensure = get_stack_optional<LinkedOutbound>(j, "TransportLinkedOutboundEnsure");
        x.transport_manager_settings = get_stack_optional<TransportManagerSettings>(j, "TransportManagerSettings");
        x.transport_path = get_stack_optional<TransportPath>(j, "TransportPath");
        x.transport_process_mode_request = get_stack_optional<TransportProcessModeRequest>(j, "TransportProcessModeRequest");
        x.transports_environment = get_stack_optional<TransportsEnvironment>(j, "TransportsEnvironment");
        x.transport_spec = get_stack_optional<Transport>(j, "TransportSpec");
        x.transport_status = get_stack_optional<TransportStatus>(j, "TransportStatus");
        x.tunnel_probe_config = get_stack_optional<TunnelProbe>(j, "TunnelProbeConfig");
        x.ui_preferences_config = get_stack_optional<UiPreferences>(j, "UiPreferencesConfig");
        x.update_started_response = get_stack_optional<UpdateStartedResponse>(j, "UpdateStartedResponse");
        x.validation_error = get_stack_optional<ValidationErrorElement>(j, "ValidationError");
        x.vless_reality_spec = get_stack_optional<Vless>(j, "VlessRealitySpec");
    }

    inline void to_json(json & j, const ApiTypes & x) {
        j = json::object();
        j["ApiConfig"] = x.api_config;
        j["AuthCredentials"] = x.auth_credentials;
        j["AuthenticatedResponse"] = x.authenticated_response;
        j["AuthSettingsRequest"] = x.auth_settings_request;
        j["AuthSettingsResponse"] = x.auth_settings_response;
        j["AuthStatus"] = x.auth_status;
        j["BackupDocument"] = x.backup_document;
        j["BackupGroupSelection"] = x.backup_group_selection;
        j["BackupReadRequest"] = x.backup_read_request;
        j["BackupRollbackAvailability"] = x.backup_rollback_availability;
        j["CacheGeneration"] = x.cache_generation;
        j["CacheMetadata"] = x.cache_metadata;
        j["CatalogPresetSelection"] = x.catalog_preset_selection;
        j["CatalogRefreshRequest"] = x.catalog_refresh_request;
        j["CatalogRefreshResult"] = x.catalog_refresh_result;
        j["CatalogSetupApplyRequest"] = x.catalog_setup_apply_request;
        j["CatalogSetupApplyResponse"] = x.catalog_setup_apply_response;
        j["CatalogSetupBlackholeSummary"] = x.catalog_setup_blackhole_summary;
        j["CatalogSetupDirectOutboundSummary"] = x.catalog_setup_direct_outbound_summary;
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
        j["ConnectionEntry"] = x.connection_entry;
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
        j["GeoLocation"] = x.geo_location;
        j["GeoLookupRequest"] = x.geo_lookup_request;
        j["GeoLookupResult"] = x.geo_lookup_result;
        j["GrantedResponse"] = x.granted_response;
        j["HealthResponse"] = x.health_response;
        j["InterfaceNames"] = x.interface_names;
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
        j["LogLevel"] = x.log_level;
        j["LogSettings"] = x.log_settings;
        j["LogSettingsRequest"] = x.log_settings_request;
        j["LogSettingsResult"] = x.log_settings_result;
        j["LogTail"] = x.log_tail;
        j["NaiveComponentInstallResult"] = x.naive_component_install_result;
        j["NaiveComponentState"] = x.naive_component_state;
        j["NdmsCatalogStatus"] = x.ndms_catalog_status;
        j["NdmsInterfaceCapabilities"] = x.ndms_interface_capabilities;
        j["NdmsInterfaceInventoryResponse"] = x.ndms_interface_inventory_response;
        j["NdmsInterfaceManagementReadiness"] = x.ndms_interface_management_readiness;
        j["NdmsInterfaceRole"] = x.ndms_interface_role;
        j["NdmsManagementBlocker"] = x.ndms_management_blocker;
        j["NdmsNativeDeleteJournalState"] = x.ndms_native_delete_journal_state;
        j["NdmsNativeDeletePhase"] = x.ndms_native_delete_phase;
        j["NdmsNativeDeleteRequest"] = x.ndms_native_delete_request;
        j["NdmsNativeDeleteResponse"] = x.ndms_native_delete_response;
        j["NdmsNativeDeleteStatus"] = x.ndms_native_delete_status;
        j["NdmsNativeDeleteStop"] = x.ndms_native_delete_stop;
        j["NdmsNativeDeleteTransportOutcome"] = x.ndms_native_delete_transport_outcome;
        j["NdmsNativeDirectObservationFailure"] = x.ndms_native_direct_observation_failure;
        j["NdmsNativeImportPreflightResponse"] = x.ndms_native_import_preflight_response;
        j["NdmsNativeImportReadiness"] = x.ndms_native_import_readiness;
        j["NdmsNativeImportReadinessJournalState"] = x.ndms_native_import_readiness_journal_state;
        j["NdmsNativeImportRecoveryAction"] = x.ndms_native_import_recovery_action;
        j["NdmsNativeImportRecoveryAdmissionState"] = x.ndms_native_import_recovery_admission_state;
        j["NdmsNativeImportRecoveryDispatchState"] = x.ndms_native_import_recovery_dispatch_state;
        j["NdmsNativeImportRecoveryPhase"] = x.ndms_native_import_recovery_phase;
        j["NdmsNativeImportRecoveryResponse"] = x.ndms_native_import_recovery_response;
        j["NdmsNativeImportRecoveryStatus"] = x.ndms_native_import_recovery_status;
        j["NdmsNativeImportRecoveryStep"] = x.ndms_native_import_recovery_step;
        j["NdmsNativeImportRecoveryStop"] = x.ndms_native_import_recovery_stop;
        j["NdmsNativeImportResponse"] = x.ndms_native_import_response;
        j["NdmsNativeImportStatus"] = x.ndms_native_import_status;
        j["NdmsNativeImportStop"] = x.ndms_native_import_stop;
        j["NdmsNativeImportTargetRange"] = x.ndms_native_import_target_range;
        j["NdmsNativeInterfaceMutationProjection"] = x.ndms_native_interface_mutation_projection;
        j["NdmsNativeInventoryDeferredDeleteCheck"] = x.ndms_native_inventory_deferred_delete_check;
        j["NdmsNativeInventoryDeleteBlocker"] = x.ndms_native_inventory_delete_blocker;
        j["NdmsNativeInventoryOwnershipState"] = x.ndms_native_inventory_ownership_state;
        j["NdmsNativeKernelInterfaceName"] = x.ndms_native_kernel_interface_name;
        j["NdmsNativeManagedInterfaceName"] = x.ndms_native_managed_interface_name;
        j["NdmsNativeMutationInventoryStatus"] = x.ndms_native_mutation_inventory_status;
        j["NdmsNativeMutationKind"] = x.ndms_native_mutation_kind;
        j["NdmsNativeOwnershipLifecycle"] = x.ndms_native_ownership_lifecycle;
        j["NdmsNativeRetainedDeletion"] = x.ndms_native_retained_deletion;
        j["NdmsNativeRetainedDeletionBlocker"] = x.ndms_native_retained_deletion_blocker;
        j["NdmsNativeRetainedDeletionDeferredCheck"] = x.ndms_native_retained_deletion_deferred_check;
        j["NdmsNativeTombstoneForgetArtifactState"] = x.ndms_native_tombstone_forget_artifact_state;
        j["NdmsNativeTombstoneForgetRequest"] = x.ndms_native_tombstone_forget_request;
        j["NdmsNativeTombstoneForgetResponse"] = x.ndms_native_tombstone_forget_response;
        j["NdmsNativeTombstoneForgetStatus"] = x.ndms_native_tombstone_forget_status;
        j["NdmsNativeTombstoneForgetStop"] = x.ndms_native_tombstone_forget_stop;
        j["NdmsNativeWalReadiness"] = x.ndms_native_wal_readiness;
        j["NdmsTunnelInterface"] = x.ndms_tunnel_interface;
        j["NdmsTunnelKind"] = x.ndms_tunnel_kind;
        j["NdmsVpnServerKind"] = x.ndms_vpn_server_kind;
        j["NdmsVpnServerService"] = x.ndms_vpn_server_service;
        j["NdmsVpnServerServiceInventoryResponse"] = x.ndms_vpn_server_service_inventory_response;
        j["NfqwsActionRequest"] = x.nfqws_action_request;
        j["NfqwsActionResult"] = x.nfqws_action_result;
        j["NfqwsFileEntry"] = x.nfqws_file_entry;
        j["NfqwsStatus"] = x.nfqws_status;
        j["OkResponse"] = x.ok_response;
        j["Outbound"] = x.outbound;
        j["OutboundGroup"] = x.outbound_group;
        j["PeriodicTaskMetricsEntry"] = x.periodic_task_metrics_entry;
        j["PeriodicTaskMetricsResponse"] = x.periodic_task_metrics_response;
        j["PeriodicTaskOutcome"] = x.periodic_task_outcome;
        j["PlainDnsTemplate"] = x.plain_dns_template;
        j["PolicyRuleCheck"] = x.policy_rule_check;
        j["PpeDeoffloadCapability"] = x.ppe_deoffload_capability;
        j["PpeDeoffloadCounter"] = x.ppe_deoffload_counter;
        j["PpeDeoffloadHealth"] = x.ppe_deoffload_health;
        j["PpeDeoffloadMode"] = x.ppe_deoffload_mode;
        j["PpeDeoffloadProtocolHealth"] = x.ppe_deoffload_protocol_health;
        j["RecommendedListSetupRequest"] = x.recommended_list_setup_request;
        j["RegistryCheckRequest"] = x.registry_check_request;
        j["RegistryCheckResponse"] = x.registry_check_response;
        j["RegistryConsentRequest"] = x.registry_consent_request;
        j["RegistryConsentResponse"] = x.registry_consent_response;
        j["ReloadResponse"] = x.reload_response;
        j["RemoteAccessRequest"] = x.remote_access_request;
        j["RemoteAccessResult"] = x.remote_access_result;
        j["RemoteAccessRuntime"] = x.remote_access_runtime;
        j["RemoteAccessSettings"] = x.remote_access_settings;
        j["RemoteAccessState"] = x.remote_access_state;
        j["ResolverConfigProbeStatus"] = x.resolver_config_probe_status;
        j["ResolverConfigSyncState"] = x.resolver_config_sync_state;
        j["RetryConfig"] = x.retry_config;
        j["RouteConfig"] = x.route_config;
        j["RouterInfo"] = x.router_info;
        j["RouteRule"] = x.route_rule;
        j["RouteTableCheck"] = x.route_table_check;
        j["RoutingHealthErrorResponse"] = x.routing_health_error_response;
        j["RoutingHealthResponse"] = x.routing_health_response;
        j["RoutingTestEntry"] = x.routing_test_entry;
        j["RoutingTestEvaluation"] = x.routing_test_evaluation;
        j["RoutingTestListMatch"] = x.routing_test_list_match;
        j["RoutingTestNfqws"] = x.routing_test_nfqws;
        j["RoutingTestNfqwsMatch"] = x.routing_test_nfqws_match;
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
        j["SingBoxInstallCapability"] = x.sing_box_install_capability;
        j["SingBoxInstallRequest"] = x.sing_box_install_request;
        j["SingBoxInstallResult"] = x.sing_box_install_result;
        j["SingBoxProcessMode"] = x.sing_box_process_mode;
        j["SortOrder"] = x.sort_order;
        j["StatusEventConnections"] = x.status_event_connections;
        j["StatusEventInterfaces"] = x.status_event_interfaces;
        j["StatusEventInterfaceTraffic"] = x.status_event_interface_traffic;
        j["StatusEventOutbounds"] = x.status_event_outbounds;
        j["StatusEventService"] = x.status_event_service;
        j["StatusEventSnapshot"] = x.status_event_snapshot;
        j["SubscriptionApplyRequest"] = x.subscription_apply_request;
        j["SubscriptionApplyResponse"] = x.subscription_apply_response;
        j["SubscriptionApplyResult"] = x.subscription_apply_result;
        j["SubscriptionApplySelection"] = x.subscription_apply_selection;
        j["SubscriptionPreviewCandidate"] = x.subscription_preview_candidate;
        j["SubscriptionPreviewRequest"] = x.subscription_preview_request;
        j["SubscriptionPreviewResponse"] = x.subscription_preview_response;
        j["SystemUpdateLocalStatus"] = x.system_update_local_status;
        j["SystemUpdateStatus"] = x.system_update_status;
        j["TransportActionRequest"] = x.transport_action_request;
        j["TransportActionResponse"] = x.transport_action_response;
        j["TransportConfigApplyRequest"] = x.transport_config_apply_request;
        j["TransportConfigApplyResponse"] = x.transport_config_apply_response;
        j["TransportConfigOperation"] = x.transport_config_operation;
        j["TransportConfigResponse"] = x.transport_config_response;
        j["TransportExitCheckProbe"] = x.transport_exit_check_probe;
        j["TransportExitCheckRequest"] = x.transport_exit_check_request;
        j["TransportExitCheckResponse"] = x.transport_exit_check_response;
        j["TransportLinkedOutboundEnsure"] = x.transport_linked_outbound_ensure;
        j["TransportManagerSettings"] = x.transport_manager_settings;
        j["TransportPath"] = x.transport_path;
        j["TransportProcessModeRequest"] = x.transport_process_mode_request;
        j["TransportsEnvironment"] = x.transports_environment;
        j["TransportSpec"] = x.transport_spec;
        j["TransportStatus"] = x.transport_status;
        j["TunnelProbeConfig"] = x.tunnel_probe_config;
        j["UiPreferencesConfig"] = x.ui_preferences_config;
        j["UpdateStartedResponse"] = x.update_started_response;
        j["ValidationError"] = x.validation_error;
        j["VlessRealitySpec"] = x.vless_reality_spec;
    }

    inline void from_json(const json & j, KeeneticEndpointSource & x) {
        if (j == "fallback") x = KeeneticEndpointSource::FALLBACK;
        else if (j == "ndms") x = KeeneticEndpointSource::NDMS;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"KeeneticEndpointSource\""); }
    }

    inline void to_json(json & j, const KeeneticEndpointSource & x) {
        switch (x) {
            case KeeneticEndpointSource::FALLBACK: j = "fallback"; break;
            case KeeneticEndpointSource::NDMS: j = "ndms"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"KeeneticEndpointSource\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Format & x) {
        if (j == "keen-pbr-sb-backup") x = Format::KEEN_PBR_SB_BACKUP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Format\""); }
    }

    inline void to_json(json & j, const Format & x) {
        switch (x) {
            case Format::KEEN_PBR_SB_BACKUP: j = "keen-pbr-sb-backup"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Format\": " + std::to_string(static_cast<int>(x)));
        }
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
        else if (j == "direct") x = CatalogSetupModeEnum::DIRECT;
        else if (j == "none") x = CatalogSetupModeEnum::NONE;
        else if (j == "outbound") x = CatalogSetupModeEnum::OUTBOUND;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"CatalogSetupModeEnum\""); }
    }

    inline void to_json(json & j, const CatalogSetupModeEnum & x) {
        switch (x) {
            case CatalogSetupModeEnum::BLOCK: j = "block"; break;
            case CatalogSetupModeEnum::DIRECT: j = "direct"; break;
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

    inline void from_json(const json & j, PpeDeoffloadMode & x) {
        if (j == "auto") x = PpeDeoffloadMode::AUTO;
        else if (j == "off") x = PpeDeoffloadMode::OFF;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"PpeDeoffloadMode\""); }
    }

    inline void to_json(json & j, const PpeDeoffloadMode & x) {
        switch (x) {
            case PpeDeoffloadMode::AUTO: j = "auto"; break;
            case PpeDeoffloadMode::OFF: j = "off"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"PpeDeoffloadMode\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, GeoLookupResultError & x) {
        if (j == "invalid_request") x = GeoLookupResultError::INVALID_REQUEST;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"GeoLookupResultError\""); }
    }

    inline void to_json(json & j, const GeoLookupResultError & x) {
        switch (x) {
            case GeoLookupResultError::INVALID_REQUEST: j = "invalid_request"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"GeoLookupResultError\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, CatalogStatus & x) {
        if (j == "fresh") x = CatalogStatus::FRESH;
        else if (j == "stale") x = CatalogStatus::STALE;
        else if (j == "unavailable") x = CatalogStatus::UNAVAILABLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"CatalogStatus\""); }
    }

    inline void to_json(json & j, const CatalogStatus & x) {
        switch (x) {
            case CatalogStatus::FRESH: j = "fresh"; break;
            case CatalogStatus::STALE: j = "stale"; break;
            case CatalogStatus::UNAVAILABLE: j = "unavailable"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"CatalogStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, LogLevel & x) {
        if (j == "debug") x = LogLevel::DEBUG;
        else if (j == "error") x = LogLevel::ERROR;
        else if (j == "info") x = LogLevel::INFO;
        else if (j == "verbose") x = LogLevel::VERBOSE;
        else if (j == "warn") x = LogLevel::WARN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"LogLevel\""); }
    }

    inline void to_json(json & j, const LogLevel & x) {
        switch (x) {
            case LogLevel::DEBUG: j = "debug"; break;
            case LogLevel::ERROR: j = "error"; break;
            case LogLevel::INFO: j = "info"; break;
            case LogLevel::VERBOSE: j = "verbose"; break;
            case LogLevel::WARN: j = "warn"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"LogLevel\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NaiveComponentInstallResultError & x) {
        if (j == "install_failed") x = NaiveComponentInstallResultError::INSTALL_FAILED;
        else if (j == "script_missing") x = NaiveComponentInstallResultError::SCRIPT_MISSING;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NaiveComponentInstallResultError\""); }
    }

    inline void to_json(json & j, const NaiveComponentInstallResultError & x) {
        switch (x) {
            case NaiveComponentInstallResultError::INSTALL_FAILED: j = "install_failed"; break;
            case NaiveComponentInstallResultError::SCRIPT_MISSING: j = "script_missing"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NaiveComponentInstallResultError\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsTunnelKindEnum & x) {
        if (j == "amnezia_wireguard") x = NdmsTunnelKindEnum::AMNEZIA_WIREGUARD;
        else if (j == "https_proxy") x = NdmsTunnelKindEnum::HTTPS_PROXY;
        else if (j == "http_proxy") x = NdmsTunnelKindEnum::HTTP_PROXY;
        else if (j == "ike") x = NdmsTunnelKindEnum::IKE;
        else if (j == "l2tp") x = NdmsTunnelKindEnum::L2_TP;
        else if (j == "openconnect") x = NdmsTunnelKindEnum::OPENCONNECT;
        else if (j == "openvpn") x = NdmsTunnelKindEnum::OPENVPN;
        else if (j == "socks5_proxy") x = NdmsTunnelKindEnum::SOCKS5_PROXY;
        else if (j == "sstp") x = NdmsTunnelKindEnum::SSTP;
        else if (j == "wireguard") x = NdmsTunnelKindEnum::WIREGUARD;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsTunnelKindEnum\""); }
    }

    inline void to_json(json & j, const NdmsTunnelKindEnum & x) {
        switch (x) {
            case NdmsTunnelKindEnum::AMNEZIA_WIREGUARD: j = "amnezia_wireguard"; break;
            case NdmsTunnelKindEnum::HTTPS_PROXY: j = "https_proxy"; break;
            case NdmsTunnelKindEnum::HTTP_PROXY: j = "http_proxy"; break;
            case NdmsTunnelKindEnum::IKE: j = "ike"; break;
            case NdmsTunnelKindEnum::L2_TP: j = "l2tp"; break;
            case NdmsTunnelKindEnum::OPENCONNECT: j = "openconnect"; break;
            case NdmsTunnelKindEnum::OPENVPN: j = "openvpn"; break;
            case NdmsTunnelKindEnum::SOCKS5_PROXY: j = "socks5_proxy"; break;
            case NdmsTunnelKindEnum::SSTP: j = "sstp"; break;
            case NdmsTunnelKindEnum::WIREGUARD: j = "wireguard"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsTunnelKindEnum\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, NdmsNativeInventoryDeferredDeleteCheckElement & x) {
        if (j == "direct_ndms_state") x = NdmsNativeInventoryDeferredDeleteCheckElement::DIRECT_NDMS_STATE;
        else if (j == "encrypted_snapshot") x = NdmsNativeInventoryDeferredDeleteCheckElement::ENCRYPTED_SNAPSHOT;
        else if (j == "keen_pbr_dependencies") x = NdmsNativeInventoryDeferredDeleteCheckElement::KEEN_PBR_DEPENDENCIES;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeInventoryDeferredDeleteCheckElement\""); }
    }

    inline void to_json(json & j, const NdmsNativeInventoryDeferredDeleteCheckElement & x) {
        switch (x) {
            case NdmsNativeInventoryDeferredDeleteCheckElement::DIRECT_NDMS_STATE: j = "direct_ndms_state"; break;
            case NdmsNativeInventoryDeferredDeleteCheckElement::ENCRYPTED_SNAPSHOT: j = "encrypted_snapshot"; break;
            case NdmsNativeInventoryDeferredDeleteCheckElement::KEEN_PBR_DEPENDENCIES: j = "keen_pbr_dependencies"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeInventoryDeferredDeleteCheckElement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeInventoryDeleteBlockerElement & x) {
        if (j == "catalog_not_fresh") x = NdmsNativeInventoryDeleteBlockerElement::CATALOG_NOT_FRESH;
        else if (j == "delete_journal_unsafe") x = NdmsNativeInventoryDeleteBlockerElement::DELETE_JOURNAL_UNSAFE;
        else if (j == "delete_recovery_required") x = NdmsNativeInventoryDeleteBlockerElement::DELETE_RECOVERY_REQUIRED;
        else if (j == "import_journal_not_authoritatively_clean") x = NdmsNativeInventoryDeleteBlockerElement::IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN;
        else if (j == "import_journal_unavailable") x = NdmsNativeInventoryDeleteBlockerElement::IMPORT_JOURNAL_UNAVAILABLE;
        else if (j == "import_journal_unsafe") x = NdmsNativeInventoryDeleteBlockerElement::IMPORT_JOURNAL_UNSAFE;
        else if (j == "import_recovery_required") x = NdmsNativeInventoryDeleteBlockerElement::IMPORT_RECOVERY_REQUIRED;
        else if (j == "invalid_or_protected_target") x = NdmsNativeInventoryDeleteBlockerElement::INVALID_OR_PROTECTED_TARGET;
        else if (j == "ownership_absent") x = NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_ABSENT;
        else if (j == "ownership_inventory_unavailable") x = NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_INVENTORY_UNAVAILABLE;
        else if (j == "ownership_kind_mismatch") x = NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_KIND_MISMATCH;
        else if (j == "ownership_not_active") x = NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_NOT_ACTIVE;
        else if (j == "unsupported_kind") x = NdmsNativeInventoryDeleteBlockerElement::UNSUPPORTED_KIND;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeInventoryDeleteBlockerElement\""); }
    }

    inline void to_json(json & j, const NdmsNativeInventoryDeleteBlockerElement & x) {
        switch (x) {
            case NdmsNativeInventoryDeleteBlockerElement::CATALOG_NOT_FRESH: j = "catalog_not_fresh"; break;
            case NdmsNativeInventoryDeleteBlockerElement::DELETE_JOURNAL_UNSAFE: j = "delete_journal_unsafe"; break;
            case NdmsNativeInventoryDeleteBlockerElement::DELETE_RECOVERY_REQUIRED: j = "delete_recovery_required"; break;
            case NdmsNativeInventoryDeleteBlockerElement::IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN: j = "import_journal_not_authoritatively_clean"; break;
            case NdmsNativeInventoryDeleteBlockerElement::IMPORT_JOURNAL_UNAVAILABLE: j = "import_journal_unavailable"; break;
            case NdmsNativeInventoryDeleteBlockerElement::IMPORT_JOURNAL_UNSAFE: j = "import_journal_unsafe"; break;
            case NdmsNativeInventoryDeleteBlockerElement::IMPORT_RECOVERY_REQUIRED: j = "import_recovery_required"; break;
            case NdmsNativeInventoryDeleteBlockerElement::INVALID_OR_PROTECTED_TARGET: j = "invalid_or_protected_target"; break;
            case NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_ABSENT: j = "ownership_absent"; break;
            case NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_INVENTORY_UNAVAILABLE: j = "ownership_inventory_unavailable"; break;
            case NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_KIND_MISMATCH: j = "ownership_kind_mismatch"; break;
            case NdmsNativeInventoryDeleteBlockerElement::OWNERSHIP_NOT_ACTIVE: j = "ownership_not_active"; break;
            case NdmsNativeInventoryDeleteBlockerElement::UNSUPPORTED_KIND: j = "unsupported_kind"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeInventoryDeleteBlockerElement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, OwnershipLifecycle & x) {
        if (j == "active_running_only") x = OwnershipLifecycle::ACTIVE_RUNNING_ONLY;
        else if (j == "active_save_acknowledged_unverified") x = OwnershipLifecycle::ACTIVE_SAVE_ACKNOWLEDGED_UNVERIFIED;
        else if (j == "deleted_save_acknowledged_unverified") x = OwnershipLifecycle::DELETED_SAVE_ACKNOWLEDGED_UNVERIFIED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"OwnershipLifecycle\""); }
    }

    inline void to_json(json & j, const OwnershipLifecycle & x) {
        switch (x) {
            case OwnershipLifecycle::ACTIVE_RUNNING_ONLY: j = "active_running_only"; break;
            case OwnershipLifecycle::ACTIVE_SAVE_ACKNOWLEDGED_UNVERIFIED: j = "active_save_acknowledged_unverified"; break;
            case OwnershipLifecycle::DELETED_SAVE_ACKNOWLEDGED_UNVERIFIED: j = "deleted_save_acknowledged_unverified"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"OwnershipLifecycle\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, OwnershipState & x) {
        if (j == "foreign") x = OwnershipState::FOREIGN;
        else if (j == "not_applicable") x = OwnershipState::NOT_APPLICABLE;
        else if (j == "panel_owned_active") x = OwnershipState::PANEL_OWNED_ACTIVE;
        else if (j == "panel_owned_tombstone") x = OwnershipState::PANEL_OWNED_TOMBSTONE;
        else if (j == "unavailable") x = OwnershipState::UNAVAILABLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"OwnershipState\""); }
    }

    inline void to_json(json & j, const OwnershipState & x) {
        switch (x) {
            case OwnershipState::FOREIGN: j = "foreign"; break;
            case OwnershipState::NOT_APPLICABLE: j = "not_applicable"; break;
            case OwnershipState::PANEL_OWNED_ACTIVE: j = "panel_owned_active"; break;
            case OwnershipState::PANEL_OWNED_TOMBSTONE: j = "panel_owned_tombstone"; break;
            case OwnershipState::UNAVAILABLE: j = "unavailable"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"OwnershipState\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, NdmsInterfaceRoleEnum & x) {
        if (j == "client") x = NdmsInterfaceRoleEnum::CLIENT;
        else if (j == "server") x = NdmsInterfaceRoleEnum::SERVER;
        else if (j == "unknown") x = NdmsInterfaceRoleEnum::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsInterfaceRoleEnum\""); }
    }

    inline void to_json(json & j, const NdmsInterfaceRoleEnum & x) {
        switch (x) {
            case NdmsInterfaceRoleEnum::CLIENT: j = "client"; break;
            case NdmsInterfaceRoleEnum::SERVER: j = "server"; break;
            case NdmsInterfaceRoleEnum::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsInterfaceRoleEnum\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, NdmsNativeImportTargetPrefix & x) {
        if (j == "Wireguard") x = NdmsNativeImportTargetPrefix::WIREGUARD;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportTargetPrefix\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportTargetPrefix & x) {
        switch (x) {
            case NdmsNativeImportTargetPrefix::WIREGUARD: j = "Wireguard"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportTargetPrefix\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportBlocker & x) {
        if (j == "allocator_range_unfenced") x = NdmsNativeImportBlocker::ALLOCATOR_RANGE_UNFENCED;
        else if (j == "reconcile_barrier_not_integrated") x = NdmsNativeImportBlocker::RECONCILE_BARRIER_NOT_INTEGRATED;
        else if (j == "recovery_journal_not_integrated") x = NdmsNativeImportBlocker::RECOVERY_JOURNAL_NOT_INTEGRATED;
        else if (j == "writer_disabled") x = NdmsNativeImportBlocker::WRITER_DISABLED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportBlocker\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportBlocker & x) {
        switch (x) {
            case NdmsNativeImportBlocker::ALLOCATOR_RANGE_UNFENCED: j = "allocator_range_unfenced"; break;
            case NdmsNativeImportBlocker::RECONCILE_BARRIER_NOT_INTEGRATED: j = "reconcile_barrier_not_integrated"; break;
            case NdmsNativeImportBlocker::RECOVERY_JOURNAL_NOT_INTEGRATED: j = "recovery_journal_not_integrated"; break;
            case NdmsNativeImportBlocker::WRITER_DISABLED: j = "writer_disabled"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportBlocker\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportJournalState & x) {
        if (j == "clean") x = NdmsNativeImportJournalState::CLEAN;
        else if (j == "clean_never_activated") x = NdmsNativeImportJournalState::CLEAN_NEVER_ACTIVATED;
        else if (j == "dormant") x = NdmsNativeImportJournalState::DORMANT;
        else if (j == "recovery_required") x = NdmsNativeImportJournalState::RECOVERY_REQUIRED;
        else if (j == "unavailable") x = NdmsNativeImportJournalState::UNAVAILABLE;
        else if (j == "unsafe") x = NdmsNativeImportJournalState::UNSAFE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportJournalState\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportJournalState & x) {
        switch (x) {
            case NdmsNativeImportJournalState::CLEAN: j = "clean"; break;
            case NdmsNativeImportJournalState::CLEAN_NEVER_ACTIVATED: j = "clean_never_activated"; break;
            case NdmsNativeImportJournalState::DORMANT: j = "dormant"; break;
            case NdmsNativeImportJournalState::RECOVERY_REQUIRED: j = "recovery_required"; break;
            case NdmsNativeImportJournalState::UNAVAILABLE: j = "unavailable"; break;
            case NdmsNativeImportJournalState::UNSAFE: j = "unsafe"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportJournalState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportReconcileBarrierState & x) {
        if (j == "dormant") x = NdmsNativeImportReconcileBarrierState::DORMANT;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportReconcileBarrierState\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportReconcileBarrierState & x) {
        switch (x) {
            case NdmsNativeImportReconcileBarrierState::DORMANT: j = "dormant"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportReconcileBarrierState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ObservedDeleteJournalState & x) {
        if (j == "clean") x = ObservedDeleteJournalState::CLEAN;
        else if (j == "recovery_required") x = ObservedDeleteJournalState::RECOVERY_REQUIRED;
        else if (j == "unavailable") x = ObservedDeleteJournalState::UNAVAILABLE;
        else if (j == "unsafe") x = ObservedDeleteJournalState::UNSAFE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ObservedDeleteJournalState\""); }
    }

    inline void to_json(json & j, const ObservedDeleteJournalState & x) {
        switch (x) {
            case ObservedDeleteJournalState::CLEAN: j = "clean"; break;
            case ObservedDeleteJournalState::RECOVERY_REQUIRED: j = "recovery_required"; break;
            case ObservedDeleteJournalState::UNAVAILABLE: j = "unavailable"; break;
            case ObservedDeleteJournalState::UNSAFE: j = "unsafe"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ObservedDeleteJournalState\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, NdmsNativeRetainedDeletionDeferredCheckElement & x) {
        if (j == "encrypted_snapshot_or_absence") x = NdmsNativeRetainedDeletionDeferredCheckElement::ENCRYPTED_SNAPSHOT_OR_ABSENCE;
        else if (j == "fresh_dual_scope_absence") x = NdmsNativeRetainedDeletionDeferredCheckElement::FRESH_DUAL_SCOPE_ABSENCE;
        else if (j == "keen_pbr_dependencies") x = NdmsNativeRetainedDeletionDeferredCheckElement::KEEN_PBR_DEPENDENCIES;
        else if (j == "retained_kernel_interface_absence") x = NdmsNativeRetainedDeletionDeferredCheckElement::RETAINED_KERNEL_INTERFACE_ABSENCE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeRetainedDeletionDeferredCheckElement\""); }
    }

    inline void to_json(json & j, const NdmsNativeRetainedDeletionDeferredCheckElement & x) {
        switch (x) {
            case NdmsNativeRetainedDeletionDeferredCheckElement::ENCRYPTED_SNAPSHOT_OR_ABSENCE: j = "encrypted_snapshot_or_absence"; break;
            case NdmsNativeRetainedDeletionDeferredCheckElement::FRESH_DUAL_SCOPE_ABSENCE: j = "fresh_dual_scope_absence"; break;
            case NdmsNativeRetainedDeletionDeferredCheckElement::KEEN_PBR_DEPENDENCIES: j = "keen_pbr_dependencies"; break;
            case NdmsNativeRetainedDeletionDeferredCheckElement::RETAINED_KERNEL_INTERFACE_ABSENCE: j = "retained_kernel_interface_absence"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeRetainedDeletionDeferredCheckElement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeRetainedDeletionBlockerElement & x) {
        if (j == "catalog_not_fresh") x = NdmsNativeRetainedDeletionBlockerElement::CATALOG_NOT_FRESH;
        else if (j == "delete_journal_unsafe") x = NdmsNativeRetainedDeletionBlockerElement::DELETE_JOURNAL_UNSAFE;
        else if (j == "delete_recovery_required") x = NdmsNativeRetainedDeletionBlockerElement::DELETE_RECOVERY_REQUIRED;
        else if (j == "import_journal_not_authoritatively_clean") x = NdmsNativeRetainedDeletionBlockerElement::IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN;
        else if (j == "import_journal_unavailable") x = NdmsNativeRetainedDeletionBlockerElement::IMPORT_JOURNAL_UNAVAILABLE;
        else if (j == "import_journal_unsafe") x = NdmsNativeRetainedDeletionBlockerElement::IMPORT_JOURNAL_UNSAFE;
        else if (j == "import_recovery_required") x = NdmsNativeRetainedDeletionBlockerElement::IMPORT_RECOVERY_REQUIRED;
        else if (j == "ownership_schema_not_forget_capable") x = NdmsNativeRetainedDeletionBlockerElement::OWNERSHIP_SCHEMA_NOT_FORGET_CAPABLE;
        else if (j == "target_present") x = NdmsNativeRetainedDeletionBlockerElement::TARGET_PRESENT;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeRetainedDeletionBlockerElement\""); }
    }

    inline void to_json(json & j, const NdmsNativeRetainedDeletionBlockerElement & x) {
        switch (x) {
            case NdmsNativeRetainedDeletionBlockerElement::CATALOG_NOT_FRESH: j = "catalog_not_fresh"; break;
            case NdmsNativeRetainedDeletionBlockerElement::DELETE_JOURNAL_UNSAFE: j = "delete_journal_unsafe"; break;
            case NdmsNativeRetainedDeletionBlockerElement::DELETE_RECOVERY_REQUIRED: j = "delete_recovery_required"; break;
            case NdmsNativeRetainedDeletionBlockerElement::IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN: j = "import_journal_not_authoritatively_clean"; break;
            case NdmsNativeRetainedDeletionBlockerElement::IMPORT_JOURNAL_UNAVAILABLE: j = "import_journal_unavailable"; break;
            case NdmsNativeRetainedDeletionBlockerElement::IMPORT_JOURNAL_UNSAFE: j = "import_journal_unsafe"; break;
            case NdmsNativeRetainedDeletionBlockerElement::IMPORT_RECOVERY_REQUIRED: j = "import_recovery_required"; break;
            case NdmsNativeRetainedDeletionBlockerElement::OWNERSHIP_SCHEMA_NOT_FORGET_CAPABLE: j = "ownership_schema_not_forget_capable"; break;
            case NdmsNativeRetainedDeletionBlockerElement::TARGET_PRESENT: j = "target_present"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeRetainedDeletionBlockerElement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeDeletePhase & x) {
        if (j == "cleanup") x = NdmsNativeDeletePhase::CLEANUP;
        else if (j == "delete_may_be_inflight") x = NdmsNativeDeletePhase::DELETE_MAY_BE_INFLIGHT;
        else if (j == "prepared") x = NdmsNativeDeletePhase::PREPARED;
        else if (j == "running_absence_verified") x = NdmsNativeDeletePhase::RUNNING_ABSENCE_VERIFIED;
        else if (j == "save_acknowledged_unverified") x = NdmsNativeDeletePhase::SAVE_ACKNOWLEDGED_UNVERIFIED;
        else if (j == "save_may_be_inflight") x = NdmsNativeDeletePhase::SAVE_MAY_BE_INFLIGHT;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeDeletePhase\""); }
    }

    inline void to_json(json & j, const NdmsNativeDeletePhase & x) {
        switch (x) {
            case NdmsNativeDeletePhase::CLEANUP: j = "cleanup"; break;
            case NdmsNativeDeletePhase::DELETE_MAY_BE_INFLIGHT: j = "delete_may_be_inflight"; break;
            case NdmsNativeDeletePhase::PREPARED: j = "prepared"; break;
            case NdmsNativeDeletePhase::RUNNING_ABSENCE_VERIFIED: j = "running_absence_verified"; break;
            case NdmsNativeDeletePhase::SAVE_ACKNOWLEDGED_UNVERIFIED: j = "save_acknowledged_unverified"; break;
            case NdmsNativeDeletePhase::SAVE_MAY_BE_INFLIGHT: j = "save_may_be_inflight"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeDeletePhase\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeMutationKind & x) {
        if (j == "amnezia_wireguard") x = NdmsNativeMutationKind::AMNEZIA_WIREGUARD;
        else if (j == "wireguard") x = NdmsNativeMutationKind::WIREGUARD;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeMutationKind\""); }
    }

    inline void to_json(json & j, const NdmsNativeMutationKind & x) {
        switch (x) {
            case NdmsNativeMutationKind::AMNEZIA_WIREGUARD: j = "amnezia_wireguard"; break;
            case NdmsNativeMutationKind::WIREGUARD: j = "wireguard"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeMutationKind\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeDirectObservationFailure & x) {
        static std::unordered_map<std::string, NdmsNativeDirectObservationFailure> enumValues {
            {"ambiguous_marker", NdmsNativeDirectObservationFailure::AMBIGUOUS_MARKER},
            {"catalog_malformed", NdmsNativeDirectObservationFailure::CATALOG_MALFORMED},
            {"catalog_unavailable", NdmsNativeDirectObservationFailure::CATALOG_UNAVAILABLE},
            {"catalog_unsafe", NdmsNativeDirectObservationFailure::CATALOG_UNSAFE},
            {"duplicate_json_key", NdmsNativeDirectObservationFailure::DUPLICATE_JSON_KEY},
            {"empty_response", NdmsNativeDirectObservationFailure::EMPTY_RESPONSE},
            {"invalid_marker", NdmsNativeDirectObservationFailure::INVALID_MARKER},
            {"invalid_target", NdmsNativeDirectObservationFailure::INVALID_TARGET},
            {"malformed_json", NdmsNativeDirectObservationFailure::MALFORMED_JSON},
            {"marker_target_not_managed_wireguard", NdmsNativeDirectObservationFailure::MARKER_TARGET_NOT_MANAGED_WIREGUARD},
            {"none", NdmsNativeDirectObservationFailure::NONE},
            {"rci_error_response", NdmsNativeDirectObservationFailure::RCI_ERROR_RESPONSE},
            {"response_not_object", NdmsNativeDirectObservationFailure::RESPONSE_NOT_OBJECT},
            {"response_too_large", NdmsNativeDirectObservationFailure::RESPONSE_TOO_LARGE},
            {"target_evidence_refused", NdmsNativeDirectObservationFailure::TARGET_EVIDENCE_REFUSED},
            {"transport_failed", NdmsNativeDirectObservationFailure::TRANSPORT_FAILED},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeDirectObservationFailure\""); }
    }

    inline void to_json(json & j, const NdmsNativeDirectObservationFailure & x) {
        switch (x) {
            case NdmsNativeDirectObservationFailure::AMBIGUOUS_MARKER: j = "ambiguous_marker"; break;
            case NdmsNativeDirectObservationFailure::CATALOG_MALFORMED: j = "catalog_malformed"; break;
            case NdmsNativeDirectObservationFailure::CATALOG_UNAVAILABLE: j = "catalog_unavailable"; break;
            case NdmsNativeDirectObservationFailure::CATALOG_UNSAFE: j = "catalog_unsafe"; break;
            case NdmsNativeDirectObservationFailure::DUPLICATE_JSON_KEY: j = "duplicate_json_key"; break;
            case NdmsNativeDirectObservationFailure::EMPTY_RESPONSE: j = "empty_response"; break;
            case NdmsNativeDirectObservationFailure::INVALID_MARKER: j = "invalid_marker"; break;
            case NdmsNativeDirectObservationFailure::INVALID_TARGET: j = "invalid_target"; break;
            case NdmsNativeDirectObservationFailure::MALFORMED_JSON: j = "malformed_json"; break;
            case NdmsNativeDirectObservationFailure::MARKER_TARGET_NOT_MANAGED_WIREGUARD: j = "marker_target_not_managed_wireguard"; break;
            case NdmsNativeDirectObservationFailure::NONE: j = "none"; break;
            case NdmsNativeDirectObservationFailure::RCI_ERROR_RESPONSE: j = "rci_error_response"; break;
            case NdmsNativeDirectObservationFailure::RESPONSE_NOT_OBJECT: j = "response_not_object"; break;
            case NdmsNativeDirectObservationFailure::RESPONSE_TOO_LARGE: j = "response_too_large"; break;
            case NdmsNativeDirectObservationFailure::TARGET_EVIDENCE_REFUSED: j = "target_evidence_refused"; break;
            case NdmsNativeDirectObservationFailure::TRANSPORT_FAILED: j = "transport_failed"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeDirectObservationFailure\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeDeleteStatus & x) {
        if (j == "blocked") x = NdmsNativeDeleteStatus::BLOCKED;
        else if (j == "recovery_required") x = NdmsNativeDeleteStatus::RECOVERY_REQUIRED;
        else if (j == "save_acknowledged_unverified") x = NdmsNativeDeleteStatus::SAVE_ACKNOWLEDGED_UNVERIFIED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeDeleteStatus\""); }
    }

    inline void to_json(json & j, const NdmsNativeDeleteStatus & x) {
        switch (x) {
            case NdmsNativeDeleteStatus::BLOCKED: j = "blocked"; break;
            case NdmsNativeDeleteStatus::RECOVERY_REQUIRED: j = "recovery_required"; break;
            case NdmsNativeDeleteStatus::SAVE_ACKNOWLEDGED_UNVERIFIED: j = "save_acknowledged_unverified"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeDeleteStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeDeleteStop & x) {
        static std::unordered_map<std::string, NdmsNativeDeleteStop> enumValues {
            {"delete_guard_rejected", NdmsNativeDeleteStop::DELETE_GUARD_REJECTED},
            {"delete_transport_ambiguous", NdmsNativeDeleteStop::DELETE_TRANSPORT_AMBIGUOUS},
            {"delete_wal_cleanup_failed", NdmsNativeDeleteStop::DELETE_WAL_CLEANUP_FAILED},
            {"delete_wal_publish_failed", NdmsNativeDeleteStop::DELETE_WAL_PUBLISH_FAILED},
            {"delete_wal_unfinished", NdmsNativeDeleteStop::DELETE_WAL_UNFINISHED},
            {"delete_wal_unsafe", NdmsNativeDeleteStop::DELETE_WAL_UNSAFE},
            {"durable_observation_failed", NdmsNativeDeleteStop::DURABLE_OBSERVATION_FAILED},
            {"external_writer_race_not_accepted", NdmsNativeDeleteStop::EXTERNAL_WRITER_RACE_NOT_ACCEPTED},
            {"import_wal_not_authoritatively_clean", NdmsNativeDeleteStop::IMPORT_WAL_NOT_AUTHORITATIVELY_CLEAN},
            {"invalid_or_protected_target", NdmsNativeDeleteStop::INVALID_OR_PROTECTED_TARGET},
            {"keen_pbr_dependencies_present", NdmsNativeDeleteStop::KEEN_PBR_DEPENDENCIES_PRESENT},
            {"keen_pbr_dependency_changed", NdmsNativeDeleteStop::KEEN_PBR_DEPENDENCY_CHANGED},
            {"keen_pbr_dependency_scan_incomplete", NdmsNativeDeleteStop::KEEN_PBR_DEPENDENCY_SCAN_INCOMPLETE},
            {"none", NdmsNativeDeleteStop::NONE},
            {"no_delete_transaction", NdmsNativeDeleteStop::NO_DELETE_TRANSACTION},
            {"observation_scope_mismatch", NdmsNativeDeleteStop::OBSERVATION_SCOPE_MISMATCH},
            {"observed_target_drifted", NdmsNativeDeleteStop::OBSERVED_TARGET_DRIFTED},
            {"observed_target_mismatch", NdmsNativeDeleteStop::OBSERVED_TARGET_MISMATCH},
            {"observed_target_reappeared_after_save", NdmsNativeDeleteStop::OBSERVED_TARGET_REAPPEARED_AFTER_SAVE},
            {"ownership_absent", NdmsNativeDeleteStop::OWNERSHIP_ABSENT},
            {"ownership_changed", NdmsNativeDeleteStop::OWNERSHIP_CHANGED},
            {"ownership_not_active", NdmsNativeDeleteStop::OWNERSHIP_NOT_ACTIVE},
            {"ownership_unreadable", NdmsNativeDeleteStop::OWNERSHIP_UNREADABLE},
            {"owner_global_save_not_acknowledged", NdmsNativeDeleteStop::OWNER_GLOBAL_SAVE_NOT_ACKNOWLEDGED},
            {"running_config_observation_failed", NdmsNativeDeleteStop::RUNNING_CONFIG_OBSERVATION_FAILED},
            {"runtime_observation_failed", NdmsNativeDeleteStop::RUNTIME_OBSERVATION_FAILED},
            {"save_guard_rejected", NdmsNativeDeleteStop::SAVE_GUARD_REJECTED},
            {"save_reconfirmation_required", NdmsNativeDeleteStop::SAVE_RECONFIRMATION_REQUIRED},
            {"save_transport_ambiguous", NdmsNativeDeleteStop::SAVE_TRANSPORT_AMBIGUOUS},
            {"snapshot_absent", NdmsNativeDeleteStop::SNAPSHOT_ABSENT},
            {"snapshot_mismatch", NdmsNativeDeleteStop::SNAPSHOT_MISMATCH},
            {"snapshot_unreadable", NdmsNativeDeleteStop::SNAPSHOT_UNREADABLE},
            {"tombstone_mismatch", NdmsNativeDeleteStop::TOMBSTONE_MISMATCH},
            {"tombstone_publish_failed", NdmsNativeDeleteStop::TOMBSTONE_PUBLISH_FAILED},
            {"unexpected_failure", NdmsNativeDeleteStop::UNEXPECTED_FAILURE},
            {"writer_lost", NdmsNativeDeleteStop::WRITER_LOST},
            {"writer_missing", NdmsNativeDeleteStop::WRITER_MISSING},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeDeleteStop\""); }
    }

    inline void to_json(json & j, const NdmsNativeDeleteStop & x) {
        switch (x) {
            case NdmsNativeDeleteStop::DELETE_GUARD_REJECTED: j = "delete_guard_rejected"; break;
            case NdmsNativeDeleteStop::DELETE_TRANSPORT_AMBIGUOUS: j = "delete_transport_ambiguous"; break;
            case NdmsNativeDeleteStop::DELETE_WAL_CLEANUP_FAILED: j = "delete_wal_cleanup_failed"; break;
            case NdmsNativeDeleteStop::DELETE_WAL_PUBLISH_FAILED: j = "delete_wal_publish_failed"; break;
            case NdmsNativeDeleteStop::DELETE_WAL_UNFINISHED: j = "delete_wal_unfinished"; break;
            case NdmsNativeDeleteStop::DELETE_WAL_UNSAFE: j = "delete_wal_unsafe"; break;
            case NdmsNativeDeleteStop::DURABLE_OBSERVATION_FAILED: j = "durable_observation_failed"; break;
            case NdmsNativeDeleteStop::EXTERNAL_WRITER_RACE_NOT_ACCEPTED: j = "external_writer_race_not_accepted"; break;
            case NdmsNativeDeleteStop::IMPORT_WAL_NOT_AUTHORITATIVELY_CLEAN: j = "import_wal_not_authoritatively_clean"; break;
            case NdmsNativeDeleteStop::INVALID_OR_PROTECTED_TARGET: j = "invalid_or_protected_target"; break;
            case NdmsNativeDeleteStop::KEEN_PBR_DEPENDENCIES_PRESENT: j = "keen_pbr_dependencies_present"; break;
            case NdmsNativeDeleteStop::KEEN_PBR_DEPENDENCY_CHANGED: j = "keen_pbr_dependency_changed"; break;
            case NdmsNativeDeleteStop::KEEN_PBR_DEPENDENCY_SCAN_INCOMPLETE: j = "keen_pbr_dependency_scan_incomplete"; break;
            case NdmsNativeDeleteStop::NONE: j = "none"; break;
            case NdmsNativeDeleteStop::NO_DELETE_TRANSACTION: j = "no_delete_transaction"; break;
            case NdmsNativeDeleteStop::OBSERVATION_SCOPE_MISMATCH: j = "observation_scope_mismatch"; break;
            case NdmsNativeDeleteStop::OBSERVED_TARGET_DRIFTED: j = "observed_target_drifted"; break;
            case NdmsNativeDeleteStop::OBSERVED_TARGET_MISMATCH: j = "observed_target_mismatch"; break;
            case NdmsNativeDeleteStop::OBSERVED_TARGET_REAPPEARED_AFTER_SAVE: j = "observed_target_reappeared_after_save"; break;
            case NdmsNativeDeleteStop::OWNERSHIP_ABSENT: j = "ownership_absent"; break;
            case NdmsNativeDeleteStop::OWNERSHIP_CHANGED: j = "ownership_changed"; break;
            case NdmsNativeDeleteStop::OWNERSHIP_NOT_ACTIVE: j = "ownership_not_active"; break;
            case NdmsNativeDeleteStop::OWNERSHIP_UNREADABLE: j = "ownership_unreadable"; break;
            case NdmsNativeDeleteStop::OWNER_GLOBAL_SAVE_NOT_ACKNOWLEDGED: j = "owner_global_save_not_acknowledged"; break;
            case NdmsNativeDeleteStop::RUNNING_CONFIG_OBSERVATION_FAILED: j = "running_config_observation_failed"; break;
            case NdmsNativeDeleteStop::RUNTIME_OBSERVATION_FAILED: j = "runtime_observation_failed"; break;
            case NdmsNativeDeleteStop::SAVE_GUARD_REJECTED: j = "save_guard_rejected"; break;
            case NdmsNativeDeleteStop::SAVE_RECONFIRMATION_REQUIRED: j = "save_reconfirmation_required"; break;
            case NdmsNativeDeleteStop::SAVE_TRANSPORT_AMBIGUOUS: j = "save_transport_ambiguous"; break;
            case NdmsNativeDeleteStop::SNAPSHOT_ABSENT: j = "snapshot_absent"; break;
            case NdmsNativeDeleteStop::SNAPSHOT_MISMATCH: j = "snapshot_mismatch"; break;
            case NdmsNativeDeleteStop::SNAPSHOT_UNREADABLE: j = "snapshot_unreadable"; break;
            case NdmsNativeDeleteStop::TOMBSTONE_MISMATCH: j = "tombstone_mismatch"; break;
            case NdmsNativeDeleteStop::TOMBSTONE_PUBLISH_FAILED: j = "tombstone_publish_failed"; break;
            case NdmsNativeDeleteStop::UNEXPECTED_FAILURE: j = "unexpected_failure"; break;
            case NdmsNativeDeleteStop::WRITER_LOST: j = "writer_lost"; break;
            case NdmsNativeDeleteStop::WRITER_MISSING: j = "writer_missing"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeDeleteStop\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeDeleteTransportOutcome & x) {
        if (j == "acknowledged_needs_observation") x = NdmsNativeDeleteTransportOutcome::ACKNOWLEDGED_NEEDS_OBSERVATION;
        else if (j == "body_empty") x = NdmsNativeDeleteTransportOutcome::BODY_EMPTY;
        else if (j == "body_too_large") x = NdmsNativeDeleteTransportOutcome::BODY_TOO_LARGE;
        else if (j == "content_type_not_json") x = NdmsNativeDeleteTransportOutcome::CONTENT_TYPE_NOT_JSON;
        else if (j == "guard_rejected") x = NdmsNativeDeleteTransportOutcome::GUARD_REJECTED;
        else if (j == "http_status_not_200") x = NdmsNativeDeleteTransportOutcome::HTTP_STATUS_NOT_200;
        else if (j == "shape_not_acknowledged") x = NdmsNativeDeleteTransportOutcome::SHAPE_NOT_ACKNOWLEDGED;
        else if (j == "transport_failed") x = NdmsNativeDeleteTransportOutcome::TRANSPORT_FAILED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeDeleteTransportOutcome\""); }
    }

    inline void to_json(json & j, const NdmsNativeDeleteTransportOutcome & x) {
        switch (x) {
            case NdmsNativeDeleteTransportOutcome::ACKNOWLEDGED_NEEDS_OBSERVATION: j = "acknowledged_needs_observation"; break;
            case NdmsNativeDeleteTransportOutcome::BODY_EMPTY: j = "body_empty"; break;
            case NdmsNativeDeleteTransportOutcome::BODY_TOO_LARGE: j = "body_too_large"; break;
            case NdmsNativeDeleteTransportOutcome::CONTENT_TYPE_NOT_JSON: j = "content_type_not_json"; break;
            case NdmsNativeDeleteTransportOutcome::GUARD_REJECTED: j = "guard_rejected"; break;
            case NdmsNativeDeleteTransportOutcome::HTTP_STATUS_NOT_200: j = "http_status_not_200"; break;
            case NdmsNativeDeleteTransportOutcome::SHAPE_NOT_ACKNOWLEDGED: j = "shape_not_acknowledged"; break;
            case NdmsNativeDeleteTransportOutcome::TRANSPORT_FAILED: j = "transport_failed"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeDeleteTransportOutcome\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryAction & x) {
        if (j == "abort_without_mutation") x = NdmsNativeImportRecoveryAction::ABORT_WITHOUT_MUTATION;
        else if (j == "block_unknown") x = NdmsNativeImportRecoveryAction::BLOCK_UNKNOWN;
        else if (j == "complete_rollback") x = NdmsNativeImportRecoveryAction::COMPLETE_ROLLBACK;
        else if (j == "resume_forward_reconcile") x = NdmsNativeImportRecoveryAction::RESUME_FORWARD_RECONCILE;
        else if (j == "retry_exact_owned_delete") x = NdmsNativeImportRecoveryAction::RETRY_EXACT_OWNED_DELETE;
        else if (j == "retry_read_only_observation") x = NdmsNativeImportRecoveryAction::RETRY_READ_ONLY_OBSERVATION;
        else if (j == "rollback_delete_exact_owned") x = NdmsNativeImportRecoveryAction::ROLLBACK_DELETE_EXACT_OWNED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryAction\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryAction & x) {
        switch (x) {
            case NdmsNativeImportRecoveryAction::ABORT_WITHOUT_MUTATION: j = "abort_without_mutation"; break;
            case NdmsNativeImportRecoveryAction::BLOCK_UNKNOWN: j = "block_unknown"; break;
            case NdmsNativeImportRecoveryAction::COMPLETE_ROLLBACK: j = "complete_rollback"; break;
            case NdmsNativeImportRecoveryAction::RESUME_FORWARD_RECONCILE: j = "resume_forward_reconcile"; break;
            case NdmsNativeImportRecoveryAction::RETRY_EXACT_OWNED_DELETE: j = "retry_exact_owned_delete"; break;
            case NdmsNativeImportRecoveryAction::RETRY_READ_ONLY_OBSERVATION: j = "retry_read_only_observation"; break;
            case NdmsNativeImportRecoveryAction::ROLLBACK_DELETE_EXACT_OWNED: j = "rollback_delete_exact_owned"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryAction\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryAdmissionState & x) {
        if (j == "action_not_actionable") x = NdmsNativeImportRecoveryAdmissionState::ACTION_NOT_ACTIONABLE;
        else if (j == "admitted") x = NdmsNativeImportRecoveryAdmissionState::ADMITTED;
        else if (j == "inventory_not_ready") x = NdmsNativeImportRecoveryAdmissionState::INVENTORY_NOT_READY;
        else if (j == "lease_busy") x = NdmsNativeImportRecoveryAdmissionState::LEASE_BUSY;
        else if (j == "lease_io_error") x = NdmsNativeImportRecoveryAdmissionState::LEASE_IO_ERROR;
        else if (j == "record_changed") x = NdmsNativeImportRecoveryAdmissionState::RECORD_CHANGED;
        else if (j == "record_missing") x = NdmsNativeImportRecoveryAdmissionState::RECORD_MISSING;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryAdmissionState\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryAdmissionState & x) {
        switch (x) {
            case NdmsNativeImportRecoveryAdmissionState::ACTION_NOT_ACTIONABLE: j = "action_not_actionable"; break;
            case NdmsNativeImportRecoveryAdmissionState::ADMITTED: j = "admitted"; break;
            case NdmsNativeImportRecoveryAdmissionState::INVENTORY_NOT_READY: j = "inventory_not_ready"; break;
            case NdmsNativeImportRecoveryAdmissionState::LEASE_BUSY: j = "lease_busy"; break;
            case NdmsNativeImportRecoveryAdmissionState::LEASE_IO_ERROR: j = "lease_io_error"; break;
            case NdmsNativeImportRecoveryAdmissionState::RECORD_CHANGED: j = "record_changed"; break;
            case NdmsNativeImportRecoveryAdmissionState::RECORD_MISSING: j = "record_missing"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryAdmissionState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryDispatchState & x) {
        if (j == "completed") x = NdmsNativeImportRecoveryDispatchState::COMPLETED;
        else if (j == "lease_not_held") x = NdmsNativeImportRecoveryDispatchState::LEASE_NOT_HELD;
        else if (j == "ownership_store_missing") x = NdmsNativeImportRecoveryDispatchState::OWNERSHIP_STORE_MISSING;
        else if (j == "plan_empty") x = NdmsNativeImportRecoveryDispatchState::PLAN_EMPTY;
        else if (j == "snapshot_retirer_missing") x = NdmsNativeImportRecoveryDispatchState::SNAPSHOT_RETIRER_MISSING;
        else if (j == "step_failed") x = NdmsNativeImportRecoveryDispatchState::STEP_FAILED;
        else if (j == "target_missing") x = NdmsNativeImportRecoveryDispatchState::TARGET_MISSING;
        else if (j == "target_not_eligible") x = NdmsNativeImportRecoveryDispatchState::TARGET_NOT_ELIGIBLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryDispatchState\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryDispatchState & x) {
        switch (x) {
            case NdmsNativeImportRecoveryDispatchState::COMPLETED: j = "completed"; break;
            case NdmsNativeImportRecoveryDispatchState::LEASE_NOT_HELD: j = "lease_not_held"; break;
            case NdmsNativeImportRecoveryDispatchState::OWNERSHIP_STORE_MISSING: j = "ownership_store_missing"; break;
            case NdmsNativeImportRecoveryDispatchState::PLAN_EMPTY: j = "plan_empty"; break;
            case NdmsNativeImportRecoveryDispatchState::SNAPSHOT_RETIRER_MISSING: j = "snapshot_retirer_missing"; break;
            case NdmsNativeImportRecoveryDispatchState::STEP_FAILED: j = "step_failed"; break;
            case NdmsNativeImportRecoveryDispatchState::TARGET_MISSING: j = "target_missing"; break;
            case NdmsNativeImportRecoveryDispatchState::TARGET_NOT_ELIGIBLE: j = "target_not_eligible"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryDispatchState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryPhase & x) {
        if (j == "absence_verified") x = NdmsNativeImportRecoveryPhase::ABSENCE_VERIFIED;
        else if (j == "delete_may_be_inflight") x = NdmsNativeImportRecoveryPhase::DELETE_MAY_BE_INFLIGHT;
        else if (j == "import_may_be_inflight") x = NdmsNativeImportRecoveryPhase::IMPORT_MAY_BE_INFLIGHT;
        else if (j == "ownership_published") x = NdmsNativeImportRecoveryPhase::OWNERSHIP_PUBLISHED;
        else if (j == "prepared") x = NdmsNativeImportRecoveryPhase::PREPARED;
        else if (j == "response_recorded") x = NdmsNativeImportRecoveryPhase::RESPONSE_RECORDED;
        else if (j == "rollback_requested") x = NdmsNativeImportRecoveryPhase::ROLLBACK_REQUESTED;
        else if (j == "target_verified") x = NdmsNativeImportRecoveryPhase::TARGET_VERIFIED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryPhase\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryPhase & x) {
        switch (x) {
            case NdmsNativeImportRecoveryPhase::ABSENCE_VERIFIED: j = "absence_verified"; break;
            case NdmsNativeImportRecoveryPhase::DELETE_MAY_BE_INFLIGHT: j = "delete_may_be_inflight"; break;
            case NdmsNativeImportRecoveryPhase::IMPORT_MAY_BE_INFLIGHT: j = "import_may_be_inflight"; break;
            case NdmsNativeImportRecoveryPhase::OWNERSHIP_PUBLISHED: j = "ownership_published"; break;
            case NdmsNativeImportRecoveryPhase::PREPARED: j = "prepared"; break;
            case NdmsNativeImportRecoveryPhase::RESPONSE_RECORDED: j = "response_recorded"; break;
            case NdmsNativeImportRecoveryPhase::ROLLBACK_REQUESTED: j = "rollback_requested"; break;
            case NdmsNativeImportRecoveryPhase::TARGET_VERIFIED: j = "target_verified"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryPhase\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeWalReadiness & x) {
        if (j == "clean") x = NdmsNativeWalReadiness::CLEAN;
        else if (j == "unfinished") x = NdmsNativeWalReadiness::UNFINISHED;
        else if (j == "unsafe") x = NdmsNativeWalReadiness::UNSAFE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeWalReadiness\""); }
    }

    inline void to_json(json & j, const NdmsNativeWalReadiness & x) {
        switch (x) {
            case NdmsNativeWalReadiness::CLEAN: j = "clean"; break;
            case NdmsNativeWalReadiness::UNFINISHED: j = "unfinished"; break;
            case NdmsNativeWalReadiness::UNSAFE: j = "unsafe"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeWalReadiness\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryStep & x) {
        if (j == "advance_wal_absence_verified") x = NdmsNativeImportRecoveryStep::ADVANCE_WAL_ABSENCE_VERIFIED;
        else if (j == "advance_wal_delete_may_be_inflight") x = NdmsNativeImportRecoveryStep::ADVANCE_WAL_DELETE_MAY_BE_INFLIGHT;
        else if (j == "advance_wal_ownership_published") x = NdmsNativeImportRecoveryStep::ADVANCE_WAL_OWNERSHIP_PUBLISHED;
        else if (j == "advance_wal_rollback_requested") x = NdmsNativeImportRecoveryStep::ADVANCE_WAL_ROLLBACK_REQUESTED;
        else if (j == "advance_wal_target_verified") x = NdmsNativeImportRecoveryStep::ADVANCE_WAL_TARGET_VERIFIED;
        else if (j == "delete_exact_owned_target") x = NdmsNativeImportRecoveryStep::DELETE_EXACT_OWNED_TARGET;
        else if (j == "publish_ownership") x = NdmsNativeImportRecoveryStep::PUBLISH_OWNERSHIP;
        else if (j == "remove_ownership_claim") x = NdmsNativeImportRecoveryStep::REMOVE_OWNERSHIP_CLAIM;
        else if (j == "remove_wal_record") x = NdmsNativeImportRecoveryStep::REMOVE_WAL_RECORD;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryStep\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryStep & x) {
        switch (x) {
            case NdmsNativeImportRecoveryStep::ADVANCE_WAL_ABSENCE_VERIFIED: j = "advance_wal_absence_verified"; break;
            case NdmsNativeImportRecoveryStep::ADVANCE_WAL_DELETE_MAY_BE_INFLIGHT: j = "advance_wal_delete_may_be_inflight"; break;
            case NdmsNativeImportRecoveryStep::ADVANCE_WAL_OWNERSHIP_PUBLISHED: j = "advance_wal_ownership_published"; break;
            case NdmsNativeImportRecoveryStep::ADVANCE_WAL_ROLLBACK_REQUESTED: j = "advance_wal_rollback_requested"; break;
            case NdmsNativeImportRecoveryStep::ADVANCE_WAL_TARGET_VERIFIED: j = "advance_wal_target_verified"; break;
            case NdmsNativeImportRecoveryStep::DELETE_EXACT_OWNED_TARGET: j = "delete_exact_owned_target"; break;
            case NdmsNativeImportRecoveryStep::PUBLISH_OWNERSHIP: j = "publish_ownership"; break;
            case NdmsNativeImportRecoveryStep::REMOVE_OWNERSHIP_CLAIM: j = "remove_ownership_claim"; break;
            case NdmsNativeImportRecoveryStep::REMOVE_WAL_RECORD: j = "remove_wal_record"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryStep\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryStatus & x) {
        if (j == "blocked") x = NdmsNativeImportRecoveryStatus::BLOCKED;
        else if (j == "completed") x = NdmsNativeImportRecoveryStatus::COMPLETED;
        else if (j == "no_work") x = NdmsNativeImportRecoveryStatus::NO_WORK;
        else if (j == "recovery_required") x = NdmsNativeImportRecoveryStatus::RECOVERY_REQUIRED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryStatus\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryStatus & x) {
        switch (x) {
            case NdmsNativeImportRecoveryStatus::BLOCKED: j = "blocked"; break;
            case NdmsNativeImportRecoveryStatus::COMPLETED: j = "completed"; break;
            case NdmsNativeImportRecoveryStatus::NO_WORK: j = "no_work"; break;
            case NdmsNativeImportRecoveryStatus::RECOVERY_REQUIRED: j = "recovery_required"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportRecoveryStop & x) {
        static std::unordered_map<std::string, NdmsNativeImportRecoveryStop> enumValues {
            {"absence_wal_publish_failed", NdmsNativeImportRecoveryStop::ABSENCE_WAL_PUBLISH_FAILED},
            {"delete_guard_rejected", NdmsNativeImportRecoveryStop::DELETE_GUARD_REJECTED},
            {"delete_transport_ambiguous", NdmsNativeImportRecoveryStop::DELETE_TRANSPORT_AMBIGUOUS},
            {"delete_wal_not_clean", NdmsNativeImportRecoveryStop::DELETE_WAL_NOT_CLEAN},
            {"delete_wal_publish_failed", NdmsNativeImportRecoveryStop::DELETE_WAL_PUBLISH_FAILED},
            {"durable_observation_failed", NdmsNativeImportRecoveryStop::DURABLE_OBSERVATION_FAILED},
            {"expected_target_not_managed", NdmsNativeImportRecoveryStop::EXPECTED_TARGET_NOT_MANAGED},
            {"external_writer_race_not_accepted", NdmsNativeImportRecoveryStop::EXTERNAL_WRITER_RACE_NOT_ACCEPTED},
            {"first_observation_failed", NdmsNativeImportRecoveryStop::FIRST_OBSERVATION_FAILED},
            {"forward_admission_failed", NdmsNativeImportRecoveryStop::FORWARD_ADMISSION_FAILED},
            {"import_wal_not_single_safe", NdmsNativeImportRecoveryStop::IMPORT_WAL_NOT_SINGLE_SAFE},
            {"none", NdmsNativeImportRecoveryStop::NONE},
            {"observation_kind_mismatch", NdmsNativeImportRecoveryStop::OBSERVATION_KIND_MISMATCH},
            {"observation_unstable", NdmsNativeImportRecoveryStop::OBSERVATION_UNSTABLE},
            {"ownership_not_exact", NdmsNativeImportRecoveryStop::OWNERSHIP_NOT_EXACT},
            {"ownership_publish_failed", NdmsNativeImportRecoveryStop::OWNERSHIP_PUBLISH_FAILED},
            {"ownership_retract_failed", NdmsNativeImportRecoveryStop::OWNERSHIP_RETRACT_FAILED},
            {"ownership_wal_publish_failed", NdmsNativeImportRecoveryStop::OWNERSHIP_WAL_PUBLISH_FAILED},
            {"phase_not_forward_only", NdmsNativeImportRecoveryStop::PHASE_NOT_FORWARD_ONLY},
            {"record_not_cooperative", NdmsNativeImportRecoveryStop::RECORD_NOT_COOPERATIVE},
            {"recovery_action_not_actionable", NdmsNativeImportRecoveryStop::RECOVERY_ACTION_NOT_ACTIONABLE},
            {"recovery_action_not_forward_only", NdmsNativeImportRecoveryStop::RECOVERY_ACTION_NOT_FORWARD_ONLY},
            {"recovery_admission_failed", NdmsNativeImportRecoveryStop::RECOVERY_ADMISSION_FAILED},
            {"rollback_wal_publish_failed", NdmsNativeImportRecoveryStop::ROLLBACK_WAL_PUBLISH_FAILED},
            {"second_observation_failed", NdmsNativeImportRecoveryStop::SECOND_OBSERVATION_FAILED},
            {"snapshot_not_exact", NdmsNativeImportRecoveryStop::SNAPSHOT_NOT_EXACT},
            {"snapshot_retirement_failed", NdmsNativeImportRecoveryStop::SNAPSHOT_RETIREMENT_FAILED},
            {"target_verified_wal_publish_failed", NdmsNativeImportRecoveryStop::TARGET_VERIFIED_WAL_PUBLISH_FAILED},
            {"unexpected_failure", NdmsNativeImportRecoveryStop::UNEXPECTED_FAILURE},
            {"wal_cleanup_failed", NdmsNativeImportRecoveryStop::WAL_CLEANUP_FAILED},
            {"writer_lost", NdmsNativeImportRecoveryStop::WRITER_LOST},
            {"writer_missing", NdmsNativeImportRecoveryStop::WRITER_MISSING},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportRecoveryStop\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportRecoveryStop & x) {
        switch (x) {
            case NdmsNativeImportRecoveryStop::ABSENCE_WAL_PUBLISH_FAILED: j = "absence_wal_publish_failed"; break;
            case NdmsNativeImportRecoveryStop::DELETE_GUARD_REJECTED: j = "delete_guard_rejected"; break;
            case NdmsNativeImportRecoveryStop::DELETE_TRANSPORT_AMBIGUOUS: j = "delete_transport_ambiguous"; break;
            case NdmsNativeImportRecoveryStop::DELETE_WAL_NOT_CLEAN: j = "delete_wal_not_clean"; break;
            case NdmsNativeImportRecoveryStop::DELETE_WAL_PUBLISH_FAILED: j = "delete_wal_publish_failed"; break;
            case NdmsNativeImportRecoveryStop::DURABLE_OBSERVATION_FAILED: j = "durable_observation_failed"; break;
            case NdmsNativeImportRecoveryStop::EXPECTED_TARGET_NOT_MANAGED: j = "expected_target_not_managed"; break;
            case NdmsNativeImportRecoveryStop::EXTERNAL_WRITER_RACE_NOT_ACCEPTED: j = "external_writer_race_not_accepted"; break;
            case NdmsNativeImportRecoveryStop::FIRST_OBSERVATION_FAILED: j = "first_observation_failed"; break;
            case NdmsNativeImportRecoveryStop::FORWARD_ADMISSION_FAILED: j = "forward_admission_failed"; break;
            case NdmsNativeImportRecoveryStop::IMPORT_WAL_NOT_SINGLE_SAFE: j = "import_wal_not_single_safe"; break;
            case NdmsNativeImportRecoveryStop::NONE: j = "none"; break;
            case NdmsNativeImportRecoveryStop::OBSERVATION_KIND_MISMATCH: j = "observation_kind_mismatch"; break;
            case NdmsNativeImportRecoveryStop::OBSERVATION_UNSTABLE: j = "observation_unstable"; break;
            case NdmsNativeImportRecoveryStop::OWNERSHIP_NOT_EXACT: j = "ownership_not_exact"; break;
            case NdmsNativeImportRecoveryStop::OWNERSHIP_PUBLISH_FAILED: j = "ownership_publish_failed"; break;
            case NdmsNativeImportRecoveryStop::OWNERSHIP_RETRACT_FAILED: j = "ownership_retract_failed"; break;
            case NdmsNativeImportRecoveryStop::OWNERSHIP_WAL_PUBLISH_FAILED: j = "ownership_wal_publish_failed"; break;
            case NdmsNativeImportRecoveryStop::PHASE_NOT_FORWARD_ONLY: j = "phase_not_forward_only"; break;
            case NdmsNativeImportRecoveryStop::RECORD_NOT_COOPERATIVE: j = "record_not_cooperative"; break;
            case NdmsNativeImportRecoveryStop::RECOVERY_ACTION_NOT_ACTIONABLE: j = "recovery_action_not_actionable"; break;
            case NdmsNativeImportRecoveryStop::RECOVERY_ACTION_NOT_FORWARD_ONLY: j = "recovery_action_not_forward_only"; break;
            case NdmsNativeImportRecoveryStop::RECOVERY_ADMISSION_FAILED: j = "recovery_admission_failed"; break;
            case NdmsNativeImportRecoveryStop::ROLLBACK_WAL_PUBLISH_FAILED: j = "rollback_wal_publish_failed"; break;
            case NdmsNativeImportRecoveryStop::SECOND_OBSERVATION_FAILED: j = "second_observation_failed"; break;
            case NdmsNativeImportRecoveryStop::SNAPSHOT_NOT_EXACT: j = "snapshot_not_exact"; break;
            case NdmsNativeImportRecoveryStop::SNAPSHOT_RETIREMENT_FAILED: j = "snapshot_retirement_failed"; break;
            case NdmsNativeImportRecoveryStop::TARGET_VERIFIED_WAL_PUBLISH_FAILED: j = "target_verified_wal_publish_failed"; break;
            case NdmsNativeImportRecoveryStop::UNEXPECTED_FAILURE: j = "unexpected_failure"; break;
            case NdmsNativeImportRecoveryStop::WAL_CLEANUP_FAILED: j = "wal_cleanup_failed"; break;
            case NdmsNativeImportRecoveryStop::WRITER_LOST: j = "writer_lost"; break;
            case NdmsNativeImportRecoveryStop::WRITER_MISSING: j = "writer_missing"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportRecoveryStop\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RequestError & x) {
        static std::unordered_map<std::string, RequestError> enumValues {
            {"dangerous_directive", RequestError::DANGEROUS_DIRECTIVE},
            {"duplicate_field", RequestError::DUPLICATE_FIELD},
            {"duplicate_peer", RequestError::DUPLICATE_PEER},
            {"duplicate_section", RequestError::DUPLICATE_SECTION},
            {"input_too_large", RequestError::INPUT_TOO_LARGE},
            {"invalid_base64", RequestError::INVALID_BASE64},
            {"invalid_compression", RequestError::INVALID_COMPRESSION},
            {"invalid_encoding", RequestError::INVALID_ENCODING},
            {"invalid_field", RequestError::INVALID_FIELD},
            {"invalid_json", RequestError::INVALID_JSON},
            {"limit_exceeded", RequestError::LIMIT_EXCEEDED},
            {"malformed_line", RequestError::MALFORMED_LINE},
            {"missing_required_field", RequestError::MISSING_REQUIRED_FIELD},
            {"unknown_field", RequestError::UNKNOWN_FIELD},
            {"unknown_section", RequestError::UNKNOWN_SECTION},
            {"unsupported_json_schema", RequestError::UNSUPPORTED_JSON_SCHEMA},
            {"unsupported_uri", RequestError::UNSUPPORTED_URI},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RequestError\""); }
    }

    inline void to_json(json & j, const RequestError & x) {
        switch (x) {
            case RequestError::DANGEROUS_DIRECTIVE: j = "dangerous_directive"; break;
            case RequestError::DUPLICATE_FIELD: j = "duplicate_field"; break;
            case RequestError::DUPLICATE_PEER: j = "duplicate_peer"; break;
            case RequestError::DUPLICATE_SECTION: j = "duplicate_section"; break;
            case RequestError::INPUT_TOO_LARGE: j = "input_too_large"; break;
            case RequestError::INVALID_BASE64: j = "invalid_base64"; break;
            case RequestError::INVALID_COMPRESSION: j = "invalid_compression"; break;
            case RequestError::INVALID_ENCODING: j = "invalid_encoding"; break;
            case RequestError::INVALID_FIELD: j = "invalid_field"; break;
            case RequestError::INVALID_JSON: j = "invalid_json"; break;
            case RequestError::LIMIT_EXCEEDED: j = "limit_exceeded"; break;
            case RequestError::MALFORMED_LINE: j = "malformed_line"; break;
            case RequestError::MISSING_REQUIRED_FIELD: j = "missing_required_field"; break;
            case RequestError::UNKNOWN_FIELD: j = "unknown_field"; break;
            case RequestError::UNKNOWN_SECTION: j = "unknown_section"; break;
            case RequestError::UNSUPPORTED_JSON_SCHEMA: j = "unsupported_json_schema"; break;
            case RequestError::UNSUPPORTED_URI: j = "unsupported_uri"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RequestError\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportStatus & x) {
        if (j == "blocked") x = NdmsNativeImportStatus::BLOCKED;
        else if (j == "completed") x = NdmsNativeImportStatus::COMPLETED;
        else if (j == "recovery_required") x = NdmsNativeImportStatus::RECOVERY_REQUIRED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportStatus\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportStatus & x) {
        switch (x) {
            case NdmsNativeImportStatus::BLOCKED: j = "blocked"; break;
            case NdmsNativeImportStatus::COMPLETED: j = "completed"; break;
            case NdmsNativeImportStatus::RECOVERY_REQUIRED: j = "recovery_required"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeImportStop & x) {
        static std::unordered_map<std::string, NdmsNativeImportStop> enumValues {
            {"cooperative_baseline_failed", NdmsNativeImportStop::COOPERATIVE_BASELINE_FAILED},
            {"cooperative_writer_admission_failed", NdmsNativeImportStop::COOPERATIVE_WRITER_ADMISSION_FAILED},
            {"delete_wal_not_clean", NdmsNativeImportStop::DELETE_WAL_NOT_CLEAN},
            {"durable_observation_failed", NdmsNativeImportStop::DURABLE_OBSERVATION_FAILED},
            {"executor_blocked", NdmsNativeImportStop::EXECUTOR_BLOCKED},
            {"external_writer_race_not_accepted", NdmsNativeImportStop::EXTERNAL_WRITER_RACE_NOT_ACCEPTED},
            {"first_free_target_not_managed", NdmsNativeImportStop::FIRST_FREE_TARGET_NOT_MANAGED},
            {"first_post_observation_failed", NdmsNativeImportStop::FIRST_POST_OBSERVATION_FAILED},
            {"forward_admission_failed", NdmsNativeImportStop::FORWARD_ADMISSION_FAILED},
            {"forward_completion_blocked", NdmsNativeImportStop::FORWARD_COMPLETION_BLOCKED},
            {"import_wal_not_clean", NdmsNativeImportStop::IMPORT_WAL_NOT_CLEAN},
            {"marker_collision", NdmsNativeImportStop::MARKER_COLLISION},
            {"none", NdmsNativeImportStop::NONE},
            {"ownership_publish_failed", NdmsNativeImportStop::OWNERSHIP_PUBLISH_FAILED},
            {"ownership_target_not_available", NdmsNativeImportStop::OWNERSHIP_TARGET_NOT_AVAILABLE},
            {"ownership_wal_publish_failed", NdmsNativeImportStop::OWNERSHIP_WAL_PUBLISH_FAILED},
            {"post_observation_kind_mismatch", NdmsNativeImportStop::POST_OBSERVATION_KIND_MISMATCH},
            {"post_observation_unstable", NdmsNativeImportStop::POST_OBSERVATION_UNSTABLE},
            {"prewrite_catalog_diverged", NdmsNativeImportStop::PREWRITE_CATALOG_DIVERGED},
            {"prewrite_catalog_unsafe", NdmsNativeImportStop::PREWRITE_CATALOG_UNSAFE},
            {"request_invalid", NdmsNativeImportStop::REQUEST_INVALID},
            {"running_config_catalog_failed", NdmsNativeImportStop::RUNNING_CONFIG_CATALOG_FAILED},
            {"runtime_catalog_failed", NdmsNativeImportStop::RUNTIME_CATALOG_FAILED},
            {"second_post_observation_failed", NdmsNativeImportStop::SECOND_POST_OBSERVATION_FAILED},
            {"snapshot_target_not_available", NdmsNativeImportStop::SNAPSHOT_TARGET_NOT_AVAILABLE},
            {"target_verified_wal_publish_failed", NdmsNativeImportStop::TARGET_VERIFIED_WAL_PUBLISH_FAILED},
            {"unexpected_failure", NdmsNativeImportStop::UNEXPECTED_FAILURE},
            {"wal_cleanup_failed", NdmsNativeImportStop::WAL_CLEANUP_FAILED},
            {"wal_record_unavailable", NdmsNativeImportStop::WAL_RECORD_UNAVAILABLE},
            {"writer_lost", NdmsNativeImportStop::WRITER_LOST},
            {"writer_missing", NdmsNativeImportStop::WRITER_MISSING},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeImportStop\""); }
    }

    inline void to_json(json & j, const NdmsNativeImportStop & x) {
        switch (x) {
            case NdmsNativeImportStop::COOPERATIVE_BASELINE_FAILED: j = "cooperative_baseline_failed"; break;
            case NdmsNativeImportStop::COOPERATIVE_WRITER_ADMISSION_FAILED: j = "cooperative_writer_admission_failed"; break;
            case NdmsNativeImportStop::DELETE_WAL_NOT_CLEAN: j = "delete_wal_not_clean"; break;
            case NdmsNativeImportStop::DURABLE_OBSERVATION_FAILED: j = "durable_observation_failed"; break;
            case NdmsNativeImportStop::EXECUTOR_BLOCKED: j = "executor_blocked"; break;
            case NdmsNativeImportStop::EXTERNAL_WRITER_RACE_NOT_ACCEPTED: j = "external_writer_race_not_accepted"; break;
            case NdmsNativeImportStop::FIRST_FREE_TARGET_NOT_MANAGED: j = "first_free_target_not_managed"; break;
            case NdmsNativeImportStop::FIRST_POST_OBSERVATION_FAILED: j = "first_post_observation_failed"; break;
            case NdmsNativeImportStop::FORWARD_ADMISSION_FAILED: j = "forward_admission_failed"; break;
            case NdmsNativeImportStop::FORWARD_COMPLETION_BLOCKED: j = "forward_completion_blocked"; break;
            case NdmsNativeImportStop::IMPORT_WAL_NOT_CLEAN: j = "import_wal_not_clean"; break;
            case NdmsNativeImportStop::MARKER_COLLISION: j = "marker_collision"; break;
            case NdmsNativeImportStop::NONE: j = "none"; break;
            case NdmsNativeImportStop::OWNERSHIP_PUBLISH_FAILED: j = "ownership_publish_failed"; break;
            case NdmsNativeImportStop::OWNERSHIP_TARGET_NOT_AVAILABLE: j = "ownership_target_not_available"; break;
            case NdmsNativeImportStop::OWNERSHIP_WAL_PUBLISH_FAILED: j = "ownership_wal_publish_failed"; break;
            case NdmsNativeImportStop::POST_OBSERVATION_KIND_MISMATCH: j = "post_observation_kind_mismatch"; break;
            case NdmsNativeImportStop::POST_OBSERVATION_UNSTABLE: j = "post_observation_unstable"; break;
            case NdmsNativeImportStop::PREWRITE_CATALOG_DIVERGED: j = "prewrite_catalog_diverged"; break;
            case NdmsNativeImportStop::PREWRITE_CATALOG_UNSAFE: j = "prewrite_catalog_unsafe"; break;
            case NdmsNativeImportStop::REQUEST_INVALID: j = "request_invalid"; break;
            case NdmsNativeImportStop::RUNNING_CONFIG_CATALOG_FAILED: j = "running_config_catalog_failed"; break;
            case NdmsNativeImportStop::RUNTIME_CATALOG_FAILED: j = "runtime_catalog_failed"; break;
            case NdmsNativeImportStop::SECOND_POST_OBSERVATION_FAILED: j = "second_post_observation_failed"; break;
            case NdmsNativeImportStop::SNAPSHOT_TARGET_NOT_AVAILABLE: j = "snapshot_target_not_available"; break;
            case NdmsNativeImportStop::TARGET_VERIFIED_WAL_PUBLISH_FAILED: j = "target_verified_wal_publish_failed"; break;
            case NdmsNativeImportStop::UNEXPECTED_FAILURE: j = "unexpected_failure"; break;
            case NdmsNativeImportStop::WAL_CLEANUP_FAILED: j = "wal_cleanup_failed"; break;
            case NdmsNativeImportStop::WAL_RECORD_UNAVAILABLE: j = "wal_record_unavailable"; break;
            case NdmsNativeImportStop::WRITER_LOST: j = "writer_lost"; break;
            case NdmsNativeImportStop::WRITER_MISSING: j = "writer_missing"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeImportStop\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeTombstoneForgetArtifactState & x) {
        if (j == "absent_durable") x = NdmsNativeTombstoneForgetArtifactState::ABSENT_DURABLE;
        else if (j == "retained") x = NdmsNativeTombstoneForgetArtifactState::RETAINED;
        else if (j == "unknown") x = NdmsNativeTombstoneForgetArtifactState::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeTombstoneForgetArtifactState\""); }
    }

    inline void to_json(json & j, const NdmsNativeTombstoneForgetArtifactState & x) {
        switch (x) {
            case NdmsNativeTombstoneForgetArtifactState::ABSENT_DURABLE: j = "absent_durable"; break;
            case NdmsNativeTombstoneForgetArtifactState::RETAINED: j = "retained"; break;
            case NdmsNativeTombstoneForgetArtifactState::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeTombstoneForgetArtifactState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ForeignReappearanceAcknowledgement & x) {
        if (j == "accepted_reappearance_is_foreign") x = ForeignReappearanceAcknowledgement::ACCEPTED_REAPPEARANCE_IS_FOREIGN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ForeignReappearanceAcknowledgement\""); }
    }

    inline void to_json(json & j, const ForeignReappearanceAcknowledgement & x) {
        switch (x) {
            case ForeignReappearanceAcknowledgement::ACCEPTED_REAPPEARANCE_IS_FOREIGN: j = "accepted_reappearance_is_foreign"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ForeignReappearanceAcknowledgement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, RollbackDiscardAcknowledgement & x) {
        if (j == "permanently_discard_rollback_data") x = RollbackDiscardAcknowledgement::PERMANENTLY_DISCARD_ROLLBACK_DATA;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RollbackDiscardAcknowledgement\""); }
    }

    inline void to_json(json & j, const RollbackDiscardAcknowledgement & x) {
        switch (x) {
            case RollbackDiscardAcknowledgement::PERMANENTLY_DISCARD_ROLLBACK_DATA: j = "permanently_discard_rollback_data"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RollbackDiscardAcknowledgement\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeTombstoneForgetStatus & x) {
        if (j == "blocked") x = NdmsNativeTombstoneForgetStatus::BLOCKED;
        else if (j == "forgotten") x = NdmsNativeTombstoneForgetStatus::FORGOTTEN;
        else if (j == "recovery_required") x = NdmsNativeTombstoneForgetStatus::RECOVERY_REQUIRED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeTombstoneForgetStatus\""); }
    }

    inline void to_json(json & j, const NdmsNativeTombstoneForgetStatus & x) {
        switch (x) {
            case NdmsNativeTombstoneForgetStatus::BLOCKED: j = "blocked"; break;
            case NdmsNativeTombstoneForgetStatus::FORGOTTEN: j = "forgotten"; break;
            case NdmsNativeTombstoneForgetStatus::RECOVERY_REQUIRED: j = "recovery_required"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeTombstoneForgetStatus\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NdmsNativeTombstoneForgetStop & x) {
        static std::unordered_map<std::string, NdmsNativeTombstoneForgetStop> enumValues {
            {"delete_wal_unfinished", NdmsNativeTombstoneForgetStop::DELETE_WAL_UNFINISHED},
            {"delete_wal_unsafe", NdmsNativeTombstoneForgetStop::DELETE_WAL_UNSAFE},
            {"import_wal_not_authoritatively_clean", NdmsNativeTombstoneForgetStop::IMPORT_WAL_NOT_AUTHORITATIVELY_CLEAN},
            {"keen_pbr_dependencies_present", NdmsNativeTombstoneForgetStop::KEEN_PBR_DEPENDENCIES_PRESENT},
            {"keen_pbr_dependency_scan_incomplete", NdmsNativeTombstoneForgetStop::KEEN_PBR_DEPENDENCY_SCAN_INCOMPLETE},
            {"kernel_inventory_unavailable", NdmsNativeTombstoneForgetStop::KERNEL_INVENTORY_UNAVAILABLE},
            {"none", NdmsNativeTombstoneForgetStop::NONE},
            {"observation_scope_mismatch", NdmsNativeTombstoneForgetStop::OBSERVATION_SCOPE_MISMATCH},
            {"observed_catalog_unsafe", NdmsNativeTombstoneForgetStop::OBSERVED_CATALOG_UNSAFE},
            {"observed_marker_present", NdmsNativeTombstoneForgetStop::OBSERVED_MARKER_PRESENT},
            {"observed_target_present", NdmsNativeTombstoneForgetStop::OBSERVED_TARGET_PRESENT},
            {"ownership_absent", NdmsNativeTombstoneForgetStop::OWNERSHIP_ABSENT},
            {"ownership_changed", NdmsNativeTombstoneForgetStop::OWNERSHIP_CHANGED},
            {"ownership_not_forget_capable", NdmsNativeTombstoneForgetStop::OWNERSHIP_NOT_FORGET_CAPABLE},
            {"ownership_unreadable", NdmsNativeTombstoneForgetStop::OWNERSHIP_UNREADABLE},
            {"retained_kernel_interface_present", NdmsNativeTombstoneForgetStop::RETAINED_KERNEL_INTERFACE_PRESENT},
            {"running_config_observation_failed", NdmsNativeTombstoneForgetStop::RUNNING_CONFIG_OBSERVATION_FAILED},
            {"runtime_observation_failed", NdmsNativeTombstoneForgetStop::RUNTIME_OBSERVATION_FAILED},
            {"snapshot_mismatch", NdmsNativeTombstoneForgetStop::SNAPSHOT_MISMATCH},
            {"snapshot_retirement_failed", NdmsNativeTombstoneForgetStop::SNAPSHOT_RETIREMENT_FAILED},
            {"snapshot_unreadable", NdmsNativeTombstoneForgetStop::SNAPSHOT_UNREADABLE},
            {"tombstone_retirement_failed", NdmsNativeTombstoneForgetStop::TOMBSTONE_RETIREMENT_FAILED},
            {"unexpected_failure", NdmsNativeTombstoneForgetStop::UNEXPECTED_FAILURE},
            {"writer_lost", NdmsNativeTombstoneForgetStop::WRITER_LOST},
            {"writer_missing", NdmsNativeTombstoneForgetStop::WRITER_MISSING},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NdmsNativeTombstoneForgetStop\""); }
    }

    inline void to_json(json & j, const NdmsNativeTombstoneForgetStop & x) {
        switch (x) {
            case NdmsNativeTombstoneForgetStop::DELETE_WAL_UNFINISHED: j = "delete_wal_unfinished"; break;
            case NdmsNativeTombstoneForgetStop::DELETE_WAL_UNSAFE: j = "delete_wal_unsafe"; break;
            case NdmsNativeTombstoneForgetStop::IMPORT_WAL_NOT_AUTHORITATIVELY_CLEAN: j = "import_wal_not_authoritatively_clean"; break;
            case NdmsNativeTombstoneForgetStop::KEEN_PBR_DEPENDENCIES_PRESENT: j = "keen_pbr_dependencies_present"; break;
            case NdmsNativeTombstoneForgetStop::KEEN_PBR_DEPENDENCY_SCAN_INCOMPLETE: j = "keen_pbr_dependency_scan_incomplete"; break;
            case NdmsNativeTombstoneForgetStop::KERNEL_INVENTORY_UNAVAILABLE: j = "kernel_inventory_unavailable"; break;
            case NdmsNativeTombstoneForgetStop::NONE: j = "none"; break;
            case NdmsNativeTombstoneForgetStop::OBSERVATION_SCOPE_MISMATCH: j = "observation_scope_mismatch"; break;
            case NdmsNativeTombstoneForgetStop::OBSERVED_CATALOG_UNSAFE: j = "observed_catalog_unsafe"; break;
            case NdmsNativeTombstoneForgetStop::OBSERVED_MARKER_PRESENT: j = "observed_marker_present"; break;
            case NdmsNativeTombstoneForgetStop::OBSERVED_TARGET_PRESENT: j = "observed_target_present"; break;
            case NdmsNativeTombstoneForgetStop::OWNERSHIP_ABSENT: j = "ownership_absent"; break;
            case NdmsNativeTombstoneForgetStop::OWNERSHIP_CHANGED: j = "ownership_changed"; break;
            case NdmsNativeTombstoneForgetStop::OWNERSHIP_NOT_FORGET_CAPABLE: j = "ownership_not_forget_capable"; break;
            case NdmsNativeTombstoneForgetStop::OWNERSHIP_UNREADABLE: j = "ownership_unreadable"; break;
            case NdmsNativeTombstoneForgetStop::RETAINED_KERNEL_INTERFACE_PRESENT: j = "retained_kernel_interface_present"; break;
            case NdmsNativeTombstoneForgetStop::RUNNING_CONFIG_OBSERVATION_FAILED: j = "running_config_observation_failed"; break;
            case NdmsNativeTombstoneForgetStop::RUNTIME_OBSERVATION_FAILED: j = "runtime_observation_failed"; break;
            case NdmsNativeTombstoneForgetStop::SNAPSHOT_MISMATCH: j = "snapshot_mismatch"; break;
            case NdmsNativeTombstoneForgetStop::SNAPSHOT_RETIREMENT_FAILED: j = "snapshot_retirement_failed"; break;
            case NdmsNativeTombstoneForgetStop::SNAPSHOT_UNREADABLE: j = "snapshot_unreadable"; break;
            case NdmsNativeTombstoneForgetStop::TOMBSTONE_RETIREMENT_FAILED: j = "tombstone_retirement_failed"; break;
            case NdmsNativeTombstoneForgetStop::UNEXPECTED_FAILURE: j = "unexpected_failure"; break;
            case NdmsNativeTombstoneForgetStop::WRITER_LOST: j = "writer_lost"; break;
            case NdmsNativeTombstoneForgetStop::WRITER_MISSING: j = "writer_missing"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NdmsNativeTombstoneForgetStop\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, NfqwsActionRequestAction & x) {
        static std::unordered_map<std::string, NfqwsActionRequestAction> enumValues {
            {"apply_strategy", NfqwsActionRequestAction::APPLY_STRATEGY},
            {"capture_restore_point", NfqwsActionRequestAction::CAPTURE_RESTORE_POINT},
            {"check_update", NfqwsActionRequestAction::CHECK_UPDATE},
            {"check_url", NfqwsActionRequestAction::CHECK_URL},
            {"clear_log", NfqwsActionRequestAction::CLEAR_LOG},
            {"create_file", NfqwsActionRequestAction::CREATE_FILE},
            {"delete_file", NfqwsActionRequestAction::DELETE_FILE},
            {"delete_strategy", NfqwsActionRequestAction::DELETE_STRATEGY},
            {"import_bundle", NfqwsActionRequestAction::IMPORT_BUNDLE},
            {"import_lists", NfqwsActionRequestAction::IMPORT_LISTS},
            {"install", NfqwsActionRequestAction::INSTALL},
            {"read_file", NfqwsActionRequestAction::READ_FILE},
            {"restore_component", NfqwsActionRequestAction::RESTORE_COMPONENT},
            {"save_file", NfqwsActionRequestAction::SAVE_FILE},
            {"save_files", NfqwsActionRequestAction::SAVE_FILES},
            {"save_strategy", NfqwsActionRequestAction::SAVE_STRATEGY},
            {"service", NfqwsActionRequestAction::SERVICE},
            {"upgrade", NfqwsActionRequestAction::UPGRADE},
        };
        auto iter = enumValues.find(j.get<std::string>());
        if (iter != enumValues.end()) {
            x = iter->second;
        }
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NfqwsActionRequestAction\""); }
    }

    inline void to_json(json & j, const NfqwsActionRequestAction & x) {
        switch (x) {
            case NfqwsActionRequestAction::APPLY_STRATEGY: j = "apply_strategy"; break;
            case NfqwsActionRequestAction::CAPTURE_RESTORE_POINT: j = "capture_restore_point"; break;
            case NfqwsActionRequestAction::CHECK_UPDATE: j = "check_update"; break;
            case NfqwsActionRequestAction::CHECK_URL: j = "check_url"; break;
            case NfqwsActionRequestAction::CLEAR_LOG: j = "clear_log"; break;
            case NfqwsActionRequestAction::CREATE_FILE: j = "create_file"; break;
            case NfqwsActionRequestAction::DELETE_FILE: j = "delete_file"; break;
            case NfqwsActionRequestAction::DELETE_STRATEGY: j = "delete_strategy"; break;
            case NfqwsActionRequestAction::IMPORT_BUNDLE: j = "import_bundle"; break;
            case NfqwsActionRequestAction::IMPORT_LISTS: j = "import_lists"; break;
            case NfqwsActionRequestAction::INSTALL: j = "install"; break;
            case NfqwsActionRequestAction::READ_FILE: j = "read_file"; break;
            case NfqwsActionRequestAction::RESTORE_COMPONENT: j = "restore_component"; break;
            case NfqwsActionRequestAction::SAVE_FILE: j = "save_file"; break;
            case NfqwsActionRequestAction::SAVE_FILES: j = "save_files"; break;
            case NfqwsActionRequestAction::SAVE_STRATEGY: j = "save_strategy"; break;
            case NfqwsActionRequestAction::SERVICE: j = "service"; break;
            case NfqwsActionRequestAction::UPGRADE: j = "upgrade"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NfqwsActionRequestAction\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NfqwsActionRequestCategory & x) {
        if (j == "config") x = NfqwsActionRequestCategory::CONFIG;
        else if (j == "list") x = NfqwsActionRequestCategory::LIST;
        else if (j == "log") x = NfqwsActionRequestCategory::LOG;
        else if (j == "lua") x = NfqwsActionRequestCategory::LUA;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NfqwsActionRequestCategory\""); }
    }

    inline void to_json(json & j, const NfqwsActionRequestCategory & x) {
        switch (x) {
            case NfqwsActionRequestCategory::CONFIG: j = "config"; break;
            case NfqwsActionRequestCategory::LIST: j = "list"; break;
            case NfqwsActionRequestCategory::LOG: j = "log"; break;
            case NfqwsActionRequestCategory::LUA: j = "lua"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NfqwsActionRequestCategory\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Command & x) {
        if (j == "reload") x = Command::RELOAD;
        else if (j == "restart") x = Command::RESTART;
        else if (j == "start") x = Command::START;
        else if (j == "stop") x = Command::STOP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Command\""); }
    }

    inline void to_json(json & j, const Command & x) {
        switch (x) {
            case Command::RELOAD: j = "reload"; break;
            case Command::RESTART: j = "restart"; break;
            case Command::START: j = "start"; break;
            case Command::STOP: j = "stop"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Command\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, NfqwsFileEntryCategory & x) {
        if (j == "list") x = NfqwsFileEntryCategory::LIST;
        else if (j == "lua") x = NfqwsFileEntryCategory::LUA;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"NfqwsFileEntryCategory\""); }
    }

    inline void to_json(json & j, const NfqwsFileEntryCategory & x) {
        switch (x) {
            case NfqwsFileEntryCategory::LIST: j = "list"; break;
            case NfqwsFileEntryCategory::LUA: j = "lua"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"NfqwsFileEntryCategory\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, PpeDeoffloadCapability & x) {
        if (j == "supported") x = PpeDeoffloadCapability::SUPPORTED;
        else if (j == "unknown") x = PpeDeoffloadCapability::UNKNOWN;
        else if (j == "unsupported") x = PpeDeoffloadCapability::UNSUPPORTED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"PpeDeoffloadCapability\""); }
    }

    inline void to_json(json & j, const PpeDeoffloadCapability & x) {
        switch (x) {
            case PpeDeoffloadCapability::SUPPORTED: j = "supported"; break;
            case PpeDeoffloadCapability::UNKNOWN: j = "unknown"; break;
            case PpeDeoffloadCapability::UNSUPPORTED: j = "unsupported"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"PpeDeoffloadCapability\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, PpeDeoffloadHealthState & x) {
        if (j == "active") x = PpeDeoffloadHealthState::ACTIVE;
        else if (j == "admissible") x = PpeDeoffloadHealthState::ADMISSIBLE;
        else if (j == "degraded") x = PpeDeoffloadHealthState::DEGRADED;
        else if (j == "inactive") x = PpeDeoffloadHealthState::INACTIVE;
        else if (j == "off") x = PpeDeoffloadHealthState::OFF;
        else if (j == "unknown") x = PpeDeoffloadHealthState::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"PpeDeoffloadHealthState\""); }
    }

    inline void to_json(json & j, const PpeDeoffloadHealthState & x) {
        switch (x) {
            case PpeDeoffloadHealthState::ACTIVE: j = "active"; break;
            case PpeDeoffloadHealthState::ADMISSIBLE: j = "admissible"; break;
            case PpeDeoffloadHealthState::DEGRADED: j = "degraded"; break;
            case PpeDeoffloadHealthState::INACTIVE: j = "inactive"; break;
            case PpeDeoffloadHealthState::OFF: j = "off"; break;
            case PpeDeoffloadHealthState::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"PpeDeoffloadHealthState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Reason & x) {
        if (j == "lookup_failed") x = Reason::LOOKUP_FAILED;
        else if (j == "registry_lookup_disabled") x = Reason::REGISTRY_LOOKUP_DISABLED;
        else if (j == "unreadable_response") x = Reason::UNREADABLE_RESPONSE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Reason\""); }
    }

    inline void to_json(json & j, const Reason & x) {
        switch (x) {
            case Reason::LOOKUP_FAILED: j = "lookup_failed"; break;
            case Reason::REGISTRY_LOOKUP_DISABLED: j = "registry_lookup_disabled"; break;
            case Reason::UNREADABLE_RESPONSE: j = "unreadable_response"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Reason\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, BlockedReason & x) {
        if (j == "auth_state_unavailable") x = BlockedReason::AUTH_STATE_UNAVAILABLE;
        else if (j == "keenetic_auth_plaintext_wan") x = BlockedReason::KEENETIC_AUTH_PLAINTEXT_WAN;
        else if (j == "listen_loopback") x = BlockedReason::LISTEN_LOOPBACK;
        else if (j == "login_disabled") x = BlockedReason::LOGIN_DISABLED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"BlockedReason\""); }
    }

    inline void to_json(json & j, const BlockedReason & x) {
        switch (x) {
            case BlockedReason::AUTH_STATE_UNAVAILABLE: j = "auth_state_unavailable"; break;
            case BlockedReason::KEENETIC_AUTH_PLAINTEXT_WAN: j = "keenetic_auth_plaintext_wan"; break;
            case BlockedReason::LISTEN_LOOPBACK: j = "listen_loopback"; break;
            case BlockedReason::LOGIN_DISABLED: j = "login_disabled"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"BlockedReason\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, SystemAuthState & x) {
        if (j == "challenge_absent") x = SystemAuthState::CHALLENGE_ABSENT;
        else if (j == "endpoint_unproven") x = SystemAuthState::ENDPOINT_UNPROVEN;
        else if (j == "firmware_policy_unknown") x = SystemAuthState::FIRMWARE_POLICY_UNKNOWN;
        else if (j == "lockout_budget_unsafe") x = SystemAuthState::LOCKOUT_BUDGET_UNSAFE;
        else if (j == "loopback_not_accepted") x = SystemAuthState::LOOPBACK_NOT_ACCEPTED;
        else if (j == "usable") x = SystemAuthState::USABLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"SystemAuthState\""); }
    }

    inline void to_json(json & j, const SystemAuthState & x) {
        switch (x) {
            case SystemAuthState::CHALLENGE_ABSENT: j = "challenge_absent"; break;
            case SystemAuthState::ENDPOINT_UNPROVEN: j = "endpoint_unproven"; break;
            case SystemAuthState::FIRMWARE_POLICY_UNKNOWN: j = "firmware_policy_unknown"; break;
            case SystemAuthState::LOCKOUT_BUDGET_UNSAFE: j = "lockout_budget_unsafe"; break;
            case SystemAuthState::LOOPBACK_NOT_ACCEPTED: j = "loopback_not_accepted"; break;
            case SystemAuthState::USABLE: j = "usable"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"SystemAuthState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TtlBypassState & x) {
        if (j == "active") x = TtlBypassState::ACTIVE;
        else if (j == "chain_absent") x = TtlBypassState::CHAIN_ABSENT;
        else if (j == "conflict") x = TtlBypassState::CONFLICT;
        else if (j == "disabled") x = TtlBypassState::DISABLED;
        else if (j == "missing") x = TtlBypassState::MISSING;
        else if (j == "unknown") x = TtlBypassState::UNKNOWN;
        else if (j == "unsupported") x = TtlBypassState::UNSUPPORTED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TtlBypassState\""); }
    }

    inline void to_json(json & j, const TtlBypassState & x) {
        switch (x) {
            case TtlBypassState::ACTIVE: j = "active"; break;
            case TtlBypassState::CHAIN_ABSENT: j = "chain_absent"; break;
            case TtlBypassState::CONFLICT: j = "conflict"; break;
            case TtlBypassState::DISABLED: j = "disabled"; break;
            case TtlBypassState::MISSING: j = "missing"; break;
            case TtlBypassState::UNKNOWN: j = "unknown"; break;
            case TtlBypassState::UNSUPPORTED: j = "unsupported"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TtlBypassState\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, RoutingTestNfqwsMatchRole & x) {
        if (j == "hostlist") x = RoutingTestNfqwsMatchRole::HOSTLIST;
        else if (j == "hostlist_auto") x = RoutingTestNfqwsMatchRole::HOSTLIST_AUTO;
        else if (j == "hostlist_exclude") x = RoutingTestNfqwsMatchRole::HOSTLIST_EXCLUDE;
        else if (j == "ipset") x = RoutingTestNfqwsMatchRole::IPSET;
        else if (j == "ipset_exclude") x = RoutingTestNfqwsMatchRole::IPSET_EXCLUDE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"RoutingTestNfqwsMatchRole\""); }
    }

    inline void to_json(json & j, const RoutingTestNfqwsMatchRole & x) {
        switch (x) {
            case RoutingTestNfqwsMatchRole::HOSTLIST: j = "hostlist"; break;
            case RoutingTestNfqwsMatchRole::HOSTLIST_AUTO: j = "hostlist_auto"; break;
            case RoutingTestNfqwsMatchRole::HOSTLIST_EXCLUDE: j = "hostlist_exclude"; break;
            case RoutingTestNfqwsMatchRole::IPSET: j = "ipset"; break;
            case RoutingTestNfqwsMatchRole::IPSET_EXCLUDE: j = "ipset_exclude"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"RoutingTestNfqwsMatchRole\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, Blocker & x) {
        if (j == "architecture_unsupported") x = Blocker::ARCHITECTURE_UNSUPPORTED;
        else if (j == "entware_absent") x = Blocker::ENTWARE_ABSENT;
        else if (j == "foreign_binary_present") x = Blocker::FOREIGN_BINARY_PRESENT;
        else if (j == "target_not_writable") x = Blocker::TARGET_NOT_WRITABLE;
        else if (j == "transports_running") x = Blocker::TRANSPORTS_RUNNING;
        else if (j == "transport_state_unknown") x = Blocker::TRANSPORT_STATE_UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Blocker\""); }
    }

    inline void to_json(json & j, const Blocker & x) {
        switch (x) {
            case Blocker::ARCHITECTURE_UNSUPPORTED: j = "architecture_unsupported"; break;
            case Blocker::ENTWARE_ABSENT: j = "entware_absent"; break;
            case Blocker::FOREIGN_BINARY_PRESENT: j = "foreign_binary_present"; break;
            case Blocker::TARGET_NOT_WRITABLE: j = "target_not_writable"; break;
            case Blocker::TRANSPORTS_RUNNING: j = "transports_running"; break;
            case Blocker::TRANSPORT_STATE_UNKNOWN: j = "transport_state_unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Blocker\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, SingBoxInstallCapabilityOperation & x) {
        if (j == "install") x = SingBoxInstallCapabilityOperation::INSTALL;
        else if (j == "reinstall_same_version") x = SingBoxInstallCapabilityOperation::REINSTALL_SAME_VERSION;
        else if (j == "replace") x = SingBoxInstallCapabilityOperation::REPLACE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"SingBoxInstallCapabilityOperation\""); }
    }

    inline void to_json(json & j, const SingBoxInstallCapabilityOperation & x) {
        switch (x) {
            case SingBoxInstallCapabilityOperation::INSTALL: j = "install"; break;
            case SingBoxInstallCapabilityOperation::REINSTALL_SAME_VERSION: j = "reinstall_same_version"; break;
            case SingBoxInstallCapabilityOperation::REPLACE: j = "replace"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"SingBoxInstallCapabilityOperation\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, InstallOutcome & x) {
        if (j == "archive_unusable") x = InstallOutcome::ARCHIVE_UNUSABLE;
        else if (j == "cancelled") x = InstallOutcome::CANCELLED;
        else if (j == "checksum_mismatch") x = InstallOutcome::CHECKSUM_MISMATCH;
        else if (j == "download_failed") x = InstallOutcome::DOWNLOAD_FAILED;
        else if (j == "installed") x = InstallOutcome::INSTALLED;
        else if (j == "install_failed") x = InstallOutcome::INSTALL_FAILED;
        else if (j == "marker_not_written") x = InstallOutcome::MARKER_NOT_WRITTEN;
        else if (j == "release_refused") x = InstallOutcome::RELEASE_REFUSED;
        else if (j == "staged_version_mismatch") x = InstallOutcome::STAGED_VERSION_MISMATCH;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"InstallOutcome\""); }
    }

    inline void to_json(json & j, const InstallOutcome & x) {
        switch (x) {
            case InstallOutcome::ARCHIVE_UNUSABLE: j = "archive_unusable"; break;
            case InstallOutcome::CANCELLED: j = "cancelled"; break;
            case InstallOutcome::CHECKSUM_MISMATCH: j = "checksum_mismatch"; break;
            case InstallOutcome::DOWNLOAD_FAILED: j = "download_failed"; break;
            case InstallOutcome::INSTALLED: j = "installed"; break;
            case InstallOutcome::INSTALL_FAILED: j = "install_failed"; break;
            case InstallOutcome::MARKER_NOT_WRITTEN: j = "marker_not_written"; break;
            case InstallOutcome::RELEASE_REFUSED: j = "release_refused"; break;
            case InstallOutcome::STAGED_VERSION_MISMATCH: j = "staged_version_mismatch"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"InstallOutcome\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, ReleaseVerdict & x) {
        if (j == "archive_missing") x = ReleaseVerdict::ARCHIVE_MISSING;
        else if (j == "checksums_missing") x = ReleaseVerdict::CHECKSUMS_MISSING;
        else if (j == "checksum_mismatch") x = ReleaseVerdict::CHECKSUM_MISMATCH;
        else if (j == "checksum_unusable") x = ReleaseVerdict::CHECKSUM_UNUSABLE;
        else if (j == "ready") x = ReleaseVerdict::READY;
        else if (j == "release_unreadable") x = ReleaseVerdict::RELEASE_UNREADABLE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ReleaseVerdict\""); }
    }

    inline void to_json(json & j, const ReleaseVerdict & x) {
        switch (x) {
            case ReleaseVerdict::ARCHIVE_MISSING: j = "archive_missing"; break;
            case ReleaseVerdict::CHECKSUMS_MISSING: j = "checksums_missing"; break;
            case ReleaseVerdict::CHECKSUM_MISMATCH: j = "checksum_mismatch"; break;
            case ReleaseVerdict::CHECKSUM_UNUSABLE: j = "checksum_unusable"; break;
            case ReleaseVerdict::READY: j = "ready"; break;
            case ReleaseVerdict::RELEASE_UNREADABLE: j = "release_unreadable"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ReleaseVerdict\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, SingBoxProcessMode & x) {
        if (j == "isolated") x = SingBoxProcessMode::ISOLATED;
        else if (j == "shared") x = SingBoxProcessMode::SHARED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"SingBoxProcessMode\""); }
    }

    inline void to_json(json & j, const SingBoxProcessMode & x) {
        switch (x) {
            case SingBoxProcessMode::ISOLATED: j = "isolated"; break;
            case SingBoxProcessMode::SHARED: j = "shared"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"SingBoxProcessMode\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, Outcome & x) {
        if (j == "already_imported") x = Outcome::ALREADY_IMPORTED;
        else if (j == "created") x = Outcome::CREATED;
        else if (j == "failed") x = Outcome::FAILED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Outcome\""); }
    }

    inline void to_json(json & j, const Outcome & x) {
        switch (x) {
            case Outcome::ALREADY_IMPORTED: j = "already_imported"; break;
            case Outcome::CREATED: j = "created"; break;
            case Outcome::FAILED: j = "failed"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Outcome\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Disposition & x) {
        if (j == "already_configured") x = Disposition::ALREADY_CONFIGURED;
        else if (j == "duplicate_in_document") x = Disposition::DUPLICATE_IN_DOCUMENT;
        else if (j == "importable") x = Disposition::IMPORTABLE;
        else if (j == "malformed") x = Disposition::MALFORMED;
        else if (j == "scheme_not_supported") x = Disposition::SCHEME_NOT_SUPPORTED;
        else if (j == "tag_conflict") x = Disposition::TAG_CONFLICT;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Disposition\""); }
    }

    inline void to_json(json & j, const Disposition & x) {
        switch (x) {
            case Disposition::ALREADY_CONFIGURED: j = "already_configured"; break;
            case Disposition::DUPLICATE_IN_DOCUMENT: j = "duplicate_in_document"; break;
            case Disposition::IMPORTABLE: j = "importable"; break;
            case Disposition::MALFORMED: j = "malformed"; break;
            case Disposition::SCHEME_NOT_SUPPORTED: j = "scheme_not_supported"; break;
            case Disposition::TAG_CONFLICT: j = "tag_conflict"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Disposition\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, DocumentKind & x) {
        if (j == "base64_link_list") x = DocumentKind::BASE64_LINK_LIST;
        else if (j == "empty") x = DocumentKind::EMPTY;
        else if (j == "json_document") x = DocumentKind::JSON_DOCUMENT;
        else if (j == "link_list") x = DocumentKind::LINK_LIST;
        else if (j == "too_large") x = DocumentKind::TOO_LARGE;
        else if (j == "unrecognized") x = DocumentKind::UNRECOGNIZED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"DocumentKind\""); }
    }

    inline void to_json(json & j, const DocumentKind & x) {
        switch (x) {
            case DocumentKind::BASE64_LINK_LIST: j = "base64_link_list"; break;
            case DocumentKind::EMPTY: j = "empty"; break;
            case DocumentKind::JSON_DOCUMENT: j = "json_document"; break;
            case DocumentKind::LINK_LIST: j = "link_list"; break;
            case DocumentKind::TOO_LARGE: j = "too_large"; break;
            case DocumentKind::UNRECOGNIZED: j = "unrecognized"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"DocumentKind\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, PackageRollbackState & x) {
        if (j == "available") x = PackageRollbackState::AVAILABLE;
        else if (j == "helper_missing") x = PackageRollbackState::HELPER_MISSING;
        else if (j == "never_captured") x = PackageRollbackState::NEVER_CAPTURED;
        else if (j == "package_unverified") x = PackageRollbackState::PACKAGE_UNVERIFIED;
        else if (j == "recovery_pending") x = PackageRollbackState::RECOVERY_PENDING;
        else if (j == "recovery_unknown") x = PackageRollbackState::RECOVERY_UNKNOWN;
        else if (j == "snapshot_unverified") x = PackageRollbackState::SNAPSHOT_UNVERIFIED;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"PackageRollbackState\""); }
    }

    inline void to_json(json & j, const PackageRollbackState & x) {
        switch (x) {
            case PackageRollbackState::AVAILABLE: j = "available"; break;
            case PackageRollbackState::HELPER_MISSING: j = "helper_missing"; break;
            case PackageRollbackState::NEVER_CAPTURED: j = "never_captured"; break;
            case PackageRollbackState::PACKAGE_UNVERIFIED: j = "package_unverified"; break;
            case PackageRollbackState::RECOVERY_PENDING: j = "recovery_pending"; break;
            case PackageRollbackState::RECOVERY_UNKNOWN: j = "recovery_unknown"; break;
            case PackageRollbackState::SNAPSHOT_UNVERIFIED: j = "snapshot_unverified"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"PackageRollbackState\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, TransportActionRequestAction & x) {
        if (j == "down") x = TransportActionRequestAction::DOWN;
        else if (j == "restart") x = TransportActionRequestAction::RESTART;
        else if (j == "up") x = TransportActionRequestAction::UP;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"TransportActionRequestAction\""); }
    }

    inline void to_json(json & j, const TransportActionRequestAction & x) {
        switch (x) {
            case TransportActionRequestAction::DOWN: j = "down"; break;
            case TransportActionRequestAction::RESTART: j = "restart"; break;
            case TransportActionRequestAction::UP: j = "up"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"TransportActionRequestAction\": " + std::to_string(static_cast<int>(x)));
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

    inline void from_json(const json & j, ExitAddress & x) {
        if (j == "changed") x = ExitAddress::CHANGED;
        else if (j == "same") x = ExitAddress::SAME;
        else if (j == "unknown") x = ExitAddress::UNKNOWN;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"ExitAddress\""); }
    }

    inline void to_json(json & j, const ExitAddress & x) {
        switch (x) {
            case ExitAddress::CHANGED: j = "changed"; break;
            case ExitAddress::SAME: j = "same"; break;
            case ExitAddress::UNKNOWN: j = "unknown"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"ExitAddress\": " + std::to_string(static_cast<int>(x)));
        }
    }

    inline void from_json(const json & j, Verdict & x) {
        if (j == "unattributed") x = Verdict::UNATTRIBUTED;
        else if (j == "unreachable") x = Verdict::UNREACHABLE;
        else if (j == "working") x = Verdict::WORKING;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Verdict\""); }
    }

    inline void to_json(json & j, const Verdict & x) {
        switch (x) {
            case Verdict::UNATTRIBUTED: j = "unattributed"; break;
            case Verdict::UNREACHABLE: j = "unreachable"; break;
            case Verdict::WORKING: j = "working"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Verdict\": " + std::to_string(static_cast<int>(x)));
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
namespace nlohmann {
    inline void adl_serializer<std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>>>::from_json(const json & j, std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>> & x) {
        if (j.is_object())
            x = j.get<std::map<std::string, json>>();
        else if (j.is_array())
            x = j.get<std::vector<keen_pbr3::api::NfqwsFileEntryElement>>();
        else throw std::runtime_error("Could not deserialise!");
    }

    inline void adl_serializer<std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>>>::to_json(json & j, const std::variant<std::vector<keen_pbr3::api::NfqwsFileEntryElement>, std::map<std::string, json>> & x) {
        switch (x.index()) {
            case 0:
                j = std::get<std::vector<keen_pbr3::api::NfqwsFileEntryElement>>(x);
                break;
            case 1:
                j = std::get<std::map<std::string, json>>(x);
                break;
            default: throw std::runtime_error("Input JSON does not conform to schema!");
        }
    }
}
