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

    struct CacheMetadata {
        std::optional<int64_t> cidrs;
        std::optional<int64_t> domains;
        std::optional<std::string> download_time;
        std::optional<std::string> etag;
        std::optional<int64_t> ips;
        std::optional<std::string> last_modified;
        std::optional<std::string> url;
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

    struct Daemon {
        std::optional<std::string> cache_dir;
        std::optional<bool> clear_dynamic_sets_on_apply;
        std::optional<DaemonConfigFirewallBackend> firewall_backend;
        std::optional<int64_t> firewall_verify_max_bytes;
        std::optional<bool> ipv6_enabled;
        std::optional<int64_t> max_file_size_bytes;
        std::optional<std::string> pid_file;
        std::optional<bool> skip_marked_packets;
        std::optional<bool> strict_enforcement;
    };

    struct DnsTestServer {
        std::optional<std::string> answer_ipv4;
        std::string listen;
    };

    struct DnsRuleElement {
        std::optional<bool> allow_domain_rebinding;
        std::optional<bool> enabled;
        std::vector<std::string> list;
        std::string server;
    };

    enum class DnsServerType : int { KEENETIC, STATIC };

    struct DnsServerElement {
        std::optional<std::string> address;
        std::optional<std::string> detour;
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

    struct ListConfigValue {
        std::optional<std::string> detour;
        std::optional<std::vector<std::string>> domains;
        std::optional<std::string> file;
        std::optional<std::vector<std::string>> ip_cidrs;
        std::optional<int64_t> ttl_ms;
        std::optional<std::string> url;
    };

    struct ListsAutoupdate {
        std::optional<std::string> cron;
        std::optional<bool> enabled;
    };

    struct OutboundGroupElement {
        std::vector<std::string> outbounds;
        std::optional<int64_t> weight;
    };

    struct Retry {
        std::optional<int64_t> attempts;
        std::optional<int64_t> interval_ms;
    };

    enum class OutboundType : int { BLACKHOLE, IGNORE, INTERFACE, TABLE, URLTEST };

    struct OutboundElement {
        std::optional<CircuitBreakerConfig> circuit_breaker;
        std::optional<std::string> gateway;
        std::optional<std::string> gateway6;
        std::optional<std::string> interface;
        std::optional<int64_t> interval_ms;
        std::optional<std::vector<OutboundGroupElement>> outbound_groups;
        std::optional<int64_t> probe_timeout_ms;
        std::optional<Retry> retry;
        std::optional<bool> strict_enforcement;
        std::optional<int64_t> table;
        std::string tag;
        std::optional<int64_t> tolerance_ms;
        OutboundType type;
        std::optional<std::string> url;
    };

    struct RouteRuleElement {
        std::optional<std::string> dest_addr;
        std::optional<std::string> dest_port;
        std::optional<int64_t> dscp;
        std::optional<bool> enabled;
        std::optional<std::vector<std::string>> list;
        std::string outbound;
        std::optional<std::string> proto;
        std::optional<std::string> src_addr;
        std::optional<std::string> src_port;
    };

    struct Route {
        std::optional<std::vector<std::string>> inbound_interfaces;
        std::optional<std::vector<RouteRuleElement>> rules;
    };

    struct ConfigObject {
        std::optional<ApiConfig> api;
        std::optional<Daemon> daemon;
        std::optional<Dns> dns;
        std::optional<Fwmark> fwmark;
        std::optional<Iproute> iproute;
        std::optional<std::map<std::string, ListConfigValue>> lists;
        std::optional<ListsAutoupdate> lists_autoupdate;
        std::optional<std::vector<OutboundElement>> outbounds;
        std::optional<Route> route;
    };

    struct ListRefreshStateValue {
        std::optional<std::string> last_updated;
    };

    struct ConfigStateResponse {
        ConfigObject config;
        bool is_draft;
        std::optional<std::map<std::string, ListRefreshStateValue>> list_refresh_state;
    };

    enum class ConfigUpdateResponseStatus : int { OK };

    struct ConfigUpdateResponse {
        std::optional<int64_t> apply_started_ts;
        std::string message;
        ConfigUpdateResponseStatus status;
    };

    struct ConnectionEventState {
        bool available;
        int64_t changed_at;
        int64_t revision;
    };

    struct ConnectionRecord {
        bool active;
        std::string destination;
        std::vector<std::string> destination_domains;
        int64_t destination_port;
        std::string device;
        int64_t first_seen;
        std::string id;
        int64_t last_seen;
        int64_t mark;
        std::string protocol;
        std::string route;
        std::string source;
        int64_t source_port;
        std::string state;
    };

    struct ConnectionPage {
        std::vector<ConnectionRecord> items;
        std::optional<std::string> next_cursor;
        int64_t snapshot_at;
        int64_t total;
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

    enum class DependencyDependentKind : int { DNS_FALLBACK, DNS_RULE, DNS_SERVER, LIST, OUTBOUND_GROUP, ROUTING_RULE };

    enum class DependencyRelation : int { CONTAINS_MEMBER, DETOURS_VIA, FALLBACK_TO, ROUTES_TO, USES_DNS_SERVER, USES_LIST };

    struct DependencyTarget {
        bool cascaded;
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
        bool safe_to_delete;
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
        bool chain_present;
        std::optional<std::string> detail;
        bool prerouting_hook_present;
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
        int64_t started_at;
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
        bool config_is_draft;
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

    struct ListRefreshRequest {
        std::optional<std::string> name;
    };

    struct ListRefreshResponse {
        std::vector<std::string> changed_lists;
        std::vector<std::string> failed_lists;
        std::string message;
        std::vector<std::string> refreshed_lists;
        bool reloaded;
        ConfigUpdateResponseStatus status;
    };

    struct NdmsInterfaceCapabilities {
        bool backup_required;
        bool can_delete;
        bool can_edit;
        bool can_hide;
    };

    enum class Kind : int { AMNEZIA_WIREGUARD, HTTPS_PROXY, HTTP_PROXY, IKE, L2_TP, OPENCONNECT, OPENVPN, SOCKS5_PROXY, SSTP, WIREGUARD };

    enum class Owner : int { KEENETIC };

    struct NdmsTunnelInterfaceElement {
        NdmsInterfaceCapabilities capabilities;
        std::optional<bool> connected;
        std::string firmware_type;
        std::string id;
        std::string kernel_name;
        Kind kind;
        std::string label;
        std::optional<bool> link;
        Owner owner;
    };

    enum class MutationMode : int { DISABLED };

    enum class RequiredGuard : int { AUTOMATIC_BACKUP, OPTIMISTIC_REVISION, OWNERSHIP_CHECK, TYPED_RCI };

    struct NdmsInterfaceInventoryResponse {
        bool available;
        std::vector<NdmsTunnelInterfaceElement> interfaces;
        MutationMode mutation_mode;
        bool read_only;
        std::vector<RequiredGuard> required_guards;
    };

    struct PolicyRuleCheck {
        std::optional<std::string> detail;
        int64_t expected_table;
        std::string fwmark;
        std::string fwmask;
        int64_t priority;
        bool rule_present_v4;
        bool rule_present_v6;
        CheckStatus status;
    };

    struct ReloadResponse {
        std::string message;
        ConfigUpdateResponseStatus status;
    };

    struct RouteTableCheck {
        bool default_route_present;
        std::optional<std::string> detail;
        std::optional<std::string> expected_destination;
        std::optional<std::string> expected_gateway;
        std::optional<std::string> expected_interface;
        std::optional<int64_t> expected_metric;
        std::optional<std::string> expected_route_type;
        bool gateway_matches;
        bool interface_matches;
        std::string outbound_tag;
        CheckStatus status;
        bool table_exists;
        int64_t table_id;
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

    struct ListMatch {
        std::string list;
        std::string via;
    };

    struct RoutingTestEntry {
        std::string actual_outbound;
        std::string expected_outbound;
        std::string ip;
        std::optional<ListMatch> list_match;
        bool ok;
    };

    struct RoutingTestRequest {
        std::string target;
    };

    struct RoutingTestRuleIpDiagnosticElement {
        std::optional<bool> in_ipset;
        std::string ip;
    };

    struct RoutingTestRuleDiagnosticElement {
        std::string interface_name;
        std::vector<RoutingTestRuleIpDiagnosticElement> ip_rows;
        std::string outbound;
        RouteRuleElement rule;
        int64_t rule_index;
        bool target_in_lists;
        std::optional<ListMatch> target_match;
    };

    struct RoutingTestResponse {
        std::optional<std::string> dns_error;
        bool is_domain;
        bool no_matching_rule;
        std::vector<std::string> resolved_ips;
        std::vector<RoutingTestEntry> results;
        std::vector<RoutingTestRuleDiagnosticElement> rule_diagnostics;
        std::string target;
        std::vector<std::string> warnings;
    };

    enum class RuntimeInterfaceInventoryStatusEnum : int { DOWN, UP };

    struct RuntimeInterfaceInventoryEntry {
        std::optional<bool> admin_up;
        std::optional<bool> carrier;
        std::optional<std::vector<std::string>> ipv4_addresses;
        std::optional<std::vector<std::string>> ipv6_addresses;
        std::string name;
        std::optional<std::string> oper_state;
        RuntimeInterfaceInventoryStatusEnum status;
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

    enum class Operation : int { CREATE, DELETE, UPDATE };

    enum class GeoMode : int { AUTO, DISABLED, MANUAL };

    enum class TransportSpecType : int { NATIVE, SING_BOX, SING_BOX_VLESS_REALITY };

    struct Vless {
        std::optional<std::string> fingerprint;
        std::optional<std::string> flow;
        std::optional<int64_t> mtu;
        std::string public_key;
        std::string server;
        std::string server_name;
        int64_t server_port;
        std::optional<std::string> short_id;
        std::optional<std::string> uuid;
    };

    struct Transport {
        std::optional<bool> auto_start;
        std::optional<std::vector<std::string>> bootstrap_dns;
        std::optional<std::string> country;
        std::optional<std::string> country_code;
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

    struct TransportConfigOperation {
        Operation operation;
        std::optional<std::string> tag;
        std::optional<Transport> transport;
    };

    enum class TransportConfigResponseStatus : int { CREATED, DELETED, UPDATED };

    struct TransportConfigResponse {
        TransportConfigResponseStatus status;
        std::string tag;
    };

    enum class Security : int { REALITY, TLS };

    enum class State : int { DEGRADED, DOWN, STARTING, UP };

    struct TransportStatus {
        bool desired_up;
        std::optional<std::string> error;
        std::string interface;
        std::optional<std::string> network;
        std::optional<std::string> next_retry_at;
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
        std::optional<CacheMetadata> cache_metadata;
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
        std::optional<Iproute> iproute_config;
        std::optional<LifecycleOperation> lifecycle_operation;
        std::optional<LifecycleOperationStageElement> lifecycle_operation_stage;
        std::optional<ListConfigValue> list_config;
        std::optional<ListRefreshRequest> list_refresh_request;
        std::optional<ListRefreshResponse> list_refresh_response;
        std::optional<ListRefreshStateValue> list_refresh_state;
        std::optional<ListsAutoupdate> lists_autoupdate_config;
        std::optional<NdmsInterfaceCapabilities> ndms_interface_capabilities;
        std::optional<NdmsInterfaceInventoryResponse> ndms_interface_inventory_response;
        std::optional<NdmsTunnelInterfaceElement> ndms_tunnel_interface;
        std::optional<Kind> ndms_tunnel_kind;
        std::optional<OutboundElement> outbound;
        std::optional<OutboundGroupElement> outbound_group;
        std::optional<PolicyRuleCheck> policy_rule_check;
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
        std::optional<ListMatch> routing_test_list_match;
        std::optional<RoutingTestRequest> routing_test_request;
        std::optional<RoutingTestResponse> routing_test_response;
        std::optional<RoutingTestRuleDiagnosticElement> routing_test_rule_diagnostic;
        std::optional<RoutingTestRuleIpDiagnosticElement> routing_test_rule_ip_diagnostic;
        std::optional<RuntimeInterfaceInventoryEntry> runtime_interface_inventory_entry;
        std::optional<RuntimeInterfaceInventoryResponse> runtime_interface_inventory_response;
        std::optional<RuntimeInterfaceInventoryStatusEnum> runtime_interface_inventory_status;
        std::optional<RuntimeInterfaceState> runtime_interface_state;
        std::optional<RuntimeInterfaceStatusEnum> runtime_interface_status;
        std::optional<RuntimeInventoryResponse> runtime_inventory_response;
        std::optional<RuntimeOutboundsResponse> runtime_outbounds_response;
        std::optional<RuntimeOutboundStateElement> runtime_outbound_state;
        std::optional<ResolverLiveStatus> runtime_outbound_status;
        std::optional<SortOrder> sort_order;
        std::optional<StatusEventConnections> status_event_connections;
        std::optional<StatusEventInterfaces> status_event_interfaces;
        std::optional<StatusEventOutbounds> status_event_outbounds;
        std::optional<StatusEventService> status_event_service;
        std::optional<StatusEventSnapshot> status_event_snapshot;
        std::optional<TransportActionRequest> transport_action_request;
        std::optional<TransportActionResponse> transport_action_response;
        std::optional<TransportConfigOperation> transport_config_operation;
        std::optional<TransportConfigResponse> transport_config_response;
        std::optional<Transport> transport_spec;
        std::optional<TransportStatus> transport_status;
        std::optional<ValidationErrorElement> validation_error;
        std::optional<Vless> vless_reality_spec;
    };
}
}

namespace keen_pbr3 {
namespace api {
    void from_json(const json & j, ApiConfig & x);
    void to_json(json & j, const ApiConfig & x);

    void from_json(const json & j, CacheMetadata & x);
    void to_json(json & j, const CacheMetadata & x);

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

    void from_json(const json & j, RouteRuleElement & x);
    void to_json(json & j, const RouteRuleElement & x);

    void from_json(const json & j, Route & x);
    void to_json(json & j, const Route & x);

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

    void from_json(const json & j, ListRefreshRequest & x);
    void to_json(json & j, const ListRefreshRequest & x);

    void from_json(const json & j, ListRefreshResponse & x);
    void to_json(json & j, const ListRefreshResponse & x);

    void from_json(const json & j, NdmsInterfaceCapabilities & x);
    void to_json(json & j, const NdmsInterfaceCapabilities & x);

    void from_json(const json & j, NdmsTunnelInterfaceElement & x);
    void to_json(json & j, const NdmsTunnelInterfaceElement & x);

    void from_json(const json & j, NdmsInterfaceInventoryResponse & x);
    void to_json(json & j, const NdmsInterfaceInventoryResponse & x);

    void from_json(const json & j, PolicyRuleCheck & x);
    void to_json(json & j, const PolicyRuleCheck & x);

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

    void from_json(const json & j, RuntimeInterfaceInventoryEntry & x);
    void to_json(json & j, const RuntimeInterfaceInventoryEntry & x);

    void from_json(const json & j, RuntimeInterfaceInventoryResponse & x);
    void to_json(json & j, const RuntimeInterfaceInventoryResponse & x);

    void from_json(const json & j, RuntimeInterfaceState & x);
    void to_json(json & j, const RuntimeInterfaceState & x);

    void from_json(const json & j, RuntimeOutboundStateElement & x);
    void to_json(json & j, const RuntimeOutboundStateElement & x);

    void from_json(const json & j, RuntimeOutboundsResponse & x);
    void to_json(json & j, const RuntimeOutboundsResponse & x);

    void from_json(const json & j, RuntimeInventoryResponse & x);
    void to_json(json & j, const RuntimeInventoryResponse & x);

    void from_json(const json & j, StatusEventConnections & x);
    void to_json(json & j, const StatusEventConnections & x);

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

    void from_json(const json & j, Vless & x);
    void to_json(json & j, const Vless & x);

    void from_json(const json & j, Transport & x);
    void to_json(json & j, const Transport & x);

    void from_json(const json & j, TransportConfigOperation & x);
    void to_json(json & j, const TransportConfigOperation & x);

    void from_json(const json & j, TransportConfigResponse & x);
    void to_json(json & j, const TransportConfigResponse & x);

    void from_json(const json & j, TransportStatus & x);
    void to_json(json & j, const TransportStatus & x);

    void from_json(const json & j, ApiTypes & x);
    void to_json(json & j, const ApiTypes & x);

    void from_json(const json & j, CheckStatus & x);
    void to_json(json & j, const CheckStatus & x);

    void from_json(const json & j, DaemonConfigFirewallBackend & x);
    void to_json(json & j, const DaemonConfigFirewallBackend & x);

    void from_json(const json & j, DnsServerType & x);
    void to_json(json & j, const DnsServerType & x);

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

    void from_json(const json & j, Kind & x);
    void to_json(json & j, const Kind & x);

    void from_json(const json & j, Owner & x);
    void to_json(json & j, const Owner & x);

    void from_json(const json & j, MutationMode & x);
    void to_json(json & j, const MutationMode & x);

    void from_json(const json & j, RequiredGuard & x);
    void to_json(json & j, const RequiredGuard & x);

    void from_json(const json & j, RoutingHealthErrorResponseOverall & x);
    void to_json(json & j, const RoutingHealthErrorResponseOverall & x);

    void from_json(const json & j, RoutingHealthResponseFirewallBackend & x);
    void to_json(json & j, const RoutingHealthResponseFirewallBackend & x);

    void from_json(const json & j, RoutingHealthResponseOverall & x);
    void to_json(json & j, const RoutingHealthResponseOverall & x);

    void from_json(const json & j, RuntimeInterfaceInventoryStatusEnum & x);
    void to_json(json & j, const RuntimeInterfaceInventoryStatusEnum & x);

    void from_json(const json & j, RuntimeInterfaceStatusEnum & x);
    void to_json(json & j, const RuntimeInterfaceStatusEnum & x);

    void from_json(const json & j, StatusEventConnectionsType & x);
    void to_json(json & j, const StatusEventConnectionsType & x);

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

    void from_json(const json & j, Operation & x);
    void to_json(json & j, const Operation & x);

    void from_json(const json & j, GeoMode & x);
    void to_json(json & j, const GeoMode & x);

    void from_json(const json & j, TransportSpecType & x);
    void to_json(json & j, const TransportSpecType & x);

    void from_json(const json & j, TransportConfigResponseStatus & x);
    void to_json(json & j, const TransportConfigResponseStatus & x);

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

    inline void from_json(const json & j, CacheMetadata& x) {
        x.cidrs = get_stack_optional<int64_t>(j, "cidrs");
        x.domains = get_stack_optional<int64_t>(j, "domains");
        x.download_time = get_stack_optional<std::string>(j, "download_time");
        x.etag = get_stack_optional<std::string>(j, "etag");
        x.ips = get_stack_optional<int64_t>(j, "ips");
        x.last_modified = get_stack_optional<std::string>(j, "last_modified");
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const CacheMetadata & x) {
        j = json::object();
        j["cidrs"] = x.cidrs;
        j["domains"] = x.domains;
        j["download_time"] = x.download_time;
        j["etag"] = x.etag;
        j["ips"] = x.ips;
        j["last_modified"] = x.last_modified;
        j["url"] = x.url;
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
        x.pid_file = get_stack_optional<std::string>(j, "pid_file");
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
        j["pid_file"] = x.pid_file;
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
        x.enabled = get_stack_optional<bool>(j, "enabled");
        x.list = j.at("list").get<std::vector<std::string>>();
        x.server = j.at("server").get<std::string>();
    }

    inline void to_json(json & j, const DnsRuleElement & x) {
        j = json::object();
        j["allow_domain_rebinding"] = x.allow_domain_rebinding;
        j["enabled"] = x.enabled;
        j["list"] = x.list;
        j["server"] = x.server;
    }

    inline void from_json(const json & j, DnsServerElement& x) {
        x.address = get_stack_optional<std::string>(j, "address");
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.tag = j.at("tag").get<std::string>();
        x.type = get_stack_optional<DnsServerType>(j, "type");
    }

    inline void to_json(json & j, const DnsServerElement & x) {
        j = json::object();
        j["address"] = x.address;
        j["detour"] = x.detour;
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

    inline void from_json(const json & j, ListConfigValue& x) {
        x.detour = get_stack_optional<std::string>(j, "detour");
        x.domains = get_stack_optional<std::vector<std::string>>(j, "domains");
        x.file = get_stack_optional<std::string>(j, "file");
        x.ip_cidrs = get_stack_optional<std::vector<std::string>>(j, "ip_cidrs");
        x.ttl_ms = get_stack_optional<int64_t>(j, "ttl_ms");
        x.url = get_stack_optional<std::string>(j, "url");
    }

    inline void to_json(json & j, const ListConfigValue & x) {
        j = json::object();
        j["detour"] = x.detour;
        j["domains"] = x.domains;
        j["file"] = x.file;
        j["ip_cidrs"] = x.ip_cidrs;
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
        x.gateway = get_stack_optional<std::string>(j, "gateway");
        x.gateway6 = get_stack_optional<std::string>(j, "gateway6");
        x.interface = get_stack_optional<std::string>(j, "interface");
        x.interval_ms = get_stack_optional<int64_t>(j, "interval_ms");
        x.outbound_groups = get_stack_optional<std::vector<OutboundGroupElement>>(j, "outbound_groups");
        x.probe_timeout_ms = get_stack_optional<int64_t>(j, "probe_timeout_ms");
        x.retry = get_stack_optional<Retry>(j, "retry");
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
        j["gateway"] = x.gateway;
        j["gateway6"] = x.gateway6;
        j["interface"] = x.interface;
        j["interval_ms"] = x.interval_ms;
        j["outbound_groups"] = x.outbound_groups;
        j["probe_timeout_ms"] = x.probe_timeout_ms;
        j["retry"] = x.retry;
        j["strict_enforcement"] = x.strict_enforcement;
        j["table"] = x.table;
        j["tag"] = x.tag;
        j["tolerance_ms"] = x.tolerance_ms;
        j["type"] = x.type;
        j["url"] = x.url;
    }

    inline void from_json(const json & j, RouteRuleElement& x) {
        x.dest_addr = get_stack_optional<std::string>(j, "dest_addr");
        x.dest_port = get_stack_optional<std::string>(j, "dest_port");
        x.dscp = get_stack_optional<int64_t>(j, "dscp");
        x.enabled = get_stack_optional<bool>(j, "enabled");
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
        j["dscp"] = x.dscp;
        j["enabled"] = x.enabled;
        j["list"] = x.list;
        j["outbound"] = x.outbound;
        j["proto"] = x.proto;
        j["src_addr"] = x.src_addr;
        j["src_port"] = x.src_port;
    }

    inline void from_json(const json & j, Route& x) {
        x.inbound_interfaces = get_stack_optional<std::vector<std::string>>(j, "inbound_interfaces");
        x.rules = get_stack_optional<std::vector<RouteRuleElement>>(j, "rules");
    }

    inline void to_json(json & j, const Route & x) {
        j = json::object();
        j["inbound_interfaces"] = x.inbound_interfaces;
        j["rules"] = x.rules;
    }

    inline void from_json(const json & j, ConfigObject& x) {
        x.api = get_stack_optional<ApiConfig>(j, "api");
        x.daemon = get_stack_optional<Daemon>(j, "daemon");
        x.dns = get_stack_optional<Dns>(j, "dns");
        x.fwmark = get_stack_optional<Fwmark>(j, "fwmark");
        x.iproute = get_stack_optional<Iproute>(j, "iproute");
        x.lists = get_stack_optional<std::map<std::string, ListConfigValue>>(j, "lists");
        x.lists_autoupdate = get_stack_optional<ListsAutoupdate>(j, "lists_autoupdate");
        x.outbounds = get_stack_optional<std::vector<OutboundElement>>(j, "outbounds");
        x.route = get_stack_optional<Route>(j, "route");
    }

    inline void to_json(json & j, const ConfigObject & x) {
        j = json::object();
        j["api"] = x.api;
        j["daemon"] = x.daemon;
        j["dns"] = x.dns;
        j["fwmark"] = x.fwmark;
        j["iproute"] = x.iproute;
        j["lists"] = x.lists;
        j["lists_autoupdate"] = x.lists_autoupdate;
        j["outbounds"] = x.outbounds;
        j["route"] = x.route;
    }

    inline void from_json(const json & j, ListRefreshStateValue& x) {
        x.last_updated = get_stack_optional<std::string>(j, "last_updated");
    }

    inline void to_json(json & j, const ListRefreshStateValue & x) {
        j = json::object();
        j["last_updated"] = x.last_updated;
    }

    inline void from_json(const json & j, ConfigStateResponse& x) {
        x.config = j.at("config").get<ConfigObject>();
        x.is_draft = j.at("is_draft").get<bool>();
        x.list_refresh_state = get_stack_optional<std::map<std::string, ListRefreshStateValue>>(j, "list_refresh_state");
    }

    inline void to_json(json & j, const ConfigStateResponse & x) {
        j = json::object();
        j["config"] = x.config;
        j["is_draft"] = x.is_draft;
        j["list_refresh_state"] = x.list_refresh_state;
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

    inline void from_json(const json & j, NdmsTunnelInterfaceElement& x) {
        x.capabilities = j.at("capabilities").get<NdmsInterfaceCapabilities>();
        x.connected = get_stack_optional<bool>(j, "connected");
        x.firmware_type = j.at("firmware_type").get<std::string>();
        x.id = j.at("id").get<std::string>();
        x.kernel_name = j.at("kernel_name").get<std::string>();
        x.kind = j.at("kind").get<Kind>();
        x.label = j.at("label").get<std::string>();
        x.link = get_stack_optional<bool>(j, "link");
        x.owner = j.at("owner").get<Owner>();
    }

    inline void to_json(json & j, const NdmsTunnelInterfaceElement & x) {
        j = json::object();
        j["capabilities"] = x.capabilities;
        j["connected"] = x.connected;
        j["firmware_type"] = x.firmware_type;
        j["id"] = x.id;
        j["kernel_name"] = x.kernel_name;
        j["kind"] = x.kind;
        j["label"] = x.label;
        j["link"] = x.link;
        j["owner"] = x.owner;
    }

    inline void from_json(const json & j, NdmsInterfaceInventoryResponse& x) {
        x.available = j.at("available").get<bool>();
        x.interfaces = j.at("interfaces").get<std::vector<NdmsTunnelInterfaceElement>>();
        x.mutation_mode = j.at("mutation_mode").get<MutationMode>();
        x.read_only = j.at("read_only").get<bool>();
        x.required_guards = j.at("required_guards").get<std::vector<RequiredGuard>>();
    }

    inline void to_json(json & j, const NdmsInterfaceInventoryResponse & x) {
        j = json::object();
        j["available"] = x.available;
        j["interfaces"] = x.interfaces;
        j["mutation_mode"] = x.mutation_mode;
        j["read_only"] = x.read_only;
        j["required_guards"] = x.required_guards;
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
        x.expected_outbound = j.at("expected_outbound").get<std::string>();
        x.ip = j.at("ip").get<std::string>();
        x.list_match = get_stack_optional<ListMatch>(j, "list_match");
        x.ok = j.at("ok").get<bool>();
    }

    inline void to_json(json & j, const RoutingTestEntry & x) {
        j = json::object();
        j["actual_outbound"] = x.actual_outbound;
        j["expected_outbound"] = x.expected_outbound;
        j["ip"] = x.ip;
        j["list_match"] = x.list_match;
        j["ok"] = x.ok;
    }

    inline void from_json(const json & j, RoutingTestRequest& x) {
        x.target = j.at("target").get<std::string>();
    }

    inline void to_json(json & j, const RoutingTestRequest & x) {
        j = json::object();
        j["target"] = x.target;
    }

    inline void from_json(const json & j, RoutingTestRuleIpDiagnosticElement& x) {
        x.in_ipset = get_stack_optional<bool>(j, "in_ipset");
        x.ip = j.at("ip").get<std::string>();
    }

    inline void to_json(json & j, const RoutingTestRuleIpDiagnosticElement & x) {
        j = json::object();
        j["in_ipset"] = x.in_ipset;
        j["ip"] = x.ip;
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
        x.dns_error = get_stack_optional<std::string>(j, "dns_error");
        x.is_domain = j.at("is_domain").get<bool>();
        x.no_matching_rule = j.at("no_matching_rule").get<bool>();
        x.resolved_ips = j.at("resolved_ips").get<std::vector<std::string>>();
        x.results = j.at("results").get<std::vector<RoutingTestEntry>>();
        x.rule_diagnostics = j.at("rule_diagnostics").get<std::vector<RoutingTestRuleDiagnosticElement>>();
        x.target = j.at("target").get<std::string>();
        x.warnings = j.at("warnings").get<std::vector<std::string>>();
    }

    inline void to_json(json & j, const RoutingTestResponse & x) {
        j = json::object();
        j["dns_error"] = x.dns_error;
        j["is_domain"] = x.is_domain;
        j["no_matching_rule"] = x.no_matching_rule;
        j["resolved_ips"] = x.resolved_ips;
        j["results"] = x.results;
        j["rule_diagnostics"] = x.rule_diagnostics;
        j["target"] = x.target;
        j["warnings"] = x.warnings;
    }

    inline void from_json(const json & j, RuntimeInterfaceInventoryEntry& x) {
        x.admin_up = get_stack_optional<bool>(j, "admin_up");
        x.carrier = get_stack_optional<bool>(j, "carrier");
        x.ipv4_addresses = get_stack_optional<std::vector<std::string>>(j, "ipv4_addresses");
        x.ipv6_addresses = get_stack_optional<std::vector<std::string>>(j, "ipv6_addresses");
        x.name = j.at("name").get<std::string>();
        x.oper_state = get_stack_optional<std::string>(j, "oper_state");
        x.status = j.at("status").get<RuntimeInterfaceInventoryStatusEnum>();
    }

    inline void to_json(json & j, const RuntimeInterfaceInventoryEntry & x) {
        j = json::object();
        j["admin_up"] = x.admin_up;
        j["carrier"] = x.carrier;
        j["ipv4_addresses"] = x.ipv4_addresses;
        j["ipv6_addresses"] = x.ipv6_addresses;
        j["name"] = x.name;
        j["oper_state"] = x.oper_state;
        j["status"] = x.status;
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

    inline void from_json(const json & j, TransportConfigOperation& x) {
        x.operation = j.at("operation").get<Operation>();
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

    inline void from_json(const json & j, TransportStatus& x) {
        x.desired_up = j.at("desired_up").get<bool>();
        x.error = get_stack_optional<std::string>(j, "error");
        x.interface = j.at("interface").get<std::string>();
        x.network = get_stack_optional<std::string>(j, "network");
        x.next_retry_at = get_stack_optional<std::string>(j, "next_retry_at");
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
        j["error"] = x.error;
        j["interface"] = x.interface;
        j["network"] = x.network;
        j["next_retry_at"] = x.next_retry_at;
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
        x.cache_metadata = get_stack_optional<CacheMetadata>(j, "CacheMetadata");
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
        x.iproute_config = get_stack_optional<Iproute>(j, "IprouteConfig");
        x.lifecycle_operation = get_stack_optional<LifecycleOperation>(j, "LifecycleOperation");
        x.lifecycle_operation_stage = get_stack_optional<LifecycleOperationStageElement>(j, "LifecycleOperationStage");
        x.list_config = get_stack_optional<ListConfigValue>(j, "ListConfig");
        x.list_refresh_request = get_stack_optional<ListRefreshRequest>(j, "ListRefreshRequest");
        x.list_refresh_response = get_stack_optional<ListRefreshResponse>(j, "ListRefreshResponse");
        x.list_refresh_state = get_stack_optional<ListRefreshStateValue>(j, "ListRefreshState");
        x.lists_autoupdate_config = get_stack_optional<ListsAutoupdate>(j, "ListsAutoupdateConfig");
        x.ndms_interface_capabilities = get_stack_optional<NdmsInterfaceCapabilities>(j, "NdmsInterfaceCapabilities");
        x.ndms_interface_inventory_response = get_stack_optional<NdmsInterfaceInventoryResponse>(j, "NdmsInterfaceInventoryResponse");
        x.ndms_tunnel_interface = get_stack_optional<NdmsTunnelInterfaceElement>(j, "NdmsTunnelInterface");
        x.ndms_tunnel_kind = get_stack_optional<Kind>(j, "NdmsTunnelKind");
        x.outbound = get_stack_optional<OutboundElement>(j, "Outbound");
        x.outbound_group = get_stack_optional<OutboundGroupElement>(j, "OutboundGroup");
        x.policy_rule_check = get_stack_optional<PolicyRuleCheck>(j, "PolicyRuleCheck");
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
        x.routing_test_list_match = get_stack_optional<ListMatch>(j, "RoutingTestListMatch");
        x.routing_test_request = get_stack_optional<RoutingTestRequest>(j, "RoutingTestRequest");
        x.routing_test_response = get_stack_optional<RoutingTestResponse>(j, "RoutingTestResponse");
        x.routing_test_rule_diagnostic = get_stack_optional<RoutingTestRuleDiagnosticElement>(j, "RoutingTestRuleDiagnostic");
        x.routing_test_rule_ip_diagnostic = get_stack_optional<RoutingTestRuleIpDiagnosticElement>(j, "RoutingTestRuleIpDiagnostic");
        x.runtime_interface_inventory_entry = get_stack_optional<RuntimeInterfaceInventoryEntry>(j, "RuntimeInterfaceInventoryEntry");
        x.runtime_interface_inventory_response = get_stack_optional<RuntimeInterfaceInventoryResponse>(j, "RuntimeInterfaceInventoryResponse");
        x.runtime_interface_inventory_status = get_stack_optional<RuntimeInterfaceInventoryStatusEnum>(j, "RuntimeInterfaceInventoryStatus");
        x.runtime_interface_state = get_stack_optional<RuntimeInterfaceState>(j, "RuntimeInterfaceState");
        x.runtime_interface_status = get_stack_optional<RuntimeInterfaceStatusEnum>(j, "RuntimeInterfaceStatus");
        x.runtime_inventory_response = get_stack_optional<RuntimeInventoryResponse>(j, "RuntimeInventoryResponse");
        x.runtime_outbounds_response = get_stack_optional<RuntimeOutboundsResponse>(j, "RuntimeOutboundsResponse");
        x.runtime_outbound_state = get_stack_optional<RuntimeOutboundStateElement>(j, "RuntimeOutboundState");
        x.runtime_outbound_status = get_stack_optional<ResolverLiveStatus>(j, "RuntimeOutboundStatus");
        x.sort_order = get_stack_optional<SortOrder>(j, "SortOrder");
        x.status_event_connections = get_stack_optional<StatusEventConnections>(j, "StatusEventConnections");
        x.status_event_interfaces = get_stack_optional<StatusEventInterfaces>(j, "StatusEventInterfaces");
        x.status_event_outbounds = get_stack_optional<StatusEventOutbounds>(j, "StatusEventOutbounds");
        x.status_event_service = get_stack_optional<StatusEventService>(j, "StatusEventService");
        x.status_event_snapshot = get_stack_optional<StatusEventSnapshot>(j, "StatusEventSnapshot");
        x.transport_action_request = get_stack_optional<TransportActionRequest>(j, "TransportActionRequest");
        x.transport_action_response = get_stack_optional<TransportActionResponse>(j, "TransportActionResponse");
        x.transport_config_operation = get_stack_optional<TransportConfigOperation>(j, "TransportConfigOperation");
        x.transport_config_response = get_stack_optional<TransportConfigResponse>(j, "TransportConfigResponse");
        x.transport_spec = get_stack_optional<Transport>(j, "TransportSpec");
        x.transport_status = get_stack_optional<TransportStatus>(j, "TransportStatus");
        x.validation_error = get_stack_optional<ValidationErrorElement>(j, "ValidationError");
        x.vless_reality_spec = get_stack_optional<Vless>(j, "VlessRealitySpec");
    }

    inline void to_json(json & j, const ApiTypes & x) {
        j = json::object();
        j["ApiConfig"] = x.api_config;
        j["CacheMetadata"] = x.cache_metadata;
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
        j["IprouteConfig"] = x.iproute_config;
        j["LifecycleOperation"] = x.lifecycle_operation;
        j["LifecycleOperationStage"] = x.lifecycle_operation_stage;
        j["ListConfig"] = x.list_config;
        j["ListRefreshRequest"] = x.list_refresh_request;
        j["ListRefreshResponse"] = x.list_refresh_response;
        j["ListRefreshState"] = x.list_refresh_state;
        j["ListsAutoupdateConfig"] = x.lists_autoupdate_config;
        j["NdmsInterfaceCapabilities"] = x.ndms_interface_capabilities;
        j["NdmsInterfaceInventoryResponse"] = x.ndms_interface_inventory_response;
        j["NdmsTunnelInterface"] = x.ndms_tunnel_interface;
        j["NdmsTunnelKind"] = x.ndms_tunnel_kind;
        j["Outbound"] = x.outbound;
        j["OutboundGroup"] = x.outbound_group;
        j["PolicyRuleCheck"] = x.policy_rule_check;
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
        j["RoutingTestListMatch"] = x.routing_test_list_match;
        j["RoutingTestRequest"] = x.routing_test_request;
        j["RoutingTestResponse"] = x.routing_test_response;
        j["RoutingTestRuleDiagnostic"] = x.routing_test_rule_diagnostic;
        j["RoutingTestRuleIpDiagnostic"] = x.routing_test_rule_ip_diagnostic;
        j["RuntimeInterfaceInventoryEntry"] = x.runtime_interface_inventory_entry;
        j["RuntimeInterfaceInventoryResponse"] = x.runtime_interface_inventory_response;
        j["RuntimeInterfaceInventoryStatus"] = x.runtime_interface_inventory_status;
        j["RuntimeInterfaceState"] = x.runtime_interface_state;
        j["RuntimeInterfaceStatus"] = x.runtime_interface_status;
        j["RuntimeInventoryResponse"] = x.runtime_inventory_response;
        j["RuntimeOutboundsResponse"] = x.runtime_outbounds_response;
        j["RuntimeOutboundState"] = x.runtime_outbound_state;
        j["RuntimeOutboundStatus"] = x.runtime_outbound_status;
        j["SortOrder"] = x.sort_order;
        j["StatusEventConnections"] = x.status_event_connections;
        j["StatusEventInterfaces"] = x.status_event_interfaces;
        j["StatusEventOutbounds"] = x.status_event_outbounds;
        j["StatusEventService"] = x.status_event_service;
        j["StatusEventSnapshot"] = x.status_event_snapshot;
        j["TransportActionRequest"] = x.transport_action_request;
        j["TransportActionResponse"] = x.transport_action_response;
        j["TransportConfigOperation"] = x.transport_config_operation;
        j["TransportConfigResponse"] = x.transport_config_response;
        j["TransportSpec"] = x.transport_spec;
        j["TransportStatus"] = x.transport_status;
        j["ValidationError"] = x.validation_error;
        j["VlessRealitySpec"] = x.vless_reality_spec;
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

    inline void from_json(const json & j, Operation & x) {
        if (j == "create") x = Operation::CREATE;
        else if (j == "delete") x = Operation::DELETE;
        else if (j == "update") x = Operation::UPDATE;
        else { throw std::runtime_error("Cannot deserialize to enumeration \"Operation\""); }
    }

    inline void to_json(json & j, const Operation & x) {
        switch (x) {
            case Operation::CREATE: j = "create"; break;
            case Operation::DELETE: j = "delete"; break;
            case Operation::UPDATE: j = "update"; break;
            default: throw std::runtime_error("Unexpected value in enumeration \"Operation\": " + std::to_string(static_cast<int>(x)));
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
