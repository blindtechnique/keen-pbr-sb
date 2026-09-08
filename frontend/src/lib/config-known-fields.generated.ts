// Generated from docs/openapi.yaml; do not edit by hand.
// Regenerate with: bun run config:known-fields:generate (from frontend/).

export const configKnownFields = {
  "ApiConfig": [
    "enabled",
    "listen"
  ],
  "CircuitBreakerConfig": [
    "failure_threshold",
    "half_open_max_requests",
    "success_threshold",
    "timeout_ms"
  ],
  "ClientDnsEnforcement": [
    "block_dot",
    "enabled"
  ],
  "ConfigObject": [
    "api",
    "daemon",
    "dns",
    "fwmark",
    "iproute",
    "list_refresh",
    "lists",
    "lists_autoupdate",
    "outbounds",
    "route",
    "schema_version",
    "tunnel_probe",
    "ui_preferences"
  ],
  "DaemonConfig": [
    "cache_dir",
    "clear_dynamic_sets_on_apply",
    "firewall_backend",
    "firewall_verify_max_bytes",
    "ipset_hashsize",
    "ipset_maxelem",
    "ipv6_enabled",
    "max_file_size_bytes",
    "meta_udp443_policy",
    "pid_file",
    "ppe_deoffload_mode",
    "ppe_deoffload_quic_enabled",
    "reconnect_owned_flows_on_routing_change_lists",
    "reconnect_unmarked_flows_on_routing_change",
    "reuse_static_sets_on_runtime_refresh",
    "skip_marked_packets",
    "strict_enforcement",
    "ttl_bypass_enabled"
  ],
  "DnsConfig": [
    "client_dns_enforcement",
    "dns_test_server",
    "fallback",
    "firefox_doh_canary",
    "rules",
    "servers",
    "system_resolver"
  ],
  "DnsRule": [
    "allow_domain_rebinding",
    "display_name",
    "enabled",
    "id",
    "list",
    "server"
  ],
  "DnsServer": [
    "address",
    "detour",
    "display_name",
    "domains",
    "tag",
    "type"
  ],
  "DnsSystemResolver": [
    "address"
  ],
  "DnsTestServer": [
    "answer_ipv4",
    "listen"
  ],
  "FwmarkConfig": [
    "mask",
    "start"
  ],
  "InternalVpnServer": [
    "interface",
    "ndms_id",
    "process_clients"
  ],
  "InternalVpnService": [
    "process_clients",
    "service_id"
  ],
  "IprouteConfig": [
    "table_start"
  ],
  "ListConfig": [
    "catalog_identity",
    "detour",
    "display_name",
    "domains",
    "fallback_detours",
    "file",
    "ip_cidrs",
    "refresh_detour_mode",
    "shrink_policy",
    "source_format",
    "ttl_ms",
    "url"
  ],
  "ListRefreshConfig": [
    "detour",
    "fallback_detours"
  ],
  "ListSourceShrinkPolicy": [
    "min_previous_entries",
    "min_retained_fraction"
  ],
  "ListsAutoupdateConfig": [
    "cron",
    "enabled"
  ],
  "Outbound": [
    "circuit_breaker",
    "conntrack_on_switch",
    "display_name",
    "gateway",
    "gateway6",
    "interface",
    "interval_ms",
    "outbound_groups",
    "probe_timeout_ms",
    "retry",
    "selection_mode",
    "strict_enforcement",
    "table",
    "tag",
    "tolerance_ms",
    "type",
    "url"
  ],
  "OutboundGroup": [
    "outbounds",
    "weight"
  ],
  "PlainDnsTemplate": [
    "name",
    "primary_ipv4",
    "secondary_ipv4"
  ],
  "RetryConfig": [
    "attempts",
    "interval_ms"
  ],
  "RouteConfig": [
    "inbound_interfaces",
    "internal_vpn_servers",
    "internal_vpn_services",
    "rules"
  ],
  "RouteRule": [
    "dest_addr",
    "dest_port",
    "display_name",
    "dscp",
    "enabled",
    "failure_policy",
    "fallback_outbound",
    "id",
    "list",
    "outbound",
    "proto",
    "src_addr",
    "src_port"
  ],
  "TunnelProbeConfig": [
    "enabled",
    "interval_ms",
    "list",
    "max_probes_per_pass",
    "outbound",
    "require_registry_confirmation"
  ],
  "UiPreferencesConfig": [
    "hidden_native_interface_ids",
    "plain_dns_templates"
  ]
} as const
