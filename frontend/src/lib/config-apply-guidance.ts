import type { ConfigObject } from "@/api/generated/model/configObject"
import { getOperationErrorPresentation } from "@/lib/api-errors"
import { stableJsonStringify } from "@/lib/semantic-json"
import { getFirefoxDohCanaryEnabled } from "@/lib/firefox-doh-canary"

export type ConfigEffectsSummary = Readonly<{
  routing: string
  dns: string
}>

export type ConfigApplyImpact =
  | "routing"
  | "dns"
  | "routing-and-dns"
  | "none"
  | "unknown"

function setMembers(values: readonly string[] | undefined) {
  return [...new Set(values ?? [])].sort()
}

// This non-cryptographic fingerprint chooses an optional UX suggestion only.
// It is never a revision, an authorization check or proof of runtime state.
// LAN HTTP needs no WebCrypto; only the digest survives this function, never
// a copy of URLs (which may contain credentials) or other configuration data.
function fingerprint(value: unknown): string {
  const text = stableJsonStringify(value) ?? ""
  let first = 0x811c9dc5
  let second = 0x9e3779b9
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index)
    first = Math.imul(first ^ code, 0x01000193)
    second = Math.imul(second ^ code, 0x85ebca6b)
  }
  return [first, second]
    .map((value) => (value >>> 0).toString(16).padStart(8, "0"))
    .join("")
}

export function summarizeConfigEffects(
  config: ConfigObject
): ConfigEffectsSummary {
  const lists = Object.fromEntries(
    Object.entries(config.lists ?? {}).map(([name, list]) => [
      name,
      {
        url: list.url || undefined,
        // A list file is a routing source, unlike a PID/cache/log file path.
        file: list.file || undefined,
        domains: setMembers(list.domains),
        ip_cidrs: setMembers(list.ip_cidrs),
        ttl_ms: list.ttl_ms,
      },
    ])
  )
  const dnsRules = (config.dns?.rules ?? [])
    .filter((rule) => rule.enabled !== false)
    .map((rule) => ({
      list: setMembers(rule.list),
      server: rule.server,
      allow_domain_rebinding: rule.allow_domain_rebinding ?? false,
    }))
  const dnsLists = Object.fromEntries(
    setMembers(dnsRules.flatMap((rule) => rule.list)).map((name) => [
      name,
      lists[name],
    ])
  )
  const daemon = config.daemon
  const routing = {
    route: {
      inbound_interfaces: setMembers(config.route?.inbound_interfaces),
      internal_vpn_servers: (config.route?.internal_vpn_servers ?? [])
        .map((server) => ({
          interface: server.ndms_id ? undefined : server.interface,
          ndms_id: server.ndms_id || undefined,
          process_clients: server.process_clients,
        }))
        .sort((left, right) =>
          (left.ndms_id ?? left.interface ?? "").localeCompare(
            right.ndms_id ?? right.interface ?? ""
          )
        ),
      internal_vpn_services: (config.route?.internal_vpn_services ?? [])
        .map((service) => ({
          service_id: service.service_id,
          process_clients: service.process_clients,
        }))
        .sort((left, right) => left.service_id.localeCompare(right.service_id)),
      rules: (config.route?.rules ?? [])
        .filter((rule) => rule.enabled !== false)
        .map((rule) => ({
          list: setMembers(rule.list),
          outbound: rule.outbound,
          failure_policy: rule.failure_policy ?? "inherit",
          fallback_outbound:
            rule.failure_policy === "fallback"
              ? rule.fallback_outbound || undefined
              : undefined,
          proto: rule.proto || undefined,
          dscp: rule.dscp,
          src_port: rule.src_port || undefined,
          dest_port: rule.dest_port || undefined,
          src_addr: rule.src_addr || undefined,
          dest_addr: rule.dest_addr || undefined,
        })),
    },
    lists,
    outbounds: (config.outbounds ?? []).map((outbound) => ({
      type: outbound.type,
      tag: outbound.tag,
      interface: outbound.interface || undefined,
      gateway: outbound.gateway || undefined,
      gateway6: outbound.gateway6 || undefined,
      table: outbound.table,
      strict_enforcement: outbound.strict_enforcement,
      selection_mode: outbound.selection_mode ?? "latency",
      conntrack_on_switch: outbound.conntrack_on_switch ?? "delete_on_failure",
      tolerance_ms: outbound.tolerance_ms,
      retry: {
        attempts: outbound.retry?.attempts,
        interval_ms: outbound.retry?.interval_ms,
      },
      circuit_breaker: {
        failure_threshold: outbound.circuit_breaker?.failure_threshold,
        success_threshold: outbound.circuit_breaker?.success_threshold,
        timeout_ms: outbound.circuit_breaker?.timeout_ms,
        half_open_max_requests:
          outbound.circuit_breaker?.half_open_max_requests,
      },
      outbound_groups: (outbound.outbound_groups ?? []).map((group) => ({
        weight: group.weight,
        // Group and member order determine preferred/fallback selection.
        outbounds: group.outbounds,
      })),
    })),
    fwmark: {
      start: config.fwmark?.start,
      mask: config.fwmark?.mask,
    },
    iproute: { table_start: config.iproute?.table_start },
    daemon: {
      firewall_backend: daemon?.firewall_backend,
      ppe_deoffload_mode: daemon?.ppe_deoffload_mode ?? "off",
      ppe_deoffload_quic_enabled: daemon?.ppe_deoffload_quic_enabled ?? false,
      skip_marked_packets: daemon?.skip_marked_packets ?? true,
      ttl_bypass_enabled: daemon?.ttl_bypass_enabled ?? true,
      clear_dynamic_sets_on_apply: daemon?.clear_dynamic_sets_on_apply ?? true,
      ipset_hashsize: daemon?.ipset_hashsize ?? undefined,
      ipset_maxelem: daemon?.ipset_maxelem ?? undefined,
      reconnect_unmarked_flows_on_routing_change:
        daemon?.reconnect_unmarked_flows_on_routing_change ?? true,
      reconnect_owned_flows_on_routing_change_lists:
        daemon?.reconnect_owned_flows_on_routing_change_lists == null
          ? undefined
          : setMembers(daemon.reconnect_owned_flows_on_routing_change_lists),
      meta_udp443_policy: daemon?.meta_udp443_policy ?? "balanced",
      ipv6_enabled: daemon?.ipv6_enabled ?? true,
      strict_enforcement: daemon?.strict_enforcement,
    },
  }
  const enforcement = config.dns?.client_dns_enforcement
  const dns = {
    servers: (config.dns?.servers ?? []).map((server) => ({
      tag: server.tag,
      type: server.type ?? "static",
      address: server.address,
      detour: server.detour,
      domains: setMembers(server.domains),
    })),
    rules: dnsRules,
    lists: dnsLists,
    fallback: config.dns?.fallback ?? [],
    system_resolver: config.dns?.system_resolver?.address,
    firefox_doh_canary: getFirefoxDohCanaryEnabled(config.dns),
    client_dns_enforcement: {
      enabled: enforcement?.enabled ?? false,
      block_dot: enforcement?.enabled ? (enforcement.block_dot ?? true) : false,
    },
  }
  return { routing: fingerprint(routing), dns: fingerprint(dns) }
}

export function compareConfigEffects(
  baseline: ConfigEffectsSummary | undefined,
  candidate: ConfigEffectsSummary | undefined
): ConfigApplyImpact {
  if (!baseline || !candidate) return "unknown"
  const routing = baseline.routing !== candidate.routing
  const dns = baseline.dns !== candidate.dns
  if (routing && dns) return "routing-and-dns"
  if (routing) return "routing"
  return dns ? "dns" : "none"
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

// An apply suggestion is optional. Old fieldless responses may still receive
// the existing generic success message, but must not imply confirmed apply.
export function confirmedConfigApply(response: unknown): boolean {
  const result = record(response)
  const data = record(result?.data)
  return (
    result?.status === 200 &&
    data?.status === "ok" &&
    data.saved === true &&
    data.applied === true &&
    data.rolled_back !== true &&
    data.recovery_required !== true
  )
}

export function configFailureDestination(
  error: unknown
): "routing" | "service" | null {
  const kind = getOperationErrorPresentation(error)?.kind
  switch (kind) {
    case "unauthenticated":
    case "reauthentication_required":
    case "forbidden":
    case "busy":
    case "draft_pending":
    case "draft_changed":
    case "validation":
      return null
    case "network":
    case "service_unavailable":
      return "service"
    default:
      return "routing"
  }
}
