import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsServer } from "@/api/generated/model/dnsServer"
import { DnsServerType } from "@/api/generated/model/dnsServerType"

export type DnsServerDraft = {
  tag: string
  type: typeof DnsServerType.static | typeof DnsServerType.keenetic
  address: string
  detour: string
}

export const emptyDnsServerDraft: DnsServerDraft = {
  tag: "",
  type: DnsServerType.static,
  address: "",
  detour: "",
}

export function getDnsServerDraft(server?: DnsServer): DnsServerDraft {
  if (!server) {
    return emptyDnsServerDraft
  }

  return {
    tag: server.tag,
    type: server.type ?? DnsServerType.static,
    address: server.address ?? "",
    detour: server.detour ?? "",
  }
}

export function buildUpdatedConfigForDnsServerUpsert(
  config: ConfigObject,
  mode: "create" | "edit",
  draft: DnsServerDraft,
  originalTag?: string
): ConfigObject | null {
  const normalizedTag = draft.tag.trim()
  const isKeeneticDns = draft.type === DnsServerType.keenetic
  const normalizedAddress = isKeeneticDns
    ? null
    : normalizeDnsAddress(draft.address)

  if (!normalizedTag || (!isKeeneticDns && !normalizedAddress)) {
    return null
  }

  const normalizedDetour = isKeeneticDns ? "" : draft.detour.trim()
  const nextServer: DnsServer = {
    tag: normalizedTag,
    type: draft.type,
    ...(normalizedAddress ? { address: normalizedAddress } : {}),
    ...(normalizedDetour ? { detour: normalizedDetour } : {}),
  }
  const currentServers = config.dns?.servers ?? []
  const nextServers =
    mode === "edit"
      ? currentServers.map((server) =>
          server.tag === originalTag ? nextServer : server
        )
      : [...currentServers, nextServer]

  return {
    ...config,
    dns: {
      ...(config.dns ?? {}),
      servers: nextServers,
    },
  }
}

export function normalizeDnsServerDraftForComparison(draft: DnsServerDraft) {
  const isKeeneticDns = draft.type === DnsServerType.keenetic
  const normalizedAddress = normalizeDnsAddress(draft.address)

  return {
    tag: draft.tag.trim(),
    type: draft.type,
    address: isKeeneticDns ? "" : (normalizedAddress ?? draft.address.trim()),
    detour: isKeeneticDns ? "" : draft.detour.trim(),
  }
}

export function normalizeDnsAddress(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  const bracketedV6Match = /^\[([^\]]+)\](?::(\d+))?$/.exec(trimmed)
  if (bracketedV6Match) {
    const host = bracketedV6Match[1].trim().toLowerCase()
    const port = bracketedV6Match[2]
    if (!isValidIpv6(host) || !isValidPort(port)) {
      return null
    }

    return port ? `[${host}]:${port}` : host
  }

  const maybeIpv4WithPort = /^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/.exec(trimmed)
  if (maybeIpv4WithPort) {
    const host = maybeIpv4WithPort[1]
    const port = maybeIpv4WithPort[2]
    if (!isValidIpv4(host) || !isValidPort(port)) {
      return null
    }

    return port ? `${host}:${port}` : host
  }

  if (trimmed.includes(":")) {
    const host = trimmed.toLowerCase()
    return isValidIpv6(host) ? host : null
  }

  return null
}

function isValidIpv4(value: string) {
  const octets = value.split(".")
  if (octets.length !== 4) {
    return false
  }

  return octets.every((octet) => {
    if (!/^\d+$/.test(octet)) {
      return false
    }

    const num = Number(octet)
    return num >= 0 && num <= 255
  })
}

function isValidIpv6(value: string) {
  if (!value || !value.includes(":") || !/^[0-9a-f:]+$/i.test(value)) {
    return false
  }

  try {
    // URL uses the browser's standards-compliant IPv6 parser and is available
    // in both the UI and the test runtime.
    const parsed = new URL(`http://[${value}]/`)
    return parsed.hostname.length > 2
  } catch {
    return false
  }
}

function isValidPort(value?: string) {
  if (!value) {
    return true
  }

  if (!/^\d+$/.test(value)) {
    return false
  }

  const port = Number(value)
  return port >= 1 && port <= 65535
}
