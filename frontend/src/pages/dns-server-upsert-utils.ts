import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsServer } from "@/api/generated/model/dnsServer"
import { DnsServerType } from "@/api/generated/model/dnsServerType"
import type { PlainDnsTemplate } from "@/api/generated/model/plainDnsTemplate"

export type DnsServerDraft = {
  displayName: string
  tag: string
  type: typeof DnsServerType.static | typeof DnsServerType.keenetic
  address: string
  detour: string
}

export type DnsServerBackupDraft = {
  displayName?: string
  tag: string
  address: string
}

export const MAX_PLAIN_DNS_TEMPLATES = 32

export const emptyDnsServerDraft: DnsServerDraft = {
  displayName: "",
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
    displayName: server.display_name ?? "",
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
  originalTag?: string,
  backupDraft?: DnsServerBackupDraft
): ConfigObject | null {
  const normalizedTag = draft.tag.trim()
  const normalizedDisplayName = draft.displayName.trim()
  const isKeeneticDns = draft.type === DnsServerType.keenetic
  const normalizedAddress = isKeeneticDns
    ? null
    : normalizeDnsAddress(draft.address)

  if (
    !normalizedTag ||
    !normalizedDisplayName ||
    normalizedDisplayName.length > 80 ||
    (!isKeeneticDns && !normalizedAddress)
  ) {
    return null
  }

  const normalizedDetour = isKeeneticDns ? "" : draft.detour.trim()
  const nextServer: DnsServer = {
    tag: normalizedTag,
    display_name: normalizedDisplayName,
    type: draft.type,
    ...(normalizedAddress ? { address: normalizedAddress } : {}),
    ...(normalizedDetour ? { detour: normalizedDetour } : {}),
  }
  const currentServers = config.dns?.servers ?? []
  let nextServers =
    mode === "edit"
      ? currentServers.map((server) =>
          server.tag === originalTag ? nextServer : server
        )
      : [...currentServers, nextServer]

  if (mode === "create" && backupDraft) {
    const backupTag = backupDraft.tag.trim()
    const backupAddress = normalizeDnsAddress(backupDraft.address)
    const duplicateTag = nextServers.some((server) => server.tag === backupTag)
    const duplicateDefinition = nextServers.some(
      (server) =>
        (server.type ?? DnsServerType.static) === DnsServerType.static &&
        server.address === backupAddress &&
        (server.detour ?? "") === normalizedDetour
    )

    if (
      !backupTag ||
      !backupAddress ||
      duplicateTag ||
      backupAddress === normalizedAddress
    ) {
      return null
    }

    if (!duplicateDefinition) {
      nextServers = [
        ...nextServers,
        {
          tag: backupTag,
          ...(backupDraft.displayName?.trim()
            ? { display_name: backupDraft.displayName.trim() }
            : {}),
          type: DnsServerType.static,
          address: backupAddress,
          ...(normalizedDetour ? { detour: normalizedDetour } : {}),
        },
      ]
    }
  }

  return {
    ...config,
    dns: {
      ...(config.dns ?? {}),
      servers: nextServers,
    },
  }
}

export function withSavedPlainDnsTemplate(
  config: ConfigObject,
  template: PlainDnsTemplate
): ConfigObject | null {
  const name = template.name.trim()
  const primaryIpv4 = normalizePlainDnsTemplateAddress(template.primary_ipv4)
  const secondaryIpv4 = template.secondary_ipv4
    ? normalizePlainDnsTemplateAddress(template.secondary_ipv4)
    : undefined

  if (
    !name ||
    name.length > 80 ||
    !primaryIpv4 ||
    (template.secondary_ipv4 && !secondaryIpv4) ||
    primaryIpv4 === secondaryIpv4
  ) {
    return null
  }

  const current = config.ui_preferences?.plain_dns_templates ?? []
  const normalizedName = name.toLowerCase()
  const replacement: PlainDnsTemplate = {
    name,
    primary_ipv4: primaryIpv4,
    ...(secondaryIpv4 ? { secondary_ipv4: secondaryIpv4 } : {}),
  }
  const existingIndex = current.findIndex(
    (item) => item.name.trim().toLowerCase() === normalizedName
  )
  const nextTemplates =
    existingIndex >= 0
      ? current.map((item, index) =>
          index === existingIndex ? replacement : item
        )
      : [...current, replacement]

  if (nextTemplates.length > MAX_PLAIN_DNS_TEMPLATES) {
    return null
  }

  return {
    ...config,
    ui_preferences: {
      ...(config.ui_preferences ?? {}),
      plain_dns_templates: nextTemplates,
    },
  }
}

export function normalizeDnsServerDraftForComparison(draft: DnsServerDraft) {
  const isKeeneticDns = draft.type === DnsServerType.keenetic
  const normalizedAddress = normalizeDnsAddress(draft.address)

  return {
    displayName: draft.displayName.trim(),
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

export function normalizePlainDnsTemplateAddress(value: string) {
  const normalized = normalizeDnsAddress(value)
  return normalized && isValidIpv4(normalized) ? normalized : null
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
