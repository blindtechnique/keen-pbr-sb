import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { ListConfig } from "@/api/generated/model/listConfig"
import { withListDisplayName } from "@/lib/list-display"

export type ListDraft = {
  displayName: string
  name: string
  ttlMs: string
  detour: string
  domains: string
  ipCidrs: string
  url: string
  file: string
}

export type QuickSetup = {
  createRouteRule: boolean
  routeOutbound: string
  createDnsRule: boolean
  dnsServer: string
}

export const NO_DNS_RULE = "__none__"

export function getDraftFromMapEntry(
  name: string | undefined,
  listConfig?: ListConfig
): ListDraft | null {
  if (!name || !listConfig) {
    return null
  }

  return {
    displayName: listConfig.display_name ?? "",
    name,
    ttlMs: String(listConfig.ttl_ms ?? 0),
    detour: listConfig.detour ?? "",
    domains: (listConfig.domains ?? []).join("\n"),
    ipCidrs: (listConfig.ip_cidrs ?? []).join("\n"),
    url: listConfig.url ?? "",
    file: listConfig.file ?? "",
  }
}

export function buildUpdatedConfigForListUpsert(
  config: ConfigObject,
  mode: "create" | "edit",
  nextDraft: ListDraft,
  originalName?: string,
  quickSetup?: QuickSetup,
  dnsServerForList?: string
): ConfigObject {
  const nextLists = { ...(config.lists ?? {}) }
  const trimmedName = nextDraft.name.trim()
  const resolvedName =
    mode === "edit" ? (originalName?.trim() ?? trimmedName) : trimmedName
  const nextListConfig = getListConfigFromDraft(nextDraft)

  nextLists[resolvedName] = nextListConfig

  const updated: ConfigObject = {
    ...config,
    lists: nextLists,
  }
  if (quickSetup?.createRouteRule && quickSetup.routeOutbound) {
    updated.route = {
      ...(config.route ?? {}),
      rules: [
        ...(config.route?.rules ?? []),
        {
          enabled: true,
          list: [resolvedName],
          outbound: quickSetup.routeOutbound,
        },
      ],
    }
  }
  if (quickSetup?.createDnsRule && quickSetup.dnsServer) {
    updated.dns = {
      ...(config.dns ?? {}),
      rules: [
        ...(config.dns?.rules ?? []),
        {
          enabled: true,
          list: [resolvedName],
          server: quickSetup.dnsServer,
          allow_domain_rebinding: false,
        },
      ],
    }
  }

  if (dnsServerForList !== undefined) {
    updated.dns = {
      ...(config.dns ?? {}),
      rules: applyDnsRuleForList(
        config.dns?.rules ?? [],
        resolvedName,
        dnsServerForList === NO_DNS_RULE ? "" : dnsServerForList
      ),
    }
  }
  return updated
}

function applyDnsRuleForList(
  rules: DnsRule[],
  listName: string,
  server: string
): DnsRule[] {
  const next: DnsRule[] = []
  let applied = false

  for (const rule of rules) {
    const lists = rule.list ?? []
    if (!lists.includes(listName)) {
      next.push(rule)
      continue
    }

    if (lists.length > 1) {
      next.push({ ...rule, list: lists.filter((item) => item !== listName) })
      continue
    }

    if (server) {
      next.push({ ...rule, server })
      applied = true
    }
  }

  if (server && !applied) {
    next.push({
      enabled: true,
      list: [listName],
      server,
      allow_domain_rebinding: false,
    })
  }

  return next
}

export function getListConfigFromDraft(draft: ListDraft): ListConfig {
  const domains = splitLines(draft.domains)
  const ipCidrs = splitLines(draft.ipCidrs)
  const trimmedUrl = draft.url.trim()
  const trimmedFile = draft.file.trim()
  const trimmedDetour = draft.detour.trim()
  const ttlMs = Number.parseInt(draft.ttlMs.trim(), 10)

  const listConfig: ListConfig = {}
  listConfig.ttl_ms = Number.isNaN(ttlMs) ? 0 : ttlMs

  if (trimmedUrl) {
    listConfig.url = trimmedUrl
  }

  if (trimmedFile) {
    listConfig.file = trimmedFile
  }

  if (domains.length > 0) {
    listConfig.domains = domains
  }

  if (ipCidrs.length > 0) {
    listConfig.ip_cidrs = ipCidrs
  }

  if (trimmedDetour) {
    listConfig.detour = trimmedDetour
  }

  return withListDisplayName(listConfig, draft.displayName)
}

export function normalizeListDraftForComparison(draft: ListDraft) {
  return {
    name: draft.name.trim(),
    config: getListConfigFromDraft(draft),
  }
}

export function normalizeQuickSetupForComparison(quickSetup: QuickSetup) {
  return {
    createRouteRule: quickSetup.createRouteRule,
    routeOutbound: quickSetup.createRouteRule ? quickSetup.routeOutbound : "",
    createDnsRule: quickSetup.createDnsRule,
    dnsServer: quickSetup.createDnsRule ? quickSetup.dnsServer : "",
  }
}

export function splitLines(value: string) {
  return value
    .split("\n")
    .map((entry) => entry.trim())
    .filter(Boolean)
}
