import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { DnsServer } from "@/api/generated/model/dnsServer"
import { DnsServerType } from "@/api/generated/model/dnsServerType"
import type { ListConfig } from "@/api/generated/model/listConfig"
import type { ListRefreshDetourMode } from "@/api/generated/model/listRefreshDetourMode"
import { getDnsServerDisplayName } from "@/lib/dns-display"
import { withListDisplayName } from "@/lib/list-display"
import { makeTechnicalId } from "@/lib/technical-id"
import {
  buildUpdatedConfigForDnsServerUpsert,
  normalizeDnsAddress,
} from "@/pages/dns-server-upsert-utils"

export type ListDraft = {
  displayName: string
  name: string
  ttlMs: string
  refreshDetourMode: ListRefreshDetourMode
  detour: string
  fallbackDetours: string[]
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

export type RecommendedDnsTemplate = {
  name: string
  primaryAddress: string
  secondaryAddress?: string
  technicalSeed: string
}

export type RecommendedDnsServerResult = {
  config: ConfigObject
  serverTag: string
}

export const NO_DNS_RULE = "__none__"

export function createListDnsServerSelectItems(
  servers: readonly DnsServer[],
  noneLabel: string
) {
  return [
    { value: NO_DNS_RULE, label: noneLabel },
    ...servers.map((server) => ({
      value: server.tag,
      label: getDnsServerDisplayName(server),
    })),
  ]
}

export function createListDraft(
  displayName = "",
  existingNames: Iterable<string> = []
): ListDraft {
  return {
    displayName,
    name: displayName
      ? makeTechnicalId(displayName, existingNames, { prefix: "list" })
      : "",
    ttlMs: "7200000",
    refreshDetourMode: "inherit",
    detour: "",
    fallbackDetours: [],
    domains: "",
    ipCidrs: "",
    url: "",
    file: "",
  }
}

export function addRecommendedDnsServer(
  config: ConfigObject,
  template: RecommendedDnsTemplate,
  outboundTag: string,
  outboundDisplayName: string
): RecommendedDnsServerResult | null {
  const normalizedOutboundTag = outboundTag.trim()
  if (!normalizedOutboundTag) {
    return null
  }

  const candidates = [
    template.primaryAddress,
    ...(template.secondaryAddress ? [template.secondaryAddress] : []),
  ]
  const candidateIdentity = (address: string) => {
    const normalized =
      normalizeDnsAddress(address) ?? address.trim().toLowerCase()
    const ipv4WithPort = /^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/.exec(normalized)
    if (ipv4WithPort) {
      const host = ipv4WithPort[1]
        .split(".")
        .map((octet) => Number(octet))
        .join(".")
      return `${host}|${Number(ipv4WithPort[2] ?? "53")}`
    }
    const bracketedIpv6WithPort = /^\[([^\]]+)\]:(\d+)$/.exec(normalized)
    if (bracketedIpv6WithPort) {
      return `${bracketedIpv6WithPort[1]}|${Number(bracketedIpv6WithPort[2])}`
    }
    return `${normalized}|53`
  }
  const candidateIdentities = new Set(candidates.map(candidateIdentity))
  const existing = (config.dns?.servers ?? []).find(
    (server) =>
      server.detour === normalizedOutboundTag &&
      Boolean(
        server.address &&
        candidateIdentities.has(candidateIdentity(server.address))
      )
  )
  if (existing) {
    return { config, serverTag: existing.tag }
  }

  const occupiedIdentities = new Set(
    (config.dns?.servers ?? [])
      .filter((server) => server.type !== DnsServerType.keenetic)
      .flatMap((server) =>
        server.address ? [candidateIdentity(server.address)] : []
      )
  )
  const address = candidates.find(
    (candidate) => !occupiedIdentities.has(candidateIdentity(candidate))
  )
  if (!address) {
    return null
  }

  const existingTags = (config.dns?.servers ?? []).map((server) => server.tag)
  const serverTag = makeTechnicalId(
    `${template.technicalSeed}_${normalizedOutboundTag}`,
    existingTags,
    { prefix: "dns" }
  )
  const displayName = [...`${template.name} · ${outboundDisplayName.trim()}`]
    .slice(0, 80)
    .join("")
    .trim()
  const updated = buildUpdatedConfigForDnsServerUpsert(config, "create", {
    displayName: displayName || template.name,
    tag: serverTag,
    type: DnsServerType.static,
    address,
    detour: normalizedOutboundTag,
  })

  return updated ? { config: updated, serverTag } : null
}

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
    refreshDetourMode:
      listConfig.refresh_detour_mode ??
      (listConfig.detour || (listConfig.fallback_detours?.length ?? 0) > 0
        ? "override"
        : "inherit"),
    detour: listConfig.detour ?? "",
    fallbackDetours: listConfig.fallback_detours ?? [],
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
  const originalListConfig =
    mode === "edit" && originalName ? config.lists?.[originalName] : undefined
  if (
    originalListConfig?.catalog_identity &&
    sameListSource(originalListConfig, nextListConfig)
  ) {
    nextListConfig.catalog_identity = originalListConfig.catalog_identity
  }

  nextLists[resolvedName] = nextListConfig

  const updated: ConfigObject = {
    ...config,
    lists: nextLists,
  }
  if (quickSetup?.createRouteRule && quickSetup.routeOutbound) {
    const routeRuleDisplayName = nextDraft.displayName.trim() || resolvedName
    const existingRuleIds = (config.route?.rules ?? [])
      .map((rule) => rule.id)
      .filter((id): id is string => Boolean(id))
    updated.route = {
      ...(config.route ?? {}),
      rules: [
        ...(config.route?.rules ?? []),
        {
          id: makeTechnicalId(routeRuleDisplayName, existingRuleIds, {
            prefix: "rule",
          }),
          display_name: routeRuleDisplayName,
          enabled: true,
          list: [resolvedName],
          outbound: quickSetup.routeOutbound,
        },
      ],
    }
  }
  if (quickSetup?.createDnsRule && quickSetup.dnsServer) {
    const dnsRuleDisplayName = nextDraft.displayName.trim() || resolvedName
    const existingDnsRuleIds = (config.dns?.rules ?? [])
      .map((rule) => rule.id)
      .filter((id): id is string => Boolean(id))
    updated.dns = {
      ...(config.dns ?? {}),
      rules: [
        ...(config.dns?.rules ?? []),
        {
          id: makeTechnicalId(dnsRuleDisplayName, existingDnsRuleIds, {
            prefix: "dns_rule",
          }),
          display_name: dnsRuleDisplayName,
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
  const refreshDetourMode =
    draft.refreshDetourMode ?? (trimmedDetour ? "override" : "inherit")
  const ttlMs = Number.parseInt(draft.ttlMs.trim(), 10)

  const listConfig: ListConfig = {}
  listConfig.ttl_ms = Number.isNaN(ttlMs) ? 0 : ttlMs

  if (trimmedUrl) {
    listConfig.url = trimmedUrl
    listConfig.refresh_detour_mode = refreshDetourMode
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

  if (trimmedUrl && refreshDetourMode === "override" && trimmedDetour) {
    listConfig.detour = trimmedDetour
    const fallbackDetours = draft.fallbackDetours
      .map((detour) => detour.trim())
      .filter((detour) => detour && detour !== trimmedDetour)
    if (fallbackDetours.length > 0) {
      listConfig.fallback_detours = [...new Set(fallbackDetours)]
    }
  }

  return withListDisplayName(listConfig, draft.displayName)
}

function sameListSource(left: ListConfig, right: ListConfig): boolean {
  return (
    normalizedOptionalText(left.url) === normalizedOptionalText(right.url) &&
    normalizedOptionalText(left.file) === normalizedOptionalText(right.file) &&
    sameNormalizedValues(left.domains, right.domains) &&
    sameNormalizedValues(left.ip_cidrs, right.ip_cidrs)
  )
}

function normalizedOptionalText(value: string | undefined): string {
  return value?.trim() ?? ""
}

function sameNormalizedValues(
  left: readonly string[] | undefined,
  right: readonly string[] | undefined
): boolean {
  const normalize = (values: readonly string[] | undefined) =>
    [
      ...new Set((values ?? []).map((value) => value.trim()).filter(Boolean)),
    ].sort()
  const normalizedLeft = normalize(left)
  const normalizedRight = normalize(right)
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  )
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

// Which of a list's sources are in play. ListConfig allows url, file and
// inline entries together - the schema says "at least one of", not "exactly
// one" - so this is a set, not a choice, and the editor has to be able to
// carry a list that arrives with several.
export type ListSourceGroup = "url" | "file" | "inline"

export const LIST_SOURCE_GROUPS: ListSourceGroup[] = ["url", "file", "inline"]

export const LIST_SOURCE_GROUP_FIELDS = {
  url: ["url"],
  file: ["file"],
  inline: ["domains", "ipCidrs"],
} satisfies Record<ListSourceGroup, (keyof ListDraft)[]>

export function isSourceGroupPopulated(
  group: ListSourceGroup,
  draft: ListDraft
) {
  if (group === "inline") {
    return (
      splitLines(draft.domains).length > 0 ||
      splitLines(draft.ipCidrs).length > 0
    )
  }

  return draft[group].trim().length > 0
}

export function getActiveSourceGroupsFromDraft(
  draft: ListDraft
): ListSourceGroup[] {
  const populated = LIST_SOURCE_GROUPS.filter((group) =>
    isSourceGroupPopulated(group, draft)
  )
  return populated.length > 0 ? populated : ["url"]
}

// Removes the sources the operator did not choose. This is the only place they
// are dropped, so validation and persistence judge the same document.
//
// Dropping `url` takes the download route with it: refreshDetourMode, detour
// and fallbackDetours describe how a URL is fetched and mean nothing without
// one. That coupling is why discarding has to be announced in terms of both.
export function narrowDraftToSourceGroups(
  draft: ListDraft,
  groups: ListSourceGroup[]
): ListDraft {
  const narrowed: ListDraft = { ...draft }

  for (const group of LIST_SOURCE_GROUPS) {
    if (groups.includes(group)) {
      continue
    }
    for (const fieldName of LIST_SOURCE_GROUP_FIELDS[group]) {
      narrowed[fieldName] = ""
    }
  }

  if (!groups.includes("url")) {
    narrowed.refreshDetourMode = "inherit"
    narrowed.detour = ""
    narrowed.fallbackDetours = []
  }

  return narrowed
}

// What saving would throw away, named, so a confirmation can list it instead
// of asking about "the fields" and leaving the operator to work out which.
export function getDiscardedSourceGroups(
  draft: ListDraft,
  groups: ListSourceGroup[]
): ListSourceGroup[] {
  return LIST_SOURCE_GROUPS.filter(
    (group) => !groups.includes(group) && isSourceGroupPopulated(group, draft)
  )
}

// The download route survives only alongside a URL, so a selection without one
// discards whatever was configured for it.
export function discardsDownloadRoute(
  draft: ListDraft,
  groups: ListSourceGroup[]
) {
  return (
    !groups.includes("url") &&
    (draft.refreshDetourMode !== "inherit" ||
      draft.detour.trim().length > 0 ||
      draft.fallbackDetours.length > 0)
  )
}
