import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListConfig } from "@/api/generated/model/listConfig"
import { withListDisplayName } from "@/lib/list-display"
import { makeTechnicalId } from "@/lib/technical-id"

export type CatalogPreset = {
  id: string
  name: string
  category?: string
  engines?: {
    dns?: { domains?: string[] }
    singbox?: {
      action?: string
      ruleSets?: { tag?: string; url?: string }[]
    }
  }
}

export type CatalogListProposal = {
  presetId: string
  technicalId: string
  displayName: string
  config: ListConfig
}

export type CatalogRuleProposal = {
  technicalId: string
  displayName: string
}

export type CatalogAddDraft = {
  lists: CatalogListProposal[]
  routeRule?: CatalogRuleProposal & { outbound: string }
  dnsRule?: CatalogRuleProposal & { server: string }
}

type CreateCatalogAddDraftOptions = {
  config: ConfigObject
  destination: string
  directDestination: string
  combinedDisplayName: string
  presets: readonly CatalogPreset[]
  selectedIds: ReadonlySet<string>
  sourceDetour: string
}

export function createCatalogAddDraft({
  config,
  destination,
  directDestination,
  combinedDisplayName,
  presets,
  selectedIds,
  sourceDetour,
}: CreateCatalogAddDraftOptions): CatalogAddDraft | null {
  const reservedListIds: Record<string, unknown> = { ...(config.lists ?? {}) }
  const lists: CatalogListProposal[] = []

  for (const preset of presets) {
    if (!selectedIds.has(preset.id)) {
      continue
    }

    const url = preset.engines?.singbox?.ruleSets?.[0]?.url
    const domains = preset.engines?.dns?.domains
    if (!url && (!domains || domains.length === 0)) {
      continue
    }

    const technicalId = listTechnicalIdFor(preset.id, reservedListIds)
    reservedListIds[technicalId] = {}
    lists.push({
      presetId: preset.id,
      technicalId,
      displayName: preset.name,
      config: url
        ? {
            url,
            ...(sourceDetour ? { detour: sourceDetour } : {}),
          }
        : { domains: domains ?? [] },
    })
  }

  if (lists.length === 0) {
    return null
  }

  const suggestedRuleName =
    lists.length === 1 ? lists[0].displayName : combinedDisplayName
  const ruleIdSeed = `catalog_${lists
    .map((item) => item.technicalId)
    .join("_")}`
  const draft: CatalogAddDraft = { lists }

  if (destination && destination !== directDestination) {
    const routeRuleIds = (config.route?.rules ?? [])
      .map((rule) => rule.id)
      .filter((id): id is string => Boolean(id))
    draft.routeRule = {
      technicalId: makeTechnicalId(ruleIdSeed, routeRuleIds, {
        prefix: "rule",
      }),
      displayName: suggestedRuleName,
      outbound: destination,
    }

    const matchingDnsServer = (config.dns?.servers ?? []).find(
      (server) => server.detour === destination
    )
    if (matchingDnsServer) {
      const dnsRuleIds = (config.dns?.rules ?? [])
        .map((rule) => rule.id)
        .filter((id): id is string => Boolean(id))
      draft.dnsRule = {
        technicalId: makeTechnicalId(ruleIdSeed, dnsRuleIds, {
          prefix: "dns_rule",
        }),
        displayName: suggestedRuleName,
        server: matchingDnsServer.tag,
      }
    }
  }

  return draft
}

export function applyCatalogAddDraft(
  config: ConfigObject,
  draft: CatalogAddDraft
): ConfigObject {
  const nextConfig: ConfigObject = {
    ...config,
    lists: { ...(config.lists ?? {}) },
  }

  for (const proposal of draft.lists) {
    nextConfig.lists![proposal.technicalId] = withListDisplayName(
      proposal.config,
      proposal.displayName
    )
  }

  const listIds = draft.lists.map((proposal) => proposal.technicalId)
  if (draft.routeRule) {
    nextConfig.route = {
      ...(config.route ?? {}),
      rules: [
        ...(config.route?.rules ?? []),
        {
          id: draft.routeRule.technicalId,
          ...(trimToUndefined(draft.routeRule.displayName)
            ? { display_name: draft.routeRule.displayName.trim() }
            : {}),
          enabled: true,
          list: listIds,
          outbound: draft.routeRule.outbound,
        },
      ],
    }
  }

  if (draft.dnsRule) {
    nextConfig.dns = {
      ...(config.dns ?? {}),
      rules: [
        ...(config.dns?.rules ?? []),
        {
          id: draft.dnsRule.technicalId,
          ...(trimToUndefined(draft.dnsRule.displayName)
            ? { display_name: draft.dnsRule.displayName.trim() }
            : {}),
          enabled: true,
          list: listIds,
          server: draft.dnsRule.server,
          allow_domain_rebinding: false,
        },
      ],
    }
  }

  return nextConfig
}

// List keys are restricted to ^[a-z][a-z0-9_]*$ and 24 characters, which
// catalogue IDs do not always satisfy.
export function sanitizeCatalogListId(id: string): string {
  const cleaned = id
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
  const prefixed = /^[a-z]/.test(cleaned) ? cleaned : `l_${cleaned}`
  return prefixed.slice(0, 24)
}

function listTechnicalIdFor(
  id: string,
  existing: Record<string, unknown>
): string {
  const base = sanitizeCatalogListId(id)
  if (!(base in existing)) {
    return base
  }
  for (let suffix = 2; suffix < 100; suffix += 1) {
    const candidate = `${base.slice(0, 21)}_${suffix}`
    if (!(candidate in existing)) {
      return candidate
    }
  }
  return base
}

function trimToUndefined(value: string): string | undefined {
  return value.trim() || undefined
}
