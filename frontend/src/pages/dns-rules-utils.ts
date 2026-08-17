import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import i18n from "@/i18n"
import { makeTechnicalId } from "@/lib/technical-id"

export type DnsRuleDraft = {
  id: string
  displayName: string
  enabled: boolean
  server: string
  lists: string[]
  allowDomainRebinding: boolean
}

export type RuleErrors = {
  id?: string
  server?: string
  lists?: string
  duplicate?: string
}

export function createDnsRuleDraft(
  displayName = "",
  existingIds: Iterable<string> = []
): DnsRuleDraft {
  return {
    id: makeTechnicalId(displayName, existingIds, { prefix: "dns_rule" }),
    displayName,
    enabled: true,
    server: "",
    lists: [],
    allowDomainRebinding: false,
  }
}

export function getRuleDraft(rule?: DnsRule): DnsRuleDraft {
  return {
    id: rule?.id ?? "",
    displayName: rule?.display_name ?? "",
    enabled: rule?.enabled ?? true,
    server: rule?.server ?? "",
    lists: [...(rule?.list ?? [])],
    allowDomainRebinding: rule?.allow_domain_rebinding ?? false,
  }
}

export function normalizeDnsRuleDraft(rule: DnsRuleDraft): DnsRule {
  const normalizedId = rule.id.trim()
  const normalizedDisplayName = rule.displayName.trim()
  return {
    ...(normalizedId ? { id: normalizedId } : {}),
    ...(normalizedDisplayName ? { display_name: normalizedDisplayName } : {}),
    enabled: rule.enabled,
    server: rule.server.trim(),
    list: Array.from(
      new Set(rule.lists.map((list) => list.trim()).filter(Boolean))
    ).sort(),
    allow_domain_rebinding: rule.allowDomainRebinding,
  }
}

export function buildUpdatedConfigWithRules(
  config: ConfigObject,
  fallback: string[],
  rules: DnsRuleDraft[]
): ConfigObject {
  return {
    ...config,
    dns: {
      ...config.dns,
      fallback,
      rules: rules.map(normalizeDnsRuleDraft),
    },
  }
}

export function setDnsRuleEnabled(
  rules: DnsRuleDraft[],
  index: number,
  enabled: boolean
) {
  return rules.map((rule, ruleIndex) =>
    ruleIndex === index ? { ...rule, enabled } : rule
  )
}

export function validateRules(
  rules: DnsRuleDraft[],
  serverTags: string[],
  listOptions: string[]
): Record<number, RuleErrors> {
  const t = i18n.t.bind(i18n)
  const errors: Record<number, RuleErrors> = {}
  const serverTagSet = new Set(serverTags)
  const listOptionSet = new Set(listOptions)
  const seenRules = new Set<string>()
  const seenIds = new Set<string>()

  for (const [index, rule] of rules.entries()) {
    const normalizedId = rule.id.trim()
    if (normalizedId) {
      if (seenIds.has(normalizedId)) {
        errors[index] = {
          ...errors[index],
          id: t("pages.dnsRuleUpsert.validation.duplicateId"),
        }
      }
      seenIds.add(normalizedId)
    }

    if (!rule.enabled) {
      continue
    }

    const nextRuleErrors: RuleErrors = {}
    const parsedLists = rule.lists

    if (!rule.server || !serverTagSet.has(rule.server)) {
      nextRuleErrors.server = t("pages.dnsRuleUpsert.validation.serverRequired")
    }

    if (parsedLists.length === 0) {
      nextRuleErrors.lists = t("pages.dnsRuleUpsert.validation.listsRequired")
    }

    const missingLists = parsedLists.filter(
      (listName) => !listOptionSet.has(listName)
    )
    if (missingLists.length > 0) {
      nextRuleErrors.lists = t("pages.dnsRuleUpsert.validation.unknownLists", {
        lists: missingLists.join(", "),
      })
    }

    const dedupeKey = `${rule.server}::${[...parsedLists].sort().join("|")}`
    if (seenRules.has(dedupeKey)) {
      nextRuleErrors.duplicate = t("pages.dnsRuleUpsert.validation.duplicate")
    }

    seenRules.add(dedupeKey)

    if (Object.keys(nextRuleErrors).length > 0) {
      errors[index] = { ...errors[index], ...nextRuleErrors }
    }
  }

  return errors
}
