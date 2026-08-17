type RuleWithStableId = {
  id?: string
}

export type RuleRouteCollection = "dns-rules" | "routing-rules"

export function getRuleEditHref(
  collection: RuleRouteCollection,
  rule: RuleWithStableId,
  legacyIndex: number
) {
  const stableId = rule.id?.trim()
  const routeIdentity = stableId || String(legacyIndex)
  return `/${collection}/${encodeURIComponent(routeIdentity)}/edit`
}

export function resolveRuleRouteIndex(
  rules: readonly RuleWithStableId[],
  routeIdentity: string | undefined
) {
  if (!routeIdentity) {
    return -1
  }

  const stableIndex = rules.findIndex(
    (rule) => rule.id?.trim() === routeIdentity
  )
  if (stableIndex >= 0) {
    return stableIndex
  }

  if (!/^(?:0|[1-9]\d*)$/.test(routeIdentity)) {
    return -1
  }
  const legacyIndex = Number(routeIdentity)
  return Number.isSafeInteger(legacyIndex) && legacyIndex < rules.length
    ? legacyIndex
    : -1
}
