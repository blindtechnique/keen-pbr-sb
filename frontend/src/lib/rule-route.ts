import { semanticJsonEqual } from "@/lib/semantic-json"

export type RuleWithStableId = {
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

// Numeric URLs are only an entry point. An open editor must keep targeting the
// record it captured, never whatever a later reorder puts at that old index.
export function resolveRuleEditTargetIndex<T extends RuleWithStableId>(
  rules: readonly T[],
  originalRule: T | undefined,
  equals: (left: T, right: T) => boolean = semanticJsonEqual
) {
  if (!originalRule) return -1

  const stableId = originalRule.id?.trim()
  if (!stableId) {
    // An unchanged snapshot can distinguish otherwise identical legacy rules.
    // Once JSON is refreshed, only a unique semantic match is safe to follow.
    const referenceIndex = rules.indexOf(originalRule)
    if (referenceIndex >= 0) {
      return rules.lastIndexOf(originalRule) === referenceIndex
        ? referenceIndex
        : -1
    }
  }
  let result = -1
  for (let index = 0; index < rules.length; index++) {
    const rule = rules[index]
    const matches = stableId
      ? rule.id?.trim() === stableId
      : !rule.id?.trim() && equals(rule, originalRule)
    if (!matches) continue
    if (result >= 0) return -1
    result = index
  }
  return result
}
