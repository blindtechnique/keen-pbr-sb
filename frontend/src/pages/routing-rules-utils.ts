import type { ApiError } from "@/api/client"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { getApiErrorMessage as getSharedApiErrorMessage } from "@/lib/api-errors"
import { stableJsonStringify } from "@/lib/semantic-json"
import { makeTechnicalId } from "@/lib/technical-id"

export type RouteRuleDraft = {
  id: string
  displayName: string
  enabled: boolean
  list: string[]
  outbound: string
  proto: string
  dscp: string
  src_port: string
  dest_port: string
  src_addr: string
  dest_addr: string
}

export const protoOptions = ["", "tcp", "udp", "tcp/udp"] as const

export function getRoutingRuleRowId(rule: RouteRule, index: number) {
  const stableId = rule.id?.trim()
  return stableId ? `id:${stableId}` : `index:${index}`
}

function normalizeRouteRulesForComparison(rules: readonly RouteRule[]) {
  return rules.map((rule) => ({
    ...rule,
    enabled: rule.enabled ?? true,
    list: rule.list ?? [],
  }))
}

export function getRouteRulesSemanticKey(rules: readonly RouteRule[]) {
  return stableJsonStringify(normalizeRouteRulesForComparison(rules))
}

export function areRouteRulesSemanticallyEqual(
  left: readonly RouteRule[],
  right: readonly RouteRule[]
) {
  return getRouteRulesSemanticKey(left) === getRouteRulesSemanticKey(right)
}

export const emptyRouteRuleDraft: RouteRuleDraft = {
  id: "",
  displayName: "",
  enabled: true,
  list: [],
  outbound: "",
  proto: "",
  dscp: "",
  src_port: "",
  dest_port: "",
  src_addr: "",
  dest_addr: "",
}

export function createRouteRuleDraft(
  displayName = "",
  existingIds: Iterable<string> = []
): RouteRuleDraft {
  return {
    ...emptyRouteRuleDraft,
    displayName,
    id: displayName
      ? makeTechnicalId(displayName, existingIds, { prefix: "rule" })
      : "",
  }
}

export function getRouteRuleDisplayName(rule: RouteRule, index: number) {
  return rule.display_name?.trim() || `#${index + 1}`
}

/**
 * У правила без имени `getRouteRuleDisplayName` отдаёт `#N`. Как идентификатор
 * в ссылках, зависимостях и aria-подписях это правильно, но в колонке
 * «Название» оно дублирует соседнюю колонку «№» и выглядит как имя, которого
 * пользователь не давал. Списки уже показаны в «Условии», а маршрут — в
 * «Маршруте», поэтому вместо третьего повтора там уместен приглушённый
 * «Без названия».
 */
export function isRouteRuleNameGenerated(rule: RouteRule): boolean {
  return !rule.display_name?.trim()
}

export function getRuleDetails(rule: RouteRule) {
  const pieces = [
    `src_addr: ${rule.src_addr || "-"}`,
    `dest_addr: ${rule.dest_addr || "-"}`,
    `dscp: ${rule.dscp ?? "-"}`,
    `src_port: ${rule.src_port || "-"}`,
    `dest_port: ${rule.dest_port || "-"}`,
  ]

  return pieces.join(" · ")
}

export function toRouteRuleDraft(rule: RouteRule): RouteRuleDraft {
  return {
    id: rule.id ?? "",
    displayName: rule.display_name ?? "",
    enabled: rule.enabled ?? true,
    list: rule.list ?? [],
    outbound: rule.outbound,
    proto: rule.proto ?? "",
    dscp: rule.dscp?.toString() ?? "",
    src_port: rule.src_port ?? "",
    dest_port: rule.dest_port ?? "",
    src_addr: rule.src_addr ?? "",
    dest_addr: rule.dest_addr ?? "",
  }
}

export function normalizeRouteRuleDraft(draft: RouteRuleDraft): RouteRule {
  return {
    id: trimToUndefined(draft.id),
    display_name: trimToUndefined(draft.displayName),
    enabled: draft.enabled,
    list: draft.list,
    outbound: draft.outbound,
    proto: trimToUndefined(draft.proto),
    dscp: parseOptionalDscp(draft.dscp),
    src_port: trimToUndefined(draft.src_port),
    dest_port: trimToUndefined(draft.dest_port),
    src_addr: trimToUndefined(draft.src_addr),
    dest_addr: trimToUndefined(draft.dest_addr),
  }
}

export function reorderRules(
  rules: RouteRule[],
  fromIndex: number,
  toIndex: number
) {
  const nextRules = [...rules]
  const [movedRule] = nextRules.splice(fromIndex, 1)
  nextRules.splice(toIndex, 0, movedRule)
  return nextRules
}

export function setRouteRuleEnabled(
  rules: RouteRule[],
  index: number,
  enabled: boolean
) {
  return rules.map((rule, ruleIndex) =>
    ruleIndex === index ? { ...rule, enabled } : rule
  )
}

export function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : undefined
}

export function getApiErrorMessage(error: ApiError) {
  return getSharedApiErrorMessage(error)
}

function trimToUndefined(value: string) {
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

function parseOptionalDscp(value: string) {
  const trimmed = value.trim()
  if (trimmed.length === 0) {
    return undefined
  }
  return Number(trimmed)
}
