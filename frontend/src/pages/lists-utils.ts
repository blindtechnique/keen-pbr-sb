import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListDeleteTarget } from "@/api/generated/model/listDeleteTarget"
import type { RouteRule } from "@/api/generated/model/routeRule"

export type ListDeleteImpact = {
  dnsRuleIndexes: number[]
  routeRuleIndexes: number[]
  removedDnsRuleIndexes: number[]
  removedRouteRuleIndexes: number[]
}

function hasRouteMatchConditionExceptLists(rule: RouteRule): boolean {
  return Boolean(
    rule.dscp !== undefined ||
    rule.src_port ||
    rule.dest_port ||
    rule.src_addr ||
    rule.dest_addr
  )
}

export function getListDeleteImpact(
  config: ConfigObject,
  listIds: Iterable<string>,
  replacementListId?: string
): ListDeleteImpact {
  const listIdSet = new Set(listIds)
  const dnsRuleIndexes: number[] = []
  const routeRuleIndexes: number[] = []
  const removedDnsRuleIndexes: number[] = []
  const removedRouteRuleIndexes: number[] = []

  for (const [index, rule] of (config.route?.rules ?? []).entries()) {
    const beforeLists = rule.list ?? []
    const afterLists = rewriteListReferences(
      beforeLists,
      listIdSet,
      replacementListId
    )

    if (!sameStringArrays(afterLists, beforeLists)) {
      routeRuleIndexes.push(index)
    }

    if (
      replacementListId === undefined &&
      beforeLists.length > 0 &&
      afterLists.length === 0 &&
      !hasRouteMatchConditionExceptLists(rule)
    ) {
      removedRouteRuleIndexes.push(index)
    }
  }

  for (const [index, rule] of (config.dns?.rules ?? []).entries()) {
    const afterLists = rewriteListReferences(
      rule.list,
      listIdSet,
      replacementListId
    )

    if (!sameStringArrays(afterLists, rule.list)) {
      dnsRuleIndexes.push(index)
    }

    if (
      replacementListId === undefined &&
      rule.list.length > 0 &&
      afterLists.length === 0
    ) {
      removedDnsRuleIndexes.push(index)
    }
  }

  return {
    dnsRuleIndexes,
    routeRuleIndexes,
    removedDnsRuleIndexes,
    removedRouteRuleIndexes,
  }
}

export function buildListDeleteTargets(
  listIds: Iterable<string>,
  replacementListId?: string
): ListDeleteTarget[] {
  const replacement = replacementListId?.trim() || undefined
  return [...new Set(listIds)].map((listId) => ({
    list_id: listId,
    replacement_list_id: replacement,
  }))
}

function rewriteListReferences(
  references: readonly string[],
  deletedListIds: ReadonlySet<string>,
  replacementListId?: string
): string[] {
  const rewritten: string[] = []
  for (const listId of references) {
    const next =
      deletedListIds.has(listId) && replacementListId
        ? replacementListId
        : deletedListIds.has(listId)
          ? undefined
          : listId
    if (next && !rewritten.includes(next)) {
      rewritten.push(next)
    }
  }
  return rewritten
}

function sameStringArrays(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  )
}

export function buildUpdatedConfigForListsDelete(
  config: ConfigObject,
  listIds: string[]
): ConfigObject {
  return listIds.reduce(
    (nextConfig, listId) => buildUpdatedConfigForListDelete(nextConfig, listId),
    config
  )
}

export function listDeletesAltersRoutingOrDnsRefs(
  before: ConfigObject,
  after: ConfigObject
) {
  return (
    JSON.stringify(before.route?.rules ?? []) !==
      JSON.stringify(after.route?.rules ?? []) ||
    JSON.stringify(before.dns?.rules ?? []) !==
      JSON.stringify(after.dns?.rules ?? [])
  )
}

export function buildUpdatedConfigForListDelete(
  config: ConfigObject,
  listId: string
): ConfigObject {
  const nextLists = { ...(config.lists ?? {}) }
  delete nextLists[listId]

  return {
    ...config,
    lists: nextLists,
    route: {
      ...config.route,
      rules: (config.route?.rules ?? [])
        .map((rule) => ({
          ...rule,
          list: (rule.list ?? []).filter((name) => name !== listId),
        }))
        .filter(
          (rule) =>
            rule.list.length > 0 || hasRouteMatchConditionExceptLists(rule)
        ),
    },
    dns: {
      ...config.dns,
      rules: (config.dns?.rules ?? [])
        .map((rule) => ({
          ...rule,
          list: rule.list.filter((name) => name !== listId),
        }))
        .filter((rule) => rule.list.length > 0),
    },
  }
}
