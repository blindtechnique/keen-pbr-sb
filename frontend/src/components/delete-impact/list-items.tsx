import type { ReactNode } from "react"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { ChangeValue } from "@/components/delete-impact/change-value"
import { formatDetail } from "@/components/delete-impact/format"
import type { DeleteImpactItem } from "@/components/shared/delete-impact-dialog"
import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
} from "@/lib/dns-display"
import {
  formatListReferenceLabels,
  getListReferenceLabel,
} from "@/lib/list-display"
import type { ListDeleteImpact } from "@/pages/lists-utils"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"

/**
 * Последствия удаления списков — общий модуль, как у маршрутов и
 * DNS-серверов (фаза 0): раньше построитель жил внутри страницы-таблицы, и
 * форме редактирования списка до него было не дотянуться.
 */
type TranslateFn = (key: string, options?: Record<string, unknown>) => string

/** Значение «удалить ссылки, ничем не заменяя» в селекте перепривязки. */
export const DELETE_REFERENCES = "__delete_references__"

export function getListDeleteImpactItems(
  config: ConfigObject | undefined,
  listIds: string[],
  impact: ListDeleteImpact,
  replacementListId: string | undefined,
  t: TranslateFn
) {
  const items: DeleteImpactItem[] = []
  const deletedListIds = new Set(listIds)

  for (const listId of listIds) {
    items.push({
      label: (
        <>
          {t("pages.lists.deleteDialog.items.listPrefix")}{" "}
          <strong>{getListReferenceLabel(listId, config?.lists)}</strong>{" "}
          {t("pages.lists.deleteDialog.items.listSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.removedRouteRuleIndexes) {
    const rule = config?.route?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.routeRuleRemoved", {
        name: rule ? getRouteRuleDisplayName(rule, index) : `#${index + 1}`,
      }),
      details: getRouteRuleDetails(
        rule,
        deletedListIds,
        true,
        replacementListId,
        config?.lists,
        t
      ),
    })
  }

  for (const index of impact.routeRuleIndexes) {
    if (impact.removedRouteRuleIndexes.includes(index)) {
      continue
    }
    const rule = config?.route?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.routeRuleUpdated", {
        name: rule ? getRouteRuleDisplayName(rule, index) : `#${index + 1}`,
      }),
      details: getRouteRuleDetails(
        rule,
        deletedListIds,
        false,
        replacementListId,
        config?.lists,
        t
      ),
    })
  }

  for (const index of impact.removedDnsRuleIndexes) {
    const rule = config?.dns?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.dnsRuleRemoved", {
        name: getDnsRuleDisplayName(rule, index),
      }),
      details: getDnsRuleDetails(
        rule,
        deletedListIds,
        true,
        replacementListId,
        config,
        t
      ),
    })
  }

  for (const index of impact.dnsRuleIndexes) {
    if (impact.removedDnsRuleIndexes.includes(index)) {
      continue
    }
    const rule = config?.dns?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.dnsRuleUpdated", {
        name: getDnsRuleDisplayName(rule, index),
      }),
      details: getDnsRuleDetails(
        rule,
        deletedListIds,
        false,
        replacementListId,
        config,
        t
      ),
    })
  }

  return items
}

function getRouteRuleDetails(
  rule: RouteRule | undefined,
  deletedListIds: ReadonlySet<string>,
  isRemoved: boolean,
  replacementListId: string | undefined,
  lists: ConfigObject["lists"],
  t: TranslateFn
) {
  if (!rule) {
    return []
  }

  const beforeLists = rule.list ?? []
  const afterLists = rewriteDisplayedListReferences(
    beforeLists,
    deletedListIds,
    replacementListId
  )
  const details: ReactNode[] = []

  if (beforeLists.length > 0) {
    details.push(
      formatDetail(
        t("pages.routingRules.criteriaLabels.lists"),
        isRemoved
          ? formatListValue(beforeLists, lists, t)
          : formatListTransition(beforeLists, afterLists, lists, t)
      )
    )
  }

  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.proto"),
    rule.proto
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.dscp"),
    rule.dscp?.toString()
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.sourceIp"),
    rule.src_addr
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.destinationIp"),
    rule.dest_addr
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.sourcePort"),
    rule.src_port
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.destinationPort"),
    rule.dest_port
  )

  return details
}

function getDnsRuleDetails(
  rule: DnsRule | undefined,
  deletedListIds: ReadonlySet<string>,
  isRemoved: boolean,
  replacementListId: string | undefined,
  config: ConfigObject | undefined,
  t: TranslateFn
) {
  if (!rule) {
    return []
  }

  const afterLists = rewriteDisplayedListReferences(
    rule.list,
    deletedListIds,
    replacementListId
  )
  const dnsServerNames = createDnsServerDisplayNameMap(
    config?.dns?.servers ?? []
  )

  return [
    formatDetail(
      t("pages.dnsRules.criteriaLabels.lists"),
      isRemoved
        ? formatListValue(rule.list, config?.lists, t)
        : formatListTransition(rule.list, afterLists, config?.lists, t)
    ),
    formatDetail(
      t("pages.dnsRules.headers.serverTag"),
      dnsServerNames.get(rule.server) ?? rule.server
    ),
  ]
}

function appendOptionalDetail(
  details: ReactNode[],
  label: string,
  value: string | undefined
) {
  if (typeof value !== "string" || value.trim().length === 0) {
    return
  }

  details.push(formatDetail(label, value))
}

function rewriteDisplayedListReferences(
  references: readonly string[],
  deletedListIds: ReadonlySet<string>,
  replacementListId?: string
) {
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

function formatListTransition(
  before: string[],
  after: string[],
  lists: ConfigObject["lists"],
  t: TranslateFn
) {
  return (
    <ChangeValue
      after={formatListValue(after, lists, t)}
      before={formatListValue(before, lists, t)}
    />
  )
}

function formatListValue(
  values: string[],
  lists: ConfigObject["lists"],
  t: TranslateFn
) {
  return values.length > 0
    ? formatListReferenceLabels(values, lists)
    : t("common.noneShort")
}
