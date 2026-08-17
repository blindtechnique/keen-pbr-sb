import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import type { RouteRule } from "@/api/generated/model/routeRule"
import type { DeleteImpactItem } from "@/components/shared/delete-impact-dialog"
import {
  formatDetail,
  formatListValue,
  formatTransition,
  type TranslateFn,
} from "@/components/delete-impact/format"
import { ChangeValue } from "@/components/delete-impact/change-value"
import {
  createDnsServerDisplayNameMap,
  getDnsServerDisplayName,
} from "@/lib/dns-display"
import {
  formatListReferenceLabels,
  getListReferenceLabel,
} from "@/lib/list-display"
import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
} from "@/lib/outbound-display"
import type { OutboundDeleteImpact } from "@/pages/outbounds-utils"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"

/**
 * Последствия удаления маршрутов и групп — общий построитель для таблицы и
 * формы редактирования. Раньше жил внутри страницы-таблицы, и форма не могла
 * его переиспользовать; в фазе 2 тем же диалогом будет пользоваться удаление
 * туннеля со связанным маршрутом.
 */
export function getOutboundDeleteImpactItems(
  config: ConfigObject | undefined,
  requestedTags: string[],
  impact: OutboundDeleteImpact,
  t: TranslateFn
) {
  const items: DeleteImpactItem[] = []
  const requestedTagSet = new Set(requestedTags)
  const outboundNames = createOutboundDisplayNameMap(config?.outbounds ?? [])
  const dnsServerNames = createDnsServerDisplayNameMap(
    config?.dns?.servers ?? []
  )

  for (const tag of requestedTags) {
    const outbound = config?.outbounds?.find((item) => item.tag === tag)
    items.push({
      label: (
        <>
          {t("pages.outbounds.deleteDialog.items.outboundPrefix")}{" "}
          <strong>{outbound ? getOutboundDisplayName(outbound) : tag}</strong>{" "}
          {t("pages.outbounds.deleteDialog.items.outboundSuffix")}
        </>
      ),
    })
  }

  for (const tag of impact.deletedOutboundTags) {
    if (requestedTagSet.has(tag)) {
      continue
    }

    const outbound = config?.outbounds?.find((item) => item.tag === tag)
    items.push({
      label: (
        <>
          {t("pages.outbounds.deleteDialog.items.dependentOutboundPrefix")}{" "}
          <strong>{outbound ? getOutboundDisplayName(outbound) : tag}</strong>{" "}
          {t("pages.outbounds.deleteDialog.items.dependentOutboundSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.routeRuleIndexes) {
    const rule = config?.route?.rules?.[index]
    items.push({
      label: t("pages.outbounds.deleteDialog.items.routingRule", {
        name: rule ? getRouteRuleDisplayName(rule, index) : `#${index + 1}`,
      }),
      details: getRouteRuleImpactDetails(
        rule,
        config?.lists,
        config?.outbounds,
        t
      ),
    })
  }

  for (const server of impact.dnsServerDetours) {
    const dnsServer = config?.dns?.servers?.find((item) => item.tag === server)
    items.push({
      label: t("pages.outbounds.deleteDialog.items.dnsDetour", {
        server: dnsServer
          ? getDnsServerDisplayName(dnsServer)
          : (dnsServerNames.get(server) ?? server),
      }),
      details: [
        formatDetail(
          t("pages.dnsServers.headers.outbound"),
          <ChangeValue
            after={t("common.noneShort")}
            before={
              outboundNames.get(dnsServer?.detour ?? "") ??
              dnsServer?.detour ??
              t("common.noneShort")
            }
          />
        ),
      ],
    })
  }

  for (const listRoute of impact.listDownloadRoutes) {
    items.push({
      label: t("pages.outbounds.deleteDialog.items.listDownloadRoutes", {
        list: getListReferenceLabel(listRoute.listName, config?.lists),
      }),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.downloadRoutes"),
          formatTransition(listRoute.before, listRoute.after, t, outboundNames)
        ),
      ],
    })
  }

  if (impact.globalListRefreshRoute) {
    items.push({
      label: t("pages.outbounds.deleteDialog.items.globalListRefreshRoutes"),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.downloadRoutes"),
          formatTransition(
            impact.globalListRefreshRoute.before,
            impact.globalListRefreshRoute.after,
            t,
            outboundNames
          )
        ),
      ],
    })
  }

  for (const membership of impact.urltestMemberships) {
    const group = config?.outbounds?.find(
      (outbound) => outbound.tag === membership.outboundTag
    )?.outbound_groups?.[membership.groupIndex]
    const remainingTags =
      group?.outbounds.filter(
        (tag) => !impact.deletedOutboundTags.includes(tag)
      ) ?? []
    const isRemoved = remainingTags.length === 0

    items.push({
      label: isRemoved
        ? t("pages.outbounds.deleteDialog.items.urltestGroupRemoved", {
            group: membership.groupIndex + 1,
            outbound:
              outboundNames.get(membership.outboundTag) ??
              membership.outboundTag,
          })
        : t("pages.outbounds.deleteDialog.items.urltestGroupChanged", {
            group: membership.groupIndex + 1,
            outbound:
              outboundNames.get(membership.outboundTag) ??
              membership.outboundTag,
          }),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.groupOutbounds"),
          isRemoved
            ? formatListValue(group?.outbounds ?? [], t, outboundNames)
            : formatTransition(
                group?.outbounds ?? [],
                remainingTags,
                t,
                outboundNames
              )
        ),
      ],
    })
  }

  return items
}

function getRouteRuleImpactDetails(
  rule: RouteRule | undefined,
  lists: ConfigObject["lists"],
  outbounds: Outbound[] | undefined,
  t: TranslateFn
) {
  if (!rule) {
    return []
  }

  const details = [
    {
      label: t("pages.routingRules.headers.outbound"),
      value:
        outbounds?.find((outbound) => outbound.tag === rule.outbound)
          ?.display_name ?? rule.outbound,
    },
    {
      label: t("pages.routingRules.criteriaLabels.lists"),
      value: formatListReferenceLabels(rule.list ?? [], lists),
    },
    {
      label: t("pages.routingRules.criteriaLabels.proto"),
      value: rule.proto,
    },
    {
      label: t("pages.routingRules.criteriaLabels.dscp"),
      value: rule.dscp?.toString(),
    },
    {
      label: t("pages.routingRules.criteriaLabels.sourceIp"),
      value: rule.src_addr,
    },
    {
      label: t("pages.routingRules.criteriaLabels.destinationIp"),
      value: rule.dest_addr,
    },
    {
      label: t("pages.routingRules.criteriaLabels.sourcePort"),
      value: rule.src_port,
    },
    {
      label: t("pages.routingRules.criteriaLabels.destinationPort"),
      value: rule.dest_port,
    },
  ]
    .filter(
      (
        item
      ): item is {
        label: string
        value: string
      } => typeof item.value === "string" && item.value.trim().length > 0
    )
    .map((item) =>
      t("pages.outbounds.deleteDialog.items.ruleDetail", {
        label: item.label,
        value: item.value,
      })
    )

  return details
}
