import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { DeleteImpactItem } from "@/components/shared/delete-impact-dialog"
import {
  formatDetail,
  formatListValue,
  type TranslateFn,
} from "@/components/delete-impact/format"
import { ChangeValue } from "@/components/delete-impact/change-value"
import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
} from "@/lib/dns-display"
import { formatListReferenceLabels } from "@/lib/list-display"
import type { DnsServerDeleteImpact } from "@/pages/dns-servers-utils"

/**
 * Последствия удаления DNS-серверов — общий построитель для таблицы и формы
 * редактирования. Раньше жил внутри страницы-таблицы, и форма не могла его
 * переиспользовать.
 */
export function getDnsServerDeleteImpactItems(
  config: ConfigObject | undefined,
  serverTags: string[],
  impact: DnsServerDeleteImpact,
  t: TranslateFn
) {
  const items: DeleteImpactItem[] = []
  const serverDisplayNames = createDnsServerDisplayNameMap(
    config?.dns?.servers ?? []
  )

  for (const tag of serverTags) {
    items.push({
      label: (
        <>
          {t("pages.dnsServers.deleteDialog.items.serverPrefix")}{" "}
          <strong>{serverDisplayNames.get(tag) ?? tag}</strong>{" "}
          {t("pages.dnsServers.deleteDialog.items.serverSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.matchingRuleIndexes) {
    items.push({
      label: t("pages.dnsServers.deleteDialog.items.dnsRule", {
        name: getDnsRuleDisplayName(config?.dns?.rules?.[index], index),
      }),
      details: getDnsRuleDetails(config?.dns?.rules?.[index], config, t),
    })
  }

  if (impact.usesFallback) {
    const fallback = config?.dns?.fallback ?? []
    items.push({
      label: t("pages.dnsServers.deleteDialog.items.fallback"),
      details: [
        formatDetail(
          t("pages.dnsRules.fallback.title"),
          <ChangeValue
            after={formatListValue(
              fallback.filter((tag) => !serverTags.includes(tag)),
              t,
              serverDisplayNames
            )}
            before={formatListValue(fallback, t, serverDisplayNames)}
          />
        ),
      ],
    })
  }

  return items
}

export function formatDnsServerNames(config: ConfigObject, tags: string[]) {
  const displayNames = createDnsServerDisplayNameMap(config.dns?.servers ?? [])
  return tags.map((tag) => displayNames.get(tag) ?? tag).join(", ")
}

function getDnsRuleDetails(
  rule: DnsRule | undefined,
  config: ConfigObject | undefined,
  t: TranslateFn
) {
  if (!rule) {
    return []
  }

  return [
    formatDetail(
      t("pages.dnsRules.criteriaLabels.lists"),
      formatListReferenceLabels(rule.list, config?.lists)
    ),
    formatDetail(
      t("pages.dnsRules.headers.serverTag"),
      createDnsServerDisplayNameMap(config?.dns?.servers ?? []).get(
        rule.server
      ) ?? rule.server
    ),
  ]
}
