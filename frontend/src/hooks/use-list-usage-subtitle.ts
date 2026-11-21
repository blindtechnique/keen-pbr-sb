import { getDnsRuleServers } from "@/lib/dns-rule-servers"
import { useCallback, useMemo } from "react"
import { useTranslation } from "react-i18next"

import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { buildListUsageByName } from "@/lib/list-usage"

type ListUsageRuleType = "routing" | "dns"
type ListUsageLabels = {
  rule: (ruleIndex: number) => string
  target: (target: string) => string
}

export function useListUsageSubtitle(
  rules: RouteRule[],
  ruleType: "routing",
  excludeRuleIndex?: number,
  labels?: ListUsageLabels
): (listName: string) => string | undefined
export function useListUsageSubtitle(
  rules: DnsRule[],
  ruleType: "dns",
  excludeRuleIndex?: number,
  labels?: ListUsageLabels
): (listName: string) => string | undefined
export function useListUsageSubtitle(
  rules: RouteRule[] | DnsRule[],
  ruleType: ListUsageRuleType,
  excludeRuleIndex?: number,
  labels?: ListUsageLabels
) {
  const { t } = useTranslation()
  const usageByName = useMemo(() => {
    if (ruleType === "routing") {
      return buildListUsageByName(
        rules as RouteRule[],
        (rule) => rule.list,
        (rule) => rule.outbound,
        excludeRuleIndex
      )
    }

    return buildListUsageByName(
      rules as DnsRule[],
      (rule) => rule.list,
      (rule) =>
        getDnsRuleServers(rule)
          .map((tag) => labels?.target(tag) ?? tag)
          .join(", "),
      excludeRuleIndex
    )
  }, [excludeRuleIndex, ruleType, rules, labels])

  return useCallback(
    (listName: string) => {
      const usages = usageByName.get(listName)
      if (!usages?.length) {
        return undefined
      }

      const summary = usages
        .map(
          (usage) =>
            `${labels?.rule(usage.ruleIndex) ?? `#${usage.ruleIndex + 1}`} → ${
              ruleType === "dns"
                ? usage.target
                : (labels?.target(usage.target) ?? usage.target)
            }`
        )
        .join(", ")

      return t("common.listUsage.usedElsewhere", { summary })
    },
    [labels, ruleType, t, usageByName]
  )
}
