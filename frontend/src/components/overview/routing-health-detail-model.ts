type Translate = (
  key: string,
  options?: Record<string, unknown>
) => string

export function localizeRoutingHealthStatus(status: string, t: Translate) {
  switch (status) {
    case "ok":
      return t("overview.routing.statuses.ok")
    case "degraded":
      return t("overview.routing.statuses.degraded")
    case "error":
      return t("overview.routing.statuses.error")
    case "missing":
      return t("overview.routing.statuses.missing")
    case "mismatch":
      return t("overview.routing.statuses.mismatch")
    default:
      return status
  }
}

export function localizeFirewallAction(action: string, t: Translate) {
  switch (action) {
    case "mark":
      return t("overview.routing.actions.mark")
    case "drop":
      return t("overview.routing.actions.drop")
    case "pass":
      return t("overview.routing.actions.pass")
    default:
      return action
  }
}

/**
 * Keep backend diagnostic details intact unless they belong to the small,
 * stable vocabulary that the dashboard knows how to present to users.
 */
export function localizeRoutingHealthDetail(
  detail: string | null | undefined,
  t: Translate
) {
  const trimmed = detail?.trim()
  const normalized = trimmed?.toLocaleLowerCase("en-US")

  if (!normalized || normalized === "ok") {
    return null
  }

  if (normalized === "disabled by configuration") {
    return t("overview.routing.details.disabledByConfiguration")
  }

  const missingRule = trimmed?.match(
    /^rule not found in (iptables|ip6tables) (raw|mangle) table \(family=(ipv4|ipv6) criteria=(.+)\)$/i
  )
  if (missingRule) {
    const [, backend, table, family, criteria] = missingRule
    return t("overview.routing.details.ruleNotFound", {
      backend,
      table,
      family:
        family.toLocaleLowerCase("en-US") === "ipv6"
          ? t("overview.routing.ipv6")
          : t("overview.routing.ipv4"),
      criteria:
        criteria.toLocaleLowerCase("en-US") === "any"
          ? t("overview.routing.details.criteriaAny")
          : criteria,
    })
  }

  return detail
}
