type Translate = (key: string, options?: Record<string, unknown>) => string

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
      return t("overview.routing.statuses.unknown")
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
      return t("overview.routing.actions.unknown")
  }
}

export function localizeRouteType(type: string, t: Translate) {
  switch (type) {
    case "unicast":
      return t("overview.routing.routeTypes.unicast")
    case "blackhole":
      return t("overview.routing.routeTypes.blackhole")
    case "unreachable":
      return t("overview.routing.routeTypes.unreachable")
    default:
      return t("overview.routing.routeTypes.unknown")
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

  if (normalized === "unexpected route present in table") {
    return t("overview.routing.details.unexpectedRoute")
  }

  const missingNftRule = trimmed?.match(
    /^rule not found in nftables prerouting chain \(family=(ipv4|ipv6) criteria=(.+)\)$/i
  )
  if (missingNftRule) {
    const [, family, criteria] = missingNftRule
    return t("overview.routing.details.nftRuleNotFound", {
      family:
        family.toLowerCase() === "ipv6"
          ? t("overview.routing.ipv6")
          : t("overview.routing.ipv4"),
      criteria:
        criteria.toLowerCase() === "any"
          ? t("overview.routing.details.criteriaAny")
          : criteria,
    })
  }

  const markMismatch = trimmed?.match(
    /^fwmark mismatch: expected (0x[\da-f]+) got (0x[\da-f]+)$/i
  )
  if (markMismatch) {
    return t("overview.routing.details.markMismatch", {
      expected: markMismatch[1],
      actual: markMismatch[2],
    })
  }

  const maskMismatch = trimmed?.match(
    /^fwmark mask mismatch: expected (0x[\da-f]+\/0x[\da-f]+) got (0x[\da-f]+\/0x[\da-f]+)$/i
  )
  if (maskMismatch) {
    return t("overview.routing.details.markMaskMismatch", {
      expected: maskMismatch[1],
      actual: maskMismatch[2],
    })
  }

  const actionMismatch = trimmed?.match(
    /^expected (MARK|DROP|RETURN|ACCEPT) rule but found (MARK|DROP|RETURN|ACCEPT) rule$/
  )
  if (actionMismatch) {
    return t("overview.routing.details.actionMismatch", {
      expected: actionMismatch[1],
      actual: actionMismatch[2],
    })
  }

  const routeTypeMismatch = trimmed?.match(
    /^route type mismatch: expected '(unicast|blackhole|unreachable)', got '(unicast|blackhole|unreachable)'\.$/
  )
  if (routeTypeMismatch) {
    return t("overview.routing.details.routeTypeMismatch", {
      expected: localizeRouteType(routeTypeMismatch[1], t),
      actual: localizeRouteType(routeTypeMismatch[2], t),
    })
  }

  const metricMismatch = trimmed?.match(
    /^metric mismatch: expected '(\d+)', got '(\d+)'\.$/
  )
  if (metricMismatch) {
    return t("overview.routing.details.metricMismatch", {
      expected: metricMismatch[1],
      actual: metricMismatch[2],
    })
  }

  const policyMissing = trimmed?.match(
    /^ip rule fwmark=(0x[\da-f]+\/0x[\da-f]+) table=(\d+) missing: (IPv4(?: IPv6)?|IPv6)$/
  )
  if (policyMissing) {
    return t("overview.routing.details.policyMissing", {
      mark: policyMissing[1],
      table: policyMissing[2],
      families: policyMissing[3],
    })
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
