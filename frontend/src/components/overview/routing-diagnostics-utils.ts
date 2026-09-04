import type {
  ConfigObject,
  RouteRule,
  RoutingTestEntry,
  RoutingTestRuleDiagnostic,
} from "@/api/generated/model"
import { formatListReferenceLabels } from "@/lib/list-display"

export type RoutingPathStepState =
  | "verified"
  | "failed"
  | "unknown"
  | "blocked"
  | "not_applicable"

export type RoutingPathStates = {
  rule: RoutingPathStepState
  firewall: RoutingPathStepState
  kernel: RoutingPathStepState
}

export type RuleCondition = {
  key:
    | "lists"
    | "proto"
    | "sourceIp"
    | "destinationIp"
    | "sourcePort"
    | "destinationPort"
    | "dscp"
  value: string
}

export function getVisibleRuleDiagnostics(
  ruleDiagnostics: RoutingTestRuleDiagnostic[],
  showAllRules: boolean
) {
  if (showAllRules) {
    return ruleDiagnostics
  }

  return ruleDiagnostics.filter((rule) => !isGrayRuleDiagnostic(rule))
}

export function isGrayRuleDiagnostic(rule: RoutingTestRuleDiagnostic) {
  if (rule.target_in_lists || rule.target_match) {
    return false
  }

  if (
    rule.ip_rows.some(
      (ipRow) =>
        ipRow.in_lists ||
        ipRow.list_match != null ||
        ipRow.evaluation !== "not_matched"
    )
  ) {
    return false
  }

  return rule.ip_rows.every((ipRow) => ipRow.in_ipset !== true)
}

export function getRuleConditions(
  rule: RouteRule,
  lists?: ConfigObject["lists"]
): RuleCondition[] {
  const conditions: RuleCondition[] = []

  if (rule.list && rule.list.length > 0) {
    conditions.push({
      key: "lists",
      value: formatListReferenceLabels(rule.list, lists),
    })
  }
  if (hasText(rule.proto)) {
    conditions.push({ key: "proto", value: rule.proto })
  }
  if (hasText(rule.src_addr)) {
    conditions.push({ key: "sourceIp", value: rule.src_addr })
  }
  if (hasText(rule.dest_addr)) {
    conditions.push({ key: "destinationIp", value: rule.dest_addr })
  }
  if (hasText(rule.src_port)) {
    conditions.push({ key: "sourcePort", value: rule.src_port })
  }
  if (hasText(rule.dest_port)) {
    conditions.push({ key: "destinationPort", value: rule.dest_port })
  }
  if (rule.dscp != null) {
    conditions.push({ key: "dscp", value: String(rule.dscp) })
  }

  return conditions
}

export function getRoutingPathStates(
  entry: RoutingTestEntry
): RoutingPathStates {
  const contextUnknown = entry.evaluation === "insufficient_context"
  const ruleUnknown = contextUnknown || entry.expected_outbound === "(unknown)"
  const firewallUnknown =
    contextUnknown || entry.actual_outbound === "(unknown)"

  let kernel: RoutingPathStepState
  switch (entry.kernel_route?.route_status) {
    case "resolved":
      kernel = "verified"
      break
    case "unroutable":
      kernel = "blocked"
      break
    case "not_applicable":
      kernel = "not_applicable"
      break
    case "unavailable":
    default:
      kernel = "unknown"
      break
  }

  return {
    rule: ruleUnknown ? "unknown" : "verified",
    firewall: firewallUnknown ? "unknown" : entry.ok ? "verified" : "failed",
    kernel,
  }
}

export function formatRoutingFwmark(fwmark: number | null | undefined) {
  if (
    fwmark == null ||
    !Number.isFinite(fwmark) ||
    fwmark < 0 ||
    fwmark > 0xffffffff
  ) {
    return null
  }

  return `0x${Math.trunc(fwmark).toString(16).padStart(8, "0")}`
}

function hasText(value: string | undefined): value is string {
  return value != null && typeof value === "string" && value.trim().length > 0
}
