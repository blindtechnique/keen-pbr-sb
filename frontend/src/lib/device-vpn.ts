import type { Outbound, RouteRule } from "@/api/generated/model"
import { makeTechnicalId } from "@/lib/technical-id"
import { areRouteRulesSemanticallyEqual } from "@/pages/routing-rules-utils"
import { resolveRuleEditTargetIndex } from "@/lib/rule-route"

export type DeviceVpnDraft = {
  name: string
  address: string
  outbound: string
  enabled: boolean
  failurePolicy: NonNullable<RouteRule["failure_policy"]>
  fallbackOutbound: string
}

export const emptyDeviceVpnDraft: DeviceVpnDraft = {
  name: "",
  address: "",
  outbound: "",
  enabled: true,
  failurePolicy: "inherit",
  fallbackOutbound: "",
}

/** Exact host only: no networks, negation, lists, octal, IPv6 or URL syntax. */
export function deviceIpv4(value: string): string | undefined {
  const text = value.trim()
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(text)) return
  const bytes = text.split(".").map(Number)
  if (
    bytes.some((byte) => byte > 255) ||
    bytes[0] === 0 ||
    bytes[0] === 127 ||
    bytes[0]! >= 224
  )
    return
  return text
}

const simpleFields = new Set([
  "id",
  "display_name",
  "enabled",
  "src_addr",
  "outbound",
  "list",
  "proto",
  "dscp",
  "src_port",
  "dest_port",
  "dest_addr",
  "failure_policy",
  "fallback_outbound",
])

// This is a view of ordinary source-only rules, not a second configuration.
// Never reinterpret a subnet or advanced/future selector as one whole device.
export function deviceRuleAddress(rule: RouteRule): string | undefined {
  if (
    (rule.list?.length ?? 0) > 0 ||
    rule.proto ||
    rule.dscp != null ||
    rule.src_port ||
    rule.dest_port ||
    rule.dest_addr ||
    Object.keys(rule).some((key) => !simpleFields.has(key))
  )
    return
  return deviceIpv4((rule.src_addr ?? "").replace(/\/32$/, ""))
}

export function deviceVpnOutbounds(outbounds: readonly Outbound[]): Outbound[] {
  return outbounds.filter(
    (outbound) => outbound.type === "interface" || outbound.type === "urltest"
  )
}

export function toDeviceVpnDraft(rule: RouteRule): DeviceVpnDraft {
  return {
    name: rule.display_name ?? "",
    address: deviceRuleAddress(rule) ?? "",
    outbound: rule.outbound,
    enabled: rule.enabled ?? true,
    failurePolicy: rule.failure_policy ?? "inherit",
    fallbackOutbound: rule.fallback_outbound ?? "",
  }
}

export function normalizeDeviceVpnDraft(draft: DeviceVpnDraft): DeviceVpnDraft {
  return {
    ...draft,
    name: draft.name.trim(),
    address: draft.address.trim(),
    fallbackOutbound:
      draft.failurePolicy === "fallback" ? draft.fallbackOutbound : "",
  }
}

export type DeviceVpnError =
  | "address"
  | "name"
  | "outbound"
  | "duplicate"
  | "changed"
  | "fallback"

export function deviceVpnError(
  draft: DeviceVpnDraft,
  rules: readonly RouteRule[],
  outbounds: readonly Outbound[],
  original?: RouteRule
): DeviceVpnError | undefined {
  const address = deviceIpv4(draft.address)
  if (!address) return "address"
  if (
    [...draft.name.trim()].length > 80 ||
    [...draft.name].some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127
    )
  )
    return "name"
  if (
    !deviceVpnOutbounds(outbounds).some(
      (outbound) => outbound.tag === draft.outbound
    )
  )
    return "outbound"
  const index = original ? resolveRuleEditTargetIndex(rules, original) : -1
  if (
    original &&
    (index < 0 ||
      !deviceRuleAddress(rules[index]!) ||
      !areRouteRulesSemanticallyEqual([rules[index]!], [original]))
  )
    return "changed"
  if (
    rules.some(
      (rule, candidate) =>
        candidate !== index && deviceRuleAddress(rule) === address
    )
  )
    return "duplicate"
  if (
    draft.failurePolicy === "fallback" &&
    (!draft.fallbackOutbound ||
      draft.fallbackOutbound === draft.outbound ||
      !deviceVpnOutbounds(outbounds).some(
        (outbound) => outbound.tag === draft.fallbackOutbound
      ))
  )
    return "fallback"
}

export function saveDeviceVpnRule(
  rules: readonly RouteRule[],
  outbounds: readonly Outbound[],
  draft: DeviceVpnDraft,
  original?: RouteRule
):
  | { rules: RouteRule[]; error?: undefined }
  | { error: DeviceVpnError; rules?: undefined } {
  const error = deviceVpnError(draft, rules, outbounds, original)
  if (error) return { error }
  const index = original ? resolveRuleEditTargetIndex(rules, original) : -1
  const value = normalizeDeviceVpnDraft(draft)
  const rule: RouteRule = {
    ...original,
    id:
      original?.id ??
      makeTechnicalId(
        "device_" + value.address.replaceAll(".", "_"),
        rules.flatMap((entry) => (entry.id ? [entry.id] : [])),
        { prefix: "device" }
      ),
    display_name: value.name || undefined,
    src_addr: value.address + "/32",
    outbound: value.outbound,
    enabled: value.enabled,
    failure_policy:
      value.failurePolicy === "inherit" ? undefined : value.failurePolicy,
    fallback_outbound:
      value.failurePolicy === "fallback" ? value.fallbackOutbound : undefined,
  }
  // Whole-device rules explicitly outrank site rules. Preserve all other rules
  // and their relative order, including disabled rules and unknown fields.
  return {
    rules: [rule, ...rules.filter((_entry, candidate) => candidate !== index)],
  }
}

export function removeDeviceVpnRule(
  rules: readonly RouteRule[],
  original: RouteRule
) {
  const index = resolveRuleEditTargetIndex(rules, original)
  if (
    index < 0 ||
    !deviceRuleAddress(rules[index]!) ||
    !areRouteRulesSemanticallyEqual([rules[index]!], [original])
  )
    return undefined
  return rules.filter((_entry, candidate) => candidate !== index)
}
