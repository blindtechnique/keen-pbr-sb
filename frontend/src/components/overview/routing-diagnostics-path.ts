import type {
  Outbound,
  RoutingTestEntry,
  RoutingTestRuleDiagnostic,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { getOutboundSelectDisplayName } from "@/lib/outbound-display"

export function isKnownRoutingOutbound(tag: string | undefined): tag is string {
  return Boolean(tag?.trim() && tag !== "(unknown)" && tag !== "-")
}

/** A missing interface is not an alias, especially for a selector group. */
export function getRoutingOutboundLabel(
  tag: string,
  outbounds: readonly Outbound[],
  interfaceLabelFor?: (name: string) => string,
  reportedInterface?: string
): string {
  const outbound = outbounds.find((candidate) => candidate.tag === tag)
  if (outbound) {
    const name = getOutboundSelectDisplayName(outbound, interfaceLabelFor)
    if (name !== tag || outbound.type !== "interface") return name
  }
  const interfaceName = [outbound?.interface, reportedInterface].find(
    (name) => isKnownRoutingOutbound(name) && name !== "(default)"
  )
  const alias = interfaceName && interfaceLabelFor?.(interfaceName)?.trim()
  // A raw interface name must not replace an already known route name.
  return alias && alias !== interfaceName && alias !== "-" ? alias : tag
}

/**
 * Keep configured destinations visible even when the backend cannot evaluate
 * a source/protocol/inbound condition from a destination-only request. These
 * are rule references, not a claim about the path taken by an observed packet.
 */
export function getConfiguredRoutingOutbounds(
  entry: RoutingTestEntry | undefined,
  ip: string,
  rules: readonly RoutingTestRuleDiagnostic[]
): string[] {
  if (isKnownRoutingOutbound(entry?.expected_outbound)) {
    return [entry.expected_outbound]
  }
  const tags = new Set<string>()
  for (const diagnostic of [...rules].sort(
    (left, right) => left.rule_index - right.rule_index
  )) {
    if (diagnostic.rule.enabled === false) continue
    const row = diagnostic.ip_rows.find((candidate) => candidate.ip === ip)
    if (row?.evaluation === "not_matched") continue
    if (
      row?.evaluation !== "matched" &&
      row?.evaluation !== "insufficient_context" &&
      !row?.in_lists &&
      !row?.list_match &&
      !diagnostic.target_in_lists &&
      !diagnostic.target_match
    )
      continue
    const tag = diagnostic.rule.outbound || diagnostic.outbound
    if (isKnownRoutingOutbound(tag)) tags.add(tag)
    // The first unconditional match ends rule evaluation. Earlier conditional
    // candidates stay visible; unrelated lower-priority rules do not.
    if (row?.evaluation === "matched") break
  }
  return [...tags]
}

/** Reuse the dashboard's current selection; never choose the first candidate. */
export function getSelectedRoutingGroupPath(
  tag: string,
  runtimeOutbounds: readonly RuntimeOutboundState[]
): RuntimeInterfaceState[] {
  const byTag = new Map(
    runtimeOutbounds.map((outbound) => [outbound.tag, outbound])
  )
  const seen = new Set([tag])
  const path: RuntimeInterfaceState[] = []
  let current = byTag.get(tag)
  while (current?.type === "urltest") {
    const selected = current.interfaces.filter(
      (member) => member.status === "active"
    )
    if (selected.length !== 1 || seen.has(selected[0].outbound_tag)) break
    const member = selected[0]
    seen.add(member.outbound_tag)
    path.push(member)
    current = byTag.get(member.outbound_tag)
  }
  return path
}
