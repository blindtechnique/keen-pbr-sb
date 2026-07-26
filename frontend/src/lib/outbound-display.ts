import type { Outbound } from "@/api/generated/model/outbound"

export function getOutboundDisplayName(outbound: Outbound): string {
  return outbound.display_name?.trim() || outbound.tag
}

export function getOutboundReferenceLabel(outbound: Outbound): string {
  const displayName = getOutboundDisplayName(outbound)
  return displayName === outbound.tag
    ? outbound.tag
    : `${displayName} (${outbound.tag})`
}

export function sortOutboundsByDisplayName(
  outbounds: readonly Outbound[]
): Outbound[] {
  return [...outbounds].sort((left, right) =>
    getOutboundDisplayName(left).localeCompare(getOutboundDisplayName(right))
  )
}

export function createOutboundDisplayNameMap(
  outbounds: readonly Outbound[]
): Map<string, string> {
  return new Map(
    outbounds.map((outbound) => [
      outbound.tag,
      getOutboundDisplayName(outbound),
    ])
  )
}
