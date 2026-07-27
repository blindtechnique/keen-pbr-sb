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
  return [...outbounds].sort((left, right) => {
    const leftName = normalizedSortKey(getOutboundDisplayName(left))
    const rightName = normalizedSortKey(getOutboundDisplayName(right))
    if (leftName < rightName) return -1
    if (leftName > rightName) return 1
    return left.tag < right.tag ? -1 : left.tag > right.tag ? 1 : 0
  })
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

// String.localeCompare() follows the host's default locale. That made the
// same mixed Latin/Cyrillic list sort differently on a Russian workstation
// and in the English CI image. UTF-16 code-point order is less linguistic but
// deterministic, while NFKC and lower-casing still make common aliases stable.
function normalizedSortKey(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US")
}
