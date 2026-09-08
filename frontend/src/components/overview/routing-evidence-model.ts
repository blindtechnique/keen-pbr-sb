import type {
  RoutingTestConnection,
  RoutingTestEntry,
  RoutingTestResponse,
} from "@/api/generated/model"

export type ConnectionMarkEvidence = "matching" | "different" | "unconfirmed"

function isUint32(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 0xffffffff
  )
}

export function compareConnectionMark(
  observed: unknown,
  expected: unknown,
  mask: unknown
): ConnectionMarkEvidence {
  if (
    !isUint32(observed) ||
    !isUint32(expected) ||
    !isUint32(mask) ||
    mask === 0
  ) {
    return "unconfirmed"
  }
  return (observed & mask) >>> 0 === (expected & mask) >>> 0
    ? "matching"
    : "different"
}

function addressKey(address: string): string | null {
  if (!address.includes(":")) return address
  // URL's IPv6 parser canonicalizes compressed, expanded and embedded IPv4
  // literals. Do not rewrite the original tuple shown in technical details.
  if (!/^[\da-f:.]+$/i.test(address)) return null
  try {
    return new URL(`http://[${address}]/`).hostname
  } catch {
    return null
  }
}

export function sameRoutingEvidenceAddress(
  left: string,
  right: string
): boolean {
  const key = addressKey(left)
  return key != null && key === addressKey(right)
}

export function getConnectionEvidence(
  diagnostics: RoutingTestResponse,
  entry: RoutingTestEntry
): { connection: RoutingTestConnection; mark: ConnectionMarkEvidence }[] {
  if (!diagnostics.connections?.snapshot_available) return []
  const destination = addressKey(entry.ip)
  if (!destination) return []
  return diagnostics.connections.items
    .filter((connection) => addressKey(connection.destination) === destination)
    .map((connection) => ({
      connection,
      mark: compareConnectionMark(
        connection.mark,
        entry.kernel_route?.fwmark,
        diagnostics.fwmark_mask
      ),
    }))
}

export function formatEvidenceTime(seconds: number | undefined): string | null {
  if (seconds == null || !Number.isFinite(seconds) || seconds <= 0) return null
  const date = new Date(seconds * 1000)
  return Number.isNaN(date.getTime()) ? null : date.toISOString()
}
