export type ListRefreshTaskSnapshot = unknown

type ListRefreshEventListener = (snapshot: ListRefreshTaskSnapshot) => void

const listeners = new Set<ListRefreshEventListener>()

export function subscribeListRefreshEvents(listener: ListRefreshEventListener) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function applyListRefreshStatusEvent(serialized: string): boolean {
  const parsed = parseListRefreshStatusEvent(serialized)
  if (!parsed.accepted) return false

  for (const listener of listeners) listener(parsed.data)
  return true
}

function parseListRefreshStatusEvent(
  serialized: string
): { accepted: true; data: ListRefreshTaskSnapshot } | { accepted: false } {
  try {
    const envelope: unknown = JSON.parse(serialized)
    if (!isRecord(envelope) || envelope.type !== "list_refresh") {
      return { accepted: false }
    }
    if (!Object.prototype.hasOwnProperty.call(envelope, "data")) {
      return { accepted: false }
    }
    return { accepted: true, data: envelope.data }
  } catch {
    return { accepted: false }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
