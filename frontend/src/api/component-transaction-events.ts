// Progress for a package operation on an external component.
//
// The operation runs inside one HTTP request that takes a minute or more, so
// until this existed the panel showed a spinner and nothing else: an operator
// could not tell a slow package download from a hung one, and a second tab
// could not tell that anything was happening at all.

export type ComponentTransactionProgress = {
  component: string
  operation: string
  step: string
  active: boolean
  detail: string
}

type Listener = (progress: ComponentTransactionProgress | null) => void

const listeners = new Set<Listener>()
let current: ComponentTransactionProgress | null = null

export function subscribeComponentTransaction(listener: Listener) {
  listeners.add(listener)
  // The stream replays its last frame to a new subscriber, but a component
  // already mounted when the frame arrived would otherwise never see it.
  listener(current)
  return () => {
    listeners.delete(listener)
  }
}

export function getComponentTransactionProgress() {
  return current
}

export function applyComponentTransactionStatusEvent(
  serialized: string
): boolean {
  const parsed = parse(serialized)
  if (!parsed) return false
  // A finished operation stops being progress rather than becoming progress
  // that says "finished" forever.
  current = parsed.active ? parsed : null
  for (const listener of listeners) listener(current)
  return true
}

// Exported for tests: a page must not have to fake an EventSource to prove it
// handles a malformed frame.
export function resetComponentTransactionProgress() {
  current = null
  for (const listener of listeners) listener(current)
}

function parse(serialized: string): ComponentTransactionProgress | null {
  try {
    const envelope: unknown = JSON.parse(serialized)
    if (!isRecord(envelope) || envelope.type !== "component_transaction") {
      return null
    }
    const data: unknown = envelope.data
    if (!isRecord(data)) return null
    // Every field is required and typed. A frame from a newer backend that
    // means something else must be ignored, not rendered as a step whose name
    // this page invented.
    if (
      typeof data.component !== "string" ||
      typeof data.operation !== "string" ||
      typeof data.step !== "string" ||
      typeof data.active !== "boolean"
    ) {
      return null
    }
    return {
      component: data.component,
      operation: data.operation,
      step: data.step,
      active: data.active,
      detail: typeof data.detail === "string" ? data.detail : "",
    }
  } catch {
    return null
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
